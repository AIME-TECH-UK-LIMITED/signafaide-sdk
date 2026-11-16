/**
 * signafAIde for OpenTelemetry: signed records of the tool calls your traces already show.
 *
 *   import { SignafaideSpanProcessor } from "signafaide/otel";
 *
 *   const provider = new NodeTracerProvider({ spanProcessors: [new SignafaideSpanProcessor()] });
 *
 * The processor runs inside your own process. It recognises tool-call spans by three conventions
 * (OpenTelemetry GenAI, OpenInference, OpenLLMetry), and writes a signed `decision` and `outcome`
 * record for each into `.signafaide/`, exactly as the SDK does for a wrapped tool. It exports
 * nothing: span data is read where it is and goes nowhere else.
 *
 * A decision is written when the span starts, before the tool runs, when the span says at its
 * start that it is a tool call. When the span only says so at its end, the decision and the
 * outcome are both written then, after the tool ran. Every record says which it was (SPEC §2.7).
 *
 * Running a tool only once it is recorded (strict mode) is a feature of wrapping the tool with
 * the SDK, not of this processor: when a record cannot be written the tool still runs.
 *
 * Needs `@opentelemetry/api`, which every OpenTelemetry set-up has. Node only.
 */

import * as fs from "node:fs";
import { trace } from "@opentelemetry/api";
import { declaredName, samplingNote, telemetryNoteName } from "./coverage.js";
import { declareBeforeCall, rememberTool, toJsonable } from "./record.js";
import { AGENT_RE, agentName, recordHash, type Kind, type SignedRecord } from "./records.js";
import { getRecorder, recording, recordingDisabled, telemetryHooks, type Recorder } from "./runtime.js";
import { ADAPTERS } from "./telemetry.js";
import { VERSION } from "./version.js";

type Attributes = Record<string, unknown>;

/** The parts of an OpenTelemetry SDK span this processor reads (`Span` and `ReadableSpan` of
 * `@opentelemetry/sdk-trace-base` 1.x and 2.x both have them). */
export interface TelemetrySpan {
  readonly name: string;
  readonly attributes?: Attributes;
  spanContext(): { traceId: string; spanId: string };
  readonly resource?: { attributes?: Attributes };
  readonly status?: { code: number; message?: string };
  readonly events?: readonly { name: string; attributes?: Attributes }[];
  readonly startTime?: readonly [number, number];
}

export interface SignafaideSpanProcessorOptions {
  /** The name of the record chain. Default: the tracer resource's `service.name`, else the
   * project folder's name. Give one name per running agent instance. */
  agent?: string;
  /** Send inputs and outputs to the witness, encrypted, as well as their hashes. Default: the
   * project's setting (hashes only). */
  storeContent?: boolean;
  /** Declare each tool seen in a span as one of the agent's recorded tools (SPEC §2.6). Default
   * true. The declaration lists the tools seen so far, never a complete tool list. */
  declareTools?: boolean;
  /** The sampler of the tracer provider this processor is added to. A span does not name its
   * sampler, so the processor looks for it on the registered global tracer provider; give it
   * here for a provider that is not registered globally. When the sampler is not always-on, a
   * signed note says once what its sampling leaves out: for a parent-based sampler with an
   * always-on root, calls inside traces that arrive marked as not sampled; for any other, some
   * tool calls. */
  sampler?: { toString(): string };
}

/** What a span says about a tool call. */
export interface ToolCall {
  convention: "gen_ai" | "openinference" | "traceloop";
  tool: string;
  id?: unknown;
  input?: unknown;
  output?: unknown;
}

/** The most spans kept in mind at once (open tool calls, spans begun inside a wrapped tool). A
 * span that never ends leaves its entry here; the oldest go first. */
const MAX_OPEN = 10_000;
const INPUT_KEYS = ["gen_ai.tool.call.arguments", "input.value", "traceloop.entity.input"];
const OUTPUT_KEYS = ["gen_ai.tool.call.result", "output.value", "traceloop.entity.output"];
const ID_KEYS = ["gen_ai.tool.call.id", "tool_call.id"];
const NAME_KEYS = { gen_ai: "gen_ai.tool.name", openinference: "tool.name", traceloop: "traceloop.entity.name" } as const;
const text = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * What a span says about a tool call, or null when it is not one.
 * A span is a tool call when `gen_ai.operation.name` is `execute_tool` (OpenTelemetry GenAI),
 * `openinference.span.kind` is `TOOL` (OpenInference) or `traceloop.span.kind` is `tool`
 * (OpenLLMetry).
 */
export function toolCall(spanName: string, attributes: Attributes | undefined | null): ToolCall | null {
  const a = attributes ?? {};
  let convention: ToolCall["convention"];
  if (a["gen_ai.operation.name"] === "execute_tool") convention = "gen_ai";
  else if (text(a["openinference.span.kind"]).toUpperCase() === "TOOL") convention = "openinference";
  else if (text(a["traceloop.span.kind"]).toLowerCase() === "tool") convention = "traceloop";
  else return null;
  // The tool's name: the convention's own attribute, then the others', then the span's name.
  let tool = [NAME_KEYS[convention], ...Object.values(NAME_KEYS)].map((k) => text(a[k])).find(Boolean) ?? "";
  if (!tool) tool = spanName.startsWith("execute_tool ") ? spanName.slice("execute_tool ".length) : spanName.endsWith(".tool") ? spanName.slice(0, -".tool".length) : spanName;
  if (!tool) return null;
  const call: ToolCall = { convention, tool };
  for (const [field, keys] of [["id", ID_KEYS], ["input", INPUT_KEYS], ["output", OUTPUT_KEYS]] as const) {
    const k = keys.find((x) => a[x] !== undefined && a[x] !== null);
    if (k) call[field] = a[k];
  }
  // A LangChain tool's result names the tool that ran; an instrumentation may name the span after
  // the tool's class instead.
  call.tool = toolMessageName(call.output) || tool;
  return call;
}

/** The tool a serialised LangChain `ToolMessage` names (its `name` field), when the span's result
 * is one, alone or under `output`; else "". */
function toolMessageName(output: unknown): string {
  if (typeof output !== "string" || !output.includes("ToolMessage")) return "";
  let v: any;
  try {
    v = JSON.parse(output);
  } catch {
    return "";
  }
  for (const m of [v, v?.output]) {
    if (m && typeof m === "object" && m.lc === 1 && Array.isArray(m.id) && m.id.at(-1) === "ToolMessage" && m.kwargs && typeof m.kwargs === "object") return text(m.kwargs.name);
  }
  return "";
}

/** A span attribute as record content: JSON text is parsed, anything else is kept as it is. */
function value(v: unknown): unknown {
  if (typeof v === "string" && /^[{["]/.test(v)) {
    try {
      return toJsonable(JSON.parse(v)) ?? null;
    } catch {
      return v;
    }
  }
  return toJsonable(v) ?? null;
}

function time(t: readonly [number, number] | undefined): string | undefined {
  if (!Array.isArray(t) || !t[0]) return undefined;
  const d = new Date(t[0] * 1000 + Math.floor(t[1] / 1e6));
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

interface Held {
  rec: Recorder;
  decision: SignedRecord;
  tool: string;
  input: boolean;
  adopted?: boolean;
}

const processors = new Set<WeakRef<SignafaideSpanProcessor>>();

function each(fn: (p: SignafaideSpanProcessor) => void): void {
  for (const ref of processors) {
    const p = ref.deref();
    if (p) fn(p);
    else processors.delete(ref);
  }
}

/** Counts span starts and wrapper calls, so their order is known without a clock. */
let tick = 0;
/** Tool calls a wrapper of the SDK recorded, not yet matched to a span. */
const claims: { tool: string; at: number }[] = [];

/** Whether a wrapper recorded a call of `tool` after the tick `began` (a span's start), and
 * forget that call: one wrapper call answers for one span. */
function claimed(tool: string, began: number): boolean {
  const i = claims.findIndex((c) => c.tool === tool && c.at > began);
  if (i < 0) return false;
  claims.splice(i, 1);
  return true;
}

/** Write signafAIde records for the tool-call spans of a tracer provider. */
export class SignafaideSpanProcessor {
  private readonly agent?: string;
  private readonly storeContent?: boolean;
  private readonly declare: boolean;
  private readonly sampler?: { toString(): string };
  /** span id -> the decision written when the span started. */
  private readonly open = new Map<string, Held>();
  /** span id -> the wrapped tool (`recording`) whose call the span began inside. */
  private readonly inside = new Map<string, string>();
  /** span id -> the tick at which the span began, for spans that did not say at their start that
   * they are a tool call (see `claim`). */
  private readonly began = new Map<string, number>();
  /** span ids left alone at their start (a wrapper or a gateway records the call). */
  private readonly skipped = new Map<string, true>();
  /** recorder -> `<agent> <tool>` -> the telemetry note last written for the tool. */
  private readonly noted = new WeakMap<Recorder, Map<string, "start" | "end">>();
  private readonly samplingNoted = new WeakMap<Recorder, Set<string>>();
  /** agent -> the tools a gateway on this machine records, and the file stamp they were read at. */
  private readonly gateway = new Map<string, { stamp: string; names: Set<string> }>();
  private warned = false;

  constructor(opts: SignafaideSpanProcessorOptions = {}) {
    if (opts.agent !== undefined && !(typeof opts.agent === "string" && AGENT_RE.test(opts.agent))) {
      throw new Error(`agent "${opts.agent}" is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)`);
    }
    this.agent = opts.agent;
    this.storeContent = opts.storeContent;
    this.declare = opts.declareTools ?? true;
    this.sampler = opts.sampler;
    ADAPTERS.add("otel");
    processors.add(new WeakRef(this));
    telemetryHooks.adopt = adopt;
    telemetryHooks.claim = claim;
  }

  // --- the SpanProcessor interface: none of these ever throws ---------------------------

  onStart(span: TelemetrySpan, _parentContext?: unknown): void {
    try {
      this.started(span);
    } catch (e) {
      this.warn(e); // the application must never see it
    }
  }

  onEnd(span: TelemetrySpan): void {
    try {
      this.ended(span);
    } catch (e) {
      this.warn(e);
    }
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }

  // --- recording --------------------------------------------------------------------

  private warn(e: unknown): void {
    if (this.warned) return;
    this.warned = true;
    console.warn(`signafaide: could not record a tool call from its span (${(e as Error)?.message ?? e}); the tool runs all the same, and later failures are not reported again`);
  }

  private keep<V>(held: Map<string, V>, spanId: string, v: V): void {
    held.set(spanId, v);
    while (held.size > MAX_OPEN) held.delete(held.keys().next().value as string);
  }

  private agentOf(span: TelemetrySpan, rec: Recorder): string {
    if (this.agent) return this.agent;
    const service = text(span.resource?.attributes?.["service.name"]);
    if (service && !service.startsWith("unknown_service")) return agentName(service);
    return rec.defaultAgent;
  }

  /** An MCP gateway on this machine records this tool for the same agent (§8 `tools/<agent>.json`). */
  private byGateway(rec: Recorder, agent: string, tool: string): boolean {
    let stamp: string;
    try {
      const st = fs.statSync(rec.state.toolsPath(agent));
      stamp = `${st.mtimeMs} ${st.size}`;
    } catch {
      return false;
    }
    let held = this.gateway.get(agent);
    if (!held || held.stamp !== stamp) {
      const names = new Set<string>();
      for (const [source, entry] of Object.entries(rec.state.toolEntries(agent))) {
        if (!source.startsWith("gateway:")) continue;
        const prefix = source.slice("gateway:".length);
        for (const [name, recorded] of Object.entries(entry.tools ?? {})) {
          if (!recorded) continue;
          names.add(name);
          if (name.startsWith(prefix)) names.add(name.slice(prefix.length));
        }
      }
      held = { stamp, names };
      this.gateway.set(agent, held);
    }
    return held.names.has(tool);
  }

  private started(span: TelemetrySpan): void {
    if (recordingDisabled()) return;
    const spanId = span.spanContext().spanId;
    const wrapped = recording.getStore();
    const call = toolCall(span.name, span.attributes);
    if (!call) {
      this.keep(this.began, spanId, ++tick);
      if (wrapped) this.keep(this.inside, spanId, wrapped); // it may turn out to be the wrapped tool's own span when it ends
      return;
    }
    if (wrapped === call.tool) {
      claimed(wrapped, 0);
      this.keep(this.skipped, spanId, true); // a wrapper of the SDK is recording this very call: its records stand
      return;
    }
    const rec = getRecorder();
    const agent = this.agentOf(span, rec);
    if (this.byGateway(rec, agent, call.tool)) {
      this.keep(this.skipped, spanId, true);
      return;
    }
    const decision = this.decide(rec, agent, span, call, true);
    this.keep(this.open, spanId, { rec, decision, tool: call.tool, input: call.input !== undefined });
  }

  private ended(span: TelemetrySpan): void {
    const spanId = span.spanContext().spanId;
    let held = this.open.get(spanId);
    const wrapped = this.inside.get(spanId);
    const skipped = this.skipped.has(spanId);
    const began = this.began.get(spanId) ?? 0;
    for (const m of [this.open, this.inside, this.skipped, this.began]) m.delete(spanId);
    if (skipped || recordingDisabled()) return;
    const call = toolCall(span.name, span.attributes);
    if (!held) {
      if (!call) return;
      if (call.tool === wrapped) {
        claimed(wrapped, began); // the span began inside the wrapper's call
        return;
      }
      if (claimed(call.tool, began)) return; // the wrapper ran inside the span
      const rec = getRecorder();
      const agent = this.agentOf(span, rec);
      if (this.byGateway(rec, agent, call.tool)) return;
      held = { rec, decision: this.decide(rec, agent, span, call, false), tool: call.tool, input: true };
    }
    const marker = this.marker(span, call);
    const meta = { telemetry: marker };
    let content: Record<string, unknown>;
    if (span.status?.code === 2 /* SpanStatusCode.ERROR */) content = { error: this.error(span), meta };
    else {
      if (call?.output === undefined) marker.output = "not in the span";
      content = { output: call?.output === undefined ? null : value(call.output), meta };
    }
    if (!held.input && call?.input !== undefined) content.input = value(call.input); // the span named its arguments only after it started
    const d = held.decision;
    held.rec.write("outcome", d.envelope.name, content, { agent: d.envelope.agent, ref: recordHash(d), storeContent: this.storeContent });
  }

  private marker(span: TelemetrySpan, call: ToolCall | null): Record<string, unknown> {
    const ctx = span.spanContext();
    return { source: "opentelemetry", trace_id: ctx.traceId, span_id: ctx.spanId, ...(call ? { convention: call.convention } : {}) };
  }

  private error(span: TelemetrySpan): { type: string; message: string } {
    let type = text(span.attributes?.["error.type"]);
    let message = text(span.status?.message);
    for (const event of span.events ?? []) {
      if (event.name !== "exception") continue;
      type = text(event.attributes?.["exception.type"]) || type;
      message = text(event.attributes?.["exception.message"]) || message;
    }
    return { type: type || "Error", message };
  }

  /** The sampler of the provider this processor belongs to, as text, or null when it is not
   * known: the one given, else the registered global provider's when this processor is one of
   * its processors. */
  private samplerText(): string | null {
    try {
      if (this.sampler) return String(this.sampler);
      const g = trace.getTracerProvider() as any;
      const p = typeof g?.getDelegate === "function" ? g.getDelegate() : g;
      const mine = p?._activeSpanProcessor?._spanProcessors ?? p?.activeSpanProcessor?._spanProcessors ?? p?._registeredSpanProcessors;
      if (!Array.isArray(mine) || !mine.includes(this)) return null;
      const sampler = p._tracerOptions?.sampler ?? p._config?.sampler;
      return sampler ? String(sampler) : null;
    } catch {
      return null;
    }
  }

  /** Write the decision of a tool call, behind the notes that say where it comes from (§2.7):
   * what the telemetry's sampling leaves out, once per agent, and whether this tool's decisions are written
   * at span start or span end, once per tool and again when that changes. The notes and the
   * decision are one run, so nothing lies between them. */
  private decide(rec: Recorder, agent: string, span: TelemetrySpan, call: ToolCall, atStart: boolean): SignedRecord {
    const tool = call.tool;
    rememberTool(agent, tool, this.declare);
    declareBeforeCall(rec, agent);
    const items: { kind: Kind; name: string; content: Record<string, unknown> }[] = [];
    const sampled = this.samplingNoted.get(rec) ?? new Set<string>();
    this.samplingNoted.set(rec, sampled);
    if (!sampled.has(agent)) {
      const sampler = this.samplerText();
      const note = sampler === null ? null : samplingNote(sampler);
      if (note) items.push({ kind: "note", name: note, content: { source: "opentelemetry", sampler } });
    }
    const when = atStart ? "start" : "end";
    const key = `${agent} ${tool}`;
    const notedBy = this.noted.get(rec) ?? new Map<string, "start" | "end">();
    this.noted.set(rec, notedBy);
    if (notedBy.get(key) !== when) {
      items.push({ kind: "note", name: telemetryNoteName(tool, atStart), content: { source: "opentelemetry", tool, decision_written: atStart ? "before" : "after" } });
    }
    const marker: Record<string, unknown> = { ...this.marker(span, call), decision_written: atStart ? "before" : "after" };
    const started = time(span.startTime);
    if (started) marker.span_start = started;
    if (call.id !== undefined) marker.tool_call_id = text(call.id) || (toJsonable(call.id) ?? null);
    if (call.input === undefined) marker.input = atStart ? "not in the span at its start" : "not in the span";
    const meta: Record<string, unknown> = { sdk: `signafaide-js/${VERSION}`, telemetry: marker };
    const name = declaredName(tool);
    if (name !== tool) meta.tool = tool;
    items.push({ kind: "decision", name, content: { input: call.input === undefined ? null : value(call.input), meta } });
    const written = rec.writeRun(items, { agent, storeContent: this.storeContent });
    sampled.add(agent);
    notedBy.set(key, when);
    return written[written.length - 1];
  }

  // --- one call, one decision (with the SDK's wrappers) ----------------------------------

  /** @internal */
  adoptFor(name: string): [Recorder, SignedRecord] | null {
    for (const held of [...this.open.values()].reverse()) {
      if (held.tool !== name || held.adopted) continue;
      held.adopted = true;
      return [held.rec, held.decision];
    }
    return null;
  }
}

/** The decision this plug-in wrote at the start of a span of the tool `name` that is still
 * running and that no wrapper has taken yet: the SDK wrapper running inside that span then
 * writes no second decision (the plug-in writes the outcome when the span ends). */
function adopt(name: string): [Recorder, SignedRecord] | null {
  try {
    let got: [Recorder, SignedRecord] | null = null;
    each((p) => (got ??= p.adoptFor(name)));
    return got;
  } catch {
    return null;
  }
}

/** A wrapper of the SDK has just written the decision of a call of the tool `name`. A span of
 * that tool that began before now, and says only at its end that it is a tool call, is that
 * call's own span and is not recorded again. */
function claim(name: string): void {
  claims.push({ tool: name, at: ++tick });
  if (claims.length > MAX_OPEN) claims.splice(0, claims.length - MAX_OPEN);
}
