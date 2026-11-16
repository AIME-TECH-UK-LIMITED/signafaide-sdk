/** The OpenTelemetry span processor (`signafaide/otel`), with the real OpenTelemetry SDK. */

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as nodeModule from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { SpanStatusCode, context, propagation, trace, type Tracer } from "@opentelemetry/api";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { AlwaysOffSampler, AlwaysOnSampler, BasicTracerProvider, InMemorySpanExporter, ParentBasedSampler, SimpleSpanProcessor, TraceIdRatioBasedSampler, type Sampler } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { tool as langchainTool } from "@langchain/core/tools";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { main } from "../src/cli.js";
import { samplingNote, telemetry, telemetryLines, telemetryNote, telemetryNoteName } from "../src/coverage.js";
import { declareTools, verify, wrapTool } from "../src/index.js";
import { SignafaideSpanProcessor, toolCall, type SignafaideSpanProcessorOptions } from "../src/otel.js";
import { recordHash, type SignedRecord } from "../src/records.js";
import { configure, getRecorder } from "../src/runtime.js";
import { ADAPTERS } from "../src/telemetry.js";
import { VERSION } from "../src/version.js";
import { records, useProject } from "./helpers.js";

const GEN_AI = { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup_order", "gen_ai.tool.call.id": "call_1", "gen_ai.tool.call.arguments": '{"order": "A1"}' };
const OPENINFERENCE = { "openinference.span.kind": "TOOL", "tool.name": "lookup_order", "input.value": '{"order": "A1"}', "input.mime_type": "application/json" };
const TRACELOOP = { "traceloop.span.kind": "tool", "traceloop.entity.name": "lookup_order", "traceloop.entity.input": '{"order": "A1"}' };
const RESULT = { gen_ai: "gen_ai.tool.call.result", openinference: "output.value", traceloop: "traceloop.entity.output" } as const;
const CONVENTIONS = [["gen_ai", GEN_AI], ["openinference", OPENINFERENCE], ["traceloop", TRACELOOP]] as const;

/** A tracer on a provider of the application's own, registered as its tracing set-up, with the
 * processor added in one line. */
function tracer(opts: { sampler?: Sampler; service?: string | null; processor?: SignafaideSpanProcessorOptions } = {}): Tracer {
  const provider = new NodeTracerProvider({
    sampler: opts.sampler ?? new AlwaysOnSampler(),
    resource: resourceFromAttributes(opts.service === null ? {} : { "service.name": opts.service ?? "support-bot" }),
    spanProcessors: [new SignafaideSpanProcessor(opts.processor)],
  });
  provider.register();
  return provider.getTracer("tests");
}

function unregister(): void {
  trace.disable();
  context.disable();
  propagation.disable();
}

const calls = (recs: SignedRecord[]) => recs.filter((r) => r.envelope.kind !== "note").map((r) => `${r.envelope.kind} ${r.envelope.name}`);
const notes = (recs: SignedRecord[]) => recs.filter((r) => r.envelope.kind === "note").map((r) => r.envelope.name);
const names = (recs: SignedRecord[]) => recs.map((r) => r.envelope.name);
const agents = () => getRecorder().state.chains().map((c) => c.split("/")[2]).sort();
const content = (r: SignedRecord) => r.content as any;

async function cli(...args: string[]): Promise<[number, string]> {
  const out: string[] = [];
  const [log, error] = [console.log, console.error];
  console.log = (s: string) => out.push(s);
  console.error = () => undefined;
  try {
    return [await main(args), out.join("\n")];
  } finally {
    [console.log, console.error] = [log, error];
  }
}

describe("signafaide/otel, local only", () => {
  const ctx = useProject();
  afterEach(unregister);

  for (const [convention, attributes] of CONVENTIONS) {
    it(`${convention}: a span that says at its start that it is a tool call`, () => {
      const t = tracer();
      t.startActiveSpan("execute_tool lookup_order", { attributes }, (span) => {
        // The tool body: the signed decision is already in the chain, and no outcome yet.
        expect(calls(records("support-bot"))).toEqual(["decision lookup_order"]);
        span.setAttribute(RESULT[convention], '{"status": "shipped"}');
        span.end();
      });
      const recs = records("support-bot");
      expect(calls(recs)).toEqual(["decision lookup_order", "outcome lookup_order"]);
      const [decision, outcome] = recs.filter((r) => r.envelope.kind !== "note");
      expect(content(decision).input).toEqual({ order: "A1" });
      const marker = content(decision).meta.telemetry;
      expect(marker).toMatchObject({ source: "opentelemetry", convention, decision_written: "before" });
      expect(marker.trace_id).toHaveLength(32);
      expect(marker.span_id).toHaveLength(16);
      expect(marker.span_start).toMatch(/Z$/);
      expect(content(decision).meta.sdk).toBe(`signafaide-js/${VERSION}`);
      expect(outcome.envelope.ref).toBe(recordHash(decision));
      expect(content(outcome).output).toEqual({ status: "shipped" });
      expect(content(outcome).meta.telemetry).toEqual({ source: "opentelemetry", convention, trace_id: marker.trace_id, span_id: marker.span_id });
      // In the envelopes, so a hash-only verifier sees it: the note right before the decision.
      const all = names(recs);
      expect(all[all.indexOf("lookup_order") - 1]).toBe("signafaide.telemetry/start/lookup_order");
      expect(all).not.toContain("signafaide.telemetry/end/lookup_order");
    });

    it(`${convention}: a span that says only at its end that it is a tool call`, () => {
      const t = tracer();
      t.startActiveSpan("lookup_order", (span) => {
        span.setAttributes(attributes); // set after the span started: the processor's start hook has run
        expect(agents()).toEqual([]); // the tool body runs with nothing recorded yet
        span.setAttribute(RESULT[convention], "shipped");
        span.end();
      });
      const recs = records("support-bot");
      expect(calls(recs)).toEqual(["decision lookup_order", "outcome lookup_order"]);
      const [decision, outcome] = recs.filter((r) => r.envelope.kind !== "note");
      expect(content(decision).input).toEqual({ order: "A1" });
      expect(content(outcome).output).toBe("shipped");
      expect(content(decision).meta.telemetry).toMatchObject({ decision_written: "after", convention });
      expect(outcome.envelope.ref).toBe(recordHash(decision));
      const all = names(recs);
      expect(all[all.indexOf("lookup_order") - 1]).toBe("signafaide.telemetry/end/lookup_order");
    });
  }

  it("toolCall reads each convention", () => {
    expect(toolCall("execute_tool refund", { "gen_ai.operation.name": "execute_tool" })).toEqual({ convention: "gen_ai", tool: "refund" });
    expect(toolCall("x", { "gen_ai.operation.name": "execute_tool", "traceloop.entity.name": "refund", "traceloop.span.kind": "task" })?.tool).toBe("refund");
    expect(toolCall("running tool", { "gen_ai.operation.name": "execute_tool" })?.tool).toBe("running tool"); // only the span's name names it
    expect(toolCall("", { "gen_ai.operation.name": "execute_tool" })).toBeNull(); // nothing names the tool
    expect(toolCall("refund", { "openinference.span.kind": "TOOL" })).toEqual({ convention: "openinference", tool: "refund" });
    expect(toolCall("refund.tool", { "traceloop.span.kind": "tool" })).toEqual({ convention: "traceloop", tool: "refund" });
    expect(toolCall("chat gpt", { "gen_ai.operation.name": "chat" })).toBeNull();
    expect(toolCall("agent", { "openinference.span.kind": "AGENT", "traceloop.span.kind": "workflow" })).toBeNull();
    expect(toolCall("x", undefined)).toBeNull();
    expect(toolCall("x", { ...GEN_AI, "gen_ai.tool.call.result": "ok" })).toEqual({ convention: "gen_ai", tool: "lookup_order", id: "call_1", input: '{"order": "A1"}', output: "ok" });
  });

  it("spans that are not tool calls write nothing", () => {
    const t = tracer();
    t.startActiveSpan("chat model", { attributes: { "gen_ai.operation.name": "chat" } }, (outer) => {
      t.startActiveSpan("GET /orders", { attributes: { "http.request.method": "GET" } }, (inner) => inner.end());
      outer.end();
    });
    expect(agents()).toEqual([]);
  });

  it("arguments named only after the start go into the outcome", () => {
    const span = tracer().startSpan("execute_tool refund", { attributes: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund" } });
    span.setAttribute("gen_ai.tool.call.arguments", '{"amount": 5}');
    span.end();
    const [decision, outcome] = records("support-bot").filter((r) => r.envelope.kind !== "note");
    expect(content(decision).input).toBeNull();
    expect(content(decision).meta.telemetry.input).toBe("not in the span at its start");
    expect(content(outcome).input).toEqual({ amount: 5 });
    expect(content(outcome).output).toBeNull();
    expect(content(outcome).meta.telemetry.output).toBe("not in the span");
  });

  it("an error span gives an error outcome", () => {
    const t = tracer();
    const first = t.startSpan("execute_tool lookup_order", { attributes: GEN_AI });
    first.recordException(new RangeError("no such order"));
    first.setStatus({ code: SpanStatusCode.ERROR, message: "no such order" });
    first.end();
    const second = t.startSpan("refund");
    second.setAttributes({ "openinference.span.kind": "TOOL", "tool.name": "refund" });
    second.setStatus({ code: SpanStatusCode.ERROR, message: "card declined" });
    second.end();
    const outcomes = records("support-bot").filter((r) => r.envelope.kind === "outcome");
    expect(content(outcomes[0]).error).toEqual({ type: "RangeError", message: "no such order" });
    expect(content(outcomes[1]).error).toEqual({ type: "Error", message: "card declined" });
    expect(content(outcomes[0])).not.toHaveProperty("output");
  });

  it("a tool recorded both ways gets a note each time it changes", () => {
    const t = tracer();
    for (const atStart of [true, true, false, false, true]) {
      const span = t.startSpan("x", atStart ? { attributes: GEN_AI } : {});
      span.setAttributes(GEN_AI);
      span.end();
    }
    const recs = records("support-bot");
    expect(notes(recs).filter((n) => n.startsWith("signafaide.telemetry/"))).toEqual([
      "signafaide.telemetry/start/lookup_order",
      "signafaide.telemetry/end/lookup_order",
      "signafaide.telemetry/start/lookup_order",
    ]);
    // Each decision's marker is the telemetry note of its tool that comes last before it.
    let last: string | undefined;
    for (const r of recs) {
      const n = telemetryNote(r.envelope.kind, r.envelope.name);
      if (n && typeof n !== "string") last = n.decision;
      else if (r.envelope.kind === "decision") expect(content(r).meta.telemetry.decision_written).toBe(last);
    }
    const got = telemetry(recs.map((r) => r.envelope))!;
    expect(got).toEqual({ tools: [{ name: "lookup_order", decision: "both" }], sampled: false, parent_sampled: false });
    expect(telemetryLines("support-bot", got)).toEqual(["support-bot: 1 tool is recorded from telemetry spans: lookup_order (decisions written before and after the tool ran)"]);
  });

  it("a long tool name is cut as a declaration cuts it", async () => {
    const tool = "t".repeat(140);
    tracer().startSpan("x", { attributes: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool } }).end();
    const recs = records("support-bot");
    const decision = recs.find((r) => r.envelope.kind === "decision")!;
    expect(decision.envelope.name).toHaveLength(101);
    expect(content(decision).meta.tool).toBe(tool);
    expect(notes(recs)).toContain(telemetryNoteName(tool, true));
    expect(telemetryNoteName(tool, true)).toHaveLength(128);
    expect((await verify()).ok).toBe(true);
  });

  // --- what a verifier sees ---------------------------------------------------------------

  it("the markers are signed and every verifier output carries them", async () => {
    const t = tracer({ sampler: new ParentBasedSampler({ root: new AlwaysOnSampler() }) });
    t.startSpan("x", { attributes: GEN_AI }).end();
    const span = t.startSpan("refund");
    span.setAttributes({ "openinference.span.kind": "TOOL" });
    span.end();
    const report = await verify();
    expect(report.ok).toBe(true);
    expect(report.check("content").status).toBe("pass");
    expect(report.check("record_sig").status).toBe("pass");
    const [chain] = getRecorder().state.chains();
    expect(report.telemetry).toEqual({ [chain]: { tools: [{ name: "lookup_order", decision: "before" }, { name: "refund", decision: "after" }], sampled: false, parent_sampled: true } });
    expect(JSON.parse(JSON.stringify(report.toJSON())).telemetry).toEqual(report.telemetry);
    const lines = String(report).split("\n");
    expect(lines).toContain(`telemetry: ${chain}: 2 tools are recorded from telemetry spans: lookup_order (decision written before the tool ran), refund (decision written after the tool ran)`);
    expect(lines).toContain(`telemetry: ${chain}: telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded`);
    expect(lines).toContain(`coverage: ${chain}: all 2 declared tools are recorded`);
    // The marker in the content is under the signature: changing it fails the content hash.
    const file = getRecorder().state.chainPath(chain);
    const text = fs.readFileSync(file, "utf8");
    expect(text).toContain('"decision_written":"before"');
    fs.writeFileSync(file, text.replace('"decision_written":"before"', '"decision_written":"after"'));
    const tampered = await verify();
    expect(tampered.ok).toBe(false);
    expect(tampered.check("content").status).toBe("fail");
  });

  it("no telemetry notes, no telemetry lines", async () => {
    wrapTool((x: number) => x, { name: "act" })(1);
    const report = await verify();
    expect(report.telemetry).toEqual({});
    expect(JSON.parse(JSON.stringify(report.toJSON())).telemetry).toEqual({});
    expect(String(report)).not.toContain("telemetry:");
  });

  // --- sampling -----------------------------------------------------------------------------

  const SAMPLED_LINE = "records come from sampled telemetry: some tool calls may not be recorded";
  const PARENT_SAMPLED_LINE = "telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded";
  /** A sampler of the application's own: what it drops is not known. */
  class CustomSampler extends TraceIdRatioBasedSampler {
    override toString() {
      return "MySampler";
    }
  }
  const SAMPLERS: [string, Sampler | undefined, string, string, "sampled" | "parent_sampled"][] = [
    // Samplers that can drop traces this program starts.
    ["ratio", new TraceIdRatioBasedSampler(1), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"],
    ["parent-based with a ratio root", new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(1) }), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"],
    ["parent-based that samples under sampled local parents", new ParentBasedSampler({ root: new AlwaysOnSampler(), localParentSampled: new TraceIdRatioBasedSampler(1) }), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"],
    ["custom", new CustomSampler(1), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"],
    // OpenTelemetry's default: every trace this program starts is kept; the caller decides for its own.
    ["parent-based with an always-on root", new ParentBasedSampler({ root: new AlwaysOnSampler() }), "signafaide.telemetry_parent_sampled", PARENT_SAMPLED_LINE, "parent_sampled"],
    ["the provider's default", undefined, "signafaide.telemetry_parent_sampled", PARENT_SAMPLED_LINE, "parent_sampled"],
  ];
  for (const [what, sampler, name, line, key] of SAMPLERS) {
    it(`a sampler that is not always-on is noted once (${what})`, async () => {
      let t: Tracer;
      if (sampler) t = tracer({ sampler });
      else {
        const provider = new NodeTracerProvider({ resource: resourceFromAttributes({ "service.name": "support-bot" }), spanProcessors: [new SignafaideSpanProcessor()] });
        provider.register();
        t = provider.getTracer("tests");
      }
      for (let i = 0; i < 3; i++) t.startSpan("x", { attributes: GEN_AI }).end();
      const recs = records("support-bot");
      expect(notes(recs)).not.toContain(name === "signafaide.telemetry_sampled" ? "signafaide.telemetry_parent_sampled" : "signafaide.telemetry_sampled");
      const noted = recs.filter((r) => r.envelope.name === name);
      expect(noted).toHaveLength(1);
      expect(noted[0].envelope.kind).toBe("note");
      expect(noted[0].content).toEqual({ source: "opentelemetry", sampler: (sampler ?? new ParentBasedSampler({ root: new AlwaysOnSampler() })).toString() });
      expect(noted[0].envelope.seq).toBeLessThan(recs.find((r) => r.envelope.kind === "decision")!.envelope.seq);
      const [chain] = getRecorder().state.chains();
      const about = (out: string) => out.split("\n").filter((x) => x.includes("sampled telemetry") || x.includes("telemetry sampling"));
      let [code, out] = await cli("verify");
      expect(code).toBe(0);
      expect(about(out)).toEqual([`telemetry: ${chain}: ${line}`]);
      expect(out.trim().split("\n").at(-1)).toMatch(/^PASS/);
      [code, out] = await cli("status");
      expect(code).toBe(0);
      expect(about(out)).toEqual([`note: ${chain}: ${line}`]);
      expect(out.split("\n")).toContain(`note: ${chain}: 1 tool is recorded from telemetry spans: lookup_order (decision written before the tool ran)`);
      [code, out] = await cli("verify", "--json");
      const got = JSON.parse(out).telemetry[chain];
      expect(got[key]).toBe(true);
      expect(got[key === "sampled" ? "parent_sampled" : "sampled"]).toBe(false);
    });
  }

  it("samplingNote reads a sampler description of either SDK", () => {
    expect(samplingNote("AlwaysOnSampler")).toBeNull();
    expect(samplingNote(new ParentBasedSampler({ root: new AlwaysOnSampler() }).toString())).toBe("signafaide.telemetry_parent_sampled");
    expect(samplingNote("ParentBased{root:AlwaysOnSampler,remoteParentSampled:AlwaysOnSampler,remoteParentNotSampled:AlwaysOffSampler,localParentSampled:AlwaysOnSampler,localParentNotSampled:AlwaysOffSampler}")).toBe("signafaide.telemetry_parent_sampled");
    for (const other of ["AlwaysOffSampler", "TraceIdRatioBased{0.1}", "ParentBased{root=TraceIdRatioBased{0.1}, remoteParentSampled=AlwaysOnSampler, localParentSampled=AlwaysOnSampler}", "ParentBased{root:AlwaysOnSampler,remoteParentSampled:AlwaysOffSampler,localParentSampled:AlwaysOnSampler}", "ParentBased{root:AlwaysOnSampler}", "MySampler", ""]) {
      expect(samplingNote(other), other).toBe("signafaide.telemetry_sampled");
    }
  });

  it("a LangChain tool message in the result names the tool", () => {
    const message = { lc: 1, type: "constructor", id: ["langchain_core", "messages", "ToolMessage"], kwargs: { content: "ok", name: "lookup_order" } };
    const base = { "gen_ai.operation.name": "execute_tool", "traceloop.entity.name": "DynamicStructuredTool" };
    expect(toolCall("execute_tool DynamicStructuredTool", base)?.tool).toBe("DynamicStructuredTool");
    expect(toolCall("x", { ...base, "traceloop.entity.output": JSON.stringify(message) })?.tool).toBe("lookup_order");
    expect(toolCall("x", { ...base, "gen_ai.tool.call.result": JSON.stringify({ output: message }) })?.tool).toBe("lookup_order");
    // Anything else in a result is content, never a name.
    for (const result of ['the ToolMessage said {"name": "refund"}', JSON.stringify({ name: "refund", id: ["ToolMessage"] }), JSON.stringify({ ...message, id: ["langchain_core", "messages", "AIMessage"] }), JSON.stringify({ ...message, kwargs: { name: 5 } })]) {
      expect(toolCall("x", { ...base, "traceloop.entity.output": result })?.tool, result).toBe("DynamicStructuredTool");
    }
  });

  it("an always-on sampler is not noted", async () => {
    tracer({ sampler: new AlwaysOnSampler() }).startSpan("x", { attributes: GEN_AI }).end();
    expect(notes(records("support-bot")).filter((n) => n.includes("sampled"))).toEqual([]);
    for (const command of ["verify", "status"]) {
      const out = (await cli(command))[1];
      expect(out).not.toContain("sampled telemetry");
      expect(out).not.toContain("telemetry sampling");
    }
  });

  it("a provider that is not the registered one: the sampler is taken from the option, else it is not known and no note is written", () => {
    let sampler: Sampler = new TraceIdRatioBasedSampler(1);
    const provider = (processor: SignafaideSpanProcessor) => new BasicTracerProvider({ sampler, resource: resourceFromAttributes({ "service.name": "support-bot" }), spanProcessors: [processor] });
    provider(new SignafaideSpanProcessor()).getTracer("tests").startSpan("x", { attributes: GEN_AI }).end();
    expect(notes(records("support-bot")).filter((n) => n.includes("sampled"))).toEqual([]);
    provider(new SignafaideSpanProcessor({ sampler })).getTracer("tests").startSpan("x", { attributes: GEN_AI }).end();
    const sampled = records("support-bot").filter((r) => r.envelope.name === "signafaide.telemetry_sampled");
    expect(sampled.map((r) => r.content)).toEqual([{ source: "opentelemetry", sampler: "TraceIdRatioBased{1}" }]);
    // The option covers the parent-based case too (a new process: another agent's chain here).
    sampler = new ParentBasedSampler({ root: new AlwaysOnSampler() });
    provider(new SignafaideSpanProcessor({ sampler, agent: "second-bot" })).getTracer("tests").startSpan("x", { attributes: GEN_AI }).end();
    expect(notes(records("second-bot")).filter((n) => n.includes("sampled"))).toEqual(["signafaide.telemetry_parent_sampled"]);
  });

  it("a span the sampler drops is not recorded", () => {
    tracer({ sampler: new AlwaysOffSampler() }).startSpan("x", { attributes: GEN_AI }).end();
    expect(agents()).toEqual([]);
  });

  // --- one tool call, one decision and one outcome -------------------------------------------

  const lookupOrder = (order: string) => ({ order, status: "shipped" });

  for (const atStart of [true, false]) {
    it(`a wrapped tool whose span begins inside the wrapper (${atStart ? "said at start" : "said at end"})`, async () => {
      const t = tracer();
      const traced = async (order: string) =>
        t.startActiveSpan("x", atStart ? { attributes: GEN_AI } : {}, async (span) => {
          span.setAttributes(GEN_AI);
          await new Promise((r) => setTimeout(r, 1));
          const out = lookupOrder(order);
          span.end();
          return out;
        });
      const wrapped = wrapTool(traced, { name: "lookup_order", agent: "support-bot" });
      expect((await wrapped("A1")).status).toBe("shipped");
      const recs = records("support-bot");
      expect(calls(recs)).toEqual(["decision lookup_order", "outcome lookup_order"]);
      expect(content(recs.at(-2)!).meta).not.toHaveProperty("telemetry"); // the wrapper's own records
      expect(notes(recs).filter((n) => n.startsWith("signafaide.telemetry"))).toEqual([]);
      // The next call of the same tool that is not wrapped is recorded from its span.
      t.startSpan("x", { attributes: GEN_AI }).end();
      expect(calls(records("support-bot")).slice(2)).toEqual(["decision lookup_order", "outcome lookup_order"]);
    });

    it(`a wrapped tool called inside its span (${atStart ? "said at start" : "said at end"})`, () => {
      const t = tracer();
      const wrapped = wrapTool(lookupOrder, { name: "lookup_order", agent: "support-bot" });
      t.startActiveSpan("x", atStart ? { attributes: GEN_AI } : {}, (span) => {
        span.setAttributes(GEN_AI);
        expect(wrapped("A1").status).toBe("shipped");
        span.end();
      });
      const recs = records("support-bot");
      expect(calls(recs)).toEqual(["decision lookup_order", "outcome lookup_order"]);
      // At span start the processor wrote the decision and the wrapper took it over; otherwise
      // the wrapper wrote it and the span was not recorded at its end.
      expect("telemetry" in content(recs.find((r) => r.envelope.kind === "decision")!).meta).toBe(atStart);
    });
  }

  for (const atStart of [true, false]) {
    it(`a wrapped tool called while its span is open but not the active span (${atStart ? "said at start" : "said at end"})`, () => {
      const t = tracer();
      const wrapped = wrapTool(lookupOrder, { name: "lookup_order", agent: "support-bot" });
      let span = t.startSpan("x", atStart ? { attributes: GEN_AI } : {}); // as a callback-based instrumentation starts it
      span.setAttributes(GEN_AI);
      expect(wrapped("A1").status).toBe("shipped");
      span.end();
      expect(calls(records("support-bot"))).toEqual(["decision lookup_order", "outcome lookup_order"]);
      // A later call of the tool with no wrapper around it is recorded from its span.
      span = t.startSpan("x");
      span.setAttributes(GEN_AI);
      span.end();
      expect(calls(records("support-bot"))).toHaveLength(4);
    });
  }

  /** A span built after its call has ended, as a tracing tool that exports finished runs builds
   * it: it carries the call's own start and end times. */
  const now = () => performance.timeOrigin + performance.now();
  function lateSpan(t: Tracer, attributes: Record<string, string>, start: number, end: number, atStart: boolean): void {
    const span = t.startSpan("x", atStart ? { startTime: start, attributes } : { startTime: start });
    span.setAttributes(attributes);
    span.end(end);
  }
  const { "gen_ai.tool.call.id": _id, ...GEN_AI_NO_ID } = GEN_AI;

  for (const atStart of [true, false]) {
    const said = atStart ? "said at start" : "said at end";

    it(`a span built after a wrapped call has ended is not recorded again (${said})`, () => {
      const t = tracer();
      let ran = 0;
      const wrapped = wrapTool((order: string) => ((ran = now()), lookupOrder(order)), { name: "lookup_order", agent: "support-bot" });
      wrapped("A1");
      // The call has ended, and only now does its span arrive, dated as the call was.
      lateSpan(t, GEN_AI_NO_ID, ran, now(), atStart);
      const recs = records("support-bot");
      expect(calls(recs)).toEqual(["decision lookup_order", "outcome lookup_order"]);
      expect(notes(recs).filter((n) => n.startsWith("signafaide.telemetry/"))).toEqual([]);
      // One wrapper call answers for one span: a second span of those times is another call's.
      lateSpan(t, GEN_AI_NO_ID, ran, now(), atStart);
      expect(calls(records("support-bot"))).toHaveLength(4);
    });

    it(`a late span of another call of the same tool is recorded (${said})`, () => {
      const t = tracer();
      wrapTool(lookupOrder, { name: "lookup_order", agent: "support-bot" })("A1");
      // Same tool name, but the span's own times lie outside the wrapped call: not that call.
      const before = now() - 10_000;
      lateSpan(t, GEN_AI_NO_ID, before, before + 1, atStart);
      const recs = records("support-bot");
      expect(calls(recs)).toEqual(["decision lookup_order", "outcome lookup_order", "decision lookup_order", "outcome lookup_order"]);
      expect(content(recs.at(-2)!).meta.telemetry.decision_written).toBe(atStart ? "before" : "after");
    });

    it(`a late span is matched by its tool call id when the wrapper has one (${said})`, async () => {
      const t = tracer();
      const lookup = langchainTool(async ({ order }: { order: string }) => `${order}: shipped`, { name: "lookup_order", description: "Look an order up.", schema: z.object({ order: z.string() }) });
      const wrapped = wrapTool(lookup, { agent: "support-bot" });
      const started = now();
      await wrapped.invoke({ type: "tool_call", id: "call_1", name: "lookup_order", args: { order: "A1" } });
      // Another call of the tool, by its id, although its times overlap the wrapped call: recorded.
      lateSpan(t, { ...GEN_AI, "gen_ai.tool.call.id": "call_2" }, started, now(), atStart);
      expect(calls(records("support-bot"))).toHaveLength(4);
      // The wrapped call's own span, by its id, whatever its times say: not recorded again.
      const longAgo = started - 3_600_000;
      lateSpan(t, GEN_AI, longAgo, longAgo + 1, atStart);
      expect(calls(records("support-bot"))).toHaveLength(4);
      // The id answered for one span only.
      lateSpan(t, GEN_AI, longAgo, longAgo + 1, atStart);
      expect(calls(records("support-bot"))).toHaveLength(6);
    });

    for (const [what, sampler, name] of [
      ["parent-based", new ParentBasedSampler({ root: new AlwaysOnSampler() }), "signafaide.telemetry_parent_sampled"],
      ["ratio", new TraceIdRatioBasedSampler(1), "signafaide.telemetry_sampled"],
      ["always-on", new AlwaysOnSampler(), null],
    ] as const) {
      it(`the sampling note is written whether the decision is written at span start or end (${what}, ${said})`, () => {
        const t = tracer({ sampler });
        for (let i = 0; i < 2; i++) {
          const span = t.startSpan("x", atStart ? { attributes: GEN_AI } : {});
          span.setAttributes(GEN_AI);
          span.end();
        }
        const recs = records("support-bot");
        expect(notes(recs).filter((n) => n.includes("sampled"))).toEqual(name ? [name] : []);
        expect(notes(recs)).toContain(`signafaide.telemetry/${atStart ? "start" : "end"}/lookup_order`);
      });
    }
  }

  it("LangSmith's attribute names for arguments and result", () => {
    const attributes = { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund", "gen_ai.prompt": '{"order":"A1","amount":5}' };
    expect(toolCall("refund", { ...attributes, "gen_ai.completion": '{"output":"refunded"}' })).toMatchObject({ input: '{"order":"A1","amount":5}', output: '{"output":"refunded"}' });
    // The convention's own names come first when a span has both.
    expect(toolCall("refund", { ...attributes, "gen_ai.tool.call.arguments": '{"order":"B2"}' })?.input).toBe('{"order":"B2"}');
    // They are read on tool-call spans only.
    expect(toolCall("chat", { "gen_ai.operation.name": "chat", "gen_ai.prompt": "hello" })).toBeNull();
    const span = tracer().startSpan("refund");
    span.setAttributes({ ...attributes, "gen_ai.completion": '{"output":"refunded"}' });
    span.end();
    const [decision, outcome] = records("support-bot").filter((r) => r.envelope.kind !== "note");
    expect(content(decision).input).toEqual({ order: "A1", amount: 5 });
    expect(content(outcome).output).toEqual({ output: "refunded" });
  });

  it("a different tool called inside a wrapped tool is still recorded", () => {
    const t = tracer();
    const delegate = (task: string) => {
      t.startSpan("x", { attributes: { ...GEN_AI, "gen_ai.tool.name": "search" } }).end();
      return task;
    };
    wrapTool(delegate, { name: "delegate", agent: "support-bot" })("find it");
    expect(calls(records("support-bot"))).toEqual(["decision delegate", "decision search", "outcome search", "outcome delegate"]);
  });

  it("a tool an MCP gateway records is left to the gateway", () => {
    // What a gateway started with --name-prefix fs. keeps in tools/<agent>.json (SPEC §8).
    ctx.rec.state.declareTools("support-bot", "gateway:fs.", { "fs.read_file": true, "fs.write_file": true }, () => "");
    const t = tracer();
    for (const tool of ["read_file", "fs.write_file", "send_email"]) {
      t.startSpan("x", { attributes: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool } }).end();
      const span = t.startSpan("x");
      span.setAttributes({ "openinference.span.kind": "TOOL", "tool.name": tool });
      span.end();
    }
    expect(calls(records("support-bot"))).toEqual(["decision send_email", "outcome send_email", "decision send_email", "outcome send_email"]);
  });

  // --- it never breaks the application ---------------------------------------------------

  it("nothing is thrown when the state folder cannot be written", () => {
    const blocker = path.join(ctx.root, "not-a-folder");
    fs.writeFileSync(blocker, "");
    process.env.SIGNAFAIDE_HOME = path.join(blocker, ".signafaide");
    configure({ quiet: true, flushIntervalMs: 3_600_000 });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      const t = tracer();
      const ran: string[] = [];
      for (let i = 0; i < 3; i++) {
        t.startActiveSpan("x", { attributes: GEN_AI }, (span) => {
          ran.push("start");
          span.end();
        });
        t.startActiveSpan("x", (span) => {
          span.setAttributes(OPENINFERENCE);
          ran.push("end");
          span.end();
        });
      }
      expect(ran).toEqual(["start", "end", "start", "end", "start", "end"]); // every tool ran
      const warnings = warn.mock.calls.map((c) => String(c[0])).filter((m) => m.includes("could not record a tool call from its span"));
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("the tool runs all the same");
    } finally {
      warn.mockRestore();
      delete process.env.SIGNAFAIDE_HOME;
    }
  });

  it("a span with unusual values is recorded or skipped without throwing", () => {
    const t = tracer();
    const span = t.startSpan("x", { attributes: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "odd", "gen_ai.tool.call.arguments": "{not json", "gen_ai.tool.call.id": 7 } });
    span.setAttribute("gen_ai.tool.call.result", ["a", "b"]);
    span.end();
    const [decision, outcome] = records("support-bot").filter((r) => r.envelope.kind !== "note");
    expect(content(decision).input).toBe("{not json");
    expect(content(outcome).output).toEqual(["a", "b"]);
    t.startSpan("x", { attributes: { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": 5 } }).end(); // the attribute is not a name: the span's own name is used
    expect(calls(records("support-bot")).slice(2)).toEqual(["decision x", "outcome x"]);
  });

  it("recording turned off writes nothing", () => {
    process.env.SIGNAFAIDE_DISABLED = "1";
    try {
      tracer().startSpan("x", { attributes: GEN_AI }).end();
      expect(agents()).toEqual([]);
    } finally {
      delete process.env.SIGNAFAIDE_DISABLED;
    }
  });

  it("the processor exports nothing and leaves other processors alone", async () => {
    const exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({
      sampler: new AlwaysOnSampler(),
      resource: resourceFromAttributes({ "service.name": "support-bot" }),
      spanProcessors: [new SignafaideSpanProcessor(), new SimpleSpanProcessor(exporter)],
    });
    provider.getTracer("tests").startSpan("x", { attributes: GEN_AI }).end();
    await provider.forceFlush();
    const [span] = exporter.getFinishedSpans();
    await provider.shutdown();
    expect(span.attributes).toEqual(GEN_AI); // the span is as the application made it
    expect(ctx.service.calls).toEqual([]); // no API key: nothing left the machine
  });

  // --- agent name, tool declaration ---------------------------------------------------------

  it("agent name: explicit, then service.name, then the default", () => {
    const run = (opts: Parameters<typeof tracer>[0]) => {
      tracer(opts).startSpan("x", { attributes: GEN_AI }).end();
      unregister();
    };
    run({ processor: { agent: "claims-bot" }, service: "Support Bot" });
    run({ service: "Support Bot" }); // normalised like a folder name
    run({ service: null }); // the SDK names it unknown_service: the SDK's default applies
    expect(agents()).toEqual(["claims-bot", "claims-project", "support-bot"]);
    expect(() => new SignafaideSpanProcessor({ agent: "Not A Name" })).toThrow(/is invalid/);
  });

  it("tools seen in spans are declared as recorded, and no more", async () => {
    const t = tracer();
    for (const tool of ["lookup_order", "refund"]) t.startSpan("x", { attributes: { ...GEN_AI, "gen_ai.tool.name": tool } }).end();
    const report = await verify();
    const [chain] = getRecorder().state.chains();
    expect(report.coverage[chain].declared).toEqual([{ name: "lookup_order", recorded: true }, { name: "refund", recorded: true }]);
    expect(report.coverage[chain].undeclared_recorded).toEqual([]);
    // With the agent's full list given, a tool no span has shown is declared as not recorded.
    declareTools(["lookup_order", "refund", "web_search"], { agent: "support-bot" });
    expect(String(await verify()).split("\n")).toContain(`coverage: ${chain}: 1 declared tool is not recorded: web_search`);
  });

  it("declareTools: false declares nothing", () => {
    tracer({ processor: { declareTools: false } }).startSpan("x", { attributes: GEN_AI }).end();
    expect(notes(records("support-bot"))).not.toContain("signafaide.tools");
  });
});

describe("signafaide/otel, after the opt-in", () => {
  const ctx = useProject({ optIn: true });
  afterEach(unregister);

  it("a strict wrapper inside a recorded span still waits for the receipt", async () => {
    const t = tracer();
    const seen: boolean[] = [];
    const wire = (amount: number) => {
      const decision = records("support-bot").find((r) => r.envelope.kind === "decision")!;
      seen.push("receipt" in decision); // the witness has co-signed the decision when the tool runs
      return amount;
    };
    const wrapped = wrapTool(wire, { name: "lookup_order", agent: "support-bot", strict: true });
    await t.startActiveSpan("x", { attributes: GEN_AI }, async (span) => {
      await wrapped(5);
      span.end();
    });
    expect(calls(records("support-bot"))).toEqual(["decision lookup_order", "outcome lookup_order"]);
    expect(seen).toEqual([true]);
  });

  it("the client header names the adapter", async () => {
    const t = tracer();
    t.startSpan("x", { attributes: GEN_AI }).end();
    ctx.service.clientIds.length = 0;
    expect((await ctx.rec.flush()).left).toBe(0);
    expect(ctx.service.clientIds.length).toBeGreaterThan(0);
    for (const c of ctx.service.clientIds) expect(c).toContain("adapter=otel;");
    process.env.SIGNAFAIDE_TELEMETRY = "0";
    try {
      ctx.service.clientIds.length = 0;
      t.startSpan("x", { attributes: GEN_AI }).end();
      await ctx.rec.flush();
      expect(ctx.service.clientIds.length).toBeGreaterThan(0);
      for (const c of ctx.service.clientIds) expect(c).not.toContain("adapter=");
    } finally {
      delete process.env.SIGNAFAIDE_TELEMETRY;
    }
    expect(ADAPTERS.has("otel")).toBe(true);
  });

  it("verify passes locally, then co-signed, then as a pack", async () => {
    const t = tracer({ sampler: new ParentBasedSampler({ root: new AlwaysOnSampler() }) });
    const first = t.startSpan("x", { attributes: GEN_AI });
    first.setAttribute("gen_ai.tool.call.result", "shipped");
    first.end();
    const second = t.startSpan("refund");
    second.setAttributes({ "openinference.span.kind": "TOOL", "input.value": "A1" });
    second.setStatus({ code: SpanStatusCode.ERROR, message: "declined" });
    second.end();
    let [code, out] = await cli("verify");
    expect(code).toBe(0);
    expect(out).toContain("PASS");
    expect(out).toContain("nothing co-signed yet");
    const sent = await ctx.rec.flush();
    expect(sent.left).toBe(0);
    expect(Object.keys(sent.errors)).toEqual([]);
    // Hash-only: what the witness got holds no input, output or span data.
    const stored = JSON.stringify([...ctx.service.projects.values()].map((p: any) => [...p.records.values()]));
    expect(stored).toContain("lookup_order");
    expect(stored).not.toContain("shipped");
    expect(stored).not.toContain("trace_id");
    [code, out] = await cli("verify");
    expect(code).toBe(0);
    expect(out).toContain("PASS");
    expect(out).not.toContain("nothing co-signed yet");
    for (const r of records("support-bot")) expect(r).toHaveProperty("receipt");
    const pack = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sfa-otel-")), "pack.json");
    expect((await cli("export", "-o", pack))[0]).toBe(0);
    [code, out] = await cli("verify", pack);
    const lines = out.split("\n");
    expect(code).toBe(0);
    expect(lines.some((l) => l.startsWith("PASS"))).toBe(true);
    expect(lines).toContain("telemetry: support-bot: 2 tools are recorded from telemetry spans: lookup_order (decision written before the tool ran), refund (decision written after the tool ran)");
    expect(lines).toContain("telemetry: support-bot: telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded");
    [code, out] = await cli("verify", pack, "--json");
    expect(code).toBe(0);
    expect(JSON.parse(out).telemetry).toEqual({ "support-bot": { tools: [{ name: "lookup_order", decision: "before" }, { name: "refund", decision: "after" }], sampled: false, parent_sampled: true } });
  });
});

describe("the package without OpenTelemetry installed", () => {
  const dist = path.resolve(__dirname, "../dist");

  it("only the signafaide/otel entry point refers to an OpenTelemetry package", () => {
    const built = fs.readdirSync(dist).filter((f) => /\.(js|cjs)$/.test(f));
    expect(built).toContain("index.js");
    expect(built.filter((f) => fs.readFileSync(path.join(dist, f), "utf8").includes("@opentelemetry/")).sort()).toEqual(["otel.cjs", "otel.js"]);
  });

  // The blocking hook needs module.registerHooks (Node.js 22.15 or later).
  it.skipIf(typeof (nodeModule as any).registerHooks !== "function")("the core entry points load and record; only signafaide/otel needs OpenTelemetry", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-no-otel-"));
    fs.mkdirSync(path.join(dir, ".git"));
    // Every attempt to load an OpenTelemetry package fails, as on a machine that has none.
    fs.writeFileSync(
      path.join(dir, "block.mjs"),
      `import { registerHooks } from "node:module";
registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith("@opentelemetry/")) throw Object.assign(new Error("Cannot find package '" + specifier + "'"), { code: "ERR_MODULE_NOT_FOUND" });
  return next(specifier, context);
} });
`,
    );
    fs.writeFileSync(
      path.join(dir, "run.mjs"),
      `import { createRequire } from "node:module";
const sfa = await import(${JSON.stringify(path.join(dist, "index.js"))});
await import(${JSON.stringify(path.join(dist, "core.js"))});
createRequire(import.meta.url)(${JSON.stringify(path.join(dist, "index.cjs"))});
sfa.record((x) => x, { name: "act" })(1);
if (!(await sfa.verify()).ok) throw new Error("verify failed");
let failed = "";
try { await import(${JSON.stringify(path.join(dist, "otel.js"))}); } catch (e) { failed = String(e.message); }
if (!failed.includes("@opentelemetry/api")) throw new Error("signafaide/otel loaded without OpenTelemetry: " + failed);
console.log("ok");
`,
    );
    const out = execFileSync(process.execPath, ["--import", path.join(dir, "block.mjs"), path.join(dir, "run.mjs")], { cwd: dir, encoding: "utf8", env: { PATH: process.env.PATH, SIGNAFAIDE_TEST: "1" } });
    expect(out.trim()).toBe("ok");
    // With OpenTelemetry there, the built entry point loads in both module systems.
    const both = `const m = await import(${JSON.stringify(path.join(dist, "otel.js"))}); const { createRequire } = await import("node:module");
const c = createRequire(${JSON.stringify(path.join(dist, "x.js"))})(${JSON.stringify(path.join(dist, "otel.cjs"))});
console.log(typeof m.SignafaideSpanProcessor, typeof c.SignafaideSpanProcessor, typeof m.toolCall);`;
    expect(execFileSync(process.execPath, ["--input-type=module", "-e", both], { cwd: dir, encoding: "utf8", env: { PATH: process.env.PATH, SIGNAFAIDE_TEST: "1" } }).trim()).toBe("function function function");
  });
});
