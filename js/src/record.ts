/** `record`, `note`, `wrapTools` and `declareTools`: the decision -> run -> outcome cycle, and
 * the agent's tool list (SPEC §2.6). Node only. */

import { canonicalize, isUnsafeInteger } from "./jcs.js";
import { SignafaideError } from "./http.js";
import { recordHash, type SignedRecord } from "./records.js";
import { getRecorder, noWrites, recordingDisabled, type Recorder } from "./runtime.js";
import { ADAPTERS } from "./telemetry.js";
import { VERSION } from "./version.js";

export interface RecordOptions {
  /** Action or tool name. Defaults to the function's name. */
  name?: string;
  /** Agent chain name. Defaults to the project folder name; give one explicitly in production
   * (one name per running instance, see the production guide). */
  agent?: string;
  /** Wait for the decision's receipt before running; refuse to run without one. */
  strict?: boolean;
  /** Send content to the service too (default: hash-only). */
  storeContent?: boolean;
  /** Extra fields for the decision's `meta`. */
  meta?: Record<string, unknown>;
}

/** Strict mode: the decision got no receipt, so the tool did not run. */
export class NotRecorded extends SignafaideError {
  override name = "NotRecorded";
}

type AnyFn = (...args: any[]) => any;

// --- the agent's tool list (§2.6) ---------------------------------------------------

/** Tool names the SDK has wrapped in this process, by agent ("" is the default agent). */
const WRAPPED = new Map<string, Set<string>>();
/** Of those, the ones wrapped by `wrapTools` / `wrapTool`, which declare themselves. */
const LISTED = new Map<string, Set<string>>();
/** The full tool list given to `declareTools`, by agent. */
const EXPLICIT = new Map<string, { names: string[]; unrecorded: Set<string> }>();
/** Bumped whenever one of the three changes, so a recorder looks again only then. */
let toolsVersion = 0;
/** recorder -> agent -> the `toolsVersion` its declaration was last checked at. */
const checked = new WeakMap<Recorder, Map<string, number>>();
let toldDeclare = false;

/** `SIGNAFAIDE_DECLARE_TOOLS=0` turns off the declarations `wrapTools` writes by itself. */
export function autoDeclareTools(env: NodeJS.ProcessEnv = process.env): boolean {
  return !/^(0|false|no|off)$/i.test((env.SIGNAFAIDE_DECLARE_TOOLS ?? "").trim());
}

function remember(map: Map<string, Set<string>>, agent: string | undefined, name: string): void {
  const set = map.get(agent ?? "") ?? new Set<string>();
  map.set(agent ?? "", set);
  if (!set.has(name)) {
    set.add(name);
    toolsVersion++;
  }
}

/** The names in `map` for `agent`: its own, and the default agent's when `agent` is that one. */
function namesFor(map: Map<string, Set<string>>, agent: string, isDefault: boolean): Set<string> {
  return new Set([...(map.get(agent) ?? []), ...(isDefault ? (map.get("") ?? []) : [])]);
}

/** What this program declares for `agent`: the list given to `declareTools` (a tool recorded
 * when the SDK wrapped it here and it was not named unrecorded), else the tools `wrapTools`
 * wrapped, or null when there is nothing to declare. */
function ownTools(rec: Recorder, agent: string): [Record<string, boolean>, "declared" | "wrap_tools"] | null {
  const isDefault = agent === rec.defaultAgent;
  const explicit = EXPLICIT.get(agent) ?? (isDefault ? EXPLICIT.get("") : undefined);
  if (explicit) {
    const wrapped = namesFor(WRAPPED, agent, isDefault);
    const tools: Record<string, boolean> = {};
    for (const n of explicit.names) tools[n] = wrapped.has(n) && !explicit.unrecorded.has(n);
    for (const n of explicit.unrecorded) tools[n] = false;
    return [tools, "declared"];
  }
  const listed = namesFor(LISTED, agent, isDefault);
  if (!listed.size || !autoDeclareTools()) return null;
  return [Object.fromEntries([...listed].map((n) => [n, true])), "wrap_tools"];
}

/** Write the agent's tool declaration when this program has one that the recorder has not
 * written yet (the first recorded call of a wrapped tool, or a change of the list). Returns the
 * header's hash, or "" when there is nothing to declare. */
function declareOwn(rec: Recorder, agentOpt: string | undefined, storeContent?: boolean): string {
  const agent = agentOpt || rec.defaultAgent;
  const own = ownTools(rec, agent);
  if (!own) return "";
  return rec.declareTools(own[0], { agent, source: "sdk", origin: own[1], storeContent });
}

/** Before a decision: declare the tools, once per change. Never fails the tool call. */
function declareBeforeCall(rec: Recorder, agentOpt: string | undefined): void {
  const agent = agentOpt || rec.defaultAgent;
  const seen = checked.get(rec) ?? new Map<string, number>();
  checked.set(rec, seen);
  if (seen.get(agent) === toolsVersion || noWrites.getStore()) return;
  try {
    declareOwn(rec, agentOpt);
    seen.set(agent, toolsVersion);
  } catch (e) {
    seen.set(agent, toolsVersion); // tried once for this list; the tool call goes on
    if (!toldDeclare) {
      toldDeclare = true;
      console.error(`signafaide: could not write the tool declaration for ${agent}: ${(e as Error).message}`);
    }
  }
}

export interface DeclareOptions {
  /** Agent chain name (default: the project folder name). */
  agent?: string;
  /** Tools of the agent that are known not to be wrapped: declared as not recorded. */
  unrecorded?: Iterable<string>;
}

/**
 * Declare the agent's full tool list (SPEC §2.6), so a verifier can say which of the agent's
 * tools are recorded. A name is declared recorded when the SDK wrapped a tool of that name in
 * this process (`record`, `wrapTools`, `wrapTool`), otherwise not recorded; `unrecorded` names
 * tools that are not wrapped. The declaration is a signed note per tool in the agent's chain:
 * it is evidence of what the program said its tools were, not proof that the list is complete.
 * Written now, and again by itself when a tool of the list is wrapped later. Returns the hash of
 * the `signafaide.tools` note ("" when recording is turned off).
 */
export function declareTools(names: Iterable<string>, opts: DeclareOptions = {}): string {
  const list = [...names];
  const unrecorded = [...(opts.unrecorded ?? [])];
  for (const n of [...list, ...unrecorded]) if (typeof n !== "string" || !n) throw new TypeError("declareTools needs tool names: non-empty strings");
  EXPLICIT.set(opts.agent ?? "", { names: list, unrecorded: new Set(unrecorded) });
  toolsVersion++;
  if (recordingDisabled()) return "";
  const rec = getRecorder();
  const hash = declareOwn(rec, opts.agent);
  const seen = checked.get(rec) ?? new Map<string, number>();
  checked.set(rec, seen);
  seen.set(opts.agent || rec.defaultAgent, toolsVersion);
  return hash;
}

/** @internal Forget every wrapped and declared tool (tests). */
export function resetToolRegistry(): void {
  WRAPPED.clear();
  LISTED.clear();
  EXPLICIT.clear();
  toolsVersion++;
  toldDeclare = false;
}

class Spec {
  constructor(
    readonly name: string,
    readonly opts: RecordOptions,
    /** Wrapped by `wrapTools` / `wrapTool`: part of the tool list it declares. */
    listed = false,
  ) {
    if (!name) throw new TypeError('record(fn) needs a name: record(fn, { name: "approve_payout" })');
    remember(WRAPPED, opts.agent, name);
    if (listed) remember(LISTED, opts.agent, name);
  }

  private decide(input: unknown): [Recorder, SignedRecord] {
    const rec = getRecorder();
    declareBeforeCall(rec, this.opts.agent);
    const meta = { sdk: `signafaide-js/${VERSION}`, ...(this.opts.meta ?? {}) };
    const content = { input: toJsonable(input) ?? null, meta: toJsonable(meta) } as Record<string, unknown>;
    return [rec, rec.write("decision", this.name, content, { agent: this.opts.agent, storeContent: this.opts.storeContent })];
  }

  private outcome(rec: Recorder, d: SignedRecord, content: Record<string, unknown>): void {
    try {
      rec.write("outcome", this.name, content, { agent: d.envelope.agent, ref: recordHash(d), storeContent: this.opts.storeContent });
    } catch (e) {
      // the action already happened: report, never mask its result
      console.error(`signafaide: could not write the outcome of ${this.name}: ${(e as Error).message}`);
    }
  }

  private async strictCheck(rec: Recorder, d: SignedRecord): Promise<void> {
    if (rec.test) return; // test mode never sends, so there is no receipt to wait for
    try {
      await rec.ensureReceipt(d);
    } catch (e) {
      const err = e instanceof SignafaideError ? e : new SignafaideError((e as Error).message);
      // Agent frameworks often swallow a tool's error (the model just sees a failed tool): say
      // once, on stderr, that a strict tool did not run and how to fix it.
      rec.warnStrictRefused(this.name, err);
      throw new NotRecorded(`${err.message} (strict mode: ${this.name} did not run)`, { code: err.code, status: err.status, docs: err.docs, body: err.body });
    }
  }

  /** Run `fn` between a decision and an outcome. Sync stays sync unless strict. */
  call(input: unknown, fn: () => unknown): unknown {
    if (recordingDisabled()) return this.opts.strict ? Promise.resolve().then(fn) : fn();
    const [rec, d] = this.decide(input);
    if (this.opts.strict) return this.strictCheck(rec, d).then(() => this.run(rec, d, fn));
    return this.run(rec, d, fn);
  }

  private run(rec: Recorder, d: SignedRecord, fn: () => unknown): unknown {
    let out: unknown;
    try {
      out = fn();
    } catch (e) {
      this.outcome(rec, d, errorContent(e));
      throw e;
    }
    if (out && typeof (out as PromiseLike<unknown>).then === "function") {
      return (out as Promise<unknown>).then(
        (v) => {
          this.outcome(rec, d, { output: toJsonable(v) ?? null });
          return v;
        },
        (e) => {
          this.outcome(rec, d, errorContent(e));
          throw e;
        },
      );
    }
    this.outcome(rec, d, { output: toJsonable(out) ?? null });
    return out;
  }
}

/**
 * Record every call of `fn`: a `decision` before it runs, an `outcome` after.
 * The decision's input is the single argument, or the argument list when there are
 * several. Errors are recorded and rethrown unchanged. With `strict: true` the
 * wrapper returns a Promise and refuses to run `fn` until the decision has a receipt.
 */
export function record<F extends AnyFn>(fn: F, opts: RecordOptions & { strict: true }): (...args: Parameters<F>) => Promise<Awaited<ReturnType<F>>>;
export function record<F extends AnyFn>(fn: F, opts?: RecordOptions): F;
export function record<F extends AnyFn>(fn: F, opts: RecordOptions = {}): AnyFn {
  return recordWith(new Spec(opts.name ?? fn.name, opts), fn);
}

function recordWith(spec: Spec, fn: AnyFn): AnyFn {
  const wrapped = function (this: unknown, ...args: unknown[]) {
    return spec.call(args.length === 1 ? args[0] : args, () => fn.apply(this, args));
  };
  Object.defineProperty(wrapped, "name", { value: fn.name });
  return wrapped;
}

/** Write a `note` record (anything worth keeping that is not a tool call). Returns its hash. */
export function note(name: string, content: Record<string, unknown>, opts: { agent?: string; storeContent?: boolean } = {}): string {
  if (recordingDisabled()) return "";
  return recordHash(getRecorder().write("note", name, toJsonable(content) as Record<string, unknown>, opts));
}

export interface WrapOptions {
  agent?: string;
  strict?: boolean;
  storeContent?: boolean;
  /** Declare the wrapped tools as the agent's recorded tools (SPEC §2.6), with the first
   * recorded call. Default true; `SIGNAFAIDE_DECLARE_TOOLS=0` turns it off everywhere. */
  declareTools?: boolean;
}

/**
 * Record every tool in an object (key = tool name) or an array. Accepts plain
 * functions, Vercel AI SDK tools (objects with `execute`), OpenAI Agents JS
 * function tools and LangChain.js tools. Returns the same shape. The wrapped tools are
 * declared as the agent's recorded tools (see `declareTools`) unless `declareTools: false`.
 */
export function wrapTools<T>(tools: T, opts: WrapOptions = {}): T {
  if (Array.isArray(tools)) return tools.map((t) => wrapTool(t, opts)) as T;
  if (tools && typeof tools === "object" && !isTool(tools)) {
    return Object.fromEntries(Object.entries(tools).map(([k, t]) => [k, wrapTool(t, { ...opts, name: k })])) as T;
  }
  return wrapTool(tools, opts);
}

const isTool = (t: any): boolean => typeof t === "function" || isOpenAIAgentsTool(t) || isLangChainTool(t) || typeof t?.execute === "function";
const isOpenAIAgentsTool = (t: any): boolean => t?.type === "function" && typeof t.invoke === "function" && typeof t.name === "string";
const isLangChainTool = (t: any): boolean => Array.isArray(t?.lc_namespace) && typeof t._call === "function" && typeof t.invoke === "function";

/** Record one tool. See `wrapTools`. */
export function wrapTool<T>(tool: T, opts: WrapOptions & { name?: string } = {}): T {
  const t = tool as any;
  const { declareTools: declare = true, ...ropts } = opts;
  const spec = (name: string) => new Spec(ropts.name ?? name, ropts, declare);
  if (isOpenAIAgentsTool(t)) {
    const s = spec(t.name);
    ADAPTERS.add("openai-agents");
    return {
      ...t,
      invoke: (runContext: unknown, input: string, details?: unknown) =>
        Promise.resolve(s.call(parseJson(input), () => t.invoke(runContext, input, details))),
    } as T;
  }
  if (isLangChainTool(t)) {
    const s = spec(t.name);
    ADAPTERS.add("langchain");
    const proxy = Object.create(t);
    proxy._call = function (arg: unknown, runManager?: unknown, config?: unknown) {
      return s.call(arg, () => t._call.call(proxy, arg, runManager, config));
    };
    return proxy;
  }
  if (typeof t === "function") return recordWith(spec(t.name), t) as T;
  if (typeof t?.execute === "function") {
    const s = spec(t.name ?? "");
    ADAPTERS.add("vercel-ai");
    return { ...t, execute: (input: unknown, options?: unknown) => s.call(input, () => t.execute(input, options)) } as T;
  }
  throw new TypeError(`wrapTools cannot record ${t === null ? "null" : typeof t}: pass a function, a tool with execute(), an OpenAI Agents tool or a LangChain tool`);
}

function parseJson(s: string): unknown {
  try {
    return s ? JSON.parse(s) : {};
  } catch {
    return s;
  }
}

function errorContent(e: unknown): Record<string, unknown> {
  const err = e as { name?: string; message?: string };
  return { error: { type: err?.name ?? typeof e, message: err?.message ?? String(e) } };
}

function base64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/** Turn `v` into plain JSON values that JCS can hash (deterministically). */
export function toJsonable(v: unknown, seen: Set<unknown> = new Set()): unknown {
  if (v === null || v === undefined) return null;
  switch (typeof v) {
    case "boolean":
    case "string":
      return v;
    case "number":
      if (!Number.isFinite(v) || isUnsafeInteger(v)) return String(v); // keep the digits as text (SPEC §1)
      return v;
    case "bigint":
      return v >= -BigInt(Number.MAX_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString();
    case "function":
    case "symbol":
      return null;
  }
  if (seen.has(v)) return "[Circular]";
  const inner = new Set(seen).add(v);
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  if (v instanceof Uint8Array) return base64(v);
  if (v instanceof ArrayBuffer) return base64(new Uint8Array(v));
  if (v instanceof Error) return { name: v.name, message: v.message };
  if (Array.isArray(v)) return v.map((x) => toJsonable(x, inner));
  if (v instanceof Set) return [...v].map((x) => toJsonable(x, inner)).sort((a, b) => (canonicalize(a) < canonicalize(b) ? -1 : 1));
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), toJsonable(x, inner)]));
  if (typeof (v as { toJSON?: unknown }).toJSON === "function") return toJsonable((v as { toJSON: () => unknown }).toJSON(), inner);
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v as object)) {
    if (x === undefined || typeof x === "function" || typeof x === "symbol") continue;
    out[k] = toJsonable(x, inner);
  }
  return out;
}
