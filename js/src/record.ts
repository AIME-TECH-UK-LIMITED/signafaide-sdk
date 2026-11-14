/** `record`, `note` and `wrapTools`: the decision -> run -> outcome cycle. Node only. */

import { canonicalize, isUnsafeInteger } from "./jcs.js";
import { SignafaideError } from "./http.js";
import { recordHash, type SignedRecord } from "./records.js";
import { getRecorder, recordingDisabled, type Recorder } from "./runtime.js";
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

class Spec {
  constructor(
    readonly name: string,
    readonly opts: RecordOptions,
  ) {
    if (!name) throw new TypeError('record(fn) needs a name: record(fn, { name: "approve_payout" })');
  }

  private decide(input: unknown): [Recorder, SignedRecord] {
    const rec = getRecorder();
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
  const spec = new Spec(opts.name ?? fn.name, opts);
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
}

/**
 * Record every tool in an object (key = tool name) or an array. Accepts plain
 * functions, Vercel AI SDK tools (objects with `execute`), OpenAI Agents JS
 * function tools and LangChain.js tools. Returns the same shape.
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
  const spec = (name: string) => new Spec(opts.name ?? name, opts);
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
  if (typeof t === "function") return record(t, { ...opts, name: opts.name ?? t.name }) as T;
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
