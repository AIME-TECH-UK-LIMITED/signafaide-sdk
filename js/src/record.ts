/** `record`, `note`, `wrapTools` and `declareTools`: the decision -> run -> outcome cycle, and
 * the agent's tool list (SPEC §2.6). Node only. */

import { CheckError, SignafaideBlocked, callLink, outcomeChecks, refusedContent, registerSyncTool, resetSyncTools, type Plan, type ToolInfo } from "./checks-runtime.js";
import { declaredName } from "./coverage.js";
import { canonicalize, isUnsafeInteger } from "./jcs.js";
import { SignafaideError } from "./http.js";
import { recordHash, type SignedRecord } from "./records.js";
import { getRecorder, noWrites, recording, recordingDisabled, telemetryHooks, type Recorder } from "./runtime.js";
import { ADAPTERS } from "./telemetry.js";
import { deliver, development, type CallNote, type NoteHandler } from "./notes.js";
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
  /** The names of the function's positional arguments (spec 1.1): the decision's input is then
   * `{<name>: <argument>}`, so rules find a value by its name (`/amount`). Arguments past the
   * names are kept, in order, under `"_rest"`. Without it the input is the single argument, or the
   * argument list when there are several. */
  args?: readonly string[];
  /** Called with each note of this tool's calls (spec 1.1: a possible hidden instruction in the
   * arguments or the result). The call runs and returns as without it; `onNote(handler)` gets the
   * notes of every tool, and `notes(result)` those of an object result. */
  onNote?: NoteHandler;
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
/** Tool names a wrapper of the SDK records in this process (`record`, `wrapTools`, `wrapTool`),
 * with a framework tool's own name when the wrapper names it otherwise. With tool-call checks on,
 * the telemetry plug-in leaves a span of such a tool to the wrapper (§8): the wrapper's decision
 * carries the checks, and a span's decision written at its start would not. */
const BY_WRAPPER = new Set<string>();
/** Of those, the names a wrapper protects (strict in code): checked even without a checks file. */
const STRICT_BY_WRAPPER = new Set<string>();

/** @internal Whether a wrapper of the SDK in this process records tool calls named `name`. */
export function wrapperRecords(name: string): boolean {
  return BY_WRAPPER.has(name);
}

/** @internal Whether a wrapper of the SDK in this process protects tool calls named `name` (strict in code). */
export function wrapperProtects(name: string): boolean {
  return STRICT_BY_WRAPPER.has(name);
}

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

/** @internal A tool the telemetry plug-in records from its spans: part of what this program
 * records for `agent`, and, with `listed`, of the tool list it declares. */
export function rememberTool(agent: string, name: string, listed: boolean): void {
  remember(WRAPPED, agent, name);
  if (listed) remember(LISTED, agent, name);
}

/** Before a decision: declare the tools, once per change. Never fails the tool call. */
export function declareBeforeCall(rec: Recorder, agentOpt: string | undefined): void {
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
  BY_WRAPPER.clear();
  STRICT_BY_WRAPPER.clear();
  resetSyncTools();
  toolsVersion++;
  toldDeclare = false;
}

class Spec {
  constructor(
    readonly name: string,
    readonly opts: RecordOptions,
    /** Wrapped by `wrapTools` / `wrapTool`: part of the tool list it declares. */
    listed = false,
    /** What the agent is shown of the tool, for its fingerprints (§11.1): a framework tool's
     * description and input schema; a plain function has none. */
    readonly tool?: ToolInfo,
    /** A plain synchronous function, not strict in code: its return type never changes, so the
     * checks file cannot make it strict (§8, JS). */
    readonly syncOnly = false,
  ) {
    if (!name) throw new TypeError('record(fn) needs a name: record(fn, { name: "approve_payout" })');
    if (syncOnly) registerSyncTool(name);
    BY_WRAPPER.add(name);
    if (tool?.name) BY_WRAPPER.add(tool.name);
    if (opts.strict) for (const n of [name, tool?.name]) if (n) STRICT_BY_WRAPPER.add(n);
    remember(WRAPPED, opts.agent, name);
    if (listed) remember(LISTED, opts.agent, name);
    // The agent is shown the tool from now on: its fingerprints are approved the first time (§8).
    if (tool && !recordingDisabled()) {
      try {
        const rec = getRecorder();
        rec.checks.seen(tool, opts.agent || rec.defaultAgent, declaredName(name), !!opts.strict);
      } catch {
        /* the first call reports what is wrong */
      }
    }
  }

  private decide(input: unknown, plan?: Plan | null): [Recorder, SignedRecord] {
    const rec = getRecorder();
    declareBeforeCall(rec, this.opts.agent);
    const meta: Record<string, unknown> = { sdk: `signafaide-js/${VERSION}`, ...(this.opts.meta ?? {}) };
    // Where a strict call's protection comes from (§8, SDK 0.5.2): code, checks file, console.
    if (plan?.strict && plan.protectedBy.length) meta.protected_by = plan.protectedBy;
    else if (!plan && this.opts.strict) meta.protected_by = ["code"];
    const content = { input: toJsonable(input) ?? null, meta: toJsonable(meta) } as Record<string, unknown>;
    const extra = plan ? { checks: plan.checks, disclosed: plan.disclosed, disclosedSalt: plan.disclosedSalt } : {};
    return [rec, rec.write("decision", this.name, content, { agent: this.opts.agent, storeContent: this.opts.storeContent, ...extra })];
  }

  /** The tool-call checks of this call (§8 steps 1 and 2) when a checks file is in place, else
   * null. The checks name the tool as the envelope does (the wrapper's name, declared, §2.6); the
   * fingerprints cover what the agent is shown of it (§11.1). */
  private plan(input: unknown, callId?: string): Plan | null {
    const rec = getRecorder();
    const decl = declaredName(this.name);
    // A tool protected in code, or from the console (the held rule set's `protect`, §8), is
    // checked even without a checks file (every check On).
    if (!rec.checks.enabled(!!this.opts.strict, decl)) {
      rec.checks.observeConsole(decl, false, rec.checks.heldRules()?.version ?? null);
      return null;
    }
    return rec.checks.plan(this.tool ?? { name: this.name }, this.opts.agent || rec.defaultAgent, toJsonable(input) ?? null, {
      strictCode: !!this.opts.strict,
      callId,
      syncOnly: this.syncOnly,
      declared: declaredName(this.name),
      protect: !!(this.opts as ProtectOptions).protect,
    });
  }

  private outcomeChecked(rec: Recorder, d: SignedRecord, content: Record<string, unknown>, checks: Record<string, unknown>): void {
    try {
      rec.write("outcome", this.name, content, { agent: d.envelope.agent, ref: recordHash(d), storeContent: this.opts.storeContent, checks });
    } catch (e) {
      console.error(`signafaide: could not write the outcome of ${this.name}: ${(e as Error).message}`);
    }
  }

  /** The outcome of a call that did not run (§8 steps 3 and 4), and the error to throw. */
  private refused(rec: Recorder, d: SignedRecord, err: CheckError, ruling: string): CheckError {
    if (err instanceof SignafaideBlocked) {
      const h = recordHash(d);
      err.attach(h, callLink(rec, h));
    }
    this.outcomeChecked(rec, d, refusedContent(err), outcomeChecks(false, ruling));
    if (err.code !== "blocked") rec.noteStrictRefused(this.name, err);
    return err;
  }

  /** A checked call (§8): blocked here, or ruled by the witness when strict, then run with the
   * result checks on what it returned. Sync stays sync unless the call is strict. */
  private checked(rec: Recorder, d: SignedRecord, plan: Plan, body: () => unknown, ended: () => void): unknown {
    const async = plan.strict || !!this.opts.strict;
    if (plan.blocked) {
      ended();
      this.notify(rec, plan.notes);
      const err = this.refused(rec, d, plan.blocked, "not_asked");
      // An async function's callers get a rejected promise, never a synchronous throw.
      if (async || !this.syncOnly) return Promise.reject(err);
      throw err;
    }
    if (!plan.strict) return async ? Promise.resolve().then(() => this.runChecked(rec, d, body, "not_asked", plan.notes)) : this.runChecked(rec, d, body, "not_asked", plan.notes);
    rec.strictUsed = true;
    return rec.checks.ruling(d, plan, this.name).then(([ruling, err]) => {
      if (err) {
        ended();
        this.notify(rec, plan.notes);
        throw this.refused(rec, d, err, ruling);
      }
      return this.runChecked(rec, d, body, ruling, plan.notes);
    });
  }

  /** Hand the call's notes to the caller (§8 notes); with a result, keep them for `notes(result)`. */
  private notify(rec: Recorder, list: readonly CallNote[], result?: unknown): void {
    deliver(list, { own: this.opts.onNote, development: development(rec), result });
  }

  private runChecked(rec: Recorder, d: SignedRecord, fn: () => unknown, ruling: string, argNotes: readonly CallNote[] = []): unknown {
    const failed = (e: unknown): never => {
      this.outcomeChecked(rec, d, errorContent(e), outcomeChecks(true, ruling));
      this.notify(rec, argNotes);
      throw e;
    };
    const done = (v: unknown): unknown => {
      const value = toJsonable(v) ?? null;
      const results = rec.checks.resultEntries(value, false, declaredName(this.name), !!this.opts.strict);
      const withheld = rec.checks.withheld(this.name, results);
      this.notify(rec, [...argNotes, ...rec.checks.resultNotes(declaredName(this.name), results)], withheld ? undefined : v);
      if (withheld) {
        // The result holds a secret: the agent gets this error instead, and the record keeps
        // the finding, never the result (§8 step 5).
        const h = recordHash(d);
        withheld.attach(h, callLink(rec, h));
        this.outcomeChecked(rec, d, { error: { type: "Withheld", message: withheld.message, check: withheld.check } }, outcomeChecks(true, ruling, results));
        throw withheld;
      }
      this.outcomeChecked(rec, d, { output: value }, outcomeChecks(true, ruling, results));
      return v;
    };
    let out: unknown;
    try {
      out = fn();
    } catch (e) {
      return failed(e);
    }
    if (out && typeof (out as PromiseLike<unknown>).then === "function") return (out as Promise<unknown>).then(done, failed);
    return done(out);
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
      rec.noteStrictRefused(this.name, err);
      throw new NotRecorded(`${err.message} (${this.name} is protected and did not run)`, { code: err.code, status: err.status, docs: err.docs, body: err.body });
    }
  }

  /** Run `fn` between a decision and an outcome. Sync stays sync unless strict. `callId` is the
   * model's tool call id, when the adapter has it: the telemetry plug-in matches the call's span
   * by it. */
  call(input: unknown, fn: () => unknown, callId?: string): unknown {
    if (recordingDisabled()) return this.opts.strict ? Promise.resolve().then(fn) : fn();
    // §8 (SDK 0.5.2): the rule set is fetched at start, with or without a checks file, so a tool
    // protected from the console is protected; a call that can wait waits for the first fetch
    // while no version is held (at most RULES_START_WAIT_MS). A plain synchronous function cannot.
    if (!this.syncOnly || this.opts.strict) {
      const wait = getRecorder().checks.startWait();
      if (wait) return wait.then(() => this.call(input, fn, callId));
    } else getRecorder().checks.start();
    // The telemetry plug-in has already written the decision of the tool span that is running
    // now (it then writes the outcome too): one call, one decision. Not with tool-call checks on:
    // the wrapper then always writes its own decision with the checks, and asks for the ruling of
    // a strict call (§8); the plug-in leaves spans of the tools a wrapper records to it.
    const held = telemetryHooks.adopt && !checksOn(!!this.opts.strict, declaredName(this.name)) ? telemetryHooks.adopt(this.name, callId) : null;
    if (held) return this.opts.strict ? this.strictCheck(held[0], held[1]).then(fn) : fn();
    let plan: Plan | null;
    try {
      plan = this.plan(input, callId);
    } catch (e) {
      // An invalid checks file with no good version in force: every checked call fails with `state`.
      if (this.opts.strict) return Promise.reject(e);
      throw e;
    }
    const [rec, d] = this.decide(input, plan);
    const claim = telemetryHooks.claim?.(this.name, callId, this.tool?.name);
    const ended = () => {
      if (claim !== undefined) telemetryHooks.done?.(claim);
    };
    const body = () => {
      let out: unknown;
      try {
        out = recording.run(this.name, fn);
      } catch (e) {
        ended();
        throw e;
      }
      if (out && typeof (out as PromiseLike<unknown>).then === "function") {
        return (out as Promise<unknown>).then(
          (v) => {
            ended();
            return v;
          },
          (e) => {
            ended();
            throw e;
          },
        );
      }
      ended();
      return out;
    };
    if (plan) return this.checked(rec, d, plan, body, ended);
    const run = () => this.run(rec, d, body);
    if (this.opts.strict) return this.strictCheck(rec, d).then(run);
    return run();
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
  checkArgNames(opts.args);
  return recordWith(new Spec(opts.name ?? fn.name, opts, false, undefined, syncFunction(fn, opts)), fn);
}

/** Options of `protect`: those of `record`, without `strict` (a protected tool is always strict). */
export type ProtectOptions = Omit<RecordOptions, "strict"> & { /** @internal */ protect?: true };

/**
 * Protect a tool (spec 1.1): record every call of `fn`, and run it only when signafAIde allows
 * it. Each call is strict: it waits for the witness's ruling under the project's rules and
 * fails closed (unless the rule set sets another fail mode for the tool), and sends the witness
 * only the fields of the call that the rules can use and that `signafaide.checks.json` lists for
 * the tool (`signafaide pull` asks before it adds one). A blocked call throws `SignafaideBlocked`,
 * whose message says why in one sentence, with the rule in words and a link to the call.
 * Name positional arguments with `args` so rules can find them: `protect(approvePayout,
 * { args: ["payee", "amount", "currency"] })`. Returns an async function.
 */
export function protect<F extends AnyFn>(fn: F, opts: ProtectOptions = {}): (...args: Parameters<F>) => Promise<Awaited<ReturnType<F>>> {
  checkArgNames(opts.args);
  const o: RecordOptions & { protect: true } = { ...opts, strict: true, protect: true };
  return recordWith(new Spec(opts.name ?? fn.name, o, false, undefined, false), fn) as (...args: Parameters<F>) => Promise<Awaited<ReturnType<F>>>;
}

function checkArgNames(names: readonly string[] | undefined): void {
  if (names === undefined) return;
  if (!Array.isArray(names) || !names.every((n) => typeof n === "string" && n.length > 0) || new Set(names).size !== names.length) {
    throw new TypeError('args names the positional arguments: distinct non-empty strings, for example { args: ["payee", "amount", "currency"] }');
  }
}

/** The decision's input of a call: named by `names` when given (spec 1.1), else the single
 * argument, or the argument list when there are several. */
export function namedInput(args: unknown[], names?: readonly string[]): unknown {
  if (!names) return args.length === 1 ? args[0] : args;
  const out: Record<string, unknown> = {};
  names.forEach((n, i) => {
    if (i < args.length && args[i] !== undefined) out[n] = args[i];
  });
  if (args.length > names.length) out._rest = args.slice(names.length);
  return out;
}

function recordWith(spec: Spec, fn: AnyFn): AnyFn {
  const names = spec.opts.args;
  const wrapped = function (this: unknown, ...args: unknown[]) {
    return spec.call(namedInput(args, names), () => fn.apply(this, args));
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
  /** Called with each note of the wrapped tools' calls (see `RecordOptions.onNote`). */
  onNote?: NoteHandler;
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
  const spec = (name: string, info?: ToolInfo) => new Spec(ropts.name ?? name, ropts, declare, info);
  if (isOpenAIAgentsTool(t)) {
    const s = spec(t.name, { name: t.name, description: str(t.description), inputSchema: jsonSchemaOf(t.parameters) });
    ADAPTERS.add("openai-agents");
    return {
      ...t,
      invoke: (runContext: unknown, input: string, details?: unknown) => {
        // The model's tool call id: the runner passes the call item in the details.
        const id = (details as { toolCall?: { callId?: unknown } } | undefined)?.toolCall?.callId;
        return promised(() => s.call(parseJson(input), () => t.invoke(runContext, input, details), typeof id === "string" && id ? id : undefined));
      },
    } as T;
  }
  if (isLangChainTool(t)) {
    const s = spec(t.name, { name: t.name, description: str(t.description), inputSchema: jsonSchemaOf(t.schema) });
    ADAPTERS.add("langchain");
    const proxy = Object.create(t);
    proxy._call = function (arg: unknown, runManager?: unknown, config?: unknown) {
      // The model's tool call id: LangChain passes it in the config when the tool is called with a tool call.
      const id = (config as { toolCall?: { id?: unknown } } | undefined)?.toolCall?.id;
      return promised(() => s.call(arg, () => t._call.call(proxy, arg, runManager, config), typeof id === "string" && id ? id : undefined));
    };
    return proxy;
  }
  if (typeof t === "function") return recordWith(new Spec(ropts.name ?? t.name, ropts, declare, undefined, syncFunction(t, ropts)), t) as T;
  if (typeof t?.execute === "function") {
    const n = ropts.name ?? t.name ?? "";
    const s = spec(t.name ?? "", { name: n, description: str(t.description), inputSchema: jsonSchemaOf(t.inputSchema ?? t.parameters) });
    ADAPTERS.add("vercel-ai");
    return {
      ...t,
      execute: (input: unknown, options?: unknown) => {
        const id = (options as { toolCallId?: unknown } | undefined)?.toolCallId;
        return promised(() => s.call(input, () => t.execute(input, options), typeof id === "string" && id ? id : undefined));
      },
    } as T;
  }
  throw new TypeError(`wrapTools cannot record ${t === null ? "null" : typeof t}: pass a function, a tool with execute(), an OpenAI Agents tool or a LangChain tool`);
}

/** Whether tool-call checks are on for the recorder in use (a checks file is in place). */
function checksOn(protect = false, tool?: string): boolean {
  try {
    return getRecorder().checks.enabled(protect, tool);
  } catch {
    return false;
  }
}

/** A framework's async tool API: a call refused before it runs rejects, never throws. */
function promised(fn: () => unknown): Promise<unknown> {
  try {
    return Promise.resolve(fn());
  } catch (e) {
    return Promise.reject(e);
  }
}

/** A plain function that is not async and not strict in code: its callers get its value
 * synchronously, so its return type must never become a Promise. */
function syncFunction(fn: AnyFn, opts: RecordOptions): boolean {
  return !opts.strict && fn.constructor?.name !== "AsyncFunction";
}

const str = (x: unknown): string => (typeof x === "string" ? x : "");

/** A tool's input schema as JSON Schema, when the framework holds one: a plain JSON Schema
 * object, or the Vercel AI SDK's `jsonSchema()` wrapper. A schema only a validation library
 * can describe (Zod) gives null: the fingerprints then cover the name and description. */
function jsonSchemaOf(x: any): unknown {
  try {
    if (!x || typeof x !== "object") return null;
    if (x.jsonSchema && typeof x.jsonSchema === "object") return JSON.parse(JSON.stringify(x.jsonSchema));
    if (Object.getPrototypeOf(x) === Object.prototype && ("type" in x || "properties" in x || "$schema" in x)) return JSON.parse(JSON.stringify(x));
  } catch {
    /* not JSON: no schema */
  }
  return null;
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
