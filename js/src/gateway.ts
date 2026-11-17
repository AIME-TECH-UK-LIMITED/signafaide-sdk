/**
 * `signafaide gateway -- <command> [args...]`: an MCP stdio proxy that records every tool call
 * that passes through it. The agent's MCP client starts the gateway instead of the MCP server;
 * the gateway starts the server as a child and relays newline-delimited JSON-RPC both ways,
 * unchanged. It understands two methods and nothing else:
 *
 * - a `tools/list` result: the server's tools are declared as the agent's recorded tools
 *   (SPEC §2.6), page by page as the client is shown them, and again when the list changes;
 * - a `tools/call` request: a `decision` is written before the call is forwarded and an
 *   `outcome` when the answer arrives. A call that cannot be recorded is not forwarded.
 *
 * With tool-call checks on (a `signafaide.checks.json`, SPEC §8) it also reads the `initialize`
 * result's `serverInfo` and each tool's description and input schema, for the tool fingerprints,
 * and checks every `tools/call` before forwarding it: a call that may not run is answered with a
 * JSON-RPC error and the server never sees it.
 *
 * It records every call that goes through it. A call the application makes around it is still
 * not recorded, so the deployment has to make the gateway the only route to those tools.
 *
 * Nothing but relayed protocol lines is ever written to stdout; diagnostics go to stderr.
 * No MCP library is used: a line that is not JSON, or any other method, is passed on as it is.
 * With tool-call checks or strict mode on, the server sees only what was checked: a client line
 * that is not a JSON object or array is answered with a JSON-RPC error and never forwarded, and
 * every message forwarded is the gateway's own serialisation of what it parsed, never the
 * client's bytes (another parser could read those bytes as another message).
 */

import { spawn, type ChildProcess } from "node:child_process";
import * as os from "node:os";
import type { Readable, Writable } from "node:stream";
import { CheckError, outcomeChecks, refusedContent, type Plan } from "./checks-runtime.js";
import { declaredName } from "./coverage.js";
import { sha256Hex } from "./crypto.js";
import { SignafaideError } from "./http.js";
import { toJsonable } from "./record.js";
import { recordHash, type SignedRecord } from "./records.js";
import { configure, recordingDisabled, type Recorder } from "./runtime.js";
import { VERSION } from "./version.js";

export interface GatewayOptions {
  /** The MCP server to run, and its arguments. */
  command: string;
  args?: string[];
  /** Agent chain name (default: the project folder's name, as everywhere in the SDK). */
  agent?: string;
  /** Put before every recorded tool name, for an agent with several servers (`github.`). */
  namePrefix?: string;
  /** Wait for the witness's receipt before forwarding any call (strict mode). */
  strict?: boolean;
  /** Strict mode for these tools only (the server's own tool names). */
  strictTools?: string[];
  /** Send content to the witness too (default: hash-only). */
  storeContent?: boolean;
  /** Where the client's messages come from, and where the server's go (default: this process's
   * stdin and stdout). Diagnostics go to `stderr`. */
  stdin?: Readable;
  stdout?: Writable;
  stderr?: Writable;
  /** The server's environment (default: this process's). */
  env?: NodeJS.ProcessEnv;
  /** The recorder to write with (default: a new one for the project in the working directory). */
  recorder?: Recorder;
  /** Pass SIGINT, SIGTERM and SIGHUP on to the server (default true; off when embedded). */
  forwardSignals?: boolean;
  /** How long the server gets to exit after a signal before it is killed (default 5000 ms). */
  killAfterMs?: number;
}

export interface GatewayResult {
  /** The server's exit code (127 when it could not be started, 126 when not allowed to). */
  code: number;
  /** The signal that ended the server, when one did. */
  signal: NodeJS.Signals | null;
}

/** JSON-RPC error code of the gateway's own answers (the implementation-defined server range). */
export const GATEWAY_ERROR = -32000;
/** JSON-RPC's own codes: the line is not JSON, and the message is not a valid request. */
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;

type Json = Record<string, any>;
type Route = { forward: true } | { reply: Json } | { drop: true };
const FORWARD: Route = { forward: true };

interface Call {
  key: string;
  /** The tool's name as recorded: prefix, then cut as a declaration holds it (§2.6). */
  name: string;
  decision: SignedRecord;
  /** `waiting`: strict, not forwarded yet. */
  state: "waiting" | "forwarded" | "cancelled";
  /** With tool-call checks: the outcome carries `checks` (§2.8), with the ruling held when the
   * call was forwarded. */
  checked?: boolean;
  ruling?: string;
}

interface Listing {
  names: Set<string>;
  complete: boolean;
}

const isObject = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);

/** A JSON-RPC id as a map key: strings and numbers never collide (`"1"` is not `1`). */
function idKey(id: unknown): string | undefined {
  return typeof id === "string" ? `s:${id}` : typeof id === "number" ? `n:${id}` : undefined;
}

function parse(line: Buffer): unknown {
  const text = line.toString("utf8").trim();
  if (!text || (text[0] !== "{" && text[0] !== "[")) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** The text of an MCP tool result (its `text` content blocks), for an error's message. */
function resultText(result: Json): string {
  const parts = Array.isArray(result.content) ? result.content.filter((c: any) => isObject(c) && c.type === "text" && typeof c.text === "string").map((c: any) => c.text) : [];
  return parts.join("\n").slice(0, 2000) || "the tool reported an error";
}

/** The outcome of a call, from the server's answer: the result, or the error in the shape the
 * SDK records a tool that threw (`{error: {type, message}}`). */
export function outcomeContent(answer: Json): Record<string, unknown> {
  if (isObject(answer.error)) {
    return { error: toJsonable({ type: "JsonRpcError", message: String(answer.error.message ?? "the server answered with an error"), code: answer.error.code ?? null }) };
  }
  const result = answer.result;
  if (isObject(result) && result.isError === true) return { error: { type: "ToolError", message: resultText(result) }, output: toJsonable(result) };
  return { output: toJsonable(result) ?? null };
}

/** Run the gateway until the server exits. Resolves with the server's exit code or signal. */
export function runGateway(opts: GatewayOptions): Promise<GatewayResult> {
  return new Gateway(opts).run();
}

class Gateway {
  private readonly rec: Recorder;
  private readonly input: Readable;
  private readonly out: Writable;
  private readonly err: Writable;
  private readonly prefix: string;
  private readonly source: string;
  private readonly strictTools: Set<string>;
  private readonly off = recordingDisabled();
  private child!: ChildProcess;
  /** Client-to-server `tools/call` requests waiting for their answer, by id. Server-to-client
   * requests have ids of their own and are never looked up here. */
  private calls = new Map<string, Call>();
  /** Client-to-server `tools/list` requests waiting for their answer, by id. */
  private lists = new Map<string, Listing>();
  /** Client-to-server `initialize` requests waiting for their answer, by id. */
  private inits = new Set<string>();
  /** The server's `serverInfo` and what the client was shown of each tool (§11.1). */
  private serverInfo: { name?: unknown; version?: unknown } | null = null;
  private toolInfo = new Map<string, { description: string; inputSchema: unknown }>();
  /** The listing the client is paging through, and the tools of the last one it finished. */
  private listing: Listing | null = null;
  private shown: Set<string> | null = null;
  /** Answers held for a client batch whose other entries went on to the server, by their ids. */
  private held = new Map<string, { replies: Json[] }>();
  /** Strict calls waiting for the witness. */
  private waiting = new Set<Promise<void>>();
  /** The shown tools changed since they were last declared. */
  private undeclared = false;
  private toldDeclare = false;
  private done = false;

  constructor(private readonly opts: GatewayOptions) {
    this.input = opts.stdin ?? process.stdin;
    this.out = opts.stdout ?? process.stdout;
    this.err = opts.stderr ?? process.stderr;
    this.prefix = opts.namePrefix ?? "";
    this.strictTools = new Set(opts.strictTools ?? []);
    // One entry per gateway in the agent's tool list (§8 tools/<agent>.json): its prefix, or
    // else its command line, so two servers of one agent never replace each other's tools.
    this.source = `gateway:${this.prefix || sha256Hex(new TextEncoder().encode([opts.command, ...(opts.args ?? [])].join("\0"))).slice(0, 8)}`;
    this.rec = opts.recorder ?? configure({ via: "gateway", storeContent: opts.storeContent });
  }

  private diag(msg: string): void {
    this.err.write(`signafaide gateway: ${msg}\n`);
  }

  // --- relay --------------------------------------------------------------------------

  private toServer(data: Buffer | string): void {
    const stdin = this.child.stdin;
    if (!stdin || stdin.destroyed || stdin.writableEnded) return;
    if (!stdin.write(data)) {
      this.input.pause();
      stdin.once("drain", () => this.input.resume());
    }
  }

  private toClient(data: Buffer | string): void {
    if (!this.out.write(data)) {
      this.child.stdout?.pause();
      this.out.once("drain", () => this.child.stdout?.resume());
    }
  }

  private send(v: Route, original: Buffer): void {
    if ("forward" in v) this.toServer(Buffer.concat([original, NL]));
    else if ("reply" in v) this.toClient(JSON.stringify(v.reply) + "\n");
  }

  /** Tool-call checks or strict mode are on: the server must see exactly what was checked. */
  private guarded(): boolean {
    return !!this.opts.strict || this.strictTools.size > 0 || this.rec.checks.enabled();
  }

  private error(id: unknown, message: string, code: string, extra: Json = {}): Json {
    return { jsonrpc: "2.0", id: id ?? null, error: { code: GATEWAY_ERROR, message, data: { signafaide: code, ...extra } } };
  }

  /** The answer to a call the tool-call checks did not let run (§8 gateway): the check, the rule,
   * the rule set version and the fields to disclose, never a value. */
  private checkError(id: unknown, err: CheckError): Json {
    const data: Json = {};
    if (err.check) data.check = err.check;
    if (err.rule) data.rule = err.rule;
    if (err.rulesVersion !== undefined) data.rules_version = err.rulesVersion;
    if (err.missing.length) data.missing = err.missing;
    return this.error(id, `signafaide gateway: ${err.message}`, err.code, data);
  }

  // --- client to server -----------------------------------------------------------------

  private fromClient(line: Buffer): void {
    if (this.off) return this.toServer(Buffer.concat([line, NL]));
    const msg = parse(line);
    const guarded = this.guarded();
    if (msg === undefined) {
      // A line that is not a JSON object or array: passed on as it is, unless what reaches the
      // server must be checked first. Then it is answered, since the server's parser might read
      // a call in it that this one did not (`NaN`, a comment, another line break).
      if (!guarded || !line.toString("utf8").trim()) return this.toServer(Buffer.concat([line, NL]));
      return this.unreadable(line);
    }
    // What the server is sent: with checks or strict mode on, the message as parsed here.
    const wire = guarded ? Buffer.from(JSON.stringify(msg), "utf8") : line;
    if (Array.isArray(msg)) return this.clientBatch(msg, wire, guarded);
    const v = this.clientMessage(msg);
    if (v instanceof Promise) this.later(v.then((got) => this.send(got, wire)));
    else this.send(v, wire);
  }

  /** A client line that is not a JSON object or array, with checks or strict mode on: a JSON-RPC
   * parse error (or invalid request, for JSON that is not a message), never forwarded. */
  private unreadable(line: Buffer): void {
    let json = true;
    try {
      JSON.parse(line.toString("utf8"));
    } catch {
      json = false;
    }
    const why = json ? "the message is not a JSON-RPC request object or batch" : "the line is not valid JSON";
    this.diag(`a client line was not forwarded: ${why}`);
    this.toClient(
      JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: json ? INVALID_REQUEST : PARSE_ERROR, message: `signafaide gateway: ${why}; it was not forwarded`, data: { signafaide: json ? "invalid_request" : "parse_error" } } }) + "\n",
    );
  }

  /** Keep a strict call's wait, so the server's stdin is not closed under it. */
  private later(p: Promise<void>): void {
    const tracked = p.catch((e) => this.diag(`${(e as Error).message}`)).finally(() => this.waiting.delete(tracked));
    this.waiting.add(tracked);
  }

  /** A batch: each entry is judged like a single message. Entries that may not run are taken
   * out and answered here; their answers travel with the server's answer to the rest. */
  private clientBatch(msgs: unknown[], line: Buffer, guarded = false): void {
    const routes = msgs.map((m) => this.clientMessage(m));
    const finish = (vs: Route[]): void => {
      const forward = msgs.filter((_, i) => "forward" in vs[i]);
      const replies = vs.flatMap((v) => ("reply" in v ? [v.reply] : []));
      if (forward.length === msgs.length && !guarded) return this.toServer(Buffer.concat([line, NL]));
      if (forward.length === msgs.length) return this.toServer(JSON.stringify(forward) + "\n");
      if (forward.length) this.toServer(JSON.stringify(forward) + "\n");
      if (!replies.length) return;
      const answered = forward.flatMap((m) => (isObject(m) && typeof m.method === "string" && idKey(m.id) !== undefined ? [idKey(m.id)!] : []));
      if (!answered.length) return this.toClient(JSON.stringify(replies) + "\n");
      const group = { replies };
      for (const k of answered) this.held.set(k, group);
    };
    if (routes.some((v) => v instanceof Promise)) this.later(Promise.all(routes).then(finish));
    else finish(routes as Route[]);
  }

  private clientMessage(msg: unknown): Route | Promise<Route> {
    // No method: an answer to a request the server made (sampling, roots). Not ours to read.
    if (!isObject(msg) || typeof msg.method !== "string") return FORWARD;
    const key = idKey(msg.id);
    if (msg.method === "tools/list" && key !== undefined) {
      // No cursor: the client starts a new listing. A cursor continues the one it is paging through.
      const cursor = isObject(msg.params) ? msg.params.cursor : undefined;
      if (typeof cursor !== "string" || !cursor || !this.listing) this.listing = { names: new Set(), complete: false };
      this.lists.set(key, this.listing);
    } else if (msg.method === "initialize" && key !== undefined) {
      this.inits.add(key);
    } else if (msg.method === "notifications/cancelled") {
      this.cancelled(isObject(msg.params) ? msg.params : {});
    } else if (msg.method === "tools/call") {
      return this.call(msg, key);
    }
    return FORWARD;
  }

  private call(msg: Json, key: string | undefined): Route | Promise<Route> {
    const params = isObject(msg.params) ? msg.params : {};
    const tool = params.name;
    // Nothing to name a record with: the server refuses such a call itself.
    if (typeof tool !== "string" || !tool) return FORWARD;
    const full = this.prefix + tool;
    const name = declaredName(full);
    // The declaration covers every tool the client has been shown before its first call.
    this.declareShown();
    const meta: Record<string, unknown> = { sdk: `signafaide-js/${VERSION}`, gateway: true };
    if (name !== tool) meta.tool = tool; // the server's own name, when a prefix or a cut changed it
    const strictCode = !!this.opts.strict || this.strictTools.has(tool);
    const checksOn = this.rec.checks.enabled();
    // A strict call needs an id to be answered by: one that is not a string or a number cannot
    // be tracked while it waits for its receipt, so it is refused as an invalid request.
    if (strictCode && !checksOn && key === undefined && "id" in msg) {
      this.diag(`${tool} was not run: a strict call's id must be a string or a number`);
      return { reply: { jsonrpc: "2.0", id: null, error: { code: INVALID_REQUEST, message: `signafaide gateway: ${tool} was not run: a strict call's id must be a string or a number`, data: { signafaide: "invalid_request" } } } };
    }
    let plan: Plan | null = null;
    if (checksOn) {
      try {
        const info = this.toolInfo.get(tool);
        plan = this.rec.checks.plan(
          { name: tool, description: info?.description ?? "", inputSchema: info?.inputSchema ?? null, serverInfo: this.serverInfo },
          this.opts.agent || this.rec.defaultAgent,
          toJsonable(params.arguments) ?? null,
          { strictCode, callId: msg.id, declared: name },
        );
      } catch (e) {
        // An invalid checks file with no good version in force: every checked call fails (`state`).
        const err = e instanceof CheckError ? e : new CheckError((e as Error).message, "state");
        this.diag(`${tool} was not run: ${err.message}`);
        return key === undefined ? { drop: true } : { reply: this.checkError(msg.id, err) };
      }
    }
    let decision: SignedRecord;
    try {
      const content = { input: toJsonable(params.arguments) ?? null, meta } as Record<string, unknown>;
      const extra = plan ? { checks: plan.checks, disclosed: plan.disclosed, disclosedSalt: plan.disclosedSalt } : {};
      decision = this.rec.write("decision", name, content, { agent: this.opts.agent, storeContent: this.opts.storeContent, ...extra });
    } catch (e) {
      // Fail closed: a call that cannot be recorded is not run.
      const why = (e as Error).message;
      this.diag(`${tool} was not run because the call could not be recorded: ${why}`);
      return key === undefined ? { drop: true } : { reply: this.error(msg.id, `signafaide gateway: ${tool} was not run because the call could not be recorded: ${why}`, "not_written") };
    }
    if (plan) return this.checked(msg, key, name, decision, plan);
    if (key === undefined) {
      // A notification: no answer will come, so no outcome. A strict one still waits for its receipt.
      if (!strictCode || this.rec.test) return FORWARD;
      return this.rec.ensureReceipt(decision).then(
        () => FORWARD,
        (e) => {
          this.rec.noteStrictRefused(name, e instanceof SignafaideError ? e : new SignafaideError((e as Error).message));
          return { drop: true } as Route;
        },
      );
    }
    const old = this.calls.get(key);
    if (old && old.state !== "cancelled") this.outcome(old, { error: { type: "NoAnswer", message: "the client used this request id again before the server answered" } });
    const call: Call = { key, name, decision, state: "forwarded" };
    this.calls.set(key, call);
    if (!strictCode || this.rec.test) return FORWARD; // test mode never sends: no receipt to wait for
    call.state = "waiting";
    const gone = (): Route => {
      // Cancelled while it waited: never forwarded, and the client expects no answer.
      if (this.calls.get(key) === call) this.calls.delete(key);
      return { drop: true };
    };
    return this.rec.ensureReceipt(decision).then(
      () => {
        if (call.state === "cancelled") return gone();
        call.state = "forwarded";
        return FORWARD;
      },
      (e) => {
        const err = e instanceof SignafaideError ? e : new SignafaideError((e as Error).message);
        this.rec.noteStrictRefused(name, err);
        if (call.state === "cancelled") return gone();
        this.calls.delete(key);
        return { reply: this.error(msg.id, `${err.message} (strict mode: ${name} did not run)`, err.code) };
      },
    );
  }

  /** A call the tool-call checks looked at (§8 gateway): answered here when a check blocks it,
   * forwarded once the witness rules `allow` when it is strict, else forwarded at once. */
  private checked(msg: Json, key: string | undefined, name: string, decision: SignedRecord, plan: Plan): Route | Promise<Route> {
    const refuse = (err: CheckError, ruling: string, call?: Call): Route => {
      this.write(name, decision, refusedContent(err), outcomeChecks(false, ruling));
      if (call && this.calls.get(call.key) === call) this.calls.delete(call.key);
      return key === undefined ? { drop: true } : { reply: this.checkError(msg.id, err) };
    };
    if (plan.blocked) return refuse(plan.blocked, "not_asked");
    let call: Call | undefined;
    if (key !== undefined) {
      const old = this.calls.get(key);
      if (old && old.state !== "cancelled") this.outcome(old, { error: { type: "NoAnswer", message: "the client used this request id again before the server answered" } });
      call = { key, name, decision, state: "forwarded", checked: true, ruling: "not_asked" };
      this.calls.set(key, call);
    }
    if (!plan.strict) return FORWARD;
    if (call) call.state = "waiting";
    return this.rec.checks.ruling(decision, plan, name).then(([ruling, err]) => {
      if (call) call.ruling = ruling;
      if (err) this.rec.noteStrictRefused(name, err);
      if (call?.state === "cancelled") {
        // Cancelled while it waited: its outcome is written, it was never forwarded, and the client expects no answer.
        if (this.calls.get(call.key) === call) this.calls.delete(call.key);
        return { drop: true };
      }
      if (err) return refuse(err, ruling, call);
      if (call) call.state = "forwarded";
      return FORWARD;
    });
  }

  private cancelled(params: Json): void {
    const key = idKey(params.requestId);
    const call = key === undefined ? undefined : this.calls.get(key);
    if (!call || call.state === "cancelled") return;
    const reason = typeof params.reason === "string" && params.reason ? `: ${params.reason.slice(0, 500)}` : "";
    const when = call.state === "waiting" ? "before the call was forwarded to the server" : "before the server answered";
    // A checked call cancelled while it waited for its ruling never ran, and had no ruling then.
    this.outcome(call, { error: { type: "Cancelled", message: `the client cancelled the call ${when}${reason}` } }, call.state === "waiting" ? { ran: false, ruling: "none" } : undefined);
    if (call.state === "waiting") call.state = "cancelled"; // dropped when its receipt wait ends
    else this.calls.delete(call.key); // a late answer is relayed and changes nothing
  }

  // --- server to client -----------------------------------------------------------------

  private fromServer(line: Buffer): void {
    const msg = this.off ? undefined : parse(line);
    if (msg === undefined) return this.toClient(Buffer.concat([line, NL]));
    const answers = (Array.isArray(msg) ? msg : [msg]).filter((m): m is Json => isObject(m) && typeof m.method !== "string" && idKey(m.id) !== undefined);
    for (const m of answers) this.answer(m);
    // Answers held for a client batch join the server's answer to the rest of that batch.
    const groups = new Set(answers.flatMap((m) => (this.held.has(idKey(m.id)!) ? [this.held.get(idKey(m.id)!)!] : [])));
    for (const m of answers) this.held.delete(idKey(m.id)!);
    const extra = [...groups].flatMap((g) => g.replies.splice(0));
    if (!extra.length) return this.toClient(Buffer.concat([line, NL]));
    if (Array.isArray(msg)) return this.toClient(JSON.stringify([...msg, ...extra]) + "\n");
    this.toClient(Buffer.concat([line, NL]));
    this.toClient(JSON.stringify(extra) + "\n");
  }

  /** An answer from the server to a request of the client's. */
  private answer(m: Json): void {
    const key = idKey(m.id)!;
    if (this.inits.delete(key) && isObject(m.result) && isObject(m.result.serverInfo)) {
      this.serverInfo = { name: m.result.serverInfo.name, version: m.result.serverInfo.version };
    }
    const listing = this.lists.get(key);
    if (listing) {
      this.lists.delete(key);
      this.listed(listing, m);
    }
    const call = this.calls.get(key);
    if (call && call.state === "forwarded") {
      this.calls.delete(key);
      // The result checks run on what the tool returned (§8 step 5); an error answer has none.
      const results = call.checked && !isObject(m.error) ? this.rec.checks.resultEntries(toJsonable(m.result) ?? null) : [];
      this.outcome(call, outcomeContent(m), { ran: true, results });
    }
  }

  private listed(listing: Listing, m: Json): void {
    const result = m.result;
    if (!isObject(result) || !Array.isArray(result.tools)) return;
    for (const t of result.tools) {
      if (!isObject(t) || typeof t.name !== "string" || !t.name) continue;
      listing.names.add(t.name);
      // What the client is shown of the tool: its fingerprints are taken from these (§11.1).
      this.toolInfo.set(t.name, { description: typeof t.description === "string" ? t.description : "", inputSchema: isObject(t.inputSchema) ? toJsonable(t.inputSchema) : null });
    }
    this.undeclared = true;
    if (typeof result.nextCursor === "string" && result.nextCursor) return; // more pages to come
    listing.complete = true;
    this.shown = listing.names;
    this.declareShown();
  }

  /** Declare the tools the client has been shown: the last finished listing, with the pages of
   * the one it is still paging through. Written once per distinct list (the recorder sees to
   * that). A failure is reported once and never stops the relay. */
  private declareShown(): void {
    const paging = this.listing && !this.listing.complete ? this.listing.names : null;
    if (!this.undeclared || (!this.shown && !paging?.size)) return;
    const tools: Record<string, boolean> = {};
    for (const n of [...(this.shown ?? []), ...(paging ?? [])]) tools[this.prefix + n] = true;
    try {
      this.rec.declareTools(tools, { agent: this.opts.agent, source: this.source, origin: "gateway", storeContent: this.opts.storeContent });
      this.undeclared = false;
    } catch (e) {
      if (!this.toldDeclare) this.diag(`could not write the tool declaration: ${(e as Error).message}`);
      this.toldDeclare = true;
    }
  }

  /** The outcome of `call`; with tool-call checks, its `checks` (§2.8): by default the call was
   * forwarded (ran) with the ruling held then, and no result checks. */
  private outcome(call: Call, content: Record<string, unknown>, how: { ran?: boolean; ruling?: string; results?: Json[] } = {}): void {
    const checks = call.checked ? outcomeChecks(how.ran ?? true, how.ruling ?? call.ruling ?? "not_asked", how.results ?? []) : undefined;
    this.write(call.name, call.decision, content, checks);
  }

  private write(name: string, decision: SignedRecord, content: Record<string, unknown>, checks?: Json): void {
    try {
      this.rec.write("outcome", name, content, { agent: decision.envelope.agent, ref: recordHash(decision), storeContent: this.opts.storeContent, checks });
    } catch (e) {
      // The call already ran (or was answered here): report, and never hold back its answer.
      this.diag(`could not write the outcome of ${name}: ${(e as Error).message}`);
    }
  }

  // --- life cycle -----------------------------------------------------------------------

  run(): Promise<GatewayResult> {
    return new Promise<GatewayResult>((resolve) => {
      const { command, args = [] } = this.opts;
      if (this.off) this.diag("SIGNAFAIDE_DISABLED is set: relaying only, nothing is recorded");
      const child = (this.child = spawn(command, args, { stdio: ["pipe", "pipe", this.opts.stderr ? "pipe" : "inherit"], windowsHide: true, env: this.opts.env ?? process.env }));
      const signals: NodeJS.Signals[] = this.opts.forwardSignals === false ? [] : ["SIGINT", "SIGTERM", "SIGHUP"];
      let killer: ReturnType<typeof setTimeout> | undefined;
      const onSignal = (sig: NodeJS.Signals): void => {
        child.kill(sig);
        killer ??= setTimeout(() => child.kill("SIGKILL"), this.opts.killAfterMs ?? 5000);
        killer.unref?.();
      };
      for (const s of signals) process.on(s, onSignal);

      const finish = async (result: GatewayResult, upstream: string): Promise<void> => {
        if (this.done) return;
        this.done = true;
        clearTimeout(killer);
        for (const s of signals) process.off(s, onSignal);
        this.input.off("data", onInput);
        this.input.off("end", onEnd);
        this.input.pause();
        await Promise.allSettled([...this.waiting]);
        // Calls the server never answered: say so, so no decision is left without an outcome.
        for (const call of [...this.calls.values()]) {
          if (call.state !== "cancelled") this.outcome(call, { error: { type: "UpstreamExited", message: `${upstream} before it answered` } });
        }
        this.calls.clear();
        if (!this.off) this.declareShown();
        try {
          // A clean end: this gateway's tools leave the agent's tool list (§8), so no later
          // declaration counts a server that is no longer behind a gateway.
          this.rec.releaseToolSources(this.source);
          if (!this.opts.recorder) await this.rec.shutdown(); // ships what is left; the stop note as the runtime writes it
        } catch (e) {
          this.diag((e as Error).message);
        }
        // Everything relayed is out before the caller ends the process.
        if (this.out.writableLength && !this.out.destroyed) await new Promise<void>((r) => this.out.write("", () => r()));
        resolve(result);
      };

      child.once("error", (e: NodeJS.ErrnoException) => {
        this.diag(`could not start ${command}: ${e.message}`);
        void finish({ code: e.code === "ENOENT" ? 127 : e.code === "EACCES" ? 126 : 1, signal: null }, "the MCP server could not be started");
      });

      // A line that cannot be handled is reported and dropped, never passed on unrecorded, and
      // never takes the relay down. The last line, with no newline after it, takes the same path.
      const guard = (what: string, fn: () => void): void => {
        try {
          fn();
        } catch (e) {
          this.diag(`${what} dropped: ${(e as Error).message}`);
        }
      };
      const clientLines = new Lines((l) => guard("a client message was", () => this.fromClient(l)));
      const serverLines = new Lines((l) => guard("a server message was", () => this.fromServer(l)));
      const onInput = (chunk: Buffer): void => clientLines.push(chunk);
      const onEnd = (): void => {
        // The client closed its side: pass what is left, then close the server's stdin, once no
        // strict call still waits to be forwarded.
        guard("a client message was", () => clientLines.end((rest) => this.fromClient(rest)));
        void Promise.allSettled([...this.waiting]).then(() => child.stdin?.end());
      };
      this.input.on("data", onInput);
      this.input.once("end", onEnd);
      child.stderr?.on("data", (chunk: Buffer) => this.err.write(chunk)); // only when stderr is not this process's own
      child.stdin?.on("error", () => undefined); // the server went away; its exit is handled below
      this.out.on("error", () => child.kill("SIGTERM")); // the client went away
      child.stdout?.on("data", (chunk: Buffer) => serverLines.push(chunk));
      child.once("close", (code, signal) => {
        guard("a server message was", () => serverLines.end((rest) => this.toClient(rest)));
        const how = signal ? `the MCP server was ended by ${signal}` : `the MCP server exited (code ${code ?? 0})`;
        void finish({ code: code ?? 128 + (os.constants.signals[signal as NodeJS.Signals] ?? 0), signal }, how);
      });
    });
  }

}

const NL = Buffer.from("\n");

/** Splits a byte stream into lines at `\n`, whole bytes kept (a UTF-8 character may span chunks). */
class Lines {
  private buf: Buffer = Buffer.alloc(0);
  constructor(private readonly onLine: (line: Buffer) => void) {}

  push(chunk: Buffer | string): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, Buffer.from(chunk)]) : Buffer.from(chunk);
    let start = 0;
    for (let i = this.buf.indexOf(10, start); i !== -1; i = this.buf.indexOf(10, start)) {
      const line = this.buf.subarray(start, i);
      start = i + 1;
      this.onLine(line);
    }
    this.buf = this.buf.subarray(start);
  }

  /** What is left when the stream ends: a last line without a newline. */
  end(onRest: (rest: Buffer) => void): void {
    if (this.buf.length) onRest(this.buf);
    this.buf = Buffer.alloc(0);
  }
}
