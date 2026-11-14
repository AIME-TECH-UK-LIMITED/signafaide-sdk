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
 * It records every call that goes through it. A call the application makes around it is still
 * not recorded, so the deployment has to make the gateway the only route to those tools.
 *
 * Nothing but relayed protocol lines is ever written to stdout; diagnostics go to stderr.
 * No MCP library is used: a line that is not JSON, or any other method, is passed on as it is.
 */

import { spawn, type ChildProcess } from "node:child_process";
import * as os from "node:os";
import type { Readable, Writable } from "node:stream";
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

type Json = Record<string, any>;
type Verdict = { forward: true } | { reply: Json } | { drop: true };
const FORWARD: Verdict = { forward: true };

interface Call {
  key: string;
  /** The tool's name as recorded: prefix, then cut as a declaration holds it (§2.6). */
  name: string;
  decision: SignedRecord;
  /** `waiting`: strict, not forwarded yet. */
  state: "waiting" | "forwarded" | "cancelled";
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

  private send(v: Verdict, original: Buffer): void {
    if ("forward" in v) this.toServer(Buffer.concat([original, NL]));
    else if ("reply" in v) this.toClient(JSON.stringify(v.reply) + "\n");
  }

  private error(id: unknown, message: string, code: string): Json {
    return { jsonrpc: "2.0", id: id ?? null, error: { code: GATEWAY_ERROR, message, data: { signafaide: code } } };
  }

  // --- client to server -----------------------------------------------------------------

  private fromClient(line: Buffer): void {
    const msg = this.off ? undefined : parse(line);
    if (msg === undefined) return this.toServer(Buffer.concat([line, NL]));
    if (Array.isArray(msg)) return this.clientBatch(msg, line);
    const v = this.clientMessage(msg);
    if (v instanceof Promise) this.later(v.then((got) => this.send(got, line)));
    else this.send(v, line);
  }

  /** Keep a strict call's wait, so the server's stdin is not closed under it. */
  private later(p: Promise<void>): void {
    const tracked = p.catch((e) => this.diag(`${(e as Error).message}`)).finally(() => this.waiting.delete(tracked));
    this.waiting.add(tracked);
  }

  /** A batch: each entry is judged like a single message. Entries that may not run are taken
   * out and answered here; their answers travel with the server's answer to the rest. */
  private clientBatch(msgs: unknown[], line: Buffer): void {
    const verdicts = msgs.map((m) => this.clientMessage(m));
    const finish = (vs: Verdict[]): void => {
      const forward = msgs.filter((_, i) => "forward" in vs[i]);
      const replies = vs.flatMap((v) => ("reply" in v ? [v.reply] : []));
      if (forward.length === msgs.length) return this.toServer(Buffer.concat([line, NL]));
      if (forward.length) this.toServer(JSON.stringify(forward) + "\n");
      if (!replies.length) return;
      const answered = forward.flatMap((m) => (isObject(m) && typeof m.method === "string" && idKey(m.id) !== undefined ? [idKey(m.id)!] : []));
      if (!answered.length) return this.toClient(JSON.stringify(replies) + "\n");
      const group = { replies };
      for (const k of answered) this.held.set(k, group);
    };
    if (verdicts.some((v) => v instanceof Promise)) this.later(Promise.all(verdicts).then(finish));
    else finish(verdicts as Verdict[]);
  }

  private clientMessage(msg: unknown): Verdict | Promise<Verdict> {
    // No method: an answer to a request the server made (sampling, roots). Not ours to read.
    if (!isObject(msg) || typeof msg.method !== "string") return FORWARD;
    const key = idKey(msg.id);
    if (msg.method === "tools/list" && key !== undefined) {
      // No cursor: the client starts a new listing. A cursor continues the one it is paging through.
      const cursor = isObject(msg.params) ? msg.params.cursor : undefined;
      if (typeof cursor !== "string" || !cursor || !this.listing) this.listing = { names: new Set(), complete: false };
      this.lists.set(key, this.listing);
    } else if (msg.method === "notifications/cancelled") {
      this.cancelled(isObject(msg.params) ? msg.params : {});
    } else if (msg.method === "tools/call") {
      return this.call(msg, key);
    }
    return FORWARD;
  }

  private call(msg: Json, key: string | undefined): Verdict | Promise<Verdict> {
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
    let decision: SignedRecord;
    try {
      const content = { input: toJsonable(params.arguments) ?? null, meta } as Record<string, unknown>;
      decision = this.rec.write("decision", name, content, { agent: this.opts.agent, storeContent: this.opts.storeContent });
    } catch (e) {
      // Fail closed: a call that cannot be recorded is not run.
      const why = (e as Error).message;
      this.diag(`${tool} was not run because the call could not be recorded: ${why}`);
      return key === undefined ? { drop: true } : { reply: this.error(msg.id, `signafaide gateway: ${tool} was not run because the call could not be recorded: ${why}`, "not_written") };
    }
    if (key === undefined) return FORWARD; // a notification: no answer will come, so no outcome
    const old = this.calls.get(key);
    if (old && old.state !== "cancelled") this.outcome(old, { error: { type: "NoAnswer", message: "the client used this request id again before the server answered" } });
    const call: Call = { key, name, decision, state: "forwarded" };
    this.calls.set(key, call);
    if (!(this.opts.strict || this.strictTools.has(tool)) || this.rec.test) return FORWARD; // test mode never sends: no receipt to wait for
    call.state = "waiting";
    const gone = (): Verdict => {
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
        this.rec.warnStrictRefused(name, err);
        if (call.state === "cancelled") return gone();
        this.calls.delete(key);
        return { reply: this.error(msg.id, `${err.message} (strict mode: ${name} did not run)`, err.code) };
      },
    );
  }

  private cancelled(params: Json): void {
    const key = idKey(params.requestId);
    const call = key === undefined ? undefined : this.calls.get(key);
    if (!call || call.state === "cancelled") return;
    const reason = typeof params.reason === "string" && params.reason ? `: ${params.reason.slice(0, 500)}` : "";
    const when = call.state === "waiting" ? "before the call was forwarded to the server" : "before the server answered";
    this.outcome(call, { error: { type: "Cancelled", message: `the client cancelled the call ${when}${reason}` } });
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
    const listing = this.lists.get(key);
    if (listing) {
      this.lists.delete(key);
      this.listed(listing, m);
    }
    const call = this.calls.get(key);
    if (call && call.state === "forwarded") {
      this.calls.delete(key);
      this.outcome(call, outcomeContent(m));
    }
  }

  private listed(listing: Listing, m: Json): void {
    const result = m.result;
    if (!isObject(result) || !Array.isArray(result.tools)) return;
    for (const t of result.tools) if (isObject(t) && typeof t.name === "string" && t.name) listing.names.add(t.name);
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

  private outcome(call: Call, content: Record<string, unknown>): void {
    try {
      this.rec.write("outcome", call.name, content, { agent: call.decision.envelope.agent, ref: recordHash(call.decision), storeContent: this.opts.storeContent });
    } catch (e) {
      // The call already ran: report, and never hold back its answer.
      this.diag(`could not write the outcome of ${call.name}: ${(e as Error).message}`);
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
      // never takes the relay down.
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
        guard("a client message was", () => clientLines.end((rest) => (this.off ? this.toServer(rest) : this.fromClientTail(rest))));
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

  /** A last client line with no newline: judged like any other, and sent without one. */
  private fromClientTail(rest: Buffer): void {
    const msg = parse(rest);
    const v = msg === undefined || Array.isArray(msg) ? FORWARD : this.clientMessage(msg);
    const put = (got: Verdict): void => {
      if ("forward" in got) this.toServer(rest);
      else if ("reply" in got) this.toClient(JSON.stringify(got.reply) + "\n");
    };
    if (v instanceof Promise) this.later(v.then(put));
    else put(v);
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
