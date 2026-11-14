/**
 * The MCP gateway (`signafaide gateway`), in this process: a fake MCP server as its child, and
 * streams in place of the client's stdin and stdout. The built command line has its own tests in
 * gateway-cli.test.ts.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { declaredName, toolNote } from "../src/coverage.js";
import { GATEWAY_ERROR, outcomeContent, runGateway, type GatewayOptions, type GatewayResult } from "../src/gateway.js";
import { verify } from "../src/index.js";
import { recordHash } from "../src/records.js";
import { useProject } from "./helpers.js";

const ctx = useProject();
const SERVER = path.resolve(__dirname, "fake-mcp-server.mjs");
const AGENT = "claims-project";

/** One gateway run: what the client writes, and every line it is sent back. */
class Session {
  readonly raw: string[] = [];
  readonly result: Promise<GatewayResult>;
  stderr = "";
  private stdin = new PassThrough();
  private taken = new Set<number>();
  private wake: (() => void)[] = [];
  private buf = "";

  constructor(opts: Partial<GatewayOptions> = {}, env: Record<string, string> = {}) {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    stdout.on("data", (d) => {
      this.buf += d;
      const parts = this.buf.split("\n");
      this.buf = parts.pop()!;
      this.raw.push(...parts);
      this.wake.splice(0).forEach((w) => w());
    });
    stderr.on("data", (d) => (this.stderr += d));
    this.result = runGateway({
      command: process.execPath,
      args: [SERVER],
      recorder: ctx.rec,
      stdin: this.stdin,
      stdout,
      stderr,
      forwardSignals: false,
      env: { PATH: process.env.PATH ?? "", FAKE_LOG: this.log, ...env },
      ...opts,
    });
  }

  /** What the server received, line by line as it arrived. */
  get log(): string {
    return path.join(ctx.root, "server.log");
  }

  seen(): string[] {
    return fs.existsSync(this.log) ? fs.readFileSync(this.log, "utf8").split("\n").filter(Boolean) : [];
  }

  send(msg: object | string): void {
    this.stdin.write((typeof msg === "string" ? msg : JSON.stringify(msg)) + "\n");
  }

  call(id: number | string, name: string, args: object = {}): void {
    this.send({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
  }

  /** The first line not yet taken that `match` accepts (parsed; a line that is not JSON as text). */
  async next(match: (m: any) => boolean, ms = 8000): Promise<any> {
    const deadline = Date.now() + ms;
    for (;;) {
      for (let i = 0; i < this.raw.length; i++) {
        if (this.taken.has(i)) continue;
        let m: any = this.raw[i];
        try {
          m = JSON.parse(this.raw[i]);
        } catch {
          /* a raw line */
        }
        if (match(m)) {
          this.taken.add(i);
          return m;
        }
      }
      if (Date.now() > deadline) throw new Error(`no such line within ${ms} ms; got ${JSON.stringify(this.raw)}; stderr ${this.stderr}`);
      await new Promise<void>((r) => {
        this.wake.push(r);
        setTimeout(r, 50);
      });
    }
  }

  /** The answer to the client's request `id` (an answer has no method). */
  answer(id: number | string): Promise<any> {
    return this.next((m) => m && typeof m === "object" && !Array.isArray(m) && m.id === id && m.method === undefined);
  }

  /** `tools/list`, every page; returns the names. */
  async list(firstId: number): Promise<string[]> {
    const names: string[] = [];
    let cursor: string | undefined;
    for (let id = firstId; ; id++) {
      this.send({ jsonrpc: "2.0", id, method: "tools/list", ...(cursor ? { params: { cursor } } : {}) });
      const r = (await this.answer(id)).result;
      names.push(...r.tools.map((t: any) => t.name));
      if (!r.nextCursor) return names;
      cursor = r.nextCursor;
    }
  }

  /** The gateway has handled everything sent so far (messages keep their order). */
  async settled(id: number | string = "settled"): Promise<void> {
    this.send({ jsonrpc: "2.0", id, method: "ping" });
    await this.answer(id);
  }

  /** Close the client's side and wait for the server to exit. */
  close(): Promise<GatewayResult> {
    this.stdin.end();
    return this.result;
  }
}

/** Every line of the agent's chain (none yet: an empty list). */
const chain = (agent = AGENT) => ctx.rec.state.chains().filter((c) => c.split("/")[2] === agent).flatMap((c) => ctx.rec.state.readAll(c));
const names = (agent = AGENT) => chain(agent).map((r) => `${r.envelope.kind}:${r.envelope.name}`);
/** The chain without its tool-declaration notes. */
const calls = (agent = AGENT) => chain(agent).filter((r) => !toolNote(r.envelope.kind, r.envelope.name));
const TOOLS = ["ask", "crash", "echo", "fail", "hang", "rpc_error", "slow"];
const DECLARED = ["note:signafaide.tools", ...TOOLS.map((t) => `note:signafaide.tool/${t}`)];

describe("gateway: tool list and calls", () => {
  it("declares the server's tools as recorded, and records a call as a decision before and an outcome after", async () => {
    const s = new Session();
    s.send({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
    expect((await s.answer(0)).result.serverInfo.name).toBe("fake");
    expect(await s.list(1)).toHaveLength(7);
    // Declared when the listing ended: one header, then one note per tool, in name order.
    expect(names()).toEqual(DECLARED);
    const [header, first] = chain();
    expect(header.content).toEqual({ source: "gateway", tools: 7, recorded: 7, unrecorded: 0 });
    expect(first.content).toEqual({ tool: "ask", recorded: true });

    s.call(2, "echo", { path: "/tmp/a", n: 1 });
    const answer = await s.answer(2);
    expect(answer.result.content[0].text).toBe('{"path":"/tmp/a","n":1}');
    const [d, o] = calls();
    expect([d.envelope.kind, d.envelope.name, d.envelope.ref]).toEqual(["decision", "echo", null]);
    expect(d.content).toEqual({ input: { path: "/tmp/a", n: 1 }, meta: { sdk: expect.stringMatching(/^signafaide-js\//), gateway: true } });
    expect([o.envelope.kind, o.envelope.name, o.envelope.ref]).toEqual(["outcome", "echo", recordHash(d)]);
    expect(o.content).toEqual({ output: answer.result });
    expect(o.envelope.seq).toBe(d.envelope.seq + 1);

    // The same list again writes nothing new.
    await s.list(10);
    expect(names().slice(0, 8)).toEqual(DECLARED);
    expect(names()).toHaveLength(10);
    expect(await s.close()).toEqual({ code: 0, signal: null });
    expect(s.stderr).toContain("fake-mcp-server: started"); // the server's stderr passes through

    // The local verify reads the declaration from the envelopes alone.
    const report = await verify();
    expect(report.ok).toBe(true);
    expect(report.coverageLines()).toEqual([`_pending/nokey/${AGENT}: all 7 declared tools are recorded`]);
    expect(String(report)).toContain(`coverage: _pending/nokey/${AGENT}: all 7 declared tools are recorded`);
  });

  it("relays every line unchanged, both ways: spacing, key order, notifications, lines that are not JSON", async () => {
    const s = new Session();
    const odd = '{ "method":"tools/call","jsonrpc" : "2.0", "params":{"arguments":{"b":2,"a":[1 , 2]},"name":"echo"},  "id":7 }';
    s.send(odd);
    await s.answer(7);
    s.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    s.send("this is not JSON");
    s.send({ jsonrpc: "2.0", id: 8, method: "test/raw", params: { line: '{"jsonrpc":"2.0",  "method":"notifications/message","params":{"level":"info","data":"héllo \\u00e9"}}' } });
    await s.next((m) => m?.method === "notifications/message");
    s.send({ jsonrpc: "2.0", id: 9, method: "test/raw", params: { line: "plain text from the server" } });
    await s.next((m) => m === "plain text from the server");
    await s.settled();
    expect(s.seen().slice(0, 3)).toEqual([odd, '{"jsonrpc":"2.0","method":"notifications/initialized"}', "this is not JSON"]);
    expect(s.raw).toContain('{"jsonrpc":"2.0",  "method":"notifications/message","params":{"level":"info","data":"héllo \\u00e9"}}');
    await s.close();
  });

  it("follows pagination: the declaration is the union of the pages the client was shown", async () => {
    const s = new Session({}, { FAKE_TOOLS: JSON.stringify(["a", "b", "c", "d", "e"]), FAKE_PAGE: "2" });
    s.send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    const page1 = (await s.answer(1)).result;
    expect([page1.tools.length, page1.nextCursor]).toEqual([2, "2"]);
    expect(names()).toEqual([]); // more pages to come: nothing declared yet
    // A call while the client is still paging: the pages shown so far are declared first.
    s.call(2, "a");
    await s.answer(2);
    expect(names()).toEqual(["note:signafaide.tools", "note:signafaide.tool/a", "note:signafaide.tool/b", "decision:a", "outcome:a"]);
    s.send({ jsonrpc: "2.0", id: 3, method: "tools/list", params: { cursor: "2" } });
    await s.answer(3);
    expect(names()).toHaveLength(5);
    s.send({ jsonrpc: "2.0", id: 4, method: "tools/list", params: { cursor: "4" } });
    expect((await s.answer(4)).result.nextCursor).toBeUndefined();
    expect(names().slice(5)).toEqual(["note:signafaide.tools", ...["a", "b", "c", "d", "e"].map((t) => `note:signafaide.tool/${t}`)]);
    await s.close();
    expect((await verify()).coverageLines()).toEqual([`_pending/nokey/${AGENT}: all 5 declared tools are recorded`]);
  });

  it("declares again when the server's tool list changes", async () => {
    const s = new Session({}, { FAKE_TOOLS: JSON.stringify(["echo", "old"]) });
    await s.list(1);
    s.send({ jsonrpc: "2.0", method: "test/change_tools", params: { tools: ["echo", "new_tool"] } });
    expect((await s.next((m) => m?.method === "notifications/tools/list_changed")).jsonrpc).toBe("2.0");
    expect(await s.list(5)).toEqual(["echo", "new_tool"]);
    expect(names()).toEqual(["note:signafaide.tools", "note:signafaide.tool/echo", "note:signafaide.tool/old", "note:signafaide.tools", "note:signafaide.tool/echo", "note:signafaide.tool/new_tool"]);
    s.call(9, "old"); // no longer listed: recorded all the same, and the verifier says so
    await s.answer(9);
    await s.close();
    expect((await verify()).coverageLines()).toEqual([
      `_pending/nokey/${AGENT}: all 2 declared tools are recorded`,
      `_pending/nokey/${AGENT}: 1 recorded tool is not in the declared tool list: old`,
    ]);
  });

  it("records a tool error and a JSON-RPC error as errors, and relays them", async () => {
    const s = new Session();
    s.call(1, "fail");
    const failed = await s.answer(1);
    expect(failed.result.isError).toBe(true);
    s.call(2, "rpc_error");
    expect((await s.answer(2)).error).toEqual({ code: -32602, message: "bad arguments" });
    const [, o1, , o2] = calls();
    expect(o1.content).toEqual({ error: { type: "ToolError", message: "no such file" }, output: failed.result });
    expect(o2.content).toEqual({ error: { type: "JsonRpcError", message: "bad arguments", code: -32602 } });
    expect(outcomeContent({ result: { content: [], isError: true } })).toEqual({ error: { type: "ToolError", message: "the tool reported an error" }, output: { content: [], isError: true } });
    await s.close();
  });

  it("the server dies during a call: the outcome says so, and its exit code is the gateway's", async () => {
    const s = new Session();
    s.call(1, "slow", { ms: 60_000, tag: "never" });
    s.call(2, "crash");
    expect(await s.result).toEqual({ code: 3, signal: null });
    const got = calls();
    expect(got.map((r) => `${r.envelope.kind}:${r.envelope.name}`)).toEqual(["decision:slow", "decision:crash", "outcome:slow", "outcome:crash"]);
    for (const [d, o] of [
      [got[0], got[2]],
      [got[1], got[3]],
    ]) {
      expect(o.envelope.ref).toBe(recordHash(d));
      expect(o.content).toEqual({ error: { type: "UpstreamExited", message: "the MCP server exited (code 3) before it answered" } });
    }
    expect(s.raw).toEqual([]); // nothing was invented for the client
  });

  it("propagates the server's exit code, and says when it cannot be started", async () => {
    const s = new Session();
    s.send({ jsonrpc: "2.0", method: "test/exit", params: { code: 7 } });
    expect(await s.result).toEqual({ code: 7, signal: null });
    const missing = new Session({ command: path.join(ctx.root, "no-such-server") });
    expect(await missing.result).toEqual({ code: 127, signal: null });
    expect(missing.stderr).toMatch(/signafaide gateway: could not start .*no-such-server/);
  });

  it("a cancelled call gets an outcome that says so; the notification still reaches the server", async () => {
    const s = new Session();
    s.call(1, "hang");
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1, reason: "user pressed stop" } });
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 99 } }); // not a call of ours
    await s.settled();
    const [d, o] = calls();
    expect(o.envelope.ref).toBe(recordHash(d));
    expect(o.content).toEqual({ error: { type: "Cancelled", message: "the client cancelled the call before the server answered: user pressed stop" } });
    expect(s.seen().filter((l) => l.includes("notifications/cancelled"))).toHaveLength(2);
    await s.close();
    expect(calls()).toHaveLength(2); // the server's exit adds no second outcome
  });

  it("matches answers to calls by id: interleaved calls, string and number ids, and the server's own requests", async () => {
    const s = new Session();
    // Number 1 and string "1" are different ids; the slower call is sent first.
    s.call(1, "slow", { ms: 300, tag: "number" });
    s.call("1", "slow", { ms: 20, tag: "string" });
    // The server asks the client something under the id the client used for its call.
    s.call(5, "ask");
    const asked = await s.next((m) => m?.method === "sampling/createMessage");
    expect(asked.id).toBe(5);
    expect(calls().filter((r) => r.envelope.kind === "outcome")).toHaveLength(0); // a request from the server is not an answer
    s.send({ jsonrpc: "2.0", id: 5, result: { role: "assistant" } }); // the client's answer to the server's request
    expect((await s.answer(5)).result.content[0].text).toBe('client said {"role":"assistant"}');
    expect((await s.answer("1")).result.content[0].text).toBe("slow string");
    expect((await s.answer(1)).result.content[0].text).toBe("slow number");
    const got = calls();
    const decisions = got.filter((r) => r.envelope.kind === "decision");
    expect(decisions.map((d) => (d.content!.input as any).tag ?? "ask")).toEqual(["number", "string", "ask"]);
    const outcomeOf = (d: (typeof got)[number]) => got.find((r) => r.envelope.ref === recordHash(d))!;
    expect((outcomeOf(decisions[0]).content as any).output.content[0].text).toBe("slow number");
    expect((outcomeOf(decisions[1]).content as any).output.content[0].text).toBe("slow string");
    expect((outcomeOf(decisions[2]).content as any).output.content[0].text).toBe('client said {"role":"assistant"}');
    expect(got.filter((r) => r.envelope.kind === "outcome")).toHaveLength(3);
    expect(s.seen().at(-1)).toBe('{"jsonrpc":"2.0","id":5,"result":{"role":"assistant"}}'); // passed on as it was
    await s.close();
  });

  it("a batch: each call in it is recorded, and the server's one answer comes back whole", async () => {
    const s = new Session();
    s.send([
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } },
      { jsonrpc: "2.0", id: 2, method: "ping" },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "fail" } },
    ]);
    const batch = await s.next((m) => Array.isArray(m));
    expect(batch.map((m: any) => m.id)).toEqual([1, 2, 3]);
    expect(calls().map((r) => `${r.envelope.kind}:${r.envelope.name}`)).toEqual(["decision:echo", "decision:fail", "outcome:echo", "outcome:fail"]);
    await s.close();
  });
});

describe("gateway: names", () => {
  it("--name-prefix goes before every recorded and declared name", async () => {
    const s = new Session({ namePrefix: "files." }, { FAKE_TOOLS: JSON.stringify(["echo", "read"]) });
    await s.list(1);
    s.call(3, "echo", { x: 1 });
    await s.answer(3);
    expect(names()).toEqual(["note:signafaide.tools", "note:signafaide.tool/files.echo", "note:signafaide.tool/files.read", "decision:files.echo", "outcome:files.echo"]);
    expect((calls()[0].content!.meta as any).tool).toBe("echo"); // the server's own name is kept with the content
    expect(JSON.parse(s.seen().at(-1)!).params.name).toBe("echo"); // and the server is asked for its own name
    await s.close();
    expect((await verify()).coverageLines()).toEqual([`_pending/nokey/${AGENT}: all 2 declared tools are recorded`]);
  });

  it("a tool name too long for an envelope is cut the same way in the declaration and in the call", async () => {
    const long = "export_" + "customer_ledger_".repeat(12); // 199 characters
    const s = new Session({}, { FAKE_TOOLS: JSON.stringify([long, "echo"]) });
    await s.list(1);
    s.call(3, long, { q: 1 });
    expect((await s.answer(3)).result.content[0].text).toBe('{"q":1}');
    const cut = declaredName(long);
    expect([...cut].length).toBe(101);
    expect(cut).toMatch(/^export_(customer_ledger_)+.*~[0-9a-f]{8}$/);
    expect(names()).toEqual(["note:signafaide.tools", "note:signafaide.tool/echo", `note:signafaide.tool/${cut}`, `decision:${cut}`, `outcome:${cut}`]);
    expect(chain()[2].content).toEqual({ tool: long, recorded: true });
    expect((calls()[0].content!.meta as any).tool).toBe(long);
    await s.close();
    const report = await verify();
    expect(report.ok).toBe(true);
    expect(report.coverageLines()).toEqual([`_pending/nokey/${AGENT}: all 2 declared tools are recorded`]);
  });

  it("two gateways of one agent: each keeps its own tools in the agent's list", async () => {
    const a = new Session({ namePrefix: "a." }, { FAKE_TOOLS: JSON.stringify(["read"]) });
    await a.list(1);
    const b = new Session({ namePrefix: "b." }, { FAKE_TOOLS: JSON.stringify(["write"]) });
    await b.list(1);
    b.call(2, "write");
    await b.answer(2);
    expect(names()).toEqual(["note:signafaide.tools", "note:signafaide.tool/a.read", "note:signafaide.tools", "note:signafaide.tool/a.read", "note:signafaide.tool/b.write", "decision:b.write", "outcome:b.write"]);
    expect(Object.keys(ctx.rec.state.toolSources(AGENT))).toEqual(["gateway:a.", "gateway:b."]);
    expect((await verify()).coverageLines()).toEqual([`_pending/nokey/${AGENT}: all 2 declared tools are recorded`]);

    // A gateway that ends leaves the agent's tool list: the next declaration no longer counts
    // its tools as recorded (its server may now be called with no gateway in front).
    await a.close();
    expect(Object.keys(ctx.rec.state.toolSources(AGENT))).toEqual(["gateway:b."]);
    expect(names()).toHaveLength(7); // ending writes nothing to the chain
    const c = new Session({ namePrefix: "c." }, { FAKE_TOOLS: JSON.stringify(["search"]) });
    await c.list(1);
    expect(names().slice(7)).toEqual(["note:signafaide.tools", "note:signafaide.tool/b.write", "note:signafaide.tool/c.search"]);
    await b.close();
    await c.close();
    expect(ctx.rec.state.toolSources(AGENT)).toEqual({});
  });
});

describe("gateway: a call that cannot be recorded does not run", () => {
  it("fails closed when the local state cannot be written", async () => {
    const s = new Session();
    await s.list(1);
    const dir = path.dirname(ctx.rec.state.chainPath(`_pending/nokey/${AGENT}`));
    fs.chmodSync(dir, 0o500);
    try {
      s.call(2, "echo", { a: 1 });
      const refused = await s.answer(2);
      expect(refused.error.code).toBe(GATEWAY_ERROR);
      expect(refused.error.message).toMatch(/^signafaide gateway: echo was not run because the call could not be recorded: cannot write signafAIde's local state/);
      expect(refused.error.data).toEqual({ signafaide: "not_written" });
      // In a batch, the refused call is taken out and its error comes back with the rest.
      s.send([
        { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo" } },
        { jsonrpc: "2.0", id: 4, method: "ping" },
      ]);
      const batch = await s.next((m) => Array.isArray(m));
      expect(batch.map((m: any) => [m.id, !!m.error])).toEqual([
        [4, false],
        [3, true],
      ]);
      await s.settled();
    } finally {
      fs.chmodSync(dir, 0o700);
    }
    expect(s.seen().filter((l) => l.includes("tools/call"))).toEqual([]); // the server never saw either call
    expect(s.stderr).toContain("signafaide gateway: echo was not run because the call could not be recorded");
    expect(calls()).toEqual([]);
    // Writable again: calls run and are recorded.
    s.call(5, "echo");
    expect((await s.answer(5)).result).toBeDefined();
    expect(calls()).toHaveLength(2);
    await s.close();
  });

  it("--strict without an API key: refused with the SDK's strict message, and never forwarded", async () => {
    const s = new Session({ strict: true });
    s.call(1, "echo");
    const refused = await s.answer(1);
    expect(refused.error.code).toBe(GATEWAY_ERROR);
    expect(refused.error.message).toMatch(/^Strict mode needs the service's receipt, and there is no API key: .* \(strict mode: echo did not run\)$/);
    expect(refused.error.data).toEqual({ signafaide: "no_key" });
    await s.settled();
    expect(s.seen().filter((l) => l.includes("tools/call"))).toEqual([]);
    expect(calls().map((r) => r.envelope.kind)).toEqual(["decision"]); // the decision stays; nothing ran, so no outcome
    expect(ctx.service.calls).toEqual([]); // and nothing was sent
    await s.close();
  });

  it("--strict with a witness: the call is forwarded only once its decision is co-signed", async () => {
    await ctx.rec.createSandbox();
    const s = new Session({ strict: true });
    s.call(1, "echo", { a: 1 });
    expect((await s.answer(1)).result.content[0].text).toBe('{"a":1}');
    expect(ctx.service.calls).toContain("POST /v1/records");
    const [d] = calls("claims-project");
    expect(d.receipt).toBeDefined();
    // The witness refuses: the call does not run.
    ctx.service.failAlways = [429, { error: { code: "quota_exceeded", message: "The monthly allowance is used up." } }];
    s.call(2, "echo");
    const refused = await s.answer(2);
    expect(refused.error.message).toContain("(strict mode: echo did not run)");
    expect(refused.error.data).toEqual({ signafaide: "quota_exceeded" });
    await s.settled();
    expect(s.seen().filter((l) => l.includes("tools/call"))).toHaveLength(1);
    ctx.service.failAlways = null;
    await s.close();
  });

  it("--strict-tools: only the named tools wait for the witness; a strict call cancelled while it waits is never forwarded", async () => {
    await ctx.rec.createSandbox();
    const s = new Session({ strictTools: ["slow"] });
    ctx.service.delayMs = 400;
    s.call(1, "slow", { ms: 1, tag: "strict" });
    s.call(2, "echo", { fast: true }); // not strict: goes straight through, ahead of the waiting call
    expect((await s.answer(2)).result.content[0].text).toBe('{"fast":true}');
    expect(s.seen().filter((l) => l.includes('"slow"'))).toEqual([]);
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } });
    await new Promise((r) => setTimeout(r, 1200));
    ctx.service.delayMs = 0;
    await s.settled();
    expect(s.seen().filter((l) => l.includes('"slow"'))).toEqual([]); // cancelled before its receipt: not forwarded
    const slow = calls().filter((r) => r.envelope.name === "slow");
    expect(slow.map((r) => r.envelope.kind)).toEqual(["decision", "outcome"]);
    expect(slow[1].content).toEqual({ error: { type: "Cancelled", message: "the client cancelled the call before the call was forwarded to the server" } });
    await s.close();
  });

  it("SIGNAFAIDE_DISABLED=1: a plain relay, nothing recorded", async () => {
    process.env.SIGNAFAIDE_DISABLED = "1";
    try {
      const s = new Session();
      await s.list(1);
      s.call(2, "echo", { a: 1 });
      expect((await s.answer(2)).result.content[0].text).toBe('{"a":1}');
      await s.close();
      expect(s.stderr).toContain("SIGNAFAIDE_DISABLED is set: relaying only, nothing is recorded");
      expect(ctx.rec.state.chains()).toEqual([]);
    } finally {
      delete process.env.SIGNAFAIDE_DISABLED;
    }
  });
});
