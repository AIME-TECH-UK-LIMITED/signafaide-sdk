/** Fix round 3, with a witness: the background sender, BLOCKED chains and repair, clocks ahead,
 * ephemeral disks, segments, claim links and errors about the API key. */
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main, statusLines } from "../src/cli.js";
import { flush, note, verify } from "../src/index.js";
import { Recorder, configure, getRecorder } from "../src/runtime.js";
import { State } from "../src/state.js";
import { useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });
const rec = (): Recorder => getRecorder();
const tick = (r: Recorder): Promise<void> => (r as any).tick();
const recordCalls = () => ctx.service.calls.filter((c) => c === "POST /v1/records").length;
const chain = () => rec().state.chains().find((c) => c.endsWith("/claims-project"))!;

async function cli(...args: string[]): Promise<[number, string]> {
  const out: string[] = [];
  const log = console.log;
  const err = console.error;
  console.log = (s: string) => out.push(s);
  console.error = (s: string) => out.push(s);
  try {
    return [await main(args), out.join("\n")];
  } finally {
    console.log = log;
    console.error = err;
  }
}

afterEach(() => {
  delete process.env.SIGNAFAIDE_SEGMENT_BYTES;
  for (const k of Object.keys(process.env)) if (k.startsWith("SIGNAFAIDE_AGENT_KEY_")) delete process.env[k];
});

describe("background sender", () => {
  it("quota_exceeded stops sending until the configuration changes; `flush` still tries", async () => {
    ctx.service.quota = 0;
    const r = rec();
    for (let i = 0; i < 5; i++) note(`n${i}`, {});
    await tick(r);
    const after = ctx.service.calls.length;
    expect(recordCalls()).toBe(1);
    for (let i = 0; i < 20; i++) await tick(r); // a storm would send 20 more
    expect(ctx.service.calls.length).toBe(after);
    expect((await r.flush()).errors).not.toEqual({}); // explicit: tries once
    expect(recordCalls()).toBe(2);
    ctx.service.quota = null;
    fs.utimesSync(r.state.keyDir(""), new Date(), new Date(Date.now() + 5000)); // the configuration changed
    await tick(r);
    expect(r.state.outboxSize()).toBe(0);
  });

  it("one flush in flight, and forced flushes honour the backoff", async () => {
    ctx.service.failAlways = [503, { error: { code: "unavailable", message: "Down for maintenance.", docs: "d" } }];
    const r = configure({ quiet: true, flushSize: 5, flushIntervalMs: 60_000 });
    for (let i = 0; i < 60; i++) r.write("note", `n${i}`, {}); // 12 forced flushes in a storm
    await new Promise((res) => setTimeout(res, 300));
    expect(recordCalls()).toBe(1);
    for (let i = 0; i < 40; i++) r.write("note", `m${i}`, {});
    await new Promise((res) => setTimeout(res, 300));
    expect(recordCalls()).toBe(1); // inside the backoff
    ctx.service.failAlways = null;
  });

  it("a witness that never answers: one request at a time, and registration is not retried every tick", async () => {
    const conns: net.Socket[] = [];
    const hole = net.createServer((s) => conns.push(s));
    await new Promise<void>((res) => hole.listen(0, "127.0.0.1", res));
    const url = `http://127.0.0.1:${(hole.address() as net.AddressInfo).port}`;
    try {
      const r = configure({ quiet: true, url, flushIntervalMs: 20 });
      r.write("note", "n", {});
      await new Promise((res) => setTimeout(res, 1200)); // 60 ticks
      expect(conns.length).toBe(1);
      r.close();
    } finally {
      for (const c of conns) c.destroy();
      hole.close();
    }
  });
});

describe("BLOCKED chains", () => {
  it("a revoked key: said plainly with the next step, status and verify fail, repair recovers", async () => {
    note("a", {});
    await flush();
    const prj = ctx.service.project();
    const key: any = [...prj.agents.get("claims-project").values()][0];
    key.valid_to = new Date().toISOString(); // revoked in the console
    note("b", {});
    note("c", {});
    const e = Object.values((await flush()).errors)[0];
    expect(e.message).toMatch(/agent key [0-9a-f]{16} was revoked.*Run `signafaide repair --agent claims-project`.*gives the agent a new key/);
    expect((await statusLines(rec())).join("\n")).toMatch(/BLOCKED .*claims-project: refused by the witness: .*revoked/);
    expect((await cli("status"))[0]).toBe(1);
    const [vcode, vout] = await cli("verify");
    expect(vcode).toBe(1);
    expect(vout).toMatch(/^FAIL: 1 chain cannot ship|^BLOCKED/m);
    expect(vout).toMatch(/BLOCKED: 1 chain cannot ship|FAIL: 1 chain cannot ship/);
    expect((await cli("keys", "rotate"))[0]).toBe(0);
    note("d", {}); // signed by the new key, behind the revoked key's records
    const e2 = Object.values((await flush()).errors)[0];
    expect(e2.message).toMatch(/after it was revoked or retired cannot be co-signed.*signafaide repair --agent claims-project/);
    const [rcode, rout] = await cli("repair");
    expect(rcode, rout).toBe(0);
    expect(rout).toMatch(/set aside 3 records in .*held/);
    const f = await flush();
    expect(f.errors).toEqual({});
    expect(f.left).toBe(0);
    const v = await verify();
    expect(v.ok, String(v)).toBe(true);
    expect(v.after.join("\n")).toMatch(/held aside by `signafaide repair`: 3 records in 1 segment/);
    expect(rec().state.blocked()).toEqual({});
    const held = rec().state.heldSegments()[0][2];
    const noteRec = rec().state.readAll(chain()).at(-1)!;
    expect(noteRec.envelope.name).toBe("signafaide.repair");
    expect((noteRec.content as any).records).toBe(3);
    expect(held.map((x) => x.envelope.seq)).toEqual([2, 3, 4]);
  });

  it("a clock ahead on the first run: registration still works, the refusal says so, repair recovers", async () => {
    const st = rec().state;
    st.loadKey("claims-project");
    const doc = JSON.parse(fs.readFileSync(st.keyPath("claims-project"), "utf8"));
    doc.created = new Date(Date.now() + 3_600_000).toISOString(); // the key was made an hour ahead
    fs.writeFileSync(st.keyPath("claims-project"), JSON.stringify(doc));
    note("a", {});
    const e = Object.values((await flush()).errors)[0];
    expect(ctx.service.registrations.length + ctx.service.calls.filter((c) => c === "POST /v1/agents").length).toBeGreaterThan(0);
    expect(ctx.service.calls).toContain("POST /v1/agents");
    expect(e.message).toMatch(/ahead of the service clock.*This machine's clock is ahead.*signafaide repair --agent claims-project/s);
    const d = rec().diagnose();
    expect(d.map((b) => b.code)).toEqual(["clock_ahead"]);
    expect((await cli("repair"))[0]).toBe(0);
    const f = await flush();
    expect(f.errors).toEqual({});
    expect((await verify()).ok).toBe(true);
  });
});

describe("ephemeral disk", () => {
  it("a new instance with its key from the environment continues the witness's chain", async () => {
    const st = rec().state;
    st.loadKey("worker-0");
    process.env.SIGNAFAIDE_AGENT_KEY_WORKER_0 = fs.readFileSync(st.keyPath("worker-0"), "utf8");
    note("a", {}, { agent: "worker-0" });
    note("b", {}, { agent: "worker-0" });
    await flush();
    // The disk is gone: no chain, no config. The API key is still in the environment.
    const env = fs.readFileSync(path.join(ctx.root, ".env"), "utf8");
    fs.rmSync(st.home, { recursive: true, force: true });
    const r = configure({ quiet: true, flushIntervalMs: 3_600_000 });
    expect(r.state.bucket(r.apiKey).startsWith("_pending/")).toBe(true);
    note("c", {}, { agent: "worker-0" });
    const f = await flush();
    expect(f.errors).toEqual({});
    expect(ctx.service.project().heads.get("worker-0").head.seq).toBe(3);
    expect(env).toContain("SIGNAFAIDE_API_KEY");
  });
});

describe("segments", () => {
  it("a shipped chain rolls into sealed segments and keeps chaining", async () => {
    process.env.SIGNAFAIDE_SEGMENT_BYTES = "4000";
    for (let i = 0; i < 12; i++) note(`n${i}`, { i });
    await flush();
    const segs = rec().state.segments(chain());
    expect(segs.length).toBeGreaterThan(0);
    expect(rec().state.tail(chain())[0]).toBe(12);
    for (let i = 0; i < 12; i++) note(`m${i}`, { i });
    expect((await flush()).errors).toEqual({});
    expect(rec().state.readAll(chain()).map((r) => r.envelope.seq)).toEqual(Array.from({ length: 24 }, (_, i) => i + 1));
    expect((await verify()).ok).toBe(true);
  });
});

describe("status and errors", () => {
  it("a claim link already used is not shown", async () => {
    expect((await statusLines(rec())).join("\n")).toMatch(/claim: http/);
    ctx.service.project().claimed = true;
    const out = (await statusLines(rec())).join("\n");
    expect(out).toContain("claim: done");
    expect(out).not.toMatch(/claim: http/);
    expect(rec().state.sandbox()!.claimed).toBe(true);
  });

  it("a wrong API key: the error names the key, not another project's chain", async () => {
    note("a", {});
    await flush();
    const r = configure({ quiet: true, apiKey: "sfa_test_" + "9".repeat(32) });
    r.write("note", "b", {});
    const errs = (await r.flush()).errors;
    expect(Object.keys(errs)).toEqual(["API key sfa_test_9999..."]);
  });

  it("agent setup edits .gitignore and remembers the coding agent; recording does not", async () => {
    process.env.CLAUDECODE = "1";
    try {
      const gi = path.join(ctx.root, ".gitignore");
      fs.writeFileSync(gi, "node_modules\n");
      note("a", {});
      await flush();
      expect(fs.readFileSync(gi, "utf8")).toBe("node_modules\n"); // recording and sending never touch it
      expect((await cli("agent", "setup", "--agent", "claude-code"))[0]).toBe(0);
      expect(fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8")).toContain(".signafaide/");
      expect(new State(path.join(ctx.root, ".signafaide"), ctx.root).config().agent).toBe("claude-code");
    } finally {
      delete process.env.CLAUDECODE;
    }
  });
});
