import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { flush, init, note, record, NotRecorded } from "../src/index.js";
import { contentHash } from "../src/crypto.js";
import { makeDraft, recordHash } from "../src/records.js";
import { configure, getRecorder } from "../src/runtime.js";
import { chainFile, chainOf, deadUrl, errorFor, records, useProject } from "./helpers.js";

const ctx = useProject();
const chain = (agent = "claims-project") => records(agent);

describe("record", () => {
  it("writes a decision before and an outcome after (sync)", () => {
    const approvePayout = record((claimId: string, amount: number) => ({ approved: true, amount, claimId }), { name: "approve_payout" });
    expect(approvePayout("c-1", 12.5)).toEqual({ approved: true, amount: 12.5, claimId: "c-1" });
    const [d, o] = chain();
    expect(d.envelope).toMatchObject({ kind: "decision", name: "approve_payout", agent: "claims-project", seq: 1 });
    expect(d.content!.input).toEqual(["c-1", 12.5]);
    expect((d.content!.meta as any).sdk).toMatch(/^signafaide-js\//);
    expect(d.envelope.content_hash).toBe(contentHash(d.content!, d.salt!));
    expect(o.envelope).toMatchObject({ kind: "outcome", ref: recordHash(d), prev: recordHash(d) });
    expect(o.content).toEqual({ output: { approved: true, amount: 12.5, claimId: "c-1" } });
  });

  it("records a single argument as the input itself and uses the function name", () => {
    function lookupOrder(args: { id: string }) {
      return args.id;
    }
    record(lookupOrder, { agent: "support-bot", meta: { model: "m1" } })({ id: "o1" });
    const [d] = chain("support-bot");
    expect(d.envelope.name).toBe("lookupOrder");
    expect(d.content).toMatchObject({ input: { id: "o1" }, meta: { model: "m1" } });
  });

  it("needs a name for anonymous functions", () => {
    expect(() => record(() => 1)).toThrow(/needs a name/);
  });

  it("records async results and errors, rethrowing unchanged", async () => {
    class Boom extends Error {
      override name = "Boom";
    }
    const err = new Boom("no funds");
    const ok = record(async (q: string) => [q], { name: "lookup" });
    const bad = record(async () => {
      throw err;
    }, { name: "pay" });
    const badSync = record(() => {
      throw err;
    }, { name: "paySync" });
    expect(await ok("a")).toEqual(["a"]);
    await expect(bad()).rejects.toBe(err);
    expect(() => badSync()).toThrow(err);
    const recs = chain();
    expect(recs.map((r) => `${r.envelope.kind}:${r.envelope.name}`)).toEqual([
      "decision:lookup",
      "outcome:lookup",
      "decision:pay",
      "outcome:pay",
      "decision:paySync",
      "outcome:paySync",
    ]);
    expect(recs[3].content).toEqual({ error: { type: "Boom", message: "no funds" } });
  });

  it("keeps `this` and turns values into JSON", () => {
    const desk = {
      prefix: "x",
      decide: record(function (this: { prefix: string }, _when: Date, tags: Set<string>, _raw: Uint8Array, _big: bigint) {
        return `${this.prefix}-${tags.size}`;
      }, { name: "decide" }),
    };
    expect(desk.decide(new Date("2026-01-02T00:00:00Z"), new Set(["b", "a"]), new Uint8Array([0]), 2n ** 64n)).toBe("x-2");
    expect(chain()[0].content!.input).toEqual(["2026-01-02T00:00:00.000Z", ["a", "b"], "AA==", "18446744073709551616"]);
  });

  it("writes notes", () => {
    const h = note("policy_loaded", { version: 3 });
    const [r] = chain();
    expect(recordHash(r)).toBe(h);
    expect(r.envelope).toMatchObject({ kind: "note", ref: null });
  });
});

describe("shipping", () => {
  it("refuses a hostile sandbox answer: nothing reaches .env or a path", async () => {
    const real = (ctx.service as any).route.bind(ctx.service);
    (ctx.service as any).route = (m: string, p: string, q: any, b: any, a?: string) =>
      p === "/v1/sandbox" ? [201, { project: "../../../escaped", api_key: "sfa_test_" + "A".repeat(32) + "\nNODE_OPTIONS=--require ./pwn.js", claim_url: "x", free_quota: 1 }] : real(m, p, q, b, a);
    note("hello", { a: 1 });
    await expect(getRecorder().createSandbox()).rejects.toMatchObject({ code: "bad_response" });
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
    expect(walk(path.dirname(ctx.root)).filter((f) => f.includes("escaped"))).toEqual([]);
  });

  it("with no key records locally, signed and chained, and sends nothing", async () => {
    const lines: string[] = [];
    const orig = console.error;
    console.error = (s: string) => lines.push(s);
    try {
      const rec = configure({ quiet: false, flushIntervalMs: 10 });
      record((x: number) => x * 2, { name: "double" })(2);
      note("n", {});
      await new Promise((r) => setTimeout(r, 60)); // the background timer ran a few times
      expect(await flush()).toEqual({ shipped: 0, left: 3, errors: {} });
      expect(ctx.service.calls).toEqual([]); // no request at all, no sandbox
      expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
      expect(rec.state.sandbox()).toBeNull();
      const recs = chain();
      expect(recs.map((r) => !!r.draft)).toEqual([true, true, true]);
      expect(recs.every((r) => /^[0-9a-f]{16}$/.test(r.key_id) && r.sig)).toBe(true); // signed locally (domain draft)
      expect(lines.filter((l) => l.includes("recording locally"))).toHaveLength(1);
      const { verify } = await import("../src/index.js");
      const report = await verify();
      expect(ctx.service.calls).toEqual([]);
      expect(report.ok).toBe(true);
      expect(report.check("record_sig").checked).toBe(3);
      expect(report.check("chain").checked).toBe(3);
      expect(report.check("content").checked).toBe(3);
      expect(String(report)).toContain("co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host");
      rec.close();
    } finally {
      console.error = orig;
    }
  });

  it("local verify fails an edited or re-signed draft", async () => {
    note("a", { v: 1 });
    note("b", { v: 2 });
    const p = chainFile();
    const lines = fs.readFileSync(p, "utf8").split("\n");
    fs.writeFileSync(p, lines[0].replace('"v":1', '"v":9') + "\n" + lines.slice(1).join("\n"));
    const { verify } = await import("../src/index.js");
    expect((await verify()).check("content").status).toBe("fail");
    const forged = JSON.parse(lines[1]);
    forged.envelope.name = "other";
    fs.writeFileSync(p, lines[0] + "\n" + JSON.stringify(forged) + "\n");
    const r = await verify();
    expect(r.check("record_sig").status).toBe("fail");
    expect(r.check("chain").status).toBe("pass");
  });

  it("ships records written before the opt-in, with their original times", async () => {
    record((x: number) => x * 2, { name: "double" })(2);
    expect(getRecorder().state.outboxSize()).toBe(0); // no key, no project yet: two drafts (§8)
    expect(chain().map((r) => !!r.draft)).toEqual([true, true]);
    const times = chain().map((r) => r.envelope.time);
    await new Promise((r) => setTimeout(r, 20));
    await getRecorder().createSandbox();
    expect(await flush()).toEqual({ shipped: 2, left: 0, errors: {} });
    expect(chain().map((r) => r.envelope.time)).toEqual(times);
    expect(chain().every((r) => r.receipt)).toBe(true);
    expect(Object.values(getRecorder().state.chainHeads())[0].head.seq).toBe(2);
    expect(getRecorder().apiKey).toMatch(/^sfa_test_/);
    expect(ctx.service.registrations[0].valid_from).toBe(getRecorder().state.keyCreated("claims-project"));
  });

  it("gives a clear error for local records older than 7 days, and keeps them local", async () => {
    const rec = getRecorder();
    const key = rec.key("claims-project");
    const old = new Date(Date.now() - 8 * 86_400_000).toISOString();
    rec.state.append("_pending/nokey/claims-project", (seq, prev) => makeDraft(key, { kind: "note", agent: "claims-project", seq, prev, name: "old", content: {}, time: old }, false), (r) => r);
    await rec.createSandbox();
    const r = await flush();
    const e = errorFor(r);
    expect(e.code).toBe("too_old");
    expect(e.message).toMatch(/more than 7 days ago.*stays local.*signafaide verify/);
    expect(rec.state.chains()).toEqual(["_pending/nokey/claims-project"]);
    expect((await (await import("../src/index.js")).verify()).ok).toBe(true);
  });

  it("is hash-only by default; storeContent sends content", async () => {
    await getRecorder().createSandbox();
    record(() => 1, { name: "a" })();
    record(() => 2, { name: "b", storeContent: true })();
    await flush();
    const stored = Object.fromEntries([...ctx.service.project().records.values()].map(([r]: any) => [r.envelope.name, "content" in r]));
    expect(stored).toEqual({ a: false, b: true });
    expect(chain().every((r) => r.content)).toBe(true);
  });

  it("ships in the background", async () => {
    await getRecorder().createSandbox();
    const rec = configure({ quiet: true, flushIntervalMs: 20 });
    record(() => null, { name: "tick" })();
    const deadline = Date.now() + 5000;
    while (rec.state.outboxSize() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    expect(rec.state.outboxSize()).toBe(0);
  });

  it("keeps the outbox offline and recovers", async () => {
    const rec = getRecorder();
    await rec.createSandbox();
    rec._url = await deadUrl();
    expect(record(() => "ok", { name: "act" })()).toBe("ok");
    const r = await flush();
    expect(r.shipped).toBe(0);
    expect(r.left).toBe(2);
    expect(errorFor(r).code).toBe("network");
    rec._url = ctx.service.url;
    expect((await flush()).shipped).toBe(2);
  });

  it("strict mode without a key refuses to run and sends nothing", async () => {
    let ran = false;
    const pay = record(async () => {
      ran = true;
    }, { name: "pay", strict: true });
    await expect(pay()).rejects.toThrow(NotRecorded);
    await expect(pay()).rejects.toThrow(/until a person runs `npx signafaide protect`.*no signafAIde key or sandbox/);
    expect(ran).toBe(false);
    expect(ctx.service.calls).toEqual([]);
  });

  it("strict mode waits for the receipt before running", async () => {
    await getRecorder().createSandbox();
    const used: number[] = [];
    const pay = record(() => {
      used.push(ctx.service.project().used);
      return "paid";
    }, { name: "pay", strict: true });
    expect(await pay()).toBe("paid");
    expect(used).toEqual([1]);
  });

  it("strict mode refuses to run without a receipt", async () => {
    const rec = getRecorder();
    rec._apiKey = "sfa_test_" + "x".repeat(32);
    rec._url = await deadUrl();
    let ran = false;
    const pay = record(async () => {
      ran = true;
    }, { name: "pay", strict: true });
    await expect(pay()).rejects.toThrow(NotRecorded);
    await expect(pay()).rejects.toThrow(/pay is protected and did not run/);
    expect(ran).toBe(false);
  });

  it("reports chain_conflict without rewriting the chain", async () => {
    await getRecorder().createSandbox();
    note("a", {});
    await flush();
    ctx.service.fail = [409, { error: { code: "chain_conflict", message: "Chain conflict, head attached.", docs: "d", head: { agent: "claims-project", seq: 7, record_hash: "ab".repeat(32) } } }];
    note("b", {});
    const p = chainFile();
    const before = fs.readFileSync(p, "utf8");
    const e = errorFor(await flush());
    expect(e.code).toBe("chain_conflict");
    expect(e.message).toMatch(/^Chain conflict, head attached\. .*seq 7.*nothing was rewritten/);
    expect(fs.readFileSync(p, "utf8")).toBe(before);
    expect(getRecorder().state.outboxSize()).toBe(1);
    // In the background the refused chain is not tried again until the configuration changes;
    // an explicit flush (`signafaide flush`) always tries.
    const calls = ctx.service.calls.length;
    expect(errorFor(await getRecorder().flush(10_000, "bg"))).toBe(e);
    expect(ctx.service.calls.length).toBe(calls);
  });

  it("surfaces the service message verbatim", async () => {
    note("a", {});
    getRecorder()._apiKey = "sfa_test_" + "0".repeat(32);
    expect(errorFor(await flush()).message).toBe("The API key is not valid; run `signafaide init` for a new sandbox key.");
  });

  it("re-registers on unknown_agent", async () => {
    await getRecorder().createSandbox();
    note("a", {});
    await flush();
    ctx.service.project().agents.clear();
    note("b", {});
    expect((await flush()).shipped).toBe(1);
  });
});

describe("init", () => {
  it("init() never creates a sandbox and sends nothing without a key", async () => {
    await init({ url: ctx.service.url, quiet: true });
    expect(ctx.service.calls).toEqual([]);
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
  });

  it("createSandbox (signafaide init) creates one sandbox and prints it once, with why to claim and the time left", async () => {
    const lines: string[] = [];
    const orig = console.error;
    console.error = (s: string) => lines.push(s);
    try {
      await configure({ url: ctx.service.url }).createSandbox();
      expect(lines).toHaveLength(3);
      expect(lines[0]).toContain(`claim it at ${ctx.service.url}/app/claim/`);
      expect(lines[1]).toMatch(/^signafaide: claiming is free and needs no card/);
      expect(lines[2]).toMatch(/^signafaide: 30 days left: /);
      const env = fs.readFileSync(path.join(ctx.root, ".env"), "utf8");
      expect(env.match(/SIGNAFAIDE_API_KEY=sfa_test_/g)).toHaveLength(1);
      await configure({ url: ctx.service.url }).createSandbox();
      expect(fs.readFileSync(path.join(ctx.root, ".env"), "utf8")).toBe(env);
      expect(lines).toHaveLength(3);
      expect(getRecorder().state.sandbox()?.claim_url).toContain(ctx.service.url);
      expect(fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8").split("\n")).toEqual(expect.arrayContaining([".signafaide/", ".env"]));
    } finally {
      console.error = orig;
    }
  });

  it("the sandbox keeps .env out of git once", async () => {
    fs.writeFileSync(path.join(ctx.root, ".gitignore"), "node_modules\n/.env\n");
    note("first", {});
    await getRecorder().createSandbox();
    expect((await flush()).shipped).toBe(1);
    expect(fs.readFileSync(path.join(ctx.root, ".env"), "utf8")).toMatch(/^SIGNAFAIDE_API_KEY=sfa_test_/);
    const ignore = fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8");
    expect(ignore.startsWith("node_modules\n/.env\n")).toBe(true);
    expect(ignore.match(/\.env/g)).toHaveLength(1);
  });

  it("adds .env to .gitignore on a fresh sandbox", async () => {
    note("first", {});
    await getRecorder().createSandbox();
    expect((await flush()).shipped).toBe(1);
    expect(fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8").split("\n")).toEqual(expect.arrayContaining([".signafaide/", ".env"]));
  });

  it("does not throw offline", async () => {
    const orig = console.error;
    const lines: string[] = [];
    console.error = (s: string) => lines.push(s);
    try {
      await init({ url: await deadUrl(), apiKey: "sfa_test_" + "k".repeat(32) });
      expect(lines[0]).toMatch(/Cannot reach/);
    } finally {
      console.error = orig;
    }
  });
});

describe("chains per project and env", () => {
  it("starts a fresh chain when the key switches to another project", async () => {
    await getRecorder().createSandbox();
    note("a", {});
    note("b", {});
    await flush();
    const sandbox = chainOf();
    const liveKey = "sfa_live_" + "L".repeat(32);
    const live = ctx.service.addProject(liveKey, "live");
    getRecorder()._apiKey = liveKey;
    note("c", {}); // project unknown yet: a pending chain
    expect(getRecorder().state.chains().some((c) => c.startsWith("_pending/"))).toBe(true);
    const r = await flush();
    expect(r.errors).toEqual({});
    expect(r.shipped).toBe(1);
    const liveChain = `${live.project}/live/claims-project`;
    expect(getRecorder().state.chains().sort()).toEqual([sandbox, liveChain].sort());
    note("d", {});
    expect((await flush()).shipped).toBe(1);
    expect(getRecorder().state.readChain(liveChain).map((x) => x.envelope.seq)).toEqual([1, 2]);
    expect(getRecorder().state.readChain(liveChain).every((x) => x.receipt)).toBe(true);
    expect(getRecorder().state.readChain(sandbox).map((x) => x.envelope.seq)).toEqual([1, 2]);
    const { verify } = await import("../src/index.js");
    expect((await verify()).ok).toBe(true);
  });

  it("moves records written before any key into the sandbox chain", async () => {
    note("a", {});
    expect(getRecorder().state.chains()).toEqual(["_pending/nokey/claims-project"]);
    await flush();
    expect(getRecorder().state.chains()).toEqual(["_pending/nokey/claims-project"]); // nothing sent before the opt-in
    await getRecorder().createSandbox();
    await flush();
    const [c] = getRecorder().state.chains();
    expect(c).toMatch(/^prj_\w+\/test\/claims-project$/);
  });
});

