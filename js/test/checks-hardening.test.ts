/**
 * Tool-call checks hardening (epic #58, release review): a span of the OpenTelemetry plug-in
 * never takes over a checked call, a renamed framework tool keeps its checks, no fail-open at a
 * cold start, the witness's keys pinned or kept, the checks file's stamp, test mode never with a
 * live key, a ruling's key active when it ruled, and rule set fingerprint exceptions.
 * Each test failed before its fix.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { context, propagation, trace } from "@opentelemetry/api";
import { AlwaysOnSampler } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { tool as langchainTool } from "@langchain/core/tools";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import * as C from "../src/checks.js";
import { CheckError, DEFAULT_SERVICE_KEYS } from "../src/checks-runtime.js";
import { SigningKey, b64url } from "../src/crypto.js";
import { DEFAULT_URL } from "../src/http.js";
import { SignafaideSpanProcessor } from "../src/otel.js";
import { record, wrapTools } from "../src/record.js";
import { Recorder, testMode } from "../src/runtime.js";
import { records, useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });
const NEVER_PAY = [{ id: "never", about: "Never.", action: "block", tools: ["pay"], agents: null, when: [] }];

function writeChecks(over: Record<string, unknown> = {}): void {
  fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify({ ...C.defaultChecksFile(), ...over }));
  ctx.rec.checks.forget();
}

const caught = async (p: unknown): Promise<CheckError> => {
  try {
    await p;
  } catch (e) {
    return e as CheckError;
  }
  throw new Error("the call ran");
};

const quiet = () => vi.spyOn(console, "warn").mockImplementation(() => undefined);
const calls = (agent?: string) => records(agent).filter((r) => r.envelope.kind !== "note");

describe("hardening: the OpenTelemetry plug-in never takes over a checked call", () => {
  const GEN_AI = { "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "pay", "gen_ai.tool.call.id": "call_1", "gen_ai.tool.call.arguments": '{"amount": 5000}' };
  afterEach(() => {
    trace.disable();
    context.disable();
    propagation.disable();
  });

  function tracer() {
    const p = new NodeTracerProvider({ sampler: new AlwaysOnSampler(), spanProcessors: [new SignafaideSpanProcessor({ agent: "support-bot" })] });
    p.register();
    return p.getTracer("tests");
  }

  for (const how of ["the checks file", "code"] as const) {
    it(`a strict tool (by ${how}) inside a gen_ai tool span is checked and blocked; the span adds no second decision`, async () => {
      ctx.service.publishRules(ctx.rec.apiKey!, NEVER_PAY, { mode: "enforce" });
      writeChecks({ mode: "enforce", tools: how === "the checks file" ? { pay: { strict: true } } : {} });
      await ctx.rec.checks.pullRules();
      const t = tracer();
      const ran: number[] = [];
      const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay", agent: "support-bot", ...(how === "code" ? { strict: true } : {}) });
      let err: CheckError | undefined;
      await t.startActiveSpan("execute_tool pay", { attributes: GEN_AI }, async (span) => {
        err = await caught(pay({ amount: 5000 }));
        span.end();
      });
      expect(ran).toEqual([]);
      expect(err?.code).toBe("blocked");
      const recs = calls("support-bot");
      expect(recs.map((r) => `${r.envelope.kind} ${r.envelope.name}`)).toEqual(["decision pay", "outcome pay"]);
      expect(recs[0].envelope.checks!.strict).toBe(true);
      expect(recs[1].envelope.checks).toEqual({ ran: false, ruling: "not_asked", results: [], result: "allow" });
    });
  }

  it("a tool strict in code inside a span waits for the witness's ruling, not only for a receipt", async () => {
    ctx.service.noRuling = true;
    writeChecks();
    const t = tracer();
    const ran: number[] = [];
    const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay", agent: "support-bot", strict: true });
    const q = quiet();
    let err: CheckError | undefined;
    await t.startActiveSpan("execute_tool pay", { attributes: GEN_AI }, async (span) => {
      err = await caught(pay({ amount: 5000 }));
      span.end();
    });
    q.mockRestore();
    expect(ran).toEqual([]);
    expect(err?.code).toBe("no_ruling");
    expect(calls("support-bot").at(-1)!.envelope.checks).toEqual({ ran: false, ruling: "none", results: [], result: "allow" });
  });

  it("a span of a tool no wrapper records is still recorded by the plug-in when checks are on", async () => {
    writeChecks();
    const t = tracer();
    record(async () => "x", { name: "other_tool", agent: "support-bot" });
    await t.startActiveSpan("execute_tool pay", { attributes: GEN_AI }, async (span) => span.end());
    expect(calls("support-bot").map((r) => `${r.envelope.kind} ${r.envelope.name}`)).toEqual(["decision pay", "outcome pay"]);
  });
});

describe("hardening: a renamed framework tool keeps its checks", () => {
  it("wrapTools({ pay: a LangChain tool named payment }): the checks file and the rule set name pay", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, NEVER_PAY, { mode: "enforce", fail: { pay: "closed" } });
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    await ctx.rec.checks.pullRules();
    const ran: number[] = [];
    const t = langchainTool(
      async ({ amount }: { amount: number }) => {
        ran.push(amount);
        return "ok";
      },
      { name: "payment", description: "Pay.", schema: z.object({ amount: z.number() }) },
    );
    const { pay } = wrapTools({ pay: t }) as any;
    const err = await caught(pay.invoke({ amount: 5000 }));
    expect(ran).toEqual([]);
    expect(err.code).toBe("blocked");
    const d = records().filter((r) => r.envelope.kind === "decision").at(-1)!;
    expect(d.envelope.name).toBe("pay");
    expect(d.envelope.checks!.strict).toBe(true);
    expect(d.envelope.checks!.fail).toBe("closed");
    expect(d.envelope.checks!.results.find((x: any) => x.check === "rule").matched).toEqual(["never"]);
    // The fingerprints still cover what the agent is shown: the tool's own name.
    expect(d.envelope.checks!.tool).toEqual(C.toolFingerprints("payment", "Pay.", null, null));
  });
});

describe("hardening: no fail-open at a cold start", () => {
  it("with no rule set held yet, the strict call waits for the first fetch; the rule set's closed wins over the checks file's open", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", fail: { pay: "closed" } });
    ctx.service.rulingError = "rules_unavailable";
    writeChecks({ mode: "enforce", tools: { pay: { strict: true, fail: "open" } } });
    const ran: number[] = [];
    const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay" });
    const q = quiet();
    const err = await caught(pay({ amount: 1 }));
    q.mockRestore();
    expect(err.code).toBe("rules_unavailable");
    expect(ran).toEqual([]);
    expect(ctx.rec.checks.heldRules()?.fail).toEqual({ pay: "closed" });
  });

  for (const removed of ["rule set", "keys"] as const) {
    it(`the held ${removed} file removed: fetched again before the call may run, and its fail mode holds`, async () => {
      ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", fail: { pay: "closed" } });
      writeChecks({ mode: "enforce", tools: { pay: { strict: true, fail: "open" } } });
      await ctx.rec.checks.pullRules();
      expect(ctx.rec.checks.heldRules()).not.toBeNull();
      const home = ctx.rec.checks.home;
      const target = removed === "keys" ? path.join(home, "keys.json") : path.join(home, "rules", ...ctx.rec.checks.projectEnv()!.slice(0, 1), `${ctx.rec.checks.projectEnv()![1]}.json`);
      fs.rmSync(target);
      expect(ctx.rec.checks.heldRules()).toBeNull();
      ctx.service.rulingError = "rules_unavailable";
      const ran: number[] = [];
      const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay" });
      const q = quiet();
      const err = await caught(pay({ amount: 1 }));
      q.mockRestore();
      expect(err.code).toBe("rules_unavailable");
      expect(ran).toEqual([]);
    });
  }

  it("with an API key and no rule set to be had, a strict call with no ruling fails closed whatever the checks file says", async () => {
    writeChecks({ tools: { pay: { strict: true, fail: "open" } } });
    ctx.service.noRuling = true;
    // The witness cannot be reached for the rule set: nothing says the project has none.
    const rules = vi.spyOn(ctx.rec.checks, "pullRules").mockRejectedValue(new Error("unreachable"));
    const ran: number[] = [];
    const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay" });
    const q = quiet();
    const err = await caught(pay({ amount: 1 }));
    q.mockRestore();
    rules.mockRestore();
    expect(err.code).toBe("no_ruling");
    expect(ran).toEqual([]);
  });
});

describe("hardening: the witness's keys", () => {
  it("the default witness's keys are pinned: a keys file on disk and the network never change them", async () => {
    const rec = new Recorder({ url: DEFAULT_URL, quiet: true });
    try {
      const forged = { key_id: "0123456789abcdef", public_key: b64url(SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n))).publicKey), valid_from: "2020-01-01T00:00:00.000Z", valid_to: null };
      fs.mkdirSync(rec.checks.home, { recursive: true });
      fs.writeFileSync(path.join(rec.checks.home, "keys.json"), JSON.stringify({ keys: [forged], fetched: "2026-11-17T00:00:00.000Z" }));
      expect(rec.checks.serviceKeys()).toEqual(DEFAULT_SERVICE_KEYS);
      expect(await rec.checks.pullKeys()).toEqual(DEFAULT_SERVICE_KEYS); // no request is made
    } finally {
      rec.close();
    }
  });

  it("a fetched key set that drops every key held before is refused, and the held keys stay", async () => {
    const held = await ctx.rec.checks.pullKeys();
    expect(held.map((k) => k.key_id)).toEqual([ctx.service.keyDoc.key_id]);
    const other = SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n)));
    const swapped = { key_id: other.keyId, public_key: b64url(other.publicKey), valid_from: "2020-01-01T00:00:00.000Z", valid_to: null };
    const original = ctx.service.keyDoc;
    ctx.service.keyDoc = swapped;
    expect((await ctx.rec.checks.pullKeys()).map((k) => k.key_id)).toEqual([original.key_id]);
    expect(ctx.rec.checks.serviceKeys().map((k) => k.key_id)).toEqual([original.key_id]);
    expect(ctx.rec.checks.problems.keys).toContain("drop every key held before");
    // A rotation adds the new key first: a set that keeps a held key is taken.
    ctx.service.keyDoc = original;
    ctx.service.extraKeys = [swapped];
    expect((await ctx.rec.checks.pullKeys()).map((k) => k.key_id)).toEqual([original.key_id, swapped.key_id]);
    expect(ctx.rec.checks.problems.keys).toBeUndefined();
  });

  it("a witness URL from the project's .env file is said once on stderr, as a note", () => {
    const saved = process.env.SIGNAFAIDE_URL;
    delete process.env.SIGNAFAIDE_URL;
    fs.writeFileSync(path.join(ctx.root, ".env"), "SIGNAFAIDE_URL=http://127.0.0.1:9/\n");
    const lines: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((s: string) => void lines.push(String(s)));
    const rec = new Recorder({ quiet: false });
    try {
      expect(rec.url).toBe("http://127.0.0.1:9");
      expect(rec.url).toBe("http://127.0.0.1:9");
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain("SIGNAFAIDE_URL in");
      expect(lines[0]).toContain(".env");
      expect(lines[0].toLowerCase()).not.toContain("warn");
      expect(lines[0]).not.toContain("\n");
      // From the environment or the code: nothing said.
      lines.length = 0;
      expect(new Recorder({ quiet: false, url: "http://127.0.0.1:9" }).url).toBe("http://127.0.0.1:9");
      expect(lines).toEqual([]);
    } finally {
      spy.mockRestore();
      rec.close();
      process.env.SIGNAFAIDE_URL = saved;
    }
  });
});

describe("hardening: local state", () => {
  it("the checks file's stamp has its inode: a file of the same size and time swapped in is read", () => {
    const p = path.join(ctx.root, "signafaide.checks.json");
    const t = new Date(1_700_000_000_000); // whole seconds: both files get exactly the same time
    writeChecks({ mode: "enforce" });
    fs.utimesSync(p, t, t);
    expect(ctx.rec.checks.file()!.mode).toBe("enforce");
    const st = fs.statSync(p, { bigint: true });
    const swapped = JSON.stringify({ ...C.defaultChecksFile(), mode: "watch" }).padEnd(Number(st.size), " ");
    expect(BigInt(Buffer.byteLength(swapped))).toBe(st.size);
    fs.writeFileSync(p + ".new", swapped);
    fs.utimesSync(p + ".new", t, t);
    fs.renameSync(p + ".new", p);
    expect(fs.statSync(p, { bigint: true }).mtimeNs).toBe(st.mtimeNs);
    ctx.rec.checks.forget();
    expect(ctx.rec.checks.file()!.mode).toBe("watch");
  });

  it("test mode never turns on by itself with a live API key", () => {
    const live = "sfa_live_" + "a".repeat(32);
    const sandbox = "sfa_test_" + "a".repeat(32);
    for (const runner of [{ VITEST: "true" }, { JEST_WORKER_ID: "1" }, { NODE_TEST_CONTEXT: "child" }]) {
      expect(testMode(runner)).toBe(true);
      expect(testMode(runner, sandbox)).toBe(true);
      expect(testMode(runner, live)).toBe(false);
      expect(testMode({ ...runner, SIGNAFAIDE_API_KEY: live })).toBe(false);
      expect(testMode({ ...runner, SIGNAFAIDE_TEST: "1" }, live)).toBe(true); // asked for in so many words
    }
    // A live key in the project's .env counts too.
    const saved = process.env.SIGNAFAIDE_TEST;
    delete process.env.SIGNAFAIDE_TEST;
    fs.writeFileSync(path.join(ctx.root, ".env"), `SIGNAFAIDE_API_KEY=${live}\n`);
    const rec = new Recorder({ quiet: true });
    try {
      expect(rec.test).toBe(false);
    } finally {
      rec.close();
      process.env.SIGNAFAIDE_TEST = saved;
    }
  });
});

describe("hardening: a ruling's service key must be active when the witness ruled", () => {
  it("a ruling signed by a key retired before its server_time is no ruling", async () => {
    ctx.service.keyDoc = { ...ctx.service.keyDoc, valid_to: "2021-01-01T00:00:00.000Z" };
    writeChecks({ tools: { pay: { strict: true } } });
    const ran: number[] = [];
    const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay" });
    const q = quiet();
    const err = await caught(pay({ amount: 1 }));
    q.mockRestore();
    expect(err.code).toBe("no_ruling");
    expect(err.message).toContain("was not active at");
    expect(ran).toEqual([]);
  });
});

describe("hardening: fingerprint exceptions of the rule set (§10.1)", () => {
  it("a shared-list match the rule set excepts is no finding on the client and no block at the witness", async () => {
    const t = C.toolFingerprints("pay", "", null, null);
    ctx.service.listUpdate([{ kind: "tool", fingerprint: t.tool }]);
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    await ctx.rec.checks.pullList();
    const ran: number[] = [];
    const pay = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay" });
    // Without an exception: blocked here by the fingerprint check.
    expect((await caught(pay({ amount: 1 }))).check).toBe("fingerprint");
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", fingerprintExceptions: [{ kind: "tool", fingerprint: t.tool, reason: "Re-approved in the console: our own tool." }] });
    await ctx.rec.checks.pullRules();
    await pay({ amount: 2 });
    expect(ran).toEqual([2]);
    const d = records().filter((r) => r.envelope.kind === "decision").at(-1)!;
    expect(d.envelope.checks!.results.find((x: any) => x.check === "fingerprint")).toEqual({ check: "fingerprint", result: "allow", mode: "enforce", found: [] });
  });

  it("the rule set document's fingerprint_exceptions: optional, validated", () => {
    const base = ctx.service.publishRules(ctx.rec.apiKey!, []).rules;
    expect(C.ruleSetErrors(base)).toBeNull();
    const ok = { ...base, fingerprint_exceptions: [{ kind: "description", fingerprint: "ab".repeat(32), reason: "Reviewed." }] };
    expect(C.ruleSetErrors(ok)).toBeNull();
    expect(C.ruleSetErrors({ ...ok, fingerprint_exceptions: [{ kind: "description", fingerprint: "ab".repeat(32) }] })).toContain("{kind, fingerprint, reason}");
    expect(C.ruleSetErrors({ ...ok, fingerprint_exceptions: [ok.fingerprint_exceptions[0], ok.fingerprint_exceptions[0]] })).toContain("listed twice");
  });
});
