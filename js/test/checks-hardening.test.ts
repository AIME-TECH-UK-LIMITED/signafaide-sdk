/**
 * Tool-call checks hardening: a span of the OpenTelemetry plug-in
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
import { CheckError, DEFAULT_SERVICE_KEYS, REVOKED_GRACE_MS } from "../src/checks-runtime.js";
import { SigningKey, b64url, hashJson } from "../src/crypto.js";
import { Client, DEFAULT_URL } from "../src/http.js";
import { SignafaideSpanProcessor } from "../src/otel.js";
import { record, wrapTools } from "../src/record.js";
import { Recorder, testMode } from "../src/runtime.js";
import { records, useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });
const NEVER_PAY = [{ id: "never", about: "Never.", action: "block", tools: ["pay"], agents: null, when: [] }];

function writeChecks(over: Record<string, unknown> = {}): void {
  fs.writeFileSync(
    path.join(ctx.root, "signafaide.checks.json"),
    JSON.stringify({ ...C.defaultChecksFile(), ...over }),
  );
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
  const GEN_AI = {
    "gen_ai.operation.name": "execute_tool",
    "gen_ai.tool.name": "pay",
    "gen_ai.tool.call.id": "call_1",
    "gen_ai.tool.call.arguments": '{"amount": 5000}',
  };
  afterEach(() => {
    trace.disable();
    context.disable();
    propagation.disable();
  });

  function tracer() {
    const p = new NodeTracerProvider({
      sampler: new AlwaysOnSampler(),
      spanProcessors: [new SignafaideSpanProcessor({ agent: "support-bot" })],
    });
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
      const pay = record(async (a: { amount: number }) => void ran.push(a.amount), {
        name: "pay",
        agent: "support-bot",
        ...(how === "code" ? { strict: true } : {}),
      });
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
      // A protected call always asks the witness, which rules with the newest rules: it blocks it.
      expect(recs[1].envelope.checks).toEqual({ ran: false, ruling: "block", results: [], result: "allow" });
    });
  }

  it("a tool strict in code inside a span waits for the witness's ruling, not only for a receipt", async () => {
    ctx.service.noRuling = true;
    writeChecks();
    const t = tracer();
    const ran: number[] = [];
    const pay = record(async (a: { amount: number }) => void ran.push(a.amount), {
      name: "pay",
      agent: "support-bot",
      strict: true,
    });
    const q = quiet();
    let err: CheckError | undefined;
    await t.startActiveSpan("execute_tool pay", { attributes: GEN_AI }, async (span) => {
      err = await caught(pay({ amount: 5000 }));
      span.end();
    });
    q.mockRestore();
    expect(ran).toEqual([]);
    expect(err?.code).toBe("no_ruling");
    expect(calls("support-bot").at(-1)!.envelope.checks).toEqual({
      ran: false,
      ruling: "none",
      results: [],
      result: "allow",
    });
  });

  it("a span of a tool no wrapper records is still recorded by the plug-in when checks are on", async () => {
    writeChecks();
    const t = tracer();
    record(async () => "x", { name: "other_tool", agent: "support-bot" });
    await t.startActiveSpan("execute_tool pay", { attributes: GEN_AI }, async (span) => span.end());
    expect(calls("support-bot").map((r) => `${r.envelope.kind} ${r.envelope.name}`)).toEqual([
      "decision pay",
      "outcome pay",
    ]);
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
    const d = records()
      .filter((r) => r.envelope.kind === "decision")
      .at(-1)!;
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
      const target =
        removed === "keys"
          ? path.join(home, "keys.json")
          : path.join(
              home,
              "rules",
              ...ctx.rec.checks.projectEnv()!.slice(0, 1),
              `${ctx.rec.checks.projectEnv()![1]}.json`,
            );
      fs.rmSync(target);
      // Keys removed: the version held is stale (its signer no longer held), enforced as held (§8).
      if (removed === "keys") expect(ctx.rec.checks.heldRules()).not.toBeNull();
      else expect(ctx.rec.checks.heldRules()).toBeNull();
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
      const forged = {
        key_id: "0123456789abcdef",
        public_key: b64url(SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n))).publicKey),
        valid_from: "2020-01-01T00:00:00.000Z",
        valid_to: null,
      };
      fs.mkdirSync(rec.checks.home, { recursive: true });
      fs.writeFileSync(
        path.join(rec.checks.home, "keys.json"),
        JSON.stringify({ keys: [forged], fetched: "2026-11-17T00:00:00.000Z" }),
      );
      expect(rec.checks.serviceKeys()).toEqual(DEFAULT_SERVICE_KEYS);
      // Online, the published list never adds a key; its revoked ids are added to the pinned ones (§5).
      const served = vi.spyOn(Client.prototype, "serviceKeys");
      served.mockRejectedValueOnce(new Error("offline"));
      expect(await rec.checks.pullKeys()).toEqual(DEFAULT_SERVICE_KEYS);
      served.mockResolvedValueOnce({ keys: [forged, ...DEFAULT_SERVICE_KEYS] } as never);
      expect(await rec.checks.pullKeys()).toEqual(DEFAULT_SERVICE_KEYS);
      served.mockResolvedValueOnce({
        keys: [...DEFAULT_SERVICE_KEYS],
        revoked: [{ key_id: DEFAULT_SERVICE_KEYS[0].key_id, revoked_at: null }],
      } as never);
      expect(await rec.checks.pullKeys()).toEqual([]);
      // A later list without the revocation never undoes it.
      served.mockResolvedValueOnce({ keys: [...DEFAULT_SERVICE_KEYS] } as never);
      expect(await rec.checks.pullKeys()).toEqual([]);
      expect(rec.checks.revokedKeys()).toEqual([DEFAULT_SERVICE_KEYS[0].key_id]);
      served.mockRestore();
    } finally {
      rec.close();
    }
  });

  it("a fetched key set that drops every key held before is refused, and the held keys stay", async () => {
    const held = await ctx.rec.checks.pullKeys();
    expect(held.map((k) => k.key_id)).toEqual([ctx.service.keyDoc.key_id]);
    const other = SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n)));
    const swapped = {
      key_id: other.keyId,
      public_key: b64url(other.publicKey),
      valid_from: "2020-01-01T00:00:00.000Z",
      valid_to: null,
    };
    const original = ctx.service.keyDoc;
    ctx.service.keyDoc = swapped;
    expect((await ctx.rec.checks.pullKeys()).map((k) => k.key_id)).toEqual([original.key_id]);
    expect(ctx.rec.checks.serviceKeys().map((k) => k.key_id)).toEqual([original.key_id]);
    expect(ctx.rec.checks.problems.keys).toContain("drop a key held");
    // A rotation adds the new key first: a set that keeps a held key is taken.
    ctx.service.keyDoc = original;
    ctx.service.extraKeys = [swapped];
    expect((await ctx.rec.checks.pullKeys()).map((k) => k.key_id)).toEqual([original.key_id, swapped.key_id]);
    expect(ctx.rec.checks.problems.keys).toBeUndefined();
    // A revoked key (§5) stays listed but is never used; a malformed `revoked` keeps the held keys.
    ctx.service.revoked = [{ key_id: original.key_id, revoked_at: null }];
    expect((await ctx.rec.checks.pullKeys()).map((k) => k.key_id)).toEqual([swapped.key_id]);
    expect(ctx.rec.checks.serviceKeys().map((k) => k.key_id)).toEqual([swapped.key_id]);
    ctx.service.revoked = { key_id: swapped.key_id };
    expect((await ctx.rec.checks.pullKeys()).map((k) => k.key_id)).toEqual([swapped.key_id]);
    ctx.service.revoked = undefined;
  });

  // --- the owner's policy: keep, then fail closed after REVOKED_GRACE_MS (§8) ---------------------

  const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
  const keyDocOf = (k: SigningKey) => ({
    key_id: k.keyId,
    public_key: b64url(k.publicKey),
    valid_from: "2020-01-01T00:00:00.000Z",
    valid_to: null,
  });
  /** The witness switches to a new key and revokes the one that signed what the client holds. */
  function switchAndRevoke() {
    const old = ctx.service.keyDoc;
    const next = SigningKey.generate(rnd);
    ctx.service.key = next;
    ctx.service.keyDoc = keyDocOf(next);
    ctx.service.extraKeys = [old];
    ctx.service.revoked = [{ key_id: old.key_id }];
    return old;
  }
  /** The newest rule set version signed again with the witness's current key (same rules). */
  function resign() {
    const items = (ctx.service as any).ruleItems.get(ctx.rec.checks.projectEnv()![0]);
    const it = items.at(-1);
    items[items.length - 1] = {
      ...it,
      sig: ctx.service.key.sign("rules", hashJson(it.rules)),
      service_key_id: ctx.service.key.keyId,
    };
  }
  /** A rule set version signed by a key nobody published. */
  function publishByStranger() {
    const real = ctx.service.key;
    ctx.service.key = SigningKey.generate(rnd);
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    ctx.service.key = real;
  }
  const pay = { name: "pay", description: "Pays", inputSchema: { type: "object" } };
  const statePath = (kind: "rules" | "list") => {
    const pe = ctx.rec.checks.projectEnv()!;
    return kind === "list"
      ? path.join(ctx.rec.checks.home, "fingerprints.state.json")
      : path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.state.json`);
  };
  const state = (kind: "rules" | "list") => JSON.parse(fs.readFileSync(statePath(kind), "utf8"));
  const setStale = (kind: "rules" | "list", patch: object) => {
    const d = state(kind);
    d.stale = { ...d.stale, ...patch };
    fs.writeFileSync(statePath(kind), JSON.stringify(d));
  };
  const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
  const staleLine = () => ctx.rec.checks.status()[0].find((l) => /^(STALE|PROBLEM) (rule set|shared list)/.test(l));
  async function heldStale() {
    ctx.rec.checks.start = () => undefined; // no background fetch racing the files these tests write
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules();
    const v1 = ctx.rec.checks.heldRules()!.version;
    switchAndRevoke();
    await ctx.rec.checks.freshKeys(true, "force");
    ctx.rec.checks.status(); // what any process does when it reads the held object
    return v1;
  }
  const staleNotes = () => {
    try {
      return records("support-bot").filter((r) => r.envelope.name === "signafaide.checks_stale");
    } catch {
      return []; // no record for the agent yet
    }
  };

  it("a held rule set signed by a revoked key: enforced as held until a deadline, noted once it outlives a pull, refused after the grace (decision written), recovered by the re-signed copy", async () => {
    const v1 = await heldStale();
    expect(ctx.rec.checks.heldRules()!.version).toBe(v1);
    expect(ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true })!.staleBlocked).toBeNull();
    const [lines, problem] = ctx.rec.checks.status();
    const line = lines.find((l) => l.startsWith("STALE rule set"))!;
    expect(line).toContain("which the witness has revoked; waiting for the witness's re-signed copy");
    expect(line).toMatch(/enforced as held until \d{4}-\d\d-\d\dT/);
    expect(problem).toBe(false);
    // Not noted yet: the mark has not outlived a pull (a one-off glitch is never noted).
    expect(staleNotes().length).toBe(0);
    vi.spyOn(Client.prototype, "rules").mockResolvedValueOnce(null as never); // an unsigned answer: nothing changes
    await ctx.rec.checks.pullRules();
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true });
    ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true });
    expect(err.mock.calls.filter((c) => String(c[0]).includes("revoked")).length).toBe(1); // once a day
    err.mockRestore();
    expect(staleNotes().length).toBe(1);
    expect(state("rules").stale.noted).toEqual(["support-bot"]);
    // After the grace period: a protected call is refused, its decision and outcome written.
    setStale("rules", { since: ago(REVOKED_GRACE_MS + 1000) });
    const ran: number[] = [];
    const payFn = record(async (a: { amount: number }) => void ran.push(a.amount), { name: "pay", strict: true });
    const e = await caught(payFn({ amount: 5 }));
    expect(e.code).toBe("rules_unavailable");
    expect(e.message).toContain("no verified replacement arrived within 7 days");
    expect(ran).toEqual([]);
    const mine = records().filter((r) => r.envelope.name === "pay");
    expect(mine.map((r) => r.envelope.kind)).toEqual(["decision", "outcome"]);
    expect(mine[1].envelope.checks!.ran).toBe(false);
    const [l2, p2] = ctx.rec.checks.status();
    expect(l2.find((l) => l.startsWith("PROBLEM rule set"))).toContain("protected calls are refused");
    expect(p2).toBe(true);
    // The same version re-signed by the new key clears it: fetched without If-None-Match while stale.
    resign();
    await ctx.rec.checks.pullRules();
    expect(ctx.service.rulesFetches.at(-1)![1]).toBeUndefined();
    expect(ctx.rec.checks.heldRules()!.version).toBe(v1);
    expect(state("rules").stale).toBeNull();
    expect(staleLine()).toBeUndefined();
    ctx.service.revoked = undefined;
  });

  it("a refused update on every pull keeps the first since; revoked, then an unknown key, then an unsigned answer: the clock stays", async () => {
    await heldStale();
    const since = state("rules").stale.since;
    publishByStranger();
    expect(await ctx.rec.checks.pullRules(true, true)).toContain("refused rule set version");
    expect(staleLine()).toContain("which its published key list does not name");
    await ctx.rec.checks.pullRules(true, true);
    expect(state("rules").stale.since).toBe(since);
    vi.spyOn(Client.prototype, "rules").mockResolvedValueOnce(null as never);
    await ctx.rec.checks.pullRules(true, true);
    expect(state("rules").stale.since).toBe(since);
    // Key list changes never clear or restart it either.
    ctx.service.revoked = [{ key_id: ctx.service.extraKeys[0].key_id }, { key_id: "0123456789abcdef" }];
    await ctx.rec.checks.freshKeys(true, "force");
    expect(state("rules").stale.since).toBe(since);
    ctx.service.revoked = undefined;
  });

  it("a one-off refusal then a healthy pull clears it, with no note; a refused version waits 60 s doubling to an hour before the next fetch", async () => {
    ctx.rec.checks.start = () => undefined; // no background fetch racing this test's own
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules();
    publishByStranger();
    await ctx.rec.checks.pullRules();
    expect(state("rules").stale.since).toBeTruthy();
    expect(state("rules").retry.failures).toBe(1);
    const fetches = ctx.service.rulesFetches.length;
    await ctx.rec.checks.pullRules(); // waiting
    expect(ctx.service.rulesFetches.length).toBe(fetches);
    ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true });
    expect(staleNotes().length).toBe(0);
    // Over a simulated hour: few fetches, never a storm.
    let t = Date.now();
    const clock = vi.spyOn(Date, "now").mockImplementation(() => t);
    try {
      for (let m = 0; m < 60; m++) {
        await ctx.rec.checks.pullRules();
        t += 60_000;
      }
    } finally {
      clock.mockRestore();
    }
    expect(ctx.service.rulesFetches.length - fetches).toBeLessThanOrEqual(7);
    // The witness signs properly again: one healthy pull clears (a forced pull never waits).
    (ctx.service as any).ruleItems.get(ctx.rec.checks.projectEnv()![0]).pop();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules(true, true);
    expect(state("rules")).toMatchObject({ stale: null, retry: null });
  });

  it("revoked ids: junk ids naming no held key are ignored, never refused, never capped; the real one applies", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules();
    ctx.service.revoked = Array.from({ length: 300 }, (_, i) => ({ key_id: i.toString(16).padStart(16, "0") }));
    await ctx.rec.checks.freshKeys(true, "force");
    const held = () =>
      JSON.parse(fs.readFileSync(path.join(ctx.rec.checks.home, "keys.json"), "utf8")).witnesses[ctx.rec.url];
    expect(held().revoked).toEqual([]);
    expect(ctx.rec.checks.problems.keys).toBeUndefined();
    ctx.service.revoked = [...(ctx.service.revoked as object[]), { key_id: ctx.service.keyDoc.key_id }];
    await ctx.rec.checks.freshKeys(true, "force");
    expect(held().revoked).toEqual([ctx.service.keyDoc.key_id]);
    expect(staleLine()).toMatch(/^STALE rule set/);
    ctx.service.revoked = undefined;
  });

  it("a self-hosted key list: merged, never dropped; more than 64 keys, a dropped or changed key: key changes refused, revocations applied", async () => {
    await ctx.rec.checks.freshKeys(true, "force");
    const own = ctx.service.keyDoc.key_id;
    ctx.service.extraKeys = Array.from({ length: 70 }, () => keyDocOf(SigningKey.generate(rnd)));
    ctx.service.revoked = [{ key_id: own }];
    await ctx.rec.checks.freshKeys(true, "force");
    expect(ctx.rec.checks.allServiceKeys().map((k) => k.key_id)).toEqual([own]);
    expect(ctx.rec.checks.revokedKeys()).toEqual([own]);
    expect(ctx.rec.checks.problems.keys).toContain("name more than 64 keys");
    ctx.service.extraKeys = [];
    ctx.service.revoked = undefined;
  });

  it("a hostile witness changing its revoked ids on every read: the key list is read every 10 minutes, the list once a minute, keys.json does not grow", async () => {
    writeChecks({ mode: "enforce" });
    ctx.service.listUpdate([{ kind: "tool", fingerprint: "e4".repeat(32) }]);
    await ctx.rec.checks.pullList();
    let n = 0;
    const keysRead = vi.spyOn(Client.prototype, "serviceKeys").mockImplementation(
      async () =>
        ({
          keys: [ctx.service.keyDoc],
          revoked: Array.from({ length: 70 }, () => ({ key_id: (n++).toString(16).padStart(16, "0") })),
        }) as never,
    );
    const listRead = vi.spyOn(Client.prototype, "fingerprints");
    let t = Date.now();
    const clock = vi.spyOn(Date, "now").mockImplementation(() => t);
    try {
      for (let minute = 0; minute < 60; minute++) {
        await ctx.rec.checks.refresh(false);
        t += 60_000;
      }
      expect(keysRead.mock.calls.length).toBeLessThanOrEqual(7);
      expect(listRead.mock.calls.length).toBeLessThanOrEqual(61);
      const held = JSON.parse(fs.readFileSync(path.join(ctx.rec.checks.home, "keys.json"), "utf8")).witnesses[
        ctx.rec.url
      ];
      expect(held.revoked).toEqual([]);
    } finally {
      clock.mockRestore();
      keysRead.mockRestore();
      listRead.mockRestore();
    }
  });

  it("a list signed by a key now revoked is fetched from a snapshot and replaced once one verifies; a list of an older release (no state file) too", async () => {
    writeChecks({ mode: "enforce" });
    ctx.service.listUpdate([{ kind: "tool", fingerprint: "c".repeat(64) }]);
    await ctx.rec.checks.pullList();
    expect(state("list").held.key_ids).toEqual([ctx.service.keyDoc.key_id]);
    switchAndRevoke();
    await ctx.rec.checks.freshKeys(true, "force");
    expect(staleLine()).toMatch(/^STALE shared list: signed by service key/);
    const since = vi.spyOn(Client.prototype, "fingerprints");
    await ctx.rec.checks.pullList();
    expect(since.mock.calls.at(-1)![0]).toBeNull(); // from a snapshot
    expect(state("list").stale).toBeNull();
    expect(state("list").held.key_ids).toEqual([ctx.service.keyDoc.key_id]);
    // An older release's list: no state file, so its signers are unknown: from a snapshot again.
    fs.rmSync(statePath("list"));
    await ctx.rec.checks.pullList();
    expect(since.mock.calls.at(-1)![0]).toBeNull();
    expect(state("list").held.key_ids).toEqual([ctx.service.keyDoc.key_id]);
    since.mockRestore();
    ctx.service.revoked = undefined;
  });

  it("a crash between writing the object and its state file: the old mark no longer counts (it names another object)", async () => {
    await heldStale();
    expect(staleLine()).toMatch(/^STALE/);
    // The re-signed copy written, the process gone before the state file: as a crash leaves it.
    resign();
    const pe = ctx.rec.checks.projectEnv()!;
    const item = (ctx.service as any).ruleItems.get(pe[0]).at(-1);
    const before = fs.readFileSync(statePath("rules"), "utf8");
    fs.writeFileSync(path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.json`), JSON.stringify(item));
    fs.writeFileSync(statePath("rules"), before);
    ctx.rec.checks.forget();
    expect(staleLine()).toBeUndefined();
    ctx.service.revoked = undefined;
  });

  it("a since in the future counts as now (written back); another witness's state file or another project's never counts here", async () => {
    await heldStale();
    setStale("rules", { since: "2999-01-01T00:00:00.000Z" });
    const line = staleLine()!;
    const until = Date.parse(line.match(/until (\S+)$/)![1]);
    expect(Math.abs(until - (Date.now() + REVOKED_GRACE_MS))).toBeLessThan(5000);
    expect(state("rules").stale.since.startsWith("2999")).toBe(false);
    // The URL changed: the state file names another witness.
    const d = state("rules");
    d.witness = "https://other.example";
    fs.writeFileSync(statePath("rules"), JSON.stringify(d));
    ctx.service.revoked = undefined;
    fs.rmSync(path.join(ctx.rec.checks.home, "keys.json"));
    await ctx.rec.checks.freshKeys(true, "force"); // the old key is not revoked here
    expect(staleLine()).toBeUndefined();
  });

  it("two processes on one folder share one clock: the earlier since stays", async () => {
    await heldStale();
    const since = state("rules").stale.since;
    const other = new Recorder({ url: ctx.rec.url, apiKey: ctx.rec.apiKey!, quiet: true });
    try {
      publishByStranger();
      await other.checks.pullRules(true, true);
      expect(state("rules").stale.since).toBe(since);
      expect(other.checks.status()[0].some((l) => l.startsWith("STALE rule set"))).toBe(true);
    } finally {
      other.close();
    }
    ctx.service.revoked = undefined;
  });

  it("no checks file, a tool protected in code, the grace over: PROBLEM with exit 1, the call refused; a broken copy counts as expired at once and is never dropped", async () => {
    await heldStale();
    fs.rmSync(path.join(ctx.root, "signafaide.checks.json"));
    ctx.rec.checks.forget();
    setStale("rules", { since: ago(REVOKED_GRACE_MS + 1000) });
    const [lines, problem] = ctx.rec.checks.status();
    expect(lines.some((l) => l.startsWith("PROBLEM rule set"))).toBe(true);
    expect(problem).toBe(true);
    expect(ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true })!.staleBlocked).toContain(
      "protected calls are refused",
    );
    // A copy that fails its own signature.
    const pe = ctx.rec.checks.projectEnv()!;
    const file = path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.json`);
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    ctx.service.revoked = undefined;
    fs.rmSync(path.join(ctx.rec.checks.home, "keys.json"));
    await ctx.rec.checks.freshKeys(true, "force");
    // The background fetch would replace the broken copy at once: it answers "current" meanwhile.
    const current = vi.spyOn(Client.prototype, "rules").mockResolvedValue(null as never);
    doc.rules.default = doc.rules.default === "allow" ? "block" : "allow";
    fs.writeFileSync(file, JSON.stringify(doc));
    expect(ctx.rec.checks.heldRules()).toBeNull();
    expect(staleLine()).toContain("unreadable or fails its own signature");
    expect(ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true })!.staleBlocked).toBeTruthy();
    expect(fs.existsSync(file)).toBe(true);
    current.mockRestore();
    await ctx.rec.checks.forcedPull();
    expect(staleLine()).toBeUndefined();
  });

  it("test mode never refuses a call for stale rules", async () => {
    await heldStale();
    setStale("rules", { since: ago(REVOKED_GRACE_MS * 2) });
    expect(ctx.rec.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true })!.staleBlocked).toBeTruthy();
    vi.stubEnv("SIGNAFAIDE_TEST", "1");
    const t = new Recorder({ url: ctx.rec.url, quiet: true });
    try {
      expect(t.test).toBe(true);
      expect(t.checks.plan(pay, "support-bot", { amount: 5 }, { strictCode: true })?.staleBlocked ?? null).toBeNull();
    } finally {
      t.close();
      vi.unstubAllEnvs();
    }
    ctx.service.revoked = undefined;
  });

  it("a client behind a reset of the update chain takes the snapshot once it verifies, with a fresh state file", async () => {
    const [a, b] = [
      { kind: "tool", fingerprint: "d".repeat(64) },
      { kind: "tool", fingerprint: "e".repeat(64) },
    ];
    ctx.service.listUpdate([a]);
    await ctx.rec.checks.pullList(); // held: seq 1
    ctx.service.listUpdate([b], [a]); // seq 2
    ctx.service.listResetSeq = 2;
    await ctx.rec.checks.pullList();
    const held = ctx.rec.checks.heldList()!;
    expect([held.seq, held.entries]).toEqual([2, [b]]);
    expect(state("list")).toMatchObject({
      held: { seq: 2, key_ids: [ctx.service.keyDoc.key_id] },
      stale: null,
      retry: null,
    });
    ctx.service.listResetSeq = 0;
  });

  it("a reset whose snapshot is older than the list held is refused: the list kept, the clock started, the next fetch waits", async () => {
    const [a, b] = [
      { kind: "tool", fingerprint: "a3".repeat(32) },
      { kind: "tool", fingerprint: "b3".repeat(32) },
    ];
    ctx.service.listUpdate([a]);
    ctx.service.listUpdate([b]);
    await ctx.rec.checks.pullList(); // held: seq 2
    ctx.service.listUpdates = ctx.service.listUpdates.slice(0, 1); // the witness serves a seq 1 snapshot
    ctx.service.listResetSeq = 3;
    const said = await ctx.rec.checks.pullList();
    expect(said).toContain("refused");
    expect(ctx.rec.checks.heldList()!.seq).toBe(2);
    const st = state("list");
    expect(st.stale.since).toBeTruthy();
    expect(st.retry.failures).toBe(1);
    const asked = vi.spyOn(Client.prototype, "fingerprints");
    await ctx.rec.checks.pullList(); // waiting
    expect(asked).not.toHaveBeenCalled();
    asked.mockRestore();
    ctx.service.listResetSeq = 0;
  });

  it("key list reads: one at a time, 10 min after a good read, 60 s after a failed one, a future time counts as now, another release's entry is never read, every witness kept", async () => {
    const served = vi.spyOn(Client.prototype, "serviceKeys");
    const file = path.join(ctx.rec.checks.home, "keys.json");
    const entry = () => JSON.parse(fs.readFileSync(file, "utf8")).witnesses[ctx.rec.url];
    let t = Date.now();
    const clock = vi.spyOn(Date, "now").mockImplementation(() => t);
    try {
      let release!: (v: unknown) => void;
      served.mockImplementationOnce(() => new Promise((r) => (release = r)) as never);
      const a = ctx.rec.checks.freshKeys(true, "force");
      const b = ctx.rec.checks.freshKeys(); // waits for the same read
      release({ keys: [ctx.service.keyDoc] });
      await Promise.all([a, b]);
      expect(served).toHaveBeenCalledTimes(1);
      expect(entry().failed).toBeUndefined();
      // After a good read: none for 10 minutes.
      t += 9 * 60_000;
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(1);
      t += 60_000;
      // A body that is not a keys document is a failed read: the next one after 60 s.
      served.mockResolvedValueOnce({ keys: [{ key_id: 5 }] } as never);
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(2);
      expect(entry().failed).toBe(true);
      expect(ctx.rec.checks.serviceKeys().map((k) => k.key_id)).toEqual([ctx.service.keyDoc.key_id]);
      t += 30_000;
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(2);
      t += 30_000;
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(3);
      // A `tried` in the future counts as now (written back), never as a wait without end.
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      doc.witnesses[ctx.rec.url].tried = "2999-01-01T00:00:00.000Z";
      doc.witnesses["https://other.example"] = {
        keys: [],
        revoked: ["0123456789abcdef"],
        tried: "2026-01-01T00:00:00.000Z",
      };
      fs.writeFileSync(file, JSON.stringify(doc));
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(3);
      expect(Date.parse(entry().tried)).toBe(t);
      t += 10 * 60_000;
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(4);
      // An entry read with other pinned keys (another release) counts as never read.
      const d2 = JSON.parse(fs.readFileSync(file, "utf8"));
      d2.witnesses[ctx.rec.url].pinned = "another release";
      fs.writeFileSync(file, JSON.stringify(d2));
      await ctx.rec.checks.freshKeys();
      expect(served).toHaveBeenCalledTimes(5);
      // Another witness's revoked ids stay in the file.
      expect(JSON.parse(fs.readFileSync(file, "utf8")).witnesses["https://other.example"].revoked).toEqual([
        "0123456789abcdef",
      ]);
    } finally {
      clock.mockRestore();
      served.mockRestore();
    }
  });

  it("nothing held, the list refused twice: no crash, no clock, the wait doubles", async () => {
    writeChecks({ mode: "enforce" });
    const real = ctx.service.key;
    ctx.service.key = SigningKey.generate(rnd); // every snapshot signed by a key nobody published
    try {
      ctx.service.listUpdate([{ kind: "tool", fingerprint: "f1".repeat(32) }]);
      expect(await ctx.rec.checks.pullList()).toContain("refused");
      expect(await ctx.rec.checks.pullList(true, true)).toContain("refused");
      const st = state("list");
      expect(st.held).toBeNull();
      expect(st.stale.since).toBeNull();
      expect(st.retry.failures).toBe(2);
      expect(ctx.rec.checks.heldList()).toBeNull();
    } finally {
      ctx.service.key = real;
    }
  });

  /** Make the held rule set fail its own signature (and name no tool), as a disk can. */
  function breakHeldCopy() {
    const pe = ctx.rec.checks.projectEnv()!;
    const file = path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.json`);
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    doc.rules.protect = {};
    doc.rules.default = doc.rules.default === "allow" ? "block" : "allow";
    fs.writeFileSync(file, JSON.stringify(doc));
    return file;
  }
  async function refused(name: string) {
    const ran: number[] = [];
    const fn = record(async (a: { amount: number }) => void ran.push(a.amount), { name });
    const e = await caught(fn({ amount: 5 }));
    expect(ran).toEqual([]);
    return e;
  }

  it("a broken held copy never un-protects a console-protected tool: refused through a refused pull and a no-rule-set answer, the dry run too", async () => {
    ctx.rec.checks.start = () => undefined;
    fs.rmSync(path.join(ctx.root, "signafaide.checks.json"), { force: true });
    ctx.rec.checks.forget();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect: { pay: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const file = breakHeldCopy();
    expect(ctx.rec.checks.heldRules()).toBeNull();
    let e = await refused("pay");
    expect(e.code).toBe("rules_unavailable");
    expect(e.message).toContain("unreadable or fails its own signature");
    // A pull refused (a key nobody published): still broken, still refused.
    publishByStranger();
    expect(await ctx.rec.checks.pullRules(true, true)).toContain("refused");
    e = await refused("pay");
    expect(e.code).toBe("rules_unavailable");
    // The witness answers that the project has no rule set: an unsigned answer, nothing changes.
    (ctx.service as any).ruleItems.set(ctx.rec.checks.projectEnv()![0], []);
    await ctx.rec.checks.pullRules(true, true);
    e = await refused("pay");
    expect(e.code).toBe("rules_unavailable");
    expect(fs.existsSync(file)).toBe(true);
    const dry = ctx.rec.checks.dryRun("pay", { amount: 5 }, "support-bot");
    expect(dry.blocked).toBe(true);
    expect(dry.lines.join("\n")).toContain("would refuse pay did not run");
  });

  it("a copy from before 0.5.4 (no state, no protect record) that breaks: which tools it protects is unknown, so every checked call is refused", async () => {
    ctx.rec.checks.start = () => undefined;
    fs.rmSync(path.join(ctx.root, "signafaide.checks.json"), { force: true });
    ctx.rec.checks.forget();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect: { pay: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const pe = ctx.rec.checks.projectEnv()!;
    for (const f of [`${pe[1]}.state.json`, `${pe[1]}.protect.json`])
      fs.rmSync(path.join(ctx.rec.checks.home, "rules", pe[0], f));
    breakHeldCopy();
    const e = await refused("lookup"); // a tool nothing names
    expect(e.code).toBe("rules_unavailable");
    expect(e.message).toContain("protection list unknown");
    expect(ctx.rec.checks.dryRun("lookup", { amount: 5 }, "support-bot").blocked).toBe(true);
    expect(ctx.rec.checks.status()[1]).toBe(true);
  });

  /** The rule set file and its protect record, for the protect record tests. */
  function rulesFiles() {
    const pe = ctx.rec.checks.projectEnv()!;
    const dir = path.join(ctx.rec.checks.home, "rules", pe[0]);
    return {
      copy: path.join(dir, `${pe[1]}.json`),
      record: path.join(dir, `${pe[1]}.protect.json`),
      item: (v: number) => (ctx.service as any).ruleItems.get(pe[0]).find((i: any) => i.rules.version === v),
    };
  }
  async function noFileProtecting(protect: Record<string, unknown>) {
    ctx.rec.checks.start = () => undefined;
    fs.rmSync(path.join(ctx.root, "signafaide.checks.json"), { force: true });
    ctx.rec.checks.forget();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect });
    await ctx.rec.checks.pullRules();
  }

  it("protect record: an older release's process wrote a newer version over the copy; broken before 0.5.4 reads it the record does not count, after it is refreshed", async () => {
    await noFileProtecting({ pay: { fail: "closed" } });
    const f = rulesFiles();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect: { refund: { fail: "closed" } } });
    fs.writeFileSync(f.copy, JSON.stringify(f.item(2))); // what a 0.5.3 process writes: the copy only
    breakHeldCopy();
    let e = await refused("refund");
    expect(e.code).toBe("rules_unavailable");
    expect(e.message).toContain("protection list unknown");
    // Read while valid: the record follows the copy (version 2 protects refund only).
    fs.writeFileSync(f.copy, JSON.stringify(f.item(2)));
    ctx.rec.checks.status();
    expect(JSON.parse(fs.readFileSync(f.record, "utf8"))).toMatchObject({ version: 2, protect: { refund: {} } });
    breakHeldCopy();
    e = await refused("refund");
    expect(e.code).toBe("rules_unavailable");
    expect(e.message).not.toContain("protection list unknown");
  });

  it("protect record: one ahead of the copy (a commit that raced the read) keeps the union until a verified newer copy replaces it", async () => {
    await noFileProtecting({ pay: { fail: "closed" } });
    const f = rulesFiles();
    fs.writeFileSync(
      f.record,
      JSON.stringify({ witness: ctx.rec.url, version: 2, protect: { refund: { fail: "closed" } } }),
    );
    ctx.rec.checks.status(); // the copy (version 1) is read: the record is refreshed from it, keeping refund
    expect(JSON.parse(fs.readFileSync(f.record, "utf8"))).toMatchObject({
      version: 1,
      protect: { pay: { fail: "closed" }, refund: { fail: "closed" } },
    });
    breakHeldCopy();
    expect((await refused("pay")).code).toBe("rules_unavailable");
    expect((await refused("refund")).code).toBe("rules_unavailable");
    // A verified newer copy replaces it.
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect: { lookup: { fail: "closed" } } });
    expect(await ctx.rec.checks.pullRules(true, true)).toBe("rule set version 2");
    expect(JSON.parse(fs.readFileSync(f.record, "utf8")).protect).toEqual({ lookup: { fail: "closed" } });
  });

  it("protect record: a crash between writing the copy and its record leaves the record behind, refreshed at the next read", async () => {
    await noFileProtecting({ pay: { fail: "closed" } });
    const f = rulesFiles();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect: { refund: { fail: "closed" } } });
    const save = (ctx.rec.checks as any).saveProtect;
    (ctx.rec.checks as any).saveProtect = () => {
      throw new Error("the process died here");
    };
    await expect(ctx.rec.checks.pullRules(true, true)).rejects.toThrow("the process died here");
    (ctx.rec.checks as any).saveProtect = save;
    expect(JSON.parse(fs.readFileSync(f.copy, "utf8")).rules.version).toBe(2);
    expect(JSON.parse(fs.readFileSync(f.record, "utf8")).version).toBe(1); // behind, never ahead
    ctx.rec.checks.status();
    expect(JSON.parse(fs.readFileSync(f.record, "utf8"))).toMatchObject({ version: 2, protect: { refund: {} } });
    breakHeldCopy();
    expect((await refused("refund")).code).toBe("rules_unavailable");
  });

  it("a ruling naming another version than the refused one forces a fetch at most once per retry interval", async () => {
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules();
    publishByStranger(); // version 2, refused
    await ctx.rec.checks.pullRules();
    publishByStranger(); // version 3: the witness rules with it; never fetched here
    ctx.rec.checks.start();
    await ctx.rec.checks.settled();
    ctx.rec.checks.refresh = async () => undefined; // the forced fetch changes nothing here
    const woke = vi.spyOn(ctx.rec.checks, "wake");
    const payFn = record(async (_a: { amount: number }) => undefined, { name: "pay", strict: true });
    for (let i = 0; i < 3; i++) await payFn({ amount: 1 }).catch(() => undefined);
    expect(woke).toHaveBeenCalledTimes(1);
    woke.mockRestore();
  });

  it("a copy from before 0.5.4 read while still valid gets its protect record, at status too", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce", protect: { pay: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const pe = ctx.rec.checks.projectEnv()!;
    const rec = path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.protect.json`);
    fs.rmSync(rec);
    // As a 0.5.3 copy: rewritten, so the cached judgement is read again.
    const file = path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.json`);
    fs.writeFileSync(file, fs.readFileSync(file, "utf8"));
    ctx.rec.checks.forget();
    ctx.rec.checks.status();
    expect(JSON.parse(fs.readFileSync(rec, "utf8"))).toMatchObject({
      witness: ctx.rec.url,
      protect: { pay: { fail: "closed" } },
    });
  });

  it("a strict ruling naming the refused version wakes nothing; one naming a newer, correctly signed version fetches it at once", async () => {
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules();
    publishByStranger(); // version 2, refused
    await ctx.rec.checks.pullRules();
    const payFn = record(async (_a: { amount: number }) => undefined, { name: "pay", strict: true });
    ctx.rec.checks.start(); // the background fetcher's own first wake, before counting
    await ctx.rec.checks.settled();
    const woke = vi.spyOn(ctx.rec.checks, "wake");
    await payFn({ amount: 1 }).catch(() => undefined);
    expect(woke).not.toHaveBeenCalled();
    woke.mockRestore();
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" }); // version 3, signed by the witness
    await payFn({ amount: 1 }).catch(() => undefined);
    await ctx.rec.checks.settled();
    expect(ctx.rec.checks.heldRules()!.version).toBe(3);
  });

  it("status reads and writes only this witness's state files: another witness's project in the same folder is left alone", async () => {
    await heldStale();
    const pe = ctx.rec.checks.projectEnv()!;
    const dir = path.join(ctx.rec.checks.home, "rules", "prj_other");
    fs.mkdirSync(dir, { recursive: true });
    fs.copyFileSync(path.join(ctx.rec.checks.home, "rules", pe[0], `${pe[1]}.json`), path.join(dir, "live.json"));
    const other = JSON.stringify({
      witness: "https://other.example",
      held: { version: 1, key_ids: ["0123456789abcdef"] },
      sdk: "0.0.0",
      stale: { since: ago(REVOKED_GRACE_MS * 3), refused: null, noted: [], said: null },
      retry: null,
    });
    fs.writeFileSync(path.join(dir, "live.state.json"), other);
    const [lines] = ctx.rec.checks.status();
    expect(lines.some((l) => l.includes("prj_other"))).toBe(false);
    expect(lines.some((l) => l.startsWith(`STALE rule set (${pe[0]}/${pe[1]})`))).toBe(true);
    expect(fs.readFileSync(path.join(dir, "live.state.json"), "utf8")).toBe(other);
    ctx.service.revoked = undefined;
  });

  it("a retry `until` more than an hour ahead counts as an hour from now (written back); a strict call never wakes a pull while a refused version waits", async () => {
    writeChecks({ mode: "enforce", tools: { pay: { strict: true } } });
    ctx.rec.checks.start = () => undefined;
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.pullRules();
    publishByStranger();
    await ctx.rec.checks.pullRules();
    const d = state("rules");
    d.retry.until = "2999-01-01T00:00:00.000Z";
    fs.writeFileSync(statePath("rules"), JSON.stringify(d));
    const n = ctx.service.rulesFetches.length;
    await ctx.rec.checks.pullRules();
    expect(ctx.service.rulesFetches.length).toBe(n);
    expect(Date.parse(state("rules").retry.until) - Date.now()).toBeLessThanOrEqual(3_600_000);
    // The witness rules with the refused newer version: no wake per call.
    const woke = vi.spyOn(ctx.rec.checks, "wake");
    const payFn = record(async (_a: { amount: number }) => undefined, { name: "pay", strict: true });
    for (let i = 0; i < 3; i++) await payFn({ amount: 1 }).catch(() => undefined);
    expect(woke).not.toHaveBeenCalled();
    woke.mockRestore();
  });

  it("a forced pull reads the key list, the rule set and the list now, whatever any wait says", async () => {
    writeChecks({ mode: "enforce" });
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    await ctx.rec.checks.refresh();
    const k = vi.spyOn(Client.prototype, "serviceKeys");
    const r = vi.spyOn(Client.prototype, "rules");
    const l = vi.spyOn(Client.prototype, "fingerprints");
    await ctx.rec.checks.refresh(); // within the waits: no key list read
    expect(k).not.toHaveBeenCalled();
    await ctx.rec.checks.forcedPull();
    expect([k.mock.calls.length, r.mock.calls.length > 0, l.mock.calls.length > 0]).toEqual([1, true, true]);
    k.mockRestore();
    r.mockRestore();
    l.mockRestore();
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
    ctx.service.publishRules(ctx.rec.apiKey!, [], {
      mode: "enforce",
      fingerprintExceptions: [
        { kind: "tool", fingerprint: t.tool, reason: "Re-approved in the console: our own tool." },
      ],
    });
    await ctx.rec.checks.pullRules();
    await pay({ amount: 2 });
    expect(ran).toEqual([2]);
    const d = records()
      .filter((r) => r.envelope.kind === "decision")
      .at(-1)!;
    expect(d.envelope.checks!.results.find((x: any) => x.check === "fingerprint")).toEqual({
      check: "fingerprint",
      result: "allow",
      mode: "enforce",
      found: [],
    });
  });

  it("the rule set document's fingerprint_exceptions: optional, validated", () => {
    const base = ctx.service.publishRules(ctx.rec.apiKey!, []).rules;
    expect(C.ruleSetErrors(base)).toBeNull();
    const ok = {
      ...base,
      fingerprint_exceptions: [{ kind: "description", fingerprint: "ab".repeat(32), reason: "Reviewed." }],
    };
    expect(C.ruleSetErrors(ok)).toBeNull();
    expect(
      C.ruleSetErrors({ ...ok, fingerprint_exceptions: [{ kind: "description", fingerprint: "ab".repeat(32) }] }),
    ).toContain("{kind, fingerprint, reason}");
    expect(
      C.ruleSetErrors({ ...ok, fingerprint_exceptions: [ok.fingerprint_exceptions[0], ok.fingerprint_exceptions[0]] }),
    ).toContain("listed twice");
  });
});
