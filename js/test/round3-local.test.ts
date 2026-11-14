/** Fix round 3, on this machine only: monotonic time, the off switch, test mode, key format,
 * read-only folders, keys from the environment, per-env keys, the default witness. */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_URL } from "../src/http.js";
import { note, record, verify } from "../src/index.js";
import { clampTime, type SignedRecord } from "../src/records.js";
import { Recorder, configure, getRecorder, recordingDisabled, testMode } from "../src/runtime.js";
import { State, StateError, agentKeyEnvName } from "../src/state.js";
import { useProject } from "./helpers.js";

const ctx = useProject();
const lines = (rec: Recorder, agent = "claims-project"): SignedRecord[] => {
  const chain = rec.state.chains().find((c) => c.endsWith(`/${agent}`))!;
  return rec.state.readAll(chain);
};

afterEach(() => {
  vi.useRealTimers();
  for (const k of Object.keys(process.env)) if (k.startsWith("SIGNAFAIDE_AGENT_KEY_")) delete process.env[k];
  delete process.env.SIGNAFAIDE_DISABLED;
});

describe("monotonic time (spec §2.2)", () => {
  it("a clock step back never writes a chain that goes back; the clock's reading is kept", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-13T10:00:10.000Z"));
    note("a", { meta: { by: "ops" } });
    vi.setSystemTime(new Date("2026-11-13T10:00:05.000Z")); // NTP steps the clock back 5 s
    note("b", { meta: { by: "ops" } });
    note("c", {});
    vi.setSystemTime(new Date("2026-11-13T10:00:11.000Z"));
    note("d", {});
    const [a, b, c, d] = lines(getRecorder());
    expect([a.envelope.time, b.envelope.time, c.envelope.time, d.envelope.time]).toEqual([
      "2026-11-13T10:00:10.000Z",
      "2026-11-13T10:00:10.000Z",
      "2026-11-13T10:00:10.000Z",
      "2026-11-13T10:00:11.000Z",
    ]);
    expect(b.content).toEqual({ meta: { by: "ops", wall_time: "2026-11-13T10:00:05.000Z" } });
    expect(c.content).toEqual({ meta: { wall_time: "2026-11-13T10:00:05.000Z" } });
    expect(a.content).toEqual({ meta: { by: "ops" } });
    vi.useRealTimers();
    const r = await verify();
    expect(r.check("chain").status, String(r)).toBe("pass");
    expect(r.check("content").status).toBe("pass");
  });

  it("a record is never dated before its key was made", () => {
    const st = getRecorder().state;
    st.loadKey("bot");
    const doc = JSON.parse(fs.readFileSync(st.keyPath("bot"), "utf8"));
    doc.created = new Date(Date.now() + 60_000).toISOString(); // made while the clock was ahead
    fs.writeFileSync(st.keyPath("bot"), JSON.stringify(doc));
    note("n", {}, { agent: "bot" });
    const [r] = lines(getRecorder(), "bot");
    expect(r.envelope.time).toBe(doc.created);
    expect((r.content!.meta as any).wall_time < doc.created).toBe(true);
  });

  it("clampTime", () => {
    expect(clampTime("2026-11-13T10:00:00.000Z", "2026-11-13T10:00:05.000Z", null)).toEqual(["2026-11-13T10:00:05.000Z", true]);
    expect(clampTime("2026-11-13T10:00:06.000Z", "2026-11-13T10:00:05.000Z", "2026-11-13T09:00:00.000Z")).toEqual(["2026-11-13T10:00:06.000Z", false]);
  });
});

describe("modes", () => {
  it("SIGNAFAIDE_DISABLED=1: wrappers run the function and write nothing", async () => {
    process.env.SIGNAFAIDE_DISABLED = "1";
    expect(recordingDisabled()).toBe(true);
    expect(record((x: number) => x * 2, { name: "double" })(21)).toBe(42);
    expect(await record(async () => "ok", { name: "strict", strict: true })()).toBe("ok");
    expect(note("n", {})).toBe("");
    expect(getRecorder().state.chains()).toEqual([]);
  });

  it("test mode: on by itself under a test runner, records in a temporary folder, nothing sent", () => {
    expect(testMode({ VITEST: "true" })).toBe(true);
    expect(testMode({ JEST_WORKER_ID: "1" })).toBe(true);
    expect(testMode({ VITEST: "true", SIGNAFAIDE_TEST: "0" })).toBe(false);
    expect(testMode({ SIGNAFAIDE_TEST: "1" })).toBe(true);
    expect(testMode({})).toBe(false);
    process.env.SIGNAFAIDE_TEST = "1";
    try {
      const rec = configure({ quiet: true, apiKey: "sfa_test_" + "a".repeat(32) });
      expect(rec.test).toBe(true);
      expect(rec.apiKey).toBeUndefined();
      expect(rec.state.home.startsWith(os.tmpdir())).toBe(true);
      rec.write("note", "n", {});
      expect(fs.existsSync(path.join(ctx.root, ".signafaide"))).toBe(false);
    } finally {
      process.env.SIGNAFAIDE_TEST = "0";
    }
  });
});

describe("API key format", () => {
  it("a malformed key is caught here and never sent", async () => {
    const rec = configure({ quiet: true, apiKey: "sk-openai-oops" });
    expect(rec.apiKey).toBeUndefined();
    note("n", {});
    await rec.flush();
    expect(ctx.service.calls).toEqual([]);
    expect(rec.status().api_key_invalid).toBe(true);
    await expect(rec.createSandbox()).rejects.toThrow(/not a signafAIde key/);
  });
});

describe("read-only folder", () => {
  it.skipIf(process.getuid?.() === 0)("says what cannot be written and how to fix it", () => {
    const ro = path.join(ctx.root, "ro");
    fs.mkdirSync(ro);
    fs.chmodSync(ro, 0o555);
    try {
      const rec = configure({ quiet: true, home: path.join(ro, ".signafaide") });
      let err: unknown;
      try {
        rec.write("note", "n", {});
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(StateError);
      expect((err as Error).message).toMatch(/cannot write signafAIde's local state in .*\(permission denied\)\. Set SIGNAFAIDE_HOME to a writable folder/);
      expect((err as Error).message).not.toMatch(/EACCES/);
    } finally {
      fs.chmodSync(ro, 0o755);
    }
  });
});

describe("agent keys", () => {
  it("SIGNAFAIDE_AGENT_KEY_<NAME>: the key comes from the environment, no key file is written", () => {
    const other = new State(path.join(ctx.root, "elsewhere"), ctx.root);
    const k = other.loadKey("env.bot-1");
    expect(agentKeyEnvName("env.bot-1")).toBe("SIGNAFAIDE_AGENT_KEY_ENV_BOT_1");
    process.env.SIGNAFAIDE_AGENT_KEY_ENV_BOT_1 = fs.readFileSync(other.keyPath("env.bot-1"), "utf8");
    const rec = configure({ quiet: true });
    note("n", {}, { agent: "env.bot-1" });
    expect(lines(rec, "env.bot-1")[0].key_id).toBe(k.keyId);
    expect(fs.existsSync(rec.state.keyPath("env.bot-1"))).toBe(false);
    expect(rec.state.exportAgentKeys().keys.map((e) => e.key_id)).toContain(k.keyId);
    expect(() => rec.state.rotateKey("env.bot-1")).toThrow(/comes from SIGNAFAIDE_AGENT_KEY_ENV_BOT_1/);
  });

  it("a key provider takes precedence, and a bad value says what it must be", () => {
    const other = new State(path.join(ctx.root, "elsewhere"), ctx.root);
    const k = other.loadKey("vault-bot");
    const doc = JSON.parse(fs.readFileSync(other.keyPath("vault-bot"), "utf8"));
    const rec = configure({ quiet: true, keyProvider: (agent) => (agent === "vault-bot" ? doc : undefined) });
    note("n", {}, { agent: "vault-bot" });
    expect(lines(rec, "vault-bot")[0].key_id).toBe(k.keyId);
    process.env.SIGNAFAIDE_AGENT_KEY_BAD = "not json";
    expect(() => configure({ quiet: true }).write("note", "n", {}, { agent: "bad" })).toThrow(/must hold the agent's key file/);
  });

  it("live chains have their own key", () => {
    const st = getRecorder().state;
    const test = st.loadKey("bot");
    const live = st.loadKey("bot", true, "live");
    expect(live.keyId).not.toBe(test.keyId);
    expect(fs.existsSync(path.join(st.home, "agents", "live", "bot.key"))).toBe(true);
    expect(st.exportAgentKeys().keys.map((e) => e.key_id).sort()).toEqual([test.keyId, live.keyId].sort());
  });
});

describe("release", () => {
  it("the default witness is the hosted service, never a loopback address", () => {
    expect(DEFAULT_URL).toBe("https://api.signafaide.com");
    const host = new URL(DEFAULT_URL).hostname;
    expect(host === "localhost" || /^127\./.test(host) || host === "::1").toBe(false);
  });
});
