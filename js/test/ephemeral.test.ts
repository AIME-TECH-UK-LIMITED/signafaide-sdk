/** Keys create, the head file and onHead hook, the signed
 * instance-start note, strict mode and the auditor path in the skill, and no
 * spurious "no answer within 10 s" when the exit flush takes over. */
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { SETUP_NOTES } from "../src/agents.js";
import { main } from "../src/cli.js";
import { flush, init, note, verify } from "../src/index.js";
import { INSTANCE_NOTE, INSTANCE_START } from "../src/records.js";
import { configure, getRecorder } from "../src/runtime.js";
import { skillBody } from "../src/skill.js";
import { useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });

async function cli(...args: string[]): Promise<[number, string, string]> {
  const [out, errs]: string[][] = [[], []];
  const [log, error] = [console.log, console.error];
  console.log = (s: string) => out.push(s);
  console.error = (s: string) => errs.push(s);
  try {
    return [await main(args), out.join("\n"), errs.join("\n")];
  } catch (e) {
    return [1, out.join("\n"), errs.concat(String((e as Error).message)).join("\n")];
  } finally {
    console.log = log;
    console.error = error;
  }
}

describe("keys create", () => {
  it("--print registers a key, prints the key file and writes nothing", async () => {
    const st = getRecorder().state;
    const before = ctx.service.registrations.length;
    const [code, out, err] = await cli("keys", "create", "--agent", "reconciler-0", "--env", "test", "--print");
    expect(code, err).toBe(0);
    const doc = JSON.parse(out);
    expect(Object.keys(doc)).toEqual(["agent", "key_id", "public_key", "private_key", "created"]);
    expect(doc.agent).toBe("reconciler-0");
    expect(err).toContain("SIGNAFAIDE_AGENT_KEY_RECONCILER_0");
    expect(ctx.service.registrations.length).toBe(before + 1);
    expect(fs.existsSync(st.keyPath("reconciler-0"))).toBe(false);
    expect(st.chains()).toEqual([]); // no record written
    // The printed key works from the environment: records ship under it without a new registration.
    process.env.SIGNAFAIDE_AGENT_KEY_RECONCILER_0 = out;
    try {
      note("first", {}, { agent: "reconciler-0" });
      expect((await flush()).errors).toEqual({});
      expect(ctx.service.project().agents.get("reconciler-0").size).toBe(1);
    } finally {
      delete process.env.SIGNAFAIDE_AGENT_KEY_RECONCILER_0;
    }
  });

  it("--print with a live key on a clean machine writes no file at all", async () => {
    const live = "sfa_live_" + "L".repeat(32);
    ctx.service.addProject(live, "live");
    const dir = fs.mkdtempSync(path.join(ctx.root, "..", "keyshop-"));
    fs.mkdirSync(path.join(dir, ".git"));
    const cwd = process.cwd();
    process.chdir(dir);
    process.env.SIGNAFAIDE_API_KEY = live;
    try {
      const [code, out, err] = await cli("keys", "create", "--agent", "reconciler-0", "--env", "live", "--print");
      expect(code, err).toBe(0);
      expect(JSON.parse(out).agent).toBe("reconciler-0");
      expect(err).toContain("SIGNAFAIDE_AGENT_KEY_LIVE_RECONCILER_0");
      expect(fs.existsSync(path.join(dir, ".signafaide"))).toBe(false);
    } finally {
      delete process.env.SIGNAFAIDE_API_KEY;
      process.chdir(cwd);
    }
  });

  it("without --print it saves the key file; a second create is refused", async () => {
    const [code, out] = await cli("keys", "create", "--agent", "risk-0", "--env", "test");
    expect(code).toBe(0);
    expect(out).toContain("no record was written");
    expect(fs.existsSync(getRecorder().state.keyPath("risk-0"))).toBe(true);
    const [again, , err] = await cli("keys", "create", "--agent", "risk-0", "--env", "test");
    expect(again).not.toBe(0);
    expect(err).toContain("keys rotate");
  });

  it("refuses an agent that already has an active key on the witness, and a key of the other env", async () => {
    note("x", {}, { agent: "busy-bot" });
    await flush();
    const [code, , err] = await cli("keys", "create", "--agent", "busy-bot", "--env", "test", "--print");
    expect(code).not.toBe(0);
    expect(err).toContain("already has an active key on the witness");
    const [live, , err2] = await cli("keys", "create", "--agent", "other", "--env", "live", "--print");
    expect(live).not.toBe(0);
    expect(err2).toContain("needs a live key");
  });

  it("rotate without a key points at keys create", async () => {
    const [code, , err] = await cli("keys", "rotate", "--agent", "nobody", "--env", "live");
    expect(code).not.toBe(0);
    expect(err).toContain("keys create --agent nobody --env live --print");
  });
});

describe("ephemeral containers", () => {
  it("the head file and onHead keep the heads; a new instance starts with a signed note", async () => {
    const dir = fs.mkdtempSync(path.join(ctx.root, "..", "vol-"));
    const headFile = path.join(dir, "heads", "head.json");
    process.env.SIGNAFAIDE_HEAD_FILE = headFile;
    try {
      const seen: unknown[] = [];
      let r = configure({ quiet: true, flushIntervalMs: 3_600_000, onHead: (h) => void seen.push(...h) });
      const st = r.state;
      st.loadKey("risk-0");
      const doc = JSON.parse(fs.readFileSync(st.keyPath("risk-0"), "utf8"));
      r.write("note", "a", {}, { agent: "risk-0" });
      r.write("note", "b", {}, { agent: "risk-0" });
      expect((await r.flush()).errors).toEqual({});
      expect(seen.length).toBe(1);
      const kept = JSON.parse(fs.readFileSync(headFile, "utf8"));
      const [project] = Object.keys(kept);
      expect(kept[project].test["risk-0"].head.seq).toBe(2);
      // The container goes: its disk with it. A new one starts with the key from the secret store.
      fs.rmSync(st.home, { recursive: true, force: true });
      r = await init({ quiet: true, keyProvider: () => doc, flushIntervalMs: 3_600_000 });
      r.write("decision", "freeze_account", { input: { account: "A1" } }, { agent: "risk-0" });
      expect((await r.flush()).errors).toEqual({});
      const chain = `${r.state.bucket(r.apiKey)}/risk-0`;
      const recs = r.state.readAll(chain) as any[];
      expect(recs.map((x) => [x.envelope.seq, x.envelope.kind, x.envelope.name])).toEqual([
        [3, "note", INSTANCE_START],
        [4, "decision", "freeze_account"],
      ]);
      expect(recs[0].content).toEqual({
        continues_after_seq: 2,
        continues_after: kept[project].test["risk-0"].head.record_hash,
        earlier_unsent: "unknown",
      });
      expect(JSON.parse(fs.readFileSync(headFile, "utf8"))[project].test["risk-0"].head.seq).toBe(4);
      const v = await verify();
      expect(v.ok).toBe(true);
      expect(v.check("chain").detail).toContain(`${INSTANCE_NOTE}: ${chain} after seq 2`);
      r.close();
    } finally {
      delete process.env.SIGNAFAIDE_HEAD_FILE;
    }
  });

  it("an onHead that throws never stops recording", async () => {
    const r = configure({
      quiet: true,
      flushIntervalMs: 3_600_000,
      onHead: () => {
        throw new Error("bucket down");
      },
    });
    const warn = console.warn;
    const said: string[] = [];
    console.warn = (s: string) => said.push(s);
    try {
      r.write("note", "a", {}, { agent: "hooked" });
      expect((await r.flush()).errors).toEqual({});
    } finally {
      console.warn = warn;
    }
    expect(said.join("\n")).toContain("onHead failed (the heads are still in head.json): bucket down");
  });

  it("a chain that starts at seq 1 has no instance-start note", async () => {
    note("only", {}, { agent: "fresh" });
    await flush();
    const st = getRecorder().state;
    const chain = st.chains().find((c) => c.endsWith("/fresh"))!;
    expect((st.readAll(chain) as any[]).map((x) => x.envelope.name)).toEqual(["only"]);
  });
});

describe("the skill and agent setup", () => {
  it("recommend strict mode for money tools and end with the auditor path", () => {
    const body = skillBody();
    expect(body).toContain("strict: true");
    expect(body).toContain("strict=True");
    expect(body).toContain("evidence for an auditor");
    expect(body).toContain("auditor link");
    expect(body).toContain("verification report");
    const notes = SETUP_NOTES().join("\n");
    expect(notes).toContain("protects a tool");
    expect(notes).toContain("auditor link");
  });

  it("the plugin's SKILL.md is the generated text", () => {
    const file = path.join(__dirname, "../../plugin/skills/signafaide/SKILL.md");
    expect(fs.readFileSync(file, "utf8")).toContain(skillBody().split("\n").slice(0, 3).join("\n"));
    expect(fs.readFileSync(file, "utf8")).toContain("evidence for an auditor");
  });
});

describe("the exit flush cutting off a background send", () => {
  it("is not reported as no answer within 10 s", async () => {
    const r = getRecorder() as any;
    const warn = console.warn;
    const said: string[] = [];
    console.warn = (s: string) => said.push(s);
    ctx.service.delayMs = 300;
    try {
      r.write("note", "a", {}, { agent: "exiting" });
      const p = r.flushLogged(10_000, "bg");
      await new Promise((res) => setTimeout(res, 50));
      r.bgAbort.abort(); // what beforeExit does before its own flush
      await p;
    } finally {
      console.warn = warn;
      ctx.service.delayMs = 0;
    }
    expect(said.join("\n")).not.toContain("no answer within");
  });
});
