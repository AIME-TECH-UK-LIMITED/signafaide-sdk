/** Fix round 4: an empty home with a known project continues the witness chain (#11), no head is
 * seq 1 (#12), the local verify of a short-lived instance (#13), one word for pending (#16), the
 * revoked-key and BLOCKED wording (#19), and housekeeping (#22). */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { main, statusLines } from "../src/cli.js";
import { flush, init, note, verify } from "../src/index.js";
import { configure, getRecorder } from "../src/runtime.js";
import { lockAgeMs, lockStamp } from "../src/state.js";
import { useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });

const reply = (status: number, code: string, message: string) => [status, { error: { code, message, docs: `https://docs.example/errors#${code}` } }] as [number, any];

async function cli(...args: string[]): Promise<[number, string]> {
  const out: string[] = [];
  const [log, error] = [console.log, console.error];
  console.log = (s: string) => out.push(s);
  console.error = (s: string) => out.push(s);
  try {
    return [await main(args), out.join("\n")];
  } finally {
    console.log = log;
    console.error = error;
  }
}

describe("#11, #13: an empty home with a known project", () => {
  it("continues the witness chain, and the local verify says where it starts", async () => {
    const st = getRecorder().state;
    st.loadKey("lambda-bot");
    const doc = JSON.parse(fs.readFileSync(st.keyPath("lambda-bot"), "utf8"));
    note("a", {}, { agent: "lambda-bot" });
    note("b", {}, { agent: "lambda-bot" });
    expect((await flush()).errors).toEqual({});
    fs.rmSync(st.home, { recursive: true, force: true }); // a cold start: the key stays in .env
    const r = await init({ quiet: true, keyProvider: () => doc, flushIntervalMs: 3_600_000 });
    const bucket = r.state.bucket(r.apiKey);
    expect(bucket.startsWith("_pending/")).toBe(false); // init() learned the project
    const rec = r.write("note", "c", {}, { agent: "lambda-bot" });
    expect((rec as any).draft).toBe(true); // no chain on this disk: a draft until the head is known
    expect((await r.flush()).errors).toEqual({});
    expect(ctx.service.project().heads.get("lambda-bot").head.seq).toBe(4); // the instance-start note is seq 3 (round 5)
    const chain = `${bucket}/lambda-bot`;
    expect(r.state.readAll(chain).map((x: any) => x.envelope.seq)).toEqual([3, 4]);
    expect(r.state.chainBase(chain)?.head.seq).toBe(2);
    const v = await verify();
    expect(v.ok).toBe(true);
    expect(v.check("chain").detail).toContain(`continues after a co-signed record this machine does not hold: ${chain} after seq 2`);
    fs.unlinkSync(path.join(r.state.home, "chain", `${chain}.base.json`));
    expect((await verify()).ok).toBe(false); // the base is what makes it pass
    r.close();
  });
});

describe("#12: a brand-new agent", () => {
  it("starts at seq 1 when the witness has no head, also from an older witness (unknown_agent)", async () => {
    ctx.service.headsUnknownAgent = true;
    fs.rmSync(getRecorder().state.home, { recursive: true, force: true });
    const r = configure({ quiet: true, flushIntervalMs: 3_600_000 });
    r.write("note", "first", {}, { agent: "new-bot" });
    const [code, out] = await cli("flush");
    expect(code, out).toBe(0);
    expect(ctx.service.project().heads.get("new-bot").head.seq).toBe(1);
  });
});

describe("#16: one word for no public timestamp yet", () => {
  it("a fresh co-signed batch is PENDING locally, with the one definition", async () => {
    note("n", {});
    await flush();
    const v = await verify();
    expect([v.check("anchor").status, v.check("ots").status]).toEqual(["pending", "pending"]);
    expect(String(v)).toContain("pending: co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms within a few hours); never counted as passed");
    const now = Date.now;
    Date.now = () => now() + 3 * 3_600_000;
    try {
      const old = await verify();
      expect(old.check("anchor").status).toBe("not_checked");
      expect(old.check("anchor").detail).toContain("verify an export");
    } finally {
      Date.now = now;
    }
  });
});

describe("#19: revoked keys and the BLOCKED line", () => {
  it("says `signafaide repair` only, with no doubled full stops", async () => {
    note("a", {});
    await flush();
    ctx.service.failAlways = reply(400, "bad_signature", "agent key was revoked at 2026-11-14T10:00:00.000Z; records it signs are refused.");
    note("b", {});
    const e = Object.values((await flush()).errors)[0] as Error;
    expect(e.message).toContain("signafaide repair --agent claims-project");
    expect(e.message).not.toContain("keys rotate");
    const [b] = getRecorder().diagnose();
    const line = `BLOCKED ${b.chain}: ${b.reason}; 1 record cannot ship. Next: ${b.next}`;
    expect(line).not.toMatch(/\.\.|\.;/);
  });

  it("a clock ahead also says wait until it catches up", async () => {
    note("a", {});
    await flush();
    ctx.service.failAlways = reply(400, "invalid_record", "records[0]: time is 900 s ahead of the service clock.");
    note("b", {});
    await flush();
    expect(getRecorder().diagnose()[0].next).toContain("wait until it catches up");
  });
});

describe("#22: housekeeping", () => {
  it(".signafaide/.gitignore holds '*', and locks age by the monotonic clock", () => {
    note("n", {});
    expect(fs.readFileSync(path.join(getRecorder().state.home, ".gitignore"), "utf8")).toBe("*\n");
    const p = path.join(os.tmpdir(), `sfa-lock-${process.pid}.lock`);
    fs.writeFileSync(p, lockStamp());
    const hourAgo = new Date(Date.now() - 3_600_000);
    fs.utimesSync(p, hourAgo, hourAgo);
    if (fs.existsSync("/proc/sys/kernel/random/boot_id")) expect(lockAgeMs(p)).toBeLessThan(5_000);
    fs.writeFileSync(p, "12345"); // an older SDK's lock: the file time
    fs.utimesSync(p, hourAgo, hourAgo);
    expect(lockAgeMs(p)).toBeGreaterThan(3_000_000);
    fs.unlinkSync(p);
  });

  it("a test-mode folder is removed when the process ends", () => {
    const dist = path.resolve(__dirname, "../dist/index.cjs");
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("SIGNAFAIDE_")));
    const home = execFileSync(process.execPath, ["-e", `const s=require(${JSON.stringify(dist)});const r=s.configure({quiet:true});s.note("n",{});console.log(r.state.home)`], {
      env: { ...env, SIGNAFAIDE_TEST: "1" },
      encoding: "utf8",
    }).trim();
    expect(home).toContain("signafaide-test-");
    expect(fs.existsSync(home)).toBe(false);
  });

  it("the exit timeout names the real limit", async () => {
    note("n", {});
    const r = configure({ quiet: true, exitFlushMs: 300, flushIntervalMs: 3_600_000 });
    const c = (r as any).ioMode;
    (r as any).ioMode = "exit";
    const client = r.client(10_000);
    (r as any).ioMode = c;
    expect(client.timeoutLabel).toBe("no answer within the 0.3 s allowed at exit (SIGNAFAIDE_EXIT_FLUSH_MS)");
  });

  it("replay picks the only agent; status names the project", async () => {
    note("n", {}, { agent: "only-bot" });
    await flush();
    expect(getRecorder().onlyAgent()).toBe("only-bot");
    const [code, out] = await cli("replay", "--json");
    expect(code, out).toBe(0);
    expect(JSON.parse(out).agent).toBe("only-bot");
    ctx.service.project().name = "Claims automation";
    const lines = await statusLines(getRecorder());
    expect(lines).toContain(`project: Claims automation (${ctx.service.project().project}, test)`);
    expect(lines.some((l) => l.startsWith("chain Claims automation/test/only-bot"))).toBe(true);
  });

  it("upgrade lines: after verify on a live Free key once a week, and at the limit; never in --json", async () => {
    const live = `sfa_live_${"1".repeat(32)}`;
    const prj = ctx.service.addProject(live, "live");
    prj.plan = "free";
    process.env.SIGNAFAIDE_API_KEY = live;
    try {
      const r = configure({ quiet: true, flushIntervalMs: 3_600_000 });
      note("n", {});
      await r.flush();
      expect((await cli("verify", "--json"))[1]).not.toContain("upgrade:");
      expect((await cli("verify"))[1].split("upgrade: Solo (£19 a month)").length - 1).toBe(1);
      expect((await cli("verify"))[1]).not.toContain("upgrade:");
      ctx.service.failAlways = reply(429, "quota_exceeded", "This request needs 1 record but only 0 of the 25000 monthly records are left.");
      note("m", {});
      expect((await cli("flush"))[1]).toContain("upgrade: Solo (£19 a month) takes 100,000 live records a month");
    } finally {
      delete process.env.SIGNAFAIDE_API_KEY;
      ctx.service.failAlways = null;
    }
  });
});
