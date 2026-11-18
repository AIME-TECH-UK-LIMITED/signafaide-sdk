/**
 * SDK 0.5.2 (SPEC §8, §10.1, issue #65): a person protects a tool from the console, and every
 * client that wraps the tool protects it from its next fetch of the rule set, as the checks
 * file's `protect: true` would. Owner: "i expect when i press the protect button i activate
 * protect same as the cli command".
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it, vi } from "vitest";
import * as C from "../src/checks.js";
import { CheckError } from "../src/checks-runtime.js";
import { main } from "../src/cli.js";
import { scriptedPrompter } from "../src/protect.js";
import { protect, record } from "../src/record.js";
import { configure } from "../src/runtime.js";
import { runPull, toolLines } from "../src/tool-commands.js";
import { records, useProject } from "./helpers.js";

const PAY_LIMIT = { id: "limit", about: "Big payouts.", action: "block", tools: ["pay"], agents: null, when: [{ field: "/amount", op: "gt", value: 1000 }] };
const PAY_RATE = { id: "rate", about: "At most 100 a minute.", action: "block", tools: ["pay"], agents: null, when: [], limit: { calls: 100, seconds: 60, per: "agent_tool" } };

const caught = async (p: unknown): Promise<CheckError> => {
  try {
    await p;
  } catch (e) {
    return e as CheckError;
  }
  throw new Error("expected the call to be refused");
};

/** stderr lines written while `fn` runs. */
async function stderr<T>(fn: () => Promise<T>): Promise<[T, string[]]> {
  const lines: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((s: string) => void lines.push(String(s)));
  try {
    return [await fn(), lines];
  } finally {
    spy.mockRestore();
  }
}

async function cli(...args: string[]): Promise<[number, string]> {
  const lines: string[] = [];
  const log = vi.spyOn(console, "log").mockImplementation((s: string) => void lines.push(String(s)));
  const error = vi.spyOn(console, "error").mockImplementation((s: string) => void lines.push(String(s)));
  try {
    return [await main(args), lines.join("\n")];
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

describe("protected from the console (SDK 0.5.2)", () => {
  const ctx = useProject({ optIn: true });

  const payTool = (ran: number[] = []) => record(async (a: { amount: number }) => (ran.push(a.amount), "paid"), { name: "pay" });

  it("takes effect after a fetch, with no checks file: strict, every local check On, the source in the record", async () => {
    const ran: number[] = [];
    const pay = payTool(ran);
    ctx.service.publishRules(ctx.rec.apiKey!, [PAY_RATE]);
    await ctx.rec.checks.pullRules();
    expect(await pay({ amount: 5 })).toBe("paid");
    // version 1 does not protect pay: no checks file, so no checks at all, as in 1.1
    expect("checks" in records().at(-2)!.envelope).toBe(false);
    ctx.service.publishRules(ctx.rec.apiKey!, [PAY_RATE], { protect: { pay: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const [got, err] = await stderr(() => pay({ amount: 7 }));
    expect(got).toBe("paid");
    expect(err).toContain("signafaide: pay is now protected from the console (rule set version 2)");
    const [d, o] = records().slice(-2);
    const ch = d.envelope.checks!;
    expect(ch.strict).toBe(true);
    expect(ch.fail).toBe("closed");
    expect(ch.results.filter((e: any) => e.check !== "rule").every((e: any) => e.mode === "enforce")).toBe(true);
    expect(ch.rules[0].version).toBe(2);
    expect((d.content as any).meta.protected_by).toEqual(["console"]);
    expect(d.receipt!.ruling!.ruling).toBe("allow");
    expect(o.envelope.checks!.ruling).toBe("allow");
    expect(ran).toEqual([5, 7]);
    // the line is said once per change
    const [, again] = await stderr(() => pay({ amount: 8 }));
    expect(again.join("\n")).not.toContain("now protected");
  });

  it("unprotect: the next version without the tool leaves it unprotected, unless the code protects it", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { protect: { pay: { fail: "closed" }, refund: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const pay = payTool();
    const refund = protect(async (_a: { amount: number }) => "refunded", { name: "refund" });
    await stderr(() => pay({ amount: 1 }));
    expect(records().at(-2)!.envelope.checks!.strict).toBe(true);
    await stderr(() => refund({ amount: 1 }));
    expect((records().at(-2)!.content as any).meta.protected_by).toEqual(["code", "console"]);
    ctx.service.publishRules(ctx.rec.apiKey!, []);
    await ctx.rec.checks.pullRules();
    const [, e1] = await stderr(() => pay({ amount: 2 }));
    expect(e1).toContain("signafaide: pay is no longer protected from the console (rule set version 2)");
    expect("checks" in records().at(-2)!.envelope).toBe(false);
    const [, e2] = await stderr(() => refund({ amount: 2 }));
    expect(e2).toContain("signafaide: refund is no longer protected from the console (rule set version 2); it stays protected by the code");
    expect(records().at(-2)!.envelope.checks!.strict).toBe(true);
    expect((records().at(-2)!.content as any).meta.protected_by).toEqual(["code"]);
  });

  for (const fail of ["closed", "open"] as const) {
    it(`no ruling follows the console's fail mode (${fail}), over the checks file`, async () => {
      ctx.service.publishRules(ctx.rec.apiKey!, [], { protect: { pay: { fail } } });
      await ctx.rec.checks.pullRules();
      // a version 1 file that says the opposite for the tool does not weaken or loosen the console's
      fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify({ ...C.defaultChecksFile(), tools: { pay: { strict: true, fail: fail === "open" ? "closed" : "open" } } }));
      ctx.service.noRuling = true;
      const ran: number[] = [];
      const pay = payTool(ran);
      const quiet = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      try {
        if (fail === "closed") {
          const e = await stderr(() => caught(pay({ amount: 1 })));
          expect(e[0].code).toBe("no_ruling");
          expect(ran).toEqual([]);
          expect(records().at(-1)!.envelope.checks).toEqual({ ran: false, ruling: "none", results: [], result: "allow" });
        } else {
          expect((await stderr(() => pay({ amount: 1 })))[0]).toBe("paid");
          expect(records().at(-1)!.envelope.checks!.ruling).toBe("none");
        }
      } finally {
        quiet.mockRestore();
      }
      expect(records().at(-2)!.envelope.checks!.fail).toBe(fail);
      expect((records().at(-2)!.content as any).meta.protected_by).toEqual(["checks_file", "console"]);
    });
  }

  it("a 1.1 document without protect changes nothing", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [PAY_LIMIT]);
    await ctx.rec.checks.pullRules();
    const doc = ctx.rec.checks.heldRules()!;
    expect("protect" in doc).toBe(false);
    fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify(C.defaultChecksFile()));
    const pay = payTool();
    expect(await pay({ amount: 5 })).toBe("paid");
    const d = records().at(-2)!;
    expect(d.envelope.checks!.strict).toBe(false);
    expect(d.envelope.checks!.fail).toBeNull();
    expect("protected_by" in (d.content as any).meta).toBe(false);
    // an empty protect map is not the same document: it is refused (left out when none)
    expect(C.ruleSetErrors({ ...doc, protect: {} })).toContain("protect");
  });

  it("field rules still need pull: the console approves no field; rate rules apply at once", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [PAY_LIMIT, PAY_RATE], { protect: { pay: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const ran: number[] = [];
    const pay = payTool(ran);
    const e = await stderr(() => caught(pay({ amount: 5 })));
    expect(e[0].code).toBe("blocked");
    expect(e[0].missing).toEqual(["/amount"]);
    expect(records().at(-2)!.envelope.checks!.disclosed).toEqual([]);
    expect(ran).toEqual([]);
    const [lines] = ctx.rec.checks.status();
    expect(lines.join("\n")).toContain("protected tool pay: rule set version 1 needs /amount: run `signafaide pull` to approve sending /amount");
    expect(lines.join("\n")).toContain("protected from the console (rule set version 1)");
    // pull asks, and approving the field writes protect: true beside it (a 1.1 client still reads the file)
    const out: string[] = [];
    const code = await runPull(ctx.rec, scriptedPrompter([true]), (s) => out.push(s));
    expect(code).toBe(0);
    expect(out.join("\n")).toContain("pay was protected from the console only; signafaide.checks.json now protects it too");
    const file = JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8"));
    expect(file.tools.pay).toEqual({ protect: true, disclose: ["/amount"] });
    expect(C.checksFileErrors(file)).toBeNull();
    ctx.rec.checks.forget();
    expect(await pay({ amount: 5 })).toBe("paid");
    const d = records().at(-2)!;
    expect(d.envelope.checks!.disclosed).toEqual(["/amount"]);
    expect((d.content as any).meta.protected_by).toEqual(["checks_file", "console"]);
  });

  it("status, checks status and prove say where protection comes from", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [PAY_RATE], { protect: { pay: { fail: "open" }, ghost: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const pay = payTool();
    await stderr(() => pay({ amount: 5 }));
    await ctx.rec.flush();
    const [lines] = ctx.rec.checks.status();
    const text = lines.join("\n");
    expect(text).toContain("protected tool pay: if signafAIde can't be reached: Let it run, local checks On; discloses no field; protected from the console (rule set version 1)");
    expect(text).toContain("protected tool ghost: protected from the console (rule set version 1), but no record or declaration of this program names it yet");
    const rows = toolLines(ctx.rec, () => "intact");
    expect(rows.find((r) => r.tool === "pay")!.protected).toBe("1 of 1 rule On, from the console (rule set version 1)");
    expect(rows.find((r) => r.tool === "ghost")!.protected).toBe("Off: protected from the console (rule set version 1), but not wrapped, so signafAIde never sees its calls");
    const [, prove] = await cli("prove", "pay");
    expect(prove).toContain("Protected  pay from the console (rule set version 1)");
    const [, checks] = await cli("checks", "status");
    expect(checks).toContain("protected from the console (rule set version 1)");
  });

  it("a plain synchronous function the console protects fails with state, naming the fix", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { protect: { lookup: { fail: "closed" } } });
    await ctx.rec.checks.pullRules();
    const lookup = record((id: string) => id, { name: "lookup" });
    let err: CheckError | null = null;
    await stderr(async () => {
      try {
        lookup("x");
      } catch (e) {
        err = e as CheckError;
      }
    });
    expect(err!.code).toBe("state");
    expect(err!.message).toContain("the console protects it (rule set version 1)");
    expect(err!.message).toContain("Make the function async");
  });

  it("at start: a fresh process waits for its first fetch, so the first call is protected", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { protect: { pay: { fail: "closed" } } });
    // a fresh recorder that holds no version yet (a new container)
    fs.rmSync(path.join(ctx.rec.state.home, "checks"), { recursive: true, force: true });
    ctx.rec.close();
    configure({ quiet: true, flushIntervalMs: 3_600_000 });
    const pay = payTool();
    await stderr(() => pay({ amount: 3 }));
    const d = records().at(-2)!;
    expect(d.envelope.checks!.strict).toBe(true);
    expect((d.content as any).meta.protected_by).toEqual(["console"]);
  });

  it("checks off: nothing is protected from the console, and the rule set is not fetched", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { protect: { pay: { fail: "closed" } } });
    process.env.SIGNAFAIDE_CHECKS = "0";
    try {
      ctx.rec.close();
      configure({ quiet: true, flushIntervalMs: 3_600_000 });
      const fetches = ctx.service.rulesFetches.length;
      const pay = payTool();
      expect(await pay({ amount: 3 })).toBe("paid");
      expect("checks" in records().at(-2)!.envelope).toBe(false);
      expect(ctx.service.rulesFetches.length).toBe(fetches);
    } finally {
      delete process.env.SIGNAFAIDE_CHECKS;
    }
  });
});

