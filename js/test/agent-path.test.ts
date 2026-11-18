/**
 * Issue #67 step 2: the path a coding agent takes. `protect --yes --tool <name> --limit-field <f>
 * --above <n>` asks nothing and adds a rule that starts Calibrating; `protect` and `init` add the
 * project note to AGENTS.md / CLAUDE.md after asking, never twice; a protected tool with no key or
 * sandbox stops with one sentence that names the one command and why.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { noteSection } from "../src/agents.js";
import * as C from "../src/checks.js";
import { SignafaideBlocked } from "../src/checks-runtime.js";
import { main, setPrompter } from "../src/cli.js";
import { CALIBRATING_LINE, flagPrompter, scriptedPrompter, toVersion2 } from "../src/protect.js";
import { protect } from "../src/record.js";
import { configure, getRecorder } from "../src/runtime.js";
import { useProject } from "./helpers.js";

const TOOLS_TS = `export async function approve_payout(payee: string, amount: number, currency: string) {
  return payee + amount + currency;
}
async function lookup_invoice(input: { id: string }) { return input.id; }

export const tools = { approve_payout, lookup_invoice };
`;

let xdg: string;
function project(): void {
  fs.mkdirSync(path.join(ctx.root, "src"), { recursive: true });
  fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), TOOLS_TS);
  fs.writeFileSync(path.join(ctx.root, "package.json"), JSON.stringify({ name: "payout-bot", version: "1.0.0" }, null, 2));
}
beforeEach(() => {
  xdg = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-xdg-"));
  process.env.XDG_CONFIG_HOME = xdg;
});
afterEach(() => {
  setPrompter(null);
  delete process.env.XDG_CONFIG_HOME;
  fs.rmSync(xdg, { recursive: true, force: true });
});

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

const read = (f: string): string => fs.readFileSync(path.join(ctx.root, f), "utf8");
const AGENT_RUN = ["protect", "--yes", "--tool", "approve_payout", "--limit-field", "amount", "--above", "1000"];

const ctx = useProject();

describe("protect --yes --tool --limit-field --above, with no key", () => {
  beforeEach(project);

  it("writes the code, the note and a Calibrating rule it cannot save yet, and says what a person does next", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli(...AGENT_RUN);
    expect(c, out).toBe(1); // not finished: the rule waits for a key
    expect(out).toContain("  Rule: Block approve_payout when amount is above 1,000");
    expect(out).toContain(CALIBRATING_LINE);
    expect(out).toContain("Rules      not saved yet: there is no key. It starts Calibrating once saved.");
    expect(out).toContain("To finish: npx signafaide protect (in a terminal)");
    expect(out).not.toContain("npx signafaide login");
    expect(read("src/tools.ts")).toContain("protect(approve_payout");
    expect(JSON.parse(read("signafaide.checks.json")).tools.approve_payout).toEqual({ protect: true, mode: "watch" }); // no field approved without a person; watch: the kept rule blocks nothing
    expect(read("AGENTS.md")).toBe(noteSection());
    expect(read("CLAUDE.md")).toBe("@AGENTS.md\n"); // Claude Code reads the same note
    expect(out).toMatch(/AGENTS\.md +signafAIde note for coding agents/);
    expect(ctx.service.calls).not.toContain("POST /v1/sandbox");
    // Run again: the note is there, so it is neither asked about nor written twice.
    const [, again] = await cli(...AGENT_RUN);
    expect(again).not.toContain("Agents     ");
    expect(read("AGENTS.md").split("<!-- signafaide:start -->")).toHaveLength(2);
  });

  it("adds the note to an existing CLAUDE.md and creates no AGENTS.md", async () => {
    fs.writeFileSync(path.join(ctx.root, "CLAUDE.md"), "# Project\n");
    setPrompter(() => flagPrompter({ yes: true }));
    await cli(...AGENT_RUN);
    expect(read("CLAUDE.md")).toBe("# Project\n\n" + noteSection());
    expect(fs.existsSync(path.join(ctx.root, "AGENTS.md"))).toBe(false);
  });

  it("keeps the agent's rule as a local Calibrating rule it does not save twice", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli(...AGENT_RUN);
    expect(c, out).toBe(1);
    expect(out).toContain("Kept in signafaide.checks.json as a local Calibrating rule (it blocks nothing)");
    const file = JSON.parse(read("signafaide.checks.json"));
    expect(file.tools.approve_payout).toEqual({ protect: true, mode: "watch" }); // watch: blocks nothing
    expect(file.rules.rules).toHaveLength(1);
    expect(file.rules.rules[0]).toMatchObject({ id: "approve_payout-amount", action: "block", tools: ["approve_payout"], when: [{ field: "/amount", op: "gt", value: 1000 }] });
    expect(file.proposed).toEqual([{ rule: "approve_payout-amount", by: "agent", on: new Date().toISOString().slice(0, 10) }]);
    expect(C.checksFileErrors(file)).toBeNull();
    // A second agent run does not add it twice.
    await cli(...AGENT_RUN);
    expect(JSON.parse(read("signafaide.checks.json")).rules.rules).toHaveLength(1);
    expect(JSON.parse(read("signafaide.checks.json")).proposed).toHaveLength(1);
  });

  it("says the kept rules in the plural when several are kept", async () => {
    fs.writeFileSync(
      path.join(ctx.root, "src", "tools.ts"),
      TOOLS_TS.replace("async function lookup_invoice", "export async function refund_payout(payee: string, amount: number) {\n  return payee + amount;\n}\nasync function lookup_invoice").replace("{ approve_payout,", "{ approve_payout, refund_payout,"),
    );
    setPrompter(() => flagPrompter({ yes: true }));
    const [, out] = await cli("protect", "--yes");
    expect(out).toContain("Kept in signafaide.checks.json as local Calibrating rules (they block nothing)");
    expect(out).toContain("is offered them.");
    expect(out).not.toContain("a local Calibrating rule");
  });

  it("accepting the proposal uses the agent's value, says where it came from and uses the proposal up", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    await cli(...AGENT_RUN);
    const p = scriptedPrompter([true, 1, false, true, true], true);
    setPrompter(() => p);
    const [, out] = await cli("protect", "--tool", "approve_payout");
    expect(p.asked.some((q) => q.includes("proposed this rule"))).toBe(true);
    expect(p.asked.some((q) => q.startsWith("What should we block on"))).toBe(false);
    expect(out).toMatch(/Rule: Block approve_payout when amount is above 1,000 +\(proposed by an agent run on \d{4}-\d{2}-\d{2}\)/);
    const file = JSON.parse(read("signafaide.checks.json"));
    expect(file.proposed).toBeUndefined();
    expect(file.rules).toBeNull();
    expect(file.tools.approve_payout.mode).toBeUndefined();
  });

  it("saying no to the proposal drops it and asks as usual", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    await cli(...AGENT_RUN);
    const p = scriptedPrompter([false, 0, "500", 1, [false, false], false, true], true);
    setPrompter(() => p);
    const [, out] = await cli("protect", "--tool", "approve_payout");
    expect(out).toContain("is dropped; asking as usual");
    expect(p.asked.some((q) => q.startsWith("What should we block on"))).toBe(true);
    expect(JSON.parse(read("signafaide.checks.json")).proposed).toBeUndefined();
  });

  it("a checks file with a proposal for a rule that is not there is an error", () => {
    const file = JSON.parse(JSON.stringify(toVersion2(null)));
    file.proposed = [{ rule: "nope", by: "agent", on: "2026-11-18" }];
    expect(C.checksFileErrors(file)).toContain("proposed[0].rule must be the id of a rule in rules");
  });

  it("with no CLAUDE.md, a note in AGENTS.md gives CLAUDE.md just the import; a CLAUDE.md that exists gets the block once; one that imports AGENTS.md is left alone", async () => {
    fs.writeFileSync(path.join(ctx.root, "AGENTS.md"), "# Team\n\n" + noteSection());
    fs.writeFileSync(path.join(ctx.root, "CLAUDE.md"), "# Project\n");
    setPrompter(() => flagPrompter({ yes: true }));
    await cli(...AGENT_RUN);
    expect(read("CLAUDE.md")).toBe("# Project\n\n" + noteSection());
    await cli(...AGENT_RUN);
    expect(read("CLAUDE.md").split("<!-- signafaide:start -->")).toHaveLength(2);
    fs.writeFileSync(path.join(ctx.root, "CLAUDE.md"), "# Project\n\n@AGENTS.md\n");
    await cli(...AGENT_RUN);
    expect(read("CLAUDE.md")).toBe("# Project\n\n@AGENTS.md\n");
  });

  it("a person who says no to the note: nothing added", async () => {
    // tick approve_payout, named arguments yes, On, sandbox no, write the code yes, note no
    setPrompter(() => scriptedPrompter([true, 0, false, true, false]));
    const [, out] = await cli("protect", "--tool", "approve_payout", "--limit-field", "amount", "--above", "500");
    expect(out).toContain("Not added; run this command again to add it.");
    expect(fs.existsSync(path.join(ctx.root, "AGENTS.md"))).toBe(false);
    expect(out).toContain("Rules      not saved yet: there is no key.");
    expect(out).not.toContain("It starts Calibrating once saved"); // the person chose On
  });

  it("names a field the tool does not have, and adds no rule", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "--yes", "--tool", "approve_payout", "--limit-field", "total", "--above", "5");
    expect(c, out).toBe(0);
    expect(out).toContain("approve_payout has no field named total (its fields: payee, amount, currency): no rule added.");
    expect(out).toContain("approve_payout has no field named total, so no rule was added");
  });

  it("refuses options that do not go together", async () => {
    for (const args of [
      ["--limit-field", "amount"],
      ["--above", "5", "--tool", "approve_payout"],
      ["--limit-field", "amount", "--above", "1000"], // no tool
      ["--tool", "approve_payout", "--limit-field", "amount", "--above", "-3"],
      ["--tool", "approve_payout", "--limit-field", "amount", "--above", "lots"],
      ["lookup_invoice", "--tool", "approve_payout"],
    ]) {
      const [c, out] = await cli("protect", "--yes", ...args);
      expect(c, args.join(" ")).toBe(2);
      expect(out).toMatch(/^signafaide protect: /);
    }
    expect(fs.existsSync(path.join(ctx.root, "signafaide.checks.json"))).toBe(false);
  });
});

describe("protect --yes --limit-field, with an unclaimed sandbox", () => {
  beforeEach(project);

  it("saves the rule Calibrating; only a person turns it On", async () => {
    await ctx.rec.createSandbox();
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli(...AGENT_RUN);
    expect(c, out).toBe(0);
    expect(out).toContain("Rules      saved in your sandbox as version 1");
    expect(out).toContain(CALIBRATING_LINE);
    const held = getRecorder().checks.heldRules()!;
    const rule = held.rules.find((r: any) => r.id === "approve_payout-amount");
    expect(rule.when).toEqual([{ field: "/amount", op: "gt", value: 1000 }]);
    expect(C.ruleState(held, rule)).toBe("calibrating");
  });
});

describe("init adds the note", () => {
  it("without a terminal, once", async () => {
    setPrompter(() => flagPrompter());
    let [c, out] = await cli("init");
    expect(c, out).toBe(0);
    expect(out).toContain("agents: AGENTS.md created, with the signafAIde note for coding agents (a marked block)");
    expect(read("AGENTS.md")).toBe(noteSection());
    [c, out] = await cli("init");
    expect(out).not.toContain("agents: ");
  });
});

describe("a protected tool with no key or sandbox", () => {
  it("stops, naming the one command and why, in one sentence", async () => {
    fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify(toVersion2(null)));
    getRecorder().checks.forget();
    const quiet = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    let ran = 0;
    const pay = protect(async function approve_payout(_amount: number) {
      ran++;
    }, { args: ["amount"] });
    const e = (await pay(5).catch((x: unknown) => x)) as SignafaideBlocked;
    quiet.mockRestore();
    expect(ran).toBe(0);
    expect(e).toBeInstanceOf(SignafaideBlocked);
    expect(e.code).toBe("no_key");
    expect(e.message).toBe(
      "approve_payout did not run: protected tools stop until a person runs `npx signafaide protect` in this project, because there is no signafAIde key or sandbox here yet to allow the call.",
    );
    expect(e.message.match(/\. /g)).toBeNull(); // one sentence
  });

  it("in a test runner it still runs, as test mode does", async () => {
    process.env.SIGNAFAIDE_TEST = "1";
    try {
      const rec = configure({ quiet: true, flushIntervalMs: 3_600_000 });
      const pay = protect(async function approve_payout(amount: number) {
        return `paid ${amount}`;
      }, { args: ["amount"] });
      expect(await pay(5)).toBe("paid 5");
      rec.close();
    } finally {
      process.env.SIGNAFAIDE_TEST = "0";
    }
  });
});
