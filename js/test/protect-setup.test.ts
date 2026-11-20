/**
 * Protected calls always ask
 * the witness, retries within the ruling window and plain quota words, `protect` writing code for
 * exported functions and one-object tools with a diff first, framework tool discovery, one agent
 * name in every call written, `prove` within the plan's limits with the agent keys, and the words
 * of a partial setup.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main, setPrompter } from "../src/cli.js";
import { SignafaideBlocked } from "../src/checks-runtime.js";
import { codeChanges, findTools, flagPrompter, scriptedPrompter, type Prompter } from "../src/protect.js";
import { protect } from "../src/record.js";
import { getRecorder } from "../src/runtime.js";
import { useProject } from "./helpers.js";

const ctx = useProject();

let xdg: string;
beforeEach(() => {
  xdg = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-xdg-"));
  process.env.XDG_CONFIG_HOME = xdg;
  fs.mkdirSync(path.join(ctx.root, "src"), { recursive: true });
  fs.writeFileSync(
    path.join(ctx.root, "package.json"),
    JSON.stringify({ name: "payout-bot", version: "1.0.0" }, null, 2),
  );
});
afterEach(() => {
  setPrompter(null);
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.SIGNAFAIDE_API_KEY;
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

/** The four tools of the quickstart as plain exported functions, the shape a typical project has. */
const POSITIONAL = `import { payments } from "./payments";

// Pays a supplier. Docs: https://example.test/payouts // not a comment to cut
export async function approve_payout(payee: string, amount: number, currency: string) {
  const memo = "a // inside a string, and a } brace";
  return payments.payout({ payee, amount, currency, memo });
}
export async function delete_payee(payeeId: string) {
  return \`deleted \${payeeId} {}\`;
}
export async function send_receipt(to: string, body: string) {
  return to + body;
}
export async function lookup_invoice(id: string) {
  return id;
}
`;

const OBJECT = POSITIONAL.replace(
  "approve_payout(payee: string, amount: number, currency: string)",
  "approve_payout({ payee, amount, currency }: { payee: string; amount: number; currency: string })",
);

/** Ticks approve_payout, block above 1000, On, also calibrate the currency, a sandbox, write. */
const ANSWERS_OBJECT = (): (string | number | boolean | boolean[])[] => [
  [true, false, false, false],
  0,
  "1000",
  0,
  [true, false],
  true,
  true,
];
const ANSWERS_POSITIONAL = (): (string | number | boolean | boolean[])[] => [
  [true, false, false, false],
  true,
  0,
  "1000",
  0,
  [true, false],
  true,
  true,
];

/** A prompter that answers like `scriptedPrompter` and keeps every question's choices. */
function recordingPrompter(
  answers: (string | number | boolean | boolean[])[],
): Prompter & { choices: Map<string, string[]> } {
  const inner = scriptedPrompter(answers);
  const choices = new Map<string, string[]>();
  return {
    person: true,
    choices,
    confirm: (q, d) => inner.confirm(q, d),
    text: (q, d) => inner.text(q, d),
    choose: (q, c, d) => (choices.set(q, c), inner.choose(q, c, d)),
    multi: (q, c, d) => (choices.set(q, c), inner.multi(q, c, d)),
  };
}

describe("protect writes the code, one-object tools get the full menu, one agent name", () => {
  it("exported functions with separate arguments: a diff first, then protect(...) in place, comments and strings kept", async () => {
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), POSITIONAL);
    setPrompter(() => scriptedPrompter(ANSWERS_POSITIONAL()));
    const [code, text] = await cli("protect");
    expect(code, text).toBe(0);
    expect(text).not.toContain("could not write");
    // The diff comes before the question.
    expect(text).toContain("Change     src/tools.ts");
    expect(text).toContain(
      "  +export const approve_payout = protect(async function approve_payout(payee: string, amount: number, currency: string) {",
    );
    expect(text).toContain(
      "  -export async function approve_payout(payee: string, amount: number, currency: string) {",
    );
    const src = fs.readFileSync(path.join(ctx.root, "src", "tools.ts"), "utf8");
    expect(src).toContain("// Pays a supplier. Docs: https://example.test/payouts // not a comment to cut");
    expect(src).toContain('const memo = "a // inside a string, and a } brace";');
    expect(src).toContain('}, { args: ["payee", "amount", "currency"], agent: "payout-bot" });');
    expect(src).toContain("export const delete_payee = record(async function delete_payee(payeeId: string) {");
    expect(src).toContain('}, { args: ["payeeId"], agent: "payout-bot" });');
    expect(src).toContain(
      'declareTools(["approve_payout", "delete_payee", "send_receipt", "lookup_invoice"], { agent: "payout-bot" });',
    );
    expect(
      src.startsWith(
        'import { payments } from "./payments";\nimport { protect, record, declareTools } from "signafaide";',
      ),
    ).toBe(true);
    expect(text).toContain("Changed    src/tools.ts");
    // Run again: nothing to change.
    expect(codeChanges(findTools(ctx.root), new Set(["approve_payout"]), "payout-bot", ctx.root)).toEqual([]);
  }, 60_000);

  it("one object argument: the amount and currency fields from the destructuring pattern, the full menu, the rule on /amount", async () => {
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), OBJECT);
    const p = recordingPrompter(ANSWERS_OBJECT());
    setPrompter(() => p);
    const [code, text] = await cli("protect");
    expect(code, text).toBe(0);
    expect(p.choices.get("What should we block on approve_payout?")).toEqual([
      "Payouts above an amount",
      "Payouts in other currencies",
      "More than a number of calls a minute",
      "Nothing yet, record only",
    ]);
    expect(text).toContain(
      "Sends to signafAIde when approve_payout runs: amount, currency (the fields your 2 rules need)",
    );
    expect(text).toContain("Never sent to signafAIde: payee.");
    const src = fs.readFileSync(path.join(ctx.root, "src", "tools.ts"), "utf8");
    expect(src).toContain(
      "export const approve_payout = protect(async function approve_payout({ payee, amount, currency }: { payee: string; amount: number; currency: string }) {",
    );
    expect(src).toContain('}, { agent: "payout-bot" });');
    const rs = getRecorder().checks.heldRules()!;
    expect(rs.rules[0]).toMatchObject({
      id: "approve_payout-amount",
      when: [{ field: "/amount", op: "gt", value: 1000 }],
      state: "on",
    });
    expect(rs.rules[1]).toMatchObject({
      id: "approve_payout-currency",
      when: [{ field: "/currency", op: "ne", value: "GBP" }],
    });
  }, 60_000);

  it("fields from a named TS type, JSDoc, or asked when the code does not show them", () => {
    fs.writeFileSync(
      path.join(ctx.root, "src", "tools.ts"),
      `interface Payout { payee: string; amount: number; currency: string }
export async function approve_payout(p: Payout) { return p; }
/**
 * @param {object} req
 * @param {number} req.amount
 * @param {string} req.currency
 */
export async function refund(req) { return req; }
export async function charge(input: Charge) { return input; }
`,
    );
    const f = findTools(ctx.root);
    const by = new Map(f.tools.map((t) => [t.name, t]));
    expect(by.get("approve_payout")!.fields.map((x) => x.pointer)).toEqual(["/payee", "/amount", "/currency"]);
    expect(by.get("refund")!.fields.map((x) => x.pointer)).toEqual(["/amount", "/currency"]);
    // A type protect cannot see: one object, fields unknown, asked at the terminal.
    expect(by.get("charge")).toMatchObject({ objectParam: true, fields: [] });
  });

  it("an object whose fields are not in the code: the person names them", async () => {
    fs.writeFileSync(
      path.join(ctx.root, "src", "tools.ts"),
      `import type { Charge } from "./types";\nexport async function charge(input: Charge) { return input; }\n`,
    );
    const p = recordingPrompter([[true], "amount, currency", 0, "500", 1, [false, false], true, true]);
    setPrompter(() => p);
    const [code, text] = await cli("protect");
    expect(code, text).toBe(0);
    expect(p.choices.get("What should we block on charge?")?.[0]).toBe("Payouts above an amount");
    expect(getRecorder().checks.heldRules()!.rules[0]).toMatchObject({
      when: [{ field: "/amount", op: "gt", value: 500 }],
      state: "calibrating",
    });
  }, 60_000);

  it("options already written are kept, and the agent the code names is the one used everywhere", async () => {
    fs.writeFileSync(
      path.join(ctx.root, "src", "tools.ts"),
      `import { record } from "signafaide";
async function approve_payout(payee: string, amount: number, currency: string) { return amount; }
async function lookup_invoice(id: string) { return id; } // "id" // stays
export const tools = {
  approve_payout: record(approve_payout, { agent: "billing-agent", storeContent: true }),
  // a comment inside the object stays
  lookup_invoice,
  note: "http://example.test/a//b",
};
`,
    );
    fs.writeFileSync(
      path.join(ctx.root, "src", "main.ts"),
      `import { declareTools } from "signafaide";\nimport { tools } from "./tools";\ndeclareTools(Object.keys(tools));\n`,
    );
    const f = findTools(ctx.root);
    const changes = codeChanges(f, new Set(["approve_payout"]), "billing-agent", ctx.root);
    const tools = changes.find((c) => c.file.endsWith("tools.ts"))!.after;
    expect(tools).toContain(
      'approve_payout: protect(approve_payout, { agent: "billing-agent", storeContent: true, args: ["payee", "amount", "currency"] }),',
    );
    expect(tools).toContain("  // a comment inside the object stays");
    expect(tools).toContain('lookup_invoice: record(lookup_invoice, { args: ["id"], agent: "billing-agent" }),');
    expect(tools).toContain('note: "http://example.test/a//b",');
    expect(tools).toContain('import { record, protect } from "signafaide";');
    expect(tools).not.toContain("declareTools(");
    // The declaration already written in main.ts gets the agent, so one project is one agent.
    expect(changes.find((c) => c.file.endsWith("main.ts"))!.after).toContain(
      'declareTools(Object.keys(tools), { agent: "billing-agent" });',
    );
    // protect uses the name the code already gives.
    setPrompter(() => scriptedPrompter([[true, false], 3, true, true, true]));
    const [, text] = await cli("protect");
    expect(text).toContain("Agent      billing-agent (the name the code already uses)");
  }, 60_000);
});

describe("tool discovery", () => {
  it("Vercel AI SDK, OpenAI Agents, LangChain, MCP servers and tool classes; unknown tools are not classified, and every tool is in the question", async () => {
    fs.writeFileSync(
      path.join(ctx.root, "src", "agent.ts"),
      `import { tool } from "ai";
import { z } from "zod";
export const tools = {
  approve_payout: tool({ description: "Pay", inputSchema: z.object({ payee: z.string(), amount: z.number(), currency: z.string() }), execute: async ({ payee, amount, currency }) => payee }),
  execute_sql: tool({ description: "SQL", inputSchema: z.object({ query: z.string() }), execute: async ({ query }) => query }),
  frobnicate: tool({ description: "?", inputSchema: z.object({ x: z.number() }), execute: async ({ x }) => x }),
};
`,
    );
    fs.writeFileSync(
      path.join(ctx.root, "src", "oa.ts"),
      `import { tool } from "@openai/agents";\nimport { z } from "zod";\nconst T = z.object({ to: z.string(), amount: z.number() });\nexport const t = tool({ name: "transfer", description: "m", parameters: T, execute: async (input) => input });\n`,
    );
    fs.writeFileSync(
      path.join(ctx.root, "src", "lc.ts"),
      `import { tool, DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";
export const u = tool(async ({ id }) => id, { name: "update_account", schema: z.object({ id: z.string() }) });
export const r = new DynamicStructuredTool({ name: "run_command", description: "x", schema: z.object({ cmd: z.string() }), func: async ({ cmd }) => cmd });
`,
    );
    fs.writeFileSync(
      path.join(ctx.root, "src", "server.ts"),
      `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1" });
server.tool("write_file", { path: z.string(), text: z.string() }, async ({ path }) => ({ content: [] }));
server.registerTool("charge", { inputSchema: { amount: z.number() } }, async ({ amount }) => ({ content: [] }));
`,
    );
    fs.writeFileSync(
      path.join(ctx.root, "src", "billing.ts"),
      `export class BillingTools {\n  async refundOrder(orderId: string, amount: number) { return orderId; }\n  getBalance(account: string) { return 1; }\n}\n`,
    );
    const f = findTools(ctx.root);
    const got = Object.fromEntries(
      f.tools.map((t) => [t.name, [t.kind, t.shape, t.framework ?? null, t.fields.map((x) => x.name).join(",")]]),
    );
    expect(got).toEqual({
      approve_payout: ["pays", "framework", "Vercel AI SDK", "payee,amount,currency"],
      execute_sql: ["runs", "framework", "Vercel AI SDK", "query"],
      frobnicate: ["other", "framework", "Vercel AI SDK", "x"],
      transfer: ["pays", "framework", "OpenAI Agents", "to,amount"],
      update_account: ["changes", "framework", "LangChain", "id"],
      run_command: ["runs", "framework", "LangChain", "cmd"],
      write_file: ["changes", "mcp", "MCP server", "path,text"],
      charge: ["pays", "mcp", "MCP server", "amount"],
      refundOrder: ["pays", "method", null, "orderId,amount"],
      getBalance: ["reads", "method", null, "account"],
    });
    const p = recordingPrompter([
      [true, false, false, false, false, false, false, false, false, false],
      3,
      true,
      true,
      true,
    ]);
    setPrompter(() => p);
    const [, text] = await cli("protect", "--local");
    expect(text).toMatch(/frobnicate\s+not classified\s+record/);
    expect(text).not.toMatch(/execute_sql\s+reads only/);
    const q = [...p.choices.keys()].find((k) => k.startsWith("Protect which tools?"))!;
    expect(q).toMatch(
      /^Protect which tools\? Suggested: .+\. Only \w+ is ticked; tick the others to protect them now \(each then asks its own short questions\), or leave them and run npx signafaide protect <tool> later\.$/,
    );
    expect(p.choices.get(q)).toHaveLength(10);
    expect(p.choices.get(q)).toContain("frobnicate (not classified)");
    const agent = fs.readFileSync(path.join(ctx.root, "src", "agent.ts"), "utf8");
    expect(agent).toContain('approve_payout: wrapTool(tool({ description: "Pay"');
    expect(agent).toContain('{ name: "approve_payout", agent: "payout-bot" })');
    expect(text).toContain("npx signafaide gateway --agent payout-bot -- <the command that starts your server>");
    expect(text).toContain("refundOrder: wrap it where the class's tools are handed to the agent");
  }, 60_000);
});

describe("protected calls always ask the witness and retry within the ruling window", () => {
  async function protectedPayout(): Promise<{
    fn: (p: string, a: number, c: string) => Promise<string>;
    ran: number[];
  }> {
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), POSITIONAL);
    setPrompter(() => scriptedPrompter(ANSWERS_POSITIONAL()));
    expect((await cli("protect"))[0]).toBe(0);
    const ran: number[] = [];
    const fn = protect(
      async function approve_payout(payee: string, amount: number, currency: string) {
        ran.push(amount);
        return `paid ${amount} ${currency} to ${payee}`;
      },
      { args: ["payee", "amount", "currency"], agent: "payout-bot" },
    );
    return { fn, ran };
  }

  it("the limit raised after the version held here: the witness allows the call the held version would block", async () => {
    const { fn, ran } = await protectedPayout();
    const v1 = getRecorder().checks.heldRules()!;
    expect(v1.version).toBe(1);
    // An admin raises the limit to 2,000 (version 2); this machine still holds version 1.
    ctx.service.publishRules(
      getRecorder().apiKey!,
      v1.rules.map((r: any) =>
        r.id === "approve_payout-amount" ? { ...r, when: [{ field: "/amount", op: "gt", value: 2000 }] } : r,
      ),
      { set: v1.set },
    );
    expect(getRecorder().checks.heldRules()!.version).toBe(1);
    await expect(fn("Harbour Lane Supplies Ltd", 1200, "GBP")).resolves.toBe(
      "paid 1200 GBP to Harbour Lane Supplies Ltd",
    );
    expect(ran).toEqual([1200]);
    const dec = getRecorder()
      .state.readAll(
        getRecorder()
          .state.chains()
          .find((c) => c.endsWith("/payout-bot"))!,
      )
      .filter((r) => r.envelope.kind === "decision")
      .at(-1)! as any;
    expect(dec.receipt.ruling).toMatchObject({ ruling: "allow", rules: { version: 2 } });
  }, 60_000);

  it("local checks still block here, worded as before, and ask no ruling", async () => {
    const { fn, ran } = await protectedPayout();
    const secret = "AKIA" + "IOSFODNN7" + "EXAMPLE";
    const e = (await fn(`pay ${secret}`, 10, "GBP").catch((x: unknown) => x)) as SignafaideBlocked;
    expect(e).toBeInstanceOf(SignafaideBlocked);
    expect(e).toMatchObject({ check: "secret", ruledBy: "client" });
    expect(e.message).toMatch(/^approve_payout did not run: its arguments hold a secret/);
    expect(ran).toEqual([]);
  }, 60_000);

  it("the witness cannot be reached: the held rules still block what they block; else the tool's setting (Let it run here)", async () => {
    const { fn, ran } = await protectedPayout();
    const v1 = getRecorder().checks.heldRules()!;
    ctx.service.publishRules(getRecorder().apiKey!, v1.rules, { set: v1.set, fail: { approve_payout: "open" } });
    await getRecorder().checks.pullRules();
    const file = path.join(ctx.root, "signafaide.checks.json");
    fs.writeFileSync(
      file,
      JSON.stringify({ ...JSON.parse(fs.readFileSync(file, "utf8")), ruling_timeout_ms: 1200 }, null, 2),
    );
    getRecorder().checks.forget();
    ctx.service.failAlways = [503, { error: { code: "unavailable", message: "restarting" } }];
    const e = (await fn("x", 5000, "GBP").catch((x: unknown) => x)) as SignafaideBlocked;
    expect(e).toBeInstanceOf(SignafaideBlocked);
    expect(
      e.message.startsWith(
        'approve_payout did not run: signafAIde did not rule on it, and the signed rule set version 2 held here blocks it ("Block approve_payout when amount is above 1,000"). To allow such calls, change the rule in the console.',
      ),
    ).toBe(true);
    await expect(fn("x", 10, "GBP")).resolves.toBe("paid 10 GBP to x");
    expect(ran).toEqual([10]);
  }, 60_000);

  it("a short restart of the witness: the call retries within the ruling window and runs", async () => {
    const { fn, ran } = await protectedPayout();
    ctx.service.fail = [503, { error: { code: "unavailable", message: "restarting" } }];
    await expect(fn("x", 10, "GBP")).resolves.toBe("paid 10 GBP to x");
    expect(ran).toEqual([10]);
    expect(ctx.service.calls.filter((c) => c === "POST /v1/records").length).toBeGreaterThanOrEqual(2);
  }, 60_000);

  it("the allowance used up: the error says so plainly, with the fix, at once", async () => {
    const { fn } = await protectedPayout();
    ctx.service.quota = 0;
    const t0 = Date.now();
    const e = (await fn("x", 10, "GBP").catch((x: unknown) => x)) as SignafaideBlocked;
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(e.code).toBe("quota_exceeded");
    expect(e.message).toMatch(
      /^approve_payout did not run: signafAIde could not rule on it: the sandbox's records for this month are used up \(quota_exceeded\)\. Keep the sandbox and choose a plan at http/,
    );
    expect(e.message).not.toContain("no receipt came within");
  }, 60_000);
});

describe("prove", () => {
  async function ready(): Promise<void> {
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), POSITIONAL);
    setPrompter(() => scriptedPrompter(ANSWERS_POSITIONAL()));
    expect((await cli("protect"))[0]).toBe(0);
    const fn = protect(
      async function approve_payout(_p: string, a: number, _c: string) {
        return a;
      },
      { args: ["payee", "amount", "currency"], agent: "payout-bot" },
    );
    await fn("x", 10, "GBP");
    await getRecorder().flush();
  }

  it("a 7-day plan: asks for 30, then the plan's longest; sends the agent keys and head; a second prove reuses the link; --days asks exactly", async () => {
    await ready();
    ctx.service.auditorMaxDays = 7;
    let [c, out] = await cli("prove", "approve_payout");
    expect(c, out).toBe(0);
    expect(out).toContain("Send this link to your auditor:");
    expect(out).toContain("They can check it in their browser; nothing to install.");
    expect(ctx.service.auditorLinks).toHaveLength(1);
    const body = ctx.service.auditorLinks[0];
    expect(body).toMatchObject({ agent: "payout-bot", tool: "approve_payout", days: 7 });
    expect(body.agent_keys.format).toBe("signafaide-agent-keys/1");
    expect(body.agent_keys.keys.map((k: any) => k.agent)).toEqual(["payout-bot"]);
    expect(Object.values(Object.values(body.head)[0] as any)[0]).toHaveProperty("payout-bot");
    [c, out] = await cli("prove", "approve_payout");
    expect(out).toContain("Send this link to your auditor (made earlier, still open):");
    expect(ctx.service.auditorLinks).toHaveLength(1);
    [c, out] = await cli("prove", "approve_payout", "--days", "3");
    expect(c, out).toBe(0);
    expect(ctx.service.auditorLinks.at(-1).days).toBe(3);
    [c, out] = await cli("prove", "approve_payout", "--days", "20");
    expect(out).toContain("this plan's links last at most 7 days (npx signafaide prove --days 7)");
  }, 60_000);

  it("the limit only in the words of the refusal; a witness that does not take keys: the link, and how to give the keys", async () => {
    await ready();
    ctx.service.auditorMaxDays = 7;
    ctx.service.auditorMaxInBody = false;
    ctx.service.auditorLinksNoKeys = true;
    const [c, out] = await cli("prove", "approve_payout");
    expect(c, out).toBe(0);
    expect(ctx.service.auditorLinks.at(-1)).toMatchObject({ days: 7 });
    expect(ctx.service.auditorLinks.at(-1)).not.toHaveProperty("agent_keys");
    expect(out).toContain("npx signafaide keys export -o agent-keys.json");
  }, 60_000);
});

describe("a partial setup is never Done, and the .env line only when true", () => {
  it("without a person: what was and was not done, and the command to finish", async () => {
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), POSITIONAL);
    setPrompter(() => flagPrompter({ yes: true }));
    const [, out] = await cli("protect");
    expect(out).not.toMatch(/^Done\./m);
    expect(out).toContain(
      "Not finished. Done: checks file signafaide.checks.json, code in src/tools.ts, the note in AGENTS.md, the note in CLAUDE.md.",
    );
    expect(out).toContain("  - no sandbox and no API key, so protected tools stop until there is one");
    expect(out).toContain("To finish: npx signafaide protect (in a terminal)");
  });

  it("a key from the environment: no .env line; a key in .env that git does not ignore: said so", async () => {
    await getRecorder().createSandbox();
    const key = getRecorder().apiKey!;
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), POSITIONAL);
    fs.rmSync(path.join(ctx.root, ".env"));
    fs.writeFileSync(path.join(ctx.root, ".env"), "OTHER=1\n");
    process.env.SIGNAFAIDE_API_KEY = key;
    setPrompter(() => scriptedPrompter([[true, false, false, false], true, 3, true]));
    let [, out] = await cli("protect");
    expect(out).not.toContain("already in .gitignore");
    fs.writeFileSync(path.join(ctx.root, ".env"), `SIGNAFAIDE_API_KEY=${key}\n`);
    fs.writeFileSync(path.join(ctx.root, ".gitignore"), ".signafaide/\n");
    setPrompter(() => scriptedPrompter([[true, false, false, false], 3]));
    [, out] = await cli("protect");
    expect(out).toContain(".env is NOT in .gitignore");
  }, 60_000);
});
