/**
 * Spec 1.1, the Record / Protect / Prove flow from the command line: `protect` finds the tools,
 * asks what to block, rewrites the code, makes the sandbox and saves the rules; the protected tool
 * is then ruled by the witness; `check`, `status`, `pull`, `prove`, `start-fresh`, `login` and
 * `logout` say and do what the mockup shows. Every question is answered by a scripted person.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main, setPrompter } from "../src/cli.js";
import { CheckError, SignafaideBlocked } from "../src/checks-runtime.js";
import { verify } from "../src/index.js";
import { addImport, codeChanges, findTools, flagPrompter, nextDraft, scriptedPrompter, toVersion2, toolKind } from "../src/protect.js";
import { declareTools, protect, record } from "../src/record.js";
import { recordHash } from "../src/records.js";
import { getRecorder } from "../src/runtime.js";
import { loadSession, login, logout, sessionFile } from "../src/session.js";
import { parseFieldArgs } from "../src/tool-commands.js";
import { useProject } from "./helpers.js";

const ctx = useProject();

const TOOLS_TS = `import { payments } from "./payments";

export async function approve_payout(payee: string, amount: number, currency: string) {
  return payments.payout({ payee, amount, currency });
}
async function delete_payee(payeeId: string) { return payeeId; }
async function send_receipt(to: string, body: string) { return to + body; }
async function lookup_invoice(input: { id: string }) { return input.id; }

export const tools = {
  approve_payout,
  delete_payee,
  send_receipt,
  lookup_invoice,
};
`;

let xdg: string;
beforeEach(() => {
  xdg = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-xdg-"));
  process.env.XDG_CONFIG_HOME = xdg;
  fs.mkdirSync(path.join(ctx.root, "src"), { recursive: true });
  fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), TOOLS_TS);
  fs.writeFileSync(path.join(ctx.root, "package.json"), JSON.stringify({ name: "payout-bot", version: "1.0.0" }, null, 2));
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

/** The answers of the mockup's terminal session: approve_payout only, named arguments, block
 * above 1000, On, also calibrate currency not GBP, a sandbox, write the code. */
const MOCKUP_ANSWERS = (): (string | number | boolean | boolean[])[] => [[true, false, false, false], true, 0, "1000", 0, [true, false], true, true];

/** The protected tool as `protect` writes it, run in this process. */
function payout() {
  const ran: number[] = [];
  const fn = protect(
    async function approve_payout(payee: string, amount: number, currency: string) {
      ran.push(amount);
      return `paid ${amount} ${currency} to ${payee}`;
    },
    { args: ["payee", "amount", "currency"], agent: "payout-bot" },
  );
  return { ran, fn };
}

describe("finding tools and writing the code", () => {
  it("finds the tools object, its functions' arguments, and what each tool does", () => {
    const f = findTools(ctx.root);
    expect(f.object?.name).toBe("tools");
    expect(f.tools.map((t) => [t.name, t.kind, t.params, t.objectParam, t.fields.map((x) => x.pointer)])).toEqual([
      ["approve_payout", "pays", ["payee", "amount", "currency"], false, ["/payee", "/amount", "/currency"]],
      ["delete_payee", "deletes", ["payeeId"], false, ["/payeeId"]],
      ["send_receipt", "sends", ["to", "body"], false, ["/to", "/body"]],
      ["lookup_invoice", "reads", [], true, ["/id"]],
    ]);
    expect(toolKind("refundOrder")).toBe("pays");
    expect(toolKind("getWeather")).toBe("reads");
    expect(toolKind("frobnicate")).toBe("other");
  });

  it("rewrites the tools object: protect for the chosen tools, record for the others, the names of positional arguments, the agent, the import and the declaration", () => {
    const f = findTools(ctx.root);
    const [ch] = codeChanges(f, new Set(["approve_payout"]), "payout-bot", ctx.root);
    const out = ch.after;
    expect(out).toContain('import { protect, record, declareTools } from "signafaide";');
    expect(out).toContain('approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }),');
    expect(out).toContain('delete_payee: record(delete_payee, { args: ["payeeId"], agent: "payout-bot" }),');
    expect(out).toContain('lookup_invoice: record(lookup_invoice, { agent: "payout-bot" }),');
    expect(out).toContain('declareTools(Object.keys(tools), { agent: "payout-bot" });');
    // Rewriting again changes nothing: it is read back as wrapped.
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), out);
    const again = findTools(ctx.root);
    expect(again.tools.find((t) => t.name === "approve_payout")?.wrapped).toBe("protect");
    expect(codeChanges(again, new Set(["approve_payout"]), "payout-bot", ctx.root)).toEqual([]);
    expect(addImport('import { record } from "signafaide";\nx', ["protect"])).toBe('import { record, protect } from "signafaide";\nx');
  });

  it("protect --tool: one tool is written, and the declaration lists every tool, also without a tools object", () => {
    fs.writeFileSync(path.join(ctx.root, "src", "tools.ts"), "export async function approve_payout(payee: string, amount: number) {\n  return payee + amount;\n}\n\nexport async function send_receipt(to: string) {\n  return to;\n}\n");
    const [ch] = codeChanges(findTools(ctx.root, "approve_payout"), new Set(["approve_payout"]), "payout-bot", ctx.root, findTools(ctx.root));
    expect(ch.after).toContain('declareTools(["approve_payout", "send_receipt"], { agent: "payout-bot" });');
    expect(ch.after).not.toContain("record(");
  });

  it("a version 1 checks file becomes version 2 with the same meaning per listed tool", () => {
    const v1 = { format: "signafaide-checks/1", mode: "enforce", checks: { secret: true, address: true, changed_tool: true, fingerprint: true, hidden_instruction: true }, tools: { pay: { strict: true, fail: "open", disclose: ["/amount", "/amount"] }, look: { strict: false } }, addresses: { hosts: [], cidrs: [], resolve: false }, rules: null };
    const v2 = toVersion2(v1);
    expect(v2.format).toBe("signafaide-checks/2");
    expect(v2.tools).toEqual({ pay: { protect: true, mode: "enforce", disclose: ["/amount"] }, look: { protect: false, mode: "enforce" } });
    expect(nextDraft({ mode: "watch", default: "allow", fail: {}, addresses: { hosts: [], cidrs: [] }, approved: null, rules: [] }, [{ id: "x", state: "on" }]).rules).toEqual([{ id: "x", state: "calibrating" }]);
  });

  it("parses check's field=value arguments", () => {
    expect(parseFieldArgs(["amount=1200", "currency=GBP", "payee/name=Ashgrove Catering Ltd", "ok=true"])).toEqual({ amount: 1200, currency: "GBP", payee: { name: "Ashgrove Catering Ltd" }, ok: true });
    expect(() => parseFieldArgs(["amount"])).toThrow(/name=value/);
  });
});

describe("protect, then the first blocked payout", () => {
  it("the mockup's terminal session: 7 answers, a sandbox, the code, version 2 checks file, rules saved with the sandbox key, On only as answered", async () => {
    const p = scriptedPrompter(MOCKUP_ANSWERS());
    setPrompter(() => p);
    const [code, text] = await cli("protect");
    expect(code, text).toBe(0);
    expect(text).toContain("Agent      payout-bot");
    expect(text).toContain("Found      4 tools in src/tools.ts");
    expect(text).toMatch(/approve_payout\s+pays money\s+protect/);
    expect(text).toMatch(/lookup_invoice\s+reads only\s+record/);
    expect(text).toContain("Done. Check a call without running it:");
    expect(text).toContain("Rule: Block approve_payout when amount is above 1,000");
    expect(text).toContain("Sends to signafAIde when approve_payout runs: amount, currency (the fields your 2 rules need)");
    expect(text).toContain("Never sent to signafAIde: payee.");
    expect(text).toContain("Sandbox    made for you");
    expect(text).toContain("Rules      saved in your sandbox as version 1, signed by signafAIde");
    expect(text).toContain("npx signafaide check approve_payout amount=1200 currency=GBP");
    expect(p.asked[0]).toMatch(/^Protect which tools\?/);
    // protect writes only the key to .env, never the witness URL (it is in the process environment).
    const envText = fs.readFileSync(path.join(ctx.root, ".env"), "utf8");
    expect(envText).toMatch(/^SIGNAFAIDE_API_KEY=sfa_test_\w+\n$/);
    expect(envText).not.toContain("SIGNAFAIDE_URL");
    expect(p.asked).toContain('Turn it on now? On blocks the call. Calibrating only notes "Would have blocked".');
    // The code.
    const src = fs.readFileSync(path.join(ctx.root, "src", "tools.ts"), "utf8");
    expect(src).toContain('approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" })');
    expect(JSON.parse(fs.readFileSync(path.join(ctx.root, "package.json"), "utf8")).dependencies.signafaide).toMatch(/^\^/);
    // The checks file: version 2, approve_payout protected, the fields of its rules approved.
    const file = JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8"));
    expect(file.format).toBe("signafaide-checks/2");
    expect(file.tools).toEqual({ approve_payout: { protect: true, disclose: ["/amount", "/currency"] } });
    // The rules: published by the unclaimed sandbox's key; On only for the rule the person turned On.
    expect(ctx.service.published).toEqual([{ project: ctx.service.project().project, version: 1, how: "sandbox_key", who: null }]);
    const rs = getRecorder().checks.heldRules()!;
    expect(rs.mode).toBe("enforce");
    expect(rs.rules.map((r: any) => [r.id, r.state])).toEqual([
      ["approve_payout-amount", "on"],
      ["approve_payout-currency", "calibrating"],
    ]);

    // The protected tool: 800 runs, 1200 is blocked by the witness, in words, with the version and a link.
    const { ran, fn } = payout();
    await expect(fn("Ashgrove Catering Ltd", 800, "GBP")).resolves.toBe("paid 800 GBP to Ashgrove Catering Ltd");
    let err: unknown;
    try {
      await fn("Ashgrove Catering Ltd", 1200, "GBP");
    } catch (e) {
      err = e;
    }
    expect(ran).toEqual([800]);
    expect(err).toBeInstanceOf(SignafaideBlocked);
    expect(err).toBeInstanceOf(CheckError);
    const b = err as SignafaideBlocked;
    expect(b.name).toBe("SignafaideBlocked");
    expect(b.code).toBe("blocked");
    // A protected call always asks the witness, also when the version held here would block it:
    // the witness rules, in words, with the version and a link.
    expect(b.message).toMatch(/^approve_payout did not run: signafAIde blocked it under "Block approve_payout when amount is above 1,000" \(rule set version 1\)\. To allow such calls, change the rule in the console\. http:\/\/127\.0\.0\.1:\d+\/r\/[0-9a-f]{64}$/);
    expect(b).toMatchObject({ tool: "approve_payout", rule: "approve_payout-amount", ruleText: "Block approve_payout when amount is above 1,000", ruledBy: "witness", rulesVersion: 1, check: "rule" });
    expect(b.link).toBe(`${ctx.service.url}/r/${b.record}`);
    const dec = getRecorder().state.readAll(getRecorder().state.chains().find((c) => c.endsWith("/payout-bot"))!).filter((r) => r.envelope.kind === "decision").at(-1)! as any;
    expect(recordHash(dec)).toBe(b.record);
    // The client's own evaluation under the version it holds is a note, never a block.
    expect(dec.envelope.checks.result).toBe("note");
    expect(dec.envelope.checks.results.find((e: any) => e.check === "rule")).toMatchObject({ mode: "watch", result: "note", enforce_result: "block", matched: ["approve_payout-amount"] });

    // A Calibrating rule never blocks; the ruling names it.
    await expect(fn("Brightmoor Print", 640, "EUR")).resolves.toBe("paid 640 EUR to Brightmoor Print");
    const last = getRecorder().state.readAll(getRecorder().state.chains().find((c) => c.endsWith("/payout-bot"))!).filter((r) => r.envelope.kind === "decision").at(-1)! as any;
    expect(last.receipt.ruling.would_block).toEqual(["approve_payout-currency"]);
    // Only the approved fields left the machine.
    expect(ctx.service.disclosed.get(recordHash(last))?.[0]).toEqual({ "/amount": 640, "/currency": "EUR" });
    // A block by the witness: the client holds an older version than the witness rules with.
    const key = getRecorder().apiKey!;
    const v1 = getRecorder().checks.heldRules()!;
    ctx.service.publishRules(key, [...v1.rules, { id: "no-brightmoor", about: "", action: "block", tools: ["approve_payout"], agents: null, when: [{ field: "/amount", op: "eq", value: 641 }], state: "on" }], { set: v1.set });
    const w = (await fn("Brightmoor Print", 641, "EUR").catch((x: unknown) => x)) as SignafaideBlocked;
    expect(w.ruledBy).toBe("witness");
    expect(w.message).toMatch(/^approve_payout did not run: signafAIde blocked it under "rule no-brightmoor" \(rule set version 2\)\. To allow such calls, change the rule in the console\. http/);

    // check: a dry run, exit 1 on would-block, 0 otherwise.
    let [c, out] = await cli("check", "approve_payout", "amount=1200", "currency=GBP", 'payee=Ashgrove Catering Ltd', "--agent", "payout-bot");
    expect(c, out).toBe(1);
    expect(out).toContain("would block  Block approve_payout when amount is above 1,000 (On, version 1)");
    expect(out).toContain("Dry run: nothing recorded, the tool did not run. Exit code 1.");
    [c, out] = await cli("check", "approve_payout", "amount=800", "currency=EUR", "--agent", "payout-bot");
    expect(c, out).toBe(0);
    expect(out).toContain("calibrating  would have blocked: Block approve_payout when currency is not \"GBP\"");

    // status: one line per tool, three states (the tool list as the rewritten code declares it).
    declareTools(["approve_payout", "delete_payee", "send_receipt", "lookup_invoice"], { agent: "payout-bot" });
    await getRecorder().flush();
    [c, out] = await cli("status");
    expect(out.split("\n")[0]).toMatch(/^tool\s+recorded\s+protected\s+proof$/);
    expect(out).toMatch(/approve_payout\s+4 calls, last \d\d:\d\d\s+2 of 3 rules On, 1 Calibrating, by the code and the checks file\s+intact/);
    expect(out).toMatch(/lookup_invoice\s+0 calls\s+Off\s+intact/);

    // prove: the link first, the calls, the rules in words, Before and the record.
    [c, out] = await cli("prove", "approve_payout");
    expect(c, out).toBe(0);
    expect(out).toContain("Proof of approve_payout (agent payout-bot), Sandbox");
    expect(out).toContain("Send this link to your auditor:");
    expect(out).toMatch(/\/audit\/aud_1 {3}read only, until/);
    expect(out).toMatch(/allowed\s+800 GBP\s+by signafAIde/);
    expect(out).toMatch(/blocked\s+1,200 GBP\s+by the signafAIde witness; it did not run/);
    expect(out).toMatch(/Block approve_payout when amount is above 1,000\s+blocked 1/);
    expect(out).toMatch(/Calibrating\s+Block approve_payout when currency is not "GBP"\s+would have blocked 2/);
    expect(out).toContain("Before     none: approve_payout was protected before its first call");
    expect(out).toContain("Every record is present and unaltered.");
    expect(ctx.service.auditorLinks[0]).toMatchObject({ agent: "payout-bot", tool: "approve_payout" });

    // prove --files: a pack that verifies, with the rules in words.
    [c, out] = await cli("prove", "approve_payout", "--files", "--content");
    expect(c, out).toBe(0);
    const dir = path.join(ctx.root, "proof", "approve_payout");
    expect(fs.readdirSync(dir).sort()).toEqual(["agent-keys.json", "content.jsonl", "head.json", "pack.json"]);
    const r = await verify(path.join(dir, "pack.json"), { keys: { keys: [ctx.service.keyDoc] }, agentKeys: path.join(dir, "agent-keys.json"), head: path.join(dir, "head.json"), content: path.join(dir, "content.jsonl"), offline: true });
    expect(r.ok, String(r)).toBe(true);
    expect(r.rulesLines()).toContain(`${getRecorder().checks.heldRules()!.set} version 1: rule approve_payout-amount: Block approve_payout when amount is above 1,000 (On)`);
  }, 60_000);

  it("pull asks before a new field leaves the machine, and never without a person", async () => {
    setPrompter(() => scriptedPrompter(MOCKUP_ANSWERS()));
    expect((await cli("protect"))[0]).toBe(0);
    // An admin allows one payee from now on: an exception on a field the tool does not send yet.
    const key = getRecorder().apiKey!;
    const v1 = getRecorder().checks.heldRules()!;
    const rules = v1.rules.map((r: any) => (r.id === "approve_payout-amount" ? { ...r, exceptions: [{ field: "/payee", value: "Harbour Lane Supplies Ltd", reason: "Quarterly rent", since: 2 }] } : r));
    ctx.service.publishRules(key, rules, { set: v1.set });
    // Without a person: listed, not added.
    setPrompter(() => flagPrompter({ yes: true }));
    let [c, out] = await cli("pull");
    expect(c, out).toBe(0);
    expect(out).toContain("Rules      version 2 (was 1)");
    expect(out).toContain("Change     approve_payout would also send: payee");
    expect(out).toContain('needed by: Block approve_payout when amount is above 1,000, except when payee is "Harbour Lane Supplies Ltd"');
    expect(out).toContain("run npx signafaide pull at a terminal to approve them");
    expect(JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8")).tools.approve_payout.disclose).toEqual(["/amount", "/currency"]);
    // A person says yes.
    const p = scriptedPrompter([true]);
    setPrompter(() => p);
    [c, out] = await cli("pull");
    expect(p.asked).toEqual(["Send payee to signafAIde for approve_payout? It is kept 30 days, admins only."]);
    expect(out).toContain("approve_payout sends amount, currency, payee");
    expect(JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8")).tools.approve_payout.disclose).toEqual(["/amount", "/currency", "/payee"]);
    // The exception now applies: that payee runs above the limit, allowed by exception.
    getRecorder().checks.forget();
    const { fn } = payout();
    await expect(fn("Harbour Lane Supplies Ltd", 4800, "GBP")).resolves.toContain("paid 4800");
    const d = getRecorder().state.readAll(getRecorder().state.chains().find((x) => x.endsWith("/payout-bot"))!).filter((r) => r.envelope.kind === "decision").at(-1)! as any;
    expect(d.receipt.ruling.excepted).toEqual(["approve_payout-amount"]);
  }, 60_000);

  it("without a person: every rule starts Calibrating and no field is approved", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "approve_payout");
    expect(c, out).toBe(1); // --yes adds the default rule, Calibrating; with no key it is not saved yet (patch 0.5.1)
    expect(out).toContain("Changed");
    expect(out).toContain("  Rule: Block approve_payout when amount is above 1,000");
    const file = JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8"));
    expect(file.tools.approve_payout).toEqual({ protect: true, mode: "watch" }); // no field approved without a person; the kept rule blocks nothing
    expect(out).toContain("Sandbox    not made: only a person at a terminal opts in.");
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    expect(ctx.service.calls).not.toContain("POST /v1/sandbox");
  });

  it("a claimed sandbox: the API key may not save rules; a person signs in and does", async () => {
    setPrompter(() => scriptedPrompter(MOCKUP_ANSWERS()));
    expect((await cli("protect"))[0]).toBe(0);
    ctx.service.project().claimed = true;
    setPrompter(() => scriptedPrompter([0, "20", 0, true]));
    let [c, out] = await cli("protect", "delete_payee");
    expect(c, out).toBe(1);
    expect(out).toContain("Rules      not saved: the sandbox is claimed, so its rules are saved by a signed-in person.");
    expect(out).toContain("npx signafaide login");
    // The device sign-in.
    const lines: string[] = [];
    const signing = login({ url: ctx.service.url, clientId: "test", out: (s) => lines.push(s), sleep: async () => ctx.service.answerDevice("approved"), browser: () => false });
    const s = await signing;
    expect(lines[0]).toBe(`Witness     ${ctx.service.url}`);
    expect(lines[1]).toBe(`Sign in at  ${ctx.service.url}/app/device`);
    expect(lines[2]).toBe("Your code   BCDF-GHJK");
    expect(s.session).toMatch(/^sfa_user_/);
    expect(loadSession(ctx.service.url)?.person?.email).toBe("owner@example.test");
    expect(fs.statSync(sessionFile()).mode & 0o777).toBe(0o600);
    expect(sessionFile().startsWith(xdg)).toBe(true);
    // Now the person's session saves the rules (the rate rule: Calibrating as answered).
    setPrompter(() => scriptedPrompter([0, "20", 1, true]));
    [c, out] = await cli("protect", "delete_payee");
    expect(c, out).toBe(0);
    expect(out).toContain("Rules      saved by owner@example.test as version 2");
    expect(ctx.service.published.at(-1)).toMatchObject({ version: 2, how: "session", who: "owner@example.test" });
    expect(getRecorder().checks.heldRules()!.rules.at(-1)).toMatchObject({ id: "delete_payee-rate", state: "calibrating", limit: { calls: 20, seconds: 60, per: "agent_tool" } });
    // logout ends the session at the witness and forgets it here.
    expect(await logout(ctx.service.url, "test")).toBe(true);
    expect(loadSession(ctx.service.url)).toBeNull();
    expect(ctx.service.sessions.size).toBe(0);
  }, 60_000);

  it("a refused sign-in saves nothing", async () => {
    await expect(login({ url: ctx.service.url, clientId: "test", out: () => undefined, sleep: async () => ctx.service.answerDevice("denied"), browser: () => false })).rejects.toThrow(/refused/);
    expect(fs.existsSync(sessionFile())).toBe(false);
  });

  it("--local: rules in the checks file only, the tool in enforce mode, the block says signafAIde did not rule", async () => {
    setPrompter(() => scriptedPrompter([[true, false, false, false], true, 0, "1000", 0, [false, false], true]));
    const [c, out] = await cli("protect", "--local");
    expect(c, out).toBe(0);
    expect(out).toContain("Rules      kept on this machine in signafaide.checks.json; signafAIde does not rule on them.");
    const file = JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8"));
    expect(file.tools.approve_payout).toEqual({ protect: false, mode: "enforce" });
    expect(file.rules.rules[0]).toMatchObject({ id: "approve_payout-amount", when: [{ field: "/amount", op: "gt", value: 1000 }] });
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    expect(fs.readFileSync(path.join(ctx.root, "src", "tools.ts"), "utf8")).toContain('approve_payout: record(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }),');
    getRecorder().checks.forget();
    const fn = record(async function approve_payout(_p: string, _a: number, _c: string) {
      return "paid";
    }, { args: ["payee", "amount", "currency"] });
    await expect(fn("x", 10, "GBP")).resolves.toBe("paid");
    const e = await fn("x", 5000, "GBP").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(SignafaideBlocked);
    expect((e as SignafaideBlocked).message).toBe('approve_payout did not run: the rule on this machine blocked it ("Block approve_payout when amount is above 1,000"); signafAIde did not rule on it. To allow it, change the rule in signafaide.checks.json.');
    expect((e as SignafaideBlocked).link).toBeUndefined();
  });

  it("--local without a person: the rule starts Calibrating (the tool in watch mode), nothing waits for approval, and it is Done", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "--local", "--tool", "approve_payout", "--limit-field", "amount", "--above", "1000");
    expect(c, out).toBe(0);
    expect(out).toContain("Starts Calibrating");
    expect(out).not.toContain("is not approved");
    expect(out).not.toContain("Sends to signafAIde");
    expect(out).not.toContain("Not finished");
    const file = JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8"));
    expect(file.tools.approve_payout).toEqual({ protect: false, mode: "watch" });
    expect(file.rules.rules.map((r: { id: string }) => r.id)).toEqual(["approve_payout-amount"]);
    // --tool records one tool, and the declaration is still the agent's full tool list.
    const code = fs.readFileSync(path.join(ctx.root, "src", "tools.ts"), "utf8");
    expect(code.match(/record\(/g)?.length).toBe(1);
    expect(code).toContain("declareTools(Object.keys(tools), { agent: \"payout-bot\" });");
    getRecorder().checks.forget();
    const fn = record(async function approve_payout(_p: string, _a: number, _c: string) {
      return "paid";
    }, { args: ["payee", "amount", "currency"] });
    await expect(fn("x", 5000, "GBP")).resolves.toBe("paid");
  });

  it("--local: a person who answers Calibrating gets the tool in watch mode, so the rule blocks nothing", async () => {
    setPrompter(() => scriptedPrompter([[true, false, false, false], true, 0, "1000", 1, [false, false], true]));
    const [c, out] = await cli("protect", "--local");
    expect(c, out).toBe(0);
    const file = JSON.parse(fs.readFileSync(path.join(ctx.root, "signafaide.checks.json"), "utf8"));
    expect(file.tools.approve_payout).toEqual({ protect: false, mode: "watch" });
  });

  it("prove says what ran before protection, and start-fresh starts the proof from now", async () => {
    setPrompter(() => scriptedPrompter([[true, false, false, false], true, 0, "1000", 0, [false, false], true, true]));
    // Two calls recorded before protection.
    const before = record(async function approve_payout(_p: string, a: number, _c: string) {
      return a;
    }, { args: ["payee", "amount", "currency"], agent: "payout-bot" });
    getRecorder().state.ensure();
    await getRecorder().createSandbox();
    await before("a", 10, "GBP");
    await before("b", 20, "GBP");
    expect((await cli("protect"))[0]).toBe(0);
    const { fn } = payout();
    await fn("c", 30, "GBP");
    let [c, out] = await cli("prove", "approve_payout");
    expect(c, out).toBe(0);
    expect(out).toMatch(/Before {5}2 calls of approve_payout \(\d\d:\d\d to \d\d:\d\d\) were recorded before it was protected\. They ran/);
    expect(out).toContain("npx signafaide start-fresh payout-bot");
    [c, out] = await cli("start-fresh", "payout-bot");
    expect(c).toBe(0);
    expect(out).toContain("The old record is kept");
    await fn("d", 40, "GBP");
    [c, out] = await cli("prove", "approve_payout");
    expect(out).toContain("Before     none");
    expect(out).toContain("Calls      1,");
    expect(ctx.service.auditorLinks.at(-1).from).toMatch(/^\d{4}-/);
    [c, out] = await cli("prove", "approve_payout", "--all");
    expect(out).toContain("Calls      4,");
  }, 60_000);

  it("a witness without auditor links: prove says so and points at files", async () => {
    setPrompter(() => scriptedPrompter(MOCKUP_ANSWERS()));
    expect((await cli("protect"))[0]).toBe(0);
    await payout().fn("x", 10, "GBP");
    ctx.service.auditorLinksOff = true;
    const [c, out] = await cli("prove", "approve_payout");
    expect(c, out).toBe(0);
    expect(out).toContain("No link: this witness does not make auditor links from the command line yet.");
    expect(out).toContain("npx signafaide prove approve_payout --files");
  }, 60_000);
});

describe("record and protect name positional arguments", () => {
  it("record(fn, { args }) writes the input by name; arguments past the names go under _rest", () => {
    const fn = record((a: number, b: string, ...rest: number[]) => a + b + rest.length, { name: "named", args: ["amount", "currency"] });
    fn(5, "GBP", 1, 2);
    const st = getRecorder().state;
    const d = st.readAll(st.chains()[0]).find((r) => r.envelope.kind === "decision")!;
    expect(d.content!.input).toEqual({ amount: 5, currency: "GBP", _rest: [1, 2] });
    expect(() => record(() => 1, { args: ["a", "a"] })).toThrow(/distinct/);
  });

  it("protect without a key: the call does not run and says how to get one", async () => {
    fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify(toVersion2(null)));
    getRecorder().checks.forget();
    const ran: number[] = [];
    const fn = protect(async function pay(amount: number) {
      ran.push(amount);
    }, { args: ["amount"] });
    const e = await fn(5).catch((x: unknown) => x);
    expect(ran).toEqual([]);
    expect(e).toBeInstanceOf(SignafaideBlocked);
    expect((e as SignafaideBlocked).code).toBe("no_key");
    expect((e as SignafaideBlocked).message).toContain("npx signafaide protect");
  });
});

describe("the terminal prompter", () => {
  it("numbered choices, Enter for the default, ticks by number, a wrong answer asked again", async () => {
    const { PassThrough } = await import("node:stream");
    const { terminalPrompter } = await import("../src/protect.js");
    const input = new PassThrough();
    const output = new PassThrough();
    let shown = "";
    output.on("data", (d) => (shown += String(d)));
    input.end(["", "n", "9", "2", "1,3", "", "1500"].join("\n") + "\n");
    const p = terminalPrompter(input, output);
    expect(p.person).toBe(true);
    expect(await p.confirm("Write it?", true)).toBe(true);
    expect(await p.confirm("Sandbox?", true)).toBe(false);
    expect(await p.choose("Which?", ["a", "b"], 0)).toBe(1); // 9 is asked again
    expect(await p.multi("Tick", ["x", "y", "z"], [false, false, false])).toEqual([true, false, true]);
    expect(await p.text("Limit:", "1000")).toBe("1000");
    expect(await p.text("Limit:", "1000")).toBe("1500");
    expect(await p.confirm("At the end of input:", false)).toBe(false);
    p.close();
    expect(shown).toContain("  > 1) a\n    2) b\n");
    expect(shown).toContain("  1) [ ] x\n");
  });
});
