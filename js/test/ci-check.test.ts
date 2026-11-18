/**
 * `signafaide check --ci` (#67 step 3, #61): risky tools not protected fail the check, one line
 * each with file:line, why and the fix; protected, allowed (with a reason) and reading tools pass;
 * `--diff` keeps only the tools added or changed since a git base. The fixture is the TypeScript
 * repository in action/test/fixtures/ts-repo, copied to a temporary folder for each test.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import { checksFileErrors, toolSettings } from "../src/checks.js";
import { ciCheck, riskOf } from "../src/ci-check.js";
import { toolKind } from "../src/find-tools.js";
import { NOTE } from "../src/skill.js";

const FIXTURE = path.resolve(__dirname, "../../action/test/fixtures/ts-repo");
let root: string;

beforeEach(() => {
  delete process.env.SIGNAFAIDE_CHECKS;
  root = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sfa-ci-")), "repo");
  fs.cpSync(FIXTURE, root, { recursive: true });
});
afterEach(() => {
  fs.rmSync(path.dirname(root), { recursive: true, force: true });
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

const edit = (rel: string, from: string | RegExp, to: string): void => {
  const p = path.join(root, rel);
  const before = fs.readFileSync(p, "utf8");
  const after = before.replace(from, to);
  expect(after).not.toBe(before);
  fs.writeFileSync(p, after);
};
const checks = (): Record<string, any> => JSON.parse(fs.readFileSync(path.join(root, "signafaide.checks.json"), "utf8"));
const saveChecks = (doc: Record<string, any>): void => fs.writeFileSync(path.join(root, "signafaide.checks.json"), JSON.stringify(doc, null, 2));
const git = (...args: string[]): string => execFileSync("git", ["-c", "user.email=ci@example.com", "-c", "user.name=CI", "-c", "commit.gpgsign=false", ...args], { cwd: root, encoding: "utf8" });

/** Every risky tool of the fixture protected: the entry, the framework tool and the MCP tool. */
function protectAll(): void {
  edit("src/tools.ts", "  approve_payout,\n", '  approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }),\n');
  edit("src/git.ts", "export const gitPush = tool({", "export const gitPush = wrapTool(tool({");
  edit("src/git.ts", "});\n", '}), { name: "gitPush", agent: "payout-bot", strict: true });\n');
  const doc = checks();
  doc.tools.send_email = { protect: true };
  saveChecks(doc);
}

describe("check --ci", () => {
  it("fails on risky tools that are not protected: one line each with file:line, why and the fix", async () => {
    const [code, text] = await cli("check", "--ci", "--dir", root);
    expect(code).toBe(1);
    const lines = text.split("\n");
    expect(lines).toContain(
      'src/tools.ts:25: approve_payout pays money; not protected. Fix: approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }) (or: npx signafaide protect --tool approve_payout)',
    );
    expect(lines).toContain('src/git.ts:4: gitPush pushes code; not protected. Fix: wrapTool(<its tool(...) definition>, { name: "gitPush", agent: "payout-bot", strict: true }) (or: npx signafaide protect --tool gitPush)');
    expect(lines.find((l) => l.startsWith("src/mcp-server.ts:5: send_email sends messages; not protected. Fix: run the server as npx signafaide gateway --strict-tools send_email"))).toBeTruthy();
    // Protected in code (delete_payee), recorded and protected by the checks file (send_receipt),
    // reading (lookup_invoice): not listed. run_migration: allowed with its reason.
    for (const t of ["delete_payee", "send_receipt", "lookup_invoice"]) expect(text).not.toContain(`${t} `);
    expect(lines).toContain("src/tools.ts:29: run_migration runs commands; allowed (checks file): runs only the migration files kept in this repository; reviewed 18 Nov 2026");
    expect(lines).toContain("signafaide check --ci: failed. 3 risky tools not protected (of 6; 2 protected, 1 allowed; TypeScript and JavaScript, 7 tools found).");
  });

  it("passes when every risky tool is protected", async () => {
    protectAll();
    const [code, text] = await cli("check", "--ci", "--dir", root);
    expect(code).toBe(0);
    expect(text).toContain("signafaide check --ci: passed. 6 risky tools: 5 protected, 1 allowed");
    expect(text).not.toContain("Fix:");
  });

  it("passes with reviewed exceptions: ci.allow with a reason, or --allow", async () => {
    const doc = checks();
    doc.ci.allow.push({ tool: "approve_payout", reason: "pays only our own test ledger" }, { tool: "gitPush", reason: "pushes to a sandbox remote" }, { tool: "send_email", reason: "sends to the team only" });
    saveChecks(doc);
    const [code, text] = await cli("check", "--ci", "--dir", root);
    expect(code).toBe(0);
    expect(text).toContain("approve_payout pays money; allowed (checks file): pays only our own test ledger");
    expect(text).toContain("4 allowed");

    fs.cpSync(FIXTURE, root, { recursive: true });
    const [code2, text2] = await cli("check", "--ci", "--dir", root, "--allow", "approve_payout", "--allow", "gitPush", "--allow", "send_email");
    expect(code2).toBe(0);
    expect(text2).toContain("gitPush pushes code; allowed (--allow): allowed on the command line (--allow)");
  });

  it("a recorded tool is not protected; protect in the checks file counts only for code that goes through signafaide", async () => {
    const doc = checks();
    doc.tools.send_receipt = { protect: false };
    doc.tools.approve_payout = { protect: true };
    saveChecks(doc);
    const r = ciCheck({ root });
    expect(r.unprotected.find((u) => u.tool === "send_receipt")?.why).toBe("sends messages; recorded, not protected");
    expect(r.unprotected.find((u) => u.tool === "approve_payout")?.why).toBe("pays money; protected in signafaide.checks.json, but its code does not go through signafaide");
  });

  it("a recorded tool with a block rule on this machine in enforce mode is protected, as protect --local writes it", async () => {
    const doc = checks();
    doc.tools.send_receipt = { protect: false, mode: "enforce" };
    const rule = { id: "send_receipt-to", about: "send_receipt: to outside the company.", action: "block", tools: ["send_receipt"], agents: null, when: [{ field: "/to", op: "eq", value: "x@example.com" }] };
    doc.rules = { default: "allow", rules: [rule] };
    saveChecks(doc);
    expect(ciCheck({ root }).unprotected.find((u) => u.tool === "send_receipt")).toBeUndefined();
    // Calibrating (watch mode) blocks nothing, and an allow rule protects nothing.
    doc.tools.send_receipt = { protect: false, mode: "watch" };
    saveChecks(doc);
    expect(ciCheck({ root }).unprotected.find((u) => u.tool === "send_receipt")?.why).toBe("sends messages; recorded, not protected");
    doc.tools.send_receipt = { protect: false, mode: "enforce" };
    doc.rules.rules = [{ ...rule, action: "allow" }];
    saveChecks(doc);
    expect(ciCheck({ root }).unprotected.find((u) => u.tool === "send_receipt")?.why).toBe("sends messages; recorded, not protected");
  });

  it("--diff reports only the tools added or changed since the base", async () => {
    git("init", "-q", "-b", "main");
    git("add", "-A");
    git("commit", "-q", "-m", "base");
    git("checkout", "-q", "-b", "feature");
    // Nothing risky changed: the tools already there are not this pull request's.
    edit("src/tools.ts", "return payments.invoice(invoiceId);", "return payments.invoice(invoiceId.trim());");
    git("commit", "-qam", "read only");
    let [code, text] = await cli("check", "--ci", "--dir", root, "--diff", "main");
    expect(code).toBe(0);
    expect(text).toContain("signafaide check --ci: passed. 0 risky tools added or changed since main");

    // A new risky tool, not protected: only it is reported.
    edit("src/tools.ts", "export const tools = {\n", "async function refund_order(orderId: string) {\n  return payments.payout({ payee: orderId, amount: 1, currency: \"GBP\" });\n}\n\nexport const tools = {\n  refund_order,\n");
    git("commit", "-qam", "refund");
    [code, text] = await cli("check", "--ci", "--dir", root, "--diff", "main");
    expect(code).toBe(1);
    expect(text).toContain("src/tools.ts:29: refund_order pays money; not protected.");
    expect(text).not.toContain("approve_payout");
    expect(text).not.toContain("gitPush");
    expect(text).toContain("1 risky tool added or changed since main not protected");

    // Protection taken away in the pull request: in code, and in the checks file.
    git("checkout", "-q", "main");
    git("checkout", "-q", "-b", "loosen");
    edit("src/tools.ts", 'delete_payee: protect(delete_payee, { args: ["payeeId"], agent: "payout-bot" })', "delete_payee");
    const doc = checks();
    delete doc.tools.send_receipt;
    saveChecks(doc);
    // A new file, not committed yet, counts as added.
    fs.writeFileSync(path.join(root, "src", "secrets.ts"), "export const tools = {};\nexport const settingsTools = { update_secret: async (name: string, value: string) => name + value };\n");
    [code, text] = await cli("check", "--ci", "--dir", root, "--diff", "main", "--json");
    expect(code).toBe(1);
    const r = JSON.parse(text);
    expect(r.format).toBe("signafaide-ci/1");
    expect(r.base).toBe("main");
    expect(r.unprotected.map((u: any) => u.tool).sort()).toEqual(["delete_payee", "send_receipt", "update_secret"]);
    expect(r.unprotected.find((u: any) => u.tool === "update_secret")).toMatchObject({ file: "src/secrets.ts", line: 2, why: "edits secrets; not protected" });
  });

  it("errors (exit 2) on a base that is not there, a checks file that is not valid, and a tool name with --ci", async () => {
    let [code, text] = await cli("check", "--ci", "--dir", root, "--diff", "main");
    expect(code).toBe(2);
    expect(text).toContain("--diff needs a git repository");
    git("init", "-q", "-b", "main");
    git("add", "-A");
    git("commit", "-q", "-m", "base");
    [code, text] = await cli("check", "--ci", "--dir", root, "--diff", "no-such-branch");
    expect(code).toBe(2);
    expect(text).toContain("--diff no-such-branch: no such commit in this clone");
    const doc = checks();
    doc.ci.allow[0].reason = " ";
    saveChecks(doc);
    [code, text] = await cli("check", "--ci", "--dir", root);
    expect(code).toBe(2);
    expect(text).toContain("ci.allow[0].reason must say why the tool is allowed");
    [code] = await cli("check", "--ci", "approve_payout");
    expect(code).toBe(2);
    [code] = await cli("check", "approve_payout", "--diff", "main");
    expect(code).toBe(2);
  });

  it("says when there are Python files, which the Python CLI checks", async () => {
    fs.writeFileSync(path.join(root, "worker.py"), "def send_alert(to):\n    return to\n");
    const r = ciCheck({ root });
    expect(r.other).toEqual({ language: "python", files: 1, command: "pipx run signafaide check --ci" });
  });
});

describe("what looks risky", () => {
  it("pays, deletes, sends, runs commands, pushes code, edits secrets or config; never a reading tool", () => {
    const why = (n: string): string | null => riskOf(n, toolKind(n));
    expect(why("approve_payout")).toBe("pays money");
    expect(why("delete_payee")).toBe("deletes data");
    expect(why("send_receipt")).toBe("sends messages");
    expect(why("run_shell")).toBe("runs commands");
    expect(why("git_push")).toBe("pushes code");
    expect(why("createCommit")).toBe("pushes code");
    expect(why("update_secret")).toBe("edits secrets");
    expect(why("set_api_key")).toBe("edits secrets");
    expect(why("write_config")).toBe("edits config");
    expect(why("get_secret")).toBeNull();
    expect(why("lookup_invoice")).toBeNull();
    expect(why("create_ticket")).toBeNull();
  });
});

describe("the checks file's ci key", () => {
  const base = { format: "signafaide-checks/2", checks: { secret: true, address: true, changed_tool: true, fingerprint: true, hidden_instruction: true }, tools: {}, addresses: { hosts: [], cidrs: [], resolve: false }, rules: null };
  it("takes ci.allow with a tool and a reason, in either version", () => {
    expect(checksFileErrors({ ...base, ci: { allow: [{ tool: "run_migration", reason: "reviewed" }] } })).toBeNull();
    expect(checksFileErrors({ ...base, format: "signafaide-checks/1", mode: "watch", ci: { allow: [] } })).toBeNull();
    expect(checksFileErrors({ ...base, ci: { allow: [{ tool: "x" }] } })).toBe("ci.allow[0] lacks the field 'reason'");
    expect(checksFileErrors({ ...base, ci: { allow: [], deny: [] } })).toBe("ci has the unknown field 'deny'");
    expect(checksFileErrors({ ...base, ci: { allow: [{ tool: "x", reason: "a" }, { tool: "x", reason: "b" }] } })).toBe("ci.allow lists x twice");
    expect(checksFileErrors({ ...base, ci: [] })).toBe('ci must be {"allow": [{"tool", "reason"}]}');
  });
});

describe("the starter templates", () => {
  const dir = path.resolve(__dirname, "../../templates/vercel-ai-agent");
  it("pass check --ci as shipped: approve_payout protected by the rule kept on the machine", () => {
    const r = ciCheck({ root: dir });
    expect(r.ok, JSON.stringify(r.unprotected)).toBe(true);
    expect(r.protected).toBe(1);
  });
  it("carry the project note", () => {
    for (const t of ["vercel-ai-agent", "openai-agents-python"]) {
      const d = path.resolve(__dirname, "../../templates", t);
      expect(fs.readFileSync(path.join(d, "AGENTS.md"), "utf8")).toBe(`<!-- signafaide:start -->\n${NOTE}<!-- signafaide:end -->\n`);
      expect(fs.readFileSync(path.join(d, "CLAUDE.md"), "utf8")).toBe("@AGENTS.md\n");
      expect(checksFileErrors(JSON.parse(fs.readFileSync(path.join(d, "signafaide.checks.json"), "utf8")))).toBeNull();
    }
  });
  it("protect approve_payout in the checks file, On, so `checks status` lists it as a protected tool", () => {
    for (const t of ["vercel-ai-agent", "openai-agents-python"]) {
      const f = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../templates", t, "signafaide.checks.json"), "utf8"));
      expect(f.tools.approve_payout).toEqual({ protect: true, mode: "enforce" });
      expect(toolSettings(f, "approve_payout").strict).toBe(true);
    }
  });
});
