/**
 * The GitHub Action in action/ (#61, #67 step 3), its scripts run here as the composite action
 * runs them, against a repository with TypeScript and Python tools (the two fixtures in
 * action/test/fixtures), with the CLIs of this checkout (the built npm CLI, the Python package's
 * source) in place of npx and pipx.
 */
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ACTION = path.resolve(__dirname, "../../action");
const FIXTURES = path.join(ACTION, "test", "fixtures");
const JS_CLI = `node ${path.resolve(__dirname, "../dist/cli.js")}`;
const VENV = path.resolve(__dirname, "../../python/.venv/bin/python");
const PY_CLI = `${fs.existsSync(VENV) ? VENV : "python3"} -m signafaide`;

let tmp: string;
let repo: string;
let files: { summary: string; env: string; output: string };

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-action-"));
  repo = path.join(tmp, "work");
  fs.cpSync(path.join(FIXTURES, "ts-repo"), repo, { recursive: true });
  fs.cpSync(path.join(FIXTURES, "py-repo"), repo, { recursive: true });
  files = { summary: path.join(tmp, "summary.md"), env: path.join(tmp, "env"), output: path.join(tmp, "output") };
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function action(script: string, args: string[], extra: Record<string, string>): { code: number; out: string } {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "",
    HOME: tmp,
    XDG_CONFIG_HOME: path.join(tmp, "config"),
    PYTHONPATH: path.resolve(__dirname, "../../python/src"),
    SIGNAFAIDE_URL: "http://127.0.0.1:9",
    SIGNAFAIDE_TEST: "0",
    GITHUB_WORKSPACE: tmp,
    GITHUB_STEP_SUMMARY: files.summary,
    GITHUB_ENV: files.env,
    GITHUB_OUTPUT: files.output,
    RUNNER_TEMP: tmp,
    SIGNAFAIDE_CI_JS_CLI: JS_CLI,
    SIGNAFAIDE_CI_PY_CLI: PY_CLI,
    SFA_VERSION: "0.5.0",
    SFA_DIR: "work",
    SFA_PYTHON: "auto",
    ...extra,
  };
  const r = spawnSync("node", [path.join(ACTION, script), ...args], { env, encoding: "utf8" });
  return { code: r.status ?? -1, out: `${r.stdout}${r.stderr}` };
}
const read = (f: string): string => (fs.existsSync(f) ? fs.readFileSync(f, "utf8") : "");
const git = (...args: string[]): string => execFileSync("git", ["-c", "user.email=ci@example.com", "-c", "user.name=CI", "-c", "commit.gpgsign=false", ...args], { cwd: repo, encoding: "utf8" });

describe("action: check", () => {
  it("runs both CLIs, notes each unprotected tool on its line, writes the summary table and fails the job", () => {
    const r = action("check.mjs", [], {});
    expect(r.code).toBe(1);
    expect(r.out).toContain(
      '::error file=work/src/tools.ts,line=25,title=signafaide%3A approve_payout is not protected::approve_payout pays money; not protected. Fix: approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }) (or: npx signafaide protect --tool approve_payout)',
    );
    expect(r.out).toContain("work/agent/tools.py:7: approve_payout pays money; not protected. Fix: add @signafaide.protect(agent=\"payout-bot\") right above def approve_payout");
    expect(r.out).toContain("work/agent/tools.py:32: git_push pushes code; not protected.");
    expect(r.out).toContain("work/src/git.ts:4: gitPush pushes code; not protected.");
    expect(r.out).toContain("signafaide check: Failed: 6 risky tools not protected (of 12; 4 protected, 2 allowed).");
    const md = read(files.summary);
    expect(md).toContain("### signafAIde check");
    expect(md).toContain("| Tool | Where | Why | Fix |");
    expect(md).toContain("| `send_email` | work/agent/server.py:6 | sends messages; not protected | `add @signafaide.protect(agent=\"payout-bot\") right above def send_email (under the framework's decorator) (or: signafaide protect --tool send_email)` |");
    expect(md).toContain("- `run_migration` (work/src/tools.ts:29, runs commands): runs only the migration files kept in this repository; reviewed 18 Nov 2026");
  });

  it("allow input: reviewed exceptions pass", () => {
    const r = action("check.mjs", [], { SFA_ALLOW: "approve_payout, gitPush\nsend_email,git_push" });
    expect(r.code).toBe(0);
    expect(r.out).toContain("signafaide check: Passed: 12 risky tools, 4 protected, 8 allowed.");
    expect(read(files.summary)).not.toContain("| Tool |");
  });

  it("on a pull request, checks only the tools added or changed since the base commit", () => {
    git("init", "-q", "-b", "main");
    git("add", "-A");
    git("commit", "-q", "-m", "base");
    const base = git("rev-parse", "HEAD").trim();
    git("checkout", "-q", "-b", "feature");
    fs.appendFileSync(path.join(repo, "agent", "tools.py"), '\n\n@signafaide.protect(agent="payout-bot")\ndef cancel_order(order_id: str) -> str:\n    return order_id\n');
    git("commit", "-qam", "a protected tool");
    let r = action("check.mjs", [], { SFA_BASE: base });
    expect(r.code).toBe(0);
    expect(r.out).toContain(`signafaide check: Passed: 1 risky tool added or changed since ${base.slice(0, 12)}, 1 protected, 0 allowed.`);
    fs.appendFileSync(path.join(repo, "agent", "tools.py"), "\n\n@tool\ndef purge_ledger() -> None:\n    \"\"\"Purge the ledger.\"\"\"\n");
    git("commit", "-qam", "an unprotected tool");
    r = action("check.mjs", [], { SFA_BASE: base });
    expect(r.code).toBe(1);
    expect(r.out).toContain("work/agent/tools.py:43: purge_ledger deletes data; not protected.");
    expect(r.out).not.toContain("approve_payout");
  });

  it("python false: only the TypeScript and JavaScript tools", () => {
    const r = action("check.mjs", [], { SFA_PYTHON: "false" });
    expect(r.code).toBe(1);
    expect(r.out).not.toContain("agent/tools.py");
    expect(r.out).toContain("Failed: 3 risky tools not protected (of 6;");
  });

  it("a CLI that cannot run fails the job with the reason (exit 2)", () => {
    const r = action("check.mjs", [], { SIGNAFAIDE_CI_JS_CLI: "node /nonexistent/cli.js" });
    expect(r.code).toBe(2);
    expect(r.out).toContain("::error title=signafaide check could not run::");
    expect(read(files.summary)).toContain("The check could not run");
  });
});

describe("action: record-runs (optional)", () => {
  it("start with an API key: masks it and gives it to the job's later steps, with the start time", () => {
    const key = "sfa_test_" + "a1".repeat(16);
    const r = action("runs.mjs", ["start"], { SFA_API_KEY: key });
    expect(r.code).toBe(0);
    expect(r.out).toContain(`::add-mask::${key}`);
    const env = read(files.env);
    expect(env).toContain(`SIGNAFAIDE_API_KEY=${key}`);
    expect(env).toMatch(/^SIGNAFAIDE_JOB_STARTED=\d{4}-\d\d-\d\dT/m);
  });

  it("finish without a key: says the records stayed on the runner, not co-signed, and exports no pack", () => {
    const r = action("runs.mjs", ["finish"], { SFA_FAIL: "false" });
    expect(r.code).toBe(0);
    const md = read(files.summary);
    expect(md).toContain("### signafAIde agent runs");
    expect(md).toContain("No API key: the records stayed on this runner and were not co-signed by the witness, so no pack was exported.");
    expect(read(files.output)).toMatch(/^result=(verified|not-verified)$/m);
    expect(read(files.output)).toMatch(/^pack-dir=/m);
  });
});
