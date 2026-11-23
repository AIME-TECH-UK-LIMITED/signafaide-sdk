// The signafAIde GitHub Action, check step: runs `signafaide check --ci` (the npm CLI for
// TypeScript and JavaScript, the Python CLI for Python when the repository has Python files),
// prints one line per risky tool that is not protected, adds an error note on that line of the
// pull request, writes a table to the job summary, and exits 1 when there is one.
//
// Inputs come from the environment (action.yml sets them):
//   SFA_VERSION      the signafaide version to run (npm and PyPI)
//   SFA_BASE         the git base to compare with (a pull request's base commit); empty: all files
//   SFA_ALLOW        reviewed exceptions, tool names separated by commas or new lines
//   SFA_PYTHON       auto (when Python files are found), true or false
//   SFA_DIR          the folder to check, relative to the repository
// For tests, SIGNAFAIDE_CI_JS_CLI and SIGNAFAIDE_CI_PY_CLI replace the commands that run the
// CLIs (a command and its arguments, separated by spaces).

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const env = process.env;
const version = (env.SFA_VERSION || "").trim();
const base = (env.SFA_BASE || "").trim();
const dir = (env.SFA_DIR || ".").trim() || ".";
const allow = (env.SFA_ALLOW || "")
  .split(/[\n,]/)
  .map((s) => s.trim())
  .filter(Boolean);
const python = (env.SFA_PYTHON || "auto").trim().toLowerCase();
const cwd = path.resolve(env.GITHUB_WORKSPACE || process.cwd(), dir);

if (!version && !(env.SIGNAFAIDE_CI_JS_CLI && env.SIGNAFAIDE_CI_PY_CLI)) {
  console.error("signafaide action: the version input is empty; set it to a released version, e.g. version: 0.5.4");
  process.exit(2);
}
if (!["auto", "true", "false"].includes(python)) {
  console.error(`signafaide action: python must be auto, true or false (got ${python})`);
  process.exit(2);
}

const has = (cmd) => spawnSync(cmd, ["--version"], { stdio: "ignore" }).status === 0;
const split = (s) => s.trim().split(/\s+/);

function jsCommand() {
  if (env.SIGNAFAIDE_CI_JS_CLI) return split(env.SIGNAFAIDE_CI_JS_CLI);
  return ["npx", "--yes", `signafaide@${version}`];
}

function pyCommand() {
  if (env.SIGNAFAIDE_CI_PY_CLI) return split(env.SIGNAFAIDE_CI_PY_CLI);
  if (has("pipx")) return ["pipx", "run", "--spec", `signafaide==${version}`, "signafaide"];
  if (has("uvx")) return ["uvx", "--from", `signafaide==${version}`, "signafaide"];
  const target = fs.mkdtempSync(path.join(env.RUNNER_TEMP || os.tmpdir(), "signafaide-py-"));
  const pip = spawnSync(
    "python3",
    ["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--target", target, `signafaide==${version}`],
    { stdio: "inherit" },
  );
  if (pip.status !== 0) throw new Error(`could not install signafaide==${version} from PyPI`);
  env.PYTHONPATH = target + (env.PYTHONPATH ? path.delimiter + env.PYTHONPATH : "");
  return ["python3", "-m", "signafaide"];
}

/** Run one CLI's `check --ci --json`: its result, or an error line. */
function run(cmd, label) {
  const args = [
    ...cmd.slice(1),
    "check",
    "--ci",
    "--json",
    ...(base ? ["--diff", base] : []),
    ...allow.flatMap((a) => ["--allow", a]),
  ];
  const r = spawnSync(cmd[0], args, {
    cwd,
    encoding: "utf8",
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error)
    return {
      error: `${label}: ${cmd[0]} could not start (${r.error.message})`,
    };
  if (r.status !== 0 && r.status !== 1)
    return {
      error: `${label}: ${(r.stderr || r.stdout || "").trim() || `exit ${r.status}`}`,
    };
  try {
    return { result: JSON.parse(r.stdout) };
  } catch {
    return {
      error: `${label}: the output was not the JSON expected (${(r.stderr || r.stdout || "").trim().slice(0, 400)})`,
    };
  }
}

const results = [];
const errors = [];
const js = run(jsCommand(), "TypeScript and JavaScript");
if (js.error) errors.push(js.error);
else results.push(js.result);
const pyFiles = js.result?.other?.language === "python" ? js.result.other.files : 0;
if (python === "true" || (python === "auto" && pyFiles > 0)) {
  let py;
  try {
    py = run(pyCommand(), "Python");
  } catch (e) {
    py = { error: `Python: ${e.message}` };
  }
  if (py.error) errors.push(py.error);
  else results.push(py.result);
}

// Paths as the repository names them, for the notes on the pull request.
const repoPath = (f) => (dir === "." ? f : path.posix.join(dir.split(path.sep).join("/"), f));
const esc = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escProp = (s) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");

const unprotected = results.flatMap((r) => r.unprotected);
const allowed = results.flatMap((r) => r.allowed);
const risky = results.reduce((n, r) => n + r.risky, 0);
const prot = results.reduce((n, r) => n + r.protected, 0);
const scope = base ? ` added or changed since ${base.slice(0, 12)}` : "";

for (const u of unprotected) {
  console.log(`${repoPath(u.file)}:${u.line}: ${u.tool} ${u.why}. Fix: ${u.fix}`);
  console.log(
    `::error file=${escProp(repoPath(u.file))},line=${u.line},title=${escProp(`signafaide: ${u.tool} is not protected`)}::${esc(`${u.tool} ${u.why}. Fix: ${u.fix}`)}`,
  );
}
for (const a of allowed)
  console.log(`${repoPath(a.file)}:${a.line}: ${a.tool} ${a.why}; allowed (${a.from}): ${a.reason}`);
for (const e of errors) console.log(`::error title=signafaide check could not run::${esc(e)}`);

const failed = unprotected.length > 0;
const line = errors.length
  ? `The check could not run: ${errors.join("; ")}`
  : failed
    ? `Failed: ${unprotected.length === 1 ? "1 risky tool" : `${unprotected.length} risky tools`}${scope} not protected (of ${risky}; ${prot} protected, ${allowed.length} allowed).`
    : `Passed: ${risky === 1 ? "1 risky tool" : `${risky} risky tools`}${scope}, ${prot} protected, ${allowed.length} allowed.`;
console.log(`signafaide check: ${line}`);

if (env.GITHUB_STEP_SUMMARY) {
  const md = ["### signafAIde check", "", line, ""];
  if (unprotected.length) {
    md.push("| Tool | Where | Why | Fix |", "| --- | --- | --- | --- |");
    for (const u of unprotected)
      md.push(`| \`${cell(u.tool)}\` | ${cell(repoPath(u.file))}:${u.line} | ${cell(u.why)} | \`${cell(u.fix)}\` |`);
    md.push("");
  }
  if (allowed.length) {
    md.push("Allowed (reviewed exceptions):", "");
    for (const a of allowed)
      md.push(`- \`${a.tool}\` (${cell(repoPath(a.file))}:${a.line}, ${a.why}): ${cell(a.reason)}`);
    md.push("");
  }
  if (failed)
    md.push(
      'A reviewed exception goes in `signafaide.checks.json`: `"ci": { "allow": [{ "tool": "<name>", "reason": "<why it is safe>" }] }`.',
      "",
    );
  fs.appendFileSync(env.GITHUB_STEP_SUMMARY, md.join("\n") + "\n");
}

process.exit(errors.length ? 2 : failed ? 1 : 0);
