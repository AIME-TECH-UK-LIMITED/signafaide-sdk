// The signafAIde GitHub Action, agent runs (optional, off by default):
//   start   before the agent runs: use the API key given, else make a sandbox (test records, no
//           account), and note the time the job's records start from;
//   finish  after the agent ran: send what is waiting, export a verification pack of the job's
//           records, verify it with the open verifier, and write the result to the job summary.
// The action uploads the pack folder as a workflow artifact.
//
// Inputs from the environment (action.yml sets them): SFA_VERSION, SFA_DIR, SFA_API_KEY,
// SFA_AGENT, SFA_FAIL (true: exit 1 when the pack does not verify). For tests,
// SIGNAFAIDE_CI_JS_CLI replaces the command that runs the CLI.

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const env = process.env;
const mode = process.argv[2];
const version = (env.SFA_VERSION || "").trim();
const cwd = path.resolve(env.GITHUB_WORKSPACE || process.cwd(), (env.SFA_DIR || ".").trim() || ".");
const agent = (env.SFA_AGENT || "").trim();
const fail = (env.SFA_FAIL || "true").trim().toLowerCase() !== "false";
const cli = env.SIGNAFAIDE_CI_JS_CLI
  ? env.SIGNAFAIDE_CI_JS_CLI.trim().split(/\s+/)
  : ["npx", "--yes", `signafaide@${version}`];

function sfa(args) {
  const r = spawnSync(cli[0], [...cli.slice(1), ...args], {
    cwd,
    encoding: "utf8",
    env,
    maxBuffer: 256 * 1024 * 1024,
  });
  return {
    code: r.status ?? 2,
    out: (r.stdout || "").trim(),
    err: (r.stderr || r.error?.message || "").trim(),
  };
}
const setEnv = (k, v) => env.GITHUB_ENV && fs.appendFileSync(env.GITHUB_ENV, `${k}=${v}\n`);
const setOutput = (k, v) => env.GITHUB_OUTPUT && fs.appendFileSync(env.GITHUB_OUTPUT, `${k}=${v}\n`);
const summary = (lines) =>
  env.GITHUB_STEP_SUMMARY &&
  fs.appendFileSync(env.GITHUB_STEP_SUMMARY, ["### signafAIde agent runs", "", ...lines, ""].join("\n") + "\n");
const keyIn = (file) => {
  try {
    return fs.readFileSync(file, "utf8").match(/^\s*SIGNAFAIDE_API_KEY\s*=\s*"?([A-Za-z0-9_]+)"?\s*$/m)?.[1] ?? null;
  } catch {
    return null;
  }
};

if (!version && !env.SIGNAFAIDE_CI_JS_CLI) {
  console.error("signafaide action: the version input is empty; set it to a released version, e.g. version: 0.5.8");
  process.exit(2);
}

if (mode === "start") {
  setEnv("SIGNAFAIDE_JOB_STARTED", new Date().toISOString());
  const given = (env.SFA_API_KEY || "").trim();
  if (given) {
    console.log(`::add-mask::${given}`);
    setEnv("SIGNAFAIDE_API_KEY", given);
    console.log("signafaide: this job's records go to the project of the API key given.");
  } else if (env.SIGNAFAIDE_API_KEY || keyIn(path.join(cwd, ".env"))) {
    console.log("signafaide: this job's records go to the project of the API key already set.");
  } else {
    const r = sfa(["init"]);
    if (r.code !== 0) {
      console.error(`signafaide init: ${r.err || r.out}`);
      process.exit(1);
    }
    const key = keyIn(path.join(cwd, ".env"));
    if (key) {
      console.log(`::add-mask::${key}`);
      setEnv("SIGNAFAIDE_API_KEY", key);
    }
    console.log(
      "signafaide: no API key was given, so this job records into a new sandbox (test records, kept 30 days, no account).",
    );
  }
  process.exit(0);
}

if (mode !== "finish") {
  console.error("usage: node runs.mjs start|finish");
  process.exit(2);
}

const outDir = path.join(env.RUNNER_TEMP || os.tmpdir(), "signafaide-pack");
fs.mkdirSync(outDir, { recursive: true });
setOutput("pack-dir", outDir);
const flush = sfa(["flush"]);
const lines = [];
let ok = false;
let records = 0;
const haveKey = !!(env.SIGNAFAIDE_API_KEY || keyIn(path.join(cwd, ".env")));
if (haveKey) {
  const pack = path.join(outDir, "pack.json");
  const exp = sfa([
    "export",
    ...(agent ? ["--agent", agent] : []),
    ...(env.SIGNAFAIDE_JOB_STARTED ? ["--from", env.SIGNAFAIDE_JOB_STARTED] : []),
    "-o",
    pack,
  ]);
  if (exp.code !== 0 || !fs.existsSync(pack)) {
    lines.push(`Not verified: the pack could not be exported (${exp.err || exp.out}).`);
    if (flush.code !== 0) lines.push(`Sending the records first said: ${flush.err || flush.out}`);
  } else {
    sfa(["keys", "export", "-o", path.join(outDir, "agent-keys.json")]);
    const head = path.join(cwd, ".signafaide", "head.json");
    const withHead = fs.existsSync(head);
    if (withHead) fs.copyFileSync(head, path.join(outDir, "head.json"));
    const v = sfa(["verify", pack, ...(withHead ? ["--head", head] : []), "--json"]);
    fs.writeFileSync(path.join(outDir, "verify.json"), v.out + "\n");
    let report = null;
    try {
      report = JSON.parse(v.out);
    } catch {
      /* the result line below says so */
    }
    ok = v.code === 0;
    records = typeof report?.records === "number" ? report.records : 0;
    lines.push(
      `${ok ? "Verified" : "Did not verify"}: ${report?.result_line ?? (v.err || v.out || `verify exit ${v.code}`)}`,
    );
    lines.push(
      `Records in the pack: ${records}${agent ? ` (agent ${agent})` : ""}${env.SIGNAFAIDE_JOB_STARTED ? `, from ${env.SIGNAFAIDE_JOB_STARTED}` : ""}.`,
    );
    lines.push(
      "The pack, the agent keys and the verifier's report are in the artifact signafaide-pack. Each record is co-signed by the witness, outside this runner; check the pack with the service keys published at /.well-known/signafaide-keys.json.",
    );
  }
} else {
  const v = sfa(["verify", "--json"]);
  let report = null;
  try {
    report = JSON.parse(v.out);
  } catch {
    /* the result line below says so */
  }
  ok = v.code === 0;
  records = typeof report?.records === "number" ? report.records : 0;
  lines.push(
    `${ok ? "Verified on this runner" : "Did not verify"}: ${report?.result_line ?? (v.err || v.out || `verify exit ${v.code}`)}`,
  );
  lines.push(
    "No API key: the records stayed on this runner and were not co-signed by the witness, so no pack was exported. Use record-runs: start before the agent step (it makes a sandbox), or give api-key.",
  );
}
for (const l of lines) console.log(`signafaide: ${l}`);
summary(lines);
setOutput("result", ok ? "verified" : "not-verified");
setOutput("records", String(records));
process.exit(!ok && fail ? 1 : 0);
