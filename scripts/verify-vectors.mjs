#!/usr/bin/env node
// Runs spec/vectors.json through one or more `signafaide-verify` command lines and checks that
// each gives the vectors' results and that all of them give the same output:
//
//   node scripts/verify-vectors.mjs <signafaide-verify> [<another signafaide-verify> ...]
//
// Each argument is the path of an executable: the Rust binary, the one a `pip install
// signafaide-verify` puts on the PATH, or node_modules/.bin/signafaide-verify. For every pack
// in the vectors (the valid pack, its variants and the tampered packs) it checks, offline:
//   - the exit code (0 PASS, 1 FAIL), the result line and every check's status (§7);
//   - for a tampered pack, the first failed check;
//   - the coverage, telemetry, tool-call checks and rules, as text lines and as --json;
//   - that every command gives the same exit code, stderr, text output and --json output as the
//     first. One part may differ: the wording of a failure's message (the indented "- <item>:
//     <message>" lines and the failures' `message` in --json). §7 fixes the check ids, statuses,
//     result line and report lines; the reason a record fails is worded by each implementation.
//     The failing items themselves must agree.
// The vectors that check public timestamps (check 11: a confirmed proof, a header without its
// proof of work, a header that is not the block's, another Merkle root) run against a local https
// explorer that serves their block headers. Two vectors are skipped and counted: keys over plain
// http (the Rust tests cover it) and a check by the service itself. The key_lifecycle packs run
// too; those with the release's pinned revoked ids (`revoked`) run through the tests' builds only,
// which read the pinned file from SIGNAFAIDE_VERIFY_KEYS_URL_PINNED.
//
// Then the input cases, through every command: service keys that are not {"keys": [...]} (§5),
// a byte order mark, keys behind an https redirect (refused), keys over https, the pinned keys
// with the published list the same, different (KEYS DIFFER, exit 2) or unreachable, --offline,
// content files with draft lines and lines whose content is not an object, a content directory
// holding a JSON array file, --version, and exit 2 for unreadable input.
//
// The local https server runs in a child process with a certificate from a test-only CA made for
// this run with openssl in the run's temporary folder: the CA's private key is deleted as soon as
// it has signed the server's certificate, so nothing else is signed by it, and no key is kept in
// the repository. Only these cases trust it: SSL_CERT_FILE for the Rust binary (and the wheel, the
// same binary), NODE_EXTRA_CA_CERTS for the npm package.
// Exit 1 on any difference.

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as https from "node:https";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** A CA and a certificate for 127.0.0.1 signed by it, made in `tls` with openssl. The CA's private
 * key is deleted once it has signed; `ca.pem`, `server.pem` and `server-key.pem` stay. */
function makeTls(tls) {
  fs.mkdirSync(tls, { recursive: true });
  const cnf = path.join(tls, "openssl.cnf");
  fs.writeFileSync(
    cnf,
    [
      "[req]",
      "distinguished_name = dn",
      "prompt = no",
      "[dn]",
      "CN = signafaide verify-vectors test CA",
      "[v3_ca]",
      "basicConstraints = critical, CA:TRUE",
      "keyUsage = critical, keyCertSign, cRLSign",
      "subjectKeyIdentifier = hash",
      "[srv]",
      "basicConstraints = critical, CA:FALSE",
      "keyUsage = critical, digitalSignature, keyEncipherment",
      "extendedKeyUsage = serverAuth",
      "subjectAltName = IP:127.0.0.1, DNS:localhost",
      "",
    ].join("\n"),
  );
  const f = (n) => path.join(tls, n);
  const openssl = (args) => {
    const r = spawnSync("openssl", args, { encoding: "utf8" });
    if (r.error || r.status !== 0)
      throw new Error(`verify-vectors: openssl ${args[0]} failed (openssl is needed): ${r.error?.message ?? r.stderr}`);
  };
  openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    f("ca.key"),
    "-out",
    f("ca.pem"),
    "-days",
    "2",
    "-config",
    cnf,
    "-extensions",
    "v3_ca",
  ]);
  openssl([
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    f("server-key.pem"),
    "-out",
    f("server.csr"),
    "-subj",
    "/CN=127.0.0.1",
    "-config",
    cnf,
  ]);
  openssl([
    "x509",
    "-req",
    "-in",
    f("server.csr"),
    "-CA",
    f("ca.pem"),
    "-CAkey",
    f("ca.key"),
    "-set_serial",
    "1",
    "-out",
    f("server.pem"),
    "-days",
    "2",
    "-extfile",
    cnf,
    "-extensions",
    "srv",
  ]);
  fs.rmSync(f("ca.key"));
  fs.rmSync(f("server.csr"));
}

// The local https server: `--serve <routes.json> <tls folder>` answers each path from the routes file (read on
// every request): {"<path>": {"status": 200, "body": "...", "location": "..."}}; else 404.
if (process.argv[2] === "--serve") {
  const routes = process.argv[3];
  const TLS = process.argv[4];
  const server = https.createServer(
    { key: fs.readFileSync(path.join(TLS, "server-key.pem")), cert: fs.readFileSync(path.join(TLS, "server.pem")) },
    (req, res) => {
      const r = JSON.parse(fs.readFileSync(routes, "utf8"))[req.url.split("?")[0]];
      if (!r) return res.writeHead(404).end();
      res.writeHead(r.status ?? 200, r.location ? { location: r.location } : {}).end(r.body ?? "");
    },
  );
  server.listen(0, "127.0.0.1", () => console.log(server.address().port));
  process.stdin.resume();
  process.stdin.on("end", () => process.exit(0));
} else await main();

async function main() {
  // Release builds as plain arguments; `--test <cmd>` adds a tests' build (Rust feature
  // test-keys-url, verify/dist-test/cli.js), the only kind that reads SIGNAFAIDE_VERIFY_KEYS_URL.
  const commands = [];
  const testCommands = [];
  for (let i = 2; i < process.argv.length; i++)
    if (process.argv[i] === "--test") testCommands.push(path.resolve(process.argv[++i]));
    else commands.push(path.resolve(process.argv[i]));
  if (!commands.length) {
    console.error(
      "usage: node scripts/verify-vectors.mjs <signafaide-verify> [<another> ...] [--test <a tests' build> ...]",
    );
    process.exit(2);
  }
  for (const c of [...commands, ...testCommands])
    if (!fs.existsSync(c)) {
      console.error(`verify-vectors: ${c} does not exist`);
      process.exit(2);
    }

  const v = JSON.parse(fs.readFileSync(path.join(root, "spec/vectors.json"), "utf8"));
  const version = fs.readFileSync(path.join(root, "verifier/Cargo.toml"), "utf8").match(/^version = "([^"]+)"/m)[1];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "signafaide-verify-vectors-"));
  const problems = [];
  let n = 0;
  const write = (name, value) => {
    const p = path.join(dir, `${n}-${name}.json`);
    fs.writeFileSync(p, JSON.stringify(value));
    return p;
  };
  // Every command runs with the same environment: no CA override unless a case trusts the test CA.
  const baseEnv = { ...process.env };
  for (const k of [
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "SIGNAFAIDE_VERIFY_KEYS_URL",
    "SIGNAFAIDE_VERIFY_KEYS_URL_PINNED",
  ])
    delete baseEnv[k];
  const TLS = path.join(dir, "tls");
  makeTls(TLS);
  const CA = path.join(TLS, "ca.pem");
  const trustTest = (extra = {}) => ({ ...baseEnv, SSL_CERT_FILE: CA, NODE_EXTRA_CA_CERTS: CA, ...extra });
  const run = (cmd, args, env = baseEnv) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", env });
    if (r.error) throw r.error;
    return { code: r.status, stdout: r.stdout, stderr: r.stderr };
  };
  /** Output with failure messages (not their items) left out: see above. */
  const sameText = (text) => text.replace(/^( {6}- .*?): .*$/gm, "$1");
  /** stderr with the reason a published key list could not be read left out: that wording comes
   * from each implementation's HTTP library (the address and the outcome must agree). */
  const sameStderr = (text) =>
    text.replace(/(could not read the published service keys at \S+) \(.*\); /g, "$1 (...); ");
  const sameJson = (j) => ({
    ...j,
    checks: (j.checks ?? []).map((c) => ({
      ...c,
      failures: (c.failures ?? []).map((f) => ({ ...f, message: undefined })),
    })),
  });
  const lines = (text, prefix) =>
    text
      .split("\n")
      .filter((l) => l.startsWith(prefix))
      .map((l) => l.slice(prefix.length));

  // The local https server.
  const routesFile = path.join(dir, "routes.json");
  const routes = {};
  const setRoute = (p, r) => {
    routes[p] = r;
    fs.writeFileSync(routesFile, JSON.stringify(routes));
  };
  setRoute("/", { body: "" });
  const server = spawn(process.execPath, [fileURLToPath(import.meta.url), "--serve", routesFile, TLS], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  const port = await new Promise((resolve, reject) => {
    server.stdout.once("data", (d) => resolve(Number(String(d).trim())));
    server.once("exit", (code) => reject(new Error(`the local https server stopped (${code})`)));
  });
  const base = `https://127.0.0.1:${port}`;
  let explorers = 0;

  /** The command-line arguments for a vector case, its environment, or why it cannot be run. */
  function argsFor(c) {
    if (c.service_keys_plain_http) return "service keys over plain http";
    if (c.by_service) return "a check by the service";
    n++;
    const args = [write("pack", c.pack)];
    if (c.trust_embedded_keys) args.push("--trust-embedded-keys");
    else args.push("--keys", write("keys", c.keys ?? v.keys_document));
    if (c.agent_keys !== null) args.push("--agent-keys", write("agent-keys", c.agent_keys ?? v.agent_keys_document));
    if (c.trust_embedded_agent_keys) args.push("--trust-embedded-agent-keys");
    if (c.head) args.push("--head", write("head", c.head));
    // The release's pinned revoked ids: only the tests' builds read another pinned file
    // (SIGNAFAIDE_VERIFY_KEYS_URL_PINNED), so these cases run through them alone.
    const pinnedEnv = c.revoked
      ? {
          SIGNAFAIDE_VERIFY_KEYS_URL_PINNED: write("pinned", {
            keys: [],
            revoked: c.revoked.map((key_id) => ({ key_id })),
          }),
        }
      : null;
    if (!c.bitcoin) {
      args.push("--offline");
      return pinnedEnv ? { args, env: { ...baseEnv, ...pinnedEnv }, cmds: testCommands } : { args };
    }
    // Check 11 against the local explorer, which serves this vector's block headers.
    const at = `/explorer-${++explorers}`;
    for (const [h, b] of Object.entries(c.bitcoin)) {
      setRoute(`${at}/block-height/${h}`, { body: b.hash });
      setRoute(`${at}/block/${b.hash}/header`, { body: b.header });
    }
    args.push("--timestamp-check", `${base}${at}`);
    return { args, env: trustTest() };
  }

  /** Runs one case through every command; checks the first against `expect(text, json, code)`. */
  function check(name, args, expect, env = baseEnv, cmds = commands) {
    if (!cmds.length) return false; // a case for the tests' builds, when none were given
    const [first, ...rest] = cmds.map((cmd) => ({
      cmd,
      text: run(cmd, args, env),
      json: run(cmd, [...args, "--json"], env),
    }));
    let json;
    try {
      json = JSON.parse(first.json.stdout);
    } catch {
      problems.push(`${name}: ${first.cmd} --json did not print JSON: ${first.json.stdout}${first.json.stderr}`);
      return;
    }
    for (const why of expect(first.text, json)) problems.push(`${name}: ${first.cmd}: ${why}`);
    for (const o of rest) {
      if (o.text.code !== first.text.code)
        problems.push(`${name}: exit ${o.text.code} from ${o.cmd}, ${first.text.code} from ${first.cmd}`);
      if (sameText(o.text.stdout) !== sameText(first.text.stdout))
        problems.push(
          `${name}: the text output of ${o.cmd} differs from ${first.cmd}:\n${o.text.stdout}\n---\n${first.text.stdout}`,
        );
      if (sameStderr(o.text.stderr) !== sameStderr(first.text.stderr))
        problems.push(
          `${name}: stderr of ${o.cmd} differs from ${first.cmd}:\n${o.text.stderr}\n---\n${first.text.stderr}`,
        );
      let other;
      try {
        other = JSON.parse(o.json.stdout);
      } catch {
        problems.push(`${name}: ${o.cmd} --json did not print JSON: ${o.json.stdout}${o.json.stderr}`);
        continue;
      }
      const [a, b] = [sameJson(other), sameJson(json)];
      const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => !isDeepStrictEqual(a[k], b[k]));
      if (keys.length)
        problems.push(`${name}: the --json output of ${o.cmd} differs from ${first.cmd} in ${keys.join(", ")}`);
    }
    return true;
  }

  /** What a valid pack or variant must show (its `expect`). */
  /** The note a result line carries when --keys gives other keys than the pinned set (the vectors'
   * keys always are), taken out to compare with the vectors; the input cases below check it. */
  const NOT_PINNED = "service keys from --keys differ from the pinned set";
  const unmark = (l) => (l ?? "").replace(` (${NOT_PINNED})`, "").replace(`; ${NOT_PINNED})`, ")");
  const matches = (e) => (text, json) => {
    const out = [];
    const code = e.result === "PASS" ? 0 : 1;
    if (text.code !== code) out.push(`exit ${text.code}, want ${code}: ${text.stdout}${text.stderr}`);
    const last = unmark(text.stdout.trimEnd().split("\n").at(-1));
    if (last !== e.result_line) out.push(`result line "${last}", want "${e.result_line}"`);
    if (unmark(json.result_line) !== e.result_line) out.push(`--json result_line "${json.result_line}"`);
    // The vectors write a confirmed public timestamp as its value (confirmed@<block>), else the status.
    const got = Object.fromEntries(
      (json.checks ?? []).map((c) => [
        c.id,
        c.status === "pass" && c.value?.startsWith("confirmed@") ? c.value : c.status,
      ]),
    );
    if (!isDeepStrictEqual(got, e.checks)) out.push(`checks ${JSON.stringify(got)}, want ${JSON.stringify(e.checks)}`);
    if (Object.keys(got).join() !== v.check_ids.join()) out.push(`check ids in order ${Object.keys(got).join()}`);
    if (e.failed_items) {
      const failed = Object.fromEntries(
        (json.checks ?? []).filter((c) => c.failures?.length).map((c) => [c.id, c.failures.map((f) => f.item)]),
      );
      if (!isDeepStrictEqual(failed, e.failed_items))
        out.push(`failed items ${JSON.stringify(failed)}, want ${JSON.stringify(e.failed_items)}`);
    }
    for (const [key, prefix] of [
      ["coverage", "coverage: "],
      ["telemetry", "telemetry: "],
      ["tool_call_checks", "tool-call checks: "],
      ["rules", "rules: "],
    ]) {
      if (!isDeepStrictEqual(lines(text.stdout, prefix), e[`${key}_lines`])) out.push(`"${prefix}" lines differ`);
      if (!isDeepStrictEqual(json[key], e[key])) out.push(`--json ${key} differs`);
    }
    return out;
  };

  const skipped = {};
  const cases = [
    ["the valid pack", { pack: v.pack.pack, expect: v.pack.expect }],
    ...v.variants.map((c) => [c.name, c]),
    // Key revocation and rotation (spec §5, §7), the same cases every implementation runs.
    ...v.key_lifecycle.packs.map((c) => [
      `key lifecycle: ${c.name}`,
      { ...c, pack: c.base === "pack" ? v.pack.pack : v.variants.find((x) => x.name === c.base).pack },
    ]),
  ];
  let ran = 0;
  for (const [name, c] of cases) {
    const args = argsFor(c);
    if (typeof args === "string") {
      skipped[args] = (skipped[args] ?? 0) + 1;
      continue;
    }
    // Counted only when it ran: a case for the tests' builds is skipped (and said) without them.
    if (check(`variant "${name}"`, args.args, matches(c.expect), args.env, args.cmds)) ran++;
    else
      skipped["the release's pinned revoked ids: the tests' builds only (--test)"] =
        (skipped["the release's pinned revoked ids: the tests' builds only (--test)"] ?? 0) + 1;
  }
  for (const t of v.tampered) {
    const args = argsFor(t);
    if (typeof args === "string") {
      skipped[args] = (skipped[args] ?? 0) + 1;
      continue;
    }
    check(
      `tampered "${t.tamper}"`,
      args.args,
      (text, json) => {
        const out = [];
        if (text.code !== 1) out.push(`exit ${text.code}, want 1: ${text.stdout}${text.stderr}`);
        if (!text.stdout.trimEnd().split("\n").at(-1).startsWith("FAIL")) out.push("the result line is not FAIL");
        const first = (json.checks ?? []).find((c) => c.status === "fail")?.id;
        if (first !== t.check) out.push(`first failed check ${first}, want ${t.check}`);
        return out;
      },
      args.env,
    );
    ran++;
  }

  // The input cases.
  /** Every command exits 2 and says `says` on stderr; with `same`, every stderr is identical. */
  function refused(name, args, says, env = baseEnv, same = false, cmds = commands) {
    if (!cmds.length) return;
    const outs = cmds.map((cmd) => ({ cmd, r: run(cmd, args, env) }));
    for (const { cmd, r } of outs) {
      if (r.code !== 2) problems.push(`${name}: ${cmd} exit ${r.code}, want 2: ${r.stderr}`);
      else if (!r.stderr.includes(says)) problems.push(`${name}: ${cmd} does not say "${says}": ${r.stderr}`);
    }
    if (same && outs.some((o) => o.r.stderr !== outs[0].r.stderr))
      problems.push(`${name}: stderr differs:\n${outs.map((o) => `${o.cmd}: ${o.r.stderr}`).join("---\n")}`);
    inputs++;
  }
  /** Every command gives the same output, and the first one's report meets `want(text, json)`. */
  function agrees(name, args, want, env = baseEnv, cmds = commands) {
    if (!cmds.length) return;
    check(name, args, (text, json) => want(text, json), env, cmds);
    inputs++;
  }
  let inputs = 0;
  n++;
  const pack = write("pack", v.pack.pack);
  const keysDoc = write("keys", v.keys_document);
  const agentKeys = write("agent-keys", v.agent_keys_document);
  const status = (json, id) => json.checks?.find((c) => c.id === id);
  const passes = (text, json) =>
    text.code === 0 && unmark(json.result_line) === v.pack.expect.result_line
      ? []
      : [`want PASS, got ${text.code}: ${text.stdout}`];

  // --keys with other keys than the pinned set: the result line says so (text and --json); the
  // pinned set itself, given with --keys, carries no note.
  const pinnedFile = path.join(root, "verifier/service-keys.json");
  agrees(
    "--keys other than the pinned set: the result line says so",
    [pack, "--keys", keysDoc, "--agent-keys", agentKeys, "--offline"],
    (text, json) => {
      const want = `PASS (${NOT_PINNED}): ${v.pack.expect.result_line.slice("PASS: ".length)}`;
      const last = text.stdout.trimEnd().split("\n").at(-1);
      return [
        ...(last === want ? [] : [`result line "${last}", want "${want}"`]),
        ...(json.result_line === want ? [] : [`--json result_line "${json.result_line}"`]),
        ...(json.service_keys_pinned_set === false ? [] : [`service_keys_pinned_set ${json.service_keys_pinned_set}`]),
      ];
    },
  );
  // The pinned entries changed in any way (a valid_to added, a valid_from moved, a revocation)
  // are a difference too; a key the supplied document revokes is never used.
  {
    const pinnedK = JSON.parse(fs.readFileSync(pinnedFile, "utf8")).keys[0];
    const revokedOf = (k) => [{ key_id: k.key_id, revoked_at: "2026-12-01T00:00:00.000Z", reason: "compromised" }];
    for (const [name, doc] of [
      ["a valid_to added", { keys: [{ ...pinnedK, valid_to: "2026-12-01T00:00:00.000Z" }] }],
      ["a valid_from moved", { keys: [{ ...pinnedK, valid_from: "2026-11-14T17:36:25.017Z" }] }],
      ["a revocation", { keys: [pinnedK], revoked: revokedOf(pinnedK) }],
    ])
      agrees(
        `--keys with the pinned entries and ${name}: they differ`,
        [pack, "--keys", write(`keys-${name.replace(/ /g, "-")}`, doc), "--agent-keys", agentKeys, "--offline"],
        (text, json) =>
          json.service_keys_pinned_set === false && json.result_line.includes(NOT_PINNED)
            ? []
            : [`no difference said: ${json.result_line}`],
      );
    const vk = v.keys_document.keys[0];
    agrees(
      "--keys whose document revokes the signing key: its batches fail",
      [
        pack,
        "--keys",
        write("keys-revoking", { ...v.keys_document, revoked: revokedOf(vk) }),
        "--agent-keys",
        agentKeys,
        "--offline",
      ],
      (text, json) =>
        text.code === 1 && status(json, "batch_sig")?.status === "fail"
          ? []
          : [`want batch_sig to fail: ${text.stdout}`],
    );
    agrees(
      "--keys revoking the signing key with null revoked_at and reason",
      [
        pack,
        "--keys",
        write("keys-revoking-nulls", {
          ...v.keys_document,
          revoked: [{ key_id: vk.key_id, revoked_at: null, reason: null }],
        }),
        "--agent-keys",
        agentKeys,
        "--offline",
      ],
      (text, json) =>
        text.code === 1 && status(json, "batch_sig")?.status === "fail"
          ? []
          : [`want batch_sig to fail: ${text.stdout}`],
    );
    // The same loader everywhere: a revoked entry needs only its key_id, other fields are ignored,
    // and the revoked key stays in the list that keys_hash is computed from.
    agrees(
      "--keys revoking the signing key by key_id only, with a field it does not know",
      [
        pack,
        "--keys",
        write("keys-revoking-min", { ...v.keys_document, revoked: [{ key_id: vk.key_id, scope: "later field" }] }),
        "--agent-keys",
        agentKeys,
        "--offline",
      ],
      (text, json) =>
        text.code === 1 &&
        status(json, "batch_sig")?.status === "fail" &&
        !text.stdout.includes("keys_hash does not match")
          ? []
          : [`want batch_sig to fail and keys_hash to match: ${text.stdout}`],
    );
    refused(
      "--keys with a malformed revoked entry",
      [
        pack,
        "--keys",
        write("keys-bad-revoked", { ...v.keys_document, revoked: [{ when: "now" }] }),
        "--agent-keys",
        agentKeys,
        "--offline",
      ],
      "",
    );
  }
  // A value from the pack can never make a line of its own: a project name holding a newline and
  // a result line is written escaped on the header line, and the one result line (with the --keys
  // qualifier, when there is one) stays the last line.
  {
    const named = v.variants.find((c) => c.pack.project_name);
    const fake = `x\nPASS: 12 of 12 checks passed; export of every agent, all records, generated 2026-11-13T12:00:00.000Z`;
    const forged = write("injected-name", { ...named.pack, project_name: fake });
    const onlyLast = (text, header = true) => {
      const lines = text.stdout.trimEnd().split("\n");
      const results = lines.filter((l) => /^(PASS|FAIL)\b/.test(l));
      return [
        ...(results.length === 1 && results[0] === lines.at(-1)
          ? []
          : [`result-like lines: ${JSON.stringify(results)}`]),
        // A raw newline from the pack never shows: either the pack is refused before its header
        // is printed, or the value is written escaped (\u000a) inside its own line.
        ...(header &&
        lines.some((l) => l.startsWith("signafAIde pack of project")) &&
        !lines[0].includes("\\u000aPASS: 12 of 12")
          ? [`the name is not escaped: ${lines[0]}`]
          : []),
        ...(text.code === 1 && lines.at(-1).startsWith("FAIL")
          ? []
          : [`want FAIL (the export statement no longer verifies): ${lines.at(-1)}`]),
      ];
    };
    agrees(
      "a project name holding a newline and a result line",
      [forged, "--keys", pinnedFile, "--agent-keys", agentKeys, "--offline"],
      onlyLast,
    );
    // An envelope field whose name holds a newline and a result line: it is echoed in check 1's
    // failure message, escaped.
    const tampered = JSON.parse(JSON.stringify(v.pack.pack));
    tampered.records[0].envelope[fake] = 1;
    agrees(
      "an envelope field name holding a newline and a result line",
      [write("injected-field", tampered), "--keys", pinnedFile, "--agent-keys", agentKeys, "--offline"],
      (text) => {
        const out = onlyLast(text, false);
        return text.stdout.includes("x\\u000aPASS: 12 of 12")
          ? out
          : [...out, `the field name is not shown escaped: ${text.stdout}`];
      },
    );
    agrees(
      "the same, with keys that differ from the pinned set",
      [forged, "--keys", keysDoc, "--agent-keys", agentKeys, "--offline"],
      (text, json) => [
        ...onlyLast(text),
        ...(json.result_line.startsWith(`FAIL (${NOT_PINNED}): `) ? [] : [`--json result_line ${json.result_line}`]),
        ...(text.stdout.trimEnd().split("\n").at(-1) === json.result_line
          ? []
          : ["the text result line is not the --json one"]),
      ],
    );
  }
  agrees(
    "--keys with the pinned set: no note",
    [pack, "--keys", pinnedFile, "--agent-keys", agentKeys, "--offline"],
    (text, json) =>
      json.service_keys_pinned_set === true && !text.stdout.includes(NOT_PINNED)
        ? []
        : [`a note or service_keys_pinned_set ${json.service_keys_pinned_set}: ${text.stdout}`],
  );

  // Service keys must be {"keys": [...]} (§5), and JSON with a byte order mark is not read.
  refused(
    "keys as a bare list",
    [pack, "--keys", write("keys-list", v.keys_document.keys), "--agent-keys", agentKeys, "--offline"],
    "keys",
  );
  const bom = (name, file) => {
    const p = path.join(dir, `bom-${name}.json`);
    fs.writeFileSync(p, "\uFEFF" + fs.readFileSync(file, "utf8"));
    return p;
  };
  refused(
    "keys with a byte order mark",
    [pack, "--keys", bom("keys", keysDoc), "--agent-keys", agentKeys, "--offline"],
    "",
  );
  refused(
    "a pack with a byte order mark",
    [bom("pack", pack), "--keys", keysDoc, "--agent-keys", agentKeys, "--offline"],
    "",
  );

  // Keys over https: read; behind a redirect: refused, never followed.
  setRoute("/keys.json", { body: JSON.stringify(v.keys_document) });
  setRoute("/moved/keys.json", { status: 302, location: `${base}/keys.json` });
  agrees(
    "keys over https",
    [pack, "--keys", `${base}/keys.json`, "--agent-keys", agentKeys, "--offline"],
    passes,
    trustTest(),
  );
  refused(
    "keys behind a redirect",
    [pack, "--keys", `${base}/moved/keys.json`, "--agent-keys", agentKeys, "--offline"],
    "answered a redirect (HTTP 302); redirects are not followed",
    trustTest(),
    true,
  );

  // Keys with a byte order mark over https: refused by every build, as from a file.
  setRoute("/bom/keys.json", { body: "\uFEFF" + JSON.stringify(v.keys_document) });
  refused(
    "keys with a byte order mark over https",
    [pack, "--keys", `${base}/bom/keys.json`, "--agent-keys", agentKeys, "--offline"],
    "",
    trustTest(),
  );

  // The pinned keys (no --keys). The vectors' packs are not signed by the hosted witness's pinned
  // keys, so these runs fail check 6: what is compared is the line on the keys and the exit code.
  const pinnedText = fs.readFileSync(path.join(root, "verifier/service-keys.json"), "utf8");
  const pinnedDoc = JSON.parse(pinnedText);
  const pinned0 = pinnedDoc.keys[0];
  const PUBLISHED = "https://signafaide.co.uk/.well-known/signafaide-keys.json";
  const pinnedArgs = [pack, "--agent-keys", agentKeys];
  const keysLine = (text) => text.stdout.trimEnd().split("\n").at(-2) ?? "";
  const keysLineIs = (want, word) => (text, json) => [
    ...(keysLine(text) === `service keys: ${want}`
      ? []
      : [`keys line "${keysLine(text)}", want "service keys: ${want}"`]),
    ...(json.service_keys_cross_check === word
      ? []
      : [`service_keys_cross_check ${json.service_keys_cross_check}, want ${word}`]),
    ...(text.code === 1 ? [] : [`exit ${text.code}, want 1 (check 6 fails with the pinned keys)`]),
  ];
  const pinnedIn = `pinned in signafaide-verify ${version}`;
  agrees(
    "pinned keys, offline",
    [...pinnedArgs, "--offline"],
    keysLineIs(`${pinnedIn}, not cross-checked (--offline)`, "not_done_offline"),
  );
  agrees(
    "pinned keys, offline (tests' builds)",
    [...pinnedArgs, "--offline"],
    keysLineIs(`${pinnedIn}, not cross-checked (--offline)`, "not_done_offline"),
    baseEnv,
    testCommands,
  );

  // A release build ignores SIGNAFAIDE_VERIFY_KEYS_URL: it names only the hosted list (checked
  // online if it can be reached, else not cross-checked), never the address in the variable.
  setRoute("/published/other.json", { body: JSON.stringify(v.keys_document) });
  for (const cmd of commands) {
    const r = run(cmd, pinnedArgs, trustTest({ SIGNAFAIDE_VERIFY_KEYS_URL: `${base}/published/other.json` }));
    const line = r.stdout.trimEnd().split("\n").at(-2) ?? "";
    if (
      r.code === 2 ||
      r.stdout.includes(base) ||
      r.stderr.includes(base) ||
      !line.startsWith(`service keys: ${pinnedIn}, `) ||
      !(line.includes(PUBLISHED) || line.endsWith("(published list unreachable)"))
    )
      problems.push(`a release build used SIGNAFAIDE_VERIFY_KEYS_URL: ${cmd} exit ${r.code}: ${line}\n${r.stderr}`);
    inputs++;
  }

  // The tests' builds: the check of the pinned keys against a list served here (§7).
  if (testCommands.length) {
    const serve = (name, doc, extra = {}) => {
      setRoute(`/published/${name}.json`, { body: typeof doc === "string" ? doc : JSON.stringify(doc), ...extra });
      return trustTest({ SIGNAFAIDE_VERIFY_KEYS_URL: `${base}/published/${name}.json` });
    };
    const listed = (name) => `${base}/published/${name}.json`;
    const other = v.keys_document.keys[0];
    agrees(
      "published list the same",
      pinnedArgs,
      keysLineIs(`${pinnedIn}, cross-checked with ${listed("same")}`, "matched"),
      serve("same", pinnedText),
      testCommands,
    );
    agrees(
      "published list with a newer key (rotation)",
      pinnedArgs,
      keysLineIs(
        `${pinnedIn}, cross-checked with ${listed("superset")}; newer keys there, not pinned in this release: ${other.key_id} (a pack made since one of them became valid needs a newer signafaide-verify)`,
        "matched",
      ),
      serve("superset", { keys: [...pinnedDoc.keys, other] }),
      testCommands,
    );
    agrees(
      "published list with a field this release does not know",
      pinnedArgs,
      keysLineIs(`${pinnedIn}, cross-checked with ${listed("extra-field")}`, "matched"),
      serve("extra-field", {
        keys: [{ ...pinned0, algorithm: "ed25519", note: "a later field" }],
        published: "2026-12-01",
      }),
      testCommands,
    );
    refused(
      "published list without the pinned key",
      pinnedArgs,
      `KEYS DIFFER`,
      serve("other", v.keys_document),
      true,
      testCommands,
    );
    // Retired (a valid_to in the list): allowed, and applied to the verification.
    agrees(
      "published list with the pinned key retired: passes, applied",
      pinnedArgs,
      keysLineIs(
        `${pinnedIn}, cross-checked with ${listed("retired")}; ${pinned0.key_id} retired there at 2026-12-01T00:00:00.000Z, applied; newer keys there, not pinned in this release: ${other.key_id} (a pack made since one of them became valid needs a newer signafaide-verify)`,
        "matched",
      ),
      serve("retired", { keys: [{ ...pinned0, valid_to: "2026-12-01T00:00:00.000Z" }, other] }),
      testCommands,
    );
    // A malformed `revoked` there: KEYS DIFFER.
    // A `revoked` that is not a list of entries with a key_id is malformed: it fails.
    for (const [name, revoked] of [
      ["an object", { key_id: pinned0.key_id }],
      ["null", null],
      ["an entry without a key_id", [{ reason: "compromised" }]],
      ["an entry with a number for revoked_at", [{ key_id: pinned0.key_id, revoked_at: 5 }]],
    ])
      refused(
        `published list whose revoked is ${name}`,
        pinnedArgs,
        "its `revoked` is not a list of entries with a key_id",
        serve(`revoked-${name.replace(/ /g, "-")}`, { keys: [pinned0], revoked }),
        true,
        testCommands,
      );
    // Revoked there: applied and named; the run goes on (the key stays in the list and in
    // keys_hash, and no signature by it verifies). An unknown field in the entry is ignored.
    agrees(
      "published list with the pinned key revoked: applied, the run goes on",
      pinnedArgs,
      keysLineIs(
        `${pinnedIn}, cross-checked with ${listed("revoked")}; ${pinned0.key_id} revoked there, applied (no signature by it verifies); newer keys there, not pinned in this release: ${other.key_id} (a pack made since one of them became valid needs a newer signafaide-verify)`,
        "matched",
      ),
      serve("revoked", {
        keys: [pinned0, other],
        revoked: [{ key_id: pinned0.key_id, reason: "compromised", scope: "later field" }],
      }),
      testCommands,
    );
    // Null revoked_at and reason read as absent, in every verifier (the core's Option fields).
    agrees(
      "published list revoking the pinned key with null revoked_at and reason: applied",
      pinnedArgs,
      keysLineIs(
        `${pinnedIn}, cross-checked with ${listed("revoked-nulls")}; ${pinned0.key_id} revoked there, applied (no signature by it verifies)`,
        "matched",
      ),
      serve("revoked-nulls", {
        keys: [pinned0],
        revoked: [{ key_id: pinned0.key_id, revoked_at: null, reason: null }],
      }),
      testCommands,
    );
    // A valid_to that is not a protocol time string: malformed, KEYS DIFFER (§7).
    for (const [name, to] of [
      ["a number", 5],
      ["not a time", "tomorrow"],
      ["an object", {}],
    ])
      refused(
        `published list whose pinned entry has a valid_to that is ${name}`,
        pinnedArgs,
        `${pinned0.key_id} has an invalid valid_to there`,
        serve(`valid-to-${name.replace(/ /g, "-")}`, { keys: [{ ...pinned0, valid_to: to }] }),
        true,
        testCommands,
      );
    refused(
      "published list with the pinned key's bytes changed",
      pinnedArgs,
      `${pinned0.key_id} has another public key there`,
      serve("changed", { keys: [{ ...pinned0, public_key: other.public_key }] }),
      true,
      testCommands,
    );
    const unreachable = keysLineIs(`${pinnedIn}, not cross-checked (published list unreachable)`, "unreachable");
    agrees(
      "published list not found: the pinned keys, said",
      pinnedArgs,
      unreachable,
      trustTest({ SIGNAFAIDE_VERIFY_KEYS_URL: listed("missing") }),
      testCommands,
    );
    agrees(
      "published list behind a redirect: the pinned keys, said",
      pinnedArgs,
      unreachable,
      serve("moved", "", { status: 301, location: listed("same") }),
      testCommands,
    );
    agrees(
      "published list with a byte order mark: the pinned keys, said",
      pinnedArgs,
      unreachable,
      serve("bom", "\uFEFF" + pinnedText),
      testCommands,
    );
    agrees(
      "published list not JSON: the pinned keys, said",
      pinnedArgs,
      unreachable,
      serve("garbage", "<html>"),
      testCommands,
    );
    // Unreachable keys never turn the public timestamp lookup off.
    const confirmed = v.variants.find((c) => c.bitcoin && c.expect.checks.ots.startsWith("confirmed@"));
    for (const [h, b] of Object.entries(confirmed.bitcoin)) {
      setRoute(`/explorer-keys/block-height/${h}`, { body: b.hash });
      setRoute(`/explorer-keys/block/${b.hash}/header`, { body: b.header });
    }
    agrees(
      "published list not found: the public timestamp is still looked up",
      [
        write("confirmed-pack", confirmed.pack),
        "--agent-keys",
        agentKeys,
        "--timestamp-check",
        `${base}/explorer-keys`,
      ],
      (text, json) => {
        const ots = status(json, "ots");
        return ots?.status === "not_checked" && /offline/i.test(ots.detail ?? "")
          ? [`check 11 was not looked up: ${JSON.stringify(ots)}`]
          : keysLine(text).endsWith("(published list unreachable)")
            ? []
            : [`keys line "${keysLine(text)}"`];
      },
      trustTest({ SIGNAFAIDE_VERIFY_KEYS_URL: listed("missing") }),
      testCommands,
    );
    refused(
      "a plain http published list address",
      pinnedArgs,
      "is not an https:// address",
      { ...baseEnv, SIGNAFAIDE_VERIFY_KEYS_URL: "http://127.0.0.1:9/keys.json" },
      true,
      testCommands,
    );
  }

  // Content from files: the pack without content, the content in local files.
  const bare = JSON.parse(JSON.stringify(v.pack.pack));
  for (const r of bare.records) {
    delete r.content;
    delete r.salt;
  }
  const barePack = write("bare-pack", bare);
  const line = (r) => ({ envelope: r.envelope, key_id: r.key_id, sig: r.sig, content: r.content, salt: r.salt });
  const contentPasses = (text, json) => {
    const c = status(json, "content");
    return text.code === 0 && c?.status === "pass" && c.checked === v.records.length
      ? []
      : [`want check 12 to pass for ${v.records.length} records, got ${JSON.stringify(c)}: ${text.stdout}`];
  };
  const withDraft = path.join(dir, "content-drafts.jsonl");
  fs.writeFileSync(
    withDraft,
    [
      ...v.records.map(line),
      { ...line(v.records[0]), envelope: { ...v.records[0].envelope, name: "draft_only" }, draft: true },
      { ...line(v.records[1]), content: "not an object" },
    ]
      .map((x) => JSON.stringify(x))
      .join("\n"),
  );
  agrees(
    "content with draft lines",
    [barePack, "--keys", keysDoc, "--agent-keys", agentKeys, "--offline", "--content", withDraft],
    contentPasses,
  );
  const contentDir = path.join(dir, "content-dir");
  fs.mkdirSync(path.join(contentDir, "sub"), { recursive: true });
  fs.writeFileSync(path.join(contentDir, "a.jsonl"), JSON.stringify(v.records.slice(0, 2).map(line)));
  fs.writeFileSync(
    path.join(contentDir, "sub", "b.jsonl"),
    v.records
      .slice(2)
      .map((r) => JSON.stringify(line(r)))
      .join("\n"),
  );
  fs.writeFileSync(path.join(contentDir, "notes.txt"), "not read");
  agrees(
    "a content directory with a JSON array file",
    [barePack, "--keys", keysDoc, "--agent-keys", agentKeys, "--offline", "--content", contentDir],
    contentPasses,
  );

  // --version, and exit 2 when the inputs cannot be read.
  for (const cmd of commands) {
    const ver = run(cmd, ["--version"]);
    if (ver.code !== 0 || ver.stdout.trim() !== `signafaide-verify ${version}`)
      problems.push(`${cmd} --version: "${ver.stdout.trim()}" (exit ${ver.code}), want "signafaide-verify ${version}"`);
    for (const args of [
      [],
      [path.join(dir, "missing.json"), "--keys", path.join(dir, "missing.json")],
      ["--no-such-flag"],
    ]) {
      const r = run(cmd, args);
      if (r.code !== 2) problems.push(`${cmd} ${args.join(" ")}: exit ${r.code}, want 2`);
    }
  }
  server.stdin.end();
  fs.rmSync(dir, { recursive: true, force: true });

  console.log(
    `verify-vectors: ${ran} packs run and ${inputs} input cases through ${commands.length} command${commands.length === 1 ? "" : "s"}${testCommands.length ? ` and ${testCommands.length} tests' build${testCommands.length === 1 ? "" : "s"}` : ""}`,
  );
  // Packs not run, on a line of their own, with why.
  const skips = Object.entries(skipped).map(([why, k]) => `${k} (${why})`);
  if (skips.length) console.log(`verify-vectors: packs not run: ${skips.join(", ")}`);
  if (problems.length) {
    for (const p of problems.slice(0, 40)) console.log(`FAIL  ${p}`);
    if (problems.length > 40) console.log(`... and ${problems.length - 40} more`);
    console.log(`\nverify-vectors: ${problems.length} problem${problems.length === 1 ? "" : "s"}`);
    process.exit(1);
  }
  console.log("verify-vectors: every result matches the vectors and every command gives the same output");
}
