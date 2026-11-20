#!/usr/bin/env node
// Checks to run before publishing a release: `node scripts/release-check.mjs`. Exit 1 on any
// failure. Offline checks always run; `--offline` skips the package-registry lookups, and
// `--no-build` checks the verifier binary that is already built instead of building it.
//
// 1. The default witness URL in both SDKs is the hosted service (https://api.signafaide.co.uk),
//    never a loopback address.
// 2. Every version string agrees (npm packages, PyPI package, Rust crates, code, plugin, agent setup),
//    including the standalone verifier packages: `signafaide-verify` on npm (js/verify) and on PyPI
//    (verifier/pyproject.toml, whose version is the verifier crate's).
// 3. The release is new and written up: the version is above the last git tag (or HEAD is that
//    tag), and CHANGELOG.md has an entry for it.
// 4. The verifier binary is built from this source: its --version is the release and its --help
//    lists every flag the source accepts.
// 5. Nothing points at the .com domain, which is not ours: the service is on signafaide.co.uk
//    (api.signafaide.co.uk for the witness). Every file of the repository and every built package
//    file is checked.
// 6. The package names coding agents and auditors are told to install are claimed: `signafaide`,
//    `signafaide-mcp` and `signafaide-verify` on npm, `signafaide` and `signafaide-verify` on PyPI.
//    Until they are, anyone could publish under those names and `npx signafaide-verify` (or an
//    agent's MCP config) would run their code. And `signafaide-verify` at this very version is
//    published on both: `signafaide prove` and `keys export` print `npx signafaide-verify@<version>`
//    and `uvx signafaide-verify@<version>`, so the SDK is released only after the verifier is
//    (release.yml, run by hand on main, publishes it).
//    On npm each name's maintainers must be NPM_OWNER alone (default aimetech). PyPI's API shows no
//    owners: there the trusted publisher (release.yml, environment pypi) binds the name.
// 8. One set of pinned service keys, append-only (§5): never a key removed or its key_id, public
//    key or valid_from changed since the last release, and a valid_to only set once. spec/service-keys.json, the copies in the npm and PyPI SDK
//    packages and the one built into the standalone verifier (verifier/service-keys.json) are
//    the same bytes; verifier/LICENSE (shipped in the verifier's sdist) is LICENSE.
// 7. The standalone verifiers agree: spec/vectors.json through the Rust binary (also what the
//    PyPI wheel holds) and the npm package's bundle (js/verify/dist, built here unless --no-build)
//    gives the vectors' results and the same output from both (scripts/verify-vectors.mjs). Set
//    VERIFY_COMMANDS to more installed `signafaide-verify` paths (separated by the path delimiter,
//    e.g. the one a `pip install` of the built wheel puts in a venv) to include them.

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { appendOnly } from "./pinned-keys-append-only.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const offline = process.argv.includes("--offline");
const noBuild = process.argv.includes("--no-build");
const sh = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...opts,
  }).trim();
const problems = [];
const ok = (msg) => console.log(`ok    ${msg}`);
const fail = (msg) => {
  problems.push(msg);
  console.log(`FAIL  ${msg}`);
};

// 1. default witness URL
const WITNESS = "https://api.signafaide.co.uk";
const loopback = (u) => {
  try {
    const h = new URL(u).hostname.replace(/^\[|\]$/g, "");
    return h === "localhost" || h.endsWith(".localhost") || /^127\./.test(h) || h === "::1" || h === "0.0.0.0";
  } catch {
    return true;
  }
};
const jsUrl = read("js/src/http.ts").match(/export const DEFAULT_URL = "([^"]+)"/)?.[1];
const pyUrl = read("python/src/signafaide/http.py").match(/^DEFAULT_URL = "([^"]+)"/m)?.[1];
for (const [name, u] of [
  ["TypeScript", jsUrl],
  ["Python", pyUrl],
]) {
  if (!u) fail(`${name} SDK: DEFAULT_URL not found`);
  else if (loopback(u) || !u.startsWith("https://"))
    fail(
      `${name} SDK: the default witness URL is ${u}; it must be the hosted https service (dev servers are set with SIGNAFAIDE_URL)`,
    );
  else if (u !== WITNESS) fail(`${name} SDK: the default witness URL is ${u}; the hosted witness is ${WITNESS}`);
  else ok(`${name} SDK default witness: ${u}`);
}

// 2. versions
const versions = {
  "js/package.json": JSON.parse(read("js/package.json")).version,
  "js/mcp/package.json": JSON.parse(read("js/mcp/package.json")).version,
  "js/verify/package.json": JSON.parse(read("js/verify/package.json")).version,
  "js/src/version.ts": read("js/src/version.ts").match(/"([^"]+)"/)?.[1],
  "python/pyproject.toml": read("python/pyproject.toml").match(/^version = "([^"]+)"/m)?.[1],
  "python/src/signafaide/_version.py": read("python/src/signafaide/_version.py").match(/"([^"]+)"/)?.[1],
  "core/Cargo.toml": read("core/Cargo.toml").match(/^version = "([^"]+)"/m)?.[1],
  "verifier/Cargo.toml": read("verifier/Cargo.toml").match(/^version = "([^"]+)"/m)?.[1],
  "gemini-extension.json": JSON.parse(read("gemini-extension.json")).version,
  "gemini-extension.json (server)": read("gemini-extension.json").match(/signafaide-mcp@([0-9][^"]*)/)?.[1],
  ".cursor-plugin/plugin.json": JSON.parse(read(".cursor-plugin/plugin.json")).version,
  "mcp.json": read("mcp.json").match(/signafaide-mcp@([0-9][^"]*)/)?.[1],
  ...Object.fromEntries(
    [...read("README.md").matchAll(/signafaide-mcp@([0-9]+\.[0-9]+\.[0-9]+)/g)].map((m, i) => [
      `README.md (mention ${i + 1})`,
      m[1],
    ]),
  ),
  // The auditor commands and attestation examples name the release they belong to.
  ...Object.fromEntries(
    ["README.md", "verifier/README.md"].flatMap((f) =>
      [...read(f).matchAll(/signafaide-verify(?:@|==)([0-9]+\.[0-9]+\.[0-9]+)/g)].map((m, i) => [
        `${f} (signafaide-verify mention ${i + 1})`,
        m[1],
      ]),
    ),
  ),
};
const v = versions["js/package.json"];
// The PyPI verifier is the Rust binary in a wheel: its version must come from verifier/Cargo.toml.
const pyVerify = read("verifier/pyproject.toml");
if (!/^dynamic = \["version"\]/m.test(pyVerify) || /^version = /m.test(pyVerify))
  fail(
    'verifier/pyproject.toml must take its version from verifier/Cargo.toml (dynamic = ["version"], no version line)',
  );
// The Claude Code plugin pins no package (its MCP server is the hosted one), so it has its own
// version, raised for each change to the plugin. It must never fall behind the packages.
const pluginVersion = JSON.parse(read("plugin/.claude-plugin/plugin.json")).version;
const off = Object.entries(versions).filter(([, x]) => x !== v);
if (off.length) fail(`versions disagree with js/package.json (${v}): ${off.map(([f, x]) => `${f} ${x}`).join(", ")}`);
else ok(`every version is ${v}`);
const parts = (x) => (x ?? "").split(".").map(Number);
const [pp, vp] = [parts(pluginVersion), parts(v)];
if (pp.length !== 3 || pp.some(isNaN) || (pp[0] - vp[0] || pp[1] - vp[1] || pp[2] - vp[2]) < 0)
  fail(
    `plugin/.claude-plugin/plugin.json is ${pluginVersion}, not MAJOR.MINOR.PATCH at or above js/package.json (${v})`,
  );
else ok(`the Claude Code plugin is ${pluginVersion}`);

// 3. the release is new (a version bump since the last tag) and has a changelog entry
const semver = (x) => (/^(\d+)\.(\d+)\.(\d+)$/.exec(x ?? "") ?? []).slice(1).map(Number);
const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
if (semver(v).length !== 3) fail(`the version ${v} is not MAJOR.MINOR.PATCH`);
else {
  let tags = [];
  try {
    tags = sh("git", ["tag", "--list", "v*"])
      .split("\n")
      .filter((t) => semver(t.slice(1)).length === 3)
      .sort((a, b) => cmp(semver(a.slice(1)), semver(b.slice(1))));
  } catch (e) {
    fail(`could not list git tags (${e.message.split("\n")[0]})`);
  }
  const last = tags.at(-1);
  if (!last) ok(`no release tag yet; ${v} would be the first`);
  else {
    const c = cmp(semver(v), semver(last.slice(1)));
    // The same version as the last tag is fine only when nothing changed since that tag.
    const moved = () =>
      sh("git", ["rev-list", "--count", `${last}..HEAD`]) !== "0" || sh("git", ["status", "--porcelain"]) !== "";
    if (c < 0) fail(`the version ${v} is below the last tag ${last}`);
    else if (c === 0 && moved())
      fail(
        `the version is still ${v}, the last tag (${last}), but the source changed since: bump the version, add its CHANGELOG.md entry, and tag it`,
      );
    else ok(c === 0 ? `HEAD is the tagged release ${last}` : `${v} is above the last tag ${last}`);
  }
  const log = fs.existsSync(path.join(root, "CHANGELOG.md")) ? read("CHANGELOG.md") : "";
  const entry = log.split(/^## /m).find((e) => e.startsWith(`v${v} `) || e.startsWith(`v${v}\n`));
  if (!log) fail("CHANGELOG.md is missing");
  else if (!entry || entry.split("\n").filter((l) => l.startsWith("- ")).length === 0)
    fail(`CHANGELOG.md has no entry for v${v} (a "## v${v} (date)" heading with at least one "- " line)`);
  else ok(`CHANGELOG.md has an entry for v${v}`);
}

// 4. the verifier binary is this source
{
  const main = read("verifier/src/main.rs");
  const flags = [...new Set([...main.matchAll(/"(--[a-z][a-z-]*)"/g)].map((m) => m[1]))].filter(
    (f) => f !== "--bitcoin",
  ); // --bitcoin: the old name of --timestamp-check
  const target = process.env.CARGO_TARGET_DIR || path.join(root, "verifier/target");
  const bin = path.join(
    target,
    "release",
    process.platform === "win32" ? "signafaide-verify.exe" : "signafaide-verify",
  );
  try {
    if (!noBuild)
      execFileSync("cargo", ["build", "--release", "--manifest-path", "verifier/Cargo.toml"], {
        cwd: root,
        stdio: ["ignore", "ignore", "inherit"],
      });
    if (!fs.existsSync(bin))
      fail(`the verifier binary ${bin} is not built (run without --no-build, or cargo build --release in verifier/)`);
    else {
      const ver = sh(bin, ["--version"]);
      const help = sh(bin, ["--help"]);
      const lacks = flags.filter((f) => !help.includes(f));
      if (ver !== `signafaide-verify ${v}`)
        fail(`the verifier binary ${bin} says "${ver}", not signafaide-verify ${v}: rebuild it`);
      else if (lacks.length)
        fail(`the verifier binary's --help lacks ${lacks.join(", ")}: it predates the source, rebuild it`);
      else ok(`verifier binary ${noBuild ? "is" : "built,"} ${ver}; --help lists ${flags.length} flags`);
    }
  } catch (e) {
    // An old binary knows neither --version nor --help (exit 2): that is the stale build this check is for.
    fail(
      `the verifier binary could not be built or does not answer --version and --help (${String(e.message).split("\n")[0]}): rebuild it from this source`,
    );
  }
}

// 5. no reference to the .com domain (written in two parts so this file passes its own check)
{
  const wrong = new RegExp("signafaide" + "\\.com\\b");
  const binary = /\.(png|jpe?g|gif|ico|woff2?|wasm|tgz|gz|zip|pdf)$/i;
  let files = [];
  try {
    files = sh("git", ["ls-files", "--cached", "--others", "--exclude-standard"]).split("\n").filter(Boolean);
  } catch (e) {
    fail(`could not list the repository's files (${e.message.split("\n")[0]})`);
  }
  // Built packages are not in git: what npm and PyPI would publish is checked too.
  const walk = (dir) =>
    fs.existsSync(path.join(root, dir))
      ? fs.readdirSync(path.join(root, dir), { recursive: true }).map((f) => path.join(dir, String(f)))
      : [];
  for (const dir of ["js/dist", "js/mcp/dist", "js/verify/dist", "python/dist"]) files.push(...walk(dir));
  const hits = [];
  for (const f of new Set(files)) {
    const p = path.join(root, f);
    if (binary.test(f) || !fs.existsSync(p) || !fs.statSync(p).isFile()) continue;
    fs.readFileSync(p, "utf8")
      .split("\n")
      .forEach((line, i) => {
        if (wrong.test(line)) hits.push(`${f}:${i + 1}`);
      });
  }
  if (hits.length)
    fail(
      `${hits.length} reference${hits.length === 1 ? "" : "s"} to the .com domain, which is not ours (the service is on signafaide.co.uk): ${hits.slice(0, 12).join(", ")}${hits.length > 12 ? ", ..." : ""}`,
    );
  else ok(`no reference to the .com domain in ${new Set(files).size} files (the service is on signafaide.co.uk)`);
}

// 8. one set of pinned keys, one licence, one list of wheels
{
  // release.yml builds a wheel for exactly the tags in verifier/wheel-tags.json.
  const tags = JSON.parse(read("verifier/wheel-tags.json")).tags;
  const built = [...read(".github/workflows/release.yml").matchAll(/\btag: ([a-z0-9_.]+)/g)].map((m) => m[1]);
  if (built.sort().join() !== [...tags].sort().join())
    fail(`release.yml builds wheels for ${built.join(", ")}, but verifier/wheel-tags.json lists ${tags.join(", ")}`);
  else ok(`release.yml builds the ${tags.length} wheels verifier/wheel-tags.json lists`);
  // Append-only (§5), against the last release's file (scripts/pinned-keys-append-only.mjs; without
  // tags, as in CI's shallow checkout, skipped here: the release workflow's preflight runs it with tags).
  {
    const r = appendOnly();
    if (!r) console.log("skip  pinned keys only ever gain keys (no earlier release to compare with)");
    else if (r.problems.length)
      fail(`spec/service-keys.json must only gain keys since ${r.tag}: ${r.problems.join("; ")}`);
    else ok(`spec/service-keys.json keeps every key of ${r.tag} unchanged (${r.added} added)`);
  }
  const keys = [
    "spec/service-keys.json",
    "js/service-keys.json",
    "python/src/signafaide/service-keys.json",
    "verifier/service-keys.json",
  ];
  const off = keys.filter((f) => read(f) !== read(keys[0]));
  if (off.length) fail(`the pinned service keys differ from ${keys[0]}: ${off.join(", ")}`);
  else ok(`the pinned service keys are the same in ${keys.length} files`);
  if (read("verifier/LICENSE") !== read("LICENSE")) fail("verifier/LICENSE is not LICENSE: copy it");
  else ok("verifier/LICENSE is LICENSE");
  // The Rust crates' licences, shipped beside LICENSE in the binaries' release, the wheels and the
  // sdist (release.yml makes it again with cargo-about and fails if it changed).
  const notices = fs.existsSync(path.join(root, "verifier/THIRD-PARTY-NOTICES.md"))
    ? read("verifier/THIRD-PARTY-NOTICES.md")
    : "";
  if (!notices.startsWith("# Third-party notices") || !/Used by: .*\bureq\b/.test(notices))
    fail("verifier/THIRD-PARTY-NOTICES.md is missing or not cargo-about's (cargo about generate, verifier/about.toml)");
  else ok("verifier/THIRD-PARTY-NOTICES.md is there");
}

// 7. the standalone verifiers agree
{
  const exe = process.platform === "win32" ? ".exe" : "";
  const target = process.env.CARGO_TARGET_DIR || path.join(root, "verifier/target");
  const bin = path.join(target, "release", `signafaide-verify${exe}`);
  // The tests' builds: the only ones that read SIGNAFAIDE_VERIFY_KEYS_URL (the pinned-keys cases).
  const testTarget = path.join(root, "verifier/target/test-keys-url");
  const testBin = path.join(testTarget, "release", `signafaide-verify${exe}`);
  const npmBin = path.join(root, "js/verify/dist/cli.js");
  const npmTest = path.join(root, "js/verify/dist-test/cli.js");
  try {
    if (!noBuild) {
      execFileSync("npx", ["tsup", "--config", "tsup.verify.config.ts"], {
        cwd: path.join(root, "js"),
        stdio: ["ignore", "ignore", "inherit"],
      });
      execFileSync(
        "cargo",
        [
          "build",
          "--release",
          "--manifest-path",
          "verifier/Cargo.toml",
          "--features",
          "test-keys-url",
          "--target-dir",
          testTarget,
        ],
        { cwd: root, stdio: ["ignore", "ignore", "inherit"] },
      );
    }
    const more = (process.env.VERIFY_COMMANDS ?? "").split(path.delimiter).filter(Boolean);
    const missing = [bin, npmBin, testBin, npmTest, ...more].filter((c) => !fs.existsSync(c));
    if (missing.length) fail(`the standalone verifiers are not built: ${missing.join(", ")}`);
    else {
      // A release build has no trace of the tests' variable.
      const leaks = [bin, npmBin].filter((f) => fs.readFileSync(f).includes("SIGNAFAIDE_VERIFY_KEYS_URL"));
      if (leaks.length) fail(`a release build reads SIGNAFAIDE_VERIFY_KEYS_URL: ${leaks.join(", ")}`);
      else ok("the release builds have no SIGNAFAIDE_VERIFY_KEYS_URL");
      const out = sh(process.execPath, [
        "scripts/verify-vectors.mjs",
        bin,
        npmBin,
        ...more,
        "--test",
        testBin,
        "--test",
        npmTest,
      ]);
      ok(out.split("\n")[0].replace(/^verify-vectors: /, "standalone verifiers agree on the vectors: "));
    }
  } catch (e) {
    const out = `${e.stdout ?? ""}`.trim().split("\n");
    fail(`the standalone verifiers disagree with the vectors or each other:\n${out.slice(-12).join("\n")}`);
  }
}

// 6. claimed package names
async function lookup(url) {
  const r = await fetch(url, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(15_000),
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
}
// The npm account that owns every package (the registry's `maintainers`). PyPI's JSON has no owner
// roles: there, the release workflow's trusted publisher (release.yml, environment pypi) is what
// ties the name to this repository.
const NPM_OWNER = process.env.NPM_OWNER ?? "aimetech";
if (offline) console.log("skip  package-name checks (--offline)");
else {
  for (const name of ["signafaide", "signafaide-mcp", "signafaide-verify"]) {
    try {
      const doc = await lookup(`https://registry.npmjs.org/${name}`);
      if (!doc)
        fail(
          `npm: "${name}" is not claimed; publish (or reserve) it before any docs, agent configs or auditor commands point at it`,
        );
      else if ((doc.maintainers ?? []).map((m) => m.name).join(",") !== NPM_OWNER)
        fail(
          `npm: "${name}" maintainers are ${(doc.maintainers ?? []).map((m) => m.name).join(", ") || "none"}, not ${NPM_OWNER} alone`,
        );
      else ok(`npm: "${name}" is claimed`);
    } catch (e) {
      fail(`npm: could not check "${name}" (${e.message})`);
    }
  }
  for (const name of ["signafaide", "signafaide-verify"]) {
    try {
      const doc = await lookup(`https://pypi.org/pypi/${name}/json`);
      if (!doc) fail(`PyPI: "${name}" is not claimed; publish (or reserve) it first`);
      else ok(`PyPI: "${name}" is claimed`);
    } catch (e) {
      fail(`PyPI: could not check "${name}" (${e.message})`);
    }
  }
  // The version the SDK tells auditors to run must exist before the SDK goes out: on npm, and on
  // PyPI with every file the release workflow makes (a partial upload is not "published").
  // The wheel tags release.yml builds (verifier/wheel-tags.json; the service's site build reads it too).
  const WHEEL_TAGS = JSON.parse(read("verifier/wheel-tags.json")).tags;
  const expected = [
    ...WHEEL_TAGS.map((t) => `signafaide_verify-${v}-py3-none-${t}.whl`),
    `signafaide_verify-${v}.tar.gz`,
  ];
  try {
    if (await lookup(`https://registry.npmjs.org/signafaide-verify/${v}`))
      ok(`npm: signafaide-verify ${v} is published`);
    else
      fail(
        `npm: signafaide-verify ${v} is not published; the SDK prints npx/uvx signafaide-verify@${v} for auditors, so publish the verifier first (Actions, Release verifier, run on main with ${v})`,
      );
  } catch (e) {
    fail(`npm: could not check signafaide-verify ${v} (${e.message})`);
  }
  try {
    const doc = await lookup(`https://pypi.org/pypi/signafaide-verify/${v}/json`);
    const have = new Set((doc?.urls ?? []).map((u) => u.filename));
    const missing = expected.filter((f) => !have.has(f));
    if (!doc)
      fail(
        `PyPI: signafaide-verify ${v} is not published; publish the verifier first (Actions, Release verifier, run on main with ${v})`,
      );
    else if (missing.length)
      fail(`PyPI: signafaide-verify ${v} lacks ${missing.join(", ")}: re-run the release's publish-pypi job`);
    else ok(`PyPI: signafaide-verify ${v} is published with all ${expected.length} files`);
  } catch (e) {
    fail(`PyPI: could not check signafaide-verify ${v} (${e.message})`);
  }
}

if (problems.length) {
  console.log(`\nrelease check: ${problems.length} problem${problems.length === 1 ? "" : "s"}; do not publish`);
  process.exit(1);
}
console.log("\nrelease check: ready");
