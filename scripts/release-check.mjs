#!/usr/bin/env node
// Checks to run before publishing a release: `node scripts/release-check.mjs`. Exit 1 on any
// failure. Offline checks always run; `--offline` skips the package-registry lookups.
//
// 1. The default witness URL in both SDKs is the hosted service, never a loopback address.
// 2. Every version string agrees (npm packages, PyPI package, code, plugin, agent setup).
// 3. The package names coding agents and auditors are told to install are claimed: `signafaide`
//    and `signafaide-mcp` on npm, `signafaide` on PyPI. Until they are, anyone could publish under
//    those names and `npx signafaide verify` (or an agent's MCP config) would run their code.
//    Set NPM_OWNER / PYPI_OWNER to also require that owner.

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const offline = process.argv.includes("--offline");
const problems = [];
const ok = (msg) => console.log(`ok    ${msg}`);
const fail = (msg) => {
  problems.push(msg);
  console.log(`FAIL  ${msg}`);
};

// 1. default witness URL
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
for (const [name, u] of [["TypeScript", jsUrl], ["Python", pyUrl]]) {
  if (!u) fail(`${name} SDK: DEFAULT_URL not found`);
  else if (loopback(u) || !u.startsWith("https://")) fail(`${name} SDK: the default witness URL is ${u}; it must be the hosted https service (dev servers are set with SIGNAFAIDE_URL)`);
  else ok(`${name} SDK default witness: ${u}`);
}

// 2. versions
const versions = {
  "js/package.json": JSON.parse(read("js/package.json")).version,
  "js/mcp/package.json": JSON.parse(read("js/mcp/package.json")).version,
  "js/src/version.ts": read("js/src/version.ts").match(/"([^"]+)"/)?.[1],
  "python/pyproject.toml": read("python/pyproject.toml").match(/^version = "([^"]+)"/m)?.[1],
  "python/src/signafaide/_version.py": read("python/src/signafaide/_version.py").match(/"([^"]+)"/)?.[1],
  "plugin/.mcp.json": read("plugin/.mcp.json").match(/signafaide-mcp@([0-9][^"]*)/)?.[1],
  "plugin/.claude-plugin/plugin.json": JSON.parse(read("plugin/.claude-plugin/plugin.json")).version,
};
const v = versions["js/package.json"];
const off = Object.entries(versions).filter(([, x]) => x !== v);
if (off.length) fail(`versions disagree with js/package.json (${v}): ${off.map(([f, x]) => `${f} ${x}`).join(", ")}`);
else ok(`every version is ${v}`);

// 3. claimed package names
async function lookup(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15_000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
}
if (offline) console.log("skip  package-name checks (--offline)");
else {
  for (const name of ["signafaide", "signafaide-mcp"]) {
    try {
      const doc = await lookup(`https://registry.npmjs.org/${name}`);
      if (!doc) fail(`npm: "${name}" is not claimed; publish (or reserve) it before any docs, agent configs or auditor commands point at it`);
      else if (process.env.NPM_OWNER && !(doc.maintainers ?? []).some((m) => m.name === process.env.NPM_OWNER)) fail(`npm: "${name}" exists but ${process.env.NPM_OWNER} is not a maintainer`);
      else ok(`npm: "${name}" is claimed`);
    } catch (e) {
      fail(`npm: could not check "${name}" (${e.message})`);
    }
  }
  try {
    const doc = await lookup("https://pypi.org/pypi/signafaide/json");
    if (!doc) fail('PyPI: "signafaide" is not claimed; publish (or reserve) it first');
    else if (process.env.PYPI_OWNER && !JSON.stringify(doc.info ?? {}).includes(process.env.PYPI_OWNER)) fail(`PyPI: "signafaide" exists but does not name ${process.env.PYPI_OWNER}`);
    else ok('PyPI: "signafaide" is claimed');
  } catch (e) {
    fail(`PyPI: could not check "signafaide" (${e.message})`);
  }
}

if (problems.length) {
  console.log(`\nrelease check: ${problems.length} problem${problems.length === 1 ? "" : "s"}; do not publish`);
  process.exit(1);
}
console.log("\nrelease check: ready");
