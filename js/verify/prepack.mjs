// Before `npm pack` / `npm publish` of signafaide-verify: the package README and LICENSE (one copy
// each in the repository), and THIRD-PARTY-NOTICES.md with the licence of every package the
// bundle inlines, read from the bundle's own metafile so the list is exactly what was bundled.
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const js = path.resolve(here, "..");
fs.copyFileSync(path.join(js, "../verifier/README.md"), path.join(here, "README.md"));
fs.copyFileSync(path.join(js, "../LICENSE"), path.join(here, "LICENSE"));
const meta = JSON.parse(fs.readFileSync(path.join(here, "dist/metafile-esm.json"), "utf8"));
const pkgs = new Set();
for (const input of Object.keys(meta.inputs)) {
  const m = input.match(/node_modules\/((?:@[^/]+\/)?[^/]+)\//);
  if (m) pkgs.add(m[1]);
}
if (!pkgs.size) throw new Error("the metafile names no bundled package: build with tsup.verify.config.ts first");
const parts = ["# Third-party notices", "", "dist/cli.js includes the following packages.", ""];
for (const name of [...pkgs].sort()) {
  const dir = path.join(js, "node_modules", name);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const file = fs.readdirSync(dir).find((f) => /^licen[cs]e/i.test(f));
  if (!file) throw new Error(`${name} has no licence file`);
  parts.push(`## ${name} ${pkg.version} (${pkg.license})`, "", "```", fs.readFileSync(path.join(dir, file), "utf8").trim(), "```", "");
}
fs.writeFileSync(path.join(here, "THIRD-PARTY-NOTICES.md"), parts.join("\n"));
console.log(`prepack: README.md, LICENSE, THIRD-PARTY-NOTICES.md (${[...pkgs].sort().join(", ")})`);
