#!/usr/bin/env node
// Pinned service keys are append-only (spec §5): against the last release's spec/service-keys.json,
// every key is still there with the same key_id, public_key and valid_from, a valid_to, once set,
// never changes, and a revoked id is never removed from `revoked`. New keys and revocations may be
// added. Used by scripts/release-check.mjs and run on its own by
// the release workflow's preflight (which has the tags). Exit 1 when a key was removed or changed.
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const git = (...args) =>
  execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

/** null without an earlier release tag (a shallow checkout); else { tag, problems, added }. */
export function appendOnly() {
  let tag = "";
  try {
    tag = git("describe", "--tags", "--abbrev=0", "--match", "v*", "HEAD");
  } catch {
    return null;
  }
  let beforeDoc;
  try {
    beforeDoc = JSON.parse(git("show", `${tag}:spec/service-keys.json`));
  } catch {
    return null; // the file did not exist then
  }
  const nowDoc = JSON.parse(fs.readFileSync(path.join(root, "spec/service-keys.json"), "utf8"));
  const [before, now] = [beforeDoc.keys, nowDoc.keys];
  const ids = (d) => (Array.isArray(d.revoked) ? d.revoked.map((r) => r.key_id) : []);
  const unrevoked = ids(beforeDoc)
    .filter((id) => !ids(nowDoc).includes(id))
    .map((id) => `${id} was removed from revoked`);
  const problems = before.flatMap((o) => {
    const k = now.find((n) => n.key_id === o.key_id);
    if (!k) return [`${o.key_id} was removed`];
    if (k.public_key !== o.public_key || k.valid_from !== o.valid_from)
      return [`${o.key_id} changed its public_key or valid_from`];
    if (o.valid_to !== null && k.valid_to !== o.valid_to) return [`${o.key_id} changed its valid_to`];
    return [];
  });
  problems.push(...unrevoked);
  return { tag, problems, added: now.length - before.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const r = appendOnly();
  if (!r) {
    // No release tag: a checkout without tags (fetch them: fetch-depth 0), or before the first release.
    console.error(
      "pinned-keys-append-only: no earlier release tag with spec/service-keys.json to compare with (fetch the tags)",
    );
    process.exit(1);
  }
  if (r.problems.length) {
    console.error(`spec/service-keys.json must only gain keys since ${r.tag}: ${r.problems.join("; ")}`);
    process.exit(1);
  }
  console.log(`spec/service-keys.json keeps every key of ${r.tag} unchanged (${r.added} added)`);
}
