/**
 * Read-only text for the MCP tools `signafaide_explain_ruling` and `signafaide_show_rules`: a
 * ruling (§3.5) read from the local records or a verification pack, and the held rule set
 * (§10). Nothing here contacts the service, and no disclosed value is ever printed: only
 * pointers, ids, codes, versions and hashes.
 */

import * as fs from "node:fs";
import * as C from "./checks.js";
import { hashJson } from "./crypto.js";
import { failWord, modeWord, ruleWords, stateWord } from "./words.js";
import { recordHash, type SignedRecord } from "./records.js";
import type { Recorder } from "./runtime.js";

type Json = Record<string, any>;
const isObj = (x: unknown): x is Json => !!x && typeof x === "object" && !Array.isArray(x);

/** A rule as one line: its id, the rule in words (§10.5), its state in a rule set, and what the
 * admin wrote about it. `doc` is the rule set (null for the local rules, whose mode is the checks
 * file's per tool). */
export function ruleLine(r: Json, doc: Json | null = null): string {
  const state = doc ? ` (${stateWord(doc.mode === "watch" ? "calibrating" : C.ruleState(doc, r))})` : "";
  return `${r.id}: ${ruleWords(r)}${state}${r.about ? `. ${r.about}` : ""}`;
}

/** The lines of `signafaide_show_rules`: the rule set this machine holds, and the checks file's part of it. */
export function showRulesLines(rec: Recorder): string[] {
  const c = rec.checks;
  const out: string[] = [];
  const [status] = c.status();
  const item = c.heldRulesItem();
  const rs = item?.rules as Json | undefined;
  let file: Json | null = null;
  try {
    file = c.file();
  } catch {
    // the status lines name the problem
  }
  out.push(status[0]);
  if (!rs) {
    out.push(
      "rule set: none held" +
        (rec.apiKey
          ? "; `signafaide rules pull` fetches it"
          : " (no API key, so there is no project rule set; local rules in the checks file still apply)"),
    );
  } else {
    out.push(
      `rule set ${rs.set}: version ${rs.version}, ${modeWord(rs.mode)}, default ${rs.default}, issued ${rs.issued}, rules_hash ${hashJson(rs)}`,
    );
    if (rs.mode === "watch")
      out.push(
        'Calibrating (`mode` is "watch"): every rule is Calibrating: a rule that would block is noted and the call is allowed.',
      );
    else
      out.push(
        'On (`mode` is "enforce"): On rules decide; a Calibrating rule never blocks, and the ruling names it when it would have blocked.',
      );
    out.push(
      `rules (${rs.rules.length}):`,
      ...(rs.rules.length ? rs.rules.map((r: Json) => `  ${ruleLine(r, rs)}`) : ["  none"]),
    );
    for (const r of rs.rules)
      for (const x of r.exceptions ?? [])
        out.push(
          `  exception to ${r.id} since version ${x.since}: ${x.field.slice(1) || "(the empty key)"} is ${JSON.stringify(x.value)}, reason ${JSON.stringify(x.reason)}`,
        );
  }
  const v2 = file ? C.checksFileVersion(file) === 2 : false;
  if (file?.rules)
    out.push(
      `local rules (checks file, ${v2 ? "mode per tool" : `${modeWord(file.mode)}`}, ${file.rules.rules.length}):`,
      ...file.rules.rules.map((r: Json) => `  ${ruleLine(r)}`),
    );
  const strict = file
    ? Object.keys(file.tools)
        .filter((n) => C.toolSettings(file!, n).strict)
        .sort()
    : [];
  const word = "protected tool";
  if (!strict.length)
    out.push(
      v2
        ? "protected tools: none (`signafaide protect <tool>` protects one)"
        : 'protected tools: none (a tool is protected by code, the gateway\'s --strict, or `"strict": true` in the checks file)',
    );
  for (const n of strict) {
    const t = C.toolSettings(file!, n);
    const fail = rs?.fail?.[n] ?? (v2 ? "closed" : (file!.tools[n].fail ?? "closed"));
    let line = `${word} ${n}: if signafAIde can't be reached: ${failWord(fail)}${rs?.fail?.[n] ? " (set by the rule set)" : ""}; discloses ${t.disclose.join(", ") || "no field"}`;
    if (rs) {
      const d = C.disclosure(rs, rec.defaultAgent, n, t.disclose);
      if (d.missing.length)
        line += `; the rule set needs ${d.missing.join(", ")}: not disclosed, so its protected calls are ruled block (fields_missing). Add them only if the person agrees those fields may leave the machine (\`signafaide pull\` asks them)`;
      if (d.unsent.length)
        line += `; Calibrating rules or exceptions can use ${d.unsent.join(", ")}, which it does not send: they are not calibrated until the person approves them with \`signafaide pull\``;
    }
    out.push(line);
  }
  out.push(
    "Read-only: this changes nothing. To change rules, publish a new version in the console (or `signafaide protect`); to change what a tool sends, `signafaide pull` asks the person.",
  );
  return out;
}

/** The records of a chain or pack: [agent label, record]. */
function candidates(rec: Recorder, pack?: string): [string, SignedRecord][] {
  if (pack) {
    const doc = JSON.parse(fs.readFileSync(pack, "utf8"));
    if (!isObj(doc) || !Array.isArray(doc.records)) throw new Error(`${pack} is not a verification pack (no records)`);
    return doc.records.map((r: SignedRecord) => [r.envelope?.agent ?? "?", r]);
  }
  return rec.state
    .chains()
    .flatMap((chain) => rec.state.readChain(chain).map((r): [string, SignedRecord] => [chain.split("/").pop()!, r]));
}

const hashOf = (r: SignedRecord): string => r.receipt?.record_hash ?? recordHash(r);

/** What to do so the call is allowed, from the ruling's basis. */
function howToAllow(g: Json, tool: string, mode: string): string[] {
  const out: string[] = [];
  if (g.ruling === "allow") {
    // nothing to fix; in watch mode say what enforce mode would have done
  } else if (g.basis === "fields_missing")
    out.push(
      `add ${g.missing.join(", ")} to the disclose list of ${tool} in the checks file (the person who owns the code decides whether those fields may leave the machine), or ask an admin to change the rule that needs them`,
    );
  else if (g.basis === "rules_version")
    out.push(
      "update the client's held rule set (`signafaide rules pull`); the client named a version the witness does not hold",
    );
  else if (g.basis === "fingerprint")
    out.push(
      `the tool, its description or its server is on the shared fingerprint list; a person re-approves it after review (\`signafaide checks approve ${tool}\`, or in the console when the rule set approves tools)`,
    );
  else if (g.basis === "rule" || g.basis === "error")
    out.push(
      "an admin changes or removes the matching rule in the console, which publishes a new version; or the call's arguments change so the rule no longer matches",
    );
  else if (g.basis === "default")
    out.push(
      "the rule set's default is block: an admin adds an allow rule for this tool, or sets the default to allow",
    );
  if (mode === "watch" && g.enforce_ruling === "block")
    out.push(
      'this rule set is Calibrating (`mode` is "watch"), so the call was allowed; On (`mode` is "enforce") would have blocked it for the reason above',
    );
  return out;
}

/** The lines of `signafaide_explain_ruling`. `record` is a record hash or a prefix (8 or more characters). */
export function explainRulingLines(rec: Recorder, record: string, pack?: string): string[] {
  const want = record.trim().toLowerCase();
  if (!/^[0-9a-f]{8,64}$/.test(want))
    throw new Error("record must be a record hash or a prefix of at least 8 characters");
  const all = candidates(rec, pack);
  const where = pack ? pack : rec.state.home;
  const hits = all.filter(([, r]) => hashOf(r).startsWith(want));
  if (!hits.length) throw new Error(`no record matches ${record} in ${where}`);
  if (new Set(hits.map(([, r]) => hashOf(r))).size > 1)
    throw new Error(`${record} matches more than one record in ${where}; give more characters`);
  let [agent, r] = hits[0];
  const out: string[] = [];
  if (r.envelope.kind === "outcome") {
    const d = all.find(([, x]) => x.envelope.kind === "decision" && hashOf(x) === r.envelope.ref);
    out.push(`${hashOf(r)} is the outcome of a call; its ruling is on the decision it belongs to.`);
    if (!d) throw new Error(`${out[0]} That decision is not in ${where}`);
    [agent, r] = d;
  }
  const env = r.envelope;
  if (env.kind !== "decision") throw new Error(`${hashOf(r)} is a ${env.kind}; only decisions are checked and ruled`);
  const ch = env.checks as Json | undefined;
  out.push(`record ${hashOf(r)}: decision of ${env.name} by ${agent}, #${env.seq}, ${env.time}`);
  if (!ch) {
    out.push(
      "tool-call checks: this record has none (written before checks were on, or with checks off); there is no ruling to explain.",
    );
    return out;
  }
  const entries: string[] = ch.results.map((e: Json) => {
    const extra =
      e.check === "rule"
        ? ` (set ${e.set}${e.matched.length ? `, matched ${e.matched.join(", ")}` : ""})`
        : e.found.length
          ? ` (found ${e.found.join(", ")})`
          : "";
    return `${e.check} ${e.result}${e.enforce_result && e.enforce_result !== e.result ? `, if On: ${e.enforce_result}` : ""}, ${modeWord(e.mode)}${extra}`;
  });
  out.push(`client checks: ${ch.result}${entries.length ? `: ${entries.join("; ")}` : ""}`);
  out.push(
    `protected: ${ch.strict ? `yes, if signafAIde can't be reached: ${failWord(ch.fail)}` : "no (central rules never block a call that is not protected)"}; rules applied: ${ch.rules.map((x: Json) => (x.set === "local" ? "local" : `${x.set} version ${x.version}`)).join(", ") || "none"}`,
  );
  out.push(`disclosed fields: ${ch.disclosed.join(", ") || "none"} (values are not shown)`);
  const g = r.receipt?.ruling as Json | undefined;
  if (g) {
    out.push(
      `ruling: ${g.ruling} (${modeWord(g.mode)}${g.enforce_ruling ? `, if On it would give ${g.enforce_ruling}` : ""}) by the witness at ${g.server_time}`,
      `basis: ${g.basis}; matched rules: ${g.matched.join(", ") || "none"}; missing fields: ${g.missing.join(", ") || "none"}`,
      ...(g.would_block?.length
        ? [`Calibrating rules that would have blocked it (they never block): ${g.would_block.join(", ")}`]
        : []),
      ...(g.not_calibrated?.length
        ? [`Calibrating rules not checked, because a field they need was not sent: ${g.not_calibrated.join(", ")}`]
        : []),
      ...(g.excepted?.length ? [`allowed by exception to: ${g.excepted.join(", ")}`] : []),
      `rule set: ${g.rules ? `${g.rules.set} version ${g.rules.version}` : "none held by the witness"}; shared fingerprint list seq ${g.fingerprints}`,
      `reason: ${g.reason}`,
    );
    const fix = howToAllow(g, env.name, g.mode);
    if (g.ruling === "block") out.push(`to allow it: ${fix.join("; ") || "see the reason"}`);
    else if (fix.length) out.push(`note: ${fix.join("; ")}`);
    const rules = [
      rec.checks.heldRules(),
      ...(pack ? (JSON.parse(fs.readFileSync(pack, "utf8")).rule_sets ?? []).map((x: Json) => x.rules) : []),
    ].filter((x) => isObj(x) && x.set === g.rules?.set && x.version === g.rules?.version);
    for (const m of [...g.matched, ...(g.would_block ?? []), ...(g.excepted ?? [])]) {
      const rule = rules[0]?.rules.find((x: Json) => x.id === m);
      if (rule) out.push(`  rule ${ruleLine(rule, rules[0])}`);
    }
    if (g.matched.length && !rules.length)
      out.push(
        "  the text of the rules is not held here: run `signafaide rules pull`, or look in the console (rule set versions are kept as long as a record names them)",
      );
    out.push(
      "The ruling is the witness's own decision on what the client disclosed, under that rule set version and fingerprint list. It does not say the call was right.",
    );
  } else if (r.receipt?.ruling_error) {
    out.push(
      `ruling: none; the witness could not rule (${r.receipt.ruling_error}). A tool set to Let it run ran without one; a tool set to Stop did not run.`,
    );
  } else if (ch.strict && ch.result !== "block") {
    out.push(
      r.receipt
        ? "ruling: none on the receipt."
        : "ruling: not yet; the record has not been co-signed (it waits in the outbox, or there is no API key).",
    );
  } else if (ch.result === "block") {
    out.push("ruling: none asked. A client check blocked the call here, before it asked the witness.");
  } else {
    out.push("ruling: none asked. The call is not protected, so only the client's own checks and rules applied.");
  }
  if (ch.result === "block") {
    const blockers = ch.results.filter((e: Json) => e.result === "block").map((e: Json) => e.check);
    out.push(
      `blocked here by: ${blockers.join(", ")}. To allow it: fix the cause named in the entry, or for a deliberate case allow it in the checks file (addresses, local rules) or re-approve the tool.`,
    );
  }
  return out;
}
