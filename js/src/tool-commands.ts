/**
 * The per-tool commands of spec 1.1: `status` (one line per tool: recorded, protected, proof),
 * `check` (a dry run that exits 1 when the call would be blocked), `pull` (fetch the rules and ask
 * before any new field leaves the machine), `prove [tool]` (what an auditor gets, with the rules in
 * words) and `start-fresh <agent>` (proofs of the agent start from now; the old record is kept).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as C from "./checks.js";
import { CHECKS_FILE, checksPath, siteOf } from "./checks-runtime.js";
import { byCodePoint, coverage, declaredName } from "./coverage.js";
import { hashJson } from "./crypto.js";
import { SignafaideError } from "./http.js";
import { verify } from "./index.js";
import { plural } from "./plural.js";
import { fieldUses, findTools, toVersion2, writeChecksFile, type Prompter } from "./protect.js";
import { recordHash, type SignedRecord } from "./records.js";
import type { Recorder } from "./runtime.js";
import { VERSION } from "./version.js";
import { fieldWords, numberWords, ruleWords, stateWord } from "./words.js";

type Json = Record<string, any>;

const isObj = (x: unknown): x is Json => !!x && typeof x === "object" && !Array.isArray(x);

function checksFile(rec: Recorder): Json | null {
  try {
    return rec.checks.file();
  } catch {
    return null;
  }
}

/** `21:04` (UTC) of a record time. */
const hhmm = (t: string): string => t.slice(11, 16);
const hhmmss = (t: string): string => t.slice(11, 19);
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** `17 Nov 2026 21:03`. */
const when = (t: string, year = true): string =>
  `${Number(t.slice(8, 10))} ${MONTHS[Number(t.slice(5, 7)) - 1]}${year ? ` ${t.slice(0, 4)}` : ""} ${hhmm(t)}`;

/** The records of this project's chains (the current key's project and env, or every chain
 * without a key), by agent. */
export function chainsByAgent(rec: Recorder): Map<string, { chain: string; records: SignedRecord[] }> {
  const key = rec.apiKey;
  const bucket = key ? rec.state.bucket(key) : null;
  const out = new Map<string, { chain: string; records: SignedRecord[] }>();
  for (const chain of rec.state.chains()) {
    const agent = chain.split("/")[2];
    const mine = bucket ? chain.startsWith(`${bucket}/`) || chain.startsWith("_pending/") : true;
    if (!mine) continue;
    const records = rec.state.readAll(chain);
    const have = out.get(agent);
    if (!have || records.length > have.records.length) out.set(agent, { chain, records });
  }
  return out;
}

export interface ToolLine {
  agent: string;
  tool: string;
  calls: number;
  last: string | null;
  protected: string;
  proof: string;
}

/** The declared names of the tools the project's code protects (`protect(...)`, or `record(fn,
 * { strict: true })`): protected whatever the checks file says (§8). */
export function protectedInCode(rec: Recorder): Set<string> {
  try {
    return new Set(
      findTools(rec.state.root)
        .tools.filter((t) => t.wrapped === "protect")
        .map((t) => declaredName(t.name)),
    );
  } catch {
    return new Set(); // code that cannot be read protects nothing here
  }
}

/** The tools that are protected: by the checks file, by the code, or whose last call was strict. */
export function protectedNames(rec: Recorder, f: Json | null, records: SignedRecord[]): Set<string> {
  const out = new Set<string>(f ? Object.keys(f.tools).filter((n) => C.toolSettings(f, n).strict) : []);
  // §8 (SDK 0.5.2): the tools the held rule set protects from the console, that the program wraps.
  const rs = rec.checks.path() !== null ? rec.checks.heldRules() : null;
  if (rs && isObj(rs.protect))
    for (const n of Object.keys(rs.protect))
      if (rec.checks.wrappedState(n) === "wrapped" || records.some((r) => r.envelope.name === n)) out.add(n);
  const last = new Map<string, boolean>();
  for (const r of records)
    if (r.envelope.kind === "decision" && isObj(r.envelope.checks))
      last.set(r.envelope.name, (r.envelope.checks as Json).strict === true);
  for (const n of protectedInCode(rec)) out.add(n);
  for (const [n, x] of last) if (x) out.add(n);
  return out;
}

/** What `status` says of each tool's protection: `1 of 3 rules On, 2 Calibrating`, `Off`, ...
 * `inCode`: the code protects it (its wrapper, or its last call was strict). */
export function protectionWords(
  rec: Recorder,
  f: Json | null,
  agent: string,
  tool: string,
  inCode = false,
  seen = true,
): string {
  const decl = declaredName(tool);
  let ts = f ? C.toolSettings(f, decl) : null;
  const rs = rec.checks.heldRules();
  // §8 (SDK 0.5.2): protected from the console when the held version's `protect` names it and the
  // program wraps it; a tool the program never shows signafAIde cannot be protected.
  const console = rec.checks.path() !== null && C.consoleProtects(rs, decl);
  if (console && !seen)
    return `Off: protected from the console (rule set version ${rs!.version}), but not wrapped, so signafAIde never sees its calls`;
  const sources = [
    ...(inCode ? ["code"] : []),
    ...(ts?.strict ? ["checks_file"] : []),
    ...(console ? ["console"] : []),
  ];
  if (inCode || console) ts = { ...(ts ?? { mode: "enforce", disclose: [], fail: "closed" }), strict: true };
  const from = sources.length ? `, ${C.sourceWords(sources, rs?.version)}` : "";
  if (ts && !ts.strict && ts.mode === "enforce" && f?.rules) {
    const n = f.rules.rules.filter((r: Json) => C.applies(r, agent, decl)).length;
    return `this machine only, ${plural(n, "rule")}`;
  }
  if (!ts?.strict) return "Off";
  const rules = rs ? rs.rules.filter((r: Json) => C.applies(r, agent, decl)) : [];
  if (!rs || !rules.length) return (rs ? "On, no rule for it yet" : "On, rules not fetched yet") + from;
  const on = rs.mode === "enforce" ? rules.filter((r: Json) => C.ruleState(rs, r) === "on").length : 0;
  const cal = rules.length - on;
  return `${on} of ${plural(rules.length, "rule")} On${cal ? `, ${cal} Calibrating` : ""}${from}`;
}

/** The tools `status` shows: the declared ones, the recorded ones and the checks file's. */
export function toolLines(rec: Recorder, proofOf: (agent: string) => string): ToolLine[] {
  const f = checksFile(rec);
  const chains = chainsByAgent(rec);
  const agents = new Set<string>([...chains.keys()]);
  for (const a of rec.state.agents()) agents.add(a);
  const out: ToolLine[] = [];
  const code = protectedInCode(rec);
  const rs = rec.checks.path() !== null ? rec.checks.heldRules() : null;
  for (const agent of [...agents].sort(byCodePoint)) {
    const names = new Set<string>();
    for (const tools of Object.values(rec.state.toolSources(agent)))
      for (const t of Object.keys(tools)) names.add(declaredName(t));
    const recs = chains.get(agent)?.records ?? [];
    const calls = new Map<string, { n: number; last: string }>();
    const strict = new Map<string, boolean>(); // the last call of each tool: strict (protected in code) or not
    for (const r of recs) {
      const e = r.envelope;
      if (e.kind !== "decision" || e.name.startsWith("signafaide.")) continue;
      names.add(e.name);
      if (isObj(e.checks)) strict.set(e.name, (e.checks as Json).strict === true);
      const c = calls.get(e.name) ?? { n: 0, last: e.time };
      c.n++;
      c.last = e.time;
      calls.set(e.name, c);
    }
    if (f && agents.size === 1) for (const t of Object.keys(f.tools)) names.add(t);
    // The tools the console protects (§8, SDK 0.5.2): listed, so one the program never wraps shows.
    if (rs && isObj(rs.protect) && agents.size === 1) for (const t of Object.keys(rs.protect)) names.add(t);
    if (!names.size) continue;
    const proof = proofOf(agent);
    for (const tool of [...names].sort(byCodePoint)) {
      const c = calls.get(tool);
      const seen = !!c || rec.checks.wrappedState(tool) === "wrapped";
      out.push({
        agent,
        tool,
        calls: c?.n ?? 0,
        last: c?.last ?? null,
        protected: protectionWords(
          rec,
          f,
          agent,
          tool,
          code.has(tool) ||
            (strict.get(tool) === true && !C.consoleProtects(rs, tool) && !(f && C.toolSettings(f, tool).strict)),
          seen,
        ),
        proof,
      });
    }
  }
  return out;
}

/** The proof column of each agent, from the local verify: `intact`, `intact, timestamp pending`,
 * `intact, not co-signed yet` or `NOT intact`. */
export async function proofByAgent(rec: Recorder): Promise<(agent: string) => string> {
  let report: Awaited<ReturnType<typeof verify>> | null = null;
  try {
    report = await verify(null, { offline: true });
  } catch {
    report = null;
  }
  const chains = chainsByAgent(rec);
  return (agent) => {
    if (!report) return "unknown (run signafaide verify)";
    if (!report.ok) return "NOT intact (run signafaide verify)";
    const recs = chains.get(agent)?.records ?? [];
    if (!recs.length) return "intact";
    if (recs.some((r) => !r.receipt)) return rec.apiKey ? "intact, not co-signed yet" : "intact, kept on this machine";
    return report.checks.some((c) => c.status === "pending") ? "intact, timestamp pending" : "intact";
  };
}

/** The tool lines of `status`: one line per tool, then the project. */
export async function statusTable(rec: Recorder): Promise<string[]> {
  const lines = toolLines(rec, await proofByAgent(rec));
  if (!lines.length) return [];
  const many = new Set(lines.map((l) => l.agent)).size > 1;
  const name = (l: ToolLine): string => (many ? `${l.agent}/${l.tool}` : l.tool);
  const rows = lines.map((l) => [
    name(l),
    l.calls ? `${plural(l.calls, "call")}, last ${hhmm(l.last!)}` : "0 calls",
    l.protected,
    l.proof,
  ]);
  const head = ["tool", "recorded", "protected", "proof"];
  const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)) + 2);
  const fmt = (r: string[]): string =>
    r
      .map((c, i) => (i < r.length - 1 ? c.padEnd(w[i]) : c))
      .join(" ")
      .trimEnd();
  return [fmt(head), ...rows.map(fmt)];
}

// --- check -----------------------------------------------------------------------------------

/** `amount=1200 currency=GBP payee/name="Ashgrove Catering Ltd"` as arguments: a value is JSON
 * when it reads as JSON, else text; `a/b=v` sets a field inside an object. */
export function parseFieldArgs(pairs: string[]): Json {
  const out: Json = {};
  for (const p of pairs) {
    const i = p.indexOf("=");
    if (i <= 0) throw new SyntaxError(`${p}: give each field as name=value, for example amount=1200`);
    const keys = p.slice(0, i).replace(/^\//, "").split("/");
    const raw = p.slice(i + 1);
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      value = raw;
    }
    let cur = out;
    keys.slice(0, -1).forEach((k) => {
      if (!isObj(cur[k])) cur[k] = {};
      cur = cur[k];
    });
    cur[keys[keys.length - 1]] = value;
  }
  return out;
}

/** `signafaide check <tool> <field>=<value>...`: lines and the exit code (1: would be blocked). */
export async function runCheck(
  rec: Recorder,
  tool: string,
  pairs: string[],
  agent?: string,
): Promise<[string[], number]> {
  const args = pairs.length === 1 && pairs[0].trim().startsWith("{") ? JSON.parse(pairs[0]) : parseFieldArgs(pairs);
  if (rec.apiKey && !rec.checks.heldRules()) {
    try {
      await rec.checks.pullRules();
    } catch {
      /* the held version, or none: said by the lines below */
    }
  }
  const { lines, blocked } = rec.checks.dryRun(tool, args, agent ?? rec.defaultAgent);
  // A protected tool with no key never runs (no_key), whatever the rules say: so the dry run fails too.
  let file: Record<string, any> | null = null;
  try {
    file = rec.checks.file();
  } catch {
    file = null;
  }
  if (!rec.apiKey && file && C.toolSettings(file, declaredName(tool)).strict) {
    if (lines.length && lines[lines.length - 1].includes("Dry run:")) lines.pop();
    lines.push(
      `would refuse ${declaredName(tool)} is protected and there is no API key, so a real run is refused (no_key). Run npx signafaide protect in a terminal (a free sandbox), or set SIGNAFAIDE_API_KEY.`,
      "             Dry run: nothing recorded, the tool did not run. Exit code 1.",
    );
    return [lines, 1];
  }
  return [lines, blocked ? 1 : 0];
}

// --- pull ------------------------------------------------------------------------------------

/** `signafaide pull`: fetch the rule set, rewrite the checks file as version 2, and for each
 * protected tool ask before adding a field the held version can use. Never removes an approved
 * field; never adds one without a person at a terminal. */
export async function runPull(rec: Recorder, prompt: Prompter, out: (s: string) => void): Promise<number> {
  const before = rec.checks.heldRules()?.version ?? null;
  let code = 0;
  if (rec.apiKey) {
    const said = await rec.checks.forcedPull(); // a person asked: key list, rule set and list, never waiting
    if ("rules" in rec.checks.problems) {
      out(`Rules      ${said}`);
      code = 1;
    }
  } else out("Rules      no API key: only the rules in the checks file apply (npx signafaide protect makes a sandbox)");
  const rs = rec.checks.heldRules();
  if (rs)
    out(
      `Rules      version ${rs.version}${before !== null && before !== rs.version ? ` (was ${before})` : before === rs.version ? " (no change)" : ""}`,
    );
  else if (rec.apiKey) out("Rules      the project has no rule set yet (npx signafaide protect adds one)");
  const p = checksPath(rec.state.root);
  if (p === null) {
    out("Checks     off (SIGNAFAIDE_CHECKS=0): nothing to write");
    return code;
  }
  let f: Json | null;
  try {
    f = rec.checks.file();
  } catch (e) {
    out(`Checks     ${(e as Error).message}`);
    return 1;
  }
  // §8 (SDK 0.5.2): the tools the held version protects from the console have fields to approve too.
  const fromConsole: string[] = rs && isObj(rs.protect) ? Object.keys(rs.protect) : [];
  if (!f && !fromConsole.length) {
    out(`Checks     no ${path.basename(p)} here: npx signafaide protect writes one`);
    return code;
  }
  const doc = toVersion2(f ?? C.defaultChecksFile());
  const agent = rec.defaultAgent;
  const changes: string[] = [];
  const wait: string[] = [];
  const nowFile: string[] = [];
  for (const name of [...new Set([...Object.keys(doc.tools), ...fromConsole])].sort(byCodePoint)) {
    const onlyConsole = !doc.tools[name]?.protect && fromConsole.includes(name);
    const t = doc.tools[name] ?? { protect: false };
    if ((!t.protect && !onlyConsole) || !rs) continue;
    const have: string[] = t.disclose ?? [];
    const uses = fieldUses(rs, agent, name);
    const fresh = C.sendableFields(rs, agent, name).filter((x) => !have.includes(x));
    for (const field of fresh) {
      out(`Change     ${name} would also send: ${fieldWords(field)}`);
      out(`           needed by: ${(uses.get(field) ?? []).join("; ")}`);
      if (!prompt.person) {
        wait.push(`${name}: ${fieldWords(field)}`);
        continue;
      }
      if (
        await prompt.confirm(
          `Send ${fieldWords(field)} to signafAIde for ${name}? It is kept 30 days, admins only.`,
          false,
        )
      ) {
        have.push(field);
        changes.push(name);
      } else wait.push(`${name}: ${fieldWords(field)}`);
    }
    if (have.length) {
      t.disclose = have;
      if (onlyConsole) {
        // A version 2 file lists fields only on a protected tool, so a client before 0.5.2 still
        // reads it: the checks file now protects the tool too.
        t.protect = true;
        doc.tools[name] = t;
        nowFile.push(name);
      }
    }
  }
  const v1 = f !== null && C.checksFileVersion(f) === 1;
  if (changes.length || v1) {
    writeChecksFile(p, doc);
    rec.checks.forget();
    const what = [...new Set(changes)].map(
      (n) => `${n} sends ${(doc.tools[n].disclose as string[]).map(fieldWords).join(", ")}`,
    );
    out(
      `Changed    ${path.basename(p)}     ${[...(v1 ? ["now version 2 (each tool Protected or Not protected, On or Calibrating)"] : []), ...what].join("; ")}`,
    );
    for (const n of nowFile)
      out(
        `           ${n} was protected from the console only; ${path.basename(p)} now protects it too (a checks file lists the fields to send only for a protected tool), so Unprotect in the console no longer unprotects it`,
      );
    out(
      "Commit it. Until then, a call a rule needs one of these fields for is blocked and the error says to run pull.",
    );
  } else out(`Checks     ${path.basename(p)} is up to date`);
  if (wait.length)
    out(
      `Not sent   ${wait.join(", ")}${prompt.person ? " (you said no)" : ": run npx signafaide pull at a terminal to approve them"}`,
    );
  return code;
}

// --- start-fresh ------------------------------------------------------------------------------

/** When the proofs of each agent start (`signafaide start-fresh`): `.signafaide/fresh.json`. */
export function freshFrom(rec: Recorder, agent: string): string | null {
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(rec.state.home, "fresh.json"), "utf8"));
    return typeof doc?.[agent] === "string" ? doc[agent] : null;
  } catch {
    return null;
  }
}

export function startFresh(rec: Recorder, agent: string): string {
  rec.state.ensure();
  const p = path.join(rec.state.home, "fresh.json");
  let doc: Json = {};
  try {
    doc = JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    doc = {};
  }
  const t = new Date().toISOString();
  doc[agent] = t;
  fs.writeFileSync(p, JSON.stringify(doc, null, 2) + "\n");
  return t;
}

// --- prove -----------------------------------------------------------------------------------

interface Call {
  d: SignedRecord;
  o?: SignedRecord;
}

/** A call's arguments in a few words: `800 GBP`, `payee=Ashgrove`. */
function callWords(input: unknown): string {
  if (!isObj(input)) return input === undefined || input === null ? "" : String(JSON.stringify(input)).slice(0, 30);
  const vals = Object.entries(input).filter(([, v]) => typeof v === "number" || typeof v === "string");
  const amount = vals.find(([k]) => /amount|total|value|price|sum|cost/i.test(k));
  const ccy = vals.find(([k]) => /currency|ccy/i.test(k));
  if (amount)
    return `${typeof amount[1] === "number" ? numberWords(String(amount[1])) : amount[1]}${ccy ? ` ${ccy[1]}` : ""}`;
  return vals
    .slice(0, 2)
    .map(([k, v]) => `${k}=${String(v).slice(0, 20)}`)
    .join(" ");
}

/** What happened to a call, in words. */
function callFate(c: Call): [string, string] {
  const ch = c.d.envelope.checks as Json | undefined;
  const g = (c.d as Json).receipt?.ruling as Json | undefined;
  const ran = c.o?.envelope.checks ? (c.o.envelope.checks as Json).ran !== false : !!c.o;
  if (ch?.result === "block") {
    const rule = (ch.results as Json[]).find((e) => e.result === "block");
    if (rule?.check === "rule" && rule.set !== "local") {
      // The client held the signed rule set and blocked the call itself: the witness never ruled on it.
      const v = ((ch.rules as Json[]) ?? []).find((x) => x.set === rule.set)?.version;
      return ["blocked", `here under signed rule set version ${v ?? "?"}; it did not run`];
    }
    if (rule?.check === "rule") return ["blocked", "here by the rules on this machine; it did not run"];
    return ["blocked", `here by the ${rule?.check ?? "local"} check; it did not run`];
  }
  if (g?.ruling === "block")
    return ["blocked", `by the signafAIde witness${ran ? ", but it ran" : "; it did not run"}`];
  if (g?.ruling === "allow") {
    if (Array.isArray(g.excepted) && g.excepted.length) return ["allowed", "by signafAIde, by exception"];
    if (Array.isArray(g.would_block) && g.would_block.length)
      return ["allowed", "by signafAIde; a Calibrating rule would have blocked it"];
    return ["allowed", "by signafAIde"];
  }
  if (ch?.strict) return [ran ? "ran" : "stopped", ran ? "no ruling yet (Let it run)" : "no ruling, it did not run"];
  return ["recorded", ch ? "not protected" : "before protection"];
}

/** One line when the witness's newest record of `agent` was signed by a key this machine does not
 * hold: another machine (or folder) uses the same agent name with its own key, so protected calls
 * here are refused and a pack made here fails its signatures. Null when they match or it cannot tell. */
export async function keyMismatch(rec: Recorder, agent: string): Promise<string | null> {
  if (!rec.apiKey) return null;
  try {
    const client = rec.client(5000);
    const h = (await client.head(agent))?.head;
    if (!h || !/^[0-9a-f]{64}$/.test(String(h.record_hash)) || h.agent !== agent) return null;
    const kid = (await client.record(h.record_hash))?.record?.key_id;
    if (typeof kid !== "string" || !/^[0-9a-f]{16}$/.test(kid)) return null;
    const mine = rec.state
      .agentPublicKeys()
      .filter((k) => k.agent === agent)
      .map((k) => k.key_id);
    if (mine.includes(kid)) return null;
    return `agent ${agent} on the witness signs with key ${kid}, but this machine has ${mine.length ? mine.join(", ") : "no key for it"}: one agent name = one key. Give this machine its own agent name, or use the same key here (signafaide keys create --print; see the production guide).`;
  } catch {
    return null;
  }
}

export interface ProveOptions {
  tool?: string;
  agent?: string;
  files?: boolean;
  /** Include what the calls said (content) in the files. */
  content?: boolean;
  /** Ignore `start-fresh`: prove from the agent's first record. */
  all?: boolean;
  /** How long the link works; default: 30, or the longest the plan allows when that is less. */
  days?: number;
  /** Make the proof even when this machine's agent key is not the one the witness holds. */
  force?: boolean;
  out: (s: string) => void;
  prompt: Prompter;
  dir?: string;
}

/** `signafaide prove [tool]`: the link (or files) for an auditor, and what they show. */
export async function runProve(rec: Recorder, o: ProveOptions): Promise<number> {
  const { out } = o;
  const chains = chainsByAgent(rec);
  let agent = o.agent;
  if (!agent) {
    if (o.tool)
      agent = [...chains.entries()].find(([, c]) =>
        c.records.some((r) => r.envelope.name === declaredName(o.tool!)),
      )?.[0];
    agent ??= chains.size === 1 ? [...chains.keys()][0] : rec.defaultAgent;
  }
  const chain = chains.get(agent);
  if (!chain) {
    out(`No records of agent ${agent} here yet: run the agent first (\`signafaide status\` lists the agents).`);
    return 1;
  }
  const from = o.all ? null : freshFrom(rec, agent);
  const tool = o.tool ? declaredName(o.tool) : null;
  const recs = chain.records.filter((r) => !from || r.envelope.time >= from);
  const byHash = new Map<string, Call>();
  const calls: Call[] = [];
  for (const r of recs) {
    const e = r.envelope;
    if (e.kind === "decision" && !e.name.startsWith("signafaide.") && (!tool || e.name === tool)) {
      const c = { d: r };
      calls.push(c);
      byHash.set(r.draft ? "" : recordHash(r), c);
    } else if (e.kind === "outcome" && e.ref && byHash.has(e.ref)) byHash.get(e.ref)!.o = r;
  }
  const mismatch = await keyMismatch(rec, agent);
  if (mismatch && !o.force) {
    out(`No proof made: ${mismatch}`);
    out("           A pack made here would fail its agent signatures. --force makes it anyway.");
    return 1;
  }
  if (mismatch) out(`Warning    ${mismatch}`);
  const what = tool ? `${o.tool} (agent ${agent})` : `agent ${agent}`;
  const env = rec.apiKey?.startsWith("sfa_live_") ? "Live" : rec.apiKey ? "Sandbox" : "this machine only";
  const t0 = calls[0]?.d.envelope.time ?? recs[0]?.envelope.time;
  const t1 = calls.at(-1)?.d.envelope.time ?? recs.at(-1)?.envelope.time;
  out(
    `Proof of ${what}, ${env}${t0 && t1 ? `, ${when(t0)} to ${t1.slice(0, 10) === t0.slice(0, 10) ? hhmm(t1) : when(t1)} UTC` : ""}`,
  );
  out("");
  // The link, or the files.
  let link: AuditorLink | null = null;
  let linkWhy = "";
  let reused = false;
  if (!o.files) {
    if (!rec.apiKey) linkWhy = "these records are on this machine only (no API key), so there is no link";
    else {
      const got = await auditorLinkFor(rec, agent, tool, from, o.days);
      if (typeof got === "string") linkWhy = got;
      else [link, reused] = [got.link, got.reused];
    }
    if (link?.url) {
      out(reused ? "Send this link to your auditor (made earlier, still open):" : "Send this link to your auditor:");
      out(
        `           ${link.url}   read only${link.expires_at ? `, until ${when(link.expires_at).slice(0, -6)}` : ""}`,
      );
      if (reused && o.days !== undefined) for (const l of await reusedLinkLines(rec, link, o.days, o.tool)) out(l);
      if (link.agent_keys === true) out("           They can check it in their browser; nothing to install.");
      else {
        out("           The witness did not keep this agent's public keys with the link, so the browser check");
        out("           cannot check the agent's signatures on its own. Give your auditor the keys too:");
        out(
          "           npx signafaide keys export -o agent-keys.json   (attach it in the console, Share with an auditor)",
        );
      }
    } else {
      out(`No link: ${linkWhy}.`);
      out(
        `           Make one in the console (${siteOf(rec.url)}, Share with an auditor), or give files: npx signafaide prove${o.tool ? ` ${o.tool}` : ""} --files`,
      );
    }
    out("");
  }
  // What it shows.
  out("What it shows");
  out(`  Calls      ${calls.length}, each signed by ${agent}${rec.apiKey ? " and witnessed by signafAIde" : ""}`);
  for (const c of calls.slice(-10)) {
    const [fate, by] = callFate(c);
    out(
      `               ${hhmmss(c.d.envelope.time)}  ${fate.padEnd(9)} ${callWords((c.d.content as Json | undefined)?.input).padEnd(12)} ${by}`,
    );
  }
  if (calls.length > 10) out(`               (the last 10 of ${calls.length})`);
  const rs = rec.checks.heldRules();
  if (rs) {
    const rules = rs.rules.filter((r: Json) =>
      tool ? C.applies(r, agent!, tool) : r.agents === null || r.agents.includes(agent),
    );
    out(`  Rules      version ${rs.version}, ${when(rs.issued, false)}, signed by signafAIde`);
    for (const r of rules) {
      const state = rs.mode === "enforce" ? C.ruleState(rs, r) : "calibrating";
      const g = calls.map((c) => (c.d as Json).receipt?.ruling as Json | undefined).filter(isObj);
      const here = calls.filter((c) =>
        ((c.d.envelope.checks as Json | undefined)?.results ?? []).some(
          (e: Json) => e.check === "rule" && e.set === rs.set && e.result === "block" && e.matched.includes(r.id),
        ),
      ).length;
      const blocked = here + g.filter((x) => x.ruling === "block" && x.matched.includes(r.id)).length;
      const would = g.filter(
        (x) =>
          (x.would_block ?? []).includes(r.id) ||
          (x.mode === "watch" && x.enforce_ruling === "block" && x.matched.includes(r.id)),
      ).length;
      const counts = state === "on" ? `blocked ${blocked}` : `would have blocked ${would}`;
      out(`               ${stateWord(state).padEnd(12)} ${ruleWords(r)}    ${counts}`);
      for (const x of r.exceptions ?? [])
        out(
          `               ${"".padEnd(12)} Allowed by exception: ${fieldWords(x.field)} is ${JSON.stringify(x.value)}, "${x.reason}", since version ${x.since}`,
        );
    }
  } else
    out(
      "  Rules      none held from signafAIde" +
        (checksFile(rec)?.rules ? "; the rules on this machine are in the checks file" : ""),
    );
  // Before: calls of the tool recorded before it was protected.
  const firstStrict = calls.findIndex((c) => (c.d.envelope.checks as Json | undefined)?.strict === true);
  const before = firstStrict < 0 ? (rs ? calls : []) : calls.slice(0, firstStrict);
  if (before.length) {
    out(
      `  Before     ${plural(before.length, `call of ${o.tool ?? agent}`, `calls of ${o.tool ?? agent}`)} (${hhmm(before[0].d.envelope.time)}${before.length > 1 ? ` to ${hhmm(before.at(-1)!.d.envelope.time)}` : ""}) ${before.length === 1 ? "was" : "were"} recorded before ${firstStrict < 0 ? "any rule applied" : "it was protected"}. ${before.length === 1 ? "It" : "They"} ran`,
    );
    out("             with no rules, and your auditor will see them. That is honest, not an error.");
    out(`             To start a fresh record from now: npx signafaide start-fresh ${agent}`);
    out("             (the old record is kept and can still be proved)");
  } else out(`  Before     none: ${o.tool ?? agent} was protected before its first call`);
  // Tools: the declaration and the checks file.
  // The declaration in the chain, read as `verify` reads it (§7 coverage); else this machine's tool list.
  const declared = new Map<string, boolean>();
  const cov = coverage(
    chain.records.map((r) => ({ seq: r.envelope.seq, kind: r.envelope.kind, name: r.envelope.name })),
  );
  for (const t of cov.declared) declared.set(t.name, t.recorded);
  if (!declared.size)
    for (const tools of Object.values(rec.state.toolSources(agent)))
      for (const [n, r] of Object.entries(tools))
        declared.set(declaredName(n), (declared.get(declaredName(n)) ?? false) || r);
  const f = checksFile(rec);
  const prot = protectedNames(rec, f, chain.records).size;
  if (declared.size) {
    const rcd = [...declared.values()].filter(Boolean).length;
    out(
      `  Tools      ${agent} has ${plural(declared.size, "tool")}, ${rcd === declared.size ? `all ${rcd}` : `${rcd}`} recorded, ${prot} protected`,
    );
  } else
    out(
      `  Tools      ${agent} has not declared its tool list (declareTools), so the proof cannot show every tool is recorded`,
    );
  // Where each protected tool's protection comes from (§8, SDK 0.5.2): never a surprise.
  const protectedNow = [...protectedNames(rec, f, chain.records)].filter((n) => !tool || n === tool).sort(byCodePoint);
  if (protectedNow.length) {
    const inCode = protectedInCode(rec);
    const words = protectedNow.map((n) => {
      const src = [
        ...(inCode.has(n) ? ["code"] : []),
        ...(f && C.toolSettings(f, n).strict ? ["checks_file"] : []),
        ...(C.consoleProtects(rs, n) ? ["console"] : []),
      ];
      return `${n} ${C.sourceWords(src.length ? src : ["code"], rs?.version)}`;
    });
    out(`  Protected  ${words.join("; ")}`);
  }
  // The record: the local verify.
  let report: Awaited<ReturnType<typeof verify>> | null = null;
  try {
    report = await verify(null, { offline: true });
  } catch (e) {
    out(`  Record     could not be checked here: ${(e as Error).message}`);
  }
  if (report) {
    const unsent = recs.filter((r) => !r.receipt).length;
    if (!report.ok) out(`  Record     NOT intact: ${report.resultLine} (run signafaide verify for the details)`);
    else if (!rec.apiKey)
      out("  Record     Every record is present and unaltered on this machine; none is witnessed yet (no API key).");
    else if (unsent)
      out(
        `  Record     Every record is present and unaltered. ${plural(unsent, "record is", "records are")} not co-signed yet: run npx signafaide flush.`,
      );
    else if (report.checks.some((c) => c.status === "pending"))
      out(
        "  Record     Every record is present and unaltered. Some records are waiting for their\n             public timestamp, normal for the last hour; the link updates by itself.",
      );
    else out("  Record     Every record is present and unaltered.");
  }
  out("");
  if (!o.files) {
    out(`Want files instead of a link? npx signafaide prove${o.tool ? ` ${o.tool}` : ""} --files`);
    out(`  writes proof/${o.tool ?? agent}/ and the command an auditor runs to check them offline`);
    return report && !report.ok ? 1 : 0;
  }
  return writeProofFiles(rec, {
    agent,
    tool: o.tool ?? null,
    from,
    out,
    prompt: o.prompt,
    content: o.content,
    dir: o.dir,
    records: recs,
  });
}

type AuditorLink = { url: string; expires_at?: string; agent_keys?: boolean; reused?: boolean };

/** Said when `prove --days N` got the link made earlier back instead of a new one: plainly that
 * it is the earlier link and until when, why, and how to get a new one. */
async function reusedLinkLines(rec: Recorder, link: AuditorLink, days: number, tool?: string): Promise<string[]> {
  let sandbox = false;
  try {
    sandbox = (await rec.client(10_000).project())?.claimed === false;
  } catch {
    /* unknown: said without the plan */
  }
  const until = link.expires_at ? when(link.expires_at).slice(0, -6) : null;
  const why = sandbox
    ? "an unclaimed sandbox's plan allows one active link"
    : "the witness gives this API key its open link again for the same agent, tool and start";
  return [
    `           You asked for ${days} ${days === 1 ? "day" : "days"}: this is not a new link. The link made earlier is reused${until ? `, open until ${until}` : ""}, because ${why}.`,
    `           For a new link: ${sandbox ? "keep the sandbox (the claim link from init), then " : ""}revoke this one in the console (${siteOf(rec.url)}, Share with an auditor), then run npx signafaide prove${tool ? ` ${tool}` : ""} --days ${days} again.`,
  ];
}

/** Links `prove` made, kept so a second `prove` reuses an active one (`.signafaide/auditor-links.json`). */
function linksFile(rec: Recorder): string {
  return path.join(rec.state.home, "auditor-links.json");
}

function keptLinks(
  rec: Recorder,
): (AuditorLink & { agent: string; tool: string | null; from: string | null; witness: string })[] {
  try {
    const doc = JSON.parse(fs.readFileSync(linksFile(rec), "utf8"));
    return Array.isArray(doc) ? doc.filter((x) => isObj(x) && typeof x.url === "string") : [];
  } catch {
    return [];
  }
}

/** The agent's §2.5 manifest (its keys only) and its newest signed head, as the auditor's browser
 * check needs them: both are public and already on this machine. */
function proofInputs(rec: Recorder, agent: string): { agent_keys: Json; head: Json | null } {
  const all = rec.state.exportAgentKeys();
  const agent_keys = { format: all.format, keys: all.keys.filter((k) => k.agent === agent) };
  let head: Json | null = null;
  for (const [p, envs] of Object.entries(rec.state.heads()))
    for (const [e, agents] of Object.entries(envs))
      if (agents[agent]) head = { [p]: { [e]: { [agent]: agents[agent] } } };
  return { agent_keys, head };
}

/** §6 `POST /v1/auditor-links` as `prove` asks it: reuse an active link for the same agent, tool
 * and start; else ask for `days` (default 30, then the longest the plan allows), with the agent's
 * keys and head. Returns the link, or why there is none. */
export async function auditorLinkFor(
  rec: Recorder,
  agent: string,
  tool: string | null,
  from: string | null,
  days?: number,
): Promise<{ link: AuditorLink; reused: boolean } | string> {
  const nowIso = new Date(Date.now() + 3_600_000).toISOString();
  const kept = keptLinks(rec);
  const same = kept.find(
    (x) =>
      x.agent === agent &&
      (x.tool ?? null) === tool &&
      (x.from ?? null) === from &&
      x.witness === rec.url &&
      (!x.expires_at || x.expires_at > nowIso),
  );
  if (same && days === undefined) return { link: same, reused: true };
  const client = rec.client(15_000);
  const inputs = proofInputs(rec, agent);
  const body = (d: number, withKeys: boolean): Json => ({
    agent,
    ...(tool ? { tool } : {}),
    from,
    days: d,
    ...(withKeys ? { agent_keys: inputs.agent_keys, ...(inputs.head ? { head: inputs.head } : {}) } : {}),
  });
  let want = days ?? 30;
  let withKeys = inputs.agent_keys.keys.length > 0;
  let link: AuditorLink | null = null;
  for (let attempt = 0; attempt < 3 && !link; attempt++) {
    try {
      link = await client.auditorLink(body(want, withKeys));
    } catch (e) {
      const err = e as SignafaideError;
      if (err.code === "not_found" && /route|endpoint/i.test(err.message))
        return "this witness does not make auditor links from the command line yet";
      if (err.code === "not_found") return `the witness did not make the link (${err.message})`;
      // The plan's longest link: from the answer, else from its words ("within 7 days").
      const max = Number(err.body?.error?.max_days ?? err.message.match(/within (\d+) days?/)?.[1] ?? NaN);
      if (err.code === "plan_required" && days === undefined && Number.isInteger(max) && max >= 1 && max < want) {
        want = max;
        continue;
      }
      if (err.code === "bad_request" && withKeys && /agent_keys|head/.test(err.message)) {
        withKeys = false; // a witness that does not take them yet: the link without them
        continue;
      }
      if (err.code === "plan_required" && days !== undefined && Number.isInteger(max))
        return `the witness did not make the link: this plan's links last at most ${max} days (npx signafaide prove --days ${max})`;
      return `the witness did not make the link (${err.message})`;
    }
  }
  if (!link?.url) return "the witness answered without a link";
  if (!withKeys) link = { ...link, agent_keys: false };
  try {
    const rest = kept.filter(
      (x) =>
        !(x.agent === agent && (x.tool ?? null) === tool && (x.from ?? null) === from && x.witness === rec.url) &&
        (!x.expires_at || x.expires_at > nowIso),
    );
    fs.mkdirSync(rec.state.home, { recursive: true });
    fs.writeFileSync(
      linksFile(rec),
      JSON.stringify([...rest, { ...link, agent, tool, from, witness: rec.url }], null, 2) + "\n",
    );
  } catch {
    /* not kept: the next prove asks again */
  }
  return { link, reused: link.reused === true };
}

/** `prove --files`: the pack (with the local rules its records name), the agent keys, the head
 * file and, when the person says so, the content; and the command an auditor runs. */
async function writeProofFiles(
  rec: Recorder,
  o: {
    agent: string;
    tool: string | null;
    from: string | null;
    out: (s: string) => void;
    prompt: Prompter;
    content?: boolean;
    dir?: string;
    records: SignedRecord[];
  },
): Promise<number> {
  const { out } = o;
  if (!rec.apiKey) {
    out("Files need the witness's pack (an API key): run npx signafaide protect or npx signafaide init first.");
    return 1;
  }
  const dir = o.dir ?? path.join(rec.state.root, "proof", o.tool ?? o.agent);
  fs.mkdirSync(dir, { recursive: true });
  await rec.flush();
  const pack = await rec.client(60_000).export(o.agent, o.from ?? undefined);
  // The local rules the records name (spec 1.1): the checks file's, when its hash is named.
  const f = checksFile(rec);
  const named = new Set<string>();
  for (const r of pack.records ?? [])
    for (const x of r.envelope?.checks?.rules ?? []) if (x.set === "local") named.add(x.hash);
  if (f?.rules) {
    const h = C.localRulesErrors(f.rules) === null ? hashJson(f.rules) : null;
    if (h && named.has(h)) pack.local_rules = [{ hash: h, rules: f.rules }];
  }
  const files = ["pack.json", "agent-keys.json", "head.json"];
  fs.writeFileSync(path.join(dir, "pack.json"), JSON.stringify(pack, null, 2) + "\n");
  fs.writeFileSync(path.join(dir, "agent-keys.json"), JSON.stringify(rec.state.exportAgentKeys(), null, 2) + "\n");
  fs.writeFileSync(path.join(dir, "head.json"), JSON.stringify(rec.state.heads(), null, 2) + "\n");
  let content = o.content;
  if (content === undefined && o.prompt.person) {
    content = await o.prompt.confirm(
      "Your auditor can also see what the calls said, from this machine's own copy. signafAIde still only receives the fields it was sent. Include it?",
      false,
    );
  }
  if (content) {
    const lines = o.records
      .filter((r) => r.content !== undefined && !r.draft)
      .map((r) => JSON.stringify({ envelope: r.envelope, content: r.content, salt: r.salt }));
    fs.writeFileSync(path.join(dir, "content.jsonl"), lines.join("\n") + (lines.length ? "\n" : ""));
    files.push("content.jsonl");
  }
  const rel = path.relative(rec.state.root, dir) || dir;
  out(`Wrote ${rel}/  ${files.join(" ")}`);
  out("Your auditor checks them with the standalone verifier (no account, no SDK), one of:");
  for (const line of auditorCommands(rec.url, "agent-keys.json", content ? " --content content.jsonl" : ""))
    out(`  ${line}`);
  out(`or with the signafaide-verify binary and the same arguments: ${AUDITOR_DOCS_URL}`);
  return 0;
}

/** How auditors install the standalone verifier (§7). */
export const AUDITOR_DOCS_URL = "https://signafaide.co.uk/docs/verify";

/** The hosted witness, whose service keys are pinned in signafaide-verify. */
const HOSTED = ["https://api.signafaide.co.uk", "https://signafaide.co.uk"];

/** The one command an auditor runs, as npx and uvx lines, pinned to this release. For the hosted
 * witness it passes no --keys: signafaide-verify uses the keys pinned in it and checks them
 * against the published list. A self-hosted witness's keys come from that witness. */
export function auditorCommands(witness: string, agentKeys: string, extra = ""): string[] {
  const base = witness.replace(/\/+$/, "");
  const keys = HOSTED.includes(base) ? "" : ` --keys ${base}/.well-known/signafaide-keys.json`;
  const args = `pack.json${keys} --agent-keys ${agentKeys} --head head.json${extra}`;
  return [`npx signafaide-verify@${VERSION} ${args}`, `uvx signafaide-verify@${VERSION} ${args}`];
}

export { CHECKS_FILE };
