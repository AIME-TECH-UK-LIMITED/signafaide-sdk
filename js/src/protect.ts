/**
 * `signafaide protect [tool]` (spec 1.1, SPEC §8): find the agent's tools in the project, propose
 * which to protect, ask what to block, write `protect(...)` and `record(...)` into the code, write a
 * version 2 checks file, make the sandbox when there is no key, and publish the rules the person
 * chose (§6 `POST /v1/rules`): into the project's sandbox while it is unclaimed, otherwise with the
 * person's session (`signafaide login`). A rule is On only when the person answered On for it at a
 * terminal; every other rule starts Calibrating. Nothing turns a rule On by itself.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import * as C from "./checks.js";
import { CHECKS_FILE, checksPath } from "./checks-runtime.js";
import { byCodePoint, declaredName } from "./coverage.js";
import { Client, SignafaideError } from "./http.js";
import { canonicalize } from "./jcs.js";
import { agentName } from "./records.js";
import type { Recorder } from "./runtime.js";
import { consoleOrigin, loadSession, onConsole, personWitness } from "./session.js";
import { VERSION } from "./version.js";
import { fieldWords, ruleWords, stateWord } from "./words.js";
import { KIND_WORDS, RISKY, agentInCode, codeChanges, findTools, wrapCall, type Field, type FoundTool } from "./find-tools.js";
import { lineDiff } from "./source.js";
import { NOTE_QUESTION, noteWhat, offerNote } from "./agents.js";
import { riskOf } from "./ci-check.js";

type Json = Record<string, any>;

// --- asking a person -----------------------------------------------------------------------

/** How `protect` and `pull` ask. `person` is true only at a terminal: a rule is On, and a field is
 * approved for sending, only when a person answered (never from flags or the environment). */
export interface Prompter {
  readonly person: boolean;
  /** `--yes` without a terminal: protect then saves default rules, all Calibrating. */
  readonly yes?: boolean;
  confirm(question: string, def: boolean): Promise<boolean>;
  choose(question: string, choices: string[], def: number): Promise<number>;
  multi(question: string, choices: string[], defaults: boolean[]): Promise<boolean[]>;
  text(question: string, def?: string): Promise<string>;
}

/** The prompter of a terminal: numbered choices, Enter takes the default. */
export function terminalPrompter(input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout): Prompter & { close(): void } {
  const rl = readline.createInterface({ input, output, terminal: false });
  const lines: string[] = [];
  const waiting: ((s: string) => void)[] = [];
  let ended = false;
  rl.on("line", (l) => {
    const w = waiting.shift();
    if (w) w(l);
    else lines.push(l);
  });
  rl.on("close", () => {
    ended = true;
    for (const w of waiting.splice(0)) w("");
  });
  const ask = (q: string): Promise<string> => {
    output.write(q);
    if (lines.length) return Promise.resolve(lines.shift()!);
    if (ended) return Promise.resolve("");
    return new Promise((r) => waiting.push(r));
  };
  return {
    person: true,
    close: () => rl.close(),
    async confirm(question, def) {
      for (let i = 0; i < 20; i++) {
        const a = (await ask(`? ${question} ${def ? "(Y/n)" : "(y/N)"} `)).trim().toLowerCase();
        if (!a) return def;
        if (["y", "yes"].includes(a)) return true;
        if (["n", "no"].includes(a)) return false;
      }
      return def;
    },
    async choose(question, choices, def) {
      output.write(`? ${question}\n`);
      choices.forEach((c, i) => output.write(`  ${i === def ? ">" : " "} ${i + 1}) ${c}\n`));
      for (let i = 0; i < 20; i++) {
        const a = (await ask(`  number (Enter for ${def + 1}): `)).trim();
        if (!a) return def;
        const n = Number(a);
        if (Number.isInteger(n) && n >= 1 && n <= choices.length) return n - 1;
      }
      return def;
    },
    async multi(question, choices, defaults) {
      output.write(`? ${question}\n`);
      choices.forEach((c, i) => output.write(`  ${i + 1}) [${defaults[i] ? "x" : " "}] ${c}\n`));
      for (let i = 0; i < 20; i++) {
        const a = (await ask(`  numbers to tick, comma separated, 0 for none (Enter keeps the ticks shown): `)).trim();
        if (!a) return [...defaults];
        if (a === "0") return choices.map(() => false);
        const picked = a.split(/[\s,]+/).map(Number);
        if (picked.every((n) => Number.isInteger(n) && n >= 1 && n <= choices.length)) return choices.map((_, j) => picked.includes(j + 1));
      }
      return [...defaults];
    },
    async text(question, def) {
      const a = (await ask(`? ${question} ${def !== undefined ? `(${def}) ` : ""}`)).trim();
      return a || def || "";
    },
  };
}

/** A prompter with no person behind it (no terminal): every question takes its default, and
 * `yes` accepts the code change and the sandbox. It never answers On and never approves a field. */
export function flagPrompter(answers: { yes?: boolean } = {}): Prompter {
  return {
    person: false,
    yes: !!answers.yes,
    async confirm(_q, def) {
      return answers.yes ? true : def;
    },
    async choose(_q, _c, def) {
      return def;
    },
    async multi(_q, _c, defaults) {
      return [...defaults];
    },
    async text(_q, def) {
      return def ?? "";
    },
  };
}

/** A prompter that answers from a list, in order (tests and scripted runs at a terminal). */
export function scriptedPrompter(answers: (string | number | boolean | boolean[])[], person = true): Prompter & { asked: string[] } {
  const asked: string[] = [];
  const next = (q: string): unknown => {
    asked.push(q);
    // The project note's question came after most scripts were written: with no answer left it takes its default (yes).
    if (!answers.length && q.startsWith(NOTE_QUESTION)) return true;
    if (!answers.length) throw new Error(`no answer left for: ${q}`);
    return answers.shift();
  };
  return {
    person,
    asked,
    async confirm(q) {
      return next(q) as boolean;
    },
    async choose(q) {
      return next(q) as number;
    },
    async multi(q) {
      return next(q) as boolean[];
    },
    async text(q) {
      return String(next(q));
    },
  };
}

// --- finding the tools and writing the code (find-tools.ts) ----------------------------------

export { KIND_WORDS, RISKY, addImport, agentInCode, codeChanges, findTools, nameWords, toolKind, walk, wrapCall, wrapOptions, type Field, type FileChange, type Found, type FoundTool, type ToolKind } from "./find-tools.js";

// --- what to block -------------------------------------------------------------------------

const AMOUNT = ["amount", "total", "value", "sum", "price", "cost", "amountcents", "amount_cents", "amountminor", "amount_minor"];
const CURRENCY = ["currency", "ccy", "currencycode", "currency_code"];

/** The field a rule reads for a tool, by its name: its name and its pointer. */
function fieldOf(t: FoundTool, names: string[]): Field | null {
  return t.fields.find((f) => names.includes(f.name.toLowerCase())) ?? null;
}

export interface Choice {
  /** What the person reads: "Payouts above an amount". */
  label: string;
  /** A short word for the rule id: `amount`, `currency`, `rate`. */
  key: string;
  /** The question for its value, and its default. */
  ask: string;
  def: string;
  numeric: boolean;
  /** The rule, from the value the person gave. */
  rule(tool: string, value: string, id: string): Json;
}

export function choicesFor(t: FoundTool): Choice[] {
  const out: Choice[] = [];
  const amount = fieldOf(t, AMOUNT);
  const currency = fieldOf(t, CURRENCY);
  const noun = t.kind === "pays" ? "Payouts" : "Calls";
  if (amount) {
    out.push({
      label: `${noun} above an amount`,
      key: "amount",
      ask: `Block ${t.name} when ${amount.name} is above:`,
      def: "1000",
      numeric: true,
      rule: (tool, v, id) => ({ id, about: `${tool}: ${amount.name} above ${v}.`, action: "block", tools: [tool], agents: null, when: [{ field: amount.pointer, op: "gt", value: Number(v) }] }),
    });
  }
  if (currency) {
    out.push({
      label: `${noun} in other currencies`,
      key: "currency",
      ask: `Block ${t.name} when ${currency.name} is not:`,
      def: "GBP",
      numeric: false,
      rule: (tool, v, id) => ({
        id,
        about: `${tool}: ${currency.name} other than ${v}.`,
        action: "block",
        tools: [tool],
        agents: null,
        when: [currencyCondition(currency.pointer, v)],
      }),
    });
  }
  out.push({
    label: "More than a number of calls a minute",
    key: "rate",
    ask: `Block ${t.name} when there are more calls a minute than:`,
    def: "20",
    numeric: true,
    rule: (tool, v, id) => ({ id, about: `${tool}: more than ${v} calls a minute.`, action: "block", tools: [tool], agents: null, when: [], limit: { calls: Number(v), seconds: 60, per: "agent_tool" } }),
  });
  return out;
}

/** The rule `--limit-field <field> --above <n>` gives: the tool's field of that name (any case), or,
 * for a tool that takes one object whose fields the code does not show, that field of it. */
export function limitChoice(t: FoundTool, field: string): Choice | null {
  const f = t.fields.find((x) => x.name.toLowerCase() === field.toLowerCase()) ?? (t.objectParam && !t.fields.length && /^[A-Za-z_$][\w$]*$/.test(field) ? { name: field, pointer: `/${field}` } : null);
  if (!f) return null;
  return {
    label: `Calls with ${f.name} above a limit`,
    key: AMOUNT.includes(f.name.toLowerCase()) ? "amount" : f.name,
    ask: `Block ${t.name} when ${f.name} is above:`,
    def: "1000",
    numeric: true,
    rule: (tool, v, id) => ({ id, about: `${tool}: ${f.name} above ${v}.`, action: "block", tools: [tool], agents: null, when: [{ field: f.pointer, op: "gt", value: Number(v) }] }),
  };
}

/** The calls a minute of each default rule (`protect --yes`), by what the tool does. */
const DEFAULT_RATE: Record<string, number> = { "pays money": 5, "deletes data": 5, "sends messages": 20, "runs commands": 5, "pushes code": 5, "edits secrets": 5, "edits config": 5 };

/** What makes a tool risky, in words (`check --ci` reads tools the same way); null when it is not. */
export function risk(t: FoundTool): string | null {
  return riskOf(t.name, t.kind);
}

/** The rule `protect --yes` saves for a risky tool, without a person to ask: a tool that pays is
 * blocked above 1000 when it has an amount, every other risky tool (and a payment without an
 * amount) above a number of calls a minute. It starts Calibrating: it blocks nothing until a
 * person turns it On. */
export function defaultRule(t: FoundTool, decl: string, taken: Set<string>): Json | null {
  const why = risk(t);
  if (why === null) return null;
  const amount = why === KIND_WORDS.pays ? fieldOf(t, AMOUNT) : null;
  if (amount) return { id: ruleId(decl, "amount", taken), about: `${decl}: ${amount.name} above 1000.`, action: "block", tools: [decl], agents: null, when: [{ field: amount.pointer, op: "gt", value: 1000 }] };
  const n = DEFAULT_RATE[why] ?? 5;
  return { id: ruleId(decl, "rate", taken), about: `${decl}: more than ${n} calls a minute.`, action: "block", tools: [decl], agents: null, when: [], limit: { calls: n, seconds: 60, per: "agent_tool" } };
}

/** Said for each rule a run without a person adds. */
export const CALIBRATING_LINE =
  "  Starts Calibrating: it notes the calls it would have blocked and blocks none. Only a person turns it On: npx signafaide protect at a terminal, or the console.";

/** "not GBP" as a condition: `ne` for one currency (it reads `currency is not "GBP"`), `not_in` for several. */
function currencyCondition(field: string, v: string): Json {
  const list = v.split(/[\s,]+/).filter(Boolean).map((x) => x.toUpperCase());
  return list.length === 1 ? { field, op: "ne", value: list[0] } : { field, op: "not_in", value: list };
}

/** A rule id for a tool and a kind of rule: `approve_payout-amount`. */
export function ruleId(tool: string, what: string, taken: Set<string>): string {
  const base =
    `${tool}-${what}`
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^[^a-z0-9]+/, "")
      .slice(0, 60) || "rule";
  let id = base;
  for (let i = 2; taken.has(id); i++) id = `${base}-${i}`;
  taken.add(id);
  return id;
}

// --- rules an agent run proposed -------------------------------------------------------------

export interface Proposal {
  rule: Json;
  on: string;
}

/** The rule an agent run proposed for this tool (checks file version 2: `proposed` names a local
 * rule, or holds a rule only the witness applies, one with a limit; and the day), or null. */
export function proposalFor(file: Json | null, decl: string): Proposal | null {
  if (!file || C.checksFileVersion(file) !== 2 || !Array.isArray(file.proposed)) return null;
  for (const p of file.proposed) {
    const rule = typeof p.rule === "object" && p.rule ? (p.rule.tools?.includes(decl) ? p.rule : undefined) : file.rules?.rules?.find((r: Json) => r.id === p.rule && r.tools?.includes(decl));
    if (rule) return { rule, on: p.on };
  }
  return null;
}

/** The id a `proposed` entry names: its local rule's, or that of the rule it holds. */
export const proposedId = (p: Json): string => (typeof p.rule === "string" ? p.rule : p.rule?.id);

/** Today as `YYYY-MM-DD` (UTC). */
const today = (): string => new Date().toISOString().slice(0, 10);

// --- the checks file -------------------------------------------------------------------------

/** A version 2 checks file from the one in place (version 1 is rewritten: `strict` becomes
 * `protect`, the file's mode becomes each listed tool's mode, `fail` moves to the console). */
export function toVersion2(file: Json | null): Json {
  if (!file) return { format: C.CHECKS_FORMAT_2, checks: Object.fromEntries(C.FILE_CHECKS.map((k) => [k, true])), tools: {}, addresses: { hosts: [], cidrs: [], resolve: false }, rules: null };
  if (C.checksFileVersion(file) === 2) return JSON.parse(JSON.stringify(file));
  const tools: Json = {};
  for (const name of Object.keys(file.tools)) {
    const s = C.toolSettings(file, name);
    tools[name] = s.strict ? { protect: true, mode: s.mode, ...(s.disclose.length ? { disclose: [...new Set(s.disclose)] } : {}) } : { protect: false, mode: s.mode };
  }
  const out: Json = { format: C.CHECKS_FORMAT_2, checks: file.checks, tools, addresses: file.addresses, rules: file.rules };
  if (file.ruling_timeout_ms !== undefined) out.ruling_timeout_ms = file.ruling_timeout_ms;
  if (file.ci !== undefined) out.ci = file.ci;
  return out;
}

export function writeChecksFile(p: string, doc: Json): void {
  const err = C.checksFileErrors(doc);
  if (err) throw new SignafaideError(`signafaide would write an invalid checks file (${err}); nothing was written`, { code: "state" });
  fs.writeFileSync(p, JSON.stringify(doc, null, 2) + "\n");
}

// --- publishing ------------------------------------------------------------------------------

export interface Publisher {
  client: Client;
  how: "session" | "sandbox_key";
  who: string;
}

/** Who may publish here (§6): the person's session when one is held for this witness, else the
 * project's key while it is an unclaimed sandbox. The reason when neither. The witness is never
 * taken from the project's `.env` (§8): when that file names another one, nothing is saved. */
export async function publisher(rec: Recorder): Promise<Publisher | string> {
  const witness = personWitness(rec._url);
  if (rec.url !== witness)
    return `SIGNAFAIDE_URL in the project's .env names ${rec.url}, and rules are saved only at a witness named by --url or SIGNAFAIDE_URL in the environment (a project file never chooses where a person's session goes); run it again with --url ${rec.url} if you trust that witness`;
  const s = loadSession(witness);
  if (s && s.url === witness) return { client: new Client(witness, s.session, 15_000, rec.clientId()), how: "session", who: s.person?.email ?? "you" };
  const key = rec.apiKey;
  if (!key) return "there is no API key";
  if (key.startsWith("sfa_live_")) return "a live project's rules are saved by a signed-in person";
  try {
    const p = await rec.client(10_000).project();
    if (p?.claimed) return "the sandbox is claimed, so its rules are saved by a signed-in person";
  } catch (e) {
    return `the witness could not be asked whether the sandbox is claimed (${(e as Error).message})`;
  }
  return { client: rec.client(15_000), how: "sandbox_key", who: "this machine (unclaimed sandbox)" };
}

/** Keep rules a run without a person could not save in the checks file as an agent run's
 * proposals, all Calibrating: a rule without a limit as a local rule (the tool's mode is watch, so
 * it blocks nothing), a rule with a limit held in its `proposed` entry (only the witness counts
 * calls, so it never applies here). A person who runs protect at a terminal is offered each one. */
export function keepProposed(doc: Json, rules: Json[]): void {
  if (!rules.length) return;
  const local = doc.rules ?? { default: "allow", rules: [] };
  let proposals: Json[] = Array.isArray(doc.proposed) ? doc.proposed : [];
  for (const r of rules) {
    const { state: _state, ...plain } = r;
    proposals = proposals.filter((p) => proposedId(p) !== plain.id);
    if ("limit" in plain) proposals.push({ rule: plain, by: "agent", on: today() });
    else {
      local.rules = local.rules.filter((x: Json) => x.id !== plain.id);
      local.rules.push(plain);
      proposals.push({ rule: plain.id, by: "agent", on: today() });
      for (const decl of plain.tools ?? []) if (doc.tools[decl]?.protect) doc.tools[decl].mode = "watch";
    }
  }
  if (local.rules.length) doc.rules = local;
  doc.proposed = proposals;
}

/** The longest a rule may be in an add link, once decoded (journeys/NOTES.md §1). */
const ADD_LINK_MAX = 4000;

/** The console link that adds one suggested rule to one tool (journeys/NOTES.md §1):
 * `<add_in_console>/<agent>/<tool>?add=<rule>`, the rule with only the keys the page takes and never
 * a state (a rule added from the link starts Calibrating). Null when it would be too long. */
export function addLink(tools: string, agent: string, r: Json): string | null {
  const tool = r.tools?.[0];
  if (typeof tool !== "string") return null;
  const rule = (about: boolean): Json => ({ id: r.id, ...(about && r.about ? { about: r.about } : {}), action: "block", tools: [tool], agents: null, when: r.when ?? [], ...(r.limit ? { limit: r.limit } : {}) });
  const text = [rule(true), rule(false)].map((x) => JSON.stringify(x)).find((x) => x.length <= ADD_LINK_MAX);
  if (!text) return null;
  return `${tools.replace(/\/+$/, "")}/${encodeURIComponent(agent)}/${encodeURIComponent(tool)}?add=${encodeURIComponent(text)}`;
}

/** Where a person adds the rules of a project an API key cannot save them in: the witness says it
 * (`add_in_console` in its refusal of `POST /v1/rules`, the project's Tools page); never built from
 * SIGNAFAIDE_URL. Asked only of a witness a person chose (not one a project's `.env` named).
 * `{published}` when the witness saved them after all (a sandbox nobody had claimed yet). */
export async function addInConsole(rec: Recorder, rules: Json[]): Promise<string | { published: Json } | null> {
  if (!rec.apiKey) return null;
  try {
    if (rec.url !== personWitness(rec._url)) return null;
  } catch {
    return null;
  }
  try {
    return { published: await publishRules(rec, { client: rec.client(15_000), how: "sandbox_key", who: "this machine (unclaimed sandbox)" }, rules) };
  } catch (e) {
    const link = (e as SignafaideError).body?.error?.add_in_console;
    if (typeof link !== "string") return null;
    try {
      const u = new URL(link);
      return (u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password ? u.href.replace(/\/+$/, "") : null;
    } catch {
      return null;
    }
  }
}

/** The draft of the next version: the held version's settings and rules, plus `add`. A new rule
 * set starts in enforce mode (§9); in a rule set in watch mode no rule may be On, so new rules
 * stay Calibrating there. */
export function nextDraft(held: Json | null, add: Json[]): Json {
  if (!held) return { mode: "enforce", default: "allow", fail: {}, addresses: { hosts: [], cidrs: [] }, approved: null, rules: add };
  const watch = held.mode === "watch";
  const rules = [...held.rules, ...add.map((r) => (watch ? { ...r, state: "calibrating" } : r))];
  const draft: Json = { mode: held.mode, default: held.default, fail: held.fail, addresses: held.addresses, approved: held.approved, rules };
  if (held.fingerprint_exceptions) draft.fingerprint_exceptions = held.fingerprint_exceptions;
  return draft;
}

/** §6: the console page a version waits on when a person must confirm it there (loosening a
 * live project's rules from the command line): from the answer, or from a refusal's body. Only a
 * page on the witness's console is given back; `""` when the witness asked but sent another page. */
export function confirmPage(rec: Recorder, x: unknown): string | null {
  const body = (x instanceof SignafaideError ? x.body : x) as Json | null;
  const link = body?.confirm_in_console ?? body?.error?.confirm_in_console ?? (x instanceof SignafaideError && x.code === "confirm_in_console" ? "" : undefined);
  if (link === undefined || link === null) return null;
  return onConsole(link, consoleOrigin(rec.url)) ?? "";
}

/** The lines that say a version waits for a person in the console. */
export function confirmLines(page: string): string[] {
  return page
    ? ["Not saved yet: loosening this project's rules is confirmed by a person in the console.", `           Open ${page}`, "           and confirm there; then run signafaide rules pull."]
    : ["Not saved yet: loosening this project's rules is confirmed by a person in the console. Open the console and confirm there (the page the witness sent is not on its console, so it is not shown)."];
}

/** Publish the next version with `add` (§6 `POST /v1/rules`), and keep it as the held version. */
export async function publishRules(rec: Recorder, pub: Publisher, add: Json[]): Promise<Json> {
  const key = rec.apiKey;
  if (!key) throw new SignafaideError("there is no API key", { code: "invalid_key" });
  await rec.resolveProject(key);
  const pe = rec.checks.projectEnv();
  if (!pe) throw new SignafaideError("the API key's project is not known yet", { code: "network" });
  await rec.checks.pullRules();
  const held = rec.checks.heldRules();
  const draft = nextDraft(held, add);
  let item: Json;
  try {
    item = await pub.client.publishRules({ project: pe[0], env: pe[1], after: held ? held.version : null, draft });
  } catch (e) {
    const page = confirmPage(rec, e);
    if (page !== null) throw new SignafaideError(confirmLines(page).map((l) => l.trim()).join(" "), { code: "confirm_in_console", body: { confirm_in_console: page } });
    throw e;
  }
  const page = confirmPage(rec, item);
  if (page !== null) throw new SignafaideError(confirmLines(page).map((l) => l.trim()).join(" "), { code: "confirm_in_console", body: { confirm_in_console: page } });
  if (!item || typeof item !== "object" || !item.rules) throw new SignafaideError("the witness answered without the published version", { code: "bad_response" });
  // Keep it as the held version when it verifies (§10.2), so the next call uses it at once.
  if (!rec.checks.keepRules(item)) await rec.checks.pullRules();
  return item;
}

/** The keys of a draft (§6 `POST /v1/rules`); a whole rule set document's other keys are the
 * service's, and are dropped. */
const DRAFT_KEYS = ["mode", "default", "fail", "addresses", "approved", "rules", "fingerprint_exceptions"];
const SERVICE_KEYS = ["format", "project", "env", "set", "version", "prev", "issued"];

/** A draft from a file: a draft, or a rule set document (its service keys dropped). */
export function draftFrom(doc: unknown): Json {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new SignafaideError("the file must hold a JSON object: a draft {mode, default, fail, addresses, approved, rules} or a rule set", { code: "bad_request" });
  const d = doc as Json;
  const unknown = Object.keys(d).filter((k) => !DRAFT_KEYS.includes(k) && !SERVICE_KEYS.includes(k));
  if (unknown.length) throw new SignafaideError(`the file has the unknown key '${unknown.sort(byCodePoint)[0]}'`, { code: "bad_request" });
  const missing = DRAFT_KEYS.slice(0, 6).filter((k) => !(k in d));
  if (missing.length) throw new SignafaideError(`the file lacks the key '${missing[0]}'`, { code: "bad_request" });
  const draft: Json = {};
  for (const k of DRAFT_KEYS) if (k in d) draft[k] = d[k];
  return draft;
}

/** `signafaide rules publish <file>` (§8): publish the file's draft as the project's next rule set
 * version, with the person's session (or the key of an unclaimed sandbox), once the person says
 * yes at a terminal. Returns the exit code. */
export async function runRulesPublish(rec: Recorder, file: string, prompt: Prompter, out: (s: string) => void): Promise<number> {
  let draft: Json;
  try {
    draft = draftFrom(JSON.parse(fs.readFileSync(file, "utf8")));
  } catch (e) {
    out(`Not published: ${file}: ${(e as Error).message}`);
    return 1;
  }
  const pub = await publisher(rec);
  if (typeof pub === "string") {
    out(`Not published: ${pub}. Sign in first: npx signafaide login`);
    return 1;
  }
  const key = rec.apiKey;
  if (!key) {
    out("Not published: there is no API key, so the project is not known. Run npx signafaide init, or set SIGNAFAIDE_API_KEY");
    return 1;
  }
  await rec.resolveProject(key);
  const pe = rec.checks.projectEnv();
  if (!pe) {
    out("Not published: the API key's project is not known yet (the witness could not be reached)");
    return 1;
  }
  await rec.checks.pullRules();
  const held = rec.checks.heldRules();
  let who = pub.who;
  if (pub.how === "session") {
    try {
      const s = await pub.client.session();
      const role = s.projects?.find((x) => x.project === pe[0] && x.env === pe[1])?.role;
      if (role) who = `${who} (${role})`;
    } catch {
      /* the witness decides who may publish; the role is only shown */
    }
  }
  const next = held ? held.version + 1 : 1;
  out(`Publish rule set version ${next} of ${pe[0]} (${pe[1]}) at ${rec.url} as ${who}, after version ${held ? held.version : "none"}:`);
  out(`  mode ${draft.mode}, calls no rule matches: ${draft.default}`);
  const before = new Map<string, Json>((held?.rules ?? []).map((r: Json) => [r.id, r]));
  const doc = { mode: draft.mode, rules: Array.isArray(draft.rules) ? draft.rules : [] };
  for (const r of doc.rules) {
    if (!r || typeof r !== "object") continue;
    let words: string;
    try {
      words = ruleWords(r);
    } catch {
      words = `rule ${String(r.id)}`;
    }
    const state = C.ruleState(doc, r);
    const was = before.get(r.id);
    const change = !was ? "new" : C.ruleState(held!, was) !== state ? `was ${stateWord(C.ruleState(held!, was))}` : canonicalize(was) === canonicalize(r) ? "unchanged" : "changed";
    out(`  ${stateWord(state).padEnd(12)} ${words}  (${change})`);
  }
  for (const id of before.keys()) if (!doc.rules.some((r: Json) => r?.id === id)) out(`  removed      rule ${id}`);
  if (!prompt.person) {
    out("Not published: publishing asks a person at a terminal. Run it at one.");
    return 1;
  }
  if (!(await prompt.confirm(`Publish this as version ${next}?`, false))) {
    out("Not published.");
    return 1;
  }
  let item: Json;
  try {
    item = await pub.client.publishRules({ project: pe[0], env: pe[1], after: held ? held.version : null, draft });
  } catch (e) {
    const page = confirmPage(rec, e);
    if (page !== null) {
      for (const l of confirmLines(page)) out(l);
      return 1;
    }
    out(`Not published: ${(e as Error).message}`);
    return 1;
  }
  const page = confirmPage(rec, item);
  if (page !== null) {
    for (const l of confirmLines(page)) out(l);
    return 1;
  }
  if (!item || typeof item !== "object" || !item.rules) {
    out("Not published: the witness answered without the published version");
    return 1;
  }
  if (!rec.checks.keepRules(item)) await rec.checks.pullRules();
  out(`Rules      saved ${pub.how === "sandbox_key" ? "in your sandbox" : `by ${who}`} as version ${item.rules.version}, signed by signafAIde`);
  return 0;
}

// --- the command ---------------------------------------------------------------------------

export interface ProtectOptions {
  rec: Recorder;
  root: string;
  tool?: string;
  /** Rules only on this machine (the checks file): no sandbox, nothing published. */
  local?: boolean;
  /** `--limit-field <field> --above <n>`: block the tool when that field is above n, without asking
   * what to block. Without a person the rule starts Calibrating, as every rule does. */
  limit?: { field: string; above: number };
  prompt: Prompter;
  out: (s: string) => void;
}

export interface ProtectResult {
  code: number;
  protected: string[];
  rules: Json[];
  published: Json | null;
}

/** The agent's name: from package.json's name, else the project folder's. */
export function projectAgent(root: string, rec: Recorder): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    if (typeof pkg.name === "string" && pkg.name) return agentName(pkg.name.replace(/^@[^/]+\//, ""));
  } catch {
    /* no package.json */
  }
  return rec.defaultAgent;
}

/** Whether `.gitignore` in `root` keeps `.env` out of git (an exact line, `/.env`, `.env*` or `*.env`). */
export function envIgnored(root: string): boolean {
  let text: string;
  try {
    text = fs.readFileSync(path.join(root, ".gitignore"), "utf8");
  } catch {
    return false;
  }
  return text.split(/\r?\n/).some((l) => ["./.env", ".env", "/.env", ".env*", "*.env", ".env.*"].includes(l.trim()));
}

/** Whether the project's `.env` holds the API key. */
function keyInEnvFile(root: string): boolean {
  try {
    return /^\s*SIGNAFAIDE_API_KEY\s*=\s*\S/m.test(fs.readFileSync(path.join(root, ".env"), "utf8"));
  } catch {
    return false;
  }
}

export async function runProtect(o: ProtectOptions): Promise<ProtectResult> {
  const { rec, root, prompt, out } = o;
  const rel = (p: string): string => path.relative(root, p) || p;
  const found = findTools(root, o.tool);
  if (!found.tools.length) {
    out(
      o.tool
        ? `No tool named ${o.tool} was found in ${root}.`
        : `No tools were found in ${root}. protect looks for an object named like tools ({ approve_payout, ... }), exported functions in files named like tools, Vercel AI SDK, OpenAI Agents and LangChain tool(...) calls, LangChain DynamicStructuredTool, MCP server.tool(...) and registerTool(...), and methods of a class named like tools.`,
    );
    out("Wrap a function by hand: protect(fn, { args: [...], agent: \"<agent>\" }) from signafaide.");
    return { code: 1, protected: [], rules: [], published: null };
  }
  const named = agentInCode(found, root);
  const agent = named ?? projectAgent(root, rec);
  out("signafAIde protect");
  out("");
  out(`Agent      ${agent}${named ? " (the name the code already uses)" : ""}`);
  out(`Found      ${found.tools.length === 1 ? "1 tool" : `${found.tools.length} tools`} in ${[...new Set(found.tools.map((t) => rel(t.file)))].join(", ")}`);
  out("");
  const w = Math.max(16, ...found.tools.map((t) => t.name.length + 2));
  out(`  ${"tool".padEnd(w)} ${"does".padEnd(16)} suggested`);
  for (const t of found.tools) out(`  ${t.name.padEnd(w)} ${KIND_WORDS[t.kind].padEnd(16)} ${RISKY.has(t.kind) ? "protect" : "record"}${t.framework ? `  (${t.framework})` : t.shape === "method" ? "  (class method)" : ""}`);
  out("");
  out(`${found.tools.length === 1 ? "It" : `All ${found.tools.length} tools`} will be recorded: each call signed here and witnessed by signafAIde.`);
  out("A protected tool also waits for signafAIde to allow it before it runs.");
  if (found.tools.some((t) => t.kind === "other")) out('"not classified": its name does not say what it does. Protect it if it pays, deletes, sends or changes anything.');
  out("");
  let chosen: FoundTool[];
  if (o.tool) chosen = found.tools.filter((t) => t.name === o.tool || t.fn === o.tool);
  else if (!prompt.person) {
    // Nobody to ask: every risky tool is protected (and any protected in the code already).
    chosen = found.tools.filter((t) => risk(t) !== null || t.wrapped === "protect");
    if (chosen.length)
      out(`Protect    ${chosen.map((t) => t.name).join(", ")}: without a terminal, every tool that pays, deletes, sends, runs commands, pushes code or edits secrets or config is protected`);
  } else {
    // Every tool is in the question; the first risky one, and any already protected, are ticked.
    const firstRisky = found.tools.findIndex((t) => RISKY.has(t.kind));
    const risky = found.tools.filter((t) => RISKY.has(t.kind));
    const question =
      risky.length > 1
        ? `Protect which tools? Suggested: ${risky.map((t) => t.name).join(", ")}. Only ${found.tools[firstRisky].name} is ticked; tick the others to protect them now (each then asks its own short questions), or leave them and run npx signafaide protect <tool> later.`
        : "Protect which tools?";
    const ticks = await prompt.multi(
      question,
      found.tools.map((t) => `${t.name} (${KIND_WORDS[t.kind]})`),
      found.tools.map((t, i) => i === firstRisky || t.wrapped === "protect"),
    );
    chosen = found.tools.filter((_, i) => ticks[i]);
    const later = found.tools.filter((t, i) => !ticks[i] && RISKY.has(t.kind));
    if (later.length) out(`  Protect the others later: npx signafaide protect ${later[0].name}`);
  }
  // Positional arguments: rules find a value by its name, so the names go into the code.
  for (const t of [...chosen]) {
    if (t.params.length > 1 && !t.objectParam && t.site && !t.wrapped) {
      out("");
      const ok = await prompt.confirm(`${t.name} takes ${t.params.length} separate arguments: (${t.params.join(", ")}).\n  Rules find a value by its name, so protect writes the names into the code. OK?`, true);
      if (!ok) {
        out(`  ${t.name}: left as it is; rules cannot read its arguments by name until they are named.`);
        chosen = chosen.filter((x) => x !== t);
      }
    }
  }
  // One object whose fields the code does not show: ask for them.
  for (const t of chosen) {
    if (!t.objectParam || t.fields.length) continue;
    out("");
    const ans = prompt.person ? await prompt.text(`${t.name} takes one object, and its fields are not in the code protect read. Which fields does it hold (comma separated, e.g. payee, amount, currency; Enter for none)?`, "") : "";
    const names = ans.split(/[\s,]+/).filter((x) => /^[A-Za-z_$][\w$]*$/.test(x));
    t.fields = [...new Set(names)].map((n) => ({ name: n, pointer: `/${n}` }));
    if (!t.fields.length) out(`  ${t.name}: no fields known, so only a limit on calls a minute can be set here. Name the fields in its type (or a destructuring pattern), or add rules in the console.`);
  }
  const held = o.local ? null : rec.checks.heldRules();
  const taken = new Set<string>((held?.rules ?? []).map((r: Json) => r.id));
  let fileNow: Json | null = null;
  try {
    fileNow = rec.checks.file();
  } catch {
    fileNow = null;
  }
  const newRules: Json[] = [];
  const consumed = new Set<string>(); // ids of proposed rules offered to this person (used or dropped)
  const notChosen: string[] = [];
  const sendsByTool = new Map<string, Set<string>>();
  for (const t of chosen) {
    const decl = declaredName(t.name);
    const choices = choicesFor(t);
    const sends = new Set<string>();
    sendsByTool.set(t.name, sends);
    out("");
    let c: Choice | null = null;
    let rule: Json;
    // A rule an agent run proposed here earlier is offered first, with the agent's value.
    let proposed: Proposal | null = null;
    const pr = !o.limit && !o.local && prompt.person ? proposalFor(fileNow, decl) : null;
    if (pr) {
      consumed.add(pr.rule.id);
      if (await prompt.confirm(`An agent run on ${pr.on} proposed this rule for ${t.name}; it blocks nothing yet: ${ruleWords(pr.rule)}\n  Use it, with the agent's value?`, true)) proposed = pr;
      else out(`  The proposal of ${pr.on} is dropped; asking as usual.`);
    }
    if (o.limit) {
      // From the command line: the field and the limit are given, nothing is asked.
      const lim = limitChoice(t, o.limit.field);
      if (!lim) {
        const names = t.fields.map((f) => f.name);
        out(`  ${t.name} has no field named ${o.limit.field}${names.length ? ` (its fields: ${names.join(", ")})` : ""}: no rule added.`);
        notChosen.push(`${t.name} has no field named ${o.limit.field}, so no rule was added`);
        continue;
      }
      rule = lim.rule(decl, String(o.limit.above), ruleId(decl, lim.key, taken));
    } else if (proposed) {
      rule = { ...proposed.rule, id: ruleId(decl, proposed.rule.id.slice(decl.length + 1) || "limit", taken) };
      out(`  Rule: ${ruleWords(rule)}  (proposed by an agent run on ${proposed.on})`);
    } else if (!prompt.person && prompt.yes && defaultRule(t, decl, new Set(taken)) !== null) {
      // protect --yes: a sensible default for what the tool does, Calibrating (it blocks nothing).
      rule = defaultRule(t, decl, taken)!;
    } else {
      const pick = await prompt.choose(`What should we block on ${t.name}?`, [...choices.map((x) => x.label), "Nothing yet, record only"], prompt.person ? 0 : choices.length);
      if (pick >= choices.length) continue;
      c = choices[pick];
      const value = await prompt.text(c.ask, c.def);
      if (!value || (c.numeric && !(Number(value) > 0 && Number.isFinite(Number(value))))) {
        out(`  ${value || "(nothing)"} is not a number above 0: no rule added for ${t.name}.`);
        continue;
      }
      rule = c.rule(decl, value, ruleId(decl, c.key, taken));
    }
    out(`  Rule: ${ruleWords(rule)}`);
    let on = false;
    if (prompt.person) on = (await prompt.choose('Turn it on now? On blocks the call. Calibrating only notes "Would have blocked".', ["On", "Calibrating"], 0)) === 0;
    else out(CALIBRATING_LINE);
    newRules.push({ ...rule, state: on ? "on" : "calibrating" });
    for (const x of rule.when) sends.add(x.field);
    if (!c) continue;
    const extras = choices.filter((x) => x !== c);
    if (extras.length) {
      out("");
      out("  Optional, each starts Calibrating and never blocks until a person turns it on:");
      const extraRules = extras.map((x) => x.rule(decl, x.def, ""));
      const ticks = await prompt.multi("Also calibrate", extraRules.map((r) => ruleWords(r).replace(` ${decl} `, " ")), extras.map(() => false));
      extras.forEach((x, i) => {
        if (!ticks[i]) return;
        const r: Json = { ...extraRules[i], id: ruleId(decl, x.key, taken), state: "calibrating" };
        newRules.push(r);
        for (const y of r.when) sends.add(y.field);
      });
      out("  Rules added later in the console also start Calibrating.");
    }
  }
  out("");
  const notDone: string[] = [...notChosen];
  let finish: string | null = null;
  // What leaves the machine: the fields of the rules the person chose, approved here because a
  // person chose them. Without a person nothing is approved (`signafaide pull` asks at a terminal).
  const fileBefore = toVersion2(fileNow);
  for (const t of chosen) {
    const sends = sendsByTool.get(t.name) ?? new Set<string>();
    const fields = [...sends].sort(byCodePoint);
    const n = newRules.filter((r) => r.tools?.includes(declaredName(t.name))).length;
    // Fields a person approved earlier (`pull` or `protect` at a terminal) are sent already.
    const was = fileBefore.tools?.[declaredName(t.name)];
    const approved: string[] = was?.protect ? (was.disclose ?? []) : [];
    const fresh = fields.filter((f) => !approved.includes(f));
    if (!o.local && !prompt.person && fresh.length) {
      const sent = fields.filter((f) => approved.includes(f));
      out(`Sends to signafAIde when ${t.name} runs: ${sent.length ? `${sent.map(fieldWords).join(", ")} (approved earlier); not ${fresh.map(fieldWords).join(", ")} yet` : "nothing yet"}. Its rules need ${fresh.map(fieldWords).join(", ")}: run npx signafaide pull at a terminal to approve sending ${fresh.length === 1 ? "it" : "them"}.`);
      notDone.push(`sending ${fresh.map(fieldWords).join(", ")} for ${t.name} is not approved (npx signafaide pull at a terminal)`);
      finish ??= "npx signafaide pull (at a terminal)";
      for (const f of fresh) sends.delete(f);
    } else if (!o.local && !prompt.person && fields.length) {
      out(`Sends to signafAIde when ${t.name} runs: ${fields.map(fieldWords).join(", ")} (approved earlier; the fields your ${n === 1 ? "rule needs" : `${n} rules need`})`);
    } else if (!o.local) {
      out(`Sends to signafAIde when ${t.name} runs: ${fields.map(fieldWords).join(", ") || "nothing but the tool's fingerprints"}${fields.length ? ` (the fields your ${n === 1 ? "rule needs" : `${n} rules need`})` : ""}`);
    }
    const never = t.fields.filter((f) => !sends.has(f.pointer)).map((f) => f.name);
    if (never.length && !o.local) out(`Never sent to signafAIde: ${never.join(", ")}. Your own records on this machine keep the whole call.`);
  }
  if (chosen.length && !o.local) out("If signafAIde can't be reached: stop (it retries for 10 s; change it in the console)");
  out("");
  // The sandbox, when there is no key and the rules go to the witness.
  // A sandbox only on a person's answer: nothing is sent without an explicit human opt-in (§8).
  if (!o.local && chosen.length && !rec.apiKey && !prompt.person) {
    out("Sandbox    not made: only a person at a terminal opts in. Run npx signafaide protect (or init) in a terminal.");
    notDone.push("no sandbox and no API key, so protected tools stop until there is one");
    finish = "npx signafaide protect (in a terminal)";
  }
  if (!o.local && chosen.length && !rec.apiKey && prompt.person) {
    const ok = await prompt.confirm("Make a free sandbox for these rules? No sign-up; test data only, deleted after 30 days unless you keep it.", true);
    if (ok) {
      rec.state.ignoreInGit(".env");
      await rec.createSandbox({ writeUrl: false });
      const sb = rec.state.sandbox();
      out(`Sandbox    made for you, no sign-up. Test data only, deleted after 30 days.`);
      if (sb?.claim_url) out(`           Keep it: ${sb.claim_url}`);
    } else {
      notDone.push("no sandbox and no API key, so protected tools stop until there is one");
      finish ??= "npx signafaide protect, and answer yes to the sandbox (or set SIGNAFAIDE_API_KEY)";
    }
  }
  // The code. With --local there is no witness to wait for: the code records, and the checks
  // file's mode for the tool (enforce when a rule is On) decides whether the local rules block.
  const changed: [string, string][] = [];
  const protectSet = new Set(o.local ? [] : chosen.map((t) => t.name));
  const handLines: string[] = [];
  const changes = codeChanges(found, protectSet, agent, root, o.tool ? findTools(root) : found);
  const written = new Set<string>();
  for (const ch of changes) {
    out(`Change     ${rel(ch.file)}`);
    for (const l of lineDiff(ch.before, ch.after)) out(`  ${l}`);
    if (await prompt.confirm(`Write this change to ${rel(ch.file)}?`, true)) {
      fs.writeFileSync(ch.file, ch.after);
      written.add(ch.file);
      const prot = ch.tools.filter((t) => protectSet.has(t.name) || t.wrapped === "protect").map((t) => t.name);
      changed.push([rel(ch.file), ch.tools.length ? `${ch.tools.length === 1 ? "1 tool" : `${ch.tools.length} tools`} recorded${prot.length ? `, ${prot.join(", ")} protected` : ""}` : `agent ${agent} named in declareTools`]);
    } else {
      for (const t of ch.tools) handLines.push(`  ${t.name}: ${wrapCall(t, protectSet.has(t.name) || t.wrapped === "protect", agent)},`);
      notDone.push(`${rel(ch.file)} was not changed: add the lines below by hand`);
    }
    out("");
  }
  for (const t of chosen) {
    if (t.site && written.has(t.file) && t.async === false && t.shape !== "framework" && !o.local)
      out(`Note       ${t.name} is not async: protect(...) makes it return a Promise, so every caller must await it.`);
  }
  // Tools protect cannot write: MCP servers (the gateway), class methods (by hand).
  const mcp = found.tools.filter((t) => t.shape === "mcp");
  if (mcp.length) {
    const strict = mcp.filter((t) => protectSet.has(t.name)).map((t) => t.name);
    out(`MCP server tools (${mcp.map((t) => t.name).join(", ")}) are recorded by the gateway, with no change to the server's code. In the MCP client's config, start the server through it:`);
    out(`           npx signafaide gateway --agent ${agent}${strict.length ? ` --strict-tools ${strict.join(",")}` : ""} -- <the command that starts your server>`);
    notDone.push("the MCP client's config does not start the server through the gateway yet (the command above)");
  }
  for (const t of found.tools.filter((x) => x.shape === "method")) handLines.push(`  ${t.name}: wrap it where the class's tools are handed to the agent: ${wrapCall(t, protectSet.has(t.name), agent, `this.${t.fn}.bind(this)`)}`);
  if (found.tools.some((t) => t.shape === "method")) notDone.push("class methods are not wrapped: add the lines below by hand");
  if (handLines.length) {
    out("Add this to the code by hand:");
    out(`  import { protect, record, declareTools } from "signafaide";`);
    for (const l of handLines) out(l);
    out(`  declareTools([${found.tools.filter((t) => t.shape !== "mcp").map((t) => JSON.stringify(t.name)).join(", ")}], { agent: ${JSON.stringify(agent)} });`);
    out("");
  }
  // The project note, so the next coding agent here protects such tools too (asked; never twice).
  const noteChanges = await offerNote(root, prompt, out);
  if (noteChanges.length) out("");
  // The checks file (version 2).
  const cp = checksPath(rec.state.root) ?? path.join(root, CHECKS_FILE);
  const doc = toVersion2(fileNow);
  for (const t of chosen) {
    const decl = declaredName(t.name);
    if (o.local) {
      // On this machine a tool's rules are all On (enforce) or all Calibrating (watch): On only
      // when a person turned a rule On here, or when its local rules were On already.
      const was = doc.tools[decl];
      const onBefore = !!was && was.protect !== true && was.mode === "enforce" && (doc.rules?.rules ?? []).some((r: Json) => r.tools === null || r.tools.includes(decl));
      const onNow = newRules.some((r) => r.state === "on" && r.tools?.includes(decl));
      doc.tools[decl] = { protect: false, mode: onBefore || onNow ? "enforce" : "watch" };
      continue;
    }
    const have: string[] = doc.tools[decl]?.protect ? (doc.tools[decl].disclose ?? []) : [];
    const disclose = [...have, ...[...(sendsByTool.get(t.name) ?? [])].sort(byCodePoint).filter((p) => !have.includes(p))];
    doc.tools[decl] = { protect: true, ...(disclose.length ? { disclose } : {}) };
  }
  // Proposals a person was just offered are used up: the rule is published below or dropped.
  if (consumed.size && doc.rules) {
    doc.rules.rules = doc.rules.rules.filter((r: Json) => !consumed.has(r.id));
    if (!doc.rules.rules.length) doc.rules = null;
  }
  if (Array.isArray(doc.proposed)) doc.proposed = doc.proposed.filter((p: Json) => !consumed.has(proposedId(p)));
  // An agent run with no key cannot save its rule at the witness: it is kept here as a local
  // Calibrating rule (the tool's mode is watch, so it blocks nothing) that a person is offered later.
  const keepProposal = !o.local && (!!o.limit || !!prompt.yes) && !prompt.person && !rec.apiKey && newRules.length > 0;
  if (keepProposal) keepProposed(doc, newRules);
  if (Array.isArray(doc.proposed) && !doc.proposed.length) delete doc.proposed;
  if (o.local && newRules.length) {
    const local = doc.rules ?? { default: "allow", rules: [] };
    const ids = new Set(local.rules.map((r: Json) => r.id));
    for (const r of newRules) {
      if ("limit" in r) {
        out(`  "${ruleWords(r)}" is not kept: only the witness counts calls.`);
        continue;
      }
      const { state, ...plain } = r;
      const on = (plain.tools ?? []).find((d: string) => doc.tools[d]?.mode === "enforce");
      if (state === "calibrating" && on) {
        out(`  "${ruleWords(r)}" is not kept: on this machine a tool's rules are all On or all Calibrating, and ${on} is On.`);
        continue;
      }
      if (!ids.has(plain.id)) local.rules.push(plain);
    }
    doc.rules = local;
  }
  writeChecksFile(cp, doc);
  changed.push([rel(cp), "written by signafaide protect and pull; commit it"]);
  for (const n of noteChanges) if (n.result === "created" || n.result === "updated") changed.push([n.file, noteWhat(n)]);
  // The key's line only when it is so: the key is in .env, and .gitignore keeps .env out of git.
  if (rec.apiKey && keyInEnvFile(root)) {
    if (envIgnored(root)) changed.push([".env", "SIGNAFAIDE_API_KEY, already in .gitignore"]);
    else {
      changed.push([".env", "SIGNAFAIDE_API_KEY; .env is NOT in .gitignore: add it before you commit"]);
      notDone.push(".env is not in .gitignore (add a line .env)");
    }
  }
  const pkgFile = path.join(root, "package.json");
  if (fs.existsSync(pkgFile) && written.size) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgFile, "utf8"));
      if (!pkg.dependencies?.signafaide && !pkg.devDependencies?.signafaide) {
        pkg.dependencies = { ...(pkg.dependencies ?? {}), signafaide: `^${VERSION}` };
        fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2) + "\n");
        changed.push(["package.json", "signafaide added; run npm install"]);
      }
    } catch {
      /* not JSON: left alone */
    }
  }
  const cw = Math.max(26, ...changed.map(([f]) => f.length + 2));
  changed.forEach(([f, what], i) => out(`${i === 0 ? "Changed    " : "           "}${f.padEnd(cw)} ${what}`));
  // The rules.
  let published: Json | null = null;
  let code = 0;
  if (!o.local && newRules.length && !rec.apiKey) {
    // No key and no sandbox: nothing can save the rules yet, and a sign-in would not help.
    const calibrating = newRules.every((r) => r.state === "calibrating");
    out(`Rules      not saved yet: there is no key.${calibrating ? ` ${newRules.length === 1 ? "It starts" : "They start"} Calibrating once saved.` : ""}`);
    if (keepProposal) {
      const one = newRules.length === 1;
      out(`           Kept in ${rel(cp)} as ${one ? "a local Calibrating rule (it blocks nothing)" : "local Calibrating rules (they block nothing)"}; a person who runs npx signafaide protect in a terminal is offered ${one ? "it" : "them"}.`);
    }
    out("           A person runs npx signafaide protect in a terminal and answers yes to the free sandbox; it asks for the rules again.");
    notDone.push("the rules are not saved (no key yet)");
    finish ??= "npx signafaide protect (in a terminal)";
    code = 1;
  } else if (!o.local && newRules.length) {
    const pub = await publisher(rec);
    // Without a person, on a project an API key cannot save rules in: the rules stay in the checks
    // file, Calibrating, and one console link per rule lets a person add it.
    const where = typeof pub === "string" && !prompt.person ? await addInConsole(rec, newRules) : null;
    if (where && typeof where === "object") {
      published = where.published;
      out(`Rules      saved in your sandbox as version ${published!.rules.version}, signed by signafAIde`);
    } else if (typeof pub === "string") {
      code = 1;
      if (!prompt.person) {
        keepProposed(doc, newRules);
        writeChecksFile(cp, doc);
      }
      if (typeof where === "string") {
        out(`Rules      kept in ${rel(cp)} as Calibrating (they block nothing). An API key`);
        out("           cannot save rules in a project of an organisation: a person adds each one in the");
        out("           console, then runs npx signafaide pull at a terminal to approve sending the fields it needs.");
        for (const r of newRules) {
          const link = addLink(where, agent, r);
          out(link ? `           Add ${r.tools?.[0]}'s rule: ${link}` : `           Add ${r.tools?.[0]}'s rule in the console: ${where}/${encodeURIComponent(agent)}/${encodeURIComponent(r.tools?.[0] ?? "")} (the rule is too long for a link)`);
        }
        notDone.push("the rules are not saved for the project: a person adds each one in the console (the links above)");
        finish = "a person opens each link above and adds the rule (Add as Calibrating); or npx signafaide login, then npx signafaide protect";
      } else {
        out(`Rules      not saved: ${pub}.`);
        out("           Saving rules needs a person's sign-in: npx signafaide login, then npx signafaide protect again (or add them in the console).");
        if (!prompt.person) out(`           Kept in ${rel(cp)} as Calibrating (they block nothing); a person who runs npx signafaide protect in a terminal is offered them.`);
        notDone.push("the rules are not saved for the project");
        finish = "npx signafaide login, then npx signafaide protect";
      }
    } else {
      try {
        published = await publishRules(rec, pub, newRules);
        out(`Rules      saved ${pub.how === "sandbox_key" ? "in your sandbox" : `by ${pub.who}`} as version ${published.rules.version}, signed by signafAIde`);
        if (!prompt.person) {
          const one = newRules.length === 1;
          out(`           ${one ? "The rule" : `All ${newRules.length} rules`} start Calibrating: ${one ? "it notes" : "they note"} the calls ${one ? "it" : "they"} would have blocked and block none until a person turns them On:`);
          for (const r of newRules) out(`             Calibrating  ${ruleWords(r)}`);
        }
        if (pub.how === "sandbox_key") {
          out("           This machine may save rules only while the sandbox is unclaimed. After you keep it,");
          out("           saving rules needs a person's sign-in (npx signafaide login); the API key cannot.");
        }
      } catch (e) {
        if ((e as SignafaideError).code === "confirm_in_console") {
          const page = String((e as SignafaideError).body.confirm_in_console ?? "");
          confirmLines(page).forEach((l, i) => out(i === 0 ? `Rules      ${l}` : l));
          notDone.push("the rules wait for a person to confirm them in the console");
          finish ??= "confirm in the console, then npx signafaide pull";
        } else {
          out(`Rules      not saved: ${(e as Error).message}`);
          notDone.push("the rules are not saved");
          finish ??= "npx signafaide protect";
        }
        code = 1;
      }
    }
  } else if (o.local && newRules.length) out(`Rules      kept on this machine in ${rel(cp)}; signafAIde does not rule on them.`);
  if (!prompt.person && chosen.length && !o.local && !newRules.length) notDone.push(`no rule was chosen for ${chosen.map((t) => t.name).join(", ")} (a person at a terminal chooses; or add rules in the console)`);
  out("");
  const ex = chosen.length ? exampleCall(chosen[0], newRules) : null;
  if (!notDone.length) {
    out(`Done.${ex ? " Check a call without running it:" : ""}`);
    if (ex) out(`           npx signafaide check ${ex}`);
  } else {
    const done = [`checks file ${rel(cp)}`, ...[...written].map((f) => `code in ${rel(f)}`), ...noteChanges.filter((n) => /^(created|updated)$/.test(n.result)).map((n) => `the note in ${n.file}`), ...(published ? [`rules version ${published.rules.version}`] : [])];
    out(`Not finished. Done: ${done.join(", ")}.`);
    out("Not done:");
    for (const n of notDone) out(`  - ${n}`);
    out(`To finish: ${finish ?? (handLines.length ? "add the lines above, then npx signafaide protect again" : "npx signafaide protect (in a terminal)")}`);
    if (ex) out(`Then check a call without running it: npx signafaide check ${ex}`);
  }
  return { code, protected: chosen.map((t) => t.name), rules: newRules, published };
}

/** `approve_payout amount=1200 currency=GBP`: a call the first new rule with a condition would
 * stop, and that the tool's other rules would let through. */
function exampleCall(t: FoundTool, rules: Json[]): string | null {
  const decl = declaredName(t.name);
  const mine = rules.filter((x) => x.tools?.includes(decl) && x.when.length);
  if (!mine.length) return null;
  const parts = new Map<string, string>();
  mine.forEach((r, i) => {
    for (const c of r.when) {
      const f = fieldWords(c.field);
      if (parts.has(f)) continue;
      const stop = i === 0;
      if (c.op === "gt") parts.set(f, String(stop ? Math.round(Number(c.value) * 1.2) : c.value));
      else if (c.op === "not_in" || c.op === "in") parts.set(f, stop === (c.op === "not_in") ? "XXX" : String(c.value[0]));
      else if (c.op === "ne") parts.set(f, stop ? "XXX" : String(c.value));
      else parts.set(f, canonicalize(c.value));
    }
  });
  return `${t.name} ${[...parts].map(([f, v]) => `${f}=${v}`).join(" ")}`;
}

/** The fields a tool's rules can use, and the rules that use each (for `signafaide pull`). */
export function fieldUses(rs: Json, agent: string, tool: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const r of rs.rules) {
    if (!C.applies(r, agent, tool)) continue;
    const fields = new Set<string>([...r.when.map((c: Json) => c.field), ...(r.exceptions ?? []).map((x: Json) => x.field)]);
    for (const f of fields) out.set(f, [...(out.get(f) ?? []), ruleWords(r)]);
  }
  return out;
}
