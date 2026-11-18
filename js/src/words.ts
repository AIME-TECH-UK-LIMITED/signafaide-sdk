/**
 * Rules in words (SPEC §10.5, spec 1.1): the one English rendering of every rule, condition,
 * exception and default, so the verifier, `signafaide prove`, `check`, `pull`, `status` and the
 * `blocked` error print a rule the same way the Rust core and the Python SDK do. The words never
 * replace the document: the document and its `rules_hash` are what was signed.
 */

import { JsonNumber, canonicalize } from "./jcs.js";
import { plural } from "./plural.js";
import { ruleState } from "./checks.js";
import { byCodePoint } from "./coverage.js";

type Json = Record<string, any>;

/** A number literal as people read it: its integer part grouped by threes with `,` when it has no
 * exponent (`1000` is `1,000`, `-1234.5` is `-1,234.5`, `1e+21` stays). */
export function numberWords(literal: string): string {
  if (/[eE]/.test(literal)) return literal;
  const neg = literal.startsWith("-");
  const rest = neg ? literal.slice(1) : literal;
  const [int, frac] = rest.split(".", 2) as [string, string | undefined];
  let grouped = "";
  for (let i = 0; i < int.length; i++) {
    if (i > 0 && (int.length - i) % 3 === 0) grouped += ",";
    grouped += int[i];
  }
  return `${neg ? "-" : ""}${grouped}${frac !== undefined ? `.${frac}` : ""}`;
}

/** A JSON value in words: a number as `numberWords`, a string as its JCS literal (in double
 * quotes), `true`, `false`, `null`, an object or array as its JCS text. */
export function valueWords(v: unknown): string {
  const text = canonicalize(v);
  return typeof v === "number" || v instanceof JsonNumber ? numberWords(text) : text;
}

/** A field in words: the pointer without its leading `/`, escapes kept; `/` is `(the empty key)`. */
export function fieldWords(pointer: string): string {
  const f = pointer.startsWith("/") ? pointer.slice(1) : pointer;
  return f === "" ? "(the empty key)" : f;
}

/** Items joined as `a`, `a or b`, `a, b or c`; `(no values)` for none. */
function either(items: string[]): string {
  if (!items.length) return "(no values)";
  if (items.length === 1) return items[0];
  return `${items.slice(0, -1).join(", ")} or ${items[items.length - 1]}`;
}

const TYPE_WORDS: Record<string, string> = {
  string: "a string",
  number: "a number",
  integer: "an integer",
  boolean: "true or false",
  null: "null",
  object: "an object",
  array: "an array",
};

/** A condition in words (§10.5 table). */
export function conditionWords(c: Json): string {
  const f = fieldWords(c.field);
  const v = (): string => valueWords(c.value);
  const list = (): string => either((Array.isArray(c.value) ? c.value : []).map(valueWords));
  switch (c.op) {
    case "eq":
      return `${f} is ${v()}`;
    case "ne":
      return `${f} is not ${v()}`;
    case "lt":
      return `${f} is below ${v()}`;
    case "le":
      return `${f} is at most ${v()}`;
    case "gt":
      return `${f} is above ${v()}`;
    case "ge":
      return `${f} is at least ${v()}`;
    case "in":
      return `${f} is one of ${list()}`;
    case "not_in":
      return `${f} is not one of ${list()}`;
    case "prefix":
      return `${f} starts with ${v()}`;
    case "suffix":
      return `${f} ends with ${v()}`;
    case "contains":
      return `${f} contains ${v()}`;
    case "present":
      return `${f} is present`;
    case "absent":
      return `${f} is absent`;
    default:
      return `${f} is ${TYPE_WORDS[String(c.value)] ?? "an array"}`;
  }
}

/** An exception in words: `<field> is <value>`. */
export function exceptionWords(x: Json): string {
  return `${fieldWords(x.field)} is ${valueWords(x.value)}`;
}

const countWords = (n: number, one: string, many: string): string => `${numberWords(String(n))} ${n === 1 ? one : many}`;
/** A limit's window as the console says it: `1 minute` for 60 seconds, `2 hours`, `90 seconds`. */
export function windowWords(seconds: number): string {
  if (seconds % 3600 === 0) return countWords(seconds / 3600, "hour", "hours");
  if (seconds % 60 === 0) return countWords(seconds / 60, "minute", "minutes");
  return countWords(seconds, "second", "seconds");
}
const PER: Record<string, string> = { agent: "by the same agent", tool: "to the same tool", agent_tool: "by the same agent to the same tool" };

/** A rule in words, without its state: `Block approve_payout when amount is above 1,000`. */
export function ruleWords(r: Json): string {
  const action = r.action === "block" ? "Block" : "Allow";
  const tools = r.tools === null ? "any tool" : either(r.tools);
  const agents = r.agents === null ? "" : r.agents.length === 1 ? ` for agent ${r.agents[0]}` : ` for agents ${either(r.agents)}`;
  const parts: string[] = r.when.map(conditionWords);
  if (r.limit) parts.push(`more than ${countWords(r.limit.calls, "call", "calls")} in ${windowWords(r.limit.seconds)} ${PER[r.limit.per]}`);
  const when = parts.length ? ` when ${parts.join(" and ")}` : "";
  const xs: Json[] = r.exceptions ?? [];
  const except = xs.length ? `, except when ${xs.map(exceptionWords).join(" or ")}` : "";
  return `${action} ${tools}${agents}${when}${except}`;
}

/** The default in words. */
export function defaultWords(action: string): string {
  return `${action === "block" ? "Block" : "Allow"} every call that no rule matches`;
}

/** `On` or `Calibrating`. */
export const stateWord = (s: string | null | undefined): string => (s === "on" ? "On" : "Calibrating");

/** A `mode` value in words: `enforce` is On, `watch` is Calibrating. */
export const modeWord = (m: string | null | undefined): string => (m === "enforce" ? "On" : "Calibrating");

/** A `fail` value in words, for "If signafAIde can't be reached": `closed` is Stop, `open` is Let it run. */
export const failWord = (f: string | null | undefined): string => (f === "open" ? "Let it run" : "Stop");

export interface RuleSetWords {
  set: string;
  version: number | null;
  hash: string;
  issued: string | null;
  rules: { id: string; state: string | null; sentence: string }[];
  default: { id: "default"; state: string | null; sentence: string };
  exceptions: { rule: string; since: number; sentence: string; reason: string }[];
  /** SDK 0.5.2: the tools the version protects from the console, in code point order; only for
   * a version that has `protect`. */
  protect?: { tool: string; fail: "open" | "closed" }[];
}

/** A valid rule set version, or local rules (`local`), in words (§7 JSON output `rules`). */
export function ruleSetWords(doc: Json, hash: string, local: boolean): RuleSetWords {
  const st = (s: string): string | null => (local ? null : s);
  const out: RuleSetWords = {
    set: local ? "local" : doc.set,
    version: local ? null : doc.version,
    hash,
    issued: local ? null : doc.issued,
    rules: doc.rules.map((r: Json) => ({ id: r.id, state: st(ruleState(local ? { mode: "enforce" } : doc, r)), sentence: ruleWords(r) })),
    default: { id: "default", state: st(doc.mode === "watch" ? "calibrating" : "on"), sentence: defaultWords(doc.default) },
    exceptions: local ? [] : doc.rules.flatMap((r: Json) => (r.exceptions ?? []).map((x: Json) => ({ rule: r.id, since: x.since, sentence: exceptionWords(x), reason: x.reason }))),
  };
  if (!local && doc.protect && typeof doc.protect === "object") {
    out.protect = Object.keys(doc.protect)
      .sort(byCodePoint)
      .map((tool) => ({ tool, fail: doc.protect[tool].fail === "open" ? "open" : "closed" }));
  }
  return out;
}

/** The report lines of one rule set version or local rules (§7), without the `rules: ` prefix. */
export function ruleSetLines(w: RuleSetWords): string[] {
  const label = w.version !== null ? `${w.set} version ${w.version}` : `local ${w.hash.slice(0, 8)}`;
  const word = (s: string | null): string => (s === null ? "" : ` (${stateWord(s)})`);
  const out: string[] = [];
  const n = plural(w.rules.length, "rule");
  out.push(w.issued !== null ? `${label}, issued ${w.issued}: ${n}` : `${label}: ${n}`);
  for (const r of w.rules) out.push(`${label}: rule ${r.id}: ${r.sentence}${word(r.state)}`);
  out.push(`${label}: ${w.default.sentence}${word(w.default.state)}`);
  for (const x of w.exceptions) out.push(`${label}: exception to rule ${x.rule} since version ${x.since}: ${x.sentence}, reason ${canonicalize(x.reason)}`);
  for (const p of w.protect ?? []) out.push(`${label}: protected from the console: ${p.tool}, if signafAIde can't be reached: ${failWord(p.fail)}`);
  return out;
}
