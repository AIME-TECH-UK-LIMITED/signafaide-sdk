/**
 * Tool-call checks (SPEC §2.8, §3.5, §8, §10, §11): the rule language, the checks a record
 * carries, the client's own checks, signed rule sets, the shared fingerprint list, tool
 * fingerprints, and the verifier's tool-call checks report. Pure functions, no I/O (the
 * optional name lookup of the `address` check is a function the caller passes).
 *
 * Rulings are `allow` or `block`, nothing between; watch mode records what enforce mode would
 * have done. The same names, rules and wording as the Rust core and the Python SDK.
 */

import { HEX64, SALT_RE, hashJson, sha256Hex, verifySig } from "./crypto.js";
import { byCodePoint } from "./coverage.js";
import { JsonNumber, canonicalBytes, canonicalize } from "./jcs.js";
import {
  BEARER_RE, DECODE_BUDGET, JWT_RE, OBFUSCATION_MAX, PAIRS_SCAN_MAX, SEPARATORS, decodings, dumpValue, hasCardNumber, hasEncodedContent, hasInstruction, hasInvisible,
  hasSeedPhrase, hasShadowing, holdsPrefix, lookAlikeName, hostLookalike, mayHoldReversed, isEnvDump, isHexKey, isJwt, isWalletAddress, isWif, lookalikeTokens, looksRandom, memberJoins, normalise, pairs, secretName,
} from "./scan.js";

// --- constants (§9) -----------------------------------------------------------------------

export const DISCLOSED_MAX_BYTES = 16_384;
export const RULING_TIMEOUT_MS = 10_000;
export const RULES_REFRESH_MS = 60_000;
/** How long a call waits for the first rule set fetch of a process when no version is held (§8, §9, SDK 0.5.2). */
export const RULES_START_WAIT_MS = 300;
export const FINGERPRINTS_REFRESH_MS = 60_000;
export const RULES_FORMAT = "signafaide-rules/1";
export const LIST_FORMAT = "signafaide-fingerprints/1";
export const CHECKS_FORMAT = "signafaide-checks/1";
/** Spec 1.1: the checks file with `protect` and a mode per tool (§8). */
export const CHECKS_FORMAT_2 = "signafaide-checks/2";
const MAX_RULE_SET_BYTES = 1 << 20;

/** The check ids, in the order of the §2.8 table. */
export const CHECK_IDS = ["secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction"] as const;
export const DECISION_CHECKS = ["secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction"];
/** The checks of an outcome (§2.8): on the tool's result. */
export const OUTCOME_CHECKS = ["secret", "hidden_instruction"];
/** The checks a checks file turns on or off (`rule` is on whenever rules are held). */
export const FILE_CHECKS = ["secret", "address", "changed_tool", "fingerprint", "hidden_instruction"] as const;
export type Result = "allow" | "note" | "block";
const RESULT_ORDER: Record<string, number> = { allow: 0, note: 1, block: 2 };
/** The secret format table of §8: id, whole-token pattern, issuing hosts. */
export const SECRET_FORMATS: readonly [string, string, readonly string[]][] = [
  ["github_token", "gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{82,244}", ["github.com", "api.github.com", "uploads.github.com"]],
  ["aws_access_key", "(AKIA|ASIA)[A-Z0-9]{16}", ["*.amazonaws.com"]],
  ["stripe_key", "(sk|rk)_(live|test)_[A-Za-z0-9]{24,99}", ["api.stripe.com"]],
  ["slack_token", "xox[abposr]-[A-Za-z0-9-]{10,200}", ["slack.com", "*.slack.com"]],
  ["anthropic_key", "sk-ant-[A-Za-z0-9_-]{20,200}", ["api.anthropic.com"]],
  ["openai_key", "sk-proj-[A-Za-z0-9_-]{20,200}", ["api.openai.com"]],
  ["google_api_key", "AIza[0-9A-Za-z_-]{35}", ["*.googleapis.com"]],
  ["signafaide_key", "sfa_(test|live|user)_[0-9A-Za-z]{32}", []], // issuer: the host of the client's witness URL; sfa_user_ is a person session (§6)
];
const SECRET_RES: [string, RegExp, readonly string[]][] = SECRET_FORMATS.map(([id, p, iss]) => [id, new RegExp(`^(?:${p})$`), iss]);
const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/;
/** Secret formats read by a text rule, not a whole-token pattern (§8): they block like the table's. */
export const TEXT_FORMATS = ["private_key", "wallet_private_key", "seed_phrase"] as const;
/** Secrets known by where they stand, not by a format (§8, spec 1.1 benchmark batch 2): a value
 * named as a secret that looks random, a JSON Web Token, a bearer credential. Read on arguments
 * only; they block like the table's formats. */
export const CONTEXT_FORMATS = ["bearer_token", "jwt", "named_secret"] as const;
/** What the `secret` check notes without blocking (§2.8): public or uncertain finds. */
export const SECRET_NOTES = ["card_number", "high_entropy", "wallet_address"] as const;
const FOUND: Record<string, Set<string>> = {
  secret: new Set([...SECRET_FORMATS.map((f) => f[0]), ...TEXT_FORMATS, ...CONTEXT_FORMATS, ...SECRET_NOTES]),
  address: new Set(["loopback", "private", "shared", "link_local", "unique_local", "unspecified", "metadata", "internal_name"]),
  changed_tool: new Set(["description_changed", "schema_changed", "not_approved"]),
  fingerprint: new Set(["tool", "description", "server"]),
  hidden_instruction: new Set(["invisible_characters", "instruction_phrase", "encoded_content", "tool_shadowing", "look_alike_name", "possible_hidden_instruction"]),
};
const OPS_VALUE = new Set(["eq", "ne", "lt", "le", "gt", "ge", "in", "not_in", "prefix", "suffix", "contains", "type"]);
const OPS_NO_VALUE = new Set(["present", "absent"]);
const TYPES = ["string", "number", "integer", "boolean", "null", "object", "array"];
const RULE_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SET_RE = /^rs_[0-9A-HJKMNP-TV-Z]{26}$/;
const AGENT_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const PROJECT_RE = /^prj_[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const HOST_PATTERN = /^(\*\.)?[a-z0-9._-]{1,253}$/;

type Json = Record<string, any>;

/** A field a pointer does not reach (§10.3). */
export const ABSENT: unique symbol = Symbol("ABSENT");
export type Field = unknown;

const isObj = (x: unknown): x is Json => !!x && typeof x === "object" && !Array.isArray(x) && !(x instanceof JsonNumber);
const cpLen = (s: string): number => [...s].length;

/** The numeric value of a JSON number (a plain number, or a literal from `parseJson`), else null. */
function num(x: unknown): number | null {
  if (typeof x === "number") return x;
  if (x instanceof JsonNumber) return x.value;
  return null;
}
export const isNum = (x: unknown): boolean => num(x) !== null;
/** An integer within ±(2^53−1), written as one (a literal `1.0` from `parseJson` is not). */
export const isSafeInt = (x: unknown): x is number => typeof x === "number" && Number.isSafeInteger(x);
const isHex64 = (x: unknown): x is string => typeof x === "string" && HEX64.test(x);

function jcsEq(a: unknown, b: unknown): boolean {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
}

function validTime(t: unknown): t is string {
  return typeof t === "string" && TIME_RE.test(t) && !t.startsWith("0000") && !Number.isNaN(Date.parse(t)) && new Date(t).toISOString() === t;
}

/** `a` and `b` (times) compared: negative, 0 or positive. Throws on a time that cannot be read. */
function cmpTime(a: unknown, b: unknown): number {
  const x = typeof a === "string" ? Date.parse(a) : NaN;
  const y = typeof b === "string" ? Date.parse(b) : NaN;
  if (Number.isNaN(x) || Number.isNaN(y)) throw new Error("not a time");
  return Math.sign(x - y);
}

function exact(o: Json, keys: string[], optional: string[], what: string): string | null {
  const extra = Object.keys(o)
    .filter((k) => !keys.includes(k) && !optional.includes(k))
    .sort(byCodePoint);
  if (extra.length) return `${what} has the unknown field '${extra[0]}'`;
  const missing = keys.filter((k) => !(k in o));
  if (missing.length) return `${what} lacks the field '${missing[0]}'`;
  return null;
}

/** Whether `xs` is in strictly increasing code point order (sorted, no repeats). */
function sortedUnique(xs: string[]): boolean {
  for (let i = 1; i < xs.length; i++) if (byCodePoint(xs[i - 1], xs[i]) >= 0) return false;
  return true;
}

const sameSet = (o: unknown, keys: string[]): o is Json => isObj(o) && Object.keys(o).length === keys.length && keys.every((k) => k in o);

// --- JSON Pointer and conditions (§10.1, §10.3) -------------------------------------------

/** A JSON Pointer as §10.1 allows it: starts with `/`, at most 256 characters, `~` only as `~0` or `~1`. */
export function pointerOk(p: unknown): p is string {
  return typeof p === "string" && p.startsWith("/") && cpLen(p) <= 256 && !/~(?![01])/.test(p);
}

/** The value at `ptr` in `doc` (RFC 6901), or `ABSENT`. */
export function resolve(doc: unknown, ptr: string): Field {
  let cur: unknown = doc;
  for (const raw of ptr.slice(1).split("/")) {
    const tok = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (isObj(cur)) {
      if (!Object.prototype.hasOwnProperty.call(cur, tok)) return ABSENT;
      cur = cur[tok];
    } else if (Array.isArray(cur)) {
      if (!/^(0|[1-9][0-9]*)$/.test(tok) || Number(tok) >= cur.length) return ABSENT;
      cur = cur[Number(tok)];
    } else return ABSENT;
  }
  return cur;
}

function typeOf(v: unknown, name: string): boolean {
  switch (name) {
    case "string":
      return typeof v === "string";
    case "number":
      return isNum(v);
    case "integer": {
      const x = num(v);
      return x !== null && Number.isFinite(x) && Number.isInteger(x);
    }
    case "boolean":
      return typeof v === "boolean";
    case "null":
      return v === null;
    case "object":
      return isObj(v);
    default:
      return Array.isArray(v);
  }
}

/** `true`, `false` or `"error"` for one condition against the field it names (`ABSENT` when absent). */
export function condition(cond: Json, value: Field): boolean | "error" {
  const op = cond.op;
  if (value === ABSENT) return op === "absent";
  if (op === "present") return true;
  if (op === "absent") return false;
  const want = cond.value;
  if (op === "eq") return jcsEq(value, want);
  if (op === "ne") return !jcsEq(value, want);
  if (op === "lt" || op === "le" || op === "gt" || op === "ge") {
    const a = num(value);
    const b = num(want) as number;
    if (a === null) return "error";
    return op === "lt" ? a < b : op === "le" ? a <= b : op === "gt" ? a > b : a >= b;
  }
  if (op === "in" || op === "not_in") {
    const hit = (want as unknown[]).some((w) => jcsEq(value, w));
    return op === "in" ? hit : !hit;
  }
  if (op === "prefix" || op === "suffix" || op === "contains") {
    if (typeof value !== "string") return "error";
    return op === "prefix" ? value.startsWith(want) : op === "suffix" ? value.endsWith(want) : value.includes(want);
  }
  return typeOf(value, want);
}

// --- rule set documents (§10.1) -----------------------------------------------------------

const declaredNameOk = (s: unknown): boolean => typeof s === "string" && cpLen(s) >= 1 && cpLen(s) <= 101;
const hostPatternOk = (s: unknown): boolean => typeof s === "string" && HOST_PATTERN.test(s) && (s.startsWith("*.") ? s.slice(2) : s).length >= 1;

export function conditionErrors(c: unknown): string | null {
  if (!isObj(c) || typeof c.op !== "string") return "a condition is {field, op, value}";
  const op = c.op;
  if (!OPS_VALUE.has(op) && !OPS_NO_VALUE.has(op)) return `unknown operator '${op}'`;
  const err = exact(c, OPS_NO_VALUE.has(op) ? ["field", "op"] : ["field", "op", "value"], [], "a condition");
  if (err) return err;
  if (!pointerOk(c.field)) return "field must be a JSON Pointer of at most 256 characters, ~ only as ~0 or ~1";
  const v = c.value;
  let ok = true;
  if (["lt", "le", "gt", "ge"].includes(op)) ok = isNum(v);
  else if (op === "in" || op === "not_in") ok = Array.isArray(v) && v.length <= 256;
  else if (op === "prefix" || op === "suffix" || op === "contains") ok = typeof v === "string";
  else if (op === "type") ok = typeof v === "string" && TYPES.includes(v);
  return ok ? null : `the value of '${op}' has the wrong type`;
}

/** The first problem with a rule (§10.1). `version` is the rule set document's version; null for
 * the local rules of a checks file, which may use neither `limit` (`allowLimit` false) nor, from
 * spec 1.1, `state` and `exceptions` (the checks file sets their mode per tool). */
export function ruleErrors(r: unknown, allowLimit = true, version: number | null = null): string | null {
  if (!isObj(r)) return "each rule is an object";
  const optional = [...(allowLimit ? ["limit"] : []), ...(version !== null ? ["state", "exceptions"] : [])];
  const err = exact(r, ["id", "about", "action", "tools", "agents", "when"], optional, "a rule");
  if (err) return err;
  if (typeof r.id !== "string" || !RULE_ID_RE.test(r.id)) return "a rule id matches ^[a-z0-9][a-z0-9._-]{0,63}$";
  const rid = r.id;
  if (typeof r.about !== "string" || cpLen(r.about) > 200) return `rule '${rid}': about is text of at most 200 characters`;
  if (r.action !== "allow" && r.action !== "block") return `rule '${rid}': action must be allow or block`;
  const lists: [string, (x: unknown) => boolean][] = [
    ["tools", declaredNameOk],
    ["agents", (a) => typeof a === "string" && AGENT_RE.test(a)],
  ];
  for (const [k, ok] of lists) {
    const v = r[k];
    if (v !== null && !(Array.isArray(v) && v.length >= 1 && v.length <= 256 && v.every(ok))) return `rule '${rid}': ${k} is null or a list of 1 to 256 names`;
  }
  if (!Array.isArray(r.when) || r.when.length > 16) return `rule '${rid}': when is a list of at most 16 conditions`;
  for (const c of r.when) {
    const e = conditionErrors(c);
    if (e) return `rule '${rid}': ${e}`;
  }
  if ("limit" in r) {
    const lim = r.limit;
    if (r.action !== "block") return `rule '${rid}': limit is allowed only on a block rule`;
    if (!sameSet(lim, ["calls", "seconds", "per"])) return `rule '${rid}': limit is {calls, seconds, per}`;
    if (!isSafeInt(lim.calls) || lim.calls < 1 || lim.calls > 1_000_000) return `rule '${rid}': limit.calls is 1 to 1,000,000`;
    if (!isSafeInt(lim.seconds) || lim.seconds < 1 || lim.seconds > 86_400) return `rule '${rid}': limit.seconds is 1 to 86,400`;
    if (!["agent", "tool", "agent_tool"].includes(lim.per)) return `rule '${rid}': limit.per is agent, tool or agent_tool`;
  }
  if ("state" in r && r.state !== "calibrating" && r.state !== "on") return `rule '${rid}': state must be calibrating or on`;
  if ("exceptions" in r) {
    if (r.action !== "block") return `rule '${rid}': exceptions are allowed only on a block rule`;
    const xs = r.exceptions;
    if (!Array.isArray(xs) || xs.length < 1 || xs.length > 256) return `rule '${rid}': exceptions is a list of 1 to 256 exceptions`;
    const seen = new Set<string>();
    for (const x of xs) {
      if (!isObj(x)) return `rule '${rid}': an exception is {field, value, reason, since}`;
      const e = exact(x, ["field", "value", "reason", "since"], [], `rule '${rid}': an exception`);
      if (e) return e;
      if (!pointerOk(x.field)) return `rule '${rid}': an exception's field must be a JSON Pointer of at most 256 characters, ~ only as ~0 or ~1`;
      if (typeof x.reason !== "string" || cpLen(x.reason) < 1 || cpLen(x.reason) > 200) return `rule '${rid}': an exception's reason is text of 1 to 200 characters`;
      if (!isSafeInt(x.since) || x.since < 1 || x.since > (version ?? 0)) return `rule '${rid}': an exception's since is the version that added it, 1 to this version`;
      let text: string;
      try {
        text = canonicalize(x.value);
      } catch (err) {
        return `rule '${rid}': an exception's value is not canonical JSON: ${(err as Error).message}`;
      }
      const k = `${x.field}\u0000${text}`;
      if (seen.has(k)) return `rule '${rid}': the exception ${x.field} ${text} is listed twice`;
      seen.add(k);
    }
  }
  return null;
}

function rulesListErrors(rules: unknown, allowLimit = true, version: number | null = null): string | null {
  if (!Array.isArray(rules) || rules.length > 1000) return "rules must be a list of at most 1,000 rules";
  const seen = new Set<string>();
  for (const r of rules) {
    const err = ruleErrors(r, allowLimit, version);
    if (err) return err;
    if (seen.has(r.id)) return `the rule id '${r.id}' is used twice`;
    seen.add(r.id);
  }
  return null;
}

/** The first problem with a rule set document (§10.1), or null when it is valid. */
export function ruleSetErrors(doc: unknown): string | null {
  if (!isObj(doc)) return "a rule set is a JSON object";
  const err = exact(doc, ["format", "project", "env", "set", "version", "prev", "issued", "mode", "default", "fail", "addresses", "approved", "rules"], ["fingerprint_exceptions", "protect"], "the rule set");
  if (err) return err;
  try {
    if (canonicalBytes(doc).length > MAX_RULE_SET_BYTES) return "the rule set's JCS form is more than 1 MiB";
  } catch (e) {
    return `the rule set is not canonical JSON: ${(e as Error).message}`;
  }
  if (doc.format !== RULES_FORMAT) return `format must be ${RULES_FORMAT}`;
  if (typeof doc.project !== "string" || !PROJECT_RE.test(doc.project)) return "project must be a project id";
  if (doc.env !== "test" && doc.env !== "live") return "env must be test or live";
  if (typeof doc.set !== "string" || !SET_RE.test(doc.set)) return "set must be rs_ followed by 26 Crockford base32 characters";
  if (!isSafeInt(doc.version) || doc.version < 1) return "version must be an integer of at least 1";
  if (!((doc.version === 1 && doc.prev === null) || (doc.version > 1 && isHex64(doc.prev)))) return "prev is the rules_hash of version - 1, and null exactly when version is 1";
  if (!validTime(doc.issued)) return "issued must be a time such as 2026-11-17T09:00:00.000Z";
  if (doc.mode !== "watch" && doc.mode !== "enforce") return "`mode` must be \"watch\" (Calibrating) or \"enforce\" (On)";
  if (doc.default !== "allow" && doc.default !== "block") return "default must be allow or block";
  const f = doc.fail;
  if (!isObj(f) || Object.keys(f).length > 1000 || !Object.entries(f).every(([k, v]) => declaredNameOk(k) && (v === "open" || v === "closed"))) return "fail maps declared tool names to open or closed";
  if ("protect" in doc) {
    const p = doc.protect;
    if (!isObj(p) || Object.keys(p).length < 1 || Object.keys(p).length > 1000) return "protect must be an object of 1 to 1,000 tools (left out when no tool is protected from the console)";
    for (const [name, e] of Object.entries(p)) {
      if (!isObj(e)) return "protect maps declared tool names to {fail}";
      const ee = exact(e, ["fail"], [], `protect.${name}`);
      if (ee) return ee;
      if (!declaredNameOk(name) || (e.fail !== "open" && e.fail !== "closed")) return 'protect maps declared tool names to {"fail": "closed" | "open"}';
      if (Object.prototype.hasOwnProperty.call(f, name) && f[name] !== e.fail) return `${name} is in fail as ${f[name]} and in protect as ${e.fail}: a tool named in both has the same fail mode`;
    }
  }
  const a = doc.addresses;
  if (!sameSet(a, ["hosts", "cidrs"])) return "addresses must be {hosts, cidrs}";
  if (!Array.isArray(a.hosts) || a.hosts.length > 1000 || !a.hosts.every(hostPatternOk)) return "addresses.hosts holds lowercase names, or *. and a suffix";
  if (!Array.isArray(a.cidrs) || a.cidrs.length > 1000 || !a.cidrs.every(cidrOk)) return "addresses.cidrs holds IPv4 or IPv6 networks in CIDR form";
  const ap = doc.approved;
  if (ap !== null) {
    if (!isObj(ap) || Object.keys(ap).length > 10_000) return "approved must be null or an object of at most 10,000 tools";
    for (const [name, e] of Object.entries(ap)) {
      if (!declaredNameOk(name) || !sameSet(e, ["description", "schema"]) || !(isHex64(e.description) && isHex64(e.schema))) return "approved maps declared tool names to {description, schema} fingerprints";
    }
  }
  if ("fingerprint_exceptions" in doc) {
    const xs = doc.fingerprint_exceptions;
    if (!Array.isArray(xs) || xs.length > 1000) return "fingerprint_exceptions must be a list of at most 1,000 entries";
    const seen = new Set<string>();
    for (const x of xs) {
      if (!sameSet(x, ["kind", "fingerprint", "reason"])) return "a fingerprint exception is {kind, fingerprint, reason}";
      if (!["tool", "description", "server"].includes(x.kind) || !isHex64(x.fingerprint)) return "a fingerprint exception names a kind (tool, description or server) and a 64 lowercase hex fingerprint";
      if (typeof x.reason !== "string" || ![...x.reason].length || [...x.reason].length > 200) return "a fingerprint exception's reason is text of 1 to 200 characters";
      const k = entryKey(x);
      if (seen.has(k)) return `the fingerprint exception ${x.kind} ${x.fingerprint} is listed twice`;
      seen.add(k);
    }
  }
  const e = rulesListErrors(doc.rules, true, doc.version);
  if (e) return e;
  if (doc.mode === "watch") {
    const on = doc.rules.find((r: Json) => r.state === "on");
    if (on) return `rule '${on.id}': a rule set whose \`mode\` is "watch" (Calibrating) never blocks, so no rule in it is On`;
  }
  return null;
}

/** The `kind` and fingerprint pairs a rule set excepts from the shared list (§10.1
 * `fingerprint_exceptions`), for `fingerprintFindingsIn`; empty without a rule set. */
export function exceptedSet(doc: Json | null | undefined): Set<string> {
  return new Set(Array.isArray(doc?.fingerprint_exceptions) ? doc.fingerprint_exceptions.map(entryKey) : []);
}

/** The checks file's `rules` (§8): null, or `{default, rules}` with no `limit`. */
export function localRulesErrors(rules: unknown): string | null {
  if (rules === null) return null;
  if (!isObj(rules)) return "rules must be null or {default, rules}";
  const err = exact(rules, ["default", "rules"], [], "rules");
  if (err) return err;
  if (rules.default !== "allow" && rules.default !== "block") return "rules.default must be allow or block";
  const e = rulesListErrors(rules.rules, false, null);
  if (e && e.includes("unknown field 'limit'")) return "rules may not use limit: only the witness counts calls";
  return e;
}

export function applies(rule: Json, agent: string, tool: string): boolean {
  return (rule.tools === null || rule.tools.includes(tool)) && (rule.agents === null || rule.agents.includes(agent));
}

/** A rule's state (§10.1, spec 1.1): as written, else from the document's mode (`calibrating` in
 * watch mode, `on` in enforce mode). Local rules (no `mode`) are always `on`: the checks file sets
 * the mode their entry is written in. */
export function ruleState(doc: Json, rule: Json): "calibrating" | "on" {
  if (rule.state === "calibrating" || rule.state === "on") return rule.state;
  return doc.mode === "watch" ? "calibrating" : "on";
}

/** Whether a rule takes part in the result (§10.3): every rule of a rule set in watch mode, and
 * the On rules of one in enforce mode. */
export function takesPart(doc: Json, rule: Json): boolean {
  return doc.mode === "watch" || ruleState(doc, rule) === "on";
}

/** §10.4: the fields a call **needs**: the `field` of every condition of every rule that applies
 * and takes part in the result, each once, in code point order. A Calibrating rule's fields and
 * the fields of exceptions are never needed. */
export function neededFields(doc: Json | null | undefined, agent: string, tool: string): string[] {
  if (!doc) return [];
  const out = new Set<string>();
  for (const r of doc.rules) if (applies(r, agent, tool) && takesPart(doc, r)) for (const c of r.when) out.add(c.field);
  return [...out].sort(byCodePoint);
}

/** §10.4 (spec 1.1): the fields a call **can send**: the `field` of every condition of every rule
 * that applies, whatever its state, and of each of their exceptions, each once, in code point order. */
export function sendableFields(doc: Json | null | undefined, agent: string, tool: string): string[] {
  if (!doc) return [];
  const out = new Set<string>();
  for (const r of doc.rules) {
    if (!applies(r, agent, tool)) continue;
    for (const c of r.when) out.add(c.field);
    for (const x of r.exceptions ?? []) out.add(x.field);
  }
  return [...out].sort(byCodePoint);
}

/** §10.4: what a strict call sends of the fields the developer approved (`disclose`): `sent`, the
 * sendable fields it lists; `missing`, the needed fields it does not list (a ruling then blocks
 * with basis `fields_missing`); `unsent`, the fields only Calibrating rules or exceptions use
 * that it does not list (nothing blocks for them). */
export function disclosure(doc: Json | null | undefined, agent: string, tool: string, disclose: readonly string[]): { sent: string[]; missing: string[]; unsent: string[] } {
  const needed = neededFields(doc, agent, tool);
  const sendable = sendableFields(doc, agent, tool);
  return {
    sent: sendable.filter((p) => disclose.includes(p)),
    missing: needed.filter((p) => !disclose.includes(p)),
    unsent: sendable.filter((p) => !disclose.includes(p) && !needed.includes(p)),
  };
}

export interface Evaluation {
  result: "allow" | "block";
  basis: "error" | "rule" | "default";
  matched: string[];
  /** Spec 1.1: the Calibrating rules (in enforce mode) that would have blocked the call. */
  would_block: string[];
  /** Spec 1.1: the Calibrating rules (in enforce mode) a field of which was not available. */
  not_calibrated: string[];
  /** Spec 1.1: the rules taking part whose conditions all held but that an exception kept from matching. */
  excepted: string[];
}

/** §10.3: the enforce-mode result. `doc` has `rules` and `default` (and `mode` for a rule set).
 * `count` is the witness's count of its earlier allow rulings for a limit rule; without it (a
 * client) limit rules are skipped. `available` says whether a pointer can be read at all: a
 * client holds the whole call (every field); the witness only the pointers it was sent. */
export function evaluate(doc: Json, agent: string, tool: string, lookup: (p: string) => Field, count?: (limit: Json) => number, available?: (p: string) => boolean): Evaluation {
  const avail = (p: string): boolean => !available || available(p);
  const errors: string[] = [];
  const blocks: string[] = [];
  const allows: string[] = [];
  const wouldBlock: string[] = [];
  const notCalibrated: string[] = [];
  const excepted: string[] = [];
  for (const r of doc.rules) {
    if (!applies(r, agent, tool)) continue;
    if ("limit" in r && !count) continue;
    const part = takesPart(doc, r);
    if (!part && r.when.some((c: Json) => !avail(c.field))) {
      notCalibrated.push(r.id);
      continue;
    }
    let status: boolean | "error" = true;
    for (const c of r.when) {
      status = condition(c, lookup(c.field));
      if (status !== true) break;
    }
    if (status === "error") {
      (part ? errors : wouldBlock).push(r.id);
      continue;
    }
    if (status !== true) continue;
    // An exception applies only to a field that is available and present (§10.1).
    const isExcepted = (r.exceptions ?? []).some((x: Json) => {
      if (!avail(x.field)) return false;
      const v = lookup(x.field);
      return v !== ABSENT && jcsEq(v, x.value);
    });
    if (isExcepted) {
      if (part) excepted.push(r.id);
      continue;
    }
    if ("limit" in r && count && count(r.limit) < r.limit.calls) continue;
    if (part) (r.action === "block" ? blocks : allows).push(r.id);
    else if (r.action === "block") wouldBlock.push(r.id);
  }
  const extra = { would_block: wouldBlock.slice(0, 16), not_calibrated: notCalibrated.slice(0, 16), excepted: excepted.slice(0, 16) };
  if (errors.length) return { result: "block", basis: "error", matched: errors.slice(0, 16), ...extra };
  if (blocks.length) return { result: "block", basis: "rule", matched: blocks.slice(0, 16), ...extra };
  if (allows.length) return { result: "allow", basis: "rule", matched: allows.slice(0, 16), ...extra };
  return { result: doc.default, basis: "default", matched: [], ...extra };
}

/** A check result as an entry writes it in `mode` (§2.8): watch mode never blocks. */
export function applyMode(result: string, mode: string): { result: string; enforce_result?: string } {
  if (mode === "watch") return { result: result === "block" ? "note" : result, enforce_result: result };
  return { result };
}

/** The mode of a client's `rule` entry (§2.8, §8): the project's rule set is ruled on by the
 * witness, never by the client, so its entry is always in watch mode (a call that is not strict is
 * not bound by it; a strict call waits for the witness's ruling); local rules follow the checks
 * file's mode (`own`) on every call. `strict` is kept for the callers of 1.1; it no longer changes
 * the mode. */
export function entryMode(own: string, _strict: boolean, local: boolean): string {
  return local ? own : "watch";
}

/** The client's `rule` entry for one rule set (§2.8): §10.3 as a client over the call's arguments, in `mode`. */
export function clientRuleEntry(doc: Json, mode: string, setId: string, agent: string, tool: string, args: unknown): Json {
  const res = evaluate(doc, agent, tool, (p) => resolve(args, p));
  const e: Json = { check: "rule", ...applyMode(res.result, mode), mode, set: setId, matched: res.matched };
  // Spec 1.1: present only when not empty, so an entry without them reads as before.
  if (res.would_block.length) e.would_block = res.would_block;
  if (res.excepted.length) e.excepted = res.excepted;
  return e;
}

// --- §10.2 client acceptance of a fetched version -----------------------------------------

export interface ServiceKey {
  key_id: string;
  public_key: string;
  valid_from?: string | null;
  valid_to?: string | null;
}

/** Whether service key `k` is active at time `at`: `valid_from <= at < valid_to` (a null `valid_to` is open). */
export function keyActive(k: ServiceKey, at: unknown): boolean {
  try {
    return cmpTime(k.valid_from, at) <= 0 && (k.valid_to == null || cmpTime(at, k.valid_to) < 0);
  } catch {
    return false;
  }
}

/** The name of the first §10.2 step that refuses `item` (`{rules, sig, service_key_id}`), or
 * null when the client accepts it. `held` is the document the client holds. */
export function acceptRules(held: Json | null | undefined, item: unknown, serviceKeys: ServiceKey[], project: string, env: string): string | null {
  const doc = isObj(item) ? item.rules : undefined;
  if (ruleSetErrors(doc)) return "schema";
  if (doc.project !== project || doc.env !== env) return "project";
  const key = serviceKeys.find((k) => k?.key_id === (item as Json).service_key_id);
  if (!key || !keyActive(key, doc.issued) || !verifySig(key.public_key ?? "", "rules", hashJson(doc), (item as Json).sig)) return "signature";
  if (!held) return null;
  if (doc.set !== held.set) return "set";
  if (doc.version < held.version) return "older";
  if (doc.version === held.version) return hashJson(doc) === hashJson(held) ? null : "conflict";
  if (cmpTime(doc.issued, held.issued) < 0) return "issued";
  if (doc.version === held.version + 1 && doc.prev !== hashJson(held)) return "prev";
  return null;
}

// --- the shared fingerprint list (§11.2) --------------------------------------------------

export interface HeldList {
  seq: number;
  last: string | null;
  entries: { kind: string; fingerprint: string }[];
}

const entryKey = (e: Json): string => `${e.kind}\u0000${e.fingerprint}`;
const cmpEntry = (a: Json, b: Json): number => byCodePoint(a.kind, b.kind) || byCodePoint(a.fingerprint, b.fingerprint);

function entriesOk(entries: unknown): entries is Json[] {
  if (!Array.isArray(entries) || entries.length > 1_000_000) return false;
  for (const e of entries) if (!sameSet(e, ["kind", "fingerprint"]) || !["tool", "description", "server"].includes(e.kind) || !isHex64(e.fingerprint)) return false;
  for (let i = 1; i < entries.length; i++) if (cmpEntry(entries[i - 1], entries[i]) >= 0) return false;
  return true;
}

export function stateHash(entries: Json[]): string {
  return hashJson([...entries].sort(cmpEntry));
}

export function emptyList(): HeldList {
  return { seq: 0, last: null, entries: [] };
}

/** One served item `{list, sig, service_key_id}` applied to `held` (§11.2): `[newHeld, null]`, or
 * `[held, refusal]` with the refusal's name (`signature`, `state`, `older`, `gap`, `prev`, `invalid`). */
export function applyList(held: HeldList, item: unknown, serviceKeys: ServiceKey[]): [HeldList, string | null] {
  const obj = isObj(item) ? item.list : undefined;
  if (!isObj(obj)) return [held, "invalid"];
  const key = serviceKeys.find((k) => k?.key_id === (item as Json).service_key_id);
  let signed = false;
  try {
    signed = !!key && keyActive(key, obj.issued) && verifySig(key.public_key ?? "", "fingerprints", hashJson(obj), (item as Json).sig);
  } catch {
    signed = false;
  }
  if (!signed) return [held, "signature"];
  if (obj.format !== LIST_FORMAT || obj.list !== "shared" || !isSafeInt(obj.seq)) return [held, "invalid"];
  if (obj.type === "snapshot") {
    if (!entriesOk(obj.entries)) return [held, "invalid"];
    if (stateHash(obj.entries) !== obj.state_hash) return [held, "state"];
    if (obj.seq < held.seq) return [held, "older"];
    return [{ seq: obj.seq, last: obj.last ?? null, entries: [...obj.entries] as HeldList["entries"] }, null];
  }
  if (obj.type !== "update") return [held, "invalid"];
  if (obj.seq <= held.seq) return [held, "older"];
  if (obj.seq !== held.seq + 1) return [held, "gap"];
  if (obj.prev !== held.last) return [held, "prev"];
  if (!(entriesOk(obj.add) && entriesOk(obj.remove))) return [held, "invalid"];
  const have = new Set(held.entries.map(entryKey));
  if (obj.add.some((e) => have.has(entryKey(e))) || obj.remove.some((e) => !have.has(entryKey(e)))) return [held, "invalid"];
  const rm = new Set(obj.remove.map(entryKey));
  const entries = [...held.entries.filter((e) => !rm.has(entryKey(e))), ...(obj.add as HeldList["entries"])].sort(cmpEntry);
  if (stateHash(entries) !== obj.state_hash) return [held, "state"];
  return [{ seq: obj.seq, last: hashJson(obj), entries }, null];
}

/** `checks/fingerprints.json` as kept (§8): entries in order, no repeats. */
export function heldListErrors(doc: unknown): string | null {
  if (!sameSet(doc, ["seq", "last", "entries"]) || !isSafeInt(doc.seq) || doc.seq < 0) return "not {seq, last, entries}";
  if (!(doc.last === null || isHex64(doc.last)) || !entriesOk(doc.entries)) return "entries out of order or repeated";
  return null;
}

// --- tool fingerprints (§11.1) ------------------------------------------------------------

const SCHEMA_MAPS = ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"];
const SCHEMA_LISTS = ["allOf", "anyOf", "oneOf", "prefixItems"];
const SCHEMA_ONE = ["items", "additionalItems", "additionalProperties", "unevaluatedItems", "unevaluatedProperties", "contains", "propertyNames", "not", "if", "then", "else"];

/** §11.1 `strip`: without `description` and `title` members, here and in every schema inside. */
export function stripSchema(s: unknown): unknown {
  if (!isObj(s)) return s;
  const out: Json = {};
  for (const [k, v] of Object.entries(s)) {
    if (k === "description" || k === "title") continue;
    if (SCHEMA_MAPS.includes(k) && isObj(v)) out[k] = Object.fromEntries(Object.entries(v).map(([name, x]) => [name, stripSchema(x)]));
    else if (SCHEMA_LISTS.includes(k) && Array.isArray(v)) out[k] = v.map(stripSchema);
    else if (SCHEMA_ONE.includes(k)) out[k] = Array.isArray(v) ? v.map(stripSchema) : stripSchema(v);
    else out[k] = v;
  }
  return out;
}

export interface ToolFingerprints {
  tool: string;
  description: string;
  schema: string;
  server: string | null;
}

/** `{tool, description, schema, server}` (§11.1); `server` is null without an MCP server. */
export function toolFingerprints(name: string, description: string | null | undefined, inputSchema: unknown, serverInfo: Json | null | undefined): ToolFingerprints {
  const d = description || "";
  const s = inputSchema === undefined ? null : inputSchema;
  return {
    tool: hashJson({ name, description: d, input_schema: s }),
    description: sha256Hex(new TextEncoder().encode(d)),
    schema: hashJson(stripSchema(s)),
    server: serverInfo == null ? null : hashJson({ name: serverInfo.name ?? null, version: serverInfo.version ?? null }),
  };
}

// --- checks in an envelope (§2.8) ---------------------------------------------------------

/** The strongest result among the entries (`block` over `note` over `allow`); `allow` for none. */
export function combined(results: Iterable<Record<string, any>>): Result {
  let best: Result = "allow";
  for (const r of results) if ((RESULT_ORDER[r.result] ?? 0) > RESULT_ORDER[best]) best = r.result as Result;
  return best;
}

function entryErrors(e: unknown, kind: string): string | null {
  if (!isObj(e) || !(CHECK_IDS as readonly string[]).includes(e.check)) return "an entry names an unknown check";
  const c: string = e.check;
  if (kind === "decision" && !DECISION_CHECKS.includes(c)) return `the check '${c}' is not a check of a decision`;
  if (kind === "outcome" && !OUTCOME_CHECKS.includes(c)) return `the check '${c}' is not a check of an outcome`;
  const keys = ["check", "result", "mode"];
  if (e.mode === "watch") keys.push("enforce_result");
  keys.push(...(c === "rule" ? ["set", "matched"] : ["found"]));
  // Spec 1.1: a rule entry's would_block and excepted, written only when not empty.
  if (c === "rule") for (const k of ["would_block", "excepted"]) if (k in e) keys.push(k);
  if (!sameSet(e, keys)) return `the '${c}' entry has the wrong keys`;
  if ((e.mode !== "watch" && e.mode !== "enforce") || !(e.result in RESULT_ORDER)) return "an entry's `mode` is \"watch\" (Calibrating) or \"enforce\" (On) and its `result` allow, note or block";
  if (e.mode === "watch" && (!(e.enforce_result in RESULT_ORDER) || e.result !== (e.enforce_result === "block" ? "note" : e.enforce_result))) {
    return "when an entry's `mode` is \"watch\" (Calibrating), its result equals its enforce_result, except that block is written as note";
  }
  if (kind === "outcome" && c === "hidden_instruction" && (e.result === "block" || e.enforce_result === "block")) return "hidden_instruction never blocks on a result";
  if (c === "hidden_instruction" && Array.isArray(e.found) && e.found.includes(POSSIBLE) && (e.result !== "note" || (e.mode === "watch" && e.enforce_result !== "note"))) {
    return "a hidden_instruction entry with possible_hidden_instruction (arguments or a result) is a note, never a block";
  }
  if (c === "rule") {
    if (!(e.set === "local" || (typeof e.set === "string" && SET_RE.test(e.set)))) return "a rule entry's set is local or the rule set's id";
    if (!Array.isArray(e.matched) || e.matched.length > 16 || !e.matched.every((m: unknown) => typeof m === "string" && RULE_ID_RE.test(m))) return "a rule entry's matched is a list of at most 16 rule ids";
    const err = idListsErrors(e, ["would_block", "excepted"], "a rule entry");
    if (err) return err;
  } else {
    const f = e.found;
    if (!Array.isArray(f) || f.length > 8 || new Set(f.map(String)).size !== f.length || !f.every((x: unknown) => typeof x === "string" && FOUND[c].has(x))) {
      return `the '${c}' entry has an unknown or repeated found code`;
    }
  }
  return null;
}

/** The §2.8 rules for an envelope's `checks`; null when valid or absent. */
export function checksErrors(env: Json): string | null {
  if (!("checks" in env)) return null;
  const ch = env.checks;
  if ((env.kind !== "decision" && env.kind !== "outcome") || typeof env.name !== "string" || env.name.startsWith("signafaide.")) {
    return "checks is allowed only on a decision or outcome whose name does not start with 'signafaide.'";
  }
  if (!isObj(ch)) return "checks must be an object";
  if (env.kind === "outcome") {
    if (!sameSet(ch, ["ran", "ruling", "results", "result"])) return "the checks of an outcome are {ran, ruling, results, result}";
    if (typeof ch.ran !== "boolean" || !["allow", "block", "none", "not_asked"].includes(ch.ruling)) return "checks.ran is a boolean and checks.ruling allow, block, none or not_asked";
    if (ch.ran && ch.ruling === "block") return "checks.ran is true but checks.ruling is block: a call ruled block never runs";
    if (!ch.ran && (Array.isArray(ch.results) ? ch.results.length > 0 : !!ch.results)) return "checks.results must be empty when the tool did not run";
  } else {
    const keys = ["results", "result", "rules", "fingerprints", "tool", "strict", "fail", "disclosed", "disclosed_hash", "call_id"];
    if (!sameSet(ch, keys)) {
      const extra = Object.keys(ch)
        .filter((k) => !keys.includes(k))
        .sort(byCodePoint);
      return extra.length ? `the checks of a decision have the unknown key '${extra[0]}'` : "the checks of a decision lack a key";
    }
    const t = ch.tool;
    if (!sameSet(t, ["tool", "description", "schema", "server"]) || !["tool", "description", "schema"].every((k) => isHex64(t[k])) || !(t.server === null || isHex64(t.server))) {
      return "checks.tool holds 64-hex fingerprints (server may be null)";
    }
    const rs = ch.rules;
    if (!Array.isArray(rs) || rs.length > 2) return "checks.rules must be a list of at most 2 entries";
    const sets: string[] = [];
    for (const r of rs) {
      if (!sameSet(r, ["set", "version", "hash"]) || !isHex64(r.hash)) return "each checks.rules entry is {set, version, hash}";
      if (r.set === "local") {
        if (r.version !== null) return "the local rules' version is null";
      } else if (!(typeof r.set === "string" && SET_RE.test(r.set) && isSafeInt(r.version) && r.version >= 1)) {
        return "checks.rules names the project's rule set (rs_..., version 1 or above) or the local rules";
      }
      sets.push(r.set === "local" ? "local" : "project");
    }
    if (new Set(sets).size !== sets.length) return "checks.rules holds at most one entry for the project's rule set and one for the local rules";
    if (!(ch.fingerprints === null || (isSafeInt(ch.fingerprints) && ch.fingerprints >= 0))) return "checks.fingerprints must be null or the seq of the shared list";
    if (typeof ch.strict !== "boolean") return "checks.strict must be true (Protected) or false (Not protected)";
    if (!((ch.strict && (ch.fail === "open" || ch.fail === "closed")) || (!ch.strict && ch.fail === null))) return "checks.fail is \"open\" (Let it run) or \"closed\" (Stop) when checks.strict is true (Protected), and null otherwise";
    const d = ch.disclosed;
    if (!Array.isArray(d) || d.length > 64 || !d.every(pointerOk) || !sortedUnique(d)) return "checks.disclosed holds at most 64 JSON Pointers, in code point order, without repeats";
    if (d.length && !ch.strict) return "checks.disclosed must be empty on a call that is not protected";
    if (d.length > 0 !== (ch.disclosed_hash !== null) || (d.length && !isHex64(ch.disclosed_hash))) return "checks.disclosed_hash is 64 hex exactly when checks.disclosed is not empty";
    const cid = ch.call_id;
    if (!(cid === null || isSafeInt(cid) || (typeof cid === "string" && cpLen(cid) >= 1 && cpLen(cid) <= 128))) {
      return "checks.call_id must be null, a string of 1 to 128 characters, or an integer within ±(2^53−1)";
    }
  }
  const res = ch.results;
  if (!Array.isArray(res) || res.length > 32) return "checks.results must be a list of at most 32 entries";
  const seen = new Set<string>();
  for (const e of res) {
    const err = entryErrors(e, env.kind);
    if (err) return err;
    const k = `${e.check}\u0000${e.set ?? ""}`;
    if (seen.has(k)) return `the '${e.check}' check appears twice (rule appears once per rule set)`;
    seen.add(k);
  }
  if (ch.result !== combined(res)) return `checks.result must be the strongest result among the entries (${combined(res)})`;
  return null;
}

/** A decision asks the witness for a ruling: strict, and not blocked on the client (§3.5). */
export function asksForRuling(checks: unknown): boolean {
  return isObj(checks) && checks.strict === true && checks.result !== "block";
}

/** `sha256(disclosed_salt || JCS(disclosed))` (§2.3). */
export function disclosedHash(values: unknown, salt: string): string {
  if (typeof salt !== "string" || !SALT_RE.test(salt)) throw new Error("disclosed_salt must be 32 lowercase hex characters");
  const body = canonicalBytes(values);
  const all = new Uint8Array(16 + body.length);
  for (let i = 0; i < 16; i++) all[i] = parseInt(salt.slice(2 * i, 2 * i + 2), 16);
  all.set(body, 16);
  return sha256Hex(all);
}

/** Check 12 for a record's disclosed values (§2.3, §7), when it carries them: with their own
 * salt, hashing to `checks.disclosed_hash`; with `content` (matched), the call's input held them. */
export function disclosedErrors(rec: Json, content?: unknown): string | null {
  const d = rec.disclosed;
  const salt = rec.disclosed_salt;
  if (d === undefined && salt === undefined) return null;
  if (d === undefined || salt === undefined || d === null || salt === null) return "disclosed and disclosed_salt come together";
  const ch = rec.envelope?.checks;
  if (!isObj(ch) || typeof ch.disclosed_hash !== "string") return "disclosed values on a record whose checks.disclosed_hash is null";
  if (!isObj(d)) return "disclosed must be an object of {pointer: value}";
  const listed: string[] = Array.isArray(ch.disclosed) ? ch.disclosed : [];
  const extra = Object.keys(d)
    .filter((k) => !listed.includes(k))
    .sort(byCodePoint);
  if (extra.length) return `disclosed holds ${extra[0]}, which checks.disclosed does not list`;
  let h: string;
  try {
    h = disclosedHash(d, salt);
  } catch (e) {
    return (e as Error).message;
  }
  if (h !== ch.disclosed_hash) return `disclosed values hash to ${h}, checks.disclosed_hash says ${ch.disclosed_hash}`;
  if (isObj(content) && isObj(content.input)) {
    for (const p of listed) {
      const field = resolve(content.input, p);
      if (p in d) {
        if (field === ABSENT || !jcsEq(d[p], field)) return `the disclosed value at ${p} differs from the call's input`;
      } else if (field !== ABSENT) return `${p} was left out of the disclosed values as absent, but the call's input holds it`;
    }
  }
  return null;
}

/** Spec 1.1: the optional lists of rule ids (`would_block`, `not_calibrated`, `excepted`) of a
 * rule entry or a ruling: each, when present, 1 to 16 rule ids, each once; no rule in two of them
 * or in `matched`. */
function idListsErrors(o: Json, keys: string[], what: string): string | null {
  const lists: [string, string[]][] = [["matched", Array.isArray(o.matched) ? o.matched : []]];
  for (const k of keys) {
    if (!(k in o)) continue;
    const l = o[k];
    if (!Array.isArray(l) || l.length < 1 || l.length > 16) return `${what}'s ${k} is a list of 1 to 16 rule ids, written only when not empty`;
    if (!l.every((x: unknown) => typeof x === "string" && RULE_ID_RE.test(x)) || new Set(l).size !== l.length) return `${what}'s ${k} holds rule ids, each once`;
    lists.push([k, l]);
  }
  for (let i = 0; i < lists.length; i++)
    for (let j = i + 1; j < lists.length; j++) {
      const id = lists[i][1].find((x) => lists[j][1].includes(x));
      if (id) return `the rule ${id} is in both ${lists[i][0]} and ${lists[j][0]} of ${what}`;
    }
  return null;
}

const RULING_LISTS = ["would_block", "not_calibrated", "excepted"];

/** Whether a ruling object follows §3.5 field by field (check 6); null when it does. */
export function rulingErrors(r: unknown): string | null {
  if (!isObj(r)) return "a ruling is an object";
  const watch = r.mode === "watch";
  const keys = ["v", "record_hash", "batch_hash", "server_time", "ruling", "mode", "basis", "matched", "missing", "rules", "fingerprints", "reason", ...(watch ? ["enforce_ruling"] : [])];
  const withLists = [...keys, ...RULING_LISTS.filter((k) => k in r)];
  if (!sameSet(r, withLists)) return "the ruling's fields are " + [...keys].sort(byCodePoint).join(", ") + " (and from spec 1.1 would_block, not_calibrated and excepted when not empty)";
  if (r.v !== 1 || !isSafeInt(r.v)) return "the ruling's v must be 1";
  if (!(isHex64(r.record_hash) && isHex64(r.batch_hash)) || !validTime(r.server_time)) return "the ruling's record_hash, batch_hash or server_time is invalid";
  if ((r.ruling !== "allow" && r.ruling !== "block") || (r.mode !== "watch" && r.mode !== "enforce")) return "the ruling is allow or block, and its `mode` is \"watch\" (Calibrating) or \"enforce\" (On)";
  if (watch) {
    if (r.ruling !== "allow") return "when the ruling's `mode` is \"watch\" (Calibrating) the ruling is always allow";
    if (r.enforce_ruling !== "allow" && r.enforce_ruling !== "block") return "enforce_ruling is allow or block";
  }
  const enforce = watch ? r.enforce_ruling : r.ruling;
  const basis = r.basis;
  if (!["rules_version", "fields_missing", "fingerprint", "error", "rule", "default"].includes(basis)) return "basis is rules_version, fields_missing, fingerprint, error, rule or default";
  if (["rules_version", "fields_missing", "fingerprint", "error"].includes(basis) && enforce !== "block") return `basis ${basis} always blocks when On (\`mode\` is \"enforce\")`;
  const m = r.matched;
  if (!Array.isArray(m) || m.length > 16 || !m.every((x: unknown) => typeof x === "string" && RULE_ID_RE.test(x))) return "matched is a list of at most 16 rule ids";
  if ((m.length === 0) === (basis === "error" || basis === "rule")) return "matched names the rules exactly for basis error and rule";
  const miss = r.missing;
  if (!Array.isArray(miss) || miss.length > 64 || !miss.every(pointerOk) || !sortedUnique(miss)) return "missing is a list of at most 64 pointers in code point order";
  if ((miss.length === 0) === (basis === "fields_missing")) return "missing lists the pointers exactly for basis fields_missing";
  const rules = r.rules;
  if (rules === null) {
    if (watch || (basis !== "fingerprint" && basis !== "default")) return "without a rule set a ruling has `mode` \"enforce\" (On), with basis fingerprint or default";
  } else if (!(sameSet(rules, ["set", "version", "hash"]) && typeof rules.set === "string" && SET_RE.test(rules.set) && isSafeInt(rules.version) && rules.version >= 1 && isHex64(rules.hash))) {
    return "the ruling's rules is null or {set, version, hash}";
  }
  if (!isSafeInt(r.fingerprints) || r.fingerprints < 0) return "the ruling's fingerprints is the seq of the shared list";
  if (typeof r.reason !== "string" || cpLen(r.reason) < 1 || cpLen(r.reason) > 300) return "the ruling's reason is 1 to 300 characters";
  for (const k of RULING_LISTS) {
    if (!(k in r)) continue;
    if (!["error", "rule", "default"].includes(basis) || rules === null) return `the ruling's ${k} comes only from the evaluation of a rule set (basis error, rule or default)`;
    if (k !== "excepted" && watch) return `the ruling's ${k} is about Calibrating rules of a rule set that is On (\`mode\` is \"enforce\")`;
  }
  return idListsErrors(r, RULING_LISTS, "the ruling");
}

// --- the client's own checks (§8) ---------------------------------------------------------

export interface Findings {
  result: Result;
  found: string[];
}

/** The strings of `value`, in the order their members appear in its JCS form. */
export function stringLeaves(value: unknown): string[] {
  return labelledLeaves(value).map((x) => x[0]);
}

/** The strings of `value` in JCS order, each with the name of the member that holds it (null in
 * an array or at the top). */
export function labelledLeaves(value: unknown): [string, string | null][] {
  const out: [string, string | null][] = [];
  const walk = (v: unknown, name: string | null): void => {
    if (typeof v === "string") out.push([v, name]);
    else if (Array.isArray(v)) v.forEach((x) => walk(x, null));
    else if (isObj(v)) for (const k of Object.keys(v).sort()) walk(v[k], k); // UTF-16 unit order, as JCS
  };
  walk(value, null);
  return out;
}

const UTF8 = new TextEncoder();

/** `s` percent-decoded, when it holds `%` and two hex digits and decodes to UTF-8; else null. */
function pctDecode(s: string): string | null {
  if (!/%[0-9A-Fa-f]{2}/.test(s)) return null;
  const bytes: number[] = [];
  for (let i = 0; i < s.length; ) {
    if (s[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 3;
      continue;
    }
    const ch = String.fromCodePoint(s.codePointAt(i)!);
    bytes.push(...UTF8.encode(ch));
    i += ch.length;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

export function hostMatches(host: string, pattern: string): boolean {
  return pattern.startsWith("*.") ? host.endsWith(pattern.slice(1)) : host === pattern;
}

/** The host of an absolute http(s), ws(s) or ftp URL, lowercased (an IPv6 host in brackets). */
export function urlHost(s: string): string | null {
  if (!/^(https?|wss?|ftp):\/\//i.test(s)) return null;
  const rest = s.slice(s.indexOf("://") + 3);
  const auth = rest.split(/[/?#\\]/, 1)[0];
  const hostport = auth.slice(auth.lastIndexOf("@") + 1);
  if (hostport.startsWith("[")) {
    const end = hostport.indexOf("]");
    return end > 0 ? hostport.slice(0, end + 1).toLowerCase() : null;
  }
  return hostport.split(":", 1)[0].toLowerCase().replace(/\.+$/, "");
}

function entropy(s: string): number {
  // The runs it is used on are ASCII: count by code unit.
  const counts = new Uint32Array(128);
  for (let i = 0; i < s.length; i++) counts[s.charCodeAt(i) & 127]++;
  let h = 0;
  for (const k of counts) if (k) h -= (k / s.length) * Math.log2(k / s.length);
  return h;
}

const TOKEN = /[A-Za-z0-9_-]+/g;
/** The shortest token any format can match (`xox?-` and 10 more). */
const MIN_TOKEN = 15;

/** The block formats `text` holds (§8 secret): the table's whole tokens (unless every known
 * destination is an issuing host of the format), a private key, a wallet private key (WIF, or 64
 * hex digits labelled as a private key by `label` or the text before them) and a seed phrase. */
function tableFormat(tok: string, hosts: string[], witnessHost: string | null | undefined, found: Set<string>): void {
  if (tok.length < MIN_TOKEN) return;
  for (const [fid, pat, issuers] of SECRET_RES) {
    if (!pat.test(tok)) continue;
    const iss = fid === "signafaide_key" && witnessHost ? [witnessHost] : issuers;
    if (hosts.length && iss.length && hosts.every((h) => iss.some((p) => hostMatches(h, p)))) continue;
    found.add(fid);
    break;
  }
}

function formatsIn(text: string, label: string, hosts: string[], witnessHost: string | null | undefined, found: Set<string>, seeds = true, ascii = false): void {
  // Look-alike letters of the larger table, only in tokens that mix scripts (§8 secret); a
  // decoding is ASCII and has none.
  if (!ascii) for (const tok of lookalikeTokens(text)) tableFormat(tok, hosts, witnessHost, found);
  for (const m of text.matchAll(TOKEN)) {
    const tok = m[0];
    if (tok.length < MIN_TOKEN) continue;
    const n = found.size;
    tableFormat(tok, hosts, witnessHost, found);
    // A key glued to a name by "_" or "-" (aws_key_AKIA..., id-AKIA...): its parts are tokens too.
    if (found.size === n && /[_-]/.test(tok)) for (const part of tok.split(/[_-]+/)) tableFormat(part, hosts, witnessHost, found);
    if (tok.length >= 51 && isWif(tok)) found.add("wallet_private_key");
    else if (tok.length >= 64 && isHexKey(tok, `${label} ${text.slice(Math.max(0, m.index! - 32), m.index!)}`)) found.add("wallet_private_key");
  }
  if (PRIVATE_KEY_RE.test(text)) found.add("private_key");
  if (seeds && hasSeedPhrase(text)) found.add("seed_phrase");
}

/** Member names that carry an HTTP credential header. */
const AUTH_HEADERS = new Set(["authorization", "proxy-authorization"]);

/** The secrets known by where they stand (§8 secret, `CONTEXT_FORMATS`) in one text of an
 * argument named `name`: a JWT, a bearer value, a `NAME=value` pair whose name says secret and
 * whose value looks random (a lower bar in an environment dump), a URL query or fragment
 * parameter named as a credential. A JWT or bearer value that is the whole of an authorization
 * header member is exempt when the call has a single destination (`single`). */
function contextIn(text: string, name: string, single: boolean, found: Set<string>): void {
  const t = text.length > PAIRS_SCAN_MAX ? text.slice(0, PAIRS_SCAN_MAX) : text;
  const header = single && AUTH_HEADERS.has(name.toLowerCase());
  if (!header) {
    for (const m of t.matchAll(JWT_RE)) {
      if (isJwt(m[0])) {
        found.add("jwt");
        break;
      }
    }
    for (const m of t.matchAll(BEARER_RE)) {
      const v = m[1];
      if (!(v.startsWith("eyJ") && isJwt(v)) && looksRandom(v)) {
        found.add("bearer_token");
        break;
      }
    }
  }
  let dump: boolean | undefined;
  for (const [n, v, i] of pairs(t)) {
    const query = i > 0 && "?&#".includes(t[i - 1]);
    if (query ? secretName(n, true) && looksRandom(v) : secretName(n) && (looksRandom(v) || (dumpValue(v) && (dump ??= isEnvDump(t))))) {
      found.add("named_secret");
      return;
    }
  }
}

/** The `secret` check (§8) on a call's arguments (`result` false) or on a tool's result (`result`
 * true): `{result, found}` in enforce mode. `witnessHost` is the host of the client's witness URL,
 * the issuer of signafAIde keys. Every string is normalised first; the texts read are each string,
 * its percent-decoding, the concatenation of all and its percent-decoding, and what each of those
 * decodes to (hex, base64, nested). A result has no destination, and is read for block formats
 * only. */
export function secretFindings(args: unknown, witnessHost?: string | null, result = false): Findings {
  const leaves = labelledLeaves(args).map(([s, name]): [string, string] => [normalise(s), name ?? ""]);
  const hosts = result ? [] : leaves.map((x) => urlHost(x[0])).filter((h): h is string => h !== null);
  const found = new Set<string>();
  const budget = { left: DECODE_BUDGET };
  const single = new Set(hosts).size === 1;
  // Each string, its percent-decoding (twice: double encoding), and what they decode to: every
  // format; on arguments also the secrets known by where they stand, and the obfuscated tokens.
  for (const [s, name] of leaves) {
    const texts = [s];
    const d = pctDecode(s);
    if (d !== null) {
      texts.push(d);
      const d2 = pctDecode(d);
      if (d2 !== null) texts.push(d2);
    }
    for (const t of texts) {
      formatsIn(t, name, hosts, witnessHost, found);
      if (!result) contextIn(t, name, single, found);
      for (const x of decodings(t, budget)) {
        formatsIn(x, name, hosts, witnessHost, found, true, true);
        if (!result) contextIn(x, name, single, found);
      }
    }
    if (!result && s.length <= OBFUSCATION_MAX) {
      if (mayHoldReversed(s)) formatsIn([...s].reverse().join(""), "", hosts, witnessHost, found, false);
      const compact = s.replace(SEPARATORS, "");
      if (compact !== s && holdsPrefix(compact)) formatsIn(compact, "", hosts, witnessHost, found, false);
    }
    // A value named as a secret, as an argument's member (not text inside a longer string): with a
    // single destination it is how a client signs in to that service, and not a finding.
    if (!result && !single && secretName(name) && looksRandom(s)) found.add("named_secret");
  }
  // Short members of one object joined, in any order: a token split across members.
  if (!result) for (const j of memberJoins(args)) formatsIn(j, "", hosts, witnessHost, found, false);
  // The concatenation of all, and its percent-decoding: a token or key split across strings.
  if (leaves.length > 1) {
    const all = leaves.map((x) => x[0]).join("");
    const d = pctDecode(all);
    for (const t of d === null ? [all] : [all, d]) formatsIn(t, "", hosts, witnessHost, found, false);
  }
  if (found.size) return { result: "block", found: [...found].sort(byCodePoint).slice(0, 8) };
  if (result) return { result: "allow", found: [] };
  const notes = new Set<string>();
  for (const [s] of leaves) {
    const d = pctDecode(s);
    for (const t of d === null ? [s] : [s, d]) {
      if (hasCardNumber(t)) notes.add("card_number");
      for (const tok of t.match(TOKEN) ?? []) if (tok.length >= 26 && isWalletAddress(tok)) notes.add("wallet_address");
      for (const run of t.match(/[A-Za-z0-9_+/=-]+/g) ?? []) {
        if (run.length < 32 || notes.has("high_entropy") || entropy(run) < 4.5) continue;
        // A run that holds a whole format match or a wallet address is that, not random.
        if ((run.match(TOKEN) ?? []).some((tok) => (tok.length >= MIN_TOKEN && SECRET_RES.some(([, p]) => p.test(tok))) || (tok.length >= 26 && isWalletAddress(tok)))) continue;
        notes.add("high_entropy");
      }
    }
  }
  return { result: notes.size ? "note" : "allow", found: [...notes].sort(byCodePoint) };
}

// IP addresses, as Python's `ipaddress` reads them: [version, value].
type Ip = [4 | 6, bigint];

/** A dotted-quad IPv4 address: four decimal octets, no leading zeros. */
function parseV4(s: string): bigint | null {
  const m = s.match(/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
  if (!m) return null;
  let v = 0n;
  for (const p of m.slice(1)) {
    if ((p.length > 1 && p[0] === "0") || Number(p) > 255) return null;
    v = (v << 8n) | BigInt(p);
  }
  return v;
}

/** An IPv6 address (with `::` and a trailing dotted quad), as a 128-bit value; null when invalid. */
function parseV6(s: string): bigint | null {
  if (!s.includes(":")) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string, tailV4: boolean): bigint[] | null => {
    if (part === "") return [];
    const out: bigint[] = [];
    const items = part.split(":");
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (tailV4 && i === items.length - 1 && it.includes(".")) {
        const v4 = parseV4(it);
        if (v4 === null) return null;
        out.push(v4 >> 16n, v4 & 0xffffn);
      } else if (/^[0-9A-Fa-f]{1,4}$/.test(it)) out.push(BigInt(`0x${it}`));
      else return null;
    }
    return out;
  };
  let all: bigint[];
  if (halves.length === 2) {
    const a = groups(halves[0], false);
    const b = groups(halves[1], true);
    if (!a || !b || a.length + b.length > 7) return null;
    all = [...a, ...new Array<bigint>(8 - a.length - b.length).fill(0n), ...b];
  } else {
    const a = groups(s, true);
    if (!a || a.length !== 8) return null;
    all = a;
  }
  return all.reduce((acc, g) => (acc << 16n) | g, 0n);
}

function ipAddress(s: string): Ip | null {
  const v4 = parseV4(s);
  if (v4 !== null) return [4, v4];
  const v6 = parseV6(s);
  return v6 === null ? null : [6, v6];
}

function cidrOk(s: unknown): boolean {
  if (typeof s !== "string" || !s.includes("/")) return false;
  const i = s.indexOf("/");
  const [addr, length] = [s.slice(0, i), s.slice(i + 1)];
  if (!/^[0-9]+$/.test(length) || length !== String(Number(length))) return false;
  const ip = ipAddress(addr);
  return ip !== null && Number(length) <= (ip[0] === 4 ? 32 : 128);
}

function inNet(ip: Ip, net: string): boolean {
  const i = net.indexOf("/");
  const base = ipAddress(net.slice(0, i));
  if (!base || base[0] !== ip[0]) return false;
  const shift = BigInt((ip[0] === 4 ? 32 : 128) - Number(net.slice(i + 1)));
  return ip[1] >> shift === base[1] >> shift;
}

/** The IPv4 address a WHATWG URL parser reads `host` as; null for a name; "failure" when invalid. */
function whatwgIpv4(host: string): bigint | null | "failure" {
  let parts = host.split(".");
  if (parts[parts.length - 1] === "" && parts.length > 1) parts = parts.slice(0, -1);
  const last = parts[parts.length - 1];
  if (!(/^[0-9]+$/.test(last) || /^0[xX][0-9A-Fa-f]*$/.test(last))) return null;
  if (parts.length > 4) return "failure";
  const nums: bigint[] = [];
  for (const p of parts) {
    if (/^0[xX][0-9A-Fa-f]*$/.test(p)) nums.push(BigInt(`0x${p.slice(2) || "0"}`));
    else if (p.length > 1 && p.startsWith("0") && /^[0-7]+$/.test(p)) nums.push(BigInt(`0o${p}`));
    else if (/^[0-9]+$/.test(p)) nums.push(BigInt(p));
    else return "failure";
  }
  if (nums.slice(0, -1).some((x) => x > 255n) || nums[nums.length - 1] >= 256n ** BigInt(5 - nums.length)) return "failure";
  let v = nums[nums.length - 1];
  nums.slice(0, -1).forEach((x, i) => (v += x * 256n ** BigInt(3 - i)));
  return v;
}

const METADATA_NAMES = new Set(["metadata.google.internal", "metadata"]);
const METADATA_IPS: Ip[] = ["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"].map((s) => ipAddress(s)!);
const V4: [string, string][] = [
  ["0.0.0.0/8", "unspecified"],
  ["10.0.0.0/8", "private"],
  ["100.64.0.0/10", "shared"],
  ["127.0.0.0/8", "loopback"],
  ["169.254.0.0/16", "link_local"],
  ["172.16.0.0/12", "private"],
  ["192.168.0.0/16", "private"],
];
const V6: [string, string][] = [
  ["::/128", "unspecified"],
  ["::1/128", "loopback"],
  ["fc00::/7", "unique_local"],
  ["fe80::/10", "link_local"],
];

function classifyIp(ip: Ip, allowCidrs: readonly string[]): string | null {
  if (ip[0] === 6 && ip[1] >> 32n === 0xffffn) ip = [4, ip[1] & 0xffffffffn]; // IPv4-mapped
  for (const c of allowCidrs) if (cidrOk(c) && inNet(ip, c)) return null;
  if (METADATA_IPS.some((m) => m[0] === ip[0] && m[1] === ip[1])) return "metadata";
  for (const [net, code] of ip[0] === 4 ? V4 : V6) if (inNet(ip, net)) return code;
  return null;
}

/** Looks up a name's addresses (the `address` check with `resolve: true`); [] when it does not resolve. */
export type Resolver = (host: string) => string[];

/** The `address` finding for one host, or null for a public or allowlisted host. */
export function classifyHost(host: string, allowHosts: readonly string[] = [], allowCidrs: readonly string[] = [], resolver?: Resolver): string | null {
  if (allowHosts.some((p) => hostMatches(host, p))) return null;
  let ip: Ip | null = null;
  if (host.startsWith("[") && host.endsWith("]")) {
    const v6 = parseV6(host.slice(1, -1));
    if (v6 === null) return null;
    ip = [6, v6];
  } else {
    const v4 = whatwgIpv4(host);
    if (v4 === "failure") return null;
    if (v4 !== null) ip = [4, v4];
  }
  if (ip) return classifyIp(ip, allowCidrs);
  if (METADATA_NAMES.has(host)) return "metadata";
  if (host === "localhost" || host.endsWith(".localhost")) return "loopback";
  if (host.endsWith(".internal") || host.endsWith(".local")) return "internal_name";
  if (resolver && host) {
    let addrs: string[] = [];
    try {
      addrs = resolver(host);
    } catch {
      return null;
    }
    for (const a of addrs) {
      const x = ipAddress(a.split("%", 1)[0]);
      if (!x) continue;
      const code = classifyIp(x, allowCidrs);
      if (code) return code;
    }
  }
  return null;
}

function bareAddress(s: string): string | null {
  if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(s)) return parseV4(s) === null ? null : s;
  const inner = s.startsWith("[") && s.endsWith("]") ? s.slice(1, -1) : s;
  if (!inner.includes(":")) return null;
  return parseV6(inner) === null ? null : `[${inner}]`;
}

/** The `address` check (§8) on a call's arguments: `{result, found}` in enforce mode. */
export function addressFindings(args: unknown, allowHosts: readonly string[] = [], allowCidrs: readonly string[] = [], resolver?: Resolver): Findings {
  const found: string[] = [];
  for (const raw of stringLeaves(args)) {
    const s = normalise(raw);
    const h = urlHost(s) ?? bareAddress(s);
    if (h === null) continue;
    let code = classifyHost(h, allowHosts, allowCidrs, resolver);
    // A host that reads as a local or metadata name once look-alike letters are mapped (§8 address).
    if (code === null) {
      const like = hostLookalike(h);
      if (like !== null && !allowHosts.some((p) => hostMatches(h, p))) code = classifyHost(like, allowHosts, allowCidrs);
    }
    if (code && !found.includes(code)) found.push(code);
  }
  return { result: found.length ? "block" : "allow", found: found.sort(byCodePoint) };
}

/** `invisible_characters` and `instruction_phrase` in `strings`; an instruction phrase is also
 * looked for in what each string decodes to (hex, base64, nested; spec 1.1, benchmark batch 3),
 * within one `DECODE_BUDGET` for all of them. */
function instructionFoundIn(strings: readonly string[]): string[] {
  const found = new Set<string>();
  const budget = { left: DECODE_BUDGET };
  for (const s of strings) {
    if (!found.has("invisible_characters") && hasInvisible(s)) found.add("invisible_characters");
    if (!found.has("instruction_phrase") && (hasInstruction(s) || decodings(normalise(s), budget).some(hasInstruction))) found.add("instruction_phrase");
    if (found.size === 2) break;
  }
  return [...found].sort(byCodePoint);
}

/** A short name-like string (most member names, types, enum values): no pattern, encoded run or
 * invisible character fits in it, so the definition check skips it (only the time changes). */
const INERT = /^[A-Za-z0-9_.-]{0,15}$/;

function instructionFound(value: unknown): string[] {
  return instructionFoundIn(stringLeaves(value));
}

/** How deep a tool definition is read (nested objects and arrays), and how much text (UTF-16 code
 * units of strings and member names) at most (§8 hidden_instruction, spec 1.1 benchmark batch 3).
 * A definition past either cannot be read in full: `encoded_content`. */
export const DEFINITION_DEPTH_MAX = 64;
export const DEFINITION_TEXT_MAX = 1 << 20;

/** Every string of a definition and every member name, at any depth (schemas' `properties`,
 * `$defs`, `anyOf`, `items`, `default`, `examples`, `enum`, ...), in JCS order, each string with the
 * name of the member that holds it (null for a member name, in an array or at the top); `over`
 * when the definition is deeper or longer than the bounds, and the walk stopped there. */
export function definitionLeaves(value: unknown): { leaves: [string, string | null][]; over: boolean } {
  const leaves: [string, string | null][] = [];
  let left = DEFINITION_TEXT_MAX;
  let over = false;
  const take = (s: string, name: string | null): void => {
    if (s.length > left) {
      over = true;
      return;
    }
    left -= s.length;
    leaves.push([s, name]);
  };
  const walk = (v: unknown, name: string | null, depth: number): void => {
    if (over) return;
    if (typeof v === "string") take(v, name);
    else if (Array.isArray(v) || isObj(v)) {
      if (depth >= DEFINITION_DEPTH_MAX) {
        over = true;
        return;
      }
      if (Array.isArray(v)) for (const x of v) walk(x, null, depth + 1);
      else
        for (const k of Object.keys(v).sort()) {
          take(k, null);
          walk(v[k], k, depth + 1);
        }
    }
  };
  walk(value, null, 0);
  return { leaves, over };
}

/** The found code that marks a hidden instruction in what an agent writes (arguments) or a tool
 * returns (a result): always a note, beside the codes that say what was found (§2.8). */
export const POSSIBLE = "possible_hidden_instruction";

/** The `hidden_instruction` check (§8) on a call's result: `{result, found}`; a note, never
 * `block`, with `possible_hidden_instruction` beside what was found. */
export function hiddenFindings(result: unknown): Findings {
  const found = instructionFound(result);
  return found.length ? { result: "note", found: [...found, POSSIBLE].sort(byCodePoint) } : { result: "allow", found: [] };
}

/** The `hidden_instruction` check (§8) on a call's arguments (spec 1.1, benchmark batch 2):
 * `{result, found}`; a note, never `block`: what an agent writes is data, often quoting such
 * phrases legitimately. Surfaced to the caller as a `possible_hidden_instruction` note. */
export function argumentFindings(args: unknown): Findings {
  return hiddenFindings(args);
}

/** A note a wrapper or the gateway hands its caller (§8 notes): a possible hidden instruction in
 * a call's arguments (`in: "arguments"`) or its result (`in: "result"`). `found` says what was
 * found (`instruction_phrase`, `invisible_characters`). */
export interface CallNote {
  note: "possible_hidden_instruction";
  in: "arguments" | "result";
  tool: string;
  found: string[];
}

/** The notes of one `hidden_instruction` finding (§8 notes): none, or one. */
export function callNotes(tool: string, where: "arguments" | "result", findings: Findings): CallNote[] {
  if (!findings.found.includes(POSSIBLE)) return [];
  return [{ note: POSSIBLE, in: where, tool, found: findings.found.filter((f) => f !== POSSIBLE) }];
}

/** The decision's `hidden_instruction` entry (§8): the definition's findings block; without them,
 * the arguments' are a note with `possible_hidden_instruction`. */
export function decisionInstructionFindings(definition: Findings | null, args: Findings): Findings {
  if (definition && definition.result === "block") return definition;
  return args;
}

/** Whether a tool's name passes for another's (§8 `look_alike_name`), for the runtime. */
export { lookAlikeName };

/** What the definition check knows of the tool list: the tool's own name and the names of the
 * other tools listed with it (the gateway's `tools/list`). */
export interface DefinitionContext {
  self?: string;
  others?: readonly string[];
  /** The names of the tools approved earlier for the agent and the server (local approvals), for
   * `look_alike_name`. */
  approved?: readonly string[];
}

/** The `hidden_instruction` check (§8) on what the agent is shown of a tool or a server: every
 * string of a tool's definition (name, title, description, schemas, annotations, `_meta`, any
 * other member), or a server's `instructions`. Besides the instruction phrases and invisible
 * characters: `encoded_content` (content a reader cannot read: binary files or long opaque
 * base64, or a definition too deep or too long to read in full), `tool_shadowing` (instructions
 * about other tools) and `look_alike_name` (a name that passes for another tool's, or mixes
 * scripts). `{result, found}` in enforce mode: `block`. */
export function definitionFindings(definition: unknown, ctx: DefinitionContext = {}): Findings {
  const { leaves, over } = definitionLeaves(definition);
  const read = leaves.filter(([x]) => !INERT.test(x));
  const found = new Set(instructionFoundIn(read.map((x) => x[0])));
  if (over) found.add("encoded_content");
  const budget = { left: DECODE_BUDGET };
  const self = ctx.self ?? (isObj(definition) && typeof definition.name === "string" ? definition.name : "");
  if (lookAlikeName(self, ctx.others ?? [], ctx.approved ?? [])) found.add("look_alike_name");
  for (const [raw, name] of read) {
    if (!found.has("encoded_content") && hasEncodedContent(normalise(raw), name, budget)) found.add("encoded_content");
    if (!found.has("tool_shadowing") && hasShadowing(raw, self, ctx.others ?? [])) found.add("tool_shadowing");
    if (found.has("encoded_content") && found.has("tool_shadowing")) break;
  }
  const out = [...found].sort(byCodePoint);
  return { result: out.length ? "block" : "allow", found: out };
}

/** The `changed_tool` check (§8): `approved` is `{description, schema}` for the tool, or null when a
 * rule set's `approved` does not list it. */
export function changedToolFindings(fps: { description: string; schema: string }, approved: { description?: string; schema?: string } | null | undefined): Findings {
  if (!approved) return { result: "block", found: ["not_approved"] };
  if (fps.schema !== approved.schema) {
    const found = ["schema_changed", ...(fps.description !== approved.description ? ["description_changed"] : [])];
    return { result: "block", found: found.sort(byCodePoint) };
  }
  if (fps.description !== approved.description) return { result: "note", found: ["description_changed"] };
  return { result: "allow", found: [] };
}

/** The set of `kind` and fingerprint pairs of a list, for `fingerprintFindingsIn`. */
export function listedSet(entries: Iterable<{ kind: string; fingerprint: string }>): Set<string> {
  return new Set([...entries].map(entryKey));
}

/** The `fingerprint` check (§8): each of the tool's fingerprints on the shared list with its kind,
 * except those the held rule set excepts (`excepted`, §10.1 `fingerprint_exceptions`). */
export function fingerprintFindingsIn(fps: Json, listed: ReadonlySet<string>, excepted?: ReadonlySet<string>): Findings {
  const found = ["tool", "description", "server"].filter((k) => {
    const key = entryKey({ kind: k, fingerprint: fps[k] });
    return fps[k] && listed.has(key) && !excepted?.has(key);
  });
  return { result: found.length ? "block" : "allow", found: found.sort(byCodePoint) };
}

export function fingerprintFindings(fps: Json, entries: Iterable<{ kind: string; fingerprint: string }>, exceptions?: Iterable<{ kind: string; fingerprint: string }>): Findings {
  return fingerprintFindingsIn(fps, listedSet(entries), exceptions ? listedSet(exceptions) : undefined);
}

/** A results entry (§2.8) for one of the client's own checks. */
export function entry(check: string, findings: Findings, mode: string): Json {
  return { check, ...applyMode(findings.result, mode), mode, found: findings.found };
}

// --- the checks file (§8) ----------------------------------------------------------------

/** The first problem with a checks file, naming the key; null when valid. */
export function checksFileErrors(doc: unknown): string | null {
  if (!isObj(doc)) return "the file is not a JSON object";
  if (doc.format !== CHECKS_FORMAT && doc.format !== CHECKS_FORMAT_2) return `format must be ${CHECKS_FORMAT} or ${CHECKS_FORMAT_2}`;
  const v2 = doc.format === CHECKS_FORMAT_2;
  let err = exact(doc, v2 ? ["format", "checks", "tools", "addresses", "rules"] : ["format", "mode", "checks", "tools", "addresses", "rules"], ["ruling_timeout_ms", "ci", "proposed"], "the checks file");
  if (err) return err;
  if (!v2 && doc.mode !== "watch" && doc.mode !== "enforce") return "`mode` must be \"watch\" (Calibrating) or \"enforce\" (On)";
  const c = doc.checks;
  if (!isObj(c)) return "checks must be an object of the five checks";
  err = exact(c, [...FILE_CHECKS], [], "checks");
  if (err) return err;
  const bad = FILE_CHECKS.filter((k) => typeof c[k] !== "boolean");
  if (bad.length) return `checks.${bad[0]} must be true or false`;
  const tools = doc.tools;
  if (!isObj(tools)) return "tools must be an object of declared tool names";
  for (const [name, t] of Object.entries(tools)) {
    if (!declaredNameOk(name)) return `tools: '${name}' is not a declared tool name (1 to 101 characters)`;
    if (v2) {
      if (!isObj(t)) return `tools.${name} must be {protect, mode?, disclose?}: \`protect\` is true (Protected) or false (Not protected), \`mode\` is "enforce" (On) or "watch" (Calibrating)`;
      err = exact(t, ["protect"], ["mode", "disclose"], `tools.${name}`);
      if (err) return err;
      if (typeof t.protect !== "boolean") return `tools.${name}.protect must be true (Protected) or false (Not protected)`;
      if ("mode" in t && t.mode !== "watch" && t.mode !== "enforce") return `tools.${name}.mode must be "watch" (Calibrating) or "enforce" (On)`;
      if ("disclose" in t) {
        if (!t.protect) return `tools.${name}.disclose is allowed only on a protected tool: only protected calls send fields (set \`protect\` to true to protect the tool)`;
        if (!(Array.isArray(t.disclose) && t.disclose.length <= 64 && t.disclose.every(pointerOk))) return `tools.${name}.disclose must be a list of at most 64 JSON Pointers`;
        const dup = t.disclose.find((p: string, i: number) => t.disclose.indexOf(p) !== i);
        if (dup !== undefined) return `tools.${name}.disclose lists ${dup} twice`;
      }
      continue;
    }
    if (!isObj(t)) return `tools.${name} must be {strict, fail?, disclose?}: \`strict\` is true (Protected) or false (Not protected), \`fail\` is "closed" (if signafAIde can't be reached: Stop) or "open" (Let it run)`;
    err = exact(t, ["strict"], ["fail", "disclose"], `tools.${name}`);
    if (err) return err;
    if (typeof t.strict !== "boolean") return `tools.${name}.strict must be true (Protected) or false (Not protected)`;
    if ("fail" in t && t.fail !== "open" && t.fail !== "closed") return `tools.${name}.fail must be "closed" (Stop) or "open" (Let it run)`;
    if ("disclose" in t && !(Array.isArray(t.disclose) && t.disclose.length <= 64 && t.disclose.every(pointerOk))) return `tools.${name}.disclose must be a list of at most 64 JSON Pointers`;
  }
  const a = doc.addresses;
  if (!isObj(a)) return "addresses must be {hosts, cidrs, resolve}";
  err = exact(a, ["hosts", "cidrs", "resolve"], [], "addresses");
  if (err) return err;
  if (!Array.isArray(a.hosts) || !a.hosts.every(hostPatternOk)) return "addresses.hosts holds lowercase names, or *. and a suffix";
  if (!Array.isArray(a.cidrs) || !a.cidrs.every(cidrOk)) return "addresses.cidrs holds IPv4 or IPv6 networks in CIDR form";
  if (typeof a.resolve !== "boolean") return "addresses.resolve must be true or false";
  err = localRulesErrors(doc.rules);
  if (err) return err;
  if ("ruling_timeout_ms" in doc && !(isSafeInt(doc.ruling_timeout_ms) && doc.ruling_timeout_ms >= 1 && doc.ruling_timeout_ms <= 60_000)) {
    return "ruling_timeout_ms must be an integer from 1 to 60,000";
  }
  if ("proposed" in doc) {
    err = proposedErrors(doc.proposed, v2, doc.rules);
    if (err) return err;
  }
  if ("ci" in doc) return ciErrors(doc.ci);
  return null;
}

/** `proposed` of a version 2 checks file: the rules an agent run proposed and could not save, each
 * `{rule, by: "agent", on: "YYYY-MM-DD"}`: `rule` is the id of a local rule, or a rule with a
 * `limit` itself (only the witness counts calls, so it is never a local rule and never applies
 * here). A person running `protect` is offered them. */
function proposedErrors(p: unknown, v2: boolean, rules: unknown): string | null {
  if (!v2) return "proposed is for checks file version 2";
  if (!Array.isArray(p) || p.length > 1000) return "proposed must be a list of at most 1,000 {rule, by, on}";
  const ids = new Set<string>(isObj(rules) && Array.isArray(rules.rules) ? rules.rules.map((r: Json) => r.id) : []);
  const seen = new Set<string>();
  for (const [i, x] of p.entries()) {
    if (!isObj(x)) return `proposed[${i}] must be {"rule", "by", "on"}`;
    const e = exact(x, ["rule", "by", "on"], [], `proposed[${i}]`);
    if (e) return e;
    let id: string;
    if (isObj(x.rule)) {
      const re = ruleErrors(x.rule, true, null);
      if (re) return `proposed[${i}].rule: ${re}`;
      if (!("limit" in x.rule)) return `proposed[${i}].rule holds a rule only when it has a limit; any other rule is a local rule in rules, named by its id`;
      if (ids.has(x.rule.id)) return `proposed[${i}].rule has the id of a rule in rules`;
      id = x.rule.id;
    } else if (typeof x.rule !== "string" || !ids.has(x.rule)) return `proposed[${i}].rule must be the id of a rule in rules, or a rule with a limit`;
    else id = x.rule;
    if (seen.has(id)) return `proposed lists ${id} twice`;
    seen.add(id);
    if (x.by !== "agent") return `proposed[${i}].by must be "agent"`;
    if (typeof x.on !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(x.on)) return `proposed[${i}].on must be a date, YYYY-MM-DD`;
  }
  return null;
}

/** `ci` of a checks file: `{"allow": [{"tool", "reason"}]}`, the reviewed exceptions of
 * `signafaide check --ci` (a risky tool left unprotected on purpose, with the reason). */
function ciErrors(ci: unknown): string | null {
  if (!isObj(ci)) return 'ci must be {"allow": [{"tool", "reason"}]}';
  const err = exact(ci, ["allow"], [], "ci");
  if (err) return err;
  if (!Array.isArray(ci.allow) || ci.allow.length > 1000) return "ci.allow must be a list of at most 1,000 {tool, reason}";
  const seen = new Set<string>();
  for (const [i, a] of ci.allow.entries()) {
    if (!isObj(a)) return `ci.allow[${i}] must be {"tool", "reason"}`;
    const e = exact(a, ["tool", "reason"], [], `ci.allow[${i}]`);
    if (e) return e;
    if (!declaredNameOk(a.tool)) return `ci.allow[${i}].tool must be a declared tool name (1 to 101 characters)`;
    if (typeof a.reason !== "string" || !a.reason.trim() || cpLen(a.reason) > 1000) return `ci.allow[${i}].reason must say why the tool is allowed (1 to 1,000 characters)`;
    if (seen.has(a.tool)) return `ci.allow lists ${a.tool} twice`;
    seen.add(a.tool);
  }
  return null;
}

/** What a checks file says for one tool (§8): whether its calls are strict by the file (version 1
 * `strict`, version 2 `protect`), the fail mode it gives a strict tool, the mode of the client's
 * own checks and local rules on its calls, and the fields the developer approved for sending. */
export interface ToolSettings {
  strict: boolean;
  fail: "open" | "closed";
  mode: "watch" | "enforce";
  disclose: string[];
}

/** §8: the settings of the tool with this declared name in a valid checks file. Version 2: a
 * protected tool defaults to enforce mode, any other tool (listed or not) to watch mode. */
export function toolSettings(file: Json, name: string): ToolSettings {
  const t: Json | undefined = isObj(file.tools) && Object.prototype.hasOwnProperty.call(file.tools, name) ? file.tools[name] : undefined;
  if (file.format === CHECKS_FORMAT_2) {
    if (!t) return { strict: false, fail: "closed", mode: "watch", disclose: [] };
    const protect = t.protect === true;
    return { strict: protect, fail: "closed", mode: t.mode ?? (protect ? "enforce" : "watch"), disclose: protect ? [...(t.disclose ?? [])] : [] };
  }
  const mode = file.mode === "enforce" ? "enforce" : "watch";
  if (!t) return { strict: false, fail: "closed", mode, disclose: [] };
  const strict = t.strict === true;
  return { strict, fail: strict && t.fail === "open" ? "open" : "closed", mode, disclose: strict ? [...(t.disclose ?? [])] : [] };
}

/** The checks file's version: 1 or 2. */
export const checksFileVersion = (file: Json): 1 | 2 => (file.format === CHECKS_FORMAT_2 ? 2 : 1);

/** The checks file `signafaide init` writes: every check on, in watch mode, no strict tool. */
export function defaultChecksFile(): Json {
  return {
    format: CHECKS_FORMAT,
    mode: "watch",
    checks: Object.fromEntries(FILE_CHECKS.map((k) => [k, true])),
    tools: {},
    addresses: { hosts: [], cidrs: [], resolve: false },
    rules: null,
  };
}

// --- the verifier's tool-call checks report (§7) ------------------------------------------

export interface AgentChecks {
  checked: number;
  allowed: number;
  noted: number;
  blocked_here: number;
  blocked_by_witness: number;
  notes: Record<string, number>;
  ruled: { allow: number; block: number; watch_would_block: number; calibrating_would_block: number; by_exception: number; not_calibrated: number };
  no_ruling: { ran: number; not_run: number; no_outcome: number };
  ran_after_block: number[];
  /** The seqs of outcomes whose result the client withheld from the agent (§2.8). */
  withheld: number[];
  rule_sets: { set: string; version: number | null; hash: string }[];
}

export interface CheckItem {
  seq: number;
  kind: string;
  checks: unknown;
  /** For an outcome, the seq of the decision its `ref` names. */
  decision_seq: number | null;
  /** The ruling on the record's receipt, if any. */
  ruling: unknown;
}

/** The report of one agent from its records, in chain order; null when it would have no line. */
export function agentChecks(items: CheckItem[]): AgentChecks | null {
  const outs = new Map<number, CheckItem>();
  for (const i of items) if (i.kind === "outcome" && i.decision_seq != null) outs.set(i.decision_seq, i);
  const j: AgentChecks = {
    checked: 0,
    allowed: 0,
    noted: 0,
    blocked_here: 0,
    blocked_by_witness: 0,
    notes: {},
    ruled: { allow: 0, block: 0, watch_would_block: 0, calibrating_would_block: 0, by_exception: 0, not_calibrated: 0 },
    no_ruling: { ran: 0, not_run: 0, no_outcome: 0 },
    ran_after_block: [],
    withheld: [],
    rule_sets: [],
  };
  const sets = new Map<string, { set: string; version: number | null; hash: string }>();
  const addSet = (x: Json): void => {
    sets.set(JSON.stringify([x.set, x.version, x.hash]), { set: x.set, version: x.version, hash: x.hash });
  };
  for (const d of items) {
    const c = d.checks;
    if (d.kind !== "decision" || !isObj(c)) continue;
    j.checked++;
    const g = isObj(d.ruling) ? d.ruling : null;
    const o = outs.get(d.seq);
    const asked = c.strict === true && c.result !== "block";
    const gRuling = g ? g.ruling : null;
    if (c.result === "block") j.blocked_here++;
    else if (gRuling === "block") j.blocked_by_witness++;
    else if (c.result === "note") j.noted++;
    else j.allowed++;
    for (const rr of Array.isArray(c.rules) ? c.rules : []) addSet(rr);
    if (g) {
      if (isObj(g.rules)) addSet(g.rules);
      if (gRuling === "allow" || gRuling === "block") j.ruled[gRuling as "allow" | "block"]++;
      if (g.mode === "watch" && g.enforce_ruling === "block") j.ruled.watch_would_block++;
      const has = (k: string): boolean => Array.isArray(g[k]) && g[k].length > 0;
      if (gRuling === "allow" && has("would_block")) j.ruled.calibrating_would_block++;
      if (gRuling === "allow" && has("excepted")) j.ruled.by_exception++;
      if (has("not_calibrated")) j.ruled.not_calibrated++;
    }
    const oc: Json = o && isObj(o.checks) ? o.checks : {};
    const oRan = "ran" in oc ? !!oc.ran : true;
    const oNone = oc.ruling === "none";
    if (asked && (!g || (o && oNone))) {
      if (!o) j.no_ruling.no_outcome++;
      else if (oRan) j.no_ruling.ran++;
      else j.no_ruling.not_run++;
    }
    const blocked = c.result === "block" || gRuling === "block";
    if (blocked && o && oRan && !oNone) j.ran_after_block.push(d.seq);
  }
  for (const i of items) {
    const c = i.checks;
    if (!isObj(c)) continue;
    for (const e of Array.isArray(c.results) ? c.results : []) if (e?.result === "note") j.notes[e.check] = (j.notes[e.check] ?? 0) + 1;
    if (i.kind === "outcome" && c.result === "block") j.withheld.push(i.seq);
  }
  j.rule_sets = [...sets.values()].sort((a, b) => byCodePoint(a.set, b.set) || (a.version ?? -1) - (b.version ?? -1) || byCodePoint(a.hash, b.hash));
  return checksLines(".", j).length ? j : null;
}

const count = (k: number, one: string, many: string): string => `${k} ${k === 1 ? one : many}`;

/** The report lines of one agent (§7), without the `tool-call checks: ` prefix. */
export function checksLines(agent: string, j: AgentChecks): string[] {
  const out: string[] = [];
  if (j.checked) {
    const parts = [`${j.allowed} allowed`];
    if (j.noted) parts.push(`${j.noted} with notes`);
    if (j.blocked_here) parts.push(`${j.blocked_here} blocked here without a ruling from the witness`);
    if (j.blocked_by_witness) parts.push(`${j.blocked_by_witness} blocked by the witness`);
    out.push(`${agent}: ${count(j.checked, "tool call", "tool calls")} checked: ${parts.join(", ")}`);
  }
  if (Object.keys(j.notes).length) out.push(`${agent}: notes: ${CHECK_IDS.filter((k) => k in j.notes).map((k) => `${k} ${j.notes[k]}`).join(", ")}`);
  const r = j.ruled;
  const ruled = r.allow + r.block;
  if (ruled) {
    const p = [`${r.allow} allowed`];
    if (r.block) p.push(`${r.block} blocked`);
    if (r.watch_would_block) p.push(`${r.watch_would_block} Calibrating (would have blocked if On)`);
    if (r.calibrating_would_block) p.push(`${r.calibrating_would_block} allowed that a Calibrating rule would have blocked if On`);
    if (r.by_exception) p.push(`${r.by_exception} allowed by exception`);
    if (r.not_calibrated) p.push(`${r.not_calibrated} with a Calibrating rule that could not be checked because a field it needs was not sent`);
    out.push(`${agent}: ${count(ruled, "protected call", "protected calls")} ruled by the witness: ${p.join(", ")}`);
  }
  const nr = j.no_ruling;
  const tot = nr.ran + nr.not_run + nr.no_outcome;
  if (tot) {
    const p: string[] = [];
    if (nr.ran) p.push(`${nr.ran} ran because the tool was set to Let it run`);
    if (nr.not_run) p.push(`${nr.not_run} did not run`);
    if (nr.no_outcome) p.push(`${nr.no_outcome} have no outcome in the pack`);
    const had = tot === 1 ? "had no ruling when it was decided" : "had no ruling when they were decided";
    out.push(`${agent}: ${count(tot, "protected call", "protected calls")} ${had}: ${p.join(", ")}`);
  }
  if (j.ran_after_block.length) out.push(`${agent}: ${count(j.ran_after_block.length, "call", "calls")} ran after a block: seq ${j.ran_after_block.join(", ")}`);
  if (j.withheld.length) out.push(`${agent}: ${count(j.withheld.length, "tool result", "tool results")} withheld from the agent: seq ${j.withheld.join(", ")}`);
  if (j.rule_sets.length) out.push(`${agent}: rule sets used: ${j.rule_sets.map((x) => (x.set === "local" ? `local ${x.hash.slice(0, 8)}` : `${x.set} version ${x.version}`)).join(", ")}`);
  return out;
}

// --- protected from the console (SDK 0.5.2, §8, §10.1) -----------------------------------------

/** The fail mode the held rule set gives `tool` (its `fail`, else its `protect`), when it names it. */
export function ruleSetFail(rs: Json | null | undefined, tool: string | undefined): "open" | "closed" | undefined {
  if (!rs || tool === undefined) return undefined;
  const own = (o: unknown, k: string): boolean => isObj(o) && Object.prototype.hasOwnProperty.call(o, k);
  if (own(rs.fail, tool)) return rs.fail[tool];
  if (own(rs.protect, tool)) return rs.protect[tool].fail;
  return undefined;
}

/** Whether the held rule set protects `tool` from the console (its `protect` names it). */
export function consoleProtects(rs: Json | null | undefined, tool: string | undefined): boolean {
  return !!rs && tool !== undefined && isObj(rs.protect) && Object.prototype.hasOwnProperty.call(rs.protect, tool);
}

/** What protects a tool, and how its calls are checked (§8, SDK 0.5.2). */
export interface Protection {
  strict: boolean;
  fail: "open" | "closed" | null;
  mode: "watch" | "enforce";
  /** `code`, `checks_file`, `console`: each that protects the tool, in that order (`meta.protected_by`). */
  sources: ("code" | "checks_file" | "console")[];
  disclose: string[];
}

/** The protection of `tool` (a declared name) from the held rule set, the checks file and the
 * code (`code`: strict in code); null when its calls are not checked at all. `vectors.json`
 * `checks.console_protect`. */
export function protection(rs: Json | null | undefined, file: Json | null | undefined, code: boolean, tool: string): Protection | null {
  const console = consoleProtects(rs, tool);
  if (!file && !code && !console) return null;
  const ts = file ? toolSettings(file, tool) : null;
  const inFile = !!ts?.strict;
  const sources: Protection["sources"] = [];
  if (code) sources.push("code");
  if (inFile) sources.push("checks_file");
  if (console) sources.push("console");
  const strict = sources.length > 0;
  let mode: "watch" | "enforce";
  if (!ts) mode = "enforce";
  else if (inFile || !console) mode = ts.mode;
  else {
    const t = file!.format === CHECKS_FORMAT_2 && isObj(file!.tools) && Object.prototype.hasOwnProperty.call(file!.tools, tool) ? file!.tools[tool] : undefined;
    mode = t && (t.mode === "watch" || t.mode === "enforce") ? t.mode : "enforce";
  }
  const fail = strict ? (ruleSetFail(rs, tool) ?? (inFile ? ts!.fail : "closed")) : null;
  return { strict, fail, mode, sources, disclose: ts ? [...ts.disclose] : [] };
}

/** Where a tool's protection comes from, in words (§8): `by the code`, `by the checks file`,
 * `from the console (rule set version 4)`, joined with `and` (`by the code and the checks file`). */
export function sourceWords(sources: readonly string[], version?: number | null): string {
  const by = sources.filter((s) => s !== "console").map((s) => (s === "code" ? "the code" : "the checks file"));
  const parts = by.length ? [`by ${by.join(" and ")}`] : [];
  if (sources.includes("console")) parts.push(`from the console${version != null ? ` (rule set version ${version})` : ""}`);
  return parts.join(" and ");
}
