/**
 * The §7 verifier, in pure TypeScript (runs in Node, browsers and edge runtimes).
 * Same check ids, statuses, text and JSON as the reference verifier (`signafaide-verify`).
 *
 * The drand BLS12-381 signature (check 9) is verified only when a `drand` verifier is
 * passed; `loadDrandVerifier()` builds one from `@noble/curves` (a dependency).
 * Without it the check is "not checked", never "pass".
 */

import { hexToBytes } from "@noble/hashes/utils";
import { HEX64, b64urlDecode, hashJson, keyId, sha256Hex, verifyInclusion, verifySig } from "./crypto.js";
import { parseJson } from "./jcs.js";
import { base64Decode, blockAttestations, otsStatus } from "./ots.js";
import { AGENT_RE, MAX_CLOCK_SKEW_MS, draftErrors, keyEntryErrors, manifestErrors, receiptErrors, recordErrors, validProjectId, validTime, type AgentKeyEntry } from "./records.js";
import { plural } from "./plural.js";
import { checkHeader, type BlockRoots } from "./timestamps.js";

export const CHECKS = [
  ["schema", "Envelope schema"],
  ["record_hash", "Record hashes"],
  ["record_sig", "Client signatures"],
  ["chain", "Agent chains"],
  ["merkle", "Merkle proofs"],
  ["batch_sig", "Batch hashes and signatures"],
  ["batch_chain", "Batch chain"],
  ["head_sig", "Signed heads"],
  ["drand", "drand rounds"],
  ["anchor", "Anchors"],
  ["ots", "OpenTimestamps"],
  ["content", "Content hashes"],
] as const;
/** Why a pack without records fails (§7): an empty pack proves nothing. */
export const NO_RECORDS = "no records: an empty pack proves nothing";
/** Shown when drand rounds are present but no BLS library could be loaded. */
export const DRAND_NOT_CHECKED = "drand: not checked (npm install @noble/curves)";
const NO_LOCAL_RECORDS = "no records: nothing has been recorded here yet";
/** Check 3 without independent agent keys (§7). */
export const NOT_INDEPENDENT =
  "NOT INDEPENDENT: agent keys came from the pack; pass --agent-keys <file|url> (the customer's `signafaide keys export`), or --trust-embedded-agent-keys";
const QUICKNET_GENESIS = 1692803367;
const MAX_ROUND_AGE_MS = 120_000;
/** The highest drand round whose publication time is a protocol time (year 9999 at most). */
export const MAX_ROUND = Math.floor((253_402_300_799 - QUICKNET_GENESIS) / 3) + 1;
/** A batch is anchored within this time of its server_time (§4); an older batch no anchor covers is "not timestamped". */
export const ANCHOR_WINDOW_MS = 7_200_000;
/** Where keys came from, when not from an independent source (§7 result line). */
export type KeySource = "independent" | "taken from the pack" | "fetched over plain http";
export interface PackFilter {
  agents: string[] | null;
  from: string | null;
  to: string | null;
}
const UNITS: [string, string?][] = [["record"], ["record"], ["record"], ["record"], ["record"], ["batch", "batches"], ["batch", "batches"], ["head"], ["round"], ["anchor"], ["proof"], ["record"]];
export const QUICKNET_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
export const QUICKNET_PUBLIC_KEY =
  "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

export type CheckId = (typeof CHECKS)[number][0];
export type Status = "pass" | "fail" | "not_checked";
export interface Failure {
  item: string;
  message: string;
}
export interface Check {
  n: number;
  id: CheckId;
  title: string;
  status: Status;
  checked: number;
  detail: string;
  value?: string;
  failures: Failure[];
}
export interface KeyDoc {
  key_id: string;
  public_key: string;
  valid_from?: string | null;
  valid_to?: string | null;
  agent?: string;
}
export interface DrandBeacon {
  chain: string;
  round: number;
  randomness: string;
  signature: string;
}
/** Verifies a quicknet beacon's BLS signature over its round. */
export type DrandVerifier = (beacon: DrandBeacon) => boolean;

/** No independent service keys and `trustEmbeddedKeys` not set: an input error (exit 2). */
export class KeysRequired extends Error {
  override name = "KeysRequired";
}

function keyReasons(service: KeySource, agent: KeySource): string | null {
  const a = service === "independent" ? null : service;
  const b = agent === "independent" ? null : agent;
  if (a && b) return a === b ? `service keys and agent keys ${a}` : `service keys ${a} and agent keys ${b}`;
  if (a) return `service keys ${a}`;
  if (b) return `agent keys ${b}`;
  return null;
}

/** What a pack covers (§7 result line): `export of every agent, all records, generated <t>`. */
export function scopeText(filter: PackFilter, generated: string): string {
  const a = filter.agents;
  const who = a === null ? "every agent" : a.length === 1 ? `agent ${a[0]}` : `agents ${a.join(", ")}`;
  const { from: f, to: t } = filter;
  const window = f === null && t === null ? "all records" : t === null ? `records from ${f}` : f === null ? `records before ${t}` : `records from ${f} before ${t}`;
  return `export of ${who}, ${window}, generated ${generated}`;
}

/** `PASS` or `FAIL`; on PASS, why keys were not independent; then what the pack covers (§7). */
export function resultLine(result: string, service: KeySource = "independent", agent: KeySource = "independent", byService = false, scope: string | null = null): string {
  let out = result;
  if (result === "PASS") {
    if (byService) out += " (checked by the service with its own key registry; not independent)";
    else {
      const r = keyReasons(service, agent);
      if (r) out += ` (${r}, not independent)`;
    }
  }
  if (scope) out += `: ${scope}`;
  return out;
}

export interface ReportScope {
  generated: string;
  filter: PackFilter;
  sources: [KeySource, KeySource];
  byService: boolean;
}

export class Report {
  /** Lines shown after the checks, before the result line: for local state, what still needs
   * the witness (co-signature, public timestamp). */
  readonly after: string[] = [];

  constructor(
    readonly checks: Check[],
    readonly project: string | null = null,
    readonly env: string | null = null,
    readonly records = 0,
    readonly warnings: string[] = [],
    readonly notes: string[] = [],
    readonly independent: { service_keys: boolean; agent_keys: boolean } = { service_keys: true, agent_keys: true },
    readonly scope: ReportScope | null = null,
  ) {}

  /** e.g. `PASS: export of every agent, all records, generated <t>`, or
   * `PASS (agent keys taken from the pack, not independent): export of ...` (§7). */
  get resultLine(): string {
    const s = this.scope;
    // Local state: the only way keys are not independent there is plain http on this machine.
    if (!s) return resultLine(this.result, this.independent.service_keys ? "independent" : "fetched over plain http", "independent");
    return resultLine(this.result, s.sources[0], s.sources[1], s.byService, scopeText(s.filter, s.generated));
  }

  get ok(): boolean {
    return this.checks.every((c) => c.status !== "fail");
  }

  get result(): "PASS" | "FAIL" {
    return this.ok ? "PASS" : "FAIL";
  }

  check(id: CheckId): Check {
    return this.checks.find((c) => c.id === id)!;
  }

  firstFailed(): CheckId | null {
    return this.checks.find((c) => c.status === "fail")?.id ?? null;
  }

  lines(): string[] {
    const out = [...this.notes];
    if (this.project && this.env) out.push(`signafAIde pack ${this.project} (${this.env}), ${plural(this.records, "record")}`);
    out.push(...this.warnings.map((w) => `WARNING: ${w}`));
    for (const c of this.checks) {
      const label = c.status === "fail" ? "FAIL" : c.status === "not_checked" ? "NOT CHECKED" : c.value?.startsWith("confirmed@") ? "CONFIRMED" : (c.value ?? "pass").toUpperCase();
      out.push(`${String(c.n).padStart(2)}. ${c.title.padEnd(28)} ${label.padEnd(12)} ${c.detail}`);
      out.push(...c.failures.slice(0, 20).map((f) => `      - ${f.item}: ${f.message}`));
      if (c.failures.length > 20) out.push(`      ... and ${c.failures.length - 20} more`);
    }
    out.push(...this.after);
    out.push(this.resultLine);
    return out;
  }

  toString(): string {
    return this.lines().join("\n");
  }

  toJSON(): object {
    return {
      result: this.result,
      result_line: this.resultLine,
      project: this.project,
      env: this.env,
      records: this.records,
      generated: this.scope?.generated ?? null,
      filter: this.scope?.filter ?? null,
      warnings: this.warnings,
      independent: this.independent,
      notes: this.notes,
      checks: this.checks,
      ...(this.after.length ? { not_yet: this.after } : {}),
    };
  }
}

/** Service keys from `{"keys": [...]}` (the well-known document) or a bare list. */
export function parseServiceKeys(doc: unknown): KeyDoc[] {
  const keys = Array.isArray(doc) ? doc : (doc as { keys?: unknown })?.keys;
  if (!Array.isArray(keys)) throw new Error('service keys must be {"keys": [...]} as served at /.well-known/signafaide-keys.json');
  for (const k of keys) {
    const errs = keyEntryErrors(k);
    if (errs.length) throw new Error("keys: " + errs.join("; "));
  }
  return keys;
}

/** The customer's agent-key manifest (§2.5); every entry's self-signature is checked. */
export function parseAgentKeys(doc: unknown): AgentKeyEntry[] {
  const errs = manifestErrors(doc);
  if (errs.length) throw new Error("agent keys: " + errs.join("; "));
  return (doc as { keys: AgentKeyEntry[] }).keys;
}

export interface SignedHeadDoc {
  head: { project: string; env: string; agent: string; seq: number; record_hash: string; server_time: string };
  head_sig: string;
}

/** The client's head file (§8 `head.json`) as a list of signed heads. */
export function parseHeadFile(doc: unknown): SignedHeadDoc[] {
  const obj = (v: unknown, what: string): Record<string, unknown> => {
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error(`head file: ${what} must be an object`);
    return v as Record<string, unknown>;
  };
  const out: SignedHeadDoc[] = [];
  for (const envs of Object.values(obj(doc, "the file")))
    for (const agents of Object.values(obj(envs, "each project")))
      for (const sh of Object.values(obj(agents, "each env"))) {
        const why = signedHeadError(sh);
        if (why) throw new Error(`head file: ${why}`);
        out.push(sh as SignedHeadDoc);
      }
  return out;
}

/** record_hash -> content from JSON lines, or a JSON array, of `{envelope, content}` (§7). */
export function contentFromText(text: string, into = new Map<string, Record<string, unknown>>()): Map<string, Record<string, unknown>> {
  let items: any[];
  try {
    const doc = parseJson(text);
    items = Array.isArray(doc) ? doc : [doc];
  } catch {
    items = text
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => parseJson(l));
  }
  for (const it of items) {
    if (it?.envelope && typeof it.envelope === "object" && it.content && typeof it.content === "object" && !Array.isArray(it.content) && !it.draft) {
      into.set(hashJson(it.envelope), it.content);
    }
  }
  return into;
}

/** The block heights the pack's public timestamps claim, to look up before verifying. */
export function timestampHeights(pack: any): number[] {
  const out = new Set<number>();
  for (const a of Array.isArray(pack?.anchors) ? pack.anchors : []) {
    try {
      for (const [h] of blockAttestations(base64Decode(a.anchor.ots))) out.add(h);
    } catch {
      /* reported by check 11 */
    }
  }
  return [...out].sort((x, y) => x - y);
}

export interface PackOptions {
  trustEmbeddedKeys?: boolean;
  /** The customer's agent-key manifest entries (`--agent-keys`, §2.5). */
  agentKeys?: AgentKeyEntry[] | { agent: string; key_id: string; public_key: string; valid_from: string }[] | null;
  trustEmbeddedAgentKeys?: boolean;
  /** The client's head file (`--head`). */
  heads?: SignedHeadDoc[] | null;
  /** Block headers looked up for the public timestamps; null/undefined: offline. */
  timestamps?: BlockRoots | null;
  /** record_hash -> content, e.g. from the local chain. */
  contents?: Map<string, Record<string, unknown>>;
  drand?: DrandVerifier | null;
  /** The service keys came over plain http from this machine (warned; not independent). */
  serviceKeysPlainHttp?: boolean;
  /** The agent keys came over plain http from this machine (warned; not independent). */
  agentKeysPlainHttp?: boolean;
  /** The service checks its own pack with its own key registry (never independent). */
  byService?: boolean;
}

/** `records_hash` (§7): sha256(JCS(list)) of every record's `receipt.record_hash`, in pack order. */
export function recordsHash(records: any[]): string {
  return hashJson(
    records.map((r) => {
      const h = r?.receipt?.record_hash;
      if (typeof h !== "string") throw new Error("a record has no receipt.record_hash");
      return h;
    }),
  );
}

/** The export statement the service signs (§7, domain `export`). */
export function exportStatement(pack: any): object {
  return { project: pack.project, env: pack.env, generated: pack.generated, filter: pack.filter, heads: pack.heads.map((sh: any) => sh.head), records_hash: recordsHash(pack.records) };
}

/** True for `http://localhost` and loopback addresses: the only hosts plain http is accepted from. */
export function isLoopbackUrl(url: string): boolean {
  if (!url.startsWith("http://")) return false;
  const authority = url.slice(7).split(/[/?#]/)[0];
  if (authority.includes("@")) return false;
  let host = authority.startsWith("[") ? authority.slice(1).split("]")[0] : authority.includes(":") ? authority.slice(0, authority.lastIndexOf(":")) : authority;
  host = host.toLowerCase();
  if (host === "localhost" || host === "::1" || /^0*:(0*:){0,6}0*1$/.test(host) || host === "0:0:0:0:0:0:0:1") return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return !!v4 && Number(v4[1]) === 127 && v4.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o);
}

/** Verify a pack. Throws `KeysRequired` when `serviceKeys` is null and embedded keys are not
 * trusted. Parse pack text with `parseJson` (not JSON.parse) so number literals are judged as written. */
export function verifyPack(pack: any, serviceKeys: KeyDoc[] | null, opts: PackOptions = {}): Report {
  const byService = !!opts.byService;
  let serviceSrc: KeySource = !serviceKeys ? "taken from the pack" : opts.serviceKeysPlainHttp ? "fetched over plain http" : "independent";
  let agentSrc: KeySource = !opts.agentKeys ? "taken from the pack" : opts.agentKeysPlainHttp ? "fetched over plain http" : "independent";
  if (byService) serviceSrc = agentSrc = "taken from the pack";
  const independent = { service_keys: serviceSrc === "independent", agent_keys: agentSrc === "independent" };
  const why = packError(pack);
  if (why) return malformed(why, independent);
  const warnings: string[] = [];
  if (!serviceKeys) {
    if (!opts.trustEmbeddedKeys || byService) throw new KeysRequired("service keys are required: pass --keys <file|url>, or --trust-embedded-keys to use the keys inside the pack");
    warnings.push("service keys were taken from the pack itself (--trust-embedded-keys); this does not prove the service signed it");
    serviceKeys = pack.service_keys as KeyDoc[];
  }
  for (const [src, what] of [[serviceSrc, "service"], [agentSrc, "agent"]] as const) {
    if (src === "fetched over plain http") warnings.push(`${what} keys were fetched over plain http, which anyone on the network path can alter: not independent`);
  }
  let agentKeys: KeyDoc[];
  let notIndependent = false;
  if (opts.agentKeys && !byService) {
    // A retirement or revocation can only narrow the window: the earlier of the customer's signed
    // retirement (§2.5) and the service's record (§7) wins.
    agentKeys = opts.agentKeys.map((e) => {
      const held = (pack.agent_keys as KeyDoc[]).find((k) => k.agent === e.agent && k.key_id === e.key_id && k.public_key === e.public_key);
      return { agent: e.agent, key_id: e.key_id, public_key: e.public_key, valid_from: e.valid_from, valid_to: earliest((e as AgentKeyEntry).valid_to ?? null, held?.valid_to ?? null) };
    });
  } else {
    if (byService) {
      /* the service's own registry: said in the result line */
    } else if (opts.trustEmbeddedAgentKeys) warnings.push("agent keys were taken from the pack itself (--trust-embedded-agent-keys); this does not prove the customer's agents signed it");
    else notIndependent = true;
    agentKeys = pack.agent_keys;
  }
  const v = new Verifier(serviceKeys, agentKeys, opts.contents ?? new Map(), pack.project, pack.env, false, {}, opts.drand ?? null, {
    filter: pack.filter,
    exportHeads: pack.heads,
    clientHeads: opts.heads ?? null,
    timestamps: opts.timestamps ?? null,
    notIndependent,
    generated: pack.generated,
    exportSig: pack.export_sig,
    pack,
  });
  return new Report(v.run(pack.records, pack.anchors), pack.project, pack.env, pack.records.length, warnings, [], independent, {
    generated: pack.generated,
    filter: pack.filter,
    sources: [serviceSrc, agentSrc],
    byService,
  });
}

function earliest(a: string | null, b: string | null): string | null {
  if (a === null || b === null) return a ?? b;
  return (ms(b) as number) < (ms(a) as number) ? b : a;
}

export interface LocalInput {
  records: any[];
  /** The chain id (`<project>/<env>/<agent>`) of each record. */
  chainIds: string[];
  agentKeys: KeyDoc[];
  /** Newest signed head per chain id. */
  heads: Record<string, { head: any; head_sig: string }>;
  /** Drafts waiting for the project (§8): not a reason for "no records". */
  drafts?: number;
}

/** Verify local state chain by chain. Unshipped records are fine; a chain must be
 * complete from seq 1 and reach the newest signed head. */
export function verifyLocalState(local: LocalInput, serviceKeys: KeyDoc[], drand: DrandVerifier | null = null, serviceKeysPlainHttp = false): Report {
  const v = new Verifier(serviceKeys, local.agentKeys, new Map(), null, null, true, local.heads, drand);
  v.drafts = local.drafts ?? 0;
  const checks = v.run(local.records, [], local.chainIds);
  return new Report(checks, null, null, local.records.length, [], [], { service_keys: !serviceKeysPlainHttp, agent_keys: true });
}

const isU64 = (x: unknown): boolean => typeof x === "number" && Number.isInteger(x) && x >= 0;
const isHex = (x: unknown): boolean => typeof x === "string" && HEX64.test(x);

function signedHeadError(sh: any): string {
  if (!exactKeys(sh, ["head", "head_sig"]) || typeof sh.head_sig !== "string") return "a signed head is {head, head_sig}";
  const h = sh.head;
  if (!exactKeys(h, ["project", "env", "agent", "seq", "record_hash", "server_time"])) return "head fields are agent, env, project, record_hash, seq, server_time";
  if (!(typeof h.project === "string" && (h.env === "test" || h.env === "live") && typeof h.agent === "string" && AGENT_RE.test(h.agent) && isU64(h.seq) && isHex(h.record_hash) && validTime(h.server_time))) {
    return "a head has an invalid value";
  }
  return "";
}

function packError(pack: any): string | null {
  if (!pack || typeof pack !== "object" || Array.isArray(pack)) return "the pack is not a JSON object";
  if (pack.format !== "signafaide-pack/1") return `format is '${pack.format}', expected 'signafaide-pack/1'`;
  const fields = ["format", "generated", "project", "env", "service_keys", "agent_keys", "filter", "heads", "records", "anchors", "export_sig"];
  for (const k of fields) if (!(k in pack)) return `missing field \`${k}\``;
  const extra = Object.keys(pack).filter((k) => !fields.includes(k)).sort();
  if (extra.length) return `unknown field \`${extra[0]}\``;
  for (const k of ["service_keys", "agent_keys", "heads", "records", "anchors"]) if (!Array.isArray(pack[k])) return `\`${k}\` must be a list`;
  if (typeof pack.export_sig !== "string") return "`export_sig` must be a string";
  if (pack.env !== "test" && pack.env !== "live") return "env must be test or live";
  if (!validProjectId(pack.project)) return "project is not a valid project id";
  if (!validTime(pack.generated)) return "generated is not a time";
  for (const k of pack.service_keys) {
    const e = keyEntryErrors(k);
    if (e.length) return e[0];
  }
  for (const k of pack.agent_keys) {
    const e = keyEntryErrors(k, true);
    if (e.length) return e[0];
  }
  const f = pack.filter;
  if (!exactKeys(f, ["agents", "from", "to"])) return "filter is {agents, from, to}";
  for (const n of ["from", "to"]) if (f[n] !== null && !validTime(f[n])) return `filter.${n} is not a time`;
  if (f.agents !== null && !(Array.isArray(f.agents) && f.agents.every((a: unknown) => typeof a === "string" && AGENT_RE.test(a)))) return "filter.agents holds an invalid agent name";
  for (const sh of pack.heads) if (signedHeadError(sh)) return "heads holds an invalid head";
  return null;
}

function malformed(why: string, independent: { service_keys: boolean; agent_keys: boolean }): Report {
  return new Report(
    CHECKS.map(([id, title], i) => ({
      n: i + 1,
      id,
      title,
      status: i === 0 ? "fail" : "not_checked",
      checked: 0,
      detail: i === 0 ? "the pack itself is malformed" : "pack unreadable",
      failures: i === 0 ? [{ item: "pack", message: why }] : [],
    })),
    null,
    null,
    0,
    [],
    [],
    independent,
  );
}

const ms = (s: unknown): number | null => (validTime(s) ? Date.parse(s as string) : null);
const fmt = (t: number): string => new Date(t).toISOString();

/** valid_from <= at < valid_to; a null bound is open. */
function active(key: KeyDoc, at: number | null): boolean {
  const s = ms(key.valid_from);
  const e = ms(key.valid_to);
  if (at === null || (key.valid_from != null && s === null) || (key.valid_to != null && e === null)) return false;
  return (s === null || s <= at) && (e === null || at < e);
}

/** `keys_hash` (§4): service keys with `valid_from <= created`, as `{key_id, public_key, valid_from}`,
 * ordered by `valid_from` then `key_id`. */
export function serviceKeysHash(keys: KeyDoc[], createdMs: number): string {
  const list = keys
    .filter((k) => ms(k.valid_from) !== null && (ms(k.valid_from) as number) <= createdMs)
    .map((k) => ({ key_id: k.key_id, public_key: k.public_key, valid_from: k.valid_from as string }))
    .sort((a, b) => (a.valid_from < b.valid_from ? -1 : a.valid_from > b.valid_from ? 1 : a.key_id < b.key_id ? -1 : a.key_id > b.key_id ? 1 : 0));
  return hashJson(list);
}

/** §3.1: why `serverMs` does not fit drand round `round`, or null. */
export function checkRoundTime(serverMs: number, round: number): string | null {
  if (!(round >= 1 && round <= MAX_ROUND)) return `drand round ${round} is out of range (1 to ${MAX_ROUND})`;
  const published = (QUICKNET_GENESIS + (round - 1) * 3) * 1000;
  if (serverMs < published) return `server_time ${fmt(serverMs)} is before drand round ${round} was published at ${fmt(published)}`;
  if (serverMs - published > MAX_ROUND_AGE_MS) return `drand round ${round} is ${Math.floor((serverMs - published) / 1000)} s older than server_time; at most ${MAX_ROUND_AGE_MS / 1000} s is allowed`;
  return null;
}

class Acc {
  checked = 0;
  failures: Failure[] = [];
  notes: string[] = [];
  notChecked = false;
  value?: string;
  fail(item: string, message: string): void {
    this.failures.push({ item, message });
  }
}

type Rec = { label: string; r: any; h: string };
type Ots = ["pending"] | ["confirmed", number] | ["unchecked", number, string];
interface PackExtras {
  filter: PackFilter;
  exportHeads: SignedHeadDoc[];
  clientHeads: SignedHeadDoc[] | null;
  timestamps: BlockRoots | null;
  notIndependent: boolean;
  generated?: string;
  exportSig?: string;
  pack?: any;
}

class Verifier {
  private acc = CHECKS.map(() => new Acc());
  private x: PackExtras;
  private recs: Rec[] = [];
  private generatedMs: number | null = null;
  private fromMs: number | null = null;
  private toMs: number | null = null;
  /** The earliest any key of each agent was valid: no record of that agent is older. */
  private firstKey = new Map<string, number>();
  drafts = 0;

  constructor(
    private serviceKeys: KeyDoc[],
    private agentKeys: KeyDoc[],
    private contents: Map<string, Record<string, unknown>>,
    private project: string | null,
    private env: string | null,
    private local: boolean,
    private localHeads: Record<string, { head: any; head_sig: string }>,
    private drandVerifier: DrandVerifier | null,
    extras?: PackExtras,
  ) {
    this.x = extras ?? { filter: { agents: null, from: null, to: null }, exportHeads: [], clientHeads: null, timestamps: null, notIndependent: false };
    this.generatedMs = this.x.generated ? ms(this.x.generated) : null;
    this.fromMs = this.x.filter.from !== null ? ms(this.x.filter.from) : null;
    this.toMs = this.x.filter.to !== null ? ms(this.x.filter.to) : null;
    for (const k of agentKeys) {
      const f = ms(k.valid_from);
      if (f !== null && typeof k.agent === "string") this.firstKey.set(k.agent, Math.min(this.firstKey.get(k.agent) ?? f, f));
    }
  }

  /** A chain may start after seq 1 only when the export's from is after the agent's first key. */
  private fromCuts(agent: string): boolean {
    const k = this.firstKey.get(agent);
    return this.fromMs !== null && k !== undefined && this.fromMs > k;
  }

  /** A head's record may be cut off by to only when it could be at or after to (its time is at
   * most 300 s after the head's server_time). */
  private toMayCut(h: any): boolean {
    const s = ms(h.server_time);
    return this.toMs !== null && (s === null || s + MAX_CLOCK_SKEW_MS >= this.toMs);
  }

  private serviceKey(kid: unknown, at: unknown): KeyDoc {
    const k = this.serviceKeys.find((k) => k.key_id === kid);
    if (!k) throw new Error(`unknown service key ${kid}`);
    if (!active(k, ms(at))) throw new Error(`service key ${kid} was not active at ${at}`);
    return k;
  }

  private anyKey(domain: "head" | "anchor" | "export", h: string, sig: string, at: unknown): boolean {
    const t = ms(at);
    return this.serviceKeys.some((k) => active(k, t) && verifySig(k.public_key, domain, h, sig));
  }

  private chainOf = new Map<any, string>();

  /** The chain a record belongs to: its agent in a pack, `<project>/<env>/<agent>` locally. */
  private chainId(r: any): string {
    return this.chainOf.get(r) ?? r.envelope.agent;
  }

  private headChain(head: any): string {
    return this.local ? `${head.project}/${head.env}/${head.agent}` : head.agent;
  }

  run(raw: any[], anchors: any[], chainIds?: string[]): Check[] {
    const a = this.acc;
    if (this.x.notIndependent) a[2].fail("agent keys", NOT_INDEPENDENT);
    if (!raw.length && !this.drafts) a[0].fail(this.local ? "local state" : "pack", this.local ? NO_LOCAL_RECORDS : NO_RECORDS);
    if (chainIds) raw.forEach((r, i) => this.chainOf.set(r, chainIds[i]));
    const recs = this.schema(raw);
    this.recs = recs;
    const shipped = recs.filter((x) => "receipt" in x.r);

    for (const { label, r, h } of shipped) {
      a[1].checked++;
      if (h !== r.receipt.record_hash) a[1].fail(label, `envelope hashes to ${h}, receipt says ${r.receipt.record_hash}`);
    }
    if (shipped.length < recs.length) a[1].notes.push(`${recs.length - shipped.length} not yet shipped (no receipt)`);

    for (const x of recs) {
      a[2].checked++;
      const err = this.clientSig(x);
      if (err) a[2].fail(x.label, err);
    }

    const chains = this.chains(recs);
    this.merkle(shipped);
    const batches = this.batchSigs(shipped);
    this.batchChain(batches);
    this.heads(shipped, chains);
    this.drand(batches);
    this.anchors(anchors, batches);
    this.content(recs);
    if (this.local && !shipped.length && recs.length) {
      // Local records no witness has co-signed yet: the checks of the witness's part are not passes.
      for (const i of [1, 4, 5, 6, 7]) {
        if (a[i].checked || a[i].failures.length) continue;
        a[i].notChecked = true;
        a[i].notes.push("nothing co-signed yet");
      }
    }

    return a.map((acc, i) => ({
      n: i + 1,
      id: CHECKS[i][0],
      title: CHECKS[i][1],
      status: acc.failures.length ? "fail" : acc.notChecked ? "not_checked" : "pass",
      checked: acc.checked,
      detail: plural(acc.checked, ...UNITS[i]) + acc.notes.map((n) => `; ${n}`).join(""),
      ...(acc.value !== undefined ? { value: acc.value } : {}),
      failures: acc.failures,
    }));
  }

  // 1
  private schema(raw: any[]): Rec[] {
    const out: Rec[] = [];
    raw.forEach((r, i) => {
      this.acc[0].checked++;
      // A local draft (§8): no project or env yet, signed over domain `draft`.
      const draft = this.local && !!r && typeof r === "object" && r.draft === true;
      let errs = draft ? draftErrors(r) : recordErrors(r);
      if (draft) {
        if (!errs.length && !this.chainId(r).startsWith("_pending/")) errs = [`a draft belongs in a pending chain, not ${this.chainId(r)}`];
      } else if (!errs.length && r && "receipt" in r) errs = receiptErrors(r.receipt).length ? receiptErrors(r.receipt) : this.consistent(r);
      else if (!errs.length && !this.local) errs = ["missing receipt"];
      else if (!errs.length) errs = this.envelopeBucket(r);
      if (errs.length) return this.acc[0].fail(`record[${i}]`, errs.join("; "));
      out.push({ label: `${this.chainId(r)}#${r.envelope.seq}`, r, h: hashJson(r.envelope) });
    });
    return out;
  }

  /** Locally, a record's envelope names the project and env of its chain. */
  private envelopeBucket(r: any): string[] {
    const e = r.envelope;
    const bucket = this.chainId(r).split("/").slice(0, 2).join("/");
    if (this.local && !bucket.startsWith("_pending/") && bucket !== `${e.project}/${e.env}`) return [`envelope is for ${e.project}/${e.env}, but the record is in chain ${this.chainId(r)}`];
    return [];
  }

  private consistent(r: any): string[] {
    const e = r.envelope;
    const { batch: b, head: h } = r.receipt;
    if (!this.local && (e.project !== this.project || e.env !== this.env)) return ["envelope belongs to another project or env"];
    if (!this.local && (b.project !== this.project || b.env !== this.env)) return ["receipt batch belongs to another project or env"];
    if (this.local && (e.project !== b.project || e.env !== b.env)) return ["envelope and receipt batch name different projects or envs"];
    const errs = this.envelopeBucket(r);
    if (errs.length) return errs;
    if (h.project !== b.project || h.env !== b.env || h.agent !== e.agent) return ["receipt head belongs to another project, env or agent"];
    return [];
  }

  private clientSig({ r, h }: Rec): string | null {
    const env = r.envelope;
    const k = this.agentKeys.find((k) => k.agent === env.agent && k.key_id === r.key_id);
    if (!k) return `no key ${r.key_id} for agent ${env.agent} in the agent keys`;
    try {
      if (keyId(b64urlDecode(k.public_key)) !== k.key_id) return "agent key_id does not match its public key";
    } catch {
      return "agent public key is not base64url";
    }
    if (!active(k, ms(env.time))) return `key ${k.key_id} was not active at ${env.time}`;
    if (k.valid_to != null && "receipt" in r) {
      const server = r.receipt.batch.server_time;
      if ((ms(server) as number) >= (ms(k.valid_to) as number)) return `key ${k.key_id} was revoked at ${k.valid_to}, before the service received this record at ${server}`;
    }
    if (!verifySig(k.public_key, r.draft === true && this.local ? "draft" : "record", h, r.sig)) return "signature does not verify";
    return null;
  }

  // 4
  private chains(recs: Rec[]): Map<string, Map<number, Rec>> {
    const acc = this.acc[3];
    const chains = new Map<string, Map<number, Rec>>();
    for (const x of recs) {
      const id = this.chainId(x.r);
      const chain = chains.get(id) ?? new Map<number, Rec>();
      chains.set(id, chain);
      const seq = x.r.envelope.seq;
      const held = chain.get(seq);
      if (held && held.h !== x.h) {
        acc.fail(x.label, "two different records with the same seq (fork)");
        continue;
      }
      if (!held) chain.set(seq, x);
    }
    let edge = 0;
    for (const agent of [...chains.keys()].sort()) {
      const chain = chains.get(agent)!;
      acc.checked += chain.size;
      let prev: Rec | null = null;
      for (const seq of [...chain.keys()].sort((x, y) => x - y)) {
        const x = chain.get(seq)!;
        const e = x.r.envelope;
        if (prev && prev.r.envelope.seq + 1 === seq) {
          if (e.prev !== prev.h) acc.fail(x.label, `prev does not equal the record_hash of seq ${seq - 1}`);
          if ((ms(e.time) as number) < (ms(prev.r.envelope.time) as number)) acc.fail(x.label, `time ${e.time} is earlier than the time of seq ${seq - 1} (${prev.r.envelope.time})`);
        } else if (prev) {
          const a = prev.r.envelope.seq + 1;
          acc.fail(x.label, this.local ? `the local chain is missing seq ${a}..${seq - 1}` : `the pack is missing seq ${a}..${seq - 1} of agent ${agent} (a gap inside the chain)`);
        } else if (seq > 1) {
          if (this.local) acc.fail(x.label, `the local chain is missing seq 1..${seq - 1}`);
          else if (this.fromCuts(agent)) edge++;
          else if (this.x.filter.from !== null) acc.fail(x.label, `the pack is missing seq 1..${seq - 1} of agent ${agent}; its export's from filter is not after the agent's first key, so they belong in it`);
          else acc.fail(x.label, `the pack is missing seq 1..${seq - 1} of agent ${agent} and its export declares no from filter`);
        }
        if ("receipt" in x.r) {
          const server = x.r.receipt.batch.server_time;
          if ((ms(e.time) as number) > (ms(server) as number) + MAX_CLOCK_SKEW_MS) acc.fail(x.label, `time ${e.time} is more than 300 s after its batch's server_time ${server}`);
        }
        prev = x;
      }
    }
    if (edge) acc.notes.push(`${plural(edge, "chain")} start after seq 1, as the export's from filter allows`);
    return chains;
  }

  // 5
  private merkle(shipped: Rec[]): void {
    for (const { label, r, h } of shipped) {
      this.acc[4].checked++;
      const rc = r.receipt;
      if (!verifyInclusion(h, rc.index, rc.batch.size, rc.proof, rc.batch.root)) this.acc[4].fail(label, `proof does not lead to the root of batch ${rc.batch.seq}`);
    }
  }

  // 6
  private batchSigs(shipped: Rec[]): Map<string, any> {
    const acc = this.acc[5];
    const batches = new Map<string, any>(); // "<seq>\n<hash>" -> receipt
    const seen = new Set<string>();
    for (const { r } of shipped) {
      const rc = r.receipt;
      const computed = hashJson(rc.batch);
      const key = [computed, rc.batch_hash, rc.batch_sig, rc.service_key_id].join("\n");
      if (seen.has(key)) continue;
      seen.add(key);
      acc.checked++;
      const item = `batch ${rc.batch.seq}`;
      if (computed !== rc.batch_hash) acc.fail(item, `batch hashes to ${computed}, receipt says ${rc.batch_hash}`);
      try {
        const k = this.serviceKey(rc.service_key_id, rc.batch.server_time);
        if (!verifySig(k.public_key, "batch", computed, rc.batch_sig)) throw new Error("signature does not verify");
      } catch (e) {
        acc.fail(item, `batch_sig: ${(e as Error).message}`);
      }
      batches.set(`${String(rc.batch.seq).padStart(16, "0")}\n${computed}`, rc);
    }
    return batches;
  }

  // 7
  private batchChain(batches: Map<string, any>): void {
    const acc = this.acc[6];
    const bySeq = new Map<string, { h: string; b: any }>();
    for (const key of [...batches.keys()].sort()) {
      acc.checked++;
      const rc = batches.get(key);
      const b = rc.batch;
      const h = key.split("\n")[1];
      const id = `${b.project}\n${b.env}\n${String(b.seq).padStart(16, "0")}`;
      const held = bySeq.get(id);
      if (held) {
        if (held.h !== h) acc.fail(`batch ${b.seq}`, "two different batches with the same seq (fork)");
        continue;
      }
      bySeq.set(id, { h, b });
    }
    let gaps = 0;
    let prev: { chain: string; seq: number; h: string; b: any } | null = null;
    for (const id of [...bySeq.keys()].sort()) {
      const { h, b } = bySeq.get(id)!;
      const chain = `${b.project}\n${b.env}`;
      if ((b.seq === 1) !== (b.prev === null)) acc.fail(`batch ${b.seq}`, "prev must be null exactly when seq is 1");
      if (prev && prev.chain === chain) {
        if (prev.seq + 1 === b.seq && b.prev !== prev.h) acc.fail(`batch ${b.seq}`, `prev does not equal the batch_hash of batch ${prev.seq}`);
        else if (prev.seq + 1 !== b.seq) gaps++;
        if ((ms(b.server_time) as number) < (ms(prev.b.server_time) as number)) {
          acc.fail(`batch ${b.seq}`, `server_time ${b.server_time} is earlier than the server_time of batch ${prev.seq} (${prev.b.server_time})`);
        }
      }
      prev = { chain, seq: b.seq, h, b };
    }
    if (gaps) acc.notes.push(`${plural(gaps, "gap")} between batches held in the pack`);
  }

  // 8
  private heads(shipped: Rec[], chains: Map<string, Map<number, Rec>>): void {
    const acc = this.acc[7];
    const seen = new Set<string>();
    const held = (chain: string, seq: number): string | undefined => chains.get(chain)?.get(seq)?.h;
    const lastHeld = (chain: string): number => Math.max(0, ...(chains.get(chain)?.keys() ?? []));
    for (const { r } of shipped) {
      const rc = r.receipt;
      const item = `head ${rc.head.agent}#${rc.head.seq}`;
      const hh = hashJson(rc.head);
      if (!seen.has(`${hh}\n${rc.head_sig}`)) {
        seen.add(`${hh}\n${rc.head_sig}`);
        try {
          const k = this.serviceKey(rc.service_key_id, rc.head.server_time);
          if (!verifySig(k.public_key, "head", hh, rc.head_sig)) throw new Error("signature does not verify");
        } catch (e) {
          acc.fail(item, `head_sig: ${(e as Error).message}`);
        }
        const x = held(this.headChain(rc.head), rc.head.seq);
        if (x && x !== rc.head.record_hash) acc.fail(item, "head names a different record than the pack holds at that seq");
      }
      if (rc.head.seq < r.envelope.seq) acc.fail(item, `head is older than record seq ${r.envelope.seq} it was issued with`);
    }
    let inFilter = (_a: string): boolean => true;
    if (!this.local) {
      try {
        const sh = hashJson(exportStatement(this.x.pack));
        if (!this.anyKey("export", sh, this.x.exportSig ?? "", this.x.generated)) {
          acc.fail("export statement", "export_sig does not verify with any service key active at generated: the pack's filter, heads, generated time or records were changed after the service signed it");
        }
      } catch (e) {
        acc.fail("export statement", (e as Error).message);
      }
      const agents = this.x.filter.agents;
      inFilter = (a: string): boolean => agents === null || agents.includes(a);
      for (const { label, r } of this.recs) {
        const e = r.envelope;
        const t = ms(e.time) as number;
        if (!inFilter(e.agent)) acc.fail(label, "the record's agent is not in the export's filter");
        else if (this.fromMs !== null && t < this.fromMs) acc.fail(label, `time ${e.time} is before the export's from filter`);
        else if (this.toMs !== null && t >= this.toMs) acc.fail(label, `time ${e.time} is not before the export's to filter`);
      }
    }
    const exp = new Map<string, any>();
    for (const sh of this.x.exportHeads) {
      const h = sh.head;
      const item = `export head ${h.agent}#${h.seq}`;
      if (h.project !== this.project || h.env !== this.env) {
        acc.fail(item, "the export head belongs to another project or env");
        continue;
      }
      const hh = hashJson(h);
      if (!seen.has(`${hh}\n${sh.head_sig}`)) {
        seen.add(`${hh}\n${sh.head_sig}`);
        if (!this.anyKey("head", hh, sh.head_sig, h.server_time)) acc.fail(item, "head_sig does not verify with any service key active at its server_time");
      }
      const sMs = ms(h.server_time);
      if (sMs === null || this.generatedMs === null || sMs > this.generatedMs) acc.fail(item, `the export head's server_time ${h.server_time} is after the pack was generated (${this.x.generated})`);
      if (!inFilter(h.agent)) acc.fail(item, "the export head is for an agent outside the export's filter");
      const x = held(h.agent, h.seq);
      if (x && x !== h.record_hash) acc.fail(item, "the export head names a different record than the pack holds at that seq");
      if (exp.has(h.agent)) acc.fail(item, "two export heads for the same agent");
      else exp.set(h.agent, h);
    }
    if (!this.local) {
      for (const agent of [...chains.keys()].sort()) {
        const have = lastHeld(agent);
        const h = exp.get(agent);
        if (!h) acc.fail(`agent ${agent}`, "the pack has no export head for this agent, so records cut off at the end cannot be detected");
        else if (have > h.seq) acc.fail(`export head ${agent}#${h.seq}`, `the pack holds seq ${have}, beyond the export head seq ${h.seq}`);
        else if (have < h.seq && !this.toMayCut(h)) acc.fail(`export head ${agent}#${h.seq}`, `the pack ends at seq ${have} but the service's head at export was seq ${h.seq} (records missing at the end)`);
      }
      for (const agent of [...exp.keys()].sort()) if (!chains.has(agent)) acc.fail(`export head ${agent}#${exp.get(agent).seq}`, "the pack holds none of this agent's records, but the export names its head");
    }
    let newer = 0;
    for (const sh of this.x.clientHeads ?? []) {
      const h = sh.head;
      if (h.project !== this.project || h.env !== this.env) continue;
      if (!inFilter(h.agent)) continue;
      const item = `head file ${h.agent}#${h.seq}`;
      const hh = hashJson(h);
      if (!seen.has(`${hh}\n${sh.head_sig}`)) {
        seen.add(`${hh}\n${sh.head_sig}`);
        if (!this.anyKey("head", hh, sh.head_sig, h.server_time)) acc.fail(item, "head_sig does not verify with any service key active at its server_time");
      }
      const x = held(h.agent, h.seq);
      if (x && x !== h.record_hash) acc.fail(item, "the client's head names a different record than the pack holds at that seq");
      const sMs = ms(h.server_time);
      if (sMs === null || this.generatedMs === null || sMs > this.generatedMs) {
        newer++;
        continue;
      }
      const have = lastHeld(h.agent);
      // Records must reach the client's head when the agent has records in the pack (time never goes
      // back along a chain), or when the window holds all its records.
      const applies = (have > 0 || !this.fromCuts(h.agent)) && !this.toMayCut(h);
      if (applies && have < h.seq) acc.fail(item, `the client's head is seq ${h.seq} but the pack ends at seq ${have} (records missing at the end)`);
    }
    if (newer) acc.notes.push(`${plural(newer, "client head")} newer than the export, not applied`);
    for (const id of Object.keys(this.localHeads).sort()) {
      const sh = this.localHeads[id] ?? ({} as any);
      const head = sh.head ?? {};
      const item = `head.json ${id}#${head.seq}`;
      const hh = hashJson(head);
      const sig = sh.head_sig ?? "";
      if (!seen.has(`${hh}\n${sig}`)) {
        seen.add(`${hh}\n${sig}`);
        if (!this.anyKey("head", hh, sig, head.server_time)) acc.fail(item, "head_sig: signature does not verify");
        const x = held(id, head.seq);
        if (x && x !== head.record_hash) acc.fail(item, "head names a different record than the pack holds at that seq");
      }
      const have = lastHeld(id);
      if (have < (head.seq ?? 0)) acc.fail(item, `the service holds seq ${head.seq} but the local chain ends at seq ${have} (truncated)`);
    }
    acc.checked = seen.size;
  }

  // 9
  private drand(batches: Map<string, any>): void {
    const acc = this.acc[8];
    let nulls = 0;
    const rounds = new Set<string>();
    for (const rc of batches.values()) {
      const d = rc.batch.drand as DrandBeacon | null;
      if (d === null) {
        nulls++;
        continue;
      }
      const item = `batch ${rc.batch.seq} round ${d.round}`;
      const why = checkRoundTime(ms(rc.batch.server_time) ?? 0, d.round);
      if (why) acc.fail(item, why);
      if (rounds.has(`${d.round}\n${d.signature}`)) continue;
      rounds.add(`${d.round}\n${d.signature}`);
      if (d.chain !== QUICKNET_CHAIN) acc.fail(item, `unknown drand chain ${d.chain}`);
      else if (!/^([0-9a-f]{2})+$/.test(d.signature)) acc.fail(item, "signature is not hex");
      else if (this.drandVerifier && !this.drandVerifier(d)) acc.fail(item, `BLS signature does not verify for round ${d.round}`);
      else if (sha256Hex(hexToBytes(d.signature)) !== d.randomness) acc.fail(item, "randomness is not sha256(signature)");
    }
    acc.checked = rounds.size;
    if (nulls) acc.notes.push(`${plural(nulls, "batch", "batches")} without a drand round (beacon unreachable when written)`);
    if (!rounds.size || !this.drandVerifier) {
      acc.notChecked = true;
      if (rounds.size) acc.notes.push(DRAND_NOT_CHECKED.split(": ")[1]);
    }
  }

  // 10, 11
  private anchors(anchors: any[], batches: Map<string, any>): void {
    const [a10, a11] = [this.acc[9], this.acc[10]];
    const batchTimes = new Map<string, [number, string]>();
    for (const [k, rc] of batches) batchTimes.set(k.split("\n")[1], [rc.batch.seq, rc.batch.server_time]);
    const anchored = new Set<string>();
    const bySeq = new Map<number, { ah: string; a: any }>();
    const proofs: Ots[] = [];
    anchors.forEach((entry, i) => {
      a10.checked++;
      const errs = anchorError(entry);
      if (errs) return a10.fail(`anchors[${i}]`, errs);
      const a = entry.anchor;
      const item = `anchor ${a.seq}`;
      const { ots: _o, status: _s, bitcoin_block: _b, ...core } = a;
      const ah = hashJson(core);
      const created = ms(a.created) as number;
      if (!this.anyKey("anchor", ah, entry.anchor_sig, a.created)) a10.fail(item, "anchor_sig does not verify with any service key active at its creation");
      if (serviceKeysHash(this.serviceKeys, created) !== a.keys_hash) a10.fail(item, "keys_hash does not match the service keys supplied: the key list was changed after this anchor was signed");
      for (const [bh, p] of Object.entries<any>(entry.paths)) {
        if (verifyInclusion(bh, p.index, a.size, p.path, a.root)) {
          anchored.add(bh);
          const bt = batchTimes.get(bh);
          if (bt && created < (ms(bt[1]) as number)) a10.fail(item, `created ${a.created} is before the server_time of batch ${bt[0]} (${bt[1]}) it covers`);
        } else a10.fail(item, `path for batch ${bh} does not lead to the anchor root`);
      }
      const held = bySeq.get(a.seq);
      if (held) {
        if (held.ah !== ah) a10.fail(item, "two different signed anchors with the same seq");
      } else bySeq.set(a.seq, { ah, a });
      a11.checked++;
      try {
        proofs.push(otsCheck(a, ah, this.x.timestamps));
      } catch (e) {
        a11.fail(item, (e as Error).message);
      }
    });
    let prev: { seq: number; ah: string } | null = null;
    for (const seq of [...bySeq.keys()].sort((x, y) => x - y)) {
      const { ah, a } = bySeq.get(seq)!;
      if (prev && prev.seq + 1 === seq && a.prev !== prev.ah) a10.fail(`anchor ${seq}`, `prev does not equal the anchor_hash of anchor ${prev.seq}`);
      prev = { seq, ah };
    }
    let stale = 0;
    let young = 0;
    for (const [k, rc] of batches) {
      if (anchored.has(k.split("\n")[1])) continue;
      const t = ms(rc.batch.server_time);
      if (!this.local && (t === null || this.generatedMs === null || t + ANCHOR_WINDOW_MS < this.generatedMs)) stale++;
      else young++;
    }
    if (stale) {
      a10.notChecked = true;
      a10.notes.push(`${plural(stale, "batch", "batches")} not timestamped: older than the 2-hour anchor window, and no anchor in the pack covers them`);
    }
    if (!anchors.length && !stale) {
      a10.notChecked = true;
      a10.notes.push(this.local ? "local state holds no anchors" : "no anchors in the pack yet (an anchor is made every hour)");
    } else if (young) a10.notes.push(`${plural(young, "batch", "batches")} not yet anchored`);
    const unchecked = proofs.filter((p): p is ["unchecked", number, string] => p[0] === "unchecked");
    if (!proofs.length) a11.notChecked = true;
    else if (unchecked.length) {
      a11.notChecked = true;
      a11.notes.push(`public timestamp not checked (${unchecked[0][2]}); claims block ${unchecked.map((p) => p[1]).join(", ")}`);
    } else if (proofs.every((p) => p[0] === "confirmed")) {
      const h = Math.max(...proofs.map((p) => p[1] as number));
      a11.value = `confirmed@${h}`;
      a11.notes.push(`each public timestamp checked against its public record (block ${h})`);
    } else {
      a11.value = "pending";
      a11.notes.push(`waiting for the public timestamp to confirm (usually within a few hours): ${proofs.filter((p) => p[0] === "pending").length} of ${proofs.length}`);
    }
  }

  // 12
  private content(recs: Rec[]): void {
    const acc = this.acc[11];
    for (const { label, r, h } of recs) {
      const c = r.content && typeof r.content === "object" && !Array.isArray(r.content) ? r.content : this.contents.get(h);
      if (c === undefined) continue;
      acc.checked++;
      let ch: string;
      try {
        ch = hashJson(c);
      } catch (e) {
        acc.fail(label, (e as Error).message);
        continue;
      }
      if (ch !== r.envelope.content_hash) acc.fail(label, `content hashes to ${ch}, envelope says ${r.envelope.content_hash}`);
    }
    if (!acc.checked) {
      acc.notChecked = true;
      acc.notes.push("no content supplied (hash-only records)");
    }
  }
}

const exactKeys = (o: unknown, keys: string[]): o is Record<string, any> =>
  !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => k in (o as object));

function anchorError(entry: any): string {
  if (!exactKeys(entry, ["anchor", "anchor_sig", "paths"])) return "an anchor entry has exactly anchor, anchor_sig and paths";
  const a = entry.anchor;
  if (!exactKeys(a, ["v", "seq", "prev", "root", "size", "created", "keys_hash", "ots", "status", "bitcoin_block"])) {
    return "anchor fields are v, seq, prev, root, size, created, keys_hash, ots, status, bitcoin_block";
  }
  if (a.v !== 1 || !isU64(a.seq) || !isU64(a.size) || !validTime(a.created)) return "anchor v, seq, size or created is invalid";
  if (!(isHex(a.root) && isHex(a.keys_hash) && (a.prev === null || isHex(a.prev)))) return "anchor root, keys_hash or prev is not a hash";
  if (typeof a.ots !== "string" || typeof entry.anchor_sig !== "string" || !(a.bitcoin_block === null || isU64(a.bitcoin_block))) return "anchor ots, anchor_sig or bitcoin_block is invalid";
  if ((a.status !== "pending" && a.status !== "confirmed") || !entry.paths || typeof entry.paths !== "object" || Array.isArray(entry.paths)) return "anchor status or paths is invalid";
  if (!Object.entries(entry.paths).every(([k, p]: [string, any]) => isHex(k) && exactKeys(p, ["index", "path"]) && isU64(p.index) && Array.isArray(p.path) && p.path.every(isHex))) {
    return 'each anchor path is {"index": n, "path": [...]}';
  }
  return "";
}

function otsCheck(a: any, anchorHash: string, headers: BlockRoots | null): Ots {
  const data = base64Decode(a.ots);
  const { digest, height } = otsStatus(data);
  if (digest !== anchorHash) throw new Error("OTS proof is for a different digest than the anchor hash");
  if (a.status === "confirmed" && height === null) throw new Error("anchor says confirmed but the proof is still pending");
  if (a.status === "confirmed" && a.bitcoin_block !== null && height !== a.bitcoin_block) throw new Error(`anchor says block ${a.bitcoin_block} but the proof attests block ${height}`);
  if (height === null) return ["pending"];
  const attested = blockAttestations(data);
  if (!headers) return ["unchecked", height, "offline"];
  // A header is trusted only when it hashes to its block and meets its own proof of work.
  const roots = new Map<number, [boolean, string]>();
  for (const [h, got] of headers) {
    if (!got[0]) roots.set(h, [false, got[1]]);
    else
      try {
        roots.set(h, [true, checkHeader(got[1].hash, got[1].header)]);
      } catch (e) {
        roots.set(h, [false, (e as Error).message]);
      }
  }
  for (const [h, msg] of attested) {
    const r = roots.get(h);
    if (r && r[0] && r[1] !== msg) throw new Error(`the timestamp claims block ${h}, but its Merkle root does not match that block's header`);
  }
  for (const [h] of attested) {
    const r = roots.get(h);
    if (!r) return ["unchecked", height, `block ${h} was not looked up`];
    if (!r[0]) return ["unchecked", height, r[1]];
  }
  return ["confirmed", height];
}

/** A drand quicknet verifier from `@noble/curves`, or null when that dependency is missing
 * (a pruned install); the drand check then says `DRAND_NOT_CHECKED`. */
export async function loadDrandVerifier(): Promise<DrandVerifier | null> {
  let bls: any;
  try {
    bls = (await import("@noble/curves/bls12-381")).bls12_381;
  } catch {
    return null;
  }
  const { sha256 } = await import("@noble/hashes/sha2");
  const DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
  return (d) => {
    try {
      const msg = new Uint8Array(8);
      new DataView(msg.buffer).setBigUint64(0, BigInt(d.round));
      return bls.shortSignatures.verify(d.signature, bls.shortSignatures.hash(sha256(msg), DST), QUICKNET_PUBLIC_KEY);
    } catch {
      return false;
    }
  };
}
