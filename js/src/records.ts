/** Envelopes and signed records (SPEC §2). */

import { HEX64, SALT_RE, b64url, b64urlDecode, contentHash, hashJson, keyId, newSalt, verifySig, type SigningKey } from "./crypto.js";
import { assertPortableNumbers } from "./jcs.js";

export type Kind = "decision" | "outcome" | "note";
export const KINDS: readonly Kind[] = ["decision", "outcome", "note"];
export const ENVELOPE_FIELDS = ["v", "kind", "project", "env", "agent", "seq", "prev", "time", "name", "content_hash", "ref"] as const;
/** A draft (§8) is an envelope without project and env, written before the project is known. */
export const DRAFT_FIELDS = ["v", "kind", "agent", "seq", "prev", "time", "name", "content_hash", "ref"] as const;
export const API_KEY_RE = /^sfa_(test|live)_[0-9A-Za-z]{32}$/;
export const AGENT_KEYS_FORMAT = "signafaide-agent-keys/1";
/** A record's time may be at most this far after its batch's server_time (§2.2). */
export const MAX_CLOCK_SKEW_MS = 300_000;
export const AGENT_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const KEY_ID_RE = /^[0-9a-f]{16}$/;
const PROJECT_RE = /^prj_[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const sameKeys = (o: unknown, keys: string[]): o is Record<string, any> =>
  !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => k in (o as object));
const RECEIPT_FIELDS = ["record_hash", "index", "proof", "batch", "batch_hash", "batch_sig", "service_key_id", "head", "head_sig"];
const BATCH_FIELDS = ["v", "project", "env", "seq", "prev", "root", "size", "server_time", "drand"];
const HEAD_FIELDS = ["project", "env", "agent", "seq", "record_hash", "server_time"];
const DRAND_FIELDS = ["chain", "round", "randomness", "signature"];

export interface Envelope {
  v: 1;
  kind: Kind;
  project: string;
  env: "test" | "live";
  agent: string;
  seq: number;
  prev: string | null;
  time: string;
  name: string;
  content_hash: string;
  ref: string | null;
}

export interface SignedRecord {
  envelope: Envelope;
  key_id: string;
  sig: string;
  /** A draft (§8): the envelope has no project and env yet; `sig` is over domain `draft`. */
  draft?: true;
  store_content?: boolean;
  content?: Record<string, unknown>;
  /** The content's salt (§2.1): kept with the content, sent only with stored content. */
  salt?: string;
  receipt?: Receipt;
}

export interface Receipt {
  record_hash: string;
  index: number;
  proof: string[];
  batch: Record<string, any>;
  batch_hash: string;
  batch_sig: string;
  service_key_id: string;
  head: Record<string, any>;
  head_sig: string;
}

/** Current time as RFC 3339 UTC with milliseconds. */
export function now(): string {
  return new Date().toISOString();
}

export function validTime(s: unknown): boolean {
  // Years 0001 to 9999 (§1): Date accepts year 0000, the protocol does not.
  return typeof s === "string" && TIME_RE.test(s) && !s.startsWith("0000") && !Number.isNaN(Date.parse(s)) && new Date(s).toISOString() === s;
}

/** Turn a folder or free-form name into a valid agent id. */
export function agentName(raw: string): string {
  const s = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .slice(0, 64)
    .replace(/-+$/, "");
  return s || "agent";
}

const isInt = (x: unknown): x is number => typeof x === "number" && Number.isInteger(x);
const isHex = (x: unknown): boolean => typeof x === "string" && HEX64.test(x);

/** `prj_` + a 26-character ULID in Crockford base32. */
export function validProjectId(s: unknown): boolean {
  return typeof s === "string" && PROJECT_RE.test(s);
}

/** Schema problems with a receipt (§3.4): exact fields and types; signatures are only
 * checked to be strings (their validity is checks 6 and 8). */
export function receiptErrors(rc: unknown): string[] {
  if (!sameKeys(rc, RECEIPT_FIELDS)) return ["receipt fields are " + [...RECEIPT_FIELDS].sort().join(", ")];
  const errs: string[] = [];
  const { batch: b, head: h } = rc;
  if (!(isHex(rc.record_hash) && isHex(rc.batch_hash) && isInt(rc.index) && rc.index >= 0)) errs.push("receipt record_hash, batch_hash or index is invalid");
  if (!(Array.isArray(rc.proof) && rc.proof.every(isHex))) errs.push("receipt proof must be a list of hashes");
  if (!["batch_sig", "head_sig", "service_key_id"].every((k) => typeof rc[k] === "string")) errs.push("receipt batch_sig, head_sig and service_key_id are strings");
  if (!sameKeys(b, BATCH_FIELDS)) errs.push("batch fields are " + [...BATCH_FIELDS].sort().join(", "));
  else if (
    !(
      b.v === 1 &&
      validProjectId(b.project) &&
      (b.env === "test" || b.env === "live") &&
      isInt(b.seq) &&
      b.seq >= 1 &&
      (b.prev === null || isHex(b.prev)) &&
      isHex(b.root) &&
      isInt(b.size) &&
      b.size >= 1 &&
      validTime(b.server_time)
    )
  )
    errs.push("batch has an invalid value");
  else if (
    b.drand !== null &&
    !(sameKeys(b.drand, DRAND_FIELDS) && isInt(b.drand.round) && ["chain", "randomness", "signature"].every((k) => typeof b.drand[k] === "string"))
  )
    errs.push("batch drand must be null or {chain, round, randomness, signature}");
  if (!sameKeys(h, HEAD_FIELDS)) errs.push("head fields are " + [...HEAD_FIELDS].sort().join(", "));
  else if (
    !(validProjectId(h.project) && (h.env === "test" || h.env === "live") && typeof h.agent === "string" && AGENT_RE.test(h.agent) && isInt(h.seq) && isHex(h.record_hash) && validTime(h.server_time))
  )
    errs.push("head has an invalid value");
  return errs;
}

/** Schema problems with an envelope; empty when valid (§2.2). */
export function envelopeErrors(env: unknown, fields: readonly string[] = ENVELOPE_FIELDS): string[] {
  if (!env || typeof env !== "object" || Array.isArray(env)) return ["envelope is not an object"];
  const e = env as Record<string, unknown>;
  const errs: string[] = [];
  const missing = fields.filter((f) => !(f in e));
  const extra = Object.keys(e)
    .filter((k) => !fields.includes(k))
    .sort();
  if (missing.length) errs.push("missing " + missing.join(", "));
  if (extra.length) errs.push("unknown field " + extra.join(", "));
  if (missing.length) return errs;
  if (e.v !== 1) errs.push("v must be 1");
  if (!KINDS.includes(e.kind as Kind)) errs.push("kind must be decision, outcome or note");
  if (fields.includes("project") && !validProjectId(e.project)) errs.push("project must be prj_ followed by a 26-character ULID");
  if (fields.includes("env") && e.env !== "test" && e.env !== "live") errs.push("env must be test or live");
  if (typeof e.agent !== "string" || !AGENT_RE.test(e.agent)) errs.push("agent does not match ^[a-z0-9][a-z0-9._-]{0,63}$");
  if (!isInt(e.seq) || e.seq < 1 || e.seq > Number.MAX_SAFE_INTEGER) errs.push("seq must be an integer from 1 to 2^53-1");
  else if (e.seq === 1 && e.prev !== null) errs.push("prev must be null when seq = 1");
  else if (e.seq > 1 && !(typeof e.prev === "string" && HEX64.test(e.prev))) errs.push("prev must be a record hash when seq > 1");
  if (!validTime(e.time)) errs.push(`time ${JSON.stringify(e.time)} is not RFC 3339 UTC with milliseconds`);
  const nameLen = typeof e.name === "string" ? [...e.name].length : 0;
  if (nameLen < 1 || nameLen > 128) errs.push("name must be 1 to 128 characters");
  if (typeof e.content_hash !== "string" || !HEX64.test(e.content_hash)) errs.push("content_hash must be 64 lowercase hex");
  if (e.kind === "outcome") {
    if (!(typeof e.ref === "string" && HEX64.test(e.ref))) errs.push("ref must be the decision's record hash for an outcome");
  } else if (e.ref !== null) errs.push("ref must be null unless kind is outcome");
  return errs;
}

/** Schema problems with a signed record (§2.3); `receipt` is allowed. */
export function recordErrors(rec: unknown): string[] {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return ["record is not an object"];
  const r = rec as Record<string, unknown>;
  const errs = envelopeErrors(r.envelope);
  const extra = Object.keys(r)
    .filter((k) => !["envelope", "key_id", "sig", "content", "salt", "receipt"].includes(k))
    .sort();
  if (extra.length) errs.push("unknown record field " + extra.join(", "));
  if (typeof r.key_id !== "string" || !KEY_ID_RE.test(r.key_id)) errs.push("key_id must be 16 lowercase hex");
  let sigOk = false;
  try {
    sigOk = b64urlDecode(r.sig as string).length === 64;
  } catch {
    sigOk = false;
  }
  if (!sigOk) errs.push("sig must be a base64url Ed25519 signature");
  if ("content" in r && (!r.content || typeof r.content !== "object" || Array.isArray(r.content))) errs.push("content must be a JSON object");
  if ("salt" in r && (typeof r.salt !== "string" || !SALT_RE.test(r.salt))) errs.push("salt must be 32 lowercase hex");
  return errs;
}

export interface RecordFields {
  kind: Kind;
  project: string;
  env: "test" | "live";
  agent: string;
  seq: number;
  prev: string | null;
  name: string;
  content: Record<string, unknown>;
  ref?: string | null;
  time?: string;
  /** The content salt (§2.1); a fresh random one when not given. */
  salt?: string;
}

/** Build and sign `{envelope, key_id, sig, content, salt}`: the content hash is salted (SPEC
 * §2.1). Throws on a bad envelope or on content numbers other implementations could not re-read
 * (SPEC §1). */
export function makeRecord(key: SigningKey, f: RecordFields): SignedRecord {
  assertPortableNumbers(f.content);
  const salt = f.salt ?? newSalt();
  const envelope: Envelope = {
    v: 1,
    kind: f.kind,
    project: f.project,
    env: f.env,
    agent: f.agent,
    seq: f.seq,
    prev: f.prev,
    time: f.time ?? now(),
    name: f.name,
    content_hash: contentHash(f.content, salt),
    ref: f.ref ?? null,
  };
  const errs = envelopeErrors(envelope);
  if (errs.length) throw new Error("invalid record: " + errs.join("; "));
  return { envelope, key_id: key.keyId, sig: key.sign("record", hashJson(envelope)), content: f.content, salt };
}

export function recordHash(rec: { envelope: unknown }): string {
  return hashJson(rec.envelope);
}

/** The record as sent to the service: content and its salt only when stored there (§2.3). */
export function wireRecord(rec: SignedRecord, storeContent: boolean): SignedRecord {
  const out: SignedRecord = { envelope: rec.envelope, key_id: rec.key_id, sig: rec.sig };
  if (storeContent && rec.content !== undefined) {
    out.content = rec.content;
    if (rec.salt !== undefined) out.salt = rec.salt;
  }
  return out;
}

/** A draft (§8) for a chain whose project is not known yet (no API key, or the key's project
 * not learned): the envelope without project and env, signed by the agent's key over domain
 * `draft`, so a local chain verifies before anything is sent. `recordHash` of a draft is its
 * draft hash. */
export function makeDraft(key: SigningKey, f: Omit<RecordFields, "project" | "env">, storeContent: boolean): SignedRecord {
  assertPortableNumbers(f.content);
  const salt = f.salt ?? newSalt();
  const d = { v: 1, kind: f.kind, agent: f.agent, seq: f.seq, prev: f.prev, time: f.time ?? now(), name: f.name, content_hash: contentHash(f.content, salt), ref: f.ref ?? null };
  const errs = envelopeErrors(d, DRAFT_FIELDS);
  if (errs.length) throw new Error("invalid record: " + errs.join("; "));
  return { draft: true, envelope: d as unknown as Envelope, key_id: key.keyId, sig: key.sign("draft", hashJson(d)), content: f.content, salt, store_content: storeContent };
}

/** Schema problems with a draft line (§8); empty when valid. */
export function draftErrors(rec: unknown): string[] {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return ["draft is not an object"];
  const r = rec as Record<string, unknown>;
  const errs = envelopeErrors(r.envelope, DRAFT_FIELDS);
  const extra = Object.keys(r)
    .filter((k) => !["draft", "envelope", "key_id", "sig", "content", "salt", "store_content"].includes(k))
    .sort();
  if (extra.length) errs.push("unknown draft field " + extra.join(", "));
  if (r.draft !== true) errs.push("draft must be true");
  if (typeof r.key_id !== "string" || !KEY_ID_RE.test(r.key_id)) errs.push("key_id must be 16 lowercase hex (an unsigned draft from an older SDK cannot be verified)");
  let sigOk = false;
  try {
    sigOk = b64urlDecode(r.sig as string).length === 64;
  } catch {
    sigOk = false;
  }
  if (!sigOk) errs.push("sig must be a base64url Ed25519 signature");
  if ("content" in r && (!r.content || typeof r.content !== "object" || Array.isArray(r.content))) errs.push("content must be a JSON object");
  if ("salt" in r && (typeof r.salt !== "string" || !SALT_RE.test(r.salt))) errs.push("salt must be 32 lowercase hex");
  if ("store_content" in r && typeof r.store_content !== "boolean") errs.push("store_content must be true or false");
  return errs;
}

/** The signed record for a draft once its project is known (§8). */
export function signDraft(key: SigningKey, draft: SignedRecord, project: string, env: "test" | "live", prev: string | null, ref: string | null): SignedRecord {
  const d = draft.envelope;
  return makeRecord(key, { kind: d.kind, project, env, agent: d.agent, seq: d.seq, prev, name: d.name, content: draft.content ?? {}, ref, time: d.time, salt: draft.salt });
}

/** A service key (§5) or, with `agent`, a pack's agent key: exact fields, valid times. */
export function keyEntryErrors(k: unknown, agent = false): string[] {
  const fields = ["key_id", "public_key", "valid_from", "valid_to", ...(agent ? ["agent"] : [])];
  if (!sameKeys(k, fields)) return ["key fields are " + [...fields].sort().join(", ")];
  if (!fields.filter((f) => f !== "valid_to").every((f) => typeof k[f] === "string")) return ["key fields must be strings"];
  if (!validTime(k.valid_from)) return [`key ${k.key_id}: valid_from is not a time`];
  if (k.valid_to !== null && !validTime(k.valid_to)) return [`key ${k.key_id}: valid_to is not null or a time`];
  return [];
}

export function registration(project: string, env: string, agent: string, publicKey: string, validFrom: string) {
  return { project, env, agent, public_key: publicKey, valid_from: validFrom };
}

export interface AgentKeyEntry {
  agent: string;
  key_id: string;
  public_key: string;
  valid_from: string;
  /** When a retired key was retired (the service's time, §2.4); null for a current key. */
  valid_to: string | null;
  sig: string;
}

/** A self-signed agent-key manifest entry (§2.5). */
export function manifestEntry(agent: string, key: SigningKey, validFrom: string, validTo: string | null = null): AgentKeyEntry {
  const e = { agent, key_id: key.keyId, public_key: b64url(key.publicKey), valid_from: validFrom, valid_to: validTo };
  return { ...e, sig: key.sign("agent_key", hashJson(e)) };
}

/** Problems with an agent-key manifest (§2.5), self-signatures included. */
export function manifestErrors(doc: any): string[] {
  if (!sameKeys(doc, ["format", "keys"]) || !Array.isArray(doc.keys)) return ['agent keys must be {"format": "signafaide-agent-keys/1", "keys": [...]}'];
  if (doc.format !== AGENT_KEYS_FORMAT) return [`format is '${doc.format}', expected '${AGENT_KEYS_FORMAT}'`];
  for (const e of doc.keys) {
    if (
      !sameKeys(e, ["agent", "key_id", "public_key", "valid_from", "valid_to", "sig"]) ||
      !Object.entries(e).every(([k, v]) => typeof v === "string" || (k === "valid_to" && v === null))
    ) {
      return ["each agent key is {agent, key_id, public_key, valid_from, valid_to, sig}"];
    }
    if (!AGENT_RE.test(e.agent)) return [`agent ${e.agent} is not a valid agent name`];
    try {
      const pk = b64urlDecode(e.public_key);
      if (pk.length !== 32 || keyId(pk) !== e.key_id) return [`key_id ${e.key_id} does not match its public key`];
    } catch {
      return [`key ${e.key_id}: public key is not base64url`];
    }
    if (!validTime(e.valid_from)) return [`key ${e.key_id}: valid_from is not a time`];
    if (e.valid_to !== null && !validTime(e.valid_to)) return [`key ${e.key_id}: valid_to is not null or a time`];
    const signed = { agent: e.agent, key_id: e.key_id, public_key: e.public_key, valid_from: e.valid_from, valid_to: e.valid_to };
    if (!verifySig(e.public_key, "agent_key", hashJson(signed), e.sig)) return [`the self-signature of key ${e.key_id} for ${e.agent} does not verify`];
  }
  return [];
}
