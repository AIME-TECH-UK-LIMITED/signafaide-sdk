/**
 * Every entry of spec/vectors.json, byte for byte. The drand BLS check runs through the
 * @noble/curves verifier (a dependency).
 *
 * The file is read with the SDK's literal-aware `parseJson`, so number literals are judged
 * as written, exactly as in Rust and Python.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { beforeAll, describe, expect, it } from "vitest";
import { SigningKey, auditPath, b64url, contentHash, hashJson, leafHash, merkleRoot, sha256Hex, signedMessage, verifyInclusion, verifySig } from "../src/crypto.js";
import { assertPortableNumbers, canonicalize, parseJson } from "../src/jcs.js";
import { MAX_NODES, MAX_PROOF_BYTES, base64Decode, blockAttestations, otsStatus, parseOts } from "../src/ots.js";
import { AGENT_RE, clampTime, envelopeErrors, manifestEntry, validProjectId, validTime } from "../src/records.js";
import { checkHeader, rootsFromVector } from "../src/timestamps.js";
import {
  ANCHOR_WINDOW_MS,
  MAX_ROUND,
  NO_RECORDS,
  checkRoundTime,
  exportStatement,
  recordsHash,
  loadDrandVerifier,
  parseAgentKeys,
  parseHeadFile,
  parseServiceKeys,
  serviceKeysHash,
  verifyPack,
  type DrandVerifier,
  type PackOptions,
} from "../src/verifier.js";

const file = path.resolve(__dirname, "../../spec/vectors.json");
const v = fs.existsSync(file) ? parseJson(fs.readFileSync(file, "utf8")) : null;

/** verifyPack inputs for a vector entry (keys, agent_keys, trust_embedded_agent_keys, head, bitcoin). */
function inputs(c: any, extra: PackOptions = {}): [any[], PackOptions] {
  const keys = parseServiceKeys(c.keys ?? v.keys_document);
  const agentKeys = c.agent_keys === null ? null : parseAgentKeys(c.agent_keys ?? v.agent_keys_document);
  return [
    keys,
    {
      agentKeys,
      trustEmbeddedAgentKeys: !!c.trust_embedded_agent_keys,
      heads: c.head ? parseHeadFile(c.head) : null,
      timestamps: c.bitcoin ? rootsFromVector(c.bitcoin) : null,
      byService: !!c.by_service,
      serviceKeysPlainHttp: !!c.service_keys_plain_http,
      ...extra,
    },
  ];
}

describe.skipIf(!v)("spec/vectors.json", () => {
  const keys: Record<string, SigningKey> = {};
  let drand: DrandVerifier | null;
  beforeAll(async () => {
    for (const k of v.keys) keys[k.name] = new SigningKey(hexToBytes(k.seed_hex));
    drand = await loadDrandVerifier();
  });

  it("jcs", () => {
    for (const c of v.jcs) {
      if ("error" in c) expect(() => canonicalize(parseJson(c.input)), c.name).toThrow();
      else expect(canonicalize(parseJson(c.input)), c.name).toBe(c.output);
      // Values JavaScript builds itself have no literal: the own-value rule (SPEC §1) rejects them.
      if (c.exact_integer_only) expect(() => assertPortableNumbers(JSON.parse(c.input)), c.name).toThrow(/unsafe_integer/);
    }
  });

  it("sha256, keys, signatures", () => {
    for (const c of v.sha256) expect(bytesToHex(sha256(new TextEncoder().encode(c.utf8)))).toBe(c.hex);
    for (const k of v.keys) {
      expect(b64url(keys[k.name].publicKey)).toBe(k.public_key);
      expect(keys[k.name].keyId).toBe(k.key_id);
    }
    for (const c of v.signatures) {
      expect(bytesToHex(signedMessage(c.domain, c.hash))).toBe(c.message_hex);
      expect(keys[c.key].sign(c.domain, c.hash)).toBe(c.sig);
      expect(verifySig(b64url(keys[c.key].publicKey), c.domain, c.hash, c.sig)).toBe(true);
    }
    for (const c of v.cross_domain) expect(verifySig(b64url(keys[c.key].publicKey), c.verify_domain, c.hash, c.sig)).toBe(c.valid);
  });

  it("merkle", () => {
    for (const t of v.merkle.trees) {
      expect(t.items.map((h: string) => bytesToHex(leafHash(h)))).toEqual(t.leaf_hashes);
      expect(merkleRoot(t.items)).toBe(t.root);
      t.paths.forEach((p: string[], i: number) => {
        expect(auditPath(t.items, i)).toEqual(p);
        expect(verifyInclusion(t.items[i], i, t.items.length, p, t.root)).toBe(true);
      });
    }
  });

  it("records", () => {
    for (const r of v.records) {
      expect(canonicalize(r.content)).toBe(r.content_jcs);
      expect(contentHash(r.content, r.salt)).toBe(r.content_hash);
      expect(sha256Hex(concatBytes(hexToBytes(r.salt), new TextEncoder().encode(r.content_jcs)))).toBe(r.content_hash);
      expect(canonicalize(r.envelope)).toBe(r.envelope_jcs);
      expect(hashJson(r.envelope)).toBe(r.record_hash);
      expect(envelopeErrors(r.envelope)).toEqual([]);
      expect(keys.agent.sign("record", r.record_hash)).toBe(r.sig);
    }
  });

  it("batch, head, anchor, receipts", () => {
    const svc = b64url(keys.service.publicKey);
    const b = v.batch;
    expect(canonicalize(b.batch)).toBe(b.batch_jcs);
    expect(hashJson(b.batch)).toBe(b.batch_hash);
    expect(verifySig(svc, "batch", b.batch_hash, b.batch_sig)).toBe(true);
    expect(merkleRoot(b.record_hashes)).toBe(b.root);
    for (const p of b.proofs) expect(verifyInclusion(b.record_hashes[p.index], p.index, b.record_hashes.length, p.proof, b.root)).toBe(true);
    const h = v.head;
    expect(canonicalize(h.head)).toBe(h.head_jcs);
    expect(hashJson(h.head)).toBe(h.head_hash);
    expect(verifySig(svc, "head", h.head_hash, h.head_sig)).toBe(true);
    const a = v.anchor;
    const { ots: _o, status: _s, bitcoin_block: _b, ...core } = a.anchor;
    expect(canonicalize(core)).toBe(a.signed_part_jcs);
    expect(hashJson(core)).toBe(a.anchor_hash);
    expect(verifySig(svc, "anchor", a.anchor_hash, a.anchor_sig)).toBe(true);
    for (const [bh, p] of Object.entries<any>(a.paths)) expect(verifyInclusion(bh, p.index, a.anchor.size, p.path, a.anchor.root)).toBe(true);
    for (const rc of v.receipts) expect(verifyInclusion(rc.record_hash, rc.index, rc.batch.size, rc.proof, rc.batch.root)).toBe(true);
  });

  it("schema, ids, time", () => {
    for (const c of v.invalid_envelopes) expect(envelopeErrors(c.envelope).length, c.name).toBeGreaterThan(0);
    for (const n of v.agent_names.valid) expect(AGENT_RE.test(n)).toBe(true);
    for (const n of v.agent_names.invalid) expect(AGENT_RE.test(n)).toBe(false);
    for (const p of v.project_ids.valid) expect(validProjectId(p)).toBe(true);
    for (const p of v.project_ids.invalid) expect(validProjectId(p)).toBe(false);
    for (const c of v.time) {
      if ("error" in c) expect(validTime(c.input), c.input).toBe(false);
      else expect(Date.parse(c.input)).toBe(c.unix_ms);
    }
  });

  it("ots", () => {
    for (const c of v.ots) {
      if (c.error) {
        expect(() => parseOts(base64Decode(c.base64)), c.name).toThrow(/ots:/);
        continue;
      }
      const { digest, height } = otsStatus(base64Decode(c.base64));
      expect(digest).toBe(c.digest);
      expect(height === null ? "pending" : `confirmed@${height}`).toBe(c.status);
      for (const b of c.bitcoin ?? []) expect(blockAttestations(base64Decode(c.base64))).toEqual([[b.height, b.merkle_root.match(/../g).reverse().join("")]]);
    }
    expect([MAX_PROOF_BYTES, MAX_NODES]).toEqual([v.ots_limits.max_proof_bytes, v.ots_limits.max_nodes]);
  });

  it("registration, agent-key manifest, keys_hash, drand time", () => {
    const r = v.registration;
    expect(canonicalize(r.registration)).toBe(r.registration_jcs);
    expect(hashJson(r.registration)).toBe(r.registration_hash);
    expect(keys.agent.sign("register", r.registration_hash)).toBe(r.proof);
    expect(keys.other.sign("rotate", r.registration_hash)).toBe(r.rotation.sig);
    const entry = v.agent_keys_document.keys[0];
    expect(manifestEntry("agent-a", keys.agent, entry.valid_from)).toEqual(entry);
    expect(parseAgentKeys(v.agent_keys_document)[0].key_id).toBe(keys.agent.keyId);
    expect(() => parseAgentKeys({ ...v.agent_keys_document, keys: [{ ...entry, valid_from: "2020-01-01T00:00:00.000Z" }] })).toThrow(/self-signature/);
    const k = v.keys_hash;
    expect(bytesToHex(sha256(new TextEncoder().encode(k.committed_jcs)))).toBe(k.keys_hash);
    expect(serviceKeysHash(k.keys, Date.parse(k.created))).toBe(k.keys_hash);
    for (const c of v.drand_time) expect(checkRoundTime(Date.parse(c.server_time), c.round) === null, JSON.stringify(c)).toBe(c.valid);
    expect([MAX_ROUND, ANCHOR_WINDOW_MS]).toEqual([v.drand_max_round, v.anchor_window_ms]);
    expect(() => parseAgentKeys({ ...v.agent_keys_document, keys: [{ ...entry, valid_to: "2026-11-13T10:04:00.000Z" }] })).toThrow(/self-signature/);
  });

  it("export statement", () => {
    const e = v.export;
    const st = exportStatement(v.pack.pack);
    expect(st).toEqual(e.statement);
    expect(canonicalize(st)).toBe(e.statement_jcs);
    expect(recordsHash(v.pack.pack.records)).toBe(e.records_hash);
    expect(hashJson(st)).toBe(e.statement_hash);
    expect(keys.service.sign("export", e.statement_hash)).toBe(e.export_sig);
  });

  it("block headers", () => {
    for (const c of v.block_headers) {
      if (c.valid) expect(checkHeader(c.hash, c.header).match(/../g)!.reverse().join(""), c.name).toBe(c.merkle_root);
      else expect(() => checkHeader(c.hash, c.header), c.name).toThrow();
    }
  });

  it("drand (BLS via @noble/curves)", () => {
    expect(drand).not.toBeNull();
    for (const c of v.drand) expect(drand!(c.beacon)).toBe(c.valid);
  });

  it("pack", () => {
    const r = verifyPack(v.pack.pack, ...inputs({}, { drand }));
    expect(r.result).toBe(v.pack.expect.result);
    expect(r.resultLine).toBe(v.pack.expect.result_line);
    expect(Object.fromEntries(r.checks.map((c) => [c.id, c.value ?? c.status]))).toEqual(v.pack.expect.checks);
    const without = verifyPack(v.pack.pack, ...inputs({}));
    expect(without.check("drand").status).toBe("not_checked");
  });

  it("variants pass with their values", () => {
    for (const c of v.variants) {
      const r = verifyPack(c.pack, ...inputs(c, { drand }));
      expect(r.resultLine, c.name).toBe(c.expect.result_line);
      expect(Object.fromEntries(r.checks.map((x) => [x.id, x.value ?? x.status])), c.name).toEqual(c.expect.checks);
      if (c.expect.chain_note) expect(r.check("chain").detail, c.name).toContain(c.expect.chain_note);
    }
    expect(v.variants.filter((c: any) => c.expect.chain_note).length).toBe(3); // an unclean start, a clean restart, a clean restart cut by the window
  });

  it("monotonic time: the client's time for a new record (spec §2.2)", () => {
    expect(v.time_clamp.length).toBe(5);
    for (const c of v.time_clamp) expect(clampTime(c.wall, c.prev, c.valid_from), c.name).toEqual([c.time, c.raised]);
  });

  it("tampered packs fail at the expected check", () => {
    expect(v.tampered.length).toBe(49);
    for (const c of v.tampered) {
      const r = verifyPack(c.pack, ...inputs(c, { drand }));
      expect(r.firstFailed(), c.tamper).toBe(c.first_failed);
      expect(r.ok).toBe(false);
    }
  });

  it("an empty pack fails with no records", () => {
    const c = v.tampered.find((t: any) => t.pack.records.length === 0);
    const r = verifyPack(c.pack, ...inputs(c));
    expect(r.ok).toBe(false);
    expect(r.firstFailed()).toBe("schema");
    expect(r.check("schema").failures).toEqual([{ item: "pack", message: NO_RECORDS }]);
    expect(String(r)).toContain("pack: no records");
  });
});
