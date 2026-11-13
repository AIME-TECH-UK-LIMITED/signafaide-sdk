import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import { SigningKey, auditPath, b64url, b64urlDecode, contentHash, hashJson, keyId, leafHash, merkleRoot, signedMessage, verifyInclusion, verifySig } from "../src/crypto.js";
import { assertPortableNumbers, canonicalize } from "../src/jcs.js";
import { agentName, envelopeErrors, makeRecord, recordErrors, recordHash } from "../src/records.js";

const enc = new TextEncoder();
const randomKey = () => SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n)));

describe("JCS", () => {
  it("matches the RFC 8785 example", () => {
    const value = JSON.parse(
      '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}',
    );
    expect(canonicalize(value)).toBe('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  });

  it("sorts keys by UTF-16 code units", () => {
    const keys = ["\u20ac", "\r", "\ufb33", "1", "\u{1f600}", "\u0080", "\u00f6"];
    const out = canonicalize(Object.fromEntries(keys.map((k, i) => [k, i])));
    const rfcOrder = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\u{1f600}", "\ufb33"];
    const pos = rfcOrder.map((k) => out.indexOf(JSON.stringify(k) + ":"));
    expect(pos.every((p, i) => p >= 0 && (i === 0 || p > pos[i - 1]))).toBe(true);
  });

  it.each([
    [0, "0"],
    [-0, "0"],
    [1, "1"],
    [-1.5, "-1.5"],
    [1e20, "100000000000000000000"],
    [1e21, "1e+21"],
    [1e-6, "0.000001"],
    [1e-7, "1e-7"],
    [0.1 + 0.2, "0.30000000000000004"],
    [5e-324, "5e-324"],
    [Number.MAX_SAFE_INTEGER, "9007199254740991"],
  ])("number %s -> %s", (n, text) => expect(canonicalize(n)).toBe(text));

  it.each([NaN, Infinity, "\ud800", new Date(), 1n])("rejects %s", (bad) => expect(() => canonicalize(bad)).toThrow());

  it("refuses to sign integers JavaScript cannot write portably (SPEC §1)", () => {
    for (const bad of [2 ** 53, -(2 ** 53), 2 ** 64, 1e20]) {
      expect(() => assertPortableNumbers({ a: [bad] })).toThrow(/unsafe_integer/);
      expect(() => makeRecord(randomKey(), { kind: "note", project: "prj_01JD0000000000000000000000", env: "test", agent: "a", seq: 1, prev: null, name: "n", content: { x: bad } })).toThrow(/unsafe_integer/);
    }
    expect(() => assertPortableNumbers({ a: [Number.MAX_SAFE_INTEGER, 1e21, 0.5] })).not.toThrow();
  });

  it("escapes like JSON.stringify and skips undefined properties", () => {
    expect(canonicalize("\u2028\x7f\x1f\b")).toBe('"\u2028\x7f\\u001f\\b"');
    expect(canonicalize({ a: undefined, b: [] })).toBe('{"b":[]}');
  });
});

describe("hashes, keys, signatures", () => {
  it("hashes JCS and derives key ids", () => {
    expect(hashJson({ b: 1, a: 2 })).toBe(bytesToHex(sha256(enc.encode('{"a":2,"b":1}'))));
    const pk = Uint8Array.from({ length: 32 }, (_, i) => i);
    expect(keyId(pk)).toBe(bytesToHex(sha256(pk)).slice(0, 16));
  });

  it("round-trips base64url without padding", () => {
    for (let n = 0; n < 70; n++) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 37) & 255);
      const s = b64url(data);
      expect(s).not.toContain("=");
      expect(b64urlDecode(s)).toEqual(data);
      expect(s).toBe(Buffer.from(data).toString("base64url"));
    }
    expect(() => b64urlDecode("AAA=")).toThrow();
  });

  it("lays out the signed message", () => {
    const h = "ab".repeat(32);
    expect(signedMessage("record", h)).toEqual(concatBytes(enc.encode("signafaide/v1/record\n"), hexToBytes(h)));
  });

  it("matches RFC 8032 test 1", () => {
    const k = new SigningKey(hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    expect(bytesToHex(k.publicKey)).toBe("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  });

  it("separates domains", () => {
    const k = randomKey();
    const pk = b64url(k.publicKey);
    const h = hashJson({ x: 1 });
    const sig = k.sign("record", h);
    expect(verifySig(pk, "record", h, sig)).toBe(true);
    for (const d of ["batch", "head", "anchor"] as const) expect(verifySig(pk, d, h, sig)).toBe(false);
    expect(verifySig(pk, "record", hashJson({ x: 2 }), sig)).toBe(false);
    expect(verifySig(b64url(randomKey().publicKey), "record", h, sig)).toBe(false);
    expect(verifySig(pk, "record", h, "nope")).toBe(false);
  });
});

describe("Merkle (RFC 6962)", () => {
  const hs = Array.from({ length: 40 }, (_, i) => hashJson(i));
  const node = (l: Uint8Array, r: Uint8Array) => sha256(concatBytes(new Uint8Array([1]), l, r));

  it("builds the three-leaf shape", () => {
    const [l0, l1, l2] = hs.slice(0, 3).map(leafHash);
    expect(merkleRoot(hs.slice(0, 1))).toBe(bytesToHex(l0));
    expect(merkleRoot(hs.slice(0, 3))).toBe(bytesToHex(node(node(l0, l1), l2)));
    expect(auditPath(hs.slice(0, 3), 2)).toEqual([bytesToHex(node(l0, l1))]);
  });

  it.each([1, 2, 3, 4, 5, 8, 13, 33])("every path of %i leaves verifies", (n) => {
    const items = hs.slice(0, n);
    const root = merkleRoot(items);
    for (let i = 0; i < n; i++) {
      const p = auditPath(items, i);
      expect(verifyInclusion(items[i], i, n, p, root)).toBe(true);
      expect(verifyInclusion(hashJson("other"), i, n, p, root)).toBe(false);
      expect(verifyInclusion(items[i], i, n, [...p, items[0]], root)).toBe(false);
      if (n > 1) expect(verifyInclusion(items[i], (i + 1) % n, n, p, root)).toBe(false);
    }
  });
});

describe("envelopes", () => {
  const rec = () => makeRecord(randomKey(), { kind: "decision", project: "prj_01JD0000000000000000000000", env: "live", agent: "bot", seq: 1, prev: null, name: "act", content: { input: {} } });

  it("builds valid signed records", () => {
    const r = rec();
    expect(recordErrors(r)).toEqual([]);
    expect(r.envelope.content_hash).toBe(contentHash({ input: {} }, r.salt!));
    expect(r.envelope.content_hash).not.toBe(hashJson({ input: {} }));
    expect(r.envelope.time).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    expect(recordHash(r)).toBe(hashJson(r.envelope));
  });

  it.each([
    [{ v: 2 }, "v must be 1"],
    [{ kind: "action" }, "kind"],
    [{ agent: "Bad Name" }, "agent"],
    [{ seq: 0 }, "seq"],
    [{ seq: 1.5 }, "seq"],
    [{ seq: 2, prev: null }, "prev must be a record hash"],
    [{ prev: "ab".repeat(32) }, "prev must be null"],
    [{ time: "2026-11-13T10:00:00Z" }, "milliseconds"],
    [{ time: "2025-02-29T00:00:00.000Z" }, "milliseconds"],
    [{ name: "" }, "name"],
    [{ name: "x".repeat(129) }, "name"],
    [{ content_hash: "AB".repeat(32) }, "content_hash"],
    [{ ref: "ab".repeat(32) }, "ref must be null"],
    [{ kind: "outcome" }, "ref must be the decision"],
    [{ extra: 1 }, "unknown field"],
  ])("rejects %j", (change, needle) => {
    const errs = envelopeErrors({ ...rec().envelope, ...change });
    expect(errs.some((e) => e.includes(needle))).toBe(true);
  });

  it("names agents after folders", () => {
    expect(agentName("Claims Project")).toBe("claims-project");
    expect(agentName("__My_Bot!!")).toBe("my_bot");
    expect(agentName("???")).toBe("agent");
    expect(agentName("a".repeat(100))).toHaveLength(64);
  });
});
