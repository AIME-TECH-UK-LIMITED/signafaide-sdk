/** Hashes, domain-separated Ed25519 and RFC 6962 Merkle proofs (SPEC §1, §3.2). */

import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { canonicalBytes } from "./jcs.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(concatBytes(...m));

export const DOMAINS = ["record", "batch", "head", "anchor", "register", "rotate", "agent_key", "export", "draft", "ruling", "rules", "fingerprints"] as const;
export type Domain = (typeof DOMAINS)[number];
export const HEX64 = /^[0-9a-f]{64}$/;
export const SALT_RE = /^[0-9a-f]{32}$/;
const encoder = new TextEncoder();

/** Native implementations the Node runtime plugs in (OpenSSL, as the Python SDK uses): the
 * pure-JS ones stay for browsers and edge runtimes. Same results, about 20 times faster. */
let nativeSha256: ((data: Uint8Array) => Uint8Array) | null = null;
let nativeVerify: ((publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array) => boolean) | null = null;
export function useNativeCrypto(impl: { sha256?: (data: Uint8Array) => Uint8Array; verify?: (publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array) => boolean }): void {
  nativeSha256 = impl.sha256 ?? null;
  nativeVerify = impl.verify ?? null;
}
const digest = (data: Uint8Array): Uint8Array => (nativeSha256 ? nativeSha256(data) : sha256(data));

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(digest(data));
}

/** sha256(JCS(value)) as 64 lowercase hex. */
export function hashJson(value: unknown): string {
  return sha256Hex(canonicalBytes(value));
}

/** A fresh content salt (SPEC §2.1): 16 random bytes as 32 lowercase hex. */
export function newSalt(): string {
  return bytesToHex(randomBytes(16));
}

/** sha256(salt || JCS(content)) as 64 lowercase hex (SPEC §2.1); content is a JSON object. */
export function contentHash(content: unknown, salt: string): string {
  if (!content || typeof content !== "object" || Array.isArray(content)) throw new Error("content must be a JSON object");
  if (typeof salt !== "string" || !SALT_RE.test(salt)) throw new Error("salt must be 32 lowercase hex characters (16 bytes)");
  return sha256Hex(concatBytes(hexToBytes(salt), canonicalBytes(content)));
}

/** The §2.3 content rule: `content` and `salt` together or not at all. Returns null when they
 * match `expected` (or are both absent); throws when they cannot be checked; returns the actual
 * hash on a mismatch. */
export function checkContent(content: unknown, salt: unknown, expected: string): string | null {
  if (content === undefined && salt === undefined) return null;
  if (salt === undefined) throw new Error("content is present without its salt");
  if (content === undefined) throw new Error("salt is present without content");
  const h = contentHash(content, salt as string);
  return h === expected ? null : h;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64url(data: Uint8Array): string {
  let out = "";
  for (let i = 0; i < data.length; i += 3) {
    const n = (data[i] << 16) | ((data[i + 1] ?? 0) << 8) | (data[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((data.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += B64[(n >> (18 - 6 * j)) & 63];
  }
  return out;
}

export function b64urlDecode(s: string): Uint8Array {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new Error("not base64url without padding");
  }
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (const c of s) {
    acc = (acc << 6) | B64.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 255;
    }
  }
  return out;
}

/** First 16 hex characters of SHA-256 of the raw 32-byte public key. */
export function keyId(publicKey: Uint8Array): string {
  return sha256Hex(publicKey).slice(0, 16);
}

export function signedMessage(domain: Domain, hashHex: string): Uint8Array {
  if (!DOMAINS.includes(domain)) throw new Error(`unknown signature domain ${domain}`);
  if (!HEX64.test(hashHex ?? "")) throw new Error("hash must be 64 lowercase hex characters");
  return concatBytes(encoder.encode(`signafaide/v1/${domain}\n`), hexToBytes(hashHex));
}

/** An Ed25519 private key. Only `sign` touches the private half. */
export class SigningKey {
  readonly publicKey: Uint8Array;
  readonly keyId: string;
  readonly #seed: Uint8Array;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
    this.#seed = seed;
    this.publicKey = ed.getPublicKey(seed);
    this.keyId = keyId(this.publicKey);
  }

  static generate(random: (n: number) => Uint8Array = randomBytes): SigningKey {
    return new SigningKey(random(32));
  }

  seed(): Uint8Array {
    return this.#seed;
  }

  /** base64url Ed25519 signature over `signafaide/v1/<domain>\n` + raw hash. */
  sign(domain: Domain, hashHex: string): string {
    return b64url(ed.sign(signedMessage(domain, hashHex), this.#seed));
  }
}

export function verifySig(publicKeyB64: string, domain: Domain, hashHex: string, sigB64: string): boolean {
  try {
    const pk = b64urlDecode(publicKeyB64);
    const sig = b64urlDecode(sigB64);
    if (pk.length !== 32 || sig.length !== 64) return false;
    if (nativeVerify) return nativeVerify(pk, signedMessage(domain, hashHex), sig);
    return ed.verify(sig, signedMessage(domain, hashHex), pk, { zip215: false });
  } catch {
    return false;
  }
}

function randomBytes(n: number): Uint8Array {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.getRandomValues) throw new Error("no secure random source: pass one to SigningKey.generate");
  return c.getRandomValues(new Uint8Array(n));
}

// --- RFC 6962 Merkle tree ----------------------------------------------------------

export function leafHash(hashHex: string): Uint8Array {
  return digest(concatBytes(new Uint8Array([0]), hexToBytes(hashHex)));
}

function node(left: Uint8Array, right: Uint8Array): Uint8Array {
  return digest(concatBytes(new Uint8Array([1]), left, right));
}

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function root(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return node(root(leaves.slice(0, k)), root(leaves.slice(k)));
}

/** Root of the RFC 6962 tree over `hashes` (hex). */
export function merkleRoot(hashes: string[]): string {
  if (!hashes.length) throw new Error("a Merkle tree needs at least one leaf");
  return bytesToHex(root(hashes.map(leafHash)));
}

/** Audit path for leaf `index`, from the leaf upward (hex). */
export function auditPath(hashes: string[], index: number): string[] {
  if (index < 0 || index >= hashes.length) throw new Error("index out of range");
  const leaves = hashes.map(leafHash);
  const path: string[] = [];
  const walk = (lo: number, hi: number): void => {
    if (hi - lo === 1) return;
    const k = split(hi - lo);
    if (index < lo + k) {
      walk(lo, lo + k);
      path.push(bytesToHex(root(leaves.slice(lo + k, hi))));
    } else {
      walk(lo + k, hi);
      path.push(bytesToHex(root(leaves.slice(lo, lo + k))));
    }
  };
  walk(0, leaves.length);
  return path;
}

/** RFC 9162 §2.1.3.2 inclusion check of `hashHex` at `index` in a tree of `size`. */
export function verifyInclusion(hashHex: string, index: unknown, size: unknown, path: unknown, rootHex: unknown): boolean {
  try {
    if (!Number.isInteger(index) || !Number.isInteger(size) || !Array.isArray(path)) return false;
    let fn = index as number;
    let sn = (size as number) - 1;
    if (fn < 0 || fn > sn) return false;
    let r = leafHash(hashHex);
    for (const pHex of path) {
      if (typeof pHex !== "string" || !HEX64.test(pHex) || sn === 0) return false;
      const p = hexToBytes(pHex);
      if (fn % 2 === 1 || fn === sn) {
        r = node(p, r);
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      } else {
        r = node(r, p);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && bytesToHex(r) === rootHex;
  } catch {
    return false;
  }
}

/** Index at which `path` proves `hashHex` into `rootHex`, or null (anchor paths carry no index). */
export function findInclusionIndex(hashHex: string, size: number, path: string[], rootHex: string): number | null {
  for (let i = 0; i < size; i++) if (verifyInclusion(hashHex, i, size, path, rootHex)) return i;
  return null;
}

