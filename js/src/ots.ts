/**
 * Read an OpenTimestamps `.ots` proof (§4, §7 check 11) the same way the Rust core does: it
 * parses the detached-file format and runs every operation, so each attestation is paired
 * with the message the proof commits to. A block attestation's message is the block's
 * Merkle root in header byte order; check it against the real block header (`timestamps.ts`)
 * before calling the proof confirmed. Proofs are capped at `MAX_PROOF_BYTES` bytes and
 * `MAX_NODES` operations and attestations in total.
 */

import { ripemd160, sha1 } from "@noble/hashes/legacy";
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";

export const MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72,
  0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
export const TAG_BITCOIN = "0588960d73d71901";
export const TAG_PENDING = "83dfe30d2ef90c8e";
const MAX_MSG = 4096;
const MAX_DEPTH = 256;
export const MAX_PROOF_BYTES = 65_536;
export const MAX_NODES = 1024;

const UNARY: Record<number, (m: Uint8Array) => Uint8Array> = {
  0x02: (m) => sha1(m),
  0x03: (m) => ripemd160(m),
  0x08: (m) => sha256(m),
  0x67: (m) => keccak_256(m),
  0xf2: (m) => Uint8Array.from(m).reverse(),
  0xf3: (m) => new TextEncoder().encode(bytesToHex(m)),
};
const BINARY: Record<number, (m: Uint8Array, a: Uint8Array) => Uint8Array> = {
  0xf0: (m, a) => concatBytes(m, a),
  0xf1: (m, a) => concatBytes(a, m),
};

export type Attestation = (
  | { kind: "bitcoin"; height: number }
  | { kind: "pending"; uri: string }
  | { kind: "unknown"; tag: string }
) & { msg: Uint8Array };

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

class Reader {
  pos = 0;
  nodes = 0;
  constructor(readonly data: Uint8Array) {}

  byte(): number {
    if (this.pos >= this.data.length) throw new Error("ots: unexpected end of proof");
    return this.data[this.pos++];
  }

  take(n: number): Uint8Array {
    if (this.data.length - this.pos < n) throw new Error("ots: unexpected end of proof");
    this.pos += n;
    return this.data.subarray(this.pos - n, this.pos);
  }

  varuint(): number {
    let value = 0;
    for (let shift = 0; shift < 64; shift += 7) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
    }
    throw new Error("ots: varuint too long");
  }

  varbytes(limit: number): Uint8Array {
    const n = this.varuint();
    if (n > limit) throw new Error(`ots: field longer than ${limit} bytes`);
    return this.take(n);
  }

  node(): void {
    if (++this.nodes > MAX_NODES) throw new Error(`ots: proof has more than ${MAX_NODES} operations and attestations`);
  }
}

/** Digest and attestations of a detached proof. Throws on a malformed proof. */
export function parseOts(data: Uint8Array): { digest: string; attestations: Attestation[] } {
  if (data.length > MAX_PROOF_BYTES) throw new Error(`ots: proof is longer than ${MAX_PROOF_BYTES} bytes`);
  const r = new Reader(data);
  if (hex(r.take(MAGIC.length)) !== hex(MAGIC)) throw new Error("ots: not an OpenTimestamps proof (bad magic)");
  if (r.varuint() !== 1) throw new Error("ots: unsupported proof version");
  if (r.byte() !== 0x08) throw new Error("ots: only SHA-256 file digests are supported");
  const digest = Uint8Array.from(r.take(32));
  const attestations: Attestation[] = [];
  readTimestamp(r, digest, attestations, 0);
  if (r.pos !== data.length) throw new Error("ots: trailing bytes after timestamp");
  return { digest: hex(digest), attestations };
}

function readTimestamp(r: Reader, msg: Uint8Array, found: Attestation[], depth: number): void {
  if (depth > MAX_DEPTH) throw new Error("ots: proof nested too deeply");
  for (;;) {
    let tag = r.byte();
    const fork = tag === 0xff;
    if (fork) tag = r.byte();
    r.node();
    if (tag === 0x00) found.push({ ...readAttestation(r), msg });
    else {
      let next: Uint8Array;
      if (tag in BINARY) next = BINARY[tag](msg, r.varbytes(MAX_MSG));
      else if (tag in UNARY) next = UNARY[tag](msg);
      else throw new Error(`ots: unknown operation tag 0x${tag.toString(16).padStart(2, "0")}`);
      if (next.length > MAX_MSG) throw new Error(`ots: operation result longer than ${MAX_MSG} bytes`);
      readTimestamp(r, next, found, depth + 1);
    }
    if (!fork) return;
  }
}

function readAttestation(
  r: Reader,
): { kind: "bitcoin"; height: number } | { kind: "pending"; uri: string } | { kind: "unknown"; tag: string } {
  const tag = hex(r.take(8));
  const p = new Reader(r.varbytes(8192));
  if (tag === TAG_BITCOIN) return { kind: "bitcoin", height: p.varuint() };
  if (tag === TAG_PENDING) {
    const uri = p.varbytes(1000);
    if (!uri.every((c) => /[A-Za-z0-9\-.:/_]/.test(String.fromCharCode(c))))
      throw new Error("ots: calendar URI has invalid characters");
    return { kind: "pending", uri: new TextDecoder().decode(uri) };
  }
  return { kind: "unknown", tag };
}

/** Digest and lowest attested block height (null while pending). Throws for a
 * malformed proof or one with no attestation at all. */
export function otsStatus(data: Uint8Array): { digest: string; height: number | null } {
  const { digest, attestations } = parseOts(data);
  const heights = attestations.flatMap((a) => (a.kind === "bitcoin" ? [a.height] : []));
  if (heights.length) return { digest, height: Math.min(...heights) };
  if (attestations.some((a) => a.kind === "pending")) return { digest, height: null };
  throw new Error("OTS proof has no attestation");
}

/** (height, Merkle root hex in header byte order) of each block attestation. */
export function blockAttestations(data: Uint8Array): [number, string][] {
  return parseOts(data).attestations.flatMap((a) => {
    if (a.kind !== "bitcoin") return [];
    if (a.msg.length !== 32)
      throw new Error(`ots: the timestamp attestation for block ${a.height} is not over a 32-byte Merkle root`);
    return [[a.height, hex(a.msg)] as [number, string]];
  });
}

/** Decode standard base64 with padding (the `ots` field, §4). */
export function base64Decode(s: string): Uint8Array {
  if (typeof s !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))
    throw new Error("ots is not standard base64");
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
