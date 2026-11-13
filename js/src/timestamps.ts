/**
 * Public-timestamp confirmation for §7 check 11: the raw 80-byte header of a block from an
 * Esplora-style explorer API (`GET {base}/block-height/{h}`, then `GET {base}/block/{hash}/header`).
 * mempool.space and blockstream.info serve this API. The header is trusted only when it hashes to
 * that block hash and meets its own proof of work (`checkHeader`). Uses built-in fetch; no
 * redirects. An explorer over plain http is never asked: anyone on the path could answer.
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { VERSION } from "./version.js";

export const DEFAULT_TIMESTAMP_URL = "https://mempool.space/api";
/** Why a plain-http explorer is not asked. */
export const PLAIN_HTTP_EXPLORER = "the explorer URL uses plain http, which anyone on the network path can alter; use https";
/** A block as an explorer serves it: its hash (display hex) and raw header (hex). */
export interface BlockHeader {
  hash: string;
  header: string;
}
/** height -> [fetched, the block header | why it could not be fetched] */
export type BlockRoots = Map<number, [true, BlockHeader] | [false, string]>;

async function get(url: string, timeoutMs: number): Promise<string> {
  const headers: Record<string, string> = typeof process !== "undefined" && process.versions?.node ? { "User-Agent": `signafaide-js/${VERSION}` } : {};
  const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs), headers });
  if (r.status >= 300 && r.status < 400) throw new Error(`${url}: an explorer answer is never a redirect (HTTP ${r.status})`);
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
}

/** The target of a compact `nBits`; null when it is negative, zero or overflows. */
export function target(bits: number): bigint | null {
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x7fffff);
  if (bits & 0x800000 || mantissa === 0n) return null;
  const t = exponent >= 3 ? mantissa << BigInt(8 * (exponent - 3)) : mantissa >> BigInt(8 * (3 - exponent));
  return t > 0n && t < 1n << 256n ? t : null;
}

/** The Merkle root (header byte order, hex) of a header that hashes to `hash` (display hex) and
 * meets its own proof of work. Throws saying why the header is not trusted. */
export function checkHeader(hash: string, headerHex: string): string {
  const hx = String(headerHex).trim();
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hx)) throw new Error("the block header is not hex");
  const header = hexToBytes(hx.toLowerCase());
  if (header.length !== 80) throw new Error(`the block header is ${header.length} bytes, not 80`);
  const id = bytesToHex(sha256(sha256(header)).reverse());
  if (id !== String(hash).trim().toLowerCase()) throw new Error(`the block header does not hash to block ${hash}`);
  const bits = new DataView(header.buffer, header.byteOffset).getUint32(72, true);
  const t = target(bits);
  if (t === null) throw new Error(`the block header's nBits 0x${bits.toString(16).padStart(8, "0")} is not a valid target`);
  if (BigInt("0x" + id) > t) throw new Error(`block ${hash} does not meet the proof of work its header claims`);
  return bytesToHex(header.slice(36, 68));
}

/** The hash and raw header of block `height` as the explorer serves them. Throws with the reason. */
export async function blockHeader(base: string, height: number, timeoutMs = 15_000): Promise<BlockHeader> {
  base = base.replace(/\/+$/, "");
  try {
    const hash = (await get(`${base}/block-height/${height}`, timeoutMs)).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`no block at height ${height}`);
    const header = (await get(`${base}/block/${hash}/header`, timeoutMs)).trim().toLowerCase();
    return { hash, header };
  } catch (e) {
    const cause = (e as { cause?: { code?: string } }).cause?.code;
    throw new Error(`${base}: ${cause ?? (e as Error).message}`);
  }
}

/** Look up every height; a failure is kept with its reason (the check then says NOT CHECKED).
 * A plain-http explorer is not asked. */
export async function lookupTimestamps(base: string, heights: number[]): Promise<BlockRoots> {
  const plain = base.startsWith("http://");
  if (plain) console.error(`WARNING: --timestamp-check ${base} uses plain http://, which anyone on the network path can alter: public timestamps are not checked; use https://`);
  const out: BlockRoots = new Map();
  for (const h of heights) {
    if (plain) {
      out.set(h, [false, PLAIN_HTTP_EXPLORER]);
      continue;
    }
    try {
      out.set(h, [true, await blockHeader(base, h)]);
    } catch (e) {
      out.set(h, [false, (e as Error).message]);
    }
  }
  return out;
}

/** The `bitcoin` object of a test vector: height -> {hash, header}. */
export function rootsFromVector(m: Record<string, unknown>): BlockRoots {
  return new Map(
    Object.entries(m)
      .filter(([, r]) => !!r && typeof r === "object")
      .map(([h, r]) => [Number(h), [true, r as BlockHeader]]),
  );
}
