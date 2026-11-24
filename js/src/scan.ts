/**
 * What the `secret` and `hidden_instruction` checks read inside a string (SPEC §8): the text
 * normalised before matching, encoded text decoded (bounded), crypto wallet keys, seed phrases,
 * wallet addresses and card numbers, and the instruction patterns. Pure functions, no I/O. The
 * Python SDK has the same functions in `signafaide/scan.py`; `vectors.json` `checks.local_checks`
 * holds the cases both reproduce.
 */

import { sha256Hex } from "./crypto.js";
import { BIP39_ENGLISH } from "./bip39.js";
import { INSTRUCTION_CONFUSABLES } from "./confusables.js";

// --- normalisation (§8) --------------------------------------------------------------------

/** Characters removed after NFKC before matching: invisible format characters, variation
 * selectors, fillers and tag characters (§8 normalisation). */
export const REMOVED: readonly [number, number][] = [
  [0x00ad, 0x00ad],
  [0x034f, 0x034f],
  [0x061c, 0x061c],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180b, 0x180f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x206f],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0000, 0xe0fff],
];
const cp = (c: number): string => `\\u{${c.toString(16)}}`;
const REMOVED_RE = new RegExp(`[${REMOVED.map(([a, b]) => (a === b ? cp(a) : `${cp(a)}-${cp(b)}`)).join("")}]`, "gu");
/** Look-alike letters (§8 normalisation): Cyrillic and Greek letters that read as a Latin letter,
 * mapped to it after NFKC (fullwidth forms are already NFKC). Bounded on purpose: only letters a
 * reader takes for a Latin one in a common typeface, so ordinary Russian and Greek words are
 * left alone by every other check, and the table is part of the specification. */
export const CONFUSABLES: readonly [number, string][] = [
  [0x037f, "J"],
  [0x0391, "A"],
  [0x0392, "B"],
  [0x0395, "E"],
  [0x0396, "Z"],
  [0x0397, "H"],
  [0x0399, "I"],
  [0x039a, "K"],
  [0x039c, "M"],
  [0x039d, "N"],
  [0x039f, "O"],
  [0x03a1, "P"],
  [0x03a4, "T"],
  [0x03a5, "Y"],
  [0x03a7, "X"],
  [0x03b1, "a"],
  [0x03b9, "i"],
  [0x03ba, "k"],
  [0x03bd, "v"],
  [0x03bf, "o"],
  [0x03c1, "p"],
  [0x03c5, "u"],
  [0x03c7, "x"],
  [0x03f3, "j"],
  [0x0405, "S"],
  [0x0406, "I"],
  [0x0408, "J"],
  [0x0410, "A"],
  [0x0412, "B"],
  [0x0415, "E"],
  [0x041a, "K"],
  [0x041c, "M"],
  [0x041d, "H"],
  [0x041e, "O"],
  [0x0420, "P"],
  [0x0421, "C"],
  [0x0422, "T"],
  [0x0423, "Y"],
  [0x0425, "X"],
  [0x0430, "a"],
  [0x0435, "e"],
  [0x043e, "o"],
  [0x0440, "p"],
  [0x0441, "c"],
  [0x0443, "y"],
  [0x0445, "x"],
  [0x0455, "s"],
  [0x0456, "i"],
  [0x0458, "j"],
  [0x0475, "v"],
  [0x04bb, "h"],
  [0x04c0, "I"],
  [0x04cf, "l"],
  [0x0501, "d"],
  [0x051b, "q"],
  [0x051d, "w"],
];
const CONFUSABLE_MAP = new Map<string, string>(CONFUSABLES.map(([c, l]) => [String.fromCodePoint(c), l]));
const CONFUSABLE_RE = new RegExp(`[${CONFUSABLES.map(([c]) => cp(c)).join("")}]`, "gu");
/** Printable ASCII, tab and line breaks: already NFKC, and holds nothing to remove. */
const PLAIN = /^[\t\n\r\x20-\x7e]*$/;

/** A string as the checks read it (§8): NFKC, then the `REMOVED` characters taken out, then each
 * `CONFUSABLES` letter replaced by the Latin letter it looks like. */
export function normalise(s: string): string {
  if (PLAIN.test(s)) return s;
  return s
    .normalize("NFKC")
    .replace(REMOVED_RE, "")
    .replace(CONFUSABLE_RE, (c) => CONFUSABLE_MAP.get(c)!);
}

/** Whitespace as Python's `str.isspace` reads it (the reference the vectors were checked with). */
export const SPACE_RUN = /[\t\n\v\f\r \x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/g;

const INSTRUCTION_MAP = new Map<string, string>(INSTRUCTION_CONFUSABLES.map(([c, l]) => [String.fromCodePoint(c), l]));
const MARK = /^\p{Mn}$/u;
const NOT_ASCII = /[^\x00-\x7f]/gu;
/** A character of NFKD text as instruction matching reads it: a mark gone, a look-alike mapped. */
const instructionChar = (c: string): string => {
  let v = INSTRUCTION_MAP.get(c);
  if (v === undefined) {
    v = MARK.test(c) ? "" : c;
    // Remembered, as a character seen once is usually seen again (at most 65,536 kept).
    if (INSTRUCTION_MAP.size < 65_536) INSTRUCTION_MAP.set(c, v);
  }
  return v;
};

/** The text the instruction patterns read (§8 hidden_instruction): normalised, then NFKD with
 * the nonspacing marks (Mn) taken out, then each `INSTRUCTION_CONFUSABLES` letter replaced by its
 * Latin letter, ASCII letters lowercased, each run of whitespace one space. Only instruction
 * matching reads the marks and that table; the secret and address checks read `normalise`. */
export function instructionText(s: string): string {
  let t = normalise(s);
  if (!PLAIN.test(t)) t = t.normalize("NFKD").replace(NOT_ASCII, instructionChar);
  // Plain ASCII: toLowerCase changes only A to Z, as the regular expression does.
  if (PLAIN.test(t)) return t.toLowerCase().replace(/[\t\n\r ]{2,}|[\t\n\r]/g, " ");
  return t.replace(/[A-Z]+/g, (c) => c.toLowerCase()).replace(SPACE_RUN, " ");
}

// --- decoding (§8 secret) ------------------------------------------------------------------

/** At most this many decodings in a row (base64 of hex of a secret is two). */
export const DECODE_DEPTH = 3;
const HEX_CHARS = "0123456789ABCDEFabcdef";
const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const table = (chars: string): Uint8Array => {
  const t = new Uint8Array(128);
  for (const c of chars) t[c.charCodeAt(0)] = 1;
  return t;
};
const IS_HEX = table(HEX_CHARS);
const IS_B64 = table(`${B64_CHARS}-_`);
const IS_B64_STD = table(B64_CHARS);

/** The maximal runs of `text` whose characters `is` accepts, at least `min` long: one pass, no
 * backtracking (a regular expression with a minimum length retries at every start). */
function runs(text: string, is: Uint8Array, min: number): string[] {
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i <= text.length; i++) {
    const c = i < text.length ? text.charCodeAt(i) : 0;
    if (c < 128 && is[c]) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= min) out.push(text.slice(start, i));
      start = -1;
    }
  }
  return out;
}
const allHex = (s: string): boolean => {
  for (let i = 0; i < s.length; i++) if (!IS_HEX[s.charCodeAt(i)]) return false;
  return true;
};
const B64_VALUE = new Int16Array(128).fill(-1);
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  .split("")
  .forEach((c, i) => (B64_VALUE[c.charCodeAt(0)] = i));
B64_VALUE["-".charCodeAt(0)] = 62;
B64_VALUE["_".charCodeAt(0)] = 63;

declare const Buffer: { from(s: string, enc: string): Uint8Array } | undefined;

function b64Bytes(run: string): Uint8Array {
  // Node's decoder reads both alphabets and drops the bits left over, as below.
  if (typeof Buffer !== "undefined") return Buffer.from(run, "base64");
  const n = Math.floor((run.length * 6) / 8);
  const out = new Uint8Array(n);
  let acc = 0;
  let bits = 0;
  let k = 0;
  for (let i = 0; i < run.length && k < n; i++) {
    acc = ((acc << 6) | B64_VALUE[run.charCodeAt(i)]) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[k++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

function hexBytes(run: string): Uint8Array {
  const out = new Uint8Array(run.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(run.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Decoded bytes as text: printable ASCII, tab and line breaks kept, every other byte a line break. */
const ASCII = new TextDecoder("ascii");
function bytesText(b: Uint8Array): string {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) {
    const x = b[i];
    out[i] = (x >= 0x20 && x <= 0x7e) || x === 9 || x === 10 || x === 13 ? x : 10;
  }
  return ASCII.decode(out);
}

/** At most this many characters of encoded runs are decoded for one call (1 MiB): a bound on the
 * work, whatever the arguments hold. Runs past it are not decoded. */
export const DECODE_BUDGET = 1 << 20;

/** What is left of a call's decoding budget (`DECODE_BUDGET`), shared by all its texts. */
export interface Budget {
  left: number;
}

/** The texts `text` decodes to (§8 secret): each run of at least 40 hex digits as hex, and each
 * run of at least 24 base64 characters that is not all hex digits as base64 (standard or URL
 * alphabet; a run holding `-` or `_` also part by part), and what those decode to in turn, at most
 * `DECODE_DEPTH` deep and within `budget`. Each level is shorter than the one before, so the work
 * stays linear. */
export function decodings(
  text: string,
  budget: Budget = { left: DECODE_BUDGET },
  out: string[] = [],
  depth = 0,
): string[] {
  if (depth >= DECODE_DEPTH) return out;
  // The secret and hidden_instruction checks read the same strings: what a string decodes to is
  // kept for the next reader, which is charged the same part of its budget (so the result is the
  // same as decoding again). Only a decoding the budget did not cut short is kept.
  if (depth === 0 && out.length === 0 && text.length >= 24) {
    const hit = DECODED.get(text);
    if (hit && hit.cost <= budget.left) {
      budget.left -= hit.cost;
      return hit.out.slice();
    }
    const before = budget.left;
    decodeInto(text, budget, out, 0);
    if (budget.left > 0) {
      if (DECODED.size >= 64) DECODED.clear();
      DECODED.set(text, { out: out.slice(), cost: before - budget.left });
    }
    return out;
  }
  return decodeInto(text, budget, out, depth);
}
const DECODED = new Map<string, { out: string[]; cost: number }>();

function decodeInto(text: string, budget: Budget, out: string[], depth: number): string[] {
  if (depth >= DECODE_DEPTH) return out;
  const add = (run: string, decode: (r: string) => Uint8Array): void => {
    if (run.length > budget.left) {
      budget.left = 0;
      return;
    }
    budget.left -= run.length;
    const t = bytesText(decode(run));
    out.push(t);
    decodeInto(t, budget, out, depth + 1);
  };
  for (const run of runs(text, IS_HEX, 40)) add(run, hexBytes);
  for (const run of runs(text, IS_B64, 24)) {
    if (allHex(run)) continue;
    add(run, b64Bytes);
    if (run.includes("-") || run.includes("_"))
      for (const p of runs(run, IS_B64_STD, 24)) if (p !== run) add(p, b64Bytes);
  }
  return out;
}

// --- crypto wallets (§8 secret) -------------------------------------------------------------

function sha256(b: Uint8Array): Uint8Array {
  return hexBytes(sha256Hex(b));
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_VALUE = new Map([...B58].map((c, i) => [c, BigInt(i)]));

/** Base58Check: the payload when the last 4 bytes are the first 4 of its double SHA-256. */
function base58Check(s: string): Uint8Array | null {
  let n = 0n;
  for (const c of s) {
    const v = B58_VALUE.get(c);
    if (v === undefined) return null;
    n = n * 58n + v;
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  if (bytes.length < 5) return null;
  const all = Uint8Array.from(bytes);
  const payload = all.slice(0, -4);
  const sum = sha256(sha256(payload));
  for (let i = 0; i < 4; i++) if (sum[i] !== all[all.length - 4 + i]) return null;
  return payload;
}

const WIF_RE = /^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/;
/** A wallet private key in Wallet Import Format: Base58Check of version 0x80 (or 0xef), 32
 * bytes, and 0x01 for a compressed key. */
export function isWif(tok: string): boolean {
  if (!WIF_RE.test(tok)) return false;
  const p = base58Check(tok);
  return !!p && (p[0] === 0x80 || p[0] === 0xef) && (p.length === 33 || (p.length === 34 && p[33] === 1));
}

const HEX_KEY_RE = /^(0x)?[0-9a-fA-F]{64}$/;
const KEY_LABELS = ["privatekey", "privkey", "secretkey", "signingkey", "walletkey"];
/** A 64-hex token is a wallet private key when its label names one: the argument's member name or
 * the 32 characters before it in its string, letters only, lowercased. */
export function isHexKey(tok: string, label: string): boolean {
  if (!HEX_KEY_RE.test(tok)) return false;
  const l = label.toLowerCase().replace(/[^a-z]/g, "");
  return KEY_LABELS.some((k) => l.includes(k));
}

const WORD_INDEX = new Map(BIP39_ENGLISH.map((w, i) => [w, i]));
const SEED_LENGTHS = [12, 15, 18, 21, 24];
const UPPER = /[A-Z]/;

function seedChecksum(idx: number[], start: number, n: number): boolean {
  const all = new Uint8Array(Math.ceil((11 * n) / 8));
  let bit = 0;
  for (let k = 0; k < n; k++) {
    const v = idx[start + k];
    for (let b = 10; b >= 0; b--, bit++) if ((v >> b) & 1) all[bit >> 3] |= 0x80 >> (bit & 7);
  }
  const cs = n / 3;
  const entBytes = (32 * cs) / 8;
  const h = sha256(all.slice(0, entBytes))[0];
  for (let i = 0; i < cs; i++) {
    const want = (h >> (7 - i)) & 1;
    const at = entBytes * 8 + i;
    if (((all[at >> 3] >> (7 - (at & 7))) & 1) !== want) return false;
  }
  return true;
}

/** At most this many characters of one text are read for a seed phrase (1 MiB), and at most
 * `SEED_CHECKS_MAX` checksums are computed for it: a bound on the work, whatever the text holds. */
export const SEED_SCAN_MAX = 1 << 20;
export const SEED_CHECKS_MAX = 1024;
/** What a phrase may hold besides its words: digits, spaces, tabs, `.` and `)` (a numbered list).
 * Every other character (a line break, a comma, a quote, a colon...) ends a phrase. */
const IN_PHRASE = table("0123456789 \t.)");
const isLetter = (c: number): boolean => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);

/** Words in the list's order, each after the one before: an alphabetical list (tags, keywords),
 * which a seed phrase of random words is about once in 12! (479,001,600) tries. */
function sortedList(ids: number[]): boolean {
  for (let i = 1; i < ids.length; i++) if (ids[i] <= ids[i - 1]) return false;
  return true;
}

/** A BIP-39 seed phrase (§8 secret): a phrase (a part of the text between two characters that end
 * one, or its start or end) whose words (runs of ASCII letters, lowercased) are all words of the
 * English list, exactly 12, 15, 18, 21 or 24 of them, not in alphabetical order (each after the
 * one before), with a right checksum. Never a window of a longer run of words: list words in a
 * sentence or a comma-separated list are no phrase. */
export function hasSeedPhrase(text: string): boolean {
  const end = Math.min(text.length, SEED_SCAN_MAX);
  let ids: number[] = [];
  let bad = false;
  let start = -1;
  let checks = 0;
  for (let i = 0; i <= end; i++) {
    const c = i < end ? text.charCodeAt(i) : 10;
    if (isLetter(c)) {
      if (start < 0) start = i;
      continue;
    }
    if (start >= 0) {
      if (!bad) {
        const w = text.slice(start, i);
        // List words are 3 to 8 letters.
        const id = w.length < 3 || w.length > 8 ? undefined : WORD_INDEX.get(UPPER.test(w) ? w.toLowerCase() : w);
        if (id === undefined || ids.length === 24) bad = true;
        else ids.push(id);
      }
      start = -1;
    }
    if (c < 128 && IN_PHRASE[c]) continue;
    if (!bad && SEED_LENGTHS.includes(ids.length)) {
      if (++checks > SEED_CHECKS_MAX) return false;
      if (!sortedList(ids) && seedChecksum(ids, 0, ids.length)) return true;
    }
    ids = [];
    bad = false;
  }
  return false;
}

const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Ok(addr: string): boolean {
  const s = addr.toLowerCase();
  if (addr !== s && addr !== addr.toUpperCase()) return false;
  const sep = s.lastIndexOf("1");
  const hrp = s.slice(0, sep);
  const values = [...hrp].map((c) => c.charCodeAt(0) >> 5);
  values.push(0, ...[...hrp].map((c) => c.charCodeAt(0) & 31));
  for (const c of s.slice(sep + 1)) {
    const v = BECH32_CHARS.indexOf(c);
    if (v < 0) return false;
    values.push(v);
  }
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk = (chk ^ BECH32_GEN[i]) >>> 0;
  }
  return chk === 1 || chk === 0x2bc830a3;
}

const ETH_RE = /^0x[0-9a-fA-F]{40}$/;
const BTC_LEGACY_RE = /^[13][1-9A-HJ-NP-Za-km-z]{25,33}$/;
const BTC_BECH32_RE = /^(bc1|BC1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}$/;
/** A crypto wallet address (public; a note, never a block): an Ethereum address, a Base58Check
 * address of version 0x00 or 0x05, or a bech32/bech32m address with the `bc` prefix. */
export function isWalletAddress(tok: string): boolean {
  if (ETH_RE.test(tok)) return true;
  if (BTC_LEGACY_RE.test(tok)) {
    const p = base58Check(tok);
    return !!p && p.length === 21 && (p[0] === 0x00 || p[0] === 0x05);
  }
  return BTC_BECH32_RE.test(tok) && bech32Ok(tok);
}

const CARD_RUN = /[0-9](?:[ -]?[0-9]){12,18}/g;
const DIGIT = /[0-9]/;
const ALNUM = /[A-Za-z0-9]/;
/** A card number (a note): 13 to 19 digits, single spaces or hyphens allowed between them, the
 * first 2 to 6, not part of a longer number or a word, with a right Luhn check digit. */
export function hasCardNumber(text: string): boolean {
  for (const m of text.matchAll(CARD_RUN)) {
    const end = m.index! + m[0].length;
    if (m.index! > 0 && ALNUM.test(text[m.index! - 1])) continue;
    if (ALNUM.test(text[end] ?? "") || (/[ -]/.test(text[end] ?? "") && DIGIT.test(text[end + 1] ?? ""))) continue;
    const d = m[0].replace(/[ -]/g, "");
    if (d[0] < "2" || d[0] > "6") continue;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let x = d.charCodeAt(d.length - 1 - i) - 48;
      if (i % 2) {
        x *= 2;
        if (x > 9) x -= 9;
      }
      sum += x;
    }
    if (sum % 10 === 0) return true;
  }
  return false;
}

// --- instruction patterns (§8 hidden_instruction) -----------------------------------------

/** Read on `instructionText`, `\b` an ASCII word boundary; no look-around, so every regex
 * engine reads them alike. Written from public descriptions of prompt injection and tool
 * poisoning (OWASP Top 10 for LLM Applications, LLM01; published MCP tool-poisoning research). */
export const INSTRUCTION_PATTERNS: readonly string[] = [
  // override directives
  "\\b(ignore|disregard|forget|override|bypass) (all |any |the |of |your |these |those |my )*(previous|prior|above|earlier|preceding|former|original|initial|system|developer) (instructions?|directions|directives|rules|guidelines|prompts?|context|messages?)\\b",
  "\\b(ignore|disregard|forget) (all |of )*your (previous |prior |earlier )?(instructions|rules|guidelines|directions)\\b",
  "\\b(new|updated) instructions:",
  "</?(important|system)>",
  "\\bsystem (note|override):",
  // keeping it from the user
  "\\b(do not|don.t|dont|never|without) (tell|telling|inform|informing|mention|mentioning|reveal|revealing) (\\S+ ){0,5}(the )?user\\b",
  "\\b(hide|conceal) (this|these|it|that|them) (\\S+ ){0,3}from the user\\b",
  "\\bkeep (this|these|it|that|them) (\\S+ ){0,3}(secret|hidden) from the user\\b",
  // asking for the model's context or the machine's secrets
  "\\b(send|reveal|leak|append|prepend|disclose|exfiltrate|post|upload|forward|attach|share|include) (\\S+ ){0,3}(system prompt|hidden instructions|private context|initial instructions|developer instructions)\\b",
  "\\b(read|cat|send|include|append|prepend|attach|pass|concatenate|forward|copy|upload|post|call|fetch) (\\S+ ){0,6}\\S*(\\.ssh/|id_rsa|id_ed25519|id_ecdsa|id_dsa|\\.aws/credentials|/etc/shadow|\\.netrc|\\.npmrc|\\.pypirc|\\.git-credentials|\\.kube/config|\\.docker/config\\.json|credential files?|credentials files?|local credentials)",
  "\\$\\((env|printenv)\\b",
  "\\b(env|printenv)( \\| ?\\S+)* \\| ?(curl|wget|nc|base64)\\b",
  // steering the model away from its other tools
  "\\b(always|only) use this tool instead of\\b",
  "\\bthis tool (supersedes|overrides|replaces) (any|all|the) (default|built-in|builtin|other|existing)\\b",
  // sending everything of a kind to an address (spec 1.1)
  "\\b(send|forward|post|upload|copy|cc|bcc|report) (\\S+ ){0,4}(all|every|each|the full|the entire|the whole|a copy of) (\\S+ ){0,3}(emails?|messages?|conversations?|chats?|requests?|responses?|results?|data|contents?|files?|documents?|history|prompts?) (\\S+ ){0,4}to (https?://|\\S+@)",
  // asking for the contents of a credential file (spec 1.1)
  "\\b(provide|give|supply|paste|submit|share|collect|gather|dump) (\\S+ ){0,3}(contents?|text|value|body) of (\\S+ ){0,2}\\S*(\\.ssh/|id_rsa|id_ed25519|id_ecdsa|id_dsa|\\.aws/credentials|/etc/shadow|\\.netrc|\\.npmrc|\\.pypirc|\\.git-credentials|\\.kube/config|\\.docker/config\\.json|credential files?|credentials files?|local credentials)",
];
const INSTRUCTION_RES = INSTRUCTION_PATTERNS.map((p) => new RegExp(p));
/** For each pattern, text one of which a match always holds: a pattern is tried only on a text
 * that holds one, and a pattern with a space only on a text with a space (no effect on what
 * matches, only on the time it takes). */
const HINTS: readonly (readonly string[])[] = [
  ["ignore", "disregard", "forget", "override", "bypass"],
  ["ignore", "disregard", "forget"],
  ["instructions:"],
  ["important>", "system>"],
  ["system "],
  ["user"],
  ["from the user"],
  ["from the user"],
  ["system prompt", "hidden instructions", "private context", "initial instructions", "developer instructions"],
  [
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credential",
    "/etc/shadow",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".kube/config",
    ".docker/config.json",
  ],
  ["$("],
  ["|"],
  ["use this tool instead of"],
  ["this tool "],
  ["@", "://"],
  [
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credential",
    "/etc/shadow",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".kube/config",
    ".docker/config.json",
  ],
];
const HINTED = INSTRUCTION_RES.map((r, i) => [r, HINTS[i], INSTRUCTION_PATTERNS[i].includes(" ")] as const);

/** Covert data collection (spec 1.1), read on `instructionText`: a text that
 * matches one of `COLLECT_PATTERNS` (gather something, then send it to somewhere) and one of
 * `CONCEAL_PATTERNS` (keep it from the user) is an instruction phrase. Either alone is not:
 * "collects the logs and sends them to the monitoring endpoint" and "never disclose the API key"
 * are ordinary descriptions. */
export const COLLECT_PATTERNS: readonly string[] = [
  "\\b(collect|gather|harvest|compile|read|grab|copy|extract|scrape|dump) (\\S+ ){0,8}(and|then|and then) (\\S+ ){0,2}(send|submit|upload|post|forward|transmit|exfiltrate|relay|deliver|pass) (\\S+ ){0,6}to\\b",
];
export const CONCEAL_PATTERNS: readonly string[] = [
  "\\b(do not|don.t|dont|never|must not|should not|shall not|without) (mention|mentioning|disclose|disclosing|tell|telling|reveal|revealing|inform|informing|notify|notifying|alert|alerting)\\b",
  "\\b(must|should|shall|will|is to|are to|may) not be (mentioned|disclosed|revealed|told)\\b",
  "\\b(silently|secretly|covertly|quietly|discreetly|stealthily)\\b",
  "\\bwithout (the user|users|anyone|them) (knowing|noticing|seeing)\\b",
];
const COLLECT_RES = COLLECT_PATTERNS.map((p) => new RegExp(p));
const CONCEAL_RES = CONCEAL_PATTERNS.map((p) => new RegExp(p));
const COLLECT_HINTS = ["collect", "gather", "harvest", "compile", "read", "grab", "copy", "extract", "scrape", "dump"];

/** Whether instruction text `t` asks to gather data and send it on while keeping that from the user. */
export function hasCovertCollection(t: string): boolean {
  return (
    t.includes(" to") &&
    COLLECT_HINTS.some((h) => t.includes(h)) &&
    COLLECT_RES.some((r) => r.test(t)) &&
    CONCEAL_RES.some((r) => r.test(t))
  );
}

/** Whether `s` holds an instruction phrase (§8 hidden_instruction). */
export function hasInstruction(s: string): boolean {
  const t = instructionText(s);
  const space = t.includes(" ");
  return (
    (space && hasCovertCollection(t)) ||
    HINTED.some(([r, hint, needsSpace]) => (space || !needsSpace) && hint.some((h) => t.includes(h)) && r.test(t))
  );
}

/** Code points of the `invisible_characters` finding (§8 hidden_instruction), read on the string
 * as it came; U+FEFF counts anywhere but at the start. */
const INVISIBLE: [number, number][] = [
  [0xe0000, 0xe007f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
];
export function hasInvisible(s: string): boolean {
  if (PLAIN.test(s)) return false;
  let first = true;
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (INVISIBLE.some(([lo, hi]) => lo <= c && c <= hi) || (c === 0xfeff && !first)) return true;
    first = false;
  }
  return false;
}

// --- look-alike letters in tokens and host names (§8 secret, address) ----------------------

const LOOKALIKE = new Map<number, string>(INSTRUCTION_CONFUSABLES);
const WIDE_TOKEN = /[\p{L}\p{N}_-]+/gu;
const HAS_ASCII_ALNUM = /[A-Za-z0-9]/;
const HAS_NOT_ASCII = /[^\x00-\x7f]/;
const isUpperChar = (ch: string): boolean => ch !== ch.toLowerCase() && ch === ch.toUpperCase();

/** The tokens of `text` that mix ASCII letters or digits with letters of another script, each
 * with every non-ASCII letter replaced by the Latin letter `INSTRUCTION_CONFUSABLES` gives it
 * (upper case for an upper-case letter). A token with a letter the table does not map is left
 * out. The `secret` check reads these for the table's formats only, so a mapping can only add a
 * finding a real token in the same place would give, never change a token that is not one. */
export function lookalikeTokens(text: string): string[] {
  if (PLAIN.test(text)) return [];
  const out: string[] = [];
  for (const m of text.matchAll(WIDE_TOKEN)) {
    const tok = m[0];
    if (!HAS_ASCII_ALNUM.test(tok) || !HAS_NOT_ASCII.test(tok)) continue;
    let s = "";
    let ok = true;
    for (const ch of tok) {
      const c = ch.codePointAt(0)!;
      if (c < 128) {
        s += ch;
        continue;
      }
      const l = LOOKALIKE.get(c);
      if (l === undefined) {
        ok = false;
        break;
      }
      s += isUpperChar(ch) ? l.toUpperCase() : l;
    }
    if (ok) out.push(s);
  }
  return out;
}

// --- look-alike tool names (§8 hidden_instruction: look_alike_name) -------------------------

/** The scripts whose letters pass for Latin ones, as code point ranges (spec 1.1): a tool name holding letters (general category L, after NFKC) of two of them mixes
 * scripts. Letters of other scripts (Han, Arabic, ...) are left out. */
export const NAME_SCRIPTS: readonly [string, readonly [number, number][]][] = [
  [
    "Latin",
    [
      [0x41, 0x5a],
      [0x61, 0x7a],
      [0xaa, 0xaa],
      [0xba, 0xba],
      [0xc0, 0xd6],
      [0xd8, 0xf6],
      [0xf8, 0x2af],
      [0x1d00, 0x1dbf],
      [0x1e00, 0x1eff],
      [0x2c60, 0x2c7f],
      [0xa720, 0xa7ff],
      [0xab30, 0xab6f],
    ],
  ],
  [
    "Greek",
    [
      [0x370, 0x3ff],
      [0x1f00, 0x1fff],
    ],
  ],
  [
    "Cyrillic",
    [
      [0x400, 0x52f],
      [0x1c80, 0x1c8f],
      [0xa640, 0xa69f],
    ],
  ],
  [
    "Armenian",
    [
      [0x531, 0x58f],
      [0xfb13, 0xfb17],
    ],
  ],
  [
    "Cherokee",
    [
      [0x13a0, 0x13ff],
      [0xab70, 0xabbf],
    ],
  ],
];
const LETTER = /^\p{L}$/u;

/** Whether a tool name mixes scripts (`NAME_SCRIPTS`): `reаd_file` with a Cyrillic `а`. */
export function mixedScripts(name: string): boolean {
  if (PLAIN.test(name)) return false;
  let seen = -1;
  for (const ch of name.normalize("NFKC")) {
    const c = ch.codePointAt(0)!;
    if (c < 128 ? !isLetter(c) : !LETTER.test(ch)) continue;
    const k = NAME_SCRIPTS.findIndex(([, rs]) => rs.some(([lo, hi]) => lo <= c && c <= hi));
    if (k < 0) continue;
    if (seen >= 0 && k !== seen) return true;
    seen = k;
  }
  return false;
}

const SKELETONS = new Map<string, string>();
/** A tool name as a reader takes it: its instruction text (NFKC, marks taken out, look-alike
 * letters mapped to Latin), lowercased. `reаd_file`, `Read_File` and `read_file` have one skeleton. */
export function nameSkeleton(name: string): string {
  let v = SKELETONS.get(name);
  if (v === undefined) {
    v = instructionText(name).toLowerCase();
    if (SKELETONS.size >= 4096) SKELETONS.clear();
    SKELETONS.set(name, v);
  }
  return v;
}

/** Whether a tool's name passes for another's (§8 hidden_instruction, `look_alike_name`): it mixes
 * scripts, or it has the skeleton of a name in `others` (the other tools listed with it) or
 * `approved` (the tools approved earlier for the agent and the server) while differing from it. */
export function lookAlikeName(name: string, others: readonly string[] = [], approved: readonly string[] = []): boolean {
  if (!name) return false;
  if (mixedScripts(name)) return true;
  const sk = nameSkeleton(name);
  for (const list of [others, approved]) for (const o of list) if (o !== name && nameSkeleton(o) === sk) return true;
  return false;
}

/** RFC 3492: the Unicode label a Punycode label (without `xn--`) stands for; null when invalid. */
export function punycodeDecode(input: string): string | null {
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const adapt = (delta: number, points: number, first: boolean): number => {
    delta = first ? Math.floor(delta / 700) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > ((base - tmin) * tmax) >> 1) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    return k + Math.floor(((base - tmin + 1) * delta) / (delta + 38));
  };
  if (input.length > 63) return null;
  const b = input.lastIndexOf("-");
  const out: number[] = [];
  for (let j = 0; j < Math.max(b, 0); j++) {
    const c = input.charCodeAt(j);
    if (c >= 128) return null;
    out.push(c);
  }
  let n = 128;
  let i = 0;
  let bias = 72;
  for (let idx = b >= 0 ? b + 1 : 0; idx < input.length;) {
    const old = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) return null;
      const c = input.charCodeAt(idx++);
      const d = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base;
      if (d >= base) return null;
      i += d * w;
      if (i > 0x10ffff * 64) return null;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    const len = out.length + 1;
    bias = adapt(i - old, len, old === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    out.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...out);
}

/** A host name as a reader takes it (§8 address): each `xn--` label Punycode-decoded, then read
 * as instruction text (marks taken out, `INSTRUCTION_CONFUSABLES` mapped, lowercased). Null when
 * the host is plain ASCII without an `xn--` label, or when it does not read as plain ASCII. */
export function hostLookalike(host: string): string | null {
  if (!HAS_NOT_ASCII.test(host) && !host.includes("xn--")) return null;
  const labels = host.split(".").map((l) => (l.startsWith("xn--") ? (punycodeDecode(l.slice(4)) ?? l) : l));
  const t = instructionText(labels.join("."));
  return t !== host && !HAS_NOT_ASCII.test(t) ? t : null;
}

// --- secrets without a known format (§8 secret: named secrets, JWTs, bearer values) -----------

/** Letters of a name: camelCase split, lowercased, cut at anything but a letter or a digit. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 0);
}

const SECRET_WORDS = new Set(["pwd", "auth", "authorization", "session", "sessionid", "passphrase"]);
const SECRET_PARTS = ["password", "passwd", "secret", "token", "apikey", "privatekey", "credential"];
const SECRET_PAIRS: [string, string][] = [
  ["api", "key"],
  ["private", "key"],
];
/** Words that make a name about a secret rather than the secret itself (a token's type, a
 * password's hint, a page token, a session's URL). */
export const NOT_SECRET_WORDS = new Set([
  "page",
  "next",
  "prev",
  "previous",
  "continuation",
  "cursor",
  "count",
  "counts",
  "max",
  "min",
  "limit",
  "length",
  "size",
  "type",
  "kind",
  "mode",
  "method",
  "scheme",
  "provider",
  "name",
  "url",
  "uri",
  "endpoint",
  "host",
  "domain",
  "path",
  "file",
  "filename",
  "dir",
  "hint",
  "label",
  "description",
  "expires",
  "expiry",
  "expiration",
  "ttl",
  "timeout",
  "format",
  "field",
  "policy",
  "version",
  "header",
  "usage",
  "used",
  "encoding",
  "algorithm",
  "alg",
  "required",
  "enabled",
  "public",
]);

/** Whether a name (an argument's member name, an environment variable, the name of a `NAME=value`
 * pair) says its value is a secret. `query`: a URL query or fragment parameter, where `key` also
 * names one (`?key=`). */
export function secretName(name: string, query = false): boolean {
  const w = nameWords(name);
  if (!w.length || w.some((x) => NOT_SECRET_WORDS.has(x))) return false;
  if (w.some((x) => SECRET_WORDS.has(x) || SECRET_PARTS.some((p) => x.includes(p)))) return true;
  for (let i = 1; i < w.length; i++) if (SECRET_PAIRS.some(([a, b]) => w[i - 1] === a && w[i] === b)) return true;
  return query && w.includes("key");
}

const PLACEHOLDER_PARTS = [
  "changeme",
  "change_me",
  "change-me",
  "placeholder",
  "your_",
  "your-",
  "yourkey",
  "yourtoken",
  "yoursecret",
  "yourpassword",
  "redacted",
  "dummy",
  "xxxx",
  "****",
  "....",
];
const PLACEHOLDER_WORDS = new Set([
  "password",
  "secret",
  "token",
  "null",
  "none",
  "true",
  "false",
  "undefined",
  "example",
]);
const REPEATED = /^(.)\1*$/;
/** An obvious placeholder: `changeme`, `xxxx`, `<...>`, `${...}`, `{{...}}`, `$NAME`, `%(...)s`, one repeated character. */
export function isPlaceholder(v: string): boolean {
  const l = v.toLowerCase();
  if (REPEATED.test(l) || PLACEHOLDER_WORDS.has(l)) return true;
  if (
    (l.startsWith("<") && l.endsWith(">")) ||
    l.startsWith("${") ||
    l.startsWith("{{") ||
    l.startsWith("%(") ||
    /^\$[a-z_][a-z0-9_]*$/.test(l)
  )
    return true;
  return PLACEHOLDER_PARTS.some((p) => l.includes(p));
}

function entropyOf(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = [...s].length;
  let h = 0;
  for (const k of counts.values()) h -= (k / n) * Math.log2(k / n);
  return h;
}

function classes(v: string): number {
  return (
    (/[a-z]/.test(v) ? 1 : 0) + (/[A-Z]/.test(v) ? 1 : 0) + (/[0-9]/.test(v) ? 1 : 0) + (/[^A-Za-z0-9]/.test(v) ? 1 : 0)
  );
}

const SPACE = /[ \t\n\r\f\v]/;
/** A value that looks random enough to be a secret: at least 16 characters, no whitespace, not a
 * placeholder or a URL, at least 3.0 bits of entropy per character, and three kinds of character
 * (lower case, upper case, digits, others), or two with digits over at least 20 characters. */
export function looksRandom(v: string): boolean {
  if ([...v].length < 16 || SPACE.test(v) || v.includes("://") || isPlaceholder(v)) return false;
  if (entropyOf(v) < 3.0) return false;
  const k = classes(v);
  return k >= 3 || (k >= 2 && /[0-9]/.test(v) && [...v].length >= 20);
}

/** A value in an environment dump (several `NAME=value` lines): at least 8 characters, no
 * whitespace, not a placeholder. */
export function dumpValue(v: string): boolean {
  return [...v].length >= 8 && !SPACE.test(v) && !isPlaceholder(v);
}

const ENV_LINE = /^[ \t]*(export[ \t]+)?[A-Z_][A-Z0-9_]{1,63}=/;
/** An environment dump: at least 3 lines of the form `NAME=value` (`export NAME=value`). */
export function isEnvDump(text: string): boolean {
  let n = 0;
  for (const line of text.slice(0, PAIRS_SCAN_MAX).split("\n")) if (ENV_LINE.test(line) && ++n >= 3) return true;
  return false;
}

/** At most this many characters of one text are read for `NAME=value` pairs (1 MiB). */
export const PAIRS_SCAN_MAX = 1 << 20;
/** A pair's value: up to whitespace, a quote, `&`, `;`, `,`, `<`, `>`, `?` or `#`, at most 512 characters. */
export const PAIR_VALUE_RE = /[^ \t\n\r\f\v"'&;,<>?#]{1,512}/y;
const NAME_PART = table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-");
const NAME_START = table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_");
const isIn = (t: Uint8Array, c: number): boolean => c < 128 && t[c] === 1;

/** The `[name, value, start]` pairs of a text (§8 secret): a `NAME=value` or `NAME: value` pair,
 * quotes allowed around both as in JSON or YAML. Read from each `:` and `=`: before it optional
 * spaces or tabs, an optional quote, then the name, the last 1 to 64 of `[A-Za-z0-9_.-]`, cut to
 * start at a letter or `_`; after it optional spaces or tabs, an optional quote, then the value
 * (`PAIR_VALUE_RE`). So a value never hides a pair inside it, and the work is linear. */
export function* pairs(t: string): Generator<[string, string, number]> {
  let colon = t.indexOf(":");
  let equals = t.indexOf("=");
  while (colon >= 0 || equals >= 0) {
    const i = colon < 0 ? equals : equals < 0 ? colon : Math.min(colon, equals);
    if (i === colon) colon = t.indexOf(":", i + 1);
    else equals = t.indexOf("=", i + 1);
    let j = i - 1;
    while (j >= 0 && (t.charCodeAt(j) === 32 || t.charCodeAt(j) === 9)) j--;
    if (j >= 0 && (t.charCodeAt(j) === 34 || t.charCodeAt(j) === 39)) j--;
    const end = j + 1;
    let k = end;
    while (k > 0 && end - k < 64 && isIn(NAME_PART, t.charCodeAt(k - 1))) k--;
    while (k < end && !isIn(NAME_START, t.charCodeAt(k))) k++;
    if (k >= end) continue;
    let v = i + 1;
    while (v < t.length && (t.charCodeAt(v) === 32 || t.charCodeAt(v) === 9)) v++;
    if (v < t.length && (t.charCodeAt(v) === 34 || t.charCodeAt(v) === 39)) v++;
    PAIR_VALUE_RE.lastIndex = v;
    const m = PAIR_VALUE_RE.exec(t);
    if (m) yield [t.slice(k, end), m[0], k];
  }
}

/** A JSON Web Token: three base64url parts, the first two JSON objects (`eyJ`). */
export const JWT_RE = /eyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*/g;
/** A JWT whose header decodes to a JSON object with a string `alg`. */
export function isJwt(tok: string): boolean {
  const head = tok.split(".", 1)[0];
  if (head.length % 4 === 1) return false;
  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b64Bytes(head)));
  } catch {
    return false;
  }
  return (
    !!doc && typeof doc === "object" && !Array.isArray(doc) && typeof (doc as Record<string, unknown>).alg === "string"
  );
}

/** A bearer credential in text (`Bearer <value>`, any case). */
export const BEARER_RE = /\bbearer[ \t]+([A-Za-z0-9._~+/=-]{16,})/gi;

// --- obfuscated tokens (§8 secret): reversed, separator-joined, split across members -------

/** Strings longer than this are not reversed or joined (4 KiB): a token hidden that way is short. */
export const OBFUSCATION_MAX = 4096;
export const SEPARATORS = /[ \t\n\r\f\v.:|,\\*-]/g;
/** The start of each whole-token format of the table (§8), for joining split members. */
export const TOKEN_PREFIXES = [
  "ghp_",
  "gho_",
  "ghu_",
  "ghs_",
  "ghr_",
  "github_pat_",
  "AKIA",
  "ASIA",
  "sk_live_",
  "sk_test_",
  "rk_live_",
  "rk_test_",
  "xoxa-",
  "xoxb-",
  "xoxp-",
  "xoxo-",
  "xoxs-",
  "xoxr-",
  "sk-ant-",
  "sk-proj-",
  "AIza",
  "sfa_test_",
  "sfa_live_",
  "sfa_user_",
];
const literal = (p: string): string => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const REVERSED_PREFIX_RE = new RegExp(TOKEN_PREFIXES.map((p) => literal([...p].reverse().join(""))).join("|"));
const PREFIX_RE = new RegExp(TOKEN_PREFIXES.map(literal).join("|"));
/** Whether a string may hold a format's token once reversed: it holds a prefix reversed. */
export const mayHoldReversed = (s: string): boolean => REVERSED_PREFIX_RE.test(s);
/** Whether a text holds the start of a format of the table. */
export const holdsPrefix = (s: string): boolean => PREFIX_RE.test(s);
const startsToken = (v: string): boolean =>
  TOKEN_PREFIXES.some((p) => v.startsWith(p) || (v.length >= 2 && p.startsWith(v)));
/** At most this many members of one object are joined, at most 4 at a time, at most this many
 * joins per call. */
export const JOIN_MEMBERS_MAX = 16;
export const JOINS_MAX = 4096;

/** The joins of an object's short string members (§8 secret, split across members): for each
 * object in `value`, its string members of 1 to 64 characters (the first `JOIN_MEMBERS_MAX`, in
 * JCS order, read normalised), every ordered choice of 2 to 4 of them that starts with a member
 * that starts a format of the table, joined. At most `JOINS_MAX` joins. */
export function memberJoins(value: unknown): string[] {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (out.length >= JOINS_MAX) return;
    if (Array.isArray(v)) {
      for (const x of v) walk(x);
      return;
    }
    if (!v || typeof v !== "object") return;
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const x = o[k];
      if (typeof x === "string" && parts.length < JOIN_MEMBERS_MAX && x.length <= 256) {
        const s = normalise(x);
        if (s.length >= 1 && s.length <= 64) parts.push(s);
      }
    }
    const grow = (have: number[], text: string): void => {
      for (let i = 0; i < parts.length && out.length < JOINS_MAX; i++) {
        if (have.includes(i)) continue;
        const t = text + parts[i];
        out.push(t);
        if (have.length + 1 < 4) grow([...have, i], t);
      }
    };
    for (let i = 0; i < parts.length && out.length < JOINS_MAX; i++) if (startsToken(parts[i])) grow([i], parts[i]);
    for (const k of keys) walk(o[k]);
  };
  walk(value);
  return out;
}

// --- unreadable content in what a tool shows (§8 hidden_instruction: encoded_content) ---------

const MAGIC: number[][] = [
  [0x25, 0x50, 0x44, 0x46, 0x2d], // %PDF-
  [0x50, 0x4b, 0x03, 0x04], // ZIP
  [0x50, 0x4b, 0x05, 0x06],
  [0x1f, 0x8b], // gzip
  [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], // 7z
  [0x52, 0x61, 0x72, 0x21], // Rar!
  [0x42, 0x5a, 0x68], // bzip2
  [0x7f, 0x45, 0x4c, 0x46], // ELF
  [0x4d, 0x5a, 0x90, 0x00], // a Windows executable
  [0xca, 0xfe, 0xba, 0xbe], // Mach-O universal, Java class
  [0x00, 0x61, 0x73, 0x6d], // WebAssembly
  [0xd0, 0xcf, 0x11, 0xe0], // an OLE document
];
const IMAGE_MAGIC: number[][] = [
  [0x89, 0x50, 0x4e, 0x47], // PNG
  [0xff, 0xd8, 0xff], // JPEG
  [0x47, 0x49, 0x46, 0x38], // GIF8
  [0x52, 0x49, 0x46, 0x46], // RIFF (WebP)
  [0x00, 0x00, 0x01, 0x00], // ICO
];
const startsWithAny = (b: Uint8Array, list: number[][]): boolean =>
  list.some((m) => b.length >= m.length && m.every((x, i) => b[i] === x));
/** Decoded bytes that start as a binary file: a document, an archive, an executable or an image. */
export const binaryMagic = (b: Uint8Array): boolean => startsWithAny(b, MAGIC) || startsWithAny(b, IMAGE_MAGIC);
const imageMagic = (b: Uint8Array): boolean => startsWithAny(b, IMAGE_MAGIC);
function nonTextShare(b: Uint8Array): number {
  if (!b.length) return 0;
  let k = 0;
  for (const x of b) if (!((x >= 0x20 && x <= 0x7e) || x === 9 || x === 10 || x === 13)) k++;
  return k / b.length;
}

/** A base64 data URI. */
export const DATA_URI = /data:([A-Za-z0-9.+/-]*)((?:;[A-Za-z0-9=.+-]*)*);base64,([A-Za-z0-9+/_-]{16,})/gi;
/** Base64 runs this long that decode to mostly non-text bytes are unreadable whatever they start with. */
export const OPAQUE_RUN_MIN = 256;
/** Base64 runs this long (12 bytes) are read for a binary file's start. */
export const MAGIC_RUN_MIN = 16;

/** Whether a string of what a tool shows (§8 hidden_instruction, `encoded_content`) carries
 * content a reader cannot read: a base64 data URI (except an image in a member named `src`, the
 * icon of a tool, when it decodes to an image or is SVG), a base64 run of 16 or more characters
 * that decodes to a binary file's start, or a run of `OPAQUE_RUN_MIN` or more that decodes to
 * more than a quarter non-text bytes. Decoding is bounded by `budget`. */
export function hasEncodedContent(s: string, name: string | null, budget: Budget = { left: DECODE_BUDGET }): boolean {
  let rest = s;
  for (const m of s.matchAll(DATA_URI)) {
    const type = m[1].toLowerCase();
    if (name === "src" && type.startsWith("image/")) {
      const head = b64Bytes(m[3].slice(0, 64));
      if (type === "image/svg+xml" || imageMagic(head)) {
        rest = rest.replace(m[0], " ");
        continue;
      }
    }
    return true;
  }
  for (const run of runs(rest, IS_B64, MAGIC_RUN_MIN)) {
    if (allHex(run)) continue;
    if (run.length > budget.left) {
      budget.left = 0;
      return false;
    }
    budget.left -= run.length;
    const b = b64Bytes(run);
    if (binaryMagic(b)) return true;
    if (run.length >= OPAQUE_RUN_MIN && nonTextShare(b) > 0.25) return true;
  }
  return false;
}

// --- cross-tool shadowing (§8 hidden_instruction: tool_shadowing) -----------------------------

/** Read on `instructionText` (after `markTools`). These need nothing else: steering every call
 * through this tool. */
export const SHADOW_PATTERNS: readonly string[] = [
  "\\b(always|you must|must always|you should always) (first )?(call|use|invoke|run) this tool (first|before)\\b",
  "\\bbefore (using|calling|invoking|running) (any|every|all|another) (other )?tools?,? (\\S+ ){0,3}(call|use|invoke|run) this tool\\b",
];
/** These count only when the text they match names another tool (`refersToOtherTool`): a
 * redirect of the user's use of another tool through this one, or a change to what another tool
 * does with data. */
export const SHADOW_REF_PATTERNS: readonly string[] = [
  "\\b(when|whenever|every time|each time|if|once) (the user|a user|users|you|the agent|the assistant|the model) (\\S+ ){0,4}(use|uses|using|call|calls|calling|invoke|invokes|invoking|run|runs|running) (\\S+ ){0,3}tools?\\b(\\S* ){0,8}(call|use|invoke|run) this tool\\b",
  "\\b\\S+ tools? (must|should|shall|has to|needs to|is required to) (always |only |also |now )*(send|forward|cc|bcc|redirect|route|copy|report|post|upload)\\b",
  "\\b(when|whenever|while|every time|each time|before|after) (using|calling|invoking|running) (\\S+ ){0,3}tools?,? (\\S+ ){0,3}(always |also |you must |must |make sure to |be sure to )*(send|forward|cc|bcc|redirect|route|copy)\\b",
];
const SHADOW_RES = SHADOW_PATTERNS.map((p) => new RegExp(p));
const SHADOW_REF_RES = SHADOW_REF_PATTERNS.map((p) => new RegExp(p, "g"));
/** Words before "tool" that name no other tool. */
export const SELF_WORDS = new Set([
  "this",
  "that",
  "same",
  "the",
  "a",
  "an",
  "its",
  "our",
  "my",
  "your",
  "which",
  "each",
  "current",
]);
const TOOL_REF = /(\S+) tools?\b/g;
const EDGE = /^[^a-z0-9]+|[^a-z0-9]+$/g;

/** Whether a matched span names a tool other than `self` ("the send_email tool", "any other tool"). */
export function refersToOtherTool(span: string, self: string): boolean {
  for (const m of span.matchAll(TOOL_REF)) {
    const w = m[1].replace(EDGE, "");
    if (w && !SELF_WORDS.has(w) && w !== self) return true;
  }
  return false;
}

const NAME_CHAR = /[a-z0-9_-]/;
const FOLLOWED_BY_TOOL = /^['"`]? tools?\b/;
/** Instruction text with " tool" written after each mention of another listed tool's name (read
 * as instruction text) that is not followed by "tool" already, so the patterns read "send_email"
 * as "send_email tool". */
export function markTools(t: string, others: readonly string[]): string {
  const at: [number, number][] = [];
  for (const o of others) {
    if (o.length < 2) continue;
    for (let i = t.indexOf(o); i >= 0; i = t.indexOf(o, i + 1)) {
      const end = i + o.length;
      if ((i > 0 && NAME_CHAR.test(t[i - 1])) || (end < t.length && NAME_CHAR.test(t[end]))) continue;
      if (FOLLOWED_BY_TOOL.test(t.slice(end, end + 8))) continue;
      at.push([end + (end < t.length && "'\"`".includes(t[end]) ? 1 : 0), i]);
    }
  }
  if (!at.length) return t;
  const cuts = [...new Set(at.map((x) => x[0]))].sort((a, b) => a - b);
  let out = "";
  let from = 0;
  for (const c of cuts) {
    out += t.slice(from, c) + " tool";
    from = c;
  }
  return out + t.slice(from);
}

/** Whether a string of a tool's definition instructs about other tools (§8 hidden_instruction,
 * `tool_shadowing`). `self` is the tool's name and `others` the names of the other tools listed
 * with it, when known. */
export function hasShadowing(s: string, self = "", others: readonly string[] = []): boolean {
  let t = instructionText(s);
  if (!t.includes(" ") || !t.includes("tool")) return false; // every pattern needs a space and "tool"
  const me = self ? instructionText(self) : "";
  const named = others.map((o) => instructionText(o)).filter((o) => o && o !== me);
  if (named.length) t = markTools(t, named);
  if (SHADOW_RES.some((r) => r.test(t))) return true;
  for (const r of SHADOW_REF_RES) for (const m of t.matchAll(r)) if (refersToOtherTool(m[0], me)) return true;
  return false;
}
