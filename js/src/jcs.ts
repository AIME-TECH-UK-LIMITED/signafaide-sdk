/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Numbers use ECMAScript Number serialization, object keys are sorted by UTF-16
 * code units, strings are escaped like JSON.stringify. Lone surrogates, NaN and
 * Infinity are rejected. Object properties whose value is `undefined` are skipped,
 * as in JSON. Values the SDK signs itself also pass `assertPortableNumbers` (SPEC §1).
 */

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const encoder = new TextEncoder();

/**
 * A number literal that a plain JS number would misrepresent, from {@link parseJson}:
 * an integer literal beyond ±(2^53−1) (JCS rejects it, as Rust and Python do), or a float
 * literal with an integral value such as `1.0` (JCS writes the double; schema checks
 * that need an integer reject it, as Rust and Python do).
 */
export class JsonNumber {
  constructor(
    readonly text: string,
    readonly value: number,
    readonly unsafeInteger: boolean,
  ) {}
  toJSON(): number {
    return this.value;
  }
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (value instanceof JsonNumber) {
    if (value.unsafeInteger) throw new RangeError(`unsafe_integer: integer ${value.text} is outside ±(2^53-1) and cannot be canonicalized exactly`);
    if (!Number.isFinite(value.value)) throw new RangeError(`number ${value.text} is not a finite IEEE 754 double`);
    return JSON.stringify(value.value);
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new RangeError("JCS does not allow NaN or Infinity");
      return JSON.stringify(value);
    case "string":
      if (LONE_SURROGATE.test(value)) throw new RangeError("JCS strings must not contain lone surrogates");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError(`JCS cannot encode ${(value as object).constructor?.name ?? "this object"}`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return "{" + keys.map((k) => canonicalize(k) + ":" + canonicalize(obj[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`JCS cannot encode ${typeof value}`);
  }
}

export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalize(value));
}

/** Numbers JavaScript writes as integer literals beyond +-(2^53-1). */
export const isUnsafeInteger = (x: number): boolean => Number.isInteger(x) && Math.abs(x) > Number.MAX_SAFE_INTEGER && Math.abs(x) < 1e21;

/**
 * SPEC §1: JavaScript cannot see literals, so content it canonicalizes itself must not
 * hold integer-valued numbers with 2^53 <= |x| < 1e21 (JSON.stringify writes them as
 * integer literals, which other implementations reject). Throws on the first one.
 */
export function assertPortableNumbers(value: unknown): void {
  if (typeof value === "number" && isUnsafeInteger(value)) throw new RangeError(`unsafe_integer: ${value} is beyond +-(2^53-1); send it as a string`);
  if (value && typeof value === "object") for (const v of Object.values(value)) assertPortableNumbers(v);
}

/**
 * Parse JSON keeping what each number literal was (SPEC §1): integer literals beyond
 * ±(2^53−1) and integral float literals become {@link JsonNumber}; every other number is a
 * plain number. Verifiers parse packs with this, so they judge literals like Rust and Python.
 * NaN, Infinity and trailing text are rejected, as in JSON.parse.
 */
export function parseJson(text: string): any {
  let i = 0;
  const fail = (what: string): never => {
    throw new SyntaxError(`JSON: ${what} at position ${i}`);
  };
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const value = (depth: number): any => {
    if (depth > 512) fail("nested too deeply");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const out: Record<string, unknown> = {};
      ws();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected a string key");
        const k = str();
        ws();
        if (text[i++] !== ":") fail("expected ':'");
        Object.defineProperty(out, k, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "}") {
          i++;
          return out;
        } else fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const out: unknown[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return out;
      }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "]") {
          i++;
          return out;
        } else fail("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return v;
      }
    }
    const m = /^-?(?:0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i, i + 400));
    if (!m) fail("unexpected character");
    i += m![0].length;
    const lit = m![0];
    const v = Number(lit);
    if (!m![1] && !m![2]) return Math.abs(v) <= Number.MAX_SAFE_INTEGER ? v : new JsonNumber(lit, v, true);
    return Number.isInteger(v) ? new JsonNumber(lit, v, false) : v;
  };
  const str = (): string => {
    const start = i;
    i++;
    let raw = false;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") {
        raw = true;
        i++;
      } else if (text.charCodeAt(i) < 0x20) fail("control character in a string");
      i++;
    }
    if (i >= text.length) fail("unterminated string");
    i++;
    const s = text.slice(start, i);
    return raw ? JSON.parse(s) : s.slice(1, -1);
  };
  const out = value(0);
  ws();
  if (i !== text.length) fail("trailing text");
  return out;
}
