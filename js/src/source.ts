/**
 * Reading JavaScript and TypeScript source for `signafaide protect`: a tokenizer that knows
 * strings, template literals, comments and regular expression literals, so a `//` inside a string
 * or a brace inside a template is never read as code; and a line diff to show a change before it
 * is written. It never throws: text it cannot read ends the token list early.
 */

export type TokenType = "id" | "str" | "tpl" | "num" | "re" | "p";

export interface Token {
  t: TokenType;
  /** The token's text (for `str`, the text between the quotes, unescaped only for plain letters). */
  v: string;
  /** Offsets in the source: `src.slice(s, e)` is the token. */
  s: number;
  e: number;
  /** The block comment that ends right before the token (JSDoc), when there is one. */
  doc?: string;
}

const ID_START = /[A-Za-z_$ -￿]/;
const ID_PART = /[\w$ -￿]/;
/** After these words a `/` starts a regular expression, not a division. */
const BEFORE_REGEX = new Set([
  "return",
  "typeof",
  "instanceof",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "throw",
  "case",
  "do",
  "else",
  "yield",
  "await",
]);

/** The tokens of `src`, comments left out. */
export function tokenize(src: string): Token[] {
  const out: Token[] = [];
  let doc: string | undefined;
  let i = 0;
  const n = src.length;
  const push = (t: TokenType, s: number, e: number, v = src.slice(s, e)): void => {
    out.push(doc !== undefined ? { t, v, s, e, doc } : { t, v, s, e });
    doc = undefined;
  };
  /** The end of a quoted string that starts at `at`. A string cut by a line end ends there. */
  const stringEnd = (at: number): number => {
    const q = src[at];
    let j = at + 1;
    while (j < n && src[j] !== q) {
      if (src[j] === "\\") j++;
      else if (src[j] === "\n") return j;
      j++;
    }
    return Math.min(j + 1, n);
  };
  /** The end of the template literal that starts at `at` (its `${...}` parts read as code). */
  const templateEnd = (at: number): number => {
    let j = at + 1;
    while (j < n) {
      const c = src[j];
      if (c === "\\") j += 2;
      else if (c === "`") return j + 1;
      else if (c === "$" && src[j + 1] === "{") j = codeEnd(j + 2);
      else j++;
    }
    return n;
  };
  /** The end of code up to the `}` that closes a `${` (that `}` included). */
  const codeEnd = (at: number): number => {
    let depth = 0;
    let j = at;
    while (j < n) {
      const c = src[j];
      if (c === "'" || c === '"') j = stringEnd(j);
      else if (c === "`") j = templateEnd(j);
      else if (c === "/" && src[j + 1] === "/") j = lineEnd(j);
      else if (c === "/" && src[j + 1] === "*") j = blockEnd(j);
      else if (c === "{") depth++, j++;
      else if (c === "}") {
        if (depth === 0) return j + 1;
        depth--;
        j++;
      } else j++;
    }
    return n;
  };
  const lineEnd = (at: number): number => {
    const k = src.indexOf("\n", at);
    return k < 0 ? n : k;
  };
  const blockEnd = (at: number): number => {
    const k = src.indexOf("*/", at + 2);
    return k < 0 ? n : k + 2;
  };
  const regexEnd = (at: number): number => {
    let j = at + 1;
    let cls = false;
    while (j < n) {
      const c = src[j];
      if (c === "\n") return j;
      if (c === "\\") j += 2;
      else if (c === "[") (cls = true), j++;
      else if (c === "]") (cls = false), j++;
      else if (c === "/" && !cls) {
        j++;
        while (j < n && /[a-z]/i.test(src[j])) j++;
        return j;
      } else j++;
    }
    return n;
  };
  const regexAllowed = (): boolean => {
    const p = out[out.length - 1];
    if (!p) return true;
    if (p.t === "id") return BEFORE_REGEX.has(p.v);
    if (p.t === "num" || p.t === "str" || p.t === "tpl" || p.t === "re") return false;
    return !(p.v === ")" || p.v === "]" || p.v === "}");
  };
  while (i < n) {
    const c = src[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v" || c === "﻿") {
      i++;
      continue;
    }
    if (c === "#" && i === 0 && src[1] === "!") {
      i = lineEnd(i);
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      i = lineEnd(i);
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const e = blockEnd(i);
      doc = src.slice(i, e);
      i = e;
      continue;
    }
    if (c === "'" || c === '"') {
      const e = stringEnd(i);
      push("str", i, e, src.slice(i + 1, Math.max(i + 1, e - 1)));
      i = e;
      continue;
    }
    if (c === "`") {
      const e = templateEnd(i);
      push("tpl", i, e);
      i = e;
      continue;
    }
    if (c === "/" && regexAllowed()) {
      const e = regexEnd(i);
      push("re", i, e);
      i = e;
      continue;
    }
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(src[i + 1] ?? ""))) {
      let j = i + 1;
      while (j < n && /[\w.]/.test(src[j])) j++;
      push("num", i, j);
      i = j;
      continue;
    }
    if (ID_START.test(c) || c === "\\") {
      let j = i + 1;
      while (j < n && ID_PART.test(src[j])) j++;
      push("id", i, j);
      i = j;
      continue;
    }
    if (c === "=" && src[i + 1] === ">") {
      push("p", i, i + 2);
      i += 2;
      continue;
    }
    if (c === "." && src[i + 1] === "." && src[i + 2] === ".") {
      push("p", i, i + 3);
      i += 3;
      continue;
    }
    push("p", i, i + 1);
    i++;
  }
  return out;
}

const OPEN: Record<string, string> = { "(": ")", "[": "]", "{": "}" };

/** The index of the token that closes the bracket at `i` (`(`, `[` or `{`); -1 when none. */
export function closing(toks: Token[], i: number): number {
  const open = toks[i]?.v;
  const close = OPEN[open];
  if (!close || toks[i].t !== "p") return -1;
  let depth = 0;
  for (let j = i; j < toks.length; j++) {
    const t = toks[j];
    if (t.t !== "p") continue;
    if (t.v in OPEN) depth++;
    else if (t.v === ")" || t.v === "]" || t.v === "}") {
      depth--;
      if (depth === 0) return t.v === close ? j : -1;
    }
  }
  return -1;
}

/** The parts of the token range [from, to) split at its top-level commas, as [start, end) index
 * ranges. Angle brackets count as brackets after a `:` (a type), so `Map<string, number>` is one
 * part. Empty parts (a trailing comma) are left out. */
export function splitTop(toks: Token[], from: number, to: number): [number, number][] {
  const out: [number, number][] = [];
  let depth = 0;
  let angle = 0;
  let inType = false;
  let start = from;
  for (let j = from; j < to; j++) {
    const t = toks[j];
    if (t.t !== "p") continue;
    if (t.v in OPEN) depth++;
    else if (t.v === ")" || t.v === "]" || t.v === "}") depth--;
    else if (depth === 0 && t.v === ":") inType = true;
    else if (depth === 0 && t.v === "=") inType = false;
    else if (inType && t.v === "<") angle++;
    else if (inType && t.v === ">" && angle > 0) angle--;
    else if (t.v === "," && depth === 0 && angle === 0) {
      if (j > start) out.push([start, j]);
      start = j + 1;
      inType = false;
    }
  }
  if (to > start) out.push([start, to]);
  return out;
}

/** The text of the tokens [from, to) of `src`, as written. */
export function textOf(src: string, toks: Token[], from: number, to: number): string {
  if (to <= from) return "";
  return src.slice(toks[from].s, toks[to - 1].e);
}

/** An edit of a text: replace [start, end) with `text`. */
export interface Edit {
  start: number;
  end: number;
  text: string;
}

/** `src` with the edits made (they must not overlap). */
export function applyEdits(src: string, edits: Edit[]): string {
  let out = src;
  for (const e of [...edits].sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

/** A unified line diff of `a` and `b` with `context` lines around each change, for a person to
 * read before a file is written (no file header). */
export function lineDiff(a: string, b: string, context = 2): string[] {
  const x = a.split("\n");
  const y = b.split("\n");
  // Common head and tail first, so a large file with a small change stays cheap.
  let head = 0;
  while (head < x.length && head < y.length && x[head] === y[head]) head++;
  let tail = 0;
  while (tail < x.length - head && tail < y.length - head && x[x.length - 1 - tail] === y[y.length - 1 - tail]) tail++;
  const xm = x.slice(head, x.length - tail);
  const ym = y.slice(head, y.length - tail);
  // LCS over the middle.
  const m = xm.length;
  const k = ym.length;
  const ops: [" " | "-" | "+", string][] = [];
  if (m * k > 4_000_000) {
    for (const l of xm) ops.push(["-", l]);
    for (const l of ym) ops.push(["+", l]);
  } else {
    const dp: Uint32Array[] = Array.from({ length: m + 1 }, () => new Uint32Array(k + 1));
    for (let i = m - 1; i >= 0; i--)
      for (let j = k - 1; j >= 0; j--)
        dp[i][j] = xm[i] === ym[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    let i = 0;
    let j = 0;
    while (i < m || j < k) {
      if (i < m && j < k && xm[i] === ym[j]) ops.push([" ", xm[i]]), i++, j++;
      else if (j < k && (i >= m || dp[i][j + 1] >= dp[i + 1][j])) ops.push(["+", ym[j]]), j++;
      else ops.push(["-", xm[i]]), i++;
    }
  }
  // Within each run of changes, the removed lines first, then the added ones.
  for (let i = 0; i < ops.length; ) {
    if (ops[i][0] === " ") {
      i++;
      continue;
    }
    let j = i;
    while (j < ops.length && ops[j][0] !== " ") j++;
    const run = ops.slice(i, j);
    ops.splice(i, j - i, ...run.filter((o) => o[0] === "-"), ...run.filter((o) => o[0] === "+"));
    i = j;
  }
  const all: [" " | "-" | "+", string, number][] = [
    ...x.slice(0, head).map((l, i): [" ", string, number] => [" ", l, i + 1]),
    ...ops.map(([o, l]): [" " | "-" | "+", string, number] => [o, l, 0]),
    ...x.slice(x.length - tail).map((l): [" ", string, number] => [" ", l, 0]),
  ];
  // Line numbers of the old file, for the hunk headers.
  let ln = 1;
  for (const r of all) {
    r[2] = ln;
    if (r[0] !== "+") ln++;
  }
  const changed = all.map((r) => r[0] !== " ");
  const keep = all.map((_, i) => {
    for (let d = -context; d <= context; d++) if (changed[i + d]) return true;
    return false;
  });
  const out: string[] = [];
  let last = -2;
  all.forEach((r, i) => {
    if (!keep[i]) return;
    if (i !== last + 1) out.push(`@@ line ${r[2]} @@`);
    out.push(`${r[0]}${r[1]}`);
    last = i;
  });
  return out;
}
