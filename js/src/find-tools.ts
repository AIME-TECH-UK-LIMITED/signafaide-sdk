/**
 * `signafaide protect`, the code side (spec 1.1, SPEC §8): find an agent's tools in a JavaScript
 * or TypeScript project and write `protect(...)`, `record(...)`, `wrapTool(...)` and
 * `declareTools(...)` into it. The source is read with a tokenizer (`source.ts`), so comments and
 * strings are never cut, and an edit replaces only the expression it wraps: options already
 * written (`record(fn, { agent, storeContent })`) are kept.
 *
 * Shapes found:
 * - an object named like tools (`const tools = { approve_payout, ... }`), its entries plain
 *   functions, wrapped functions, inline functions or framework tools;
 * - exported functions (declarations and `const f = async (...) => ...`) of files named like tools;
 * - Vercel AI SDK `tool({ execute })`, OpenAI Agents `tool({ name, execute })`, LangChain
 *   `tool(fn, { name })` and `new DynamicStructuredTool({ name, func })`, anywhere;
 * - MCP server tools (`server.tool("name", ...)`, `server.registerTool("name", ...)`): found, and
 *   protected at the gateway (no code change);
 * - methods of a class named like tools (`class PayoutTools`): found, wrapped by hand.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { applyEdits, closing, splitTop, textOf, tokenize, type Edit, type Token } from "./source.js";

export type ToolKind = "pays" | "deletes" | "sends" | "changes" | "runs" | "reads" | "other";
export const KIND_WORDS: Record<ToolKind, string> = {
  pays: "pays money",
  deletes: "deletes data",
  sends: "sends messages",
  changes: "changes data",
  runs: "runs commands",
  reads: "reads only",
  other: "not classified",
};
/** The kinds `protect` suggests protecting. */
export const RISKY: ReadonlySet<ToolKind> = new Set(["pays", "deletes", "sends", "changes", "runs"]);

/** A field a rule can read on a call of the tool: its name, and its JSON Pointer in the call's input. */
export interface Field {
  name: string;
  pointer: string;
}

export type Shape = "entry" | "function" | "framework" | "mcp" | "method";

export interface FoundTool {
  /** The tool's name (the key in the tools object, the framework tool's name, or the function's name). */
  name: string;
  /** The function the tool calls (for the lines to add by hand). */
  fn: string;
  /** The names of its positional arguments (empty for one object). */
  params: string[];
  /** One object parameter (destructured, typed as an object, or a framework tool's input). */
  objectParam: boolean;
  /** The fields rules can read, from the arguments, the destructuring pattern, a TS type, JSDoc or a schema. */
  fields: Field[];
  file: string;
  kind: ToolKind;
  /** Already wrapped in the code: `protect` or `record` (`wrapTool` with `strict: true` is `protect`). */
  wrapped: "protect" | "record" | null;
  shape: Shape;
  /** The framework, for framework and MCP tools: "Vercel AI SDK", "OpenAI Agents", "LangChain", "MCP server". */
  framework?: string;
  /** Whether the function is async (false: protect makes it return a Promise); null when not known. */
  async: boolean | null;
  /** The agent name already written in its wrapper, when there is one. */
  agent?: string;
  /** Where the code is, for writing it (none for MCP and class tools). */
  site?: Site;
}

export interface Found {
  tools: FoundTool[];
  /** The file and the name of the tools object, when the tools come from one. */
  object: { file: string; name: string } | null;
}

type Site =
  /** An entry of a tools object: [start, end) is the whole entry. `value` is null for shorthand. */
  | { kind: "entry"; start: number; end: number; key: string; value: [number, number] | null; method: boolean }
  /** A function declaration [start, end): `fn` is where `async`/`function` starts. */
  | { kind: "decl"; start: number; fn: number; end: number; exported: boolean; name: string }
  /** An expression to wrap in place: an initializer, a framework tool, or a call already wrapped. */
  | { kind: "expr"; start: number; end: number };

const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  "out",
  ".git",
  ".signafaide",
  "coverage",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
  "target",
  "proof",
]);

export function walk(root: string, exts: string[], max = 2000): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length && out.length < max) {
    const d = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !/^(test|tests|__tests__|spec)$/.test(e.name)) stack.push(p);
      } else if (
        exts.some((x) => e.name.endsWith(x)) &&
        !e.name.endsWith(".d.ts") &&
        !/[.](test|spec)[.][cm]?[jt]sx?$/.test(e.name) &&
        !/^test_|_test[.]py$/.test(e.name)
      )
        out.push(p);
    }
  }
  return out.sort();
}

/** Words of a name: `approvePayout` and `approve_payout` are both `approve`, `payout`. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

const KIND_TOKENS: [ToolKind, string[]][] = [
  [
    "pays",
    [
      "pay",
      "pays",
      "payout",
      "payouts",
      "payment",
      "payments",
      "transfer",
      "transfers",
      "refund",
      "refunds",
      "charge",
      "charges",
      "wire",
      "disburse",
      "withdraw",
      "invoice_pay",
    ],
  ],
  [
    "deletes",
    [
      "delete",
      "deletes",
      "remove",
      "removes",
      "drop",
      "destroy",
      "purge",
      "erase",
      "wipe",
      "truncate",
      "revoke",
      "cancel",
    ],
  ],
  [
    "sends",
    [
      "send",
      "sends",
      "email",
      "mail",
      "notify",
      "message",
      "sms",
      "post",
      "publish",
      "tweet",
      "reply",
      "forward",
      "invite",
    ],
  ],
  [
    "runs",
    [
      "execute",
      "exec",
      "run",
      "runs",
      "command",
      "shell",
      "bash",
      "sql",
      "eval",
      "spawn",
      "script",
      "deploy",
      "invoke",
    ],
  ],
  [
    "changes",
    [
      "update",
      "updates",
      "write",
      "writes",
      "set",
      "create",
      "creates",
      "insert",
      "edit",
      "modify",
      "patch",
      "upsert",
      "save",
      "put",
      "add",
      "rename",
      "move",
      "upload",
      "approve",
      "grant",
      "assign",
      "book",
      "order",
      "submit",
    ],
  ],
  [
    "reads",
    [
      "get",
      "list",
      "lookup",
      "look",
      "read",
      "search",
      "find",
      "fetch",
      "query",
      "show",
      "describe",
      "view",
      "check",
      "count",
      "load",
      "browse",
      "summarize",
      "retrieve",
      "status",
    ],
  ],
];

/** What a tool does, from the words of its name; `other` (not classified) when no word says. */
export function toolKind(name: string): ToolKind {
  const w = nameWords(name);
  for (const [kind, tokens] of KIND_TOKENS) if (w.some((x) => tokens.includes(x))) return kind;
  return "other";
}

// --- reading the source ---------------------------------------------------------------------

interface Fn {
  name: string;
  params: string[];
  objectParam: boolean;
  fields: Field[];
  async: boolean;
}

const PRIMITIVE = new Set([
  "string",
  "number",
  "boolean",
  "bigint",
  "symbol",
  "any",
  "unknown",
  "never",
  "String",
  "Number",
  "Boolean",
  "Date",
  "Array",
  "Function",
  "Promise",
  "Buffer",
  "Uint8Array",
]);
const isId = (t: Token | undefined, v?: string): boolean => !!t && t.t === "id" && (v === undefined || t.v === v);
const isP = (t: Token | undefined, v: string): boolean => !!t && t.t === "p" && t.v === v;

/** One file read once: its text and tokens. */
interface Src {
  file: string;
  text: string;
  toks: Token[];
}

/** The type names a project defines as object shapes: `interface X { ... }` and `type X = { ... }`. */
function objectTypes(srcs: Src[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const { toks } of srcs) {
    for (let i = 0; i < toks.length; i++) {
      let open = -1;
      if (isId(toks[i], "interface") && isId(toks[i + 1])) {
        let j = i + 2;
        while (j < toks.length && !isP(toks[j], "{")) j++;
        open = j;
      } else if (isId(toks[i], "type") && isId(toks[i + 1]) && isP(toks[i + 2], "=") && isP(toks[i + 3], "{"))
        open = i + 3;
      if (open < 0 || open >= toks.length) continue;
      const keys = objectKeys(toks, open);
      if (keys && !out.has(toks[i + 1].v)) out.set(toks[i + 1].v, keys);
    }
  }
  return out;
}

/** The keys of an object literal or type literal whose `{` is at `open`. */
function objectKeys(toks: Token[], open: number): string[] | null {
  const close = closing(toks, open);
  if (close < 0) return null;
  const keys: string[] = [];
  for (const [a, b] of splitTop(toks, open + 1, close)) {
    // A type literal separates members with `;` too.
    for (const [x] of splitAt(toks, a, b, ";")) {
      const t = toks[x];
      if (!t) continue;
      if (t.t === "p" && t.v === "...") continue;
      let k: string | null = null;
      if (t.t === "id" && !["readonly", "get", "set", "async"].includes(t.v)) k = t.v;
      else if (t.t === "id" && isId(toks[x + 1])) k = toks[x + 1].v;
      else if (t.t === "str") k = t.v;
      if (k && /^[A-Za-z_$][\w$]*$/.test(k) && !keys.includes(k)) keys.push(k);
    }
  }
  return keys;
}

/** [from, to) split at top-level `sep` tokens. */
function splitAt(toks: Token[], from: number, to: number, sep: string): [number, number][] {
  const out: [number, number][] = [];
  let depth = 0;
  let start = from;
  for (let j = from; j < to; j++) {
    const t = toks[j];
    if (t.t !== "p") continue;
    if ("([{".includes(t.v)) depth++;
    else if (")]}".includes(t.v)) depth--;
    else if (t.v === sep && depth === 0) {
      if (j > start) out.push([start, j]);
      start = j + 1;
    }
  }
  if (to > start) out.push([start, to]);
  return out;
}

/** JSDoc `@param {T} name.field` lines: the fields of an object parameter. */
function jsdocFields(doc: string | undefined, param: string): string[] {
  if (!doc) return [];
  const out: string[] = [];
  for (const m of doc.matchAll(/@param\s+(?:\{[^}]*\}\s*)?\[?([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)/g))
    if (m[1] === param && !out.includes(m[2])) out.push(m[2]);
  return out;
}

/** The parameters of the list (open at `open`, `(`): positional names, or one object with its fields. */
function readParams(
  toks: Token[],
  open: number,
  types: Map<string, string[]>,
  doc?: string,
): Omit<Fn, "name" | "async"> {
  const close = closing(toks, open);
  if (close < 0) return { params: [], objectParam: false, fields: [] };
  const parts = splitTop(toks, open + 1, close).filter(([a]) => !(isId(toks[a], "this") && isP(toks[a + 1], ":")));
  const names: string[] = [];
  for (const [a] of parts) {
    const t = isP(toks[a], "...") ? toks[a + 1] : toks[a];
    if (isId(t)) names.push(t!.v);
    else names.push("");
  }
  if (parts.length === 1) {
    const [a, b] = parts[0];
    // A destructuring pattern: `({ payee, amount, currency }: Payout)`.
    if (isP(toks[a], "{")) {
      const keys = objectKeys(toks, a) ?? [];
      return { params: [], objectParam: true, fields: keys.map((k) => ({ name: k, pointer: `/${k}` })) };
    }
    const colon = toks.slice(a, b).findIndex((t) => isP(t, ":"));
    const name = isId(toks[a]) ? toks[a].v : "";
    if (colon > 0) {
      const ty = a + colon + 1;
      let keys: string[] | null = null;
      if (isP(toks[ty], "{")) keys = objectKeys(toks, ty);
      else if (isId(toks[ty]) && !PRIMITIVE.has(toks[ty].v) && !isP(toks[ty + 1], "["))
        keys = types.get(toks[ty].v) ?? (/^[A-Z]/.test(toks[ty].v) ? [] : null);
      if (keys) return { params: [], objectParam: true, fields: keys.map((k) => ({ name: k, pointer: `/${k}` })) };
    }
    const jd = name ? jsdocFields(doc, name) : [];
    if (jd.length) return { params: [], objectParam: true, fields: jd.map((k) => ({ name: k, pointer: `/${k}` })) };
  }
  const ok = names.every((n) => /^[A-Za-z_$][\w$]*$/.test(n));
  const params = ok ? names : [];
  return { params, objectParam: false, fields: params.map((p) => ({ name: p, pointer: `/${p}` })) };
}

/** The end (exclusive token index) of a function whose parameter list closes at `close`: past its
 * body for a block, else past the expression body of an arrow. */
function functionEnd(toks: Token[], close: number): number {
  let j = close + 1;
  if (isP(toks[j], ":")) {
    // The return type: `{` right after `:`, `|`, `&`, `<`, `,` or `=>` is a type literal.
    j++;
    let typeEnded = false;
    let angle = 0;
    while (j < toks.length) {
      const t = toks[j];
      if (t.t === "p" && t.v === "{" && typeEnded && angle === 0) break;
      if (t.t === "p" && t.v === "=>" && typeEnded && angle === 0) break;
      if (t.t === "p" && "([{".includes(t.v)) {
        const c = closing(toks, j);
        if (c < 0) return toks.length;
        j = c + 1;
        typeEnded = true;
        continue;
      }
      if (t.t === "p" && t.v === "<") angle++;
      else if (t.t === "p" && t.v === ">") angle = Math.max(0, angle - 1);
      typeEnded = t.t === "id" || t.t === "str" || t.t === "num" || (t.t === "p" && (t.v === ">" || t.v === "]"));
      j++;
    }
  }
  if (isP(toks[j], "=>")) j++;
  if (isP(toks[j], "{")) {
    const c = closing(toks, j);
    return c < 0 ? toks.length : c + 1;
  }
  // An expression body: up to a top-level `,`, `;` or closing bracket.
  let depth = 0;
  for (; j < toks.length; j++) {
    const t = toks[j];
    if (t.t !== "p") continue;
    if ("([{".includes(t.v)) depth++;
    else if (")]}".includes(t.v)) {
      if (depth === 0) return j;
      depth--;
    } else if ((t.v === "," || t.v === ";") && depth === 0) return j;
  }
  return toks.length;
}

/** A function expression starting at token `i` (`async`? `function`... or an arrow): its params,
 * whether it is async, and its end token index. */
function functionAt(
  toks: Token[],
  i: number,
  types: Map<string, string[]>,
  doc?: string,
): (Omit<Fn, "name"> & { end: number }) | null {
  let j = i;
  let isAsync = false;
  if (isId(toks[j], "async") && !isP(toks[j + 1], "=>") && !isP(toks[j + 1], ",") && !isP(toks[j + 1], ")")) {
    isAsync = true;
    j++;
  }
  if (isId(toks[j], "function")) {
    j++;
    if (isP(toks[j], "*")) j++;
    if (isId(toks[j])) j++;
    if (isP(toks[j], "<")) while (j < toks.length && !isP(toks[j], "(")) j++;
    if (!isP(toks[j], "(")) return null;
    const p = readParams(toks, j, types, doc);
    return { ...p, async: isAsync, end: functionEnd(toks, closing(toks, j)) };
  }
  if (isP(toks[j], "<")) while (j < toks.length && !isP(toks[j], "(")) j++;
  if (isP(toks[j], "(")) {
    const c = closing(toks, j);
    if (c < 0) return null;
    // An arrow: `)` then `=>` (or a return type, then `=>`).
    let k = c + 1;
    if (isP(toks[k], ":")) {
      k = functionEnd(toks, c);
      // functionEnd stops at `=>`'s body; find the arrow between.
      if (!toks.slice(c + 1, k).some((t) => isP(t, "=>"))) return null;
    } else if (!isP(toks[k], "=>")) return null;
    const p = readParams(toks, j, types, doc);
    return { ...p, async: isAsync, end: functionEnd(toks, c) };
  }
  if (isId(toks[j]) && isP(toks[j + 1], "=>")) {
    const name = toks[j].v;
    const jd = jsdocFields(doc, name);
    const end = functionEnd(toks, j);
    return jd.length
      ? { params: [], objectParam: true, fields: jd.map((k) => ({ name: k, pointer: `/${k}` })), async: isAsync, end }
      : { params: [name], objectParam: false, fields: [{ name, pointer: `/${name}` }], async: isAsync, end };
  }
  return null;
}

/** The function declarations and `const f = <function>` of a file, by name. */
function functionsIn(src: Src, types: Map<string, string[]>): Map<string, Fn & { site: Site }> {
  const out = new Map<string, Fn & { site: Site }>();
  const { toks } = src;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    // Only statements: the token before is a statement boundary.
    const prev = toks[i - 1];
    const atStatement =
      !prev || (prev.t === "p" && ";{}".includes(prev.v)) || src.text.slice(prev.e, t.s).includes("\n");
    if (!atStatement) continue;
    let j = i;
    const exported = isId(toks[j], "export");
    if (exported) j++;
    if (isId(toks[j], "default")) continue;
    const start = toks[i].s;
    const doc = t.doc;
    if ((isId(toks[j], "async") && isId(toks[j + 1], "function")) || isId(toks[j], "function")) {
      const fnTok = j;
      if (isId(toks[j], "async")) j++;
      j++;
      if (isP(toks[j], "*")) j++;
      if (!isId(toks[j])) continue;
      const name = toks[j].v;
      const f = functionAt(toks, fnTok, types, doc);
      if (!f || out.has(name)) continue;
      out.set(name, {
        name,
        params: f.params,
        objectParam: f.objectParam,
        fields: f.fields,
        async: f.async,
        site: { kind: "decl", start, fn: toks[fnTok].s, end: toks[f.end - 1].e, exported, name },
      });
      i = Math.max(i, f.end - 1);
      continue;
    }
    if ((isId(toks[j], "const") || isId(toks[j], "let") || isId(toks[j], "var")) && isId(toks[j + 1])) {
      const name = toks[j + 1].v;
      let k = j + 2;
      if (isP(toks[k], ":")) {
        // A type annotation: up to the `=` at depth 0.
        let depth = 0;
        for (; k < toks.length; k++) {
          const x = toks[k];
          if (x.t !== "p") continue;
          if ("([{".includes(x.v)) depth++;
          else if (")]}".includes(x.v)) depth--;
          else if (x.v === "=" && depth === 0) break;
        }
      }
      if (!isP(toks[k], "=")) continue;
      const init = k + 1;
      let f = functionAt(toks, init, types, doc);
      if (f && !out.has(name)) {
        out.set(name, {
          name,
          params: f.params,
          objectParam: f.objectParam,
          fields: f.fields,
          async: f.async,
          site: { kind: "expr", start: toks[init].s, end: toks[f.end - 1].e },
        });
        i = Math.max(i, f.end - 1);
        continue;
      }
      // Already wrapped: `const f = protect(async function f(...) {...}, {...})`.
      if ((isId(toks[init], "protect") || isId(toks[init], "record")) && isP(toks[init + 1], "(")) {
        f = functionAt(toks, init + 2, types, doc);
        const c = closing(toks, init + 1);
        if (f && c > 0 && !out.has(name))
          out.set(name, {
            name,
            params: f.params,
            objectParam: f.objectParam,
            fields: f.fields,
            async: true,
            site: { kind: "expr", start: toks[init].s, end: toks[c].e },
          });
      }
    }
  }
  return out;
}

/** A call `W(first, { props })` at token `i`: the wrapper's name, the first argument's text, the
 * option properties as written, and the agent named in them. */
export interface Wrapped {
  wrapper: string;
  first: string;
  props: string[];
  agent?: string;
  end: number;
}

function wrappedAt(src: Src, i: number): Wrapped | null {
  const { toks, text } = src;
  if (!isId(toks[i]) || !isP(toks[i + 1], "(")) return null;
  const c = closing(toks, i + 1);
  if (c < 0) return null;
  const args = splitTop(toks, i + 2, c);
  if (!args.length) return null;
  const first = textOf(text, toks, args[0][0], args[0][1]);
  let props: string[] = [];
  let agent: string | undefined;
  if (args[1] && isP(toks[args[1][0]], "{")) {
    const oc = closing(toks, args[1][0]);
    props = splitTop(toks, args[1][0] + 1, oc).map(([a, b]) => textOf(text, toks, a, b));
    for (const [a] of splitTop(toks, args[1][0] + 1, oc))
      if (isId(toks[a], "agent") && isP(toks[a + 1], ":") && toks[a + 2]?.t === "str") agent = toks[a + 2].v;
  } else if (args[1]) return null;
  return { wrapper: toks[i].v, first, props, agent, end: c + 1 };
}

const propKey = (p: string): string => p.match(/^["']?([A-Za-z_$][\w$]*)/)?.[1] ?? "";

/** Framework imports of a file: `tool` from "ai" (Vercel AI SDK), "@openai/agents" or LangChain. */
function frameworkOf(text: string, name: string): string | null {
  const re = new RegExp(`import\\s*\\{[^}]*\\b${name}\\b[^}]*\\}\\s*from\\s*["']([^"']+)["']`);
  const m =
    text.match(re) ?? text.match(new RegExp(`\\{[^}]*\\b${name}\\b[^}]*\\}\\s*=\\s*require\\(\\s*["']([^"']+)["']`));
  if (!m) return null;
  const mod = m[1];
  if (mod === "ai" || mod.startsWith("@ai-sdk/")) return "Vercel AI SDK";
  if (mod.startsWith("@openai/agents")) return "OpenAI Agents";
  if (mod.startsWith("@langchain/") || mod.startsWith("langchain")) return "LangChain";
  return null;
}

/** The fields of a schema expression at token `i`: `z.object({ ... })`, a JSON Schema
 * `{ properties: { ... } }`, a zod shape `{ amount: z.number() }`, or a schema variable. */
function schemaFields(src: Src, i: number, schemas: Map<string, string[]>): string[] | null {
  const { toks } = src;
  if (
    isId(toks[i]) &&
    isP(toks[i + 1], ".") &&
    isId(toks[i + 2], "object") &&
    isP(toks[i + 3], "(") &&
    isP(toks[i + 4], "{")
  )
    return objectKeys(toks, i + 4);
  if (isId(toks[i], "jsonSchema") && isP(toks[i + 1], "(") && isP(toks[i + 2], "{"))
    return schemaFields(src, i + 2, schemas);
  if (isP(toks[i], "{")) {
    const c = closing(toks, i);
    for (const [a] of splitTop(toks, i + 1, c))
      if (isId(toks[a], "properties") && isP(toks[a + 1], ":") && isP(toks[a + 2], "{")) return objectKeys(toks, a + 2);
    return objectKeys(toks, i);
  }
  if (isId(toks[i]) && !isP(toks[i + 1], "(") && !isP(toks[i + 1], ".")) return schemas.get(toks[i].v) ?? null;
  return null;
}

/** `const X = z.object({...})` across the project: schema variables by name. */
function schemaVars(srcs: Src[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const s of srcs) {
    const { toks } = s;
    for (let i = 0; i + 3 < toks.length; i++) {
      if ((isId(toks[i], "const") || isId(toks[i], "let")) && isId(toks[i + 1]) && isP(toks[i + 2], "=")) {
        const f = schemaFields(s, i + 3, new Map());
        if (f && !out.has(toks[i + 1].v)) out.set(toks[i + 1].v, f);
      }
    }
  }
  return out;
}

/** The properties of the object literal at `open`: key -> [value start, value end) token range. */
function props(toks: Token[], open: number): Map<string, [number, number]> {
  const out = new Map<string, [number, number]>();
  const c = closing(toks, open);
  if (c < 0) return out;
  for (const [a, b] of splitTop(toks, open + 1, c)) {
    const k = toks[a];
    if ((k.t === "id" || k.t === "str") && isP(toks[a + 1], ":")) out.set(k.v, [a + 2, b]);
    else if (k.t === "id" && a + 1 === b) out.set(k.v, [a, b]);
    else if (k.t === "id" && (isP(toks[a + 1], "(") || (k.v === "async" && isId(toks[a + 1]) && isP(toks[a + 2], "("))))
      out.set(k.v === "async" ? toks[a + 1].v : k.v, [a, b]);
  }
  return out;
}

const str = (t: Token | undefined): string | null => (t && t.t === "str" ? t.v : null);

/** A framework tool at token `i` (`tool(` or `new DynamicStructuredTool(`), named `fallback`
 * when it carries no name of its own. */
function frameworkTool(
  src: Src,
  i: number,
  fallback: string | null,
  schemas: Map<string, string[]>,
  types: Map<string, string[]>,
): (Omit<FoundTool, "file" | "kind" | "wrapped" | "shape"> & { end: number }) | null {
  const { toks, text } = src;
  let j = i;
  let fw: string | null = null;
  if (
    isId(toks[j], "new") &&
    isId(toks[j + 1]) &&
    /^(Dynamic(Structured)?Tool|StructuredTool)$/.test(toks[j + 1].v) &&
    isP(toks[j + 2], "(")
  ) {
    fw = frameworkOf(text, toks[j + 1].v) ?? "LangChain";
    j += 2;
  } else if (isId(toks[j], "tool") && isP(toks[j + 1], "(") && !isP(toks[j - 1], ".")) {
    fw = frameworkOf(text, "tool");
    if (!fw) return null;
    j += 1;
  } else return null;
  const c = closing(toks, j);
  if (c < 0) return null;
  const args = splitTop(toks, j + 1, c);
  let name = fallback;
  let fields: string[] | null = null;
  let fnAt = -1;
  // LangChain `tool(fn, { name, schema })`: the function first.
  const optsAt = args.find(([a]) => isP(toks[a], "{"));
  if (args.length >= 2 && !isP(toks[args[0][0]], "{")) fnAt = args[0][0];
  if (optsAt) {
    const pr = props(toks, optsAt[0]);
    name = str(toks[pr.get("name")?.[0] ?? -1]) ?? name;
    for (const k of ["inputSchema", "parameters", "schema"]) {
      const v = pr.get(k);
      if (v && !fields) fields = schemaFields(src, v[0], schemas);
    }
    for (const k of ["execute", "func"]) {
      const v = pr.get(k);
      if (v && fnAt < 0) fnAt = v[0] === v[1] - 1 ? -1 : v[0];
    }
  }
  if (!name) return null;
  let isAsync: boolean | null = null;
  if (fnAt >= 0) {
    const f = functionAt(toks, fnAt, types);
    if (f) {
      isAsync = f.async;
      if (!fields && f.objectParam) fields = f.fields.map((x) => x.name);
    }
  }
  const fl = (fields ?? []).map((k) => ({ name: k, pointer: `/${k}` }));
  return { name, fn: name, params: [], objectParam: true, fields: fl, framework: fw, async: isAsync, end: c + 1 };
}

/** The tools of a JS or TS project (see the file's comment). `only` keeps the tool of that name. */
export function findTools(root: string, only?: string): Found {
  const srcs: Src[] = [];
  for (const f of walk(root, [".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts"])) {
    try {
      const text = fs.readFileSync(f, "utf8");
      srcs.push({ file: f, text, toks: tokenize(text) });
    } catch {
      /* unreadable: skipped */
    }
  }
  const types = objectTypes(srcs);
  const schemas = schemaVars(srcs);
  const decls = new Map<string, Fn & { site: Site; file: string }>();
  const perFile = new Map<string, Map<string, Fn & { site: Site }>>();
  for (const s of srcs) {
    const fns = functionsIn(s, types);
    perFile.set(s.file, fns);
    for (const [n, d] of fns) if (!decls.has(n)) decls.set(n, { ...d, file: s.file });
  }
  const tools: FoundTool[] = [];
  const seen = new Set<string>();
  const add = (t: FoundTool): void => {
    if (seen.has(t.name)) return;
    seen.add(t.name);
    tools.push(t);
  };
  let object: Found["object"] = null;
  const inObjects = new Set<number>(); // token starts of framework tools already read as entries
  // 1. Objects named like tools.
  for (const s of srcs) {
    const { toks, text } = s;
    for (let i = 0; i + 3 < toks.length; i++) {
      if (
        !(
          (isId(toks[i], "const") || isId(toks[i], "let") || isId(toks[i], "var")) &&
          isId(toks[i + 1]) &&
          /tools$/i.test(toks[i + 1].v)
        )
      )
        continue;
      let k = i + 2;
      if (isP(toks[k], ":")) while (k < toks.length && !isP(toks[k], "=")) k++;
      if (!isP(toks[k], "=") || !isP(toks[k + 1], "{")) continue;
      const open = k + 1;
      const close = closing(toks, open);
      if (close < 0) continue;
      const before = tools.length;
      for (const [a, b] of splitTop(toks, open + 1, close)) {
        const kt = toks[a];
        if (isP(kt, "...")) continue;
        let key: string | null = null;
        let method = false;
        let v: [number, number] | null = null;
        if ((kt.t === "id" || kt.t === "str") && isP(toks[a + 1], ":")) {
          key = kt.v;
          v = [a + 2, b];
        } else if (kt.t === "id" && a + 1 === b) key = kt.v;
        else if (
          kt.t === "id" &&
          (isP(toks[a + 1], "(") || (kt.v === "async" && isId(toks[a + 1]) && isP(toks[a + 2], "(")))
        ) {
          key = kt.v === "async" ? toks[a + 1].v : kt.v;
          method = true;
        }
        if (!key) continue;
        const site: Site = {
          kind: "entry",
          start: kt.s,
          end: toks[b - 1].e,
          key: textOf(text, toks, a, a + 1),
          value: v ? [toks[v[0]].s, toks[v[1] - 1].e] : null,
          method,
        };
        const base = { name: key, file: s.file, kind: toolKind(key), site };
        if (method) {
          // `async approve_payout(payee, amount) { ... }`: an inline method.
          const at = kt.v === "async" ? a + 2 : a + 1;
          const p = readParams(toks, at, types, kt.doc);
          add({ ...base, fn: key, ...p, wrapped: null, shape: "entry", async: kt.v === "async" });
          continue;
        }
        const vi = v ? v[0] : a;
        // A framework tool as the value, wrapped already or not.
        const inner = isId(toks[vi], "wrapTool") && isP(toks[vi + 1], "(") ? vi + 2 : vi;
        const ft = frameworkTool(s, inner, key, schemas, types);
        if (ft) {
          inObjects.add(toks[inner].s);
          const w = inner !== vi ? wrappedAt(s, vi) : null;
          add({
            ...base,
            ...ft,
            name: key,
            file: s.file,
            kind: toolKind(key),
            shape: "framework",
            wrapped: w ? (w.props.some((p) => /^strict\s*:\s*true$/.test(p)) ? "protect" : "record") : null,
            agent: w?.agent,
          });
          continue;
        }
        // A wrapped function: `protect(fn, {...})`, `record(fn, {...})`.
        if ((isId(toks[vi], "protect") || isId(toks[vi], "record")) && isP(toks[vi + 1], "(")) {
          const w = wrappedAt(s, vi);
          const ref = isId(toks[vi + 2]) && (isP(toks[vi + 3], ",") || isP(toks[vi + 3], ")")) ? toks[vi + 2].v : null;
          const f = ref ? decls.get(ref) : functionAt(toks, vi + 2, types);
          const strictProp = w?.props.some((p) => /^strict\s*:\s*true$/.test(p));
          add({
            ...base,
            fn: ref ?? key,
            params: f?.params ?? [],
            objectParam: f?.objectParam ?? false,
            fields: f?.fields ?? [],
            wrapped: toks[vi].v === "protect" || strictProp ? "protect" : "record",
            shape: "entry",
            async: f ? f.async : null,
            agent: w?.agent,
          });
          continue;
        }
        // A plain function reference, or an inline function.
        if (isId(toks[vi]) && vi + 1 === (v ? v[1] : b)) {
          const d = decls.get(toks[vi].v);
          add({
            ...base,
            fn: toks[vi].v,
            params: d?.params ?? [],
            objectParam: d?.objectParam ?? false,
            fields: d?.fields ?? [],
            wrapped: null,
            shape: "entry",
            async: d ? d.async : null,
          });
          continue;
        }
        const f = functionAt(toks, vi, types);
        if (f && f.end === (v ? v[1] : b))
          add({
            ...base,
            fn: key,
            params: f.params,
            objectParam: f.objectParam,
            fields: f.fields,
            wrapped: null,
            shape: "entry",
            async: f.async,
          });
      }
      if (tools.length > before && !object) object = { file: s.file, name: toks[i + 1].v };
    }
  }
  // 2. Framework tools anywhere else: `const approvePayout = tool({...})`.
  for (const s of srcs) {
    const { toks } = s;
    for (let i = 0; i < toks.length; i++) {
      if (!(isId(toks[i], "tool") || isId(toks[i], "new")) || inObjects.has(toks[i].s)) continue;
      const varName =
        isP(toks[i - 1], "=") && isId(toks[i - 2])
          ? toks[i - 2].v
          : isP(toks[i - 1], "(") && isId(toks[i - 2], "wrapTool") && isP(toks[i - 3], "=") && isId(toks[i - 4])
            ? toks[i - 4].v
            : null;
      const ft = frameworkTool(s, i, varName, schemas, types);
      if (!ft) continue;
      const wrapper = isP(toks[i - 1], "(") && isId(toks[i - 2], "wrapTool") ? wrappedAt(s, i - 2) : null;
      const site: Site = wrapper
        ? { kind: "expr", start: toks[i - 2].s, end: toks[wrapper.end - 1].e }
        : { kind: "expr", start: toks[i].s, end: toks[ft.end - 1].e };
      add({
        ...ft,
        file: s.file,
        kind: toolKind(ft.name),
        shape: "framework",
        wrapped: wrapper ? (wrapper.props.some((p) => /^strict\s*:\s*true$/.test(p)) ? "protect" : "record") : null,
        agent: wrapper?.agent,
        site,
      });
      i = ft.end - 1;
    }
  }
  // 3. MCP server tools: `server.tool("name", ...)`, `server.registerTool("name", ...)`.
  for (const s of srcs) {
    if (!/@modelcontextprotocol\//.test(s.text)) continue;
    const { toks } = s;
    for (let i = 2; i + 3 < toks.length; i++) {
      if (
        !(isId(toks[i], "tool") || isId(toks[i], "registerTool")) ||
        !isP(toks[i - 1], ".") ||
        !isP(toks[i + 1], "(") ||
        toks[i + 2].t !== "str"
      )
        continue;
      const name = toks[i + 2].v;
      const c = closing(toks, i + 1);
      const args = splitTop(toks, i + 2, c);
      let fields: string[] | null = null;
      let fnAt = -1;
      for (const [a] of args.slice(1)) {
        if (isP(toks[a], "{")) {
          const pr = props(toks, a);
          const sch = pr.get("inputSchema");
          fields ??= sch ? schemaFields(s, sch[0], schemas) : objectKeys(toks, a);
        } else if (functionAt(toks, a, types)) fnAt = a;
      }
      const f = fnAt >= 0 ? functionAt(toks, fnAt, types) : null;
      if (!fields && f?.objectParam) fields = f.fields.map((x) => x.name);
      add({
        name,
        fn: name,
        params: [],
        objectParam: true,
        fields: (fields ?? []).map((k) => ({ name: k, pointer: `/${k}` })),
        file: s.file,
        kind: toolKind(name),
        wrapped: null,
        shape: "mcp",
        framework: "MCP server",
        async: f ? f.async : null,
      });
    }
  }
  // 4. Methods of a class named like tools.
  for (const s of srcs) {
    const { toks } = s;
    for (let i = 0; i + 2 < toks.length; i++) {
      if (!isId(toks[i], "class") || !isId(toks[i + 1]) || !/(Tools|Toolkit|Toolset)$/.test(toks[i + 1].v)) continue;
      let k = i + 2;
      while (k < toks.length && !isP(toks[k], "{")) k++;
      const close = closing(toks, k);
      if (close < 0) continue;
      for (let j = k + 1; j < close; j++) {
        const boundary = isP(toks[j - 1], "{") || isP(toks[j - 1], "}") || isP(toks[j - 1], ";");
        if (!boundary) continue;
        let m = j;
        while (isId(toks[m]) && ["public", "async", "override"].includes(toks[m].v) && isId(toks[m + 1])) m++;
        if (
          !isId(toks[m]) ||
          !isP(toks[m + 1], "(") ||
          ["constructor", "get", "set", "static", "private", "protected"].includes(toks[m].v) ||
          toks[m].v.startsWith("_")
        ) {
          if (isP(toks[j], "{")) j = Math.max(j, closing(toks, j));
          continue;
        }
        const p = readParams(toks, m + 1, types, toks[j].doc);
        const isAsync = toks.slice(j, m).some((t) => isId(t, "async"));
        add({
          name: toks[m].v,
          fn: toks[m].v,
          ...p,
          file: s.file,
          kind: toolKind(toks[m].v),
          wrapped: null,
          shape: "method",
          async: isAsync,
        });
        const pc = closing(toks, m + 1);
        const end = functionEnd(toks, pc);
        j = end - 1;
      }
    }
  }
  // 5. No tools of the shapes above: the exported functions of files named like tools.
  if (!tools.length || only) {
    for (const s of srcs) {
      if (!/tool/i.test(path.basename(s.file)) && !only) continue;
      for (const [n, d] of perFile.get(s.file) ?? []) {
        const exported = d.site.kind === "decl" ? d.site.exported : exportedConst(s, d.site.start);
        if (!exported && !only) continue;
        if (only && n !== only) continue;
        const w =
          d.site.kind === "expr"
            ? wrappedAt(
                s,
                s.toks.findIndex((t) => t.s === d.site.start),
              )
            : null;
        const wrapped =
          w && (w.wrapper === "protect" || w.wrapper === "record") ? (w.wrapper as "protect" | "record") : null;
        add({
          name: n,
          fn: n,
          params: d.params,
          objectParam: d.objectParam,
          fields: d.fields,
          file: s.file,
          kind: toolKind(n),
          wrapped,
          shape: "function",
          async: d.async,
          agent: w?.agent,
          site: d.site,
        });
      }
    }
  }
  return { tools: only ? tools.filter((t) => t.name === only || t.fn === only) : tools, object };
}

/** Whether the `const` whose initializer starts at offset `init` is exported. */
function exportedConst(s: Src, init: number): boolean {
  const i = s.toks.findIndex((t) => t.s === init);
  for (let j = i - 1; j >= 0 && j >= i - 40; j--) {
    if (isId(s.toks[j], "const") || isId(s.toks[j], "let") || isId(s.toks[j], "var"))
      return isId(s.toks[j - 1], "export");
  }
  return false;
}

// --- writing the code ---------------------------------------------------------------------

/** What `protect` writes for a tool, by the tool's shape. */
function wrapperFor(t: FoundTool, protect: boolean): string {
  if (t.shape === "framework") return "wrapTool";
  return protect ? "protect" : "record";
}

/** The options of the wrapper: the ones already written, kept as written, plus `args` (named
 * positional arguments), `name` (a framework tool's own name), `agent` and `strict` (wrapTool). */
export function wrapOptions(t: FoundTool, protect: boolean, agent: string, have: string[] = []): string[] {
  const out = have.filter(
    (p) =>
      !(t.shape === "framework" && !protect && propKey(p) === "strict") &&
      !(t.shape !== "framework" && propKey(p) === "strict"),
  );
  const keys = new Set(out.map(propKey));
  if (t.shape !== "framework" && t.params.length && !t.objectParam && !keys.has("args"))
    out.push(`args: [${t.params.map((p) => JSON.stringify(p)).join(", ")}]`);
  if (t.shape === "framework" && !keys.has("name")) out.push(`name: ${JSON.stringify(t.name)}`);
  if (!keys.has("agent")) out.push(`agent: ${JSON.stringify(agent)}`);
  if (t.shape === "framework" && protect && !keys.has("strict")) out.push("strict: true");
  return out;
}

/** The call that wraps a tool's function: `protect(fn, { args: [...], agent: "..." })`. */
export function wrapCall(t: FoundTool, protect: boolean, agent: string, first = t.fn, have: string[] = []): string {
  return `${wrapperFor(t, protect)}(${first}, { ${wrapOptions(t, protect, agent, have).join(", ")} })`;
}

/** Add `import { ... } from "signafaide"`, merging with an import already there (CommonJS: a
 * `require`). */
export function addImport(text: string, names: string[]): string {
  const re = /import\s*\{([^}]*)\}\s*from\s*["']signafaide["'];?/;
  const m = text.match(re);
  if (m) {
    const have = m[1]
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const want = names.filter((n) => !have.includes(n));
    if (!want.length) return text;
    return text.replace(re, `import { ${[...have, ...want].join(", ")} } from "signafaide";`);
  }
  const req = /const\s*\{([^}]*)\}\s*=\s*require\(\s*["']signafaide["']\s*\);?/;
  const r = text.match(req);
  if (r) {
    const have = r[1]
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const want = names.filter((n) => !have.includes(n));
    if (!want.length) return text;
    return text.replace(req, `const { ${[...have, ...want].join(", ")} } = require("signafaide");`);
  }
  const cjs = /\brequire\s*\(/.test(text) && !/^\s*(import|export)\s/m.test(text);
  const line = cjs
    ? `const { ${names.join(", ")} } = require("signafaide");`
    : `import { ${names.join(", ")} } from "signafaide";`;
  const lines = text.split("\n");
  let i = 0;
  // After a leading comment, shebang or directive, and after the other imports.
  while (i < lines.length && (/^\s*(\/\/|\/\*|\*|#!|"use |'use )/.test(lines[i]) || !lines[i].trim())) i++;
  let last = -1;
  for (let j = i; j < lines.length; j++) {
    if (
      /^\s*import\s[^;]*from\s*["'][^"']+["'];?\s*$/.test(lines[j]) ||
      /^\s*import\s*["'][^"']+["'];?\s*$/.test(lines[j])
    )
      last = j;
    else if (lines[j].trim() && !/^\s*(\/\/|\/\*|\*)/.test(lines[j]) && last >= 0) break;
  }
  lines.splice(last >= 0 ? last + 1 : i, 0, line);
  return lines.join("\n");
}

/** One file's change: the new text, the tools it wraps. */
export interface FileChange {
  file: string;
  before: string;
  after: string;
  tools: FoundTool[];
}

/** The agent the code names already (a wrapper's or a declaration's `agent`), when one does. */
export function agentInCode(found: Found, root: string): string | null {
  for (const t of found.tools) if (t.agent) return t.agent;
  for (const f of walk(root, [".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts"])) {
    let text: string;
    try {
      text = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    if (!/declareTools\s*\(/.test(text)) continue;
    const toks = tokenize(text);
    for (let i = 0; i < toks.length; i++) {
      if (!isId(toks[i], "declareTools") || !isP(toks[i + 1], "(")) continue;
      const c = closing(toks, i + 1);
      const args = splitTop(toks, i + 2, c);
      if (args[1] && isP(toks[args[1][0]], "{")) {
        const pr = props(toks, args[1][0]);
        const v = pr.get("agent");
        if (v && toks[v[0]].t === "str") return toks[v[0]].v;
      }
    }
  }
  return null;
}

const DECLARE_COMMENT = "// The agent's full tool list, so a proof shows every tool is recorded.";
const NOT_CALLS = new Set([
  "const",
  "let",
  "var",
  "function",
  "class",
  "export",
  "import",
  "if",
  "for",
  "while",
  "do",
  "return",
  "type",
  "interface",
  "enum",
  "switch",
  "try",
  "throw",
  "new",
  "declare",
  "namespace",
  "module",
  "abstract",
  "async",
  "default",
]);
/** Tokens after which a line break does not end a statement. */
const GOES_ON = new Set([
  ",",
  ".",
  "(",
  "[",
  "{",
  "=",
  "+",
  "-",
  "*",
  "/",
  "%",
  "&&",
  "||",
  "??",
  "?",
  ":",
  "=>",
  "!",
  "|",
  "&",
  "<",
  ">",
  "?.",
  "...",
  "==",
  "===",
  "!=",
  "!==",
  "+=",
  "-=",
]);

/** The top-level statements of `toks` that run the program: a main guard (`if (import.meta.url
 * === ...)`, `if (require.main === module)`) or a call (`main();`, `await main()`, `main().catch(...)`,
 * `app.listen(...)`), never `declareTools` itself; as [start index, token index of the statement's start]. */
function runStatements(text: string, toks: Token[]): { at: number; i: number; declare: boolean }[] {
  const out: { at: number; i: number; declare: boolean }[] = [];
  let depth = 0;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    const prev = toks[i - 1];
    const starts =
      depth === 0 &&
      (!prev ||
        isP(prev, ";") ||
        isP(prev, "}") ||
        (text.slice(prev.e, t.s).includes("\n") &&
          !(prev.t === "p" && GOES_ON.has(prev.v)) &&
          !(t.t === "p" && GOES_ON.has(t.v))));
    if (starts) {
      if (isId(t, "if") && isP(toks[i + 1], "(")) {
        const c = closing(toks, i + 1);
        const cond = c > 0 ? text.slice(toks[i + 1].s, toks[c].e) : "";
        if (/require\.main|import\.meta\.(url|main|filename)|process\.argv/.test(cond))
          out.push({ at: t.s, i, declare: false });
      } else {
        let j = i;
        if (isId(toks[j], "await") || isId(toks[j], "void")) j++;
        if (isId(toks[j]) && !NOT_CALLS.has(toks[j].v)) {
          let last = toks[j].v;
          while (isP(toks[j + 1], ".") && isId(toks[j + 2])) {
            j += 2;
            last = toks[j].v;
          }
          if (isP(toks[j + 1], "(")) out.push({ at: t.s, i, declare: last === "declareTools" });
        }
      }
    }
    if (t.t === "p") {
      if (t.v === "(" || t.v === "[" || t.v === "{") depth++;
      else if (t.v === ")" || t.v === "]" || t.v === "}") depth = Math.max(0, depth - 1);
    }
  }
  return out;
}

/** Put the `declareTools` call where it always runs: before the first top-level statement after
 * the tools (from offset `from`) that runs the program, else at the end. `line` adds a new call;
 * with none, a top-level call already there after the program's run is moved up before it (a
 * program that exits early never reaches a line after its run). */
export function placeDeclaration(text: string, from: number, line: string | null): string {
  const toks = tokenize(text);
  const stmts = runStatements(text, toks);
  const run = stmts.find((x) => !x.declare && x.at >= from);
  const lineStart = (at: number): number => text.lastIndexOf("\n", at - 1) + 1;
  if (line !== null) {
    if (!run) return `${text.replace(/\s*$/, "")}\n\n${DECLARE_COMMENT}\n${line}\n`;
    let at = lineStart(run.at);
    // Comments right above the run statement stay with it.
    while (at > 0 && /^\s*\/\//.test(text.slice(lineStart(at - 1), at))) at = lineStart(at - 1);
    const pre = text.slice(0, at);
    return `${pre}${!pre || /\n[ \t]*\n$/.test(pre) ? "" : "\n"}${DECLARE_COMMENT}\n${line}\n\n${text.slice(at)}`;
  }
  const decl = stmts.find((x) => x.declare);
  const first = stmts.find((x) => !x.declare);
  if (!decl || !first || decl.at < first.at) return text;
  // The statement: to its closing parenthesis, and a `;` after it.
  let j = decl.i;
  while (j < toks.length && !isP(toks[j], "(")) j++;
  const c = closing(toks, j);
  if (c < 0) return text;
  let end = isP(toks[c + 1], ";") ? toks[c + 1].e : toks[c].e;
  if (text[end] === "\n") end++;
  let start = lineStart(decl.at);
  const block = text.slice(start, end).replace(/\s*$/, "");
  const above = lineStart(start - 1);
  if (start > 0 && text.slice(above, start).trim() === DECLARE_COMMENT) start = above;
  const rest = text.slice(0, start).replace(/\n{3,}$/, "\n\n") + text.slice(end);
  // The run statement comes before the call, so its offset is the same in what is left.
  let target = lineStart(first.at);
  while (target > 0 && /^\s*\/\//.test(rest.slice(lineStart(target - 1), target))) target = lineStart(target - 1);
  const pre = rest.slice(0, target);
  return `${pre}${!pre || /\n[ \t]*\n$/.test(pre) ? "" : "\n"}${DECLARE_COMMENT}\n${block}\n\n${rest.slice(target)}`;
}

/** The changes that record every tool found and protect the ones in `protectSet`, with `agent`
 * in every call written, and the agent's tool list declared once. Tools that cannot be written
 * (MCP servers, class methods) are left out; `declareTools` lists them too, except MCP tools,
 * which the gateway records and declares. `all` is every tool of the project when `found` holds
 * only the one `protect --tool` names: the declaration is the agent's full tool list either way. */
export function codeChanges(
  found: Found,
  protectSet: Set<string>,
  agent: string,
  root: string,
  all: Found = found,
): FileChange[] {
  const byFile = new Map<string, FoundTool[]>();
  for (const t of found.tools) if (t.site) byFile.set(t.file, [...(byFile.get(t.file) ?? []), t]);
  const texts = new Map<string, string>();
  const read = (f: string): string => {
    if (!texts.has(f)) texts.set(f, fs.readFileSync(f, "utf8"));
    return texts.get(f)!;
  };
  // Is the tool list declared anywhere in the project already?
  const files = walk(root, [".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts"]);
  const declaredIn = files.filter((f) => {
    try {
      return /\bdeclareTools\s*\(/.test(read(f));
    } catch {
      return false;
    }
  });
  const out: FileChange[] = [];
  const declareNames = all.tools.filter((t) => t.shape !== "mcp").map((t) => t.name);
  let declared = declaredIn.length > 0;
  const order = [...byFile.keys()];
  if (found.object && !order.includes(found.object.file)) order.unshift(found.object.file);
  if (found.object) order.sort((a, b) => (a === found.object!.file ? -1 : b === found.object!.file ? 1 : 0));
  for (const f of new Set([...order, ...declaredIn])) {
    const before = read(f);
    const s: Src = { file: f, text: before, toks: tokenize(before) };
    const tools = byFile.get(f) ?? [];
    const edits: Edit[] = [];
    const imports = new Set<string>();
    for (const t of tools) {
      const site = t.site!;
      const want = protectSet.has(t.name) || t.wrapped === "protect";
      const fresh = (first: string): string => wrapCall(t, want, agent, first);
      const rewrap = (start: number, end: number): string | null => {
        // A call already there: keep its function and options, change only what must change.
        const i = s.toks.findIndex((x) => x.s === start);
        const w = i >= 0 ? wrappedAt(s, i) : null;
        if (!w || !["protect", "record", "wrapTool"].includes(w.wrapper) || s.toks[w.end - 1].e !== end) return null;
        return wrapCall(t, want, agent, w.first, w.props);
      };
      imports.add(wrapperFor(t, want));
      if (site.kind === "entry") {
        const valueText = site.value ? before.slice(site.value[0], site.value[1]) : null;
        let call: string;
        if (site.method) {
          // `async key(a, b) { ... }` -> `key: protect(async function key(a, b) { ... }, {...})`.
          const src = before.slice(site.start, site.end);
          const fnText = src.replace(/^(async\s+)?/, (m) => `${m}function `);
          call = fresh(fnText);
        } else if (site.value) call = rewrap(site.value[0], site.value[1]) ?? fresh(valueText!);
        else call = fresh(site.key);
        const next = `${site.key}: ${call}`;
        if (before.slice(site.start, site.end) !== next) edits.push({ start: site.start, end: site.end, text: next });
      } else if (site.kind === "decl") {
        const fnText = before.slice(site.fn, site.end);
        edits.push({
          start: site.start,
          end: site.end,
          text: `${site.exported ? "export " : ""}const ${site.name} = ${fresh(fnText)};`,
        });
      } else {
        const now = before.slice(site.start, site.end);
        const next = rewrap(site.start, site.end) ?? fresh(now);
        if (next !== now) edits.push({ start: site.start, end: site.end, text: next });
      }
    }
    // declareTools already written: it names the agent too.
    if (declaredIn.includes(f)) {
      for (let i = 0; i < s.toks.length; i++) {
        if (!isId(s.toks[i], "declareTools") || !isP(s.toks[i + 1], "(")) continue;
        const c = closing(s.toks, i + 1);
        if (c < 0) continue;
        const args = splitTop(s.toks, i + 2, c);
        if (!args.length) continue;
        if (!args[1])
          edits.push({
            start: s.toks[args[0][1] - 1].e,
            end: s.toks[args[0][1] - 1].e,
            text: `, { agent: ${JSON.stringify(agent)} }`,
          });
        else if (isP(s.toks[args[1][0]], "{") && !props(s.toks, args[1][0]).has("agent")) {
          const oc = closing(s.toks, args[1][0]);
          const inner = splitTop(s.toks, args[1][0] + 1, oc);
          const at = inner.length ? s.toks[inner[inner.length - 1][1] - 1].e : s.toks[args[1][0]].e;
          edits.push({
            start: at,
            end: at,
            text: `${inner.length ? ", " : " "}agent: ${JSON.stringify(agent)}${inner.length ? "" : " "}`,
          });
        }
      }
    }
    let after = applyEdits(before, edits);
    // The tool list, once: after the tools object, else at the end of the first file written.
    if (!declared && tools.length) {
      const objName = found.object && found.object.file === f ? found.object.name : null;
      const list =
        objName && all.tools.every((t) => t.shape !== "mcp" && t.file === f)
          ? `Object.keys(${objName})`
          : `[${declareNames.map((n) => JSON.stringify(n)).join(", ")}]`;
      const call = `declareTools(${list}, { agent: ${JSON.stringify(agent)} });`;
      const line = `${DECLARE_COMMENT}\n${call}`;
      // Where the last tool ends in the changed text: the edits before it moved it.
      const toolsEnd = (): number => {
        const end = Math.max(...tools.map((t) => t.site!.end));
        return end + edits.filter((e) => e.end <= end).reduce((n, e) => n + e.text.length - (e.end - e.start), 0);
      };
      if (objName) {
        const toks = tokenize(after);
        let at = -1;
        for (let i = 0; i + 3 < toks.length; i++) {
          if ((isId(toks[i], "const") || isId(toks[i], "let") || isId(toks[i], "var")) && isId(toks[i + 1], objName)) {
            let k = i + 2;
            while (k < toks.length && !isP(toks[k], "{")) k++;
            const c = closing(toks, k);
            if (c > 0) at = isP(toks[c + 1], ";") ? toks[c + 1].e : toks[c].e;
            break;
          }
        }
        after =
          at >= 0 ? `${after.slice(0, at)}\n\n${line}${after.slice(at)}` : placeDeclaration(after, toolsEnd(), call);
      } else after = placeDeclaration(after, toolsEnd(), call);
      imports.add("declareTools");
      declared = true;
    } else if (declaredIn.includes(f)) after = placeDeclaration(after, 0, null);
    if (imports.size && after !== before)
      after = addImport(
        after,
        ["protect", "record", "wrapTool", "declareTools"].filter((n) => imports.has(n)),
      );
    if (after !== before) out.push({ file: f, before, after, tools });
  }
  return out;
}
