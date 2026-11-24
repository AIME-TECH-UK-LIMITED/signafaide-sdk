/**
 * `signafaide check --ci`: the pull request check. It finds the agent's
 * tools the way `protect` does (`find-tools.ts`), keeps the ones that look risky (they pay,
 * delete, send, run commands, push code, or edit secrets or config) and lists those not
 * protected: not wrapped by `protect(...)` (or `wrapTool(..., { strict: true })`), and not a
 * recorded tool the checks file protects (`"protect": true`, or a block rule kept on this machine
 * that names it with the tool in enforce mode, as `protect --local` writes). Reviewed exceptions are allowed by name, with a reason,
 * in the checks file's `ci.allow`, or with `--allow <tool>`.
 *
 * It reads the code and the checks file only: no account, no key, nothing sent. `--diff <base>`
 * keeps the tools whose code (or checks file entry) changed against a git base, for pull requests.
 */

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { checksFileErrors, toolSettings } from "./checks.js";
import { checksPath } from "./checks-runtime.js";
import { declaredName } from "./coverage.js";
import { KIND_WORDS, agentInCode, findTools, nameWords, walk, wrapCall, type FoundTool } from "./find-tools.js";
import { agentName } from "./records.js";
import { closing, tokenize } from "./source.js";

type Json = Record<string, any>;

export const CI_FORMAT = "signafaide-ci/1";

// --- what looks risky -------------------------------------------------------------------------

const MORE_PAYS = ["purchase", "buy", "checkout", "payroll"];
const MORE_RUNS = ["terminal", "subprocess", "cmd", "powershell", "sh"];
const CODE = ["push", "commit", "merge", "rebase", "git", "pr"];
const SECRETS = [
  "secret",
  "secrets",
  "credential",
  "credentials",
  "password",
  "passwords",
  "token",
  "tokens",
  "apikey",
];
const CONFIG = [
  "config",
  "configs",
  "configuration",
  "settings",
  "setting",
  "env",
  "dotenv",
  "environment",
  "permission",
  "permissions",
  "iam",
];

/** Why a tool looks risky, in words, from its name and kind; null when it does not. Reading tools
 * never do; a tool that changes data does when it touches code, secrets or config. */
export function riskOf(name: string, kind: string): string | null {
  if (kind === "pays" || kind === "deletes" || kind === "sends" || kind === "runs")
    return KIND_WORDS[kind as keyof typeof KIND_WORDS];
  if (kind === "reads") return null;
  const w = nameWords(name);
  const has = (list: string[]): boolean => w.some((x) => list.includes(x));
  if (has(MORE_PAYS)) return KIND_WORDS.pays;
  if (has(MORE_RUNS)) return KIND_WORDS.runs;
  if (has(CODE)) return "pushes code";
  if (has(SECRETS) || (w.includes("api") && w.includes("key"))) return "edits secrets";
  if (has(CONFIG)) return "edits config";
  return null;
}

// --- the result -------------------------------------------------------------------------------

export interface CiTool {
  tool: string;
  file: string;
  line: number;
  why: string;
  fix: string;
  shape: string;
  framework: string | null;
}

export interface CiAllowed {
  tool: string;
  file: string;
  line: number;
  why: string;
  reason: string;
  from: "checks file" | "--allow";
}

export interface CiResult {
  format: string;
  language: "javascript" | "python";
  ok: boolean;
  root: string;
  base: string | null;
  tools_found: number;
  risky: number;
  protected: number;
  unprotected: CiTool[];
  allowed: CiAllowed[];
  /** Files of the other language, which the other CLI checks. */
  other: { language: string; files: number; command: string } | null;
}

export class CiError extends Error {}

export interface CiOptions {
  root: string;
  base?: string | null;
  allow?: string[];
}

// --- the checks file --------------------------------------------------------------------------

function readChecks(root: string): { file: Json | null; path: string | null } {
  const p = checksPath(root);
  if (!p || !fs.existsSync(p)) return { file: null, path: p };
  let doc: unknown;
  try {
    doc = JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    throw new CiError(`${p} is not JSON: ${(e as Error).message}`);
  }
  const err = checksFileErrors(doc);
  if (err) throw new CiError(`${p}: ${err}`);
  return { file: doc as Json, path: p };
}

/** Whether the checks file protects the tool: `"protect": true` (signafAIde rules on its calls),
 * or, as `protect --local` writes, its entry in enforce mode with a block rule on this machine that
 * names it (`status` says "this machine only"). */
function protectedByFile(file: Json | null, tool: string): boolean {
  if (!file) return false;
  const decl = declaredName(tool);
  const ts = toolSettings(file, decl);
  if (ts.strict) return true;
  const local: Json[] = file.rules?.rules ?? [];
  return (
    ts.mode === "enforce" && local.some((r) => r.action === "block" && (r.tools === null || r.tools.includes(decl)))
  );
}

// --- where a tool is ----------------------------------------------------------------------------

const lineAt = (text: string, offset: number): number => {
  let n = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
};

/** The first and last line of a tool's code (its definition, its wrapper and options). */
function spanOf(t: FoundTool, text: string): [number, number] {
  if (t.site) return [lineAt(text, t.site.start), lineAt(text, t.site.end)];
  const toks = tokenize(text);
  for (let i = 0; i + 2 < toks.length; i++) {
    const a = toks[i];
    if (t.shape === "mcp") {
      if (!(
        a.t === "id" &&
        (a.v === "tool" || a.v === "registerTool") &&
        toks[i + 1]?.v === "(" &&
        toks[i + 2]?.t === "str" &&
        toks[i + 2].v === t.name
      ))
        continue;
      const c = closing(toks, i + 1);
      return [lineAt(text, a.s), lineAt(text, c >= 0 ? toks[c].e : a.e)];
    }
    if (a.t === "id" && a.v === t.name && toks[i + 1]?.t === "p" && toks[i + 1].v === "(") {
      const c = closing(toks, i + 1);
      let j = c + 1;
      while (j < toks.length && !(toks[j].t === "p" && toks[j].v === "{")) j++;
      const b = j < toks.length ? closing(toks, j) : -1;
      return [lineAt(text, a.s), lineAt(text, b >= 0 ? toks[b].e : a.e)];
    }
  }
  return [1, 1];
}

/** The line that protects a tool, for the shape it has. */
function fixFor(t: FoundTool, agent: string): string {
  const cmd = `npx signafaide protect --tool ${t.name}`;
  if (t.shape === "mcp")
    return `run the server as npx signafaide gateway --strict-tools ${t.name} -- <server command>, and set "${declaredName(t.name)}": { "protect": true } in signafaide.checks.json`;
  if (t.shape === "framework") return `${wrapCall(t, true, agent, "<its tool(...) definition>")} (or: ${cmd})`;
  if (t.shape === "method")
    return `${wrapCall(t, true, agent, `<instance>.${t.fn}.bind(<instance>)`)} where the agent gets its tools`;
  if (t.site?.kind === "entry") return `${t.name}: ${wrapCall(t, true, agent)} (or: ${cmd})`;
  return `const ${t.fn} = ${wrapCall(t, true, agent, "<its function>")} (or: ${cmd})`;
}

/** The agent's name: the one the code uses, else package.json's name, else the folder's. */
function agentFor(root: string, found: ReturnType<typeof findTools>): string {
  const named = agentInCode(found, root);
  if (named) return named;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    if (typeof pkg.name === "string" && pkg.name) return agentName(pkg.name.replace(/^@[^/]+\//, ""));
  } catch {
    /* no package.json */
  }
  return agentName(path.basename(root));
}

// --- the git base ------------------------------------------------------------------------------

function git(root: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });
}

export interface Changes {
  /** Lines added or changed since the base, by absolute path; "all" for a new file. */
  lines: Map<string, Set<number> | "all">;
  /** The checks file as it was at the base (null when there was none). */
  baseChecks: Json | null;
  /** The commit compared against (the merge base of the base and HEAD, when there is one). */
  commit: string;
}

/** What changed in the working tree against `base` (a branch, tag or commit), from the merge base
 * so the base branch's own new commits do not count. */
export function changesSince(root: string, base: string, checksFile: string | null): Changes {
  let top: string;
  try {
    top = git(root, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    throw new CiError(`--diff needs a git repository; ${root} is not in one`);
  }
  try {
    git(root, ["rev-parse", "--verify", "--quiet", `${base}^{commit}`]);
  } catch {
    throw new CiError(
      `--diff ${base}: no such commit in this clone; fetch it first (in GitHub Actions: actions/checkout with fetch-depth: 0)`,
    );
  }
  let commit = base;
  try {
    commit = git(root, ["merge-base", base, "HEAD"]).trim() || base;
  } catch {
    /* no merge base (a shallow clone): compare with the base itself */
  }
  const lines = new Map<string, Set<number> | "all">();
  const diff = git(root, [
    "-c",
    "core.quotepath=off",
    "diff",
    "--unified=0",
    "--no-color",
    "--no-ext-diff",
    "-M",
    commit,
    "--",
  ]);
  let cur: Set<number> | null = null;
  for (const l of diff.split("\n")) {
    if (l.startsWith("+++ ")) {
      const p = l.slice(4);
      if (p === "/dev/null") {
        cur = null;
        continue;
      }
      const abs = path.join(top, p.replace(/^b\//, ""));
      cur = new Set<number>();
      lines.set(abs, cur);
      continue;
    }
    const m = l.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (m && cur) {
      const start = Number(m[1]);
      const n = m[2] === undefined ? 1 : Number(m[2]);
      // Lines removed with nothing added in their place: the lines on either side changed.
      if (n === 0) [start, start + 1].forEach((x) => cur!.add(x));
      for (let i = 0; i < n; i++) cur.add(start + i);
    }
  }
  for (const p of git(root, ["ls-files", "--others", "--exclude-standard", "--full-name"]).split("\n"))
    if (p.trim()) lines.set(path.join(top, p.trim()), "all");
  // A new file shows as all its lines added; keep it as "all".
  for (const p of git(root, ["diff", "--name-only", "--diff-filter=A", "-M", commit, "--"]).split("\n"))
    if (p.trim()) lines.set(path.join(top, p.trim()), "all");
  let baseChecks: Json | null = null;
  if (checksFile) {
    const rel = path.relative(top, path.resolve(checksFile)).split(path.sep).join("/");
    try {
      const doc = JSON.parse(git(root, ["show", `${commit}:${rel}`]));
      if (!checksFileErrors(doc)) baseChecks = doc;
    } catch {
      /* no checks file at the base */
    }
  }
  return { lines, baseChecks, commit };
}

function changedIn(ch: Changes, file: string, span: [number, number]): boolean {
  const l = ch.lines.get(path.resolve(file));
  if (!l) return false;
  if (l === "all") return true;
  for (let i = span[0]; i <= span[1]; i++) if (l.has(i)) return true;
  return false;
}

// --- the check ---------------------------------------------------------------------------------

export function ciCheck(o: CiOptions): CiResult {
  const root = path.resolve(o.root);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new CiError(`${root} is not a folder`);
  const { file: checks, path: checksFile } = readChecks(root);
  const found = findTools(root);
  const agent = agentFor(root, found);
  const ch = o.base ? changesSince(root, o.base, checksFile) : null;
  const fileAllow = new Map<string, string>();
  for (const a of (checks?.ci?.allow ?? []) as { tool: string; reason: string }[]) fileAllow.set(a.tool, a.reason);
  const cliAllow = new Set(o.allow ?? []);
  const rel = (p: string): string => path.relative(root, p).split(path.sep).join("/") || p;
  const texts = new Map<string, string>();
  const textOf = (f: string): string => {
    if (!texts.has(f)) texts.set(f, fs.readFileSync(f, "utf8"));
    return texts.get(f)!;
  };
  const out: CiResult = {
    format: CI_FORMAT,
    language: "javascript",
    ok: true,
    root,
    base: o.base ?? null,
    tools_found: found.tools.length,
    risky: 0,
    protected: 0,
    unprotected: [],
    allowed: [],
    other: null,
  };
  for (const t of found.tools) {
    const why = riskOf(t.name, t.kind);
    if (!why) continue;
    const span = spanOf(t, textOf(t.file));
    if (ch) {
      const fileNow = protectedByFile(checks, t.name);
      const fileThen = protectedByFile(ch.baseChecks, t.name);
      if (!changedIn(ch, t.file, span) && fileNow === fileThen) continue;
    }
    out.risky++;
    // The checks file protects a tool whose calls go through signafaide: a recorded function, or
    // an MCP server tool run through the gateway.
    const viaFile = protectedByFile(checks, t.name) && (t.wrapped === "record" || t.shape === "mcp");
    if (t.wrapped === "protect" || viaFile) {
      out.protected++;
      continue;
    }
    const where = { tool: t.name, file: rel(t.file), line: span[0] };
    const reason = fileAllow.get(declaredName(t.name)) ?? fileAllow.get(t.name);
    if (reason !== undefined || cliAllow.has(t.name)) {
      out.allowed.push({
        ...where,
        why,
        reason: reason ?? "allowed on the command line (--allow)",
        from: reason !== undefined ? "checks file" : "--allow",
      });
      continue;
    }
    const state =
      t.wrapped === "record"
        ? "recorded, not protected"
        : protectedByFile(checks, t.name)
          ? "protected in signafaide.checks.json, but its code does not go through signafaide"
          : "not protected";
    out.unprotected.push({
      ...where,
      why: `${why}; ${state}`,
      fix: fixFor(t, agent),
      shape: t.shape,
      framework: t.framework ?? null,
    });
  }
  const order = (a: { file: string; line: number }, b: { file: string; line: number }): number =>
    a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line;
  out.unprotected.sort(order);
  out.allowed.sort(order);
  out.ok = out.unprotected.length === 0;
  const py = walk(root, [".py"]).length;
  if (py) out.other = { language: "python", files: py, command: "pipx run signafaide check --ci" };
  return out;
}

const n = (k: number, one: string, many = `${one}s`): string => `${k} ${k === 1 ? one : many}`;

/** The lines `check --ci` prints: one per tool not protected, with its fix, then the total. */
export function ciLines(r: CiResult): string[] {
  const lines: string[] = [];
  for (const u of r.unprotected) lines.push(`${u.file}:${u.line}: ${u.tool} ${u.why}. Fix: ${u.fix}`);
  for (const a of r.allowed) lines.push(`${a.file}:${a.line}: ${a.tool} ${a.why}; allowed (${a.from}): ${a.reason}`);
  const scope = r.base ? ` added or changed since ${r.base}` : "";
  const lang = r.language === "python" ? "Python" : "TypeScript and JavaScript";
  lines.push(
    r.ok
      ? `signafaide check --ci: passed. ${n(r.risky, "risky tool")}${scope}: ${r.protected} protected, ${r.allowed.length} allowed (${lang}, ${n(r.tools_found, "tool")} found).`
      : `signafaide check --ci: failed. ${n(r.unprotected.length, "risky tool")}${scope} not protected (of ${r.risky}; ${r.protected} protected, ${r.allowed.length} allowed; ${lang}, ${n(r.tools_found, "tool")} found).`,
  );
  if (r.other)
    lines.push(
      `note: ${n(r.other.files, `${r.other.language === "python" ? "Python" : "TypeScript or JavaScript"} file`)} not checked here; run ${r.other.command} for them (the GitHub Action runs both).`,
    );
  if (!r.ok)
    lines.push(
      'A reviewed exception: add { "tool": "<name>", "reason": "<why it is safe>" } to "ci": { "allow": [...] } in signafaide.checks.json.',
    );
  return lines;
}
