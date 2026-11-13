/**
 * `signafaide agent setup`: installs the signafAIde MCP server and the skill in each coding
 * agent's own format. Every edit merges into existing files and is idempotent.
 *
 * Formats (checked against each tool's CLI or official docs, see the README):
 * - Claude Code: `.mcp.json` `mcpServers` (as `claude mcp add -s project` writes it), `.claude/skills/signafaide/SKILL.md`, `CLAUDE.md`
 * - Codex: `$CODEX_HOME/config.toml` (default `~/.codex`) `[mcp_servers.signafaide]` (as `codex mcp add` writes it), `AGENTS.md`
 * - Cursor: `.cursor/mcp.json` `mcpServers`, `.cursor/rules/signafaide.mdc`
 * - Gemini CLI: `.gemini/settings.json` `mcpServers` (as `gemini mcp add -s project` writes it), `GEMINI.md`
 * - GitHub Copilot in VS Code: `.vscode/mcp.json` `servers`, `.github/copilot-instructions.md`
 * - Windsurf (Cascade, now documented under Devin Local): `.devin/mcp_config.json` `mcpServers`, `AGENTS.md`
 *
 * With `url` (a self-hosted witness), every MCP entry gets `SIGNAFAIDE_URL` in its env.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { SECTION_END, SECTION_START, claudeSkill, cursorRule, instructionsSection } from "./skill.js";
import { detectAgent } from "./telemetry.js";
import { VERSION } from "./version.js";

export const SERVER = "signafaide";
export const COMMAND = "npx";
/** Pinned to this SDK's version, so a coding agent never runs whatever `latest` is today. */
export const ARGS = ["-y", `signafaide@${VERSION}`, "mcp"];

export interface Ctx {
  root: string;
  home: string;
  env: Record<string, string | undefined>;
  dryRun: boolean;
  /** A self-hosted witness: written as SIGNAFAIDE_URL into each MCP entry's env. */
  url?: string;
}

/** Printed after `agent setup`: what is sent, what stays, and how to opt in. */
export function SETUP_NOTES(url?: string): string[] {
  return [
    "what is sent: nothing yet. Records are signed and chained locally in .signafaide/ (verify with `signafaide verify`) until a person runs `signafaide init` or sets SIGNAFAIDE_API_KEY.",
    "what leaves the machine after that: only hashes (hash-only by default). Full inputs and outputs stay in .signafaide/chain/<project>/<env>/<agent>.jsonl; storeContent (TypeScript) or store_content=True (Python) sends the content too, encrypted at rest (live records need the Team plan).",
    url
      ? `witness: ${url} (SIGNAFAIDE_URL in each MCP entry); it needs an API key from that instance, or \`signafaide init\` against it`
      : "witness: the hosted service by default; to keep the evidence in your environment, self-host it and rerun with --url <your witness url> (https://signafaide.com/docs/self-host)",
  ];
}

/** The MCP server entry's env: SIGNAFAIDE_URL when a witness URL was given. */
const mcpEnv = (c: Ctx): Record<string, string> => (c.url ? { SIGNAFAIDE_URL: c.url } : {});
/** A stdio entry, with `env` only when there is something in it (unless `alwaysEnv`). */
const entry = (c: Ctx, extra: object = {}, alwaysEnv = false): object => {
  const env = mcpEnv(c);
  return { ...extra, command: COMMAND, args: ARGS, ...(alwaysEnv || Object.keys(env).length ? { env } : {}) };
};

/** One file change: `created`, `updated`, `unchanged` or `skipped (reason)`. */
export interface Change {
  file: string;
  result: string;
}

interface Agent {
  id: string;
  /** Why we think it is installed or in use, or null. */
  detect(ctx: Ctx): string | null;
  install(ctx: Ctx): Change[];
  /** What the person still has to do in that agent, if anything. */
  note?: string;
}

// --- file edits -------------------------------------------------------------------

/** A symbolic link on the way to `file` (the file itself, or a folder below the project or
 * home folder) could point the write anywhere: refuse it. */
function throughLink(ctx: Ctx, file: string): string | null {
  const base = [ctx.root, ctx.home].find((b) => file === b || file.startsWith(b + path.sep));
  const parts = base ? path.relative(base, file).split(path.sep) : [path.basename(file)];
  let p = base ?? path.dirname(file);
  for (const part of parts) {
    p = path.join(p, part);
    try {
      if (fs.lstatSync(p).isSymbolicLink()) return p;
    } catch {
      return null; // does not exist yet, nor anything below it
    }
  }
  return null;
}

function write(ctx: Ctx, file: string, next: string): Change {
  const shown = shortPath(ctx, file);
  const link = throughLink(ctx, file);
  if (link) return { file: shown, result: `skipped (${shortPath(ctx, link)} is a symbolic link; write it by hand)` };
  const prev = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
  if (prev === next) return { file: shown, result: "unchanged" };
  if (!ctx.dryRun) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, next);
  }
  return { file: shown, result: prev === null ? "created" : "updated" };
}

function shortPath(ctx: Ctx, file: string): string {
  const rel = path.relative(ctx.root, file);
  if (!rel.startsWith("..") && !path.isAbsolute(rel)) return rel;
  return file.startsWith(ctx.home + path.sep) ? "~" + file.slice(ctx.home.length) : file;
}

/** Set `doc[key][SERVER] = entry` in a JSON file, keeping everything else. */
export function mergeJson(ctx: Ctx, file: string, key: string, entry: object): Change {
  const link = throughLink(ctx, file);
  if (link) return { file: shortPath(ctx, file), result: `skipped (${shortPath(ctx, link)} is a symbolic link; write it by hand)` };
  let doc: any = {};
  if (fs.existsSync(file)) {
    const raw = fs.readFileSync(file, "utf8");
    if (raw.trim()) {
      try {
        doc = JSON.parse(raw);
      } catch {
        // JSON with comments (VS Code allows them): rewriting would drop them
        return { file: shortPath(ctx, file), result: `skipped (not plain JSON; add "${SERVER}": ${JSON.stringify(entry)} under "${key}" by hand)` };
      }
    }
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return { file: shortPath(ctx, file), result: "skipped (not a JSON object)" };
  }
  const servers = typeof doc[key] === "object" && doc[key] !== null ? doc[key] : {};
  if (JSON.stringify(servers[SERVER]) === JSON.stringify(entry)) return { file: shortPath(ctx, file), result: "unchanged" };
  doc[key] = { ...servers, [SERVER]: entry };
  return write(ctx, file, JSON.stringify(doc, null, 2) + "\n");
}

/** Put the marked signafAIde section in a Markdown file: replaced in place if present, else appended. */
export function mergeSection(ctx: Ctx, file: string): Change {
  const section = instructionsSection();
  const prev = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const a = prev.indexOf(SECTION_START);
  const b = prev.indexOf(SECTION_END, a);
  let next: string;
  if (a >= 0 && b > a) {
    let end = b + SECTION_END.length;
    if (prev[end] === "\n") end++;
    next = prev.slice(0, a) + section + prev.slice(end);
  } else {
    next = prev ? prev.replace(/\n*$/, "\n\n") + section : section;
  }
  return write(ctx, file, next);
}

const tomlString = (s: string): string => JSON.stringify(s);

/** Set `command` and `args` of `[mcp_servers.signafaide]` in a Codex config.toml, keeping every other line and key.
 * With a witness URL, `SIGNAFAIDE_URL` goes in the server's env: the `[mcp_servers.signafaide.env]` table or
 * inline `env = {...}` when there is one, else a new inline `env`. */
export function mergeToml(ctx: Ctx, file: string): Change {
  const want = [`command = ${tomlString(COMMAND)}`, `args = [${ARGS.map(tomlString).join(", ")}]`];
  const urlKey = ctx.url ? `SIGNAFAIDE_URL = ${tomlString(ctx.url)}` : null;
  const prev = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const lines = prev.split("\n");
  const header = new RegExp(`^\\s*\\[\\s*mcp_servers\\.(${SERVER}|"${SERVER}")\\s*\\]\\s*(#.*)?$`);
  const envHeader = new RegExp(`^\\s*\\[\\s*mcp_servers\\.(${SERVER}|"${SERVER}")\\.env\\s*\\]\\s*(#.*)?$`);
  const start = lines.findIndex((l) => header.test(l));
  if (start < 0) {
    const env = urlKey ? [`env = { ${urlKey} }`] : [];
    return write(ctx, file, (prev.trim() ? prev.replace(/\n*$/, "\n\n") : "") + `[mcp_servers.${SERVER}]\n${[...want, ...env].join("\n")}\n`);
  }
  let end = start + 1;
  while (end < lines.length && !/^\s*\[/.test(lines[end])) end++;
  // drop our two keys (args may span lines), keep the rest of the table as it was
  const body: string[] = [];
  let inlineEnv = false;
  for (let i = start + 1; i < end; i++) {
    if (/^\s*command\s*=/.test(lines[i])) continue;
    if (/^\s*args\s*=/.test(lines[i])) {
      while (i < end - 1 && !lines[i].includes("]")) i++;
      continue;
    }
    const m = urlKey && lines[i].match(/^(\s*env\s*=\s*\{)([^}]*)(\}.*)$/);
    if (m) {
      // an inline env table: set SIGNAFAIDE_URL in it, keep the other variables
      const vars = m[2].split(",").map((v) => v.trim()).filter((v) => v && !/^"?SIGNAFAIDE_URL"?\s*=/.test(v));
      body.push(`${m[1]} ${[...vars, urlKey].join(", ")} ${m[3]}`);
      inlineEnv = true;
      continue;
    }
    body.push(lines[i]);
  }
  let out = [...lines.slice(0, start + 1), ...want, ...body, ...lines.slice(end)];
  if (urlKey && !inlineEnv) {
    const e = out.findIndex((l) => envHeader.test(l));
    if (e >= 0) {
      let f = e + 1;
      while (f < out.length && !/^\s*\[/.test(out[f])) f++;
      const kept = out.slice(e + 1, f).filter((l) => !/^\s*"?SIGNAFAIDE_URL"?\s*=/.test(l));
      out = [...out.slice(0, e + 1), urlKey, ...kept, ...out.slice(f)];
    } else out.splice(start + 1 + want.length, 0, `env = { ${urlKey} }`);
  }
  return write(ctx, file, out.join("\n"));
}

// --- agents -----------------------------------------------------------------------

const onPath = (ctx: Ctx, bin: string): boolean =>
  (ctx.env.PATH ?? "")
    .split(path.delimiter)
    .filter(Boolean)
    .some((d) => [bin, `${bin}.cmd`, `${bin}.exe`].some((b) => fs.existsSync(path.join(d, b))));

/** The first reason that holds: `[label, test]` pairs. */
const why = (checks: [string, boolean][]): string | null => checks.find(([, ok]) => ok)?.[0] ?? null;
const inProject = (ctx: Ctx, f: string): boolean => fs.existsSync(path.join(ctx.root, f));
const inHome = (ctx: Ctx, f: string): boolean => fs.existsSync(path.join(ctx.home, f));
const running = (ctx: Ctx, id: string): boolean => detectAgent(ctx.env) === id;

export const AGENTS: Agent[] = [
  {
    id: "claude-code",
    detect: (c) =>
      why([
        ["running in it", running(c, "claude-code")],
        ["`claude` on PATH", onPath(c, "claude")],
        [".claude/ in the project", inProject(c, ".claude")],
        ["~/.claude", inHome(c, ".claude")],
      ]),
    note: "Claude Code asks once to approve the project's MCP servers when it next starts here",
    install: (c) => [
      mergeJson(c, path.join(c.root, ".mcp.json"), "mcpServers", entry(c, { type: "stdio" }, true)),
      write(c, path.join(c.root, ".claude", "skills", "signafaide", "SKILL.md"), claudeSkill()),
      // Claude Code reads CLAUDE.md as the project's instructions; the skill alone is read as a file.
      mergeSection(c, path.join(c.root, "CLAUDE.md")),
    ],
  },
  {
    id: "codex",
    detect: (c) =>
      why([
        ["running in it", running(c, "codex")],
        ["`codex` on PATH", onPath(c, "codex")],
        ["CODEX_HOME", !!c.env.CODEX_HOME],
        ["~/.codex", inHome(c, ".codex")],
      ]),
    install: (c) => [mergeToml(c, path.join(c.env.CODEX_HOME || path.join(c.home, ".codex"), "config.toml")), mergeSection(c, path.join(c.root, "AGENTS.md"))],
  },
  {
    id: "cursor",
    detect: (c) =>
      why([
        ["running in it", running(c, "cursor")],
        ["`cursor` on PATH", onPath(c, "cursor") || onPath(c, "cursor-agent")],
        [".cursor/ in the project", inProject(c, ".cursor")],
        ["~/.cursor", inHome(c, ".cursor")],
      ]),
    install: (c) => [
      mergeJson(c, path.join(c.root, ".cursor", "mcp.json"), "mcpServers", entry(c, { type: "stdio" })),
      write(c, path.join(c.root, ".cursor", "rules", "signafaide.mdc"), cursorRule()),
    ],
  },
  {
    id: "gemini-cli",
    detect: (c) =>
      why([
        ["running in it", running(c, "gemini-cli")],
        ["`gemini` on PATH", onPath(c, "gemini")],
        [".gemini/ in the project", inProject(c, ".gemini")],
        ["~/.gemini", inHome(c, ".gemini")],
      ]),
    note: "Gemini CLI reads .gemini/settings.json only in folders you trust (it asks when it first starts in a folder)",
    install: (c) => [mergeJson(c, path.join(c.root, ".gemini", "settings.json"), "mcpServers", entry(c)), mergeSection(c, path.join(c.root, "GEMINI.md"))],
  },
  {
    id: "copilot",
    detect: (c) =>
      why([
        ["running in it", running(c, "copilot")],
        [".github/copilot-instructions.md in the project", inProject(c, ".github/copilot-instructions.md")],
        [".vscode/mcp.json in the project", inProject(c, ".vscode/mcp.json")],
        ["`copilot` on PATH", onPath(c, "copilot")],
      ]),
    install: (c) => [
      mergeJson(c, path.join(c.root, ".vscode", "mcp.json"), "servers", entry(c, { type: "stdio" })),
      mergeSection(c, path.join(c.root, ".github", "copilot-instructions.md")),
    ],
  },
  {
    id: "windsurf",
    detect: (c) =>
      why([
        ["running in it", running(c, "windsurf")],
        ["`windsurf` on PATH", onPath(c, "windsurf")],
        [".windsurf/ or .devin/ in the project", inProject(c, ".windsurf") || inProject(c, ".devin")],
        ["~/.codeium/windsurf", inHome(c, ".codeium/windsurf")],
      ]),
    install: (c) => [mergeJson(c, path.join(c.root, ".devin", "mcp_config.json"), "mcpServers", entry(c)), mergeSection(c, path.join(c.root, "AGENTS.md"))],
  },
];

export const AGENT_IDS = AGENTS.map((a) => a.id);

/** A witness URL for `--url`: http(s), no credentials, query or fragment; trailing slashes dropped. Throws otherwise. */
export function witnessUrl(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new Error(`--url ${raw} is not a URL; use the witness's base URL, e.g. https://signafaide.internal.example.com`);
  }
  if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username || u.password || u.search || u.hash) {
    throw new Error(`--url ${raw} must be an http(s) base URL without credentials, query or fragment`);
  }
  return u.toString().replace(/\/+$/, "");
}
const ALIASES: Record<string, string> = { claude: "claude-code", gemini: "gemini-cli", "github-copilot": "copilot", vscode: "copilot" };

export interface SetupResult {
  agent: string;
  reason: string;
  changes: Change[];
  note?: string;
}

/**
 * Install for the named agents (`all` for every one), or for every detected agent.
 * Throws on an unknown name.
 */
export function setup(opts: { root: string; agents?: string[]; dryRun?: boolean; env?: Record<string, string | undefined>; home?: string; url?: string }): SetupResult[] {
  const ctx: Ctx = { root: path.resolve(opts.root), home: opts.home ?? os.homedir(), env: opts.env ?? process.env, dryRun: !!opts.dryRun, url: witnessUrl(opts.url) };
  let chosen: { agent: Agent; reason: string }[];
  if (opts.agents?.length) {
    const ids = opts.agents.flatMap((a) => a.split(",")).map((a) => a.trim().toLowerCase()).filter(Boolean);
    const wanted = ids.includes("all") ? AGENT_IDS : ids.map((a) => ALIASES[a] ?? a);
    const unknown = wanted.filter((a) => !AGENT_IDS.includes(a));
    if (unknown.length) throw new Error(`unknown agent ${unknown.join(", ")}; use one of ${AGENT_IDS.join(", ")} or all`);
    chosen = AGENTS.filter((a) => wanted.includes(a.id)).map((agent) => ({ agent, reason: "asked for" }));
  } else {
    chosen = AGENTS.map((agent) => ({ agent, reason: agent.detect(ctx) ?? "" })).filter((a) => a.reason);
  }
  return chosen.map(({ agent, reason }) => ({ agent: agent.id, reason, changes: agent.install(ctx), ...(agent.note ? { note: agent.note } : {}) }));
}
