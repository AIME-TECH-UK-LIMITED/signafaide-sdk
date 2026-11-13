/**
 * The `X-Signafaide-Client` header and usage events.
 *
 * Sent: the SDK name and version, the runtime and its version, the framework adapter
 * in use, the coding agent that set the project up, and how the request was made
 * (sdk, cli or mcp). CLI `verify` and `export` also send one event naming the command.
 * Never sent: content, names, paths, hostnames or anything personal.
 * `SIGNAFAIDE_TELEMETRY=0` drops the adapter, the agent and the events.
 */

import { VERSION } from "./version.js";

export const HEADER = "X-Signafaide-Client";
export const SDK = "signafaide-js";
/** Framework adapters used in this process ("vercel-ai", "openai-agents", "langchain"). */
export const ADAPTERS = new Set<string>();

type Env = Record<string, string | undefined>;
const processEnv = (): Env => (typeof process !== "undefined" && process.env ? process.env : {});
const hasPrefix = (env: Env, prefix: string, skip: string[] = []): boolean =>
  Object.keys(env).some((k) => k.startsWith(prefix) && !skip.some((s) => k.startsWith(s)));
const term = (env: Env): string => (env.TERM_PROGRAM ?? "").toLowerCase();

// Checked in order: an agent running inside an editor terminal (Claude Code in Cursor)
// must win over the editor.
const AGENTS: [string, (e: Env) => boolean][] = [
  ["claude-code", (e) => e.CLAUDECODE === "1" || hasPrefix(e, "CLAUDE_CODE_")],
  ["codex", (e) => hasPrefix(e, "CODEX_", ["CODEX_COMPANION_"])],
  ["gemini-cli", (e) => hasPrefix(e, "GEMINI_CLI")],
  ["copilot", (e) => hasPrefix(e, "COPILOT_") || hasPrefix(e, "GITHUB_COPILOT_")],
  ["windsurf", (e) => hasPrefix(e, "WINDSURF_") || term(e) === "windsurf"],
  ["cursor", (e) => hasPrefix(e, "CURSOR_") || term(e) === "cursor"],
];

/** The coding agent whose environment this is, or `unknown`. */
export function detectAgent(env: Env = processEnv()): string {
  return AGENTS.find(([, test]) => test(env))?.[0] ?? "unknown";
}

export function telemetryEnabled(env: Env = processEnv()): boolean {
  return (env.SIGNAFAIDE_TELEMETRY ?? "").trim() !== "0";
}

export function adapterField(): string {
  return [...ADAPTERS].sort().join(",") || "none";
}

function runtimeName(): string {
  const g = globalThis as any;
  if (g.Bun?.version) return `bun ${g.Bun.version}`;
  if (g.Deno?.version?.deno) return `deno ${g.Deno.version.deno}`;
  if (typeof process !== "undefined" && process.versions?.node) return `node ${process.versions.node}`;
  return "js unknown";
}

/** `signafaide-js/<v> (node <v>; adapter=<a>; agent=<a>; via=<v>[; strict=1])`; with
 * telemetry off, adapter, agent and strict are left out. */
export function clientHeader(opts: { via?: string; adapter?: string; agent?: string; strict?: boolean; env?: Env } = {}): string {
  const on = telemetryEnabled(opts.env);
  const parts = [runtimeName()];
  if (on) parts.push(`adapter=${opts.adapter || "none"}`, `agent=${opts.agent || "unknown"}`);
  parts.push(`via=${opts.via ?? "sdk"}`);
  if (on && opts.strict) parts.push("strict=1");
  return `${SDK}/${VERSION} (${parts.join("; ")})`;
}
