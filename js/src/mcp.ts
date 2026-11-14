/**
 * `signafaide-mcp` (the separate package): an MCP server over stdio for coding agents. Every tool returns short
 * text the agent can act on. Tools work on the project in `directory`, else the server's cwd.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { statusLines } from "./cli.js";
import { explainError } from "./errors.js";
import { verify } from "./index.js";
import { FRAMEWORKS, LANGUAGES, detectProject, installCommand, snippet, verifyCommand, type Framework, type Language } from "./project.js";
import { configure, envOf, legalLinks, termsNotice, type Recorder } from "./runtime.js";
import { findRoot } from "./state.js";
import { SELF_HOST_DOC, SKILL_DESCRIPTION } from "./skill.js";
import { VERSION } from "./version.js";

type Result = { content: { type: "text"; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): Result => ({ content: [{ type: "text", text: t }], ...(isError ? { isError } : {}) });

const directory = z
  .string()
  .optional()
  .describe("Path of the project to work on: the folder the MCP server was started in, or one below it. Default: that folder.");

/** The folder the server was started in: tools never reach outside it. */
let serverRoot = path.resolve(process.cwd());

/** `p` resolved inside the server's root folder (symbolic links followed), or an error. */
export function inside(p: string): string {
  const base = fs.realpathSync(serverRoot);
  let real: string;
  try {
    real = fs.realpathSync(path.resolve(serverRoot, p));
  } catch {
    throw new Error(`${p} does not exist`);
  }
  if (real !== base && !real.startsWith(base + path.sep)) throw new Error(`${p} is outside ${base}, the folder this MCP server was started in; start the server in that project instead`);
  return real;
}

/** Point the recorder at `dir` (records, keys and .env live in its project root), without
 * changing the process's working directory. */
function open(dir?: string): Recorder {
  const start = dir ? inside(dir) : serverRoot;
  const found = findRoot(start);
  const base = fs.realpathSync(serverRoot);
  const root = found === base || found.startsWith(base + path.sep) ? found : start;
  return configure({ quiet: true, via: "mcp", root });
}

async function guard(fn: () => Promise<string>): Promise<Result> {
  try {
    return text(await fn());
  } catch (e) {
    return text(`signafaide: ${(e as Error).message}`, true);
  }
}

/** One line on the API key, without creating anything. */
function keyLine(rec: Recorder): string {
  const had = rec.apiKey;
  if (!had) {
    return "API key: none. Records stay on this machine (signed, chained, verifiable with signafaide verify); nothing is sent and no sandbox exists.";
  }
  const claim = had.startsWith("sfa_test_") ? rec.state.sandbox()?.claim_url : undefined;
  return `API key: found (${envOf(had)} env); record hashes are sent to ${rec.url}${claim ? `; the human claims the sandbox at ${claim}` : ""}.`;
}

/** What `signafaide_init` (or `signafaide init`) would create and send. */
function sandboxPreview(rec: Recorder): string[] {
  return [
    `What a sandbox would send (only after a person agrees: signafaide_init, or \`npx signafaide init\` run by them): one POST ${rec.url}/v1/sandbox with no body, which creates an anonymous project (no account, email or card) and returns an API key saved to .env and a claim link.`,
    `Creating it means the person agrees to the signafAIde Terms (${legalLinks({}, rec.url).terms_url}) and Privacy notice (${legalLinks({}, rec.url).privacy_url}); show them both links when you ask.`,
    "Then, per record, only the envelope: {v, kind, project, env, agent, seq, prev, time, name, content_hash, ref} with the agent's signature, plus each agent's public key once. Inputs and outputs stay in .signafaide/chain/ (hash-only); store_content=True / storeContent sends them encrypted (live records need the Team plan).",
    `To keep the evidence in your environment instead, self-host the witness and set SIGNAFAIDE_URL (${SELF_HOST_DOC}).`,
  ];
}

function steps(language: Language, framework: Framework, install: string, verifyCmd: string): string {
  return [
    `1. Install: ${install}`,
    `2. Wrap the functions that act (pay, send, approve, delete, change). Each call then writes a signed decision record before it runs and an outcome record after:`,
    "",
    "```" + (language === "python" ? "python" : "ts"),
    snippet(language, framework),
    "```",
    "",
    `3. Run the agent once so a wrapped function is called, then: ${verifyCmd} (or the signafaide_verify tool). Its last line must start with PASS.`,
  ].join("\n");
}

/** The MCP server; its tools are confined to `root` (default: the folder it starts in). */
export function createServer(root: string = process.cwd()): McpServer {
  serverRoot = path.resolve(root);
  const server = new McpServer({ name: "signafaide", version: VERSION }, { instructions: `signafAIde: ${SKILL_DESCRIPTION} Start with signafaide_setup (a preview that changes nothing).` });

  server.registerTool(
    "signafaide_setup",
    {
      title: "Preview signafAIde setup for this project (changes nothing)",
      description:
        `${SKILL_DESCRIPTION} ` +
        "A preview: it changes no file, creates nothing and sends nothing. Returns the detected language, package manager and framework, the exact install command, " +
        "the code edit for this framework, the functions that look like actions, and what a sandbox would send. Make the edit yourself, run the agent, then call signafaide_verify.",
      inputSchema: z.object({ directory }),
    },
    ({ directory: dir }) =>
      guard(async () => {
        const rec = open(dir);
        const p = detectProject(rec.state.root);
        const out = [`Project: ${p.root}`];
        if (!p.language) {
          out.push(
            "No pyproject.toml, requirements.txt, setup.py or package.json found, so the language is unknown.",
            "Call signafaide_quickstart with language python, typescript or javascript, or pass the project's directory.",
          );
          return out.join("\n");
        }
        out.push(`Language: ${p.language}; framework: ${p.framework === "plain" ? "none detected (plain functions)" : p.framework}`);
        out.push(keyLine(rec));
        out.push("", steps(p.language, p.framework, p.installed ? `already a dependency (${p.install.split(",")[0]} updates it)` : p.install, p.verify));
        if (p.candidates.length) out.push("", "Functions that look like actions (check which ones the agent calls):", ...p.candidates.map((c) => `- ${c}`));
        out.push(
          "",
          "Content: hash-only by default. The full inputs and outputs stay in .signafaide/chain/<project>/<env>/<agent>.jsonl on this machine (with the agent keys; the SDK adds .signafaide/ to .gitignore). " +
            `${p.language === "python" ? "store_content=True" : "storeContent: true"} sends the content too, encrypted at rest (live records need the Team plan). ` +
            `The agent name defaults to the project folder name; to choose one, pass ${p.language === "python" ? "agent=... to signafaide.record or wrap_tools" : "{ agent: ... } to record() or wrapTools()"}.`,
        );
        if (!rec.apiKey) out.push("", ...sandboxPreview(rec));
        out.push("", "Nothing was changed, created or sent by this preview.");
        return out.join("\n");
      }),
  );

  server.registerTool(
    "signafaide_init",
    {
      title: "Create an external signafAIde sandbox (ask the user first)",
      description:
        "Creates an external sandbox project on the signafAIde service (or the SIGNAFAIDE_URL witness), saves its API key to .env and returns the claim link. " +
        "From then on record hashes (never content) are sent there, and records written earlier ship with their original times. " +
        "This is an external side effect: ask the user and call it only after they agree. Without it, records stay local and still verify. " +
        "Creating a sandbox means the user agrees to the signafAIde Terms and Privacy notice (<service>/legal/terms and <service>/legal/privacy, where <service> is SIGNAFAIDE_URL or the signafAIde service): show them both links when you ask, and pass on the notice this tool returns.",
      inputSchema: z.object({ directory }),
    },
    ({ directory: dir }) =>
      guard(async () => {
        const rec = open(dir);
        if (rec.apiKey) return keyLine(rec) + " Nothing was created.";
        rec.rememberAgent();
        await rec.createSandbox();
        const claim = rec.state.sandbox()?.claim_url;
        return (
          `Created a sandbox at ${rec.url} (no account) and saved SIGNAFAIDE_API_KEY to ${path.join(rec.state.root, ".env")} (in .gitignore). ` +
          `Give the human this claim link so they can keep the records: ${claim}. Records written before now ship on the next run, or call signafaide_verify.\n` +
          `Tell the human: ${termsNotice(rec.legal())}`
        );
      }),
  );

  server.registerTool(
    "signafaide_quickstart",
    {
      title: "signafAIde snippet for a language and framework",
      description: "Returns the install command, the canonical code to record an agent's tool calls with signafAIde, and the verify command, for one language and framework.",
      inputSchema: z.object({
        language: z.enum(LANGUAGES),
        framework: z.enum(FRAMEWORKS).optional().describe("plain (default) for ordinary functions."),
      }),
    },
    ({ language, framework }) => guard(async () => steps(language, framework ?? "plain", installCommand(language), verifyCommand(language))),
  );

  server.registerTool(
    "signafaide_verify",
    {
      title: "Verify the local signafAIde records",
      description:
        "Checks every record in the project's .signafaide/ folder (or a verification pack): schema, hashes, agent signatures, chain links and content hashes, and, " +
        "for records a witness has co-signed, Merkle proofs, the service's batch and head signatures, drand and anchors. With an API key it first ships waiting records; " +
        "without one nothing is sent. Returns one line per check, what still needs the witness, and PASS or FAIL.",
      inputSchema: z.object({
        directory,
        pack: z.string().optional().describe("Path of a pack from `signafaide export`, instead of the local state."),
      }),
    },
    ({ directory: dir, pack }) =>
      guard(async () => {
        const rec = open(dir);
        const out: string[] = [];
        if (!pack) {
          if (!rec.state.chains().length) return `No records yet in ${rec.state.home}. Run the agent so a wrapped function is called, then verify again.`;
          const f = await rec.flush(); // sends nothing without an API key
          for (const [chain, e] of Object.entries(f.errors)) out.push(`shipping ${chain} failed: ${e.message} (code ${e.code}; see signafaide_explain_error)`);
          if (f.shipped) out.push(`shipped ${f.shipped} waiting records first`);
        }
        const report = await verify(pack ? inside(pack) : null);
        await rec.event("verify");
        out.push(...report.lines());
        const failed = report.checks.filter((c) => c.status === "fail");
        if (failed.length) out.push(`Failed: ${failed.map((c) => c.title).join(", ")}. Do not edit .signafaide/ to make this pass; a failure is evidence. Show it to the user.`);
        return out.join("\n");
      }),
  );

  server.registerTool(
    "signafaide_status",
    {
      title: "signafAIde status",
      description: "API key and env, the service URL, each agent chain with its record count and last receipt, records waiting in the outbox, the quota and the claim link.",
      inputSchema: z.object({ directory }),
    },
    ({ directory: dir }) => guard(async () => (await statusLines(open(dir))).join("\n")),
  );

  server.registerTool(
    "signafaide_explain_error",
    {
      title: "Explain a signafAIde error code",
      description: "What a signafAIde error code means and how to fix it, e.g. chain_conflict, quota_exceeded, invalid_key, network, not_recorded.",
      inputSchema: z.object({ code: z.string().describe("The error code, e.g. from SignafaideError.code or the service's error body.") }),
    },
    ({ code }) => guard(async () => explainError(code, open().url)),
  );

  server.registerTool(
    "signafaide_claim_link",
    {
      title: "signafAIde sandbox claim link",
      description: "The link the human opens to claim this project's free sandbox and keep its records. Show it to the user; do not open it yourself.",
      inputSchema: z.object({ directory }),
    },
    ({ directory: dir }) =>
      guard(async () => {
        const rec = open(dir);
        if (rec.apiKey?.startsWith("sfa_live_")) return "This project uses a live key; there is nothing to claim.";
        const claim = rec.state.sandbox()?.claim_url;
        return claim
          ? `Claim link for the human: ${claim}`
          : "No sandbox in this project: records stay local. A sandbox is created only when the user agrees (signafaide_init, or `npx signafaide init`).";
      }),
  );

  return server;
}

/** Serve over stdio until the client closes stdin. */
export async function serve(): Promise<void> {
  const { serveStdio } = await import("@modelcontextprotocol/server/stdio");
  const root = process.cwd();
  serveStdio(() => createServer(root));
}
