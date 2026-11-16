/**
 * `signafaide-mcp` (the separate package): an MCP server over stdio for coding agents. Every tool returns short
 * text the agent can act on. Tools work on the project in `directory`, else the server's cwd.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { flushReport, statusLines } from "./cli.js";
import { claimLines, sandboxGone, sandboxView } from "./claim.js";
import { explainError } from "./errors.js";
import { verify } from "./index.js";
import { plural } from "./plural.js";
import { FRAMEWORKS, LANGUAGES, detectProject, installCommand, snippet, verifyCommand, type Framework, type Language } from "./project.js";
import { configure, envOf, legalLinks, termsNotice, type Recorder } from "./runtime.js";
import { KeysRequired, ANCHOR_WINDOW_MS } from "./verifier.js";
import { replay, type Entry } from "./replay.js";
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

/** The API key, without creating anything; with a sandbox key, the claim step for the human. */
async function keyLine(rec: Recorder, refresh = true): Promise<string> {
  const had = rec.apiKey;
  if (!had) {
    return "API key: none. Records stay on this machine (signed, chained, verifiable with signafaide verify); nothing is sent and no sandbox exists.";
  }
  const line = `API key: found (${envOf(had)} env); record hashes are sent to ${rec.url}.`;
  const view = await sandboxView(rec, { refresh });
  return view ? `${line}\n${claimText(view, rec)}` : line;
}

/** The claim step, for the agent to pass on to the human as it stands. */
function claimText(view: NonNullable<Awaited<ReturnType<typeof sandboxView>>>, rec: Recorder): string {
  const lines = claimLines(view, rec.state.root);
  if (view.claimed) return lines.join("\n");
  if (sandboxGone(view)) return `Tell the human:\n${lines.join("\n")}`;
  return `Give the human the claim link and what follows it, in these words; do not open the link yourself:\n${lines.join("\n")}`;
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
    `3. Record what you did not wrap. For each MCP server the agent uses, start it through the gateway in the agent's MCP configuration: {"command": "npx", "args": ["-y", "signafaide", "gateway", "--agent", "<agent name>", "--", <the server's command and arguments>]}. Then give the full list of the tools your code hands the agent, once at start-up: ${language === "python" ? 'signafaide.declare_tools(["tool_a", "tool_b"], agent="<agent name>")' : 'declareTools(["tool_a", "tool_b"], { agent: "<agent name>" })'}; a tool you did not wrap is declared as not recorded, and verify names it. The gateway records only the calls that go through it, so make it the only route to those tools.`,
    `4. Run the agent once so a wrapped function is called, then: ${verifyCmd} (or the signafaide_verify tool). Its last line must start with PASS.`,
  ].join("\n");
}

/** Tool annotations (MCP hints). `service`: the tool may contact the signafAIde service. */
const readOnly = (service: boolean) => ({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: service });
/** A tool that sends to the service or creates something there; it deletes nothing and repeating it adds nothing. */
const SENDS = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };

const RECORDS_DEFAULT = 20;
const RECORDS_MAX = 100;

/** An ISO time (any offset) as a protocol time for replay; a bare date is left for replay to read. */
function isoArg(value: string | undefined, name: string): string | undefined {
  if (!value || /^\d{4}-\d{2}-\d{2}$/.test(value)) return value || undefined;
  const d = new Date(value);
  if (!/^\d{4}-\d{2}-\d{2}T/.test(value) || Number.isNaN(d.getTime())) throw new Error(`${name} must be YYYY-MM-DD or an ISO time like 2026-11-13T10:00:00Z`);
  return d.toISOString();
}

/** A record's status from what the local files hold: its signature, its receipt and the checks replay ran. */
function recordStatus(e: Entry, now: number): string {
  if (e.status === "FAIL") return `FAILED a check (${[...new Set(e.problems.map((p) => p.split(":")[0]))].join(", ")}); run signafaide_verify`;
  if (e.status === "BLOCKED") return "signed only; BLOCKED, the service cannot take it as it is (see signafaide_status)";
  if (!e.receipt) return "signed only, not co-signed yet";
  const t = Date.parse(e.receipt.batch?.server_time ?? "");
  return Number.isFinite(t) && t + ANCHOR_WINDOW_MS >= now ? "co-signed, public timestamp pending" : "co-signed";
}

/** `signafaide_records`: the local records as metadata lines, read and checked by replay. Never the content. */
async function recordLines(rec: Recorder, q: { agent?: string; from?: string; to?: string; record?: string; limit?: number }): Promise<string> {
  const all = rec.state.chains();
  if (!all.length) return `No records yet in ${rec.state.home}. Run the agent so a wrapped function is called, then list again.`;
  const chains = q.agent ? all.filter((c) => c.split("/").pop() === q.agent) : all;
  if (!chains.length) throw new Error(`no local records for agent "${q.agent}" in ${rec.state.home}; agents here: ${rec.state.agents().join(", ") || "none"}`);
  const since = isoArg(q.from, "from");
  const until = isoArg(q.to, "to");
  const want = q.record?.trim().toLowerCase();
  if (want !== undefined && !/^[0-9a-f]{8,64}$/.test(want)) throw new Error("record must be a record hash or a prefix of at least 8 characters");
  const limit = Math.min(RECORDS_MAX, Math.max(1, Math.floor(q.limit ?? RECORDS_DEFAULT)));
  const found: { agent: string; e: Entry }[] = [];
  for (const chain of chains) {
    const agent = chain.split("/").pop()!;
    let r;
    try {
      r = await replay({ agent, chain, since, until });
    } catch (e) {
      if (!(e instanceof KeysRequired)) throw e;
      throw new Error(`records of ${chain} have been co-signed, and listing checks their receipts with the service's public keys, which could not be loaded from ${rec.url}. Try again when it can be reached, or run \`npx signafaide replay --agent ${agent} --keys <file>\``);
    }
    let entries = r.entries;
    if (want) {
      const hit = entries.filter((e) => e.hash.startsWith(want));
      entries = [...new Set(hit.flatMap((e) => (e.pair ? [e, e.pair] : [e])))];
    }
    found.push(...entries.map((e) => ({ agent, e })));
  }
  if (want && !found.length) throw new Error(`no record matches ${q.record} in ${rec.state.home}`);
  found.sort((a, b) => (a.e.envelope.time < b.e.envelope.time ? 1 : a.e.envelope.time > b.e.envelope.time ? -1 : b.e.envelope.seq - a.e.envelope.seq));
  const shown = found.slice(0, limit);
  const truncated = found.length > shown.length;
  const now = Date.now();
  const out = [`Records in ${rec.state.home}, newest first. Each line: time, agent, sequence number, kind, tool name, record hash, status.`];
  for (const { agent, e } of shown) out.push(`${e.envelope.time}  ${agent}  #${e.envelope.seq}  ${e.envelope.kind}  ${e.envelope.name}  ${e.hash}  ${recordStatus(e, now)}`);
  if (!found.length) out.push("(no record matches these filters)");
  out.push(
    `total: ${plural(found.length, "record")} matched; shown: ${shown.length}; truncated: ${truncated ? `yes (pass agent, from or to to narrow the list, or limit up to ${RECORDS_MAX})` : "no"}`,
    "Only metadata is listed. The inputs and outputs of each call stay in the local files under .signafaide/chain/ and are not returned by this tool.",
  );
  if (shown.some(({ e }) => e.receipt)) out.push("Public timestamps are not kept in the local files: `signafaide export`, then `signafaide verify <pack>`, checks them for co-signed records.");
  return out.join("\n");
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
        "Call this first when you are working inside a project. It reads the project's dependency files and source and returns a preview: it changes no file, creates nothing and sends nothing. " +
        "Returns the detected language, package manager and framework, the exact install command, the code edit for this framework, the functions that look like actions, whether an API key is present, and what a sandbox would send. " +
        "Make the edit yourself, run the agent, then call signafaide_verify. " +
        "For a snippet in a language and framework you name, without reading any project, use signafaide_quickstart instead.",
      inputSchema: z.object({ directory }),
      annotations: readOnly(false),
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
        out.push(await keyLine(rec, false)); // a preview: the witness is not asked and nothing is saved
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
        "Creates an external sandbox project on the signafAIde service (or the SIGNAFAIDE_URL witness), saves its API key to .env and returns the claim link, what claiming gives and when an unclaimed sandbox is deleted. " +
        "From then on record hashes (never content) are sent there, and records written earlier ship with their original times. " +
        "This is an external side effect: ask the user and call it only after they agree. Without it, records stay local and still verify. " +
        "Creating a sandbox means the user agrees to the signafAIde Terms and Privacy notice (<service>/legal/terms and <service>/legal/privacy, where <service> is SIGNAFAIDE_URL or the signafAIde service): show them both links when you ask, and pass on the notice this tool returns. " +
        "It creates nothing unless confirm_user_agreed is true and user_words holds what the user wrote when they agreed.",
      inputSchema: z.object({
        directory,
        confirm_user_agreed: z
          .boolean()
          .optional()
          .describe("Set to true only after the user, in this conversation, agreed to create the sandbox and to the Terms and Privacy notice. Never set it on your own judgement."),
        user_words: z.string().optional().describe("The user's own words when they agreed, quoted from the conversation (for example \"yes, create the sandbox\")."),
      }),
      annotations: SENDS,
    },
    ({ directory: dir, confirm_user_agreed, user_words }) =>
      guard(async () => {
        const rec = open(dir);
        if (rec.apiKey) return `Nothing was created. ${await keyLine(rec)}`;
        const words = (user_words ?? "").trim();
        if (confirm_user_agreed !== true || words.length < 2) {
          const legal = legalLinks({}, rec.url);
          throw new Error(
            "nothing was created. signafaide_init needs the user's agreement as arguments: confirm_user_agreed: true and user_words (what the user wrote when they agreed). " +
              `Ask the user first: creating a sandbox at ${rec.url} sends record hashes there and accepts the signafAIde Terms (${legal.terms_url}) and Privacy notice (${legal.privacy_url}). ` +
              "If they have not agreed, do not call this tool again; records stay local and still verify.",
          );
        }
        rec.rememberAgent();
        await rec.createSandbox();
        const view = await sandboxView(rec, { refresh: false });
        return (
          `Created a sandbox at ${rec.url} (no account) and saved SIGNAFAIDE_API_KEY to ${path.join(rec.state.root, ".env")} (in .gitignore). ` +
          "Records written before now ship on the next run, or call signafaide_flush to send them now.\n" +
          (view ? `${claimText(view, rec)}\n` : "") +
          `Tell the human: ${termsNotice(rec.legal())}`
        );
      }),
  );

  server.registerTool(
    "signafaide_quickstart",
    {
      title: "signafAIde snippet for a language and framework",
      description:
        "A reference snippet for a language and framework you name: returns the install command, the canonical code to record an agent's tool calls with signafAIde, and the verify command. " +
        "It reads nothing in the project, detects nothing, changes nothing and sends nothing; the same arguments always give the same answer. " +
        "Use it to answer a question about a stack that is not the open project, or when signafaide_setup could not tell the language. " +
        "When you are working inside a project, use signafaide_setup instead: it detects the stack and previews the exact edit for that project.",
      inputSchema: z.object({
        language: z.enum(LANGUAGES),
        framework: z.enum(FRAMEWORKS).optional().describe("plain (default) for ordinary functions."),
      }),
      annotations: readOnly(false),
    },
    ({ language, framework }) => guard(async () => steps(language, framework ?? "plain", installCommand(language), verifyCommand(language))),
  );

  server.registerTool(
    "signafaide_verify",
    {
      title: "Verify the local signafAIde records",
      description:
        "Checks every record in the project's .signafaide/ folder (or a verification pack): schema, hashes, agent signatures, chain links and content hashes, and, " +
        "for records a witness has co-signed, Merkle proofs, the service's batch and head signatures, drand and anchors. With an API key it first ships waiting records " +
        "(signafaide_flush is the explicit way to ship them without verifying); without one nothing is sent. Returns one line per check, what still needs the witness, and PASS or FAIL. " +
        "To list the records themselves, use signafaide_records.",
      inputSchema: z.object({
        directory,
        pack: z.string().optional().describe("Path of a pack from `signafaide export`, instead of the local state."),
      }),
      annotations: SENDS,
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
      title: "Show the state of signafAIde in this project",
      description:
        "Reports how signafAIde is set up in this project and whether records are reaching the service. " +
        "Call it to check that set-up worked, after signafaide_init, or when signafaide_verify or signafaide_flush reports a problem and you need to see why. " +
        "Returns one line for each of: the API key (masked) and its env, or that there is none and records stay on this machine; the service URL; the project; the local state folder; " +
        "every agent chain with its key id, record count and last receipt; any chain that is BLOCKED, with the reason and the next step; how many records wait in the outbox; the quota used; " +
        "and, for a sandbox, the claim link with how long an unclaimed sandbox has left. " +
        "Read-only: it sends no records and changes no code, record or key (it only saves what the service says about the sandbox's claim state in .signafaide/). " +
        "It contacts the service only when an API key exists, to read the project, the quota and the claim state; without a key it makes no request. " +
        "Use signafaide_records to list the records themselves, signafaide_flush to send the waiting ones, and signafaide_claim_link when the user only needs the claim link.",
      inputSchema: z.object({ directory }),
      annotations: readOnly(true),
    },
    ({ directory: dir }) => guard(async () => (await statusLines(open(dir))).join("\n")),
  );

  server.registerTool(
    "signafaide_explain_error",
    {
      title: "Explain a signafAIde error code",
      description: "What a signafAIde error code means and how to fix it, e.g. chain_conflict, quota_exceeded, invalid_key, network, not_recorded.",
      inputSchema: z.object({ code: z.string().describe("The error code, e.g. from SignafaideError.code or the service's error body.") }),
      annotations: readOnly(false),
    },
    ({ code }) => guard(async () => explainError(code, open().url)),
  );

  server.registerTool(
    "signafaide_claim_link",
    {
      title: "signafAIde sandbox claim link",
      description:
        "The link the human opens to claim this project's free sandbox and keep its records, what claiming gives and how long an unclaimed sandbox has left. Show it to the user; do not open it yourself. " +
        "Use this tool when the user only needs the claim link, or needs it again. signafaide_status shows the same link among the whole state of the project (key, chains, outbox, quota): call that one when you need those too. " +
        "Read-only: with a sandbox key it asks the service whether the sandbox is still unclaimed; with no sandbox it makes no request and says so. It never creates a sandbox: that is signafaide_init, after the user agrees.",
      inputSchema: z.object({ directory }),
      annotations: readOnly(true),
    },
    ({ directory: dir }) =>
      guard(async () => {
        const rec = open(dir);
        if (rec.apiKey?.startsWith("sfa_live_")) return "This project uses a live key; there is nothing to claim.";
        const view = await sandboxView(rec);
        return view
          ? claimText(view, rec)
          : "No sandbox in this project: records stay local. A sandbox is created only when the user agrees (signafaide_init, or `npx signafaide init`).";
      }),
  );

  server.registerTool(
    "signafaide_records",
    {
      title: "List and search the signafAIde records on this machine",
      description:
        "Lists the records in this project's .signafaide/ folder, newest first, and searches them by agent, by time window, or by record hash. " +
        "Use it to see what was recorded: which tool calls, by which agent, when, and how far each record has got. " +
        "Returns one line per record with its time, agent, sequence number, kind (decision, outcome or note), tool name, record hash and status " +
        "(signed only; co-signed; co-signed with the public timestamp pending; BLOCKED; or FAILED a check), then the total that matched, how many are shown and whether the list was truncated. " +
        "Metadata only: the inputs and outputs of the tool calls are never returned, they stay in the local files (a person reads them with `npx signafaide replay`). " +
        "Read-only: it writes nothing and sends no records. Each record is checked against its signature and its chain as it is listed; when records here have been co-signed, " +
        "it fetches the service's public keys to check their receipts, and otherwise it makes no request. " +
        "For the full check with PASS or FAIL use signafaide_verify; for counts per chain, the outbox and the quota use signafaide_status.",
      inputSchema: z.object({
        directory,
        agent: z.string().optional().describe("Only this agent's records. Default: every agent with records here."),
        from: z.string().optional().describe("Only records at or after this time: an ISO time such as 2026-11-13T10:00:00Z, or a date (YYYY-MM-DD)."),
        to: z.string().optional().describe("Only records before this ISO time, or up to the end of this date (YYYY-MM-DD)."),
        record: z.string().optional().describe("A record hash, or its first 8 or more characters: returns that record and its paired decision or outcome."),
        limit: z.number().int().min(1).optional().describe(`The most records to return. Default ${RECORDS_DEFAULT}; values above ${RECORDS_MAX} are treated as ${RECORDS_MAX}.`),
      }),
      annotations: readOnly(true),
    },
    ({ directory: dir, agent, from, to, record, limit }) => guard(() => recordLines(open(dir), { agent, from, to, record, limit })),
  );

  server.registerTool(
    "signafaide_flush",
    {
      title: "Send the waiting signafAIde records now",
      description:
        "Sends the records waiting in this project's outbox to the signafAIde service (or the SIGNAFAIDE_URL witness) now, the same as `signafaide flush`, and saves the receipts that come back beside the records. " +
        "What is sent is each record's envelope (hashes, agent and tool names, times) with the agent's signature, never inputs or outputs unless stored content was turned on in the code. " +
        "Use it after signafaide_init, or when signafaide_status shows records waiting. Records also ship by themselves while the agent runs, and signafaide_verify ships them before it checks; this tool only ships. " +
        "It sends only when an API key already exists, which means a person opted in with `signafaide init`, signafaide_init or SIGNAFAIDE_API_KEY. " +
        "Without a key it does nothing and says so: it never creates a sandbox and never opts in. " +
        "Returns how many records were shipped, how many are left in the outbox, each chain that is BLOCKED with its next step, and each error with its code (see signafaide_explain_error). " +
        "Safe to repeat: a record that has shipped is not sent again.",
      inputSchema: z.object({ directory }),
      annotations: SENDS,
    },
    async ({ directory: dir }) => {
      try {
        const rec = open(dir);
        const r = await flushReport(rec);
        const out = [...r.errors.map((e) => `could not ship ${e}`), ...r.lines];
        if (r.codes.length) out.push(`error ${r.codes.length === 1 ? "code" : "codes"}: ${r.codes.join(", ")} (see signafaide_explain_error)`);
        if (!r.sent) out.push("This tool never creates a sandbox. Sending starts only after the user agrees: ask them, then call signafaide_init, or they run `npx signafaide init` or set SIGNAFAIDE_API_KEY.");
        return text(out.join("\n"), r.failed);
      } catch (e) {
        return text(`signafaide: ${(e as Error).message}`, true);
      }
    },
  );

  return server;
}

/** Serve over stdio until the client closes stdin. */
export async function serve(): Promise<void> {
  const { serveStdio } = await import("@modelcontextprotocol/server/stdio");
  const root = process.cwd();
  serveStdio(() => createServer(root));
}
