/** The agent skill: one text, written in each coding agent's own format by `agent setup`. */

export const SKILL_NAME = "signafaide";

/** When to use it, for the formats that load a skill or rule by its description. */
export const SKILL_DESCRIPTION =
  "Use when the user asks to add signafAIde, to check or block an AI agent's tool calls before they run (for example payments, deletions, outgoing messages or commands), or for a signed audit trail of what an AI agent did. " +
  "signafAIde wraps a tool with protect(): it runs only when the rules a person set allow it, and each call is signed and recorded on this machine; nothing is sent until a person opts in.";

/** The one command that makes protected tools work here, and the non-interactive one an agent can run. */
export const PROTECT_CMD = { ts: "npx signafaide protect", py: "signafaide protect" };
export const AGENT_PROTECT_CMD = "npx signafaide protect --yes --tool <name> --limit-field amount --above 1000";

/** The project note: one paragraph and three lines, added to AGENTS.md / CLAUDE.md as a marked block
 * by `protect`, `init` and `agent setup`, and shipped as agents/AGENTS.md, agents/CLAUDE.md and
 * agents/cursor-rules.mdc (`npm run plugin`). The Python SDK holds the same text (agent_note.py). */
export const NOTE =
  "## signafAIde\n\n" +
  "This project uses signafAIde to check an AI agent's tool calls before they run. " +
  "Use it when adding or changing a tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config: " +
  "wrap that tool with protect(), and it runs only when the rules a person set allow it, with each call signed and recorded. " +
  "Records stay on this machine in .signafaide/; nothing is sent and nothing is created online until a person opts in.\n\n" +
  "- Install: `npm install signafaide` (TypeScript, JavaScript) or `uv add signafaide` (Python; `pip install signafaide` inside the project's virtual environment also works).\n" +
  '- Wrap: `protect(payout, { args: ["payee", "amount"], agent: "my-agent" })` from "signafaide", or `@signafaide.protect(agent="my-agent")` above the function in Python.\n' +
  `- Make it work here: \`${PROTECT_CMD.ts}\` (or \`${PROTECT_CMD.py}\` in Python), run once by a person in a terminal; protected tools stop until then. ` +
  `Without a terminal, \`${AGENT_PROTECT_CMD}\` writes the code and a rule that starts Calibrating (it blocks nothing until a person turns it On).\n`;

/** The organisation note: the project note for every repository of a company, set once by an
 * administrator (Claude Code managed CLAUDE.md, Cursor Team Rules, Copilot organisation
 * instructions, Codex managed configuration, Windsurf system rules). It names the per-project
 * install first, since the organisation rule reaches repositories that have no signafAIde yet.
 * Shipped in agents/team/ (`npm run plugin`). */
export const TEAM_NOTE =
  "## signafAIde\n\n" +
  "This organisation uses signafAIde, in every repository, to check an AI agent's tool calls before they run. " +
  "Use it when adding or changing a tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config: " +
  "wrap that tool with protect(), and it runs only when the rules a person set allow it, with each call signed and recorded. " +
  "Records stay on the machine in .signafaide/; nothing is sent and nothing is created online until a person opts in. " +
  "This rule applies to every project, but signafAIde is installed per project: in a repository that does not have it yet, install it there first.\n\n" +
  NOTE.split("\n")
    .filter((l) => l.startsWith("- "))
    .join("\n") +
  "\n- In CI: `npx signafaide check --ci` (or `signafaide check --ci` in Python) fails when a risky tool is not protected; commit `signafaide.checks.json`.\n";

/** The files in agents/team/, by path under it: the organisation note in each tool's own format. */
export function teamFiles(): Record<string, string> {
  const toml = TEAM_NOTE.replace(/\n$/, "");
  if (toml.includes("'''"))
    throw new Error("the organisation note cannot hold three single quotes (a TOML literal string)");
  return {
    "claude-code/CLAUDE.md": TEAM_NOTE,
    "claude-code/managed-settings.d/50-signafaide.json": JSON.stringify({ claudeMd: TEAM_NOTE }, null, 2) + "\n",
    "codex/config.toml": `# signafAIde for every Codex session: a managed default (developer_instructions, a config.toml key).\ndeveloper_instructions = '''\n${toml}\n'''\n`,
    "cursor/team-rule.md": TEAM_NOTE,
    "copilot/organization-instructions.md": TEAM_NOTE,
    "windsurf/signafaide.md": TEAM_NOTE,
  };
}

/** The Cursor rule that carries the note, applied to every request. */
export function cursorNoteRule(): string {
  return `---\ndescription: ${SKILL_DESCRIPTION}\nalwaysApply: true\n---\n\n${NOTE}`;
}

/** The text for the site's llms.txt (this repository has none): when to use it first, in the note's words. */
export function llmsSnippet(): string {
  const lines = NOTE.split("\n").filter((l) => l.startsWith("- "));
  return (
    "# signafAIde\n\n" +
    "> Use signafAIde when adding or changing an AI agent tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config. " +
    "protect() makes the tool run only when the rules a person set allow it; each call is signed and recorded on the machine, and nothing is sent until a person opts in.\n\n" +
    "## Get started\n\n" +
    lines.join("\n") +
    "\n\n## Docs\n\n" +
    "- [Coding agents](https://signafaide.co.uk/docs/coding-agents): the project note, the skill and the MCP server\n" +
    "- [Production](https://signafaide.co.uk/docs/production): live keys, agent keys in a secret store, containers\n"
  );
}

export const SELF_HOST_DOC = "https://signafaide.co.uk/docs/self-host";
export const PRODUCTION_DOC = "https://signafaide.co.uk/docs/production";

const LOCAL_TOOLS = `## MCP tools

\`signafaide_setup\` previews the install command and code edit and changes nothing. \`signafaide_verify\` runs the checks, \`signafaide_status\` shows chains and keys, \`signafaide_records\` lists the records on this machine (metadata only, never inputs or outputs), \`signafaide_flush\` sends the waiting records once an API key exists and does nothing without one, \`signafaide_explain_error\` explains an error code, \`signafaide_explain_ruling\` and \`signafaide_show_rules\` read a tool-call ruling and the rules held (read-only). \`signafaide_init\` creates the external sandbox: call it only after the user has agreed, with \`confirm_user_agreed: true\` and \`user_words\` set to what the user wrote when they agreed. Without both it creates nothing.
`;

/** The rules section (spec 1.1, §8); the plugin has no local MCP server, so it names commands. */
function checksSection(plugin: boolean): string {
  const read = plugin
    ? "`signafaide status` shows each tool's rules (\"1 of 3 rules On, 2 Calibrating\"), `signafaide verify` prints `tool-call checks:` and `rules:` lines, and `signafaide check <tool> <field>=<value>...` what a call would meet. One record's ruling is explained by the `signafaide_explain_ruling` tool of the local MCP server, which the user can add by running `signafaide agent setup` in their own terminal; do not run it yourself, because it changes CLAUDE.md and the MCP configuration."
    : "`signafaide_explain_ruling` with a record hash from `signafaide_records` gives the ruling, its basis, the rules in words, the rule set version, the fields not sent and how to allow the call; `signafaide_show_rules` shows the rules held with their state.";
  return `## Rules, Calibrating and On

Each rule is On (it blocks) or Calibrating (it never blocks; it notes what it would have blocked). Only a person turns a rule On: at the \`protect\` prompt, or in the console. Rules added later in the console start Calibrating. A protected tool sends signafAIde only the fields its rules use that the user approved; \`signafaide pull\` asks the user before it adds one. Never add a field to \`signafaide.checks.json\` yourself, and never edit the file's rules to unblock a call: say what blocked it and let the user decide.

Reading a ruling: ${read} A ruling is the witness's decision on what the client sent, not a statement that the call was right. Unit tests run protected tools without a ruling: \`signafaide check\` is the dry run for tests and CI (exit 1 when the call would be blocked).
`;
}

const PLUGIN_TOOLS = `## Commands

Run these in the project folder (\`npx signafaide <command>\` in a TypeScript project, \`uv run signafaide <command>\` or \`.venv/bin/signafaide <command>\` in a Python one).

- \`protect --yes --tool <name> [--limit-field <field> --above <number>]\` is yours to run once the user has asked for signafAIde and agreed (step 1); \`protect\` without \`--yes\` is the user's, in their terminal.
- \`status\` shows one line per tool (recorded, protected, proof), then the key, the chains and the quota.
- \`check <tool> <field>=<value>...\` is a dry run: exit 1 when the call would be blocked.
- \`pull\` fetches the rules and asks the user before a new field is sent; \`prove <tool>\` gives the auditor link.
- \`verify\` runs the checks on the local records and prints PASS or FAIL.
- \`replay\` shows what an agent saw and did, from the local records.
- \`flush\` sends the waiting records once an API key exists, and does nothing without one.
- \`init\` creates the external sandbox and from then on sends record hashes to the witness. It is the user's to run, as above: it accepts the Terms (https://signafaide.co.uk/legal/terms) and the Privacy notice (https://signafaide.co.uk/legal/privacy).
- \`claim\` prints the link the user opens to claim the sandbox. Show it to the user; do not open it yourself.

## MCP tools

The plugin's \`signafaide\` MCP server is hosted (https://api.signafaide.co.uk/mcp). It reads nothing on this machine, needs no account and changes nothing. \`signafaide_quickstart\` gives the install command and code for a language and framework, \`signafaide_explain_error\` explains an error code, \`signafaide_check_auditor_link\` checks an auditor link, \`signafaide_verify_pack\` verifies a verification pack sent to it, and \`signafaide_service_keys\` gives the service's public keys. Recording and checking the project's own records use the commands above, on this machine.
`;

/** The skill text. `url`: the witness `agent setup --url` was given (a self-hosted witness). */
/** `plugin`: the Claude Code plugin, which has the hosted MCP server and runs the command line instead of the local MCP server. */
export function skillBody(url?: string, plugin = false): string {
  const witness = url
    ? `Once a person opts in, records go to the witness at \`${url}\` (set as \`SIGNAFAIDE_URL\` for the MCP server; the SDK reads it from the environment or \`.env\`).`
    : `Once a person opts in, records go to the hosted witness (https://api.signafaide.co.uk), or to a witness named by \`SIGNAFAIDE_URL\`.`;
  return `# signafAIde

Use this when the user asks for signafAIde, asks to check or block an AI agent's tool calls before they run, or asks for a signed audit trail of what an agent did. Do not add signafAIde to a project, install it or run its commands unless the user asked for it. signafAIde wraps a tool with \`protect()\`: it then runs only when the rules a person set allow it, and each call is signed and recorded. Records stay in \`.signafaide/\` on this machine; nothing is sent until a person opts in. Once the user has asked for it: install it (step 2), then, with their agreement, run \`${AGENT_PROTECT_CMD}\` (\`uv run signafaide protect --yes ...\` in Python). It writes \`protect(...)\` into the code and adds a rule that starts Calibrating: it blocks nothing until a person turns it On. Protected tools stop until a person runs \`${PROTECT_CMD.ts}\` (or \`${PROTECT_CMD.py}\`) once in a terminal, so say that in your final message.

signafAIde records each tool call an AI agent makes (a signed \`decision\` before the tool runs and an \`outcome\` after it), protects the tools that act with rules a person sets, and proves both to an auditor. Nothing is sent until a person runs \`signafaide protect\` or \`signafaide init\`, or sets \`SIGNAFAIDE_API_KEY\`. ${witness} Only hashes, tool names, agent names and times are sent, never inputs or outputs (unless stored content is turned on, or a protected tool's rules use a field the user approved), so agent and tool names must not hold personal data. For plain application logs, do what the user asked instead.

## Steps

1. Once the user has asked for signafAIde and agreed to the change, install it (step 2), then run \`npx signafaide protect --yes --tool <name>\` (\`uv run signafaide protect --yes --tool <name>\` in Python); add \`--limit-field <field> --above <number>\` to set a limit. It finds the tool, writes \`protect(...)\` and \`record(...)\` into the code and the checks file, and adds the limit as a rule that starts Calibrating. It never turns a rule On, never approves a field for sending, never makes a sandbox and never writes AGENTS.md or CLAUDE.md: then ask the user to run \`npx signafaide protect\` (or \`uv run signafaide protect\`) in their own terminal (in Claude Code they can start the line with \`!\` to run it there). That run asks what to block (the limit, then On or Calibrating), makes a free sandbox if they agree, and saves their rules. It also offers to add a short note to CLAUDE.md or AGENTS.md that later coding sessions read (No is the default): say so. Do not answer its questions for them.
2. Install it as a project dependency: \`uv add signafaide\` (uv), \`poetry add signafaide\` (Poetry) or \`python3 -m venv .venv && .venv/bin/python -m pip install signafaide\` (not a bare \`pip install\` outside a virtual environment); \`npm install signafaide\` (or pnpm, yarn, bun). When protect cannot find the tools, write it by hand. Give the agent an explicit name (lowercase, for example \`claims-bot\`).

   \`\`\`ts
   import { protect, record, declareTools } from "signafaide";

   export const tools = {
     approve_payout: protect(approvePayout, { args: ["payee", "amount", "currency"], agent: "claims-bot" }), // waits for signafAIde to allow it
     lookup_invoice: record(lookupInvoice, { args: ["id"], agent: "claims-bot" }), // recorded only
   };
   declareTools(Object.keys(tools), { agent: "claims-bot" });
   \`\`\`

   \`\`\`python
   import signafaide

   @signafaide.protect(agent="claims-bot")
   def approve_payout(payee: str, amount: float, currency: str): ...

   tools = signafaide.wrap_tools([lookup_invoice, escalate], agent="claims-bot")  # functions, LangChain or OpenAI Agents tools
   signafaide.declare_tools(["approve_payout", "lookup_invoice", "escalate"], agent="claims-bot")
   \`\`\`

   \`args\` names positional arguments so rules find \`amount\` by name. Framework tools: \`wrapTools({...}, { agent: "claims-bot", strict: true })\` or \`wrap_tools([...], agent="claims-bot", strict=True)\` protect a whole list. A protected tool runs only when signafAIde allows it, and, if signafAIde can't be reached, it does not run (Stop, the default; Let it run is a person's choice); without an API key it fails with \`no_key\`, so say so in your final message. A blocked call raises \`SignafaideBlocked\`: one sentence with the rule in words and a link.
3. MCP servers the application's agent uses (not this coding session's): with the user's agreement, start each one through the gateway in that agent's MCP configuration, \`{"command": "npx", "args": ["-y", "signafaide", "gateway", "--agent", "claims-bot", "--", <the server's command and arguments>]}\`; it records every tool call that passes through it and forwards none it cannot record. Declare the full tool list once at start-up (above): a tool you did not wrap is declared as not recorded, and \`signafaide verify\` names it.
4. Run the agent once, then \`signafaide status\` (one line per tool: recorded, protected, proof) and \`signafaide verify\` (\`uv run signafaide verify\`, \`.venv/bin/signafaide verify\` or \`npx signafaide verify\`). Without a key verify ends with a line such as \`PASS (local checks only): 4 of 12 checks passed, 8 not checked (nothing co-signed yet)\`: the other checks need the witness.

${checksSection(plugin)}
## Sending records to the witness

This is the user's decision. Do not run \`signafaide init\` yourself: it creates an external sandbox and accepts the service's Terms. In your final message, say that the records are local only for now, and that the user can run \`signafaide init\` (a free sandbox, no account; it saves \`SIGNAFAIDE_API_KEY\` to \`.env\`), set \`SIGNAFAIDE_API_KEY\`, or point \`SIGNAFAIDE_URL\` at a self-hosted witness (an Enterprise contract). Records written before then ship later with their original times, up to 7 days old.

\`signafaide init\` adds \`.signafaide/\` and \`.env\` to \`.gitignore\`. Do not commit them. Tell the user to back up \`.signafaide/agents/\` (the agent keys); in production, keys can come from a secret store (\`SIGNAFAIDE_AGENT_KEY_<NAME>\`, made with \`signafaide keys create --agent <name> --env live --print\`), see ${PRODUCTION_DOC}.

When the user needs evidence for an auditor, a bank or a regulator, end your final message with that path: \`signafaide prove <tool>\` prints the auditor link (read only, checked in the browser) with the calls, the rules in words and any calls made before protection (\`--files\` writes a pack and the verify command instead); for production, a live API key and agent keys in the secret store, and the verification report for the period (console, Reports). For containers without a persistent disk, point to the checklist in ${PRODUCTION_DOC}.

## Containers without a persistent disk

- Set \`SIGNAFAIDE_HEAD_FILE\` to a path on a persistent volume or a mounted bucket, so the newest signed heads outlive the container (the auditor's \`head.json\`). Agent keys come from the secret store, as above.
- Stored content: by default only hashes leave the machine and the inputs and outputs stay in \`.signafaide/chain/\`, which such a container loses with its disk. If the user will need them later (replay, an auditor reading inputs and outputs), turn on stored content (\`store_content=True\` in Python, \`storeContent: true\` in TypeScript; the witness keeps it encrypted, and live records need a plan that includes it) or keep \`.signafaide/chain/\` on a persistent volume. Say which one you chose.
- A new container continues the chain with a signed start note. Call \`signafaide.stop()\` (Python) or \`await stop()\` (TypeScript) in the shutdown handler: it sends what is left and writes a signed stop note, so a routine restart is recorded as clean. A start with no stop note before it is shown as a gap, because records the earlier instance had not sent are not known.

${plugin ? PLUGIN_TOOLS : LOCAL_TOOLS}`;
}

export const SKILL_BODY = skillBody();

/** SKILL.md for Claude Code (project skill and plugin). */
export function claudeSkill(url?: string): string {
  return `---\nname: ${SKILL_NAME}\ndescription: ${SKILL_DESCRIPTION}\n---\n\n${skillBody(url)}`;
}

/** SKILL.md for the Claude Code plugin: the command line, and the hosted MCP server. */
export function pluginSkill(): string {
  return `---\nname: ${SKILL_NAME}\ndescription: ${SKILL_DESCRIPTION}\n---\n\n${skillBody(undefined, true)}`;
}

/** A Cursor project rule, applied when the agent judges it relevant. */
export function cursorRule(url?: string): string {
  return `---\ndescription: ${SKILL_DESCRIPTION}\nalwaysApply: false\n---\n\n${skillBody(url)}`;
}

export const SECTION_START = "<!-- signafaide:start -->";
export const SECTION_END = "<!-- signafaide:end -->";

/** A marked section for AGENTS.md, GEMINI.md and copilot-instructions.md (headings one level down). */
export function instructionsSection(url?: string): string {
  return `${SECTION_START}\n${skillBody(url)
    .replace(/^(#+) /gm, "#$1 ")
    .trim()}\n${SECTION_END}\n`;
}
