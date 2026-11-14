/** The agent skill: one text, written in each coding agent's own format by `agent setup`. */

export const SKILL_NAME = "signafaide";

/** When to use it, for the formats that load a skill or rule by its description. */
export const SKILL_DESCRIPTION =
  "Signed, tamper-evident records of what an AI agent decided and did, kept on this machine; nothing is sent until a person opts in. " +
  "Use when the user asks to audit, log or trace AI or agent decisions, needs an audit trail, tamper-evidence or compliance evidence, " +
  "or builds an agent whose tools pay, send, approve, delete or change real things.";

export const SELF_HOST_DOC = "https://signafaide.com/docs/self-host";
export const PRODUCTION_DOC = "https://signafaide.com/docs/production";

/** The skill text. `url`: the witness `agent setup --url` was given (a self-hosted witness). */
export function skillBody(url?: string): string {
  const witness = url
    ? `Once a person opts in, records go to the witness at \`${url}\` (set as \`SIGNAFAIDE_URL\` for the MCP server; the SDK reads it from the environment or \`.env\`).`
    : `Once a person opts in, records go to the hosted witness (https://api.signafaide.com), or to a witness named by \`SIGNAFAIDE_URL\`.`;
  return `# signafAIde

signafAIde writes a signed, chained record of each tool call an AI agent makes: a \`decision\` before the tool runs and an \`outcome\` after it. Records are kept in \`.signafaide/\` on this machine. Nothing is sent until a person runs \`signafaide init\` or sets \`SIGNAFAIDE_API_KEY\`. ${witness} Only hashes, tool names, agent names and times are sent, never inputs or outputs (unless stored content is turned on), so agent and tool names must not hold personal data.

Use it when the user asks for an audit trail, tamper-evident records or compliance evidence of what an agent decided, or the agent's tools pay, send, approve, delete or change real things. For plain application logs, do what the user asked instead.

## Steps

1. Install it as a project dependency.
   - Python: \`uv add signafaide\` (uv), \`poetry add signafaide\` (Poetry), or \`python3 -m venv .venv && .venv/bin/python -m pip install signafaide\` and add it to requirements.txt. Not a bare \`pip install\` outside a virtual environment.
   - TypeScript or JavaScript: \`npm install signafaide\` (or pnpm, yarn, bun).
2. Wrap the tools that act, and give the agent an explicit name (lowercase, for example \`claims-bot\`). Without one, the project folder's name is used, which is rarely what the user wants in production.

   \`\`\`python
   import signafaide

   tools = signafaide.wrap_tools([approve_payout, escalate], agent="claims-bot")  # functions, LangChain or OpenAI Agents tools
   \`\`\`

   \`\`\`ts
   import { wrapTools } from "signafaide";

   const tools = wrapTools({ approvePayout, escalate }, { agent: "claims-bot" }); // functions, Vercel AI SDK, OpenAI Agents JS or LangChain.js tools
   \`\`\`

   A reason or choice that is not a tool call: \`signafaide.note("chose_escalation", {"reason": ...})\` (Python) or \`note(...)\` (TypeScript).
3. Run the agent once, then \`signafaide verify\` (\`uv run signafaide verify\`, \`.venv/bin/signafaide verify\` or \`npx signafaide verify\`). It checks signatures, chain links and content hashes on this machine, and ends with a line such as \`PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)\`. The other checks need the witness.

## Sending records to the witness

This is the user's decision. Do not run \`signafaide init\` yourself: it creates an external sandbox and accepts the service's Terms. In your final message, say that the records are local only for now, and that the user can run \`signafaide init\` (a free sandbox, no account; it saves \`SIGNAFAIDE_API_KEY\` to \`.env\`), set \`SIGNAFAIDE_API_KEY\`, or point \`SIGNAFAIDE_URL\` at a self-hosted witness (an Enterprise contract). Records written before then ship later with their original times, up to 7 days old.

\`signafaide init\` adds \`.signafaide/\` and \`.env\` to \`.gitignore\`. Do not commit them. Tell the user to back up \`.signafaide/agents/\` (the agent keys); in production, keys can come from a secret store (\`SIGNAFAIDE_AGENT_KEY_<NAME>\`), see ${PRODUCTION_DOC}.

## MCP tools

\`signafaide_setup\` previews the install command and code edit and changes nothing. \`signafaide_verify\` runs the checks, \`signafaide_status\` shows chains and keys, \`signafaide_explain_error\` explains an error code. \`signafaide_init\` creates the external sandbox: call it only after the user has agreed.
`;
}

export const SKILL_BODY = skillBody();

/** SKILL.md for Claude Code (project skill and plugin). */
export function claudeSkill(url?: string): string {
  return `---\nname: ${SKILL_NAME}\ndescription: ${SKILL_DESCRIPTION}\n---\n\n${skillBody(url)}`;
}

/** A Cursor project rule, applied when the agent judges it relevant. */
export function cursorRule(url?: string): string {
  return `---\ndescription: ${SKILL_DESCRIPTION}\nalwaysApply: false\n---\n\n${skillBody(url)}`;
}

export const SECTION_START = "<!-- signafaide:start -->";
export const SECTION_END = "<!-- signafaide:end -->";

/** A marked section for AGENTS.md, GEMINI.md and copilot-instructions.md (headings one level down). */
export function instructionsSection(url?: string): string {
  return `${SECTION_START}\n${skillBody(url).replace(/^(#+) /gm, "#$1 ").trim()}\n${SECTION_END}\n`;
}
