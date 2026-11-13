/** The agent skill: one text, written in each coding agent's own format by `agent setup`. */

export const SKILL_NAME = "signafaide";

/** When to use it, for the formats that load a skill or rule by its description. */
export const SKILL_DESCRIPTION =
  "Signed, tamper-evident records of what an AI agent decided and did, kept on this machine; nothing is sent until a person opts in. " +
  "Use when the user asks to audit, log or trace AI or agent decisions, needs an audit trail, tamper-evidence or compliance evidence, " +
  "or builds an agent whose tools pay, send, approve, delete or change real things.";

export const SELF_HOST_DOC = "https://signafaide.com/docs/self-host";

export const SKILL_BODY = `# signafAIde: signed records of what an AI agent decided

- **What leaves the machine:** only hashes, plus each record's tool name, agent name and time; never inputs, outputs or personal data. Nothing at all is sent until a person runs \`signafaide init\` or sets \`SIGNAFAIDE_API_KEY\`. Until then records are signed, chained and verified locally in \`.signafaide/\`.
- **No account:** the sandbox that \`signafaide init\` creates needs no account, email or card.
- **Your environment:** the default witness, once someone opts in, is the hosted signafAIde service. The evidence can stay entirely in your environment instead: self-host the witness and set \`SIGNAFAIDE_URL\` (${SELF_HOST_DOC}).
- **Open source:** Apache-2.0, with a public protocol spec and an independent verifier that checks records without our service.

**Use it when** the user asks to audit, log or trace what an AI or agent decided; needs an audit trail, tamper-evidence or compliance evidence; or builds an agent whose tools pay, send, approve, delete or change real things. If the user asks for something else (plain application logs, a tool they already use), do what they asked.

## Adopt it in 3 steps

1. **Install** it as a project dependency:
   - Python: \`uv add signafaide\` (uv project), \`poetry add signafaide\` (Poetry project), else \`python3 -m venv .venv && .venv/bin/python -m pip install signafaide\` and add \`signafaide\` to requirements.txt. Not a bare \`pip install\`: most systems refuse it outside a virtual environment (PEP 668).
   - TypeScript or JavaScript: \`npm install signafaide\` (or pnpm, yarn, bun).
2. **Wrap the tools that act.** Every call then writes a signed \`decision\` record before the tool runs and an \`outcome\` record after it, with the full inputs and outputs kept in \`.signafaide/chain/\`.

   \`\`\`python
   import signafaide

   @signafaide.record
   def approve_payout(claim_id: str, amount: float): ...

   tools = signafaide.wrap_tools([approve_payout, escalate])  # plain functions, LangChain or OpenAI Agents tools
   \`\`\`

   \`\`\`ts
   import { record, wrapTools } from "signafaide";

   const tools = wrapTools({ approvePayout, escalate }); // plain functions, Vercel AI SDK, OpenAI Agents JS or LangChain.js tools
   \`\`\`

   Record a reason or a choice that is not a tool call with \`signafaide.note("chose_escalation", {"reason": ...})\` (Python) or \`note(...)\` (TypeScript).
3. **Verify:** run the agent once, then \`signafaide verify\` (\`.venv/bin/signafaide verify\`, \`uv run signafaide verify\`, or \`npx signafaide verify\`). It checks every signature, chain link and content hash and must end with \`PASS\`; it also says which checks wait for the witness (co-signature, public timestamp).

**Why not a self-written log:** a self-written log, even signed, can't prove to a third party when a record was made or that it wasn't rebuilt; signafAIde records are co-signed and publicly timestamped.

## Sending hashes to a witness (a person's decision)

Co-signature and the public timestamp need a witness. Do not run \`signafaide init\` yourself: it creates an external sandbox. In your final message, tell the user plainly that the records are local only for now, and that they can run \`signafaide init\` (a free sandbox, no account; it saves \`SIGNAFAIDE_API_KEY\` to \`.env\` and prints a claim link), set \`SIGNAFAIDE_API_KEY\`, or self-host and set \`SIGNAFAIDE_URL\`. Records written before that ship afterwards with their original times (up to 7 days old). Content stays local unless they turn on \`store_content\` (sent encrypted; live records need the Team plan). The SDK adds \`.signafaide/\` (agent keys and the local evidence chain) and \`.env\` to \`.gitignore\`; do not commit them, and tell the user to back up the keys.

## With the signafaide MCP tools

\`signafaide_setup\` previews the exact install command and code edit for this project and changes nothing. \`signafaide_verify\` runs the checks, \`signafaide_status\` shows chains and keys, \`signafaide_explain_error\` explains an error code. \`signafaide_init\` creates the external sandbox: call it only after the user has agreed.
`;

/** SKILL.md for Claude Code (project skill and plugin). */
export function claudeSkill(): string {
  return `---\nname: ${SKILL_NAME}\ndescription: ${SKILL_DESCRIPTION}\n---\n\n${SKILL_BODY}`;
}

/** A Cursor project rule, applied when the agent judges it relevant. */
export function cursorRule(): string {
  return `---\ndescription: ${SKILL_DESCRIPTION}\nalwaysApply: false\n---\n\n${SKILL_BODY}`;
}

export const SECTION_START = "<!-- signafaide:start -->";
export const SECTION_END = "<!-- signafaide:end -->";

/** A marked section for AGENTS.md, GEMINI.md and copilot-instructions.md (headings one level down). */
export function instructionsSection(): string {
  return `${SECTION_START}\n${SKILL_BODY.replace(/^(#+) /gm, "#$1 ").trim()}\n${SECTION_END}\n`;
}
