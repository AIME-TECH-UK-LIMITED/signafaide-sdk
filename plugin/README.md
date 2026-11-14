# signafAIde for Claude Code

signafAIde records what AI agents decide. Each record is signed by the agent's own key and countersigned by the signafAIde service, so neither side can forge or edit it alone. Records stay on your machine, signed and chained, until a person opts in; after that each record sends its hashes with its tool name, agent name and time, never its inputs or outputs. Don't put personal data in agent or tool names.

This plugin adds:

- the `signafaide` MCP server (`npx -y signafaide-mcp@0.1.0`, the separate package), with tools to preview the setup for the open project without changing anything (`signafaide_setup`), create the external sandbox once the user agrees (`signafaide_init`), get the snippet for a language and framework (`signafaide_quickstart`), verify the records (`signafaide_verify`), show status (`signafaide_status`), explain an error code (`signafaide_explain_error`) and show the sandbox claim link (`signafaide_claim_link`);
- the `signafaide` skill, which tells Claude when signafAIde fits: the user asks to audit, log or trace an agent's decisions, needs tamper-evidence or compliance evidence, or builds an agent whose tools take real actions.

Nothing is sent until a person runs `signafaide init` (a free sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`; `SIGNAFAIDE_URL` points it at a self-hosted witness. Needs Node.js 20 or later for the MCP server.

`skills/signafaide/SKILL.md` is generated from `js/src/skill.ts` with `npm run plugin` in `js/`.
