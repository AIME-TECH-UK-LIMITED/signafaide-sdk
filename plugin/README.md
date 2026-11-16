# signafAIde for Claude Code

signafAIde records what AI agents decide. Each record is signed by the agent's own key and countersigned by the signafAIde service, so neither side can forge or edit it alone. Records stay on your machine, signed and chained, until a person opts in; after that each record sends its hashes with its tool name, agent name and time, never its inputs or outputs. Don't put personal data in agent or tool names.

This plugin adds:

- the `signafaide` MCP server (`npx -y signafaide-mcp@0.3.4`, the separate package), with tools to preview the setup for the open project without changing anything (`signafaide_setup`), create the external sandbox once the user agrees (`signafaide_init`, which creates nothing unless it is called with `confirm_user_agreed: true` and the user's own words), get a reference snippet for a named language and framework (`signafaide_quickstart`), verify the records (`signafaide_verify`), show status (`signafaide_status`), list and search the records on this machine, metadata only (`signafaide_records`), send the waiting records once an API key exists (`signafaide_flush`, which sends nothing without one), explain an error code (`signafaide_explain_error`) and show the sandbox claim link (`signafaide_claim_link`);
- the `signafaide` skill, which tells Claude when signafAIde fits: the user asks to audit, log or trace an agent's decisions, needs tamper-evidence or compliance evidence, or builds an agent whose tools take real actions. Besides wrapping tools, it has Claude start the MCP servers the application's agent uses through `signafaide gateway`, which records every tool call that passes through it, and declare the agent's full tool list, so a verifier can say which tools are recorded. The gateway records every call that goes through it; a call the application makes around it is still not recorded, so the deployment has to make the gateway the only route to those tools.

## What it sends, and where

- Before a person opts in: nothing. The MCP server and the SDK work on the local machine only.
- After `signafaide init` or with `SIGNAFAIDE_API_KEY` set: for each record, its hashes, the agent name, the tool name, the time and the agent's signature go to the signafAIde service at `https://api.signafaide.co.uk` (hosted in London), or to the address in `SIGNAFAIDE_URL`. Inputs and outputs are not sent unless the project turns on stored content.
- The service keeps these records with no time limit, because they are the evidence. A sandbox that nobody claims expires. See the [privacy notice](https://signafaide.co.uk/legal/privacy).
- Requests to the service carry a client header: the SDK name and version, the runtime and its version, the framework adapter in use, the coding agent that set the project up, and how the request was made. `verify` and `export` also send one event naming the command. Never content, file paths, hostnames or user names. `SIGNAFAIDE_TELEMETRY=0` drops the adapter, the agent and the events.

Nothing is sent until a person runs `signafaide init` (a free sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`; `SIGNAFAIDE_URL` points it at a self-hosted witness. Needs Node.js 20 or later for the MCP server.

`skills/signafaide/SKILL.md` is generated from `js/src/skill.ts` with `npm run plugin` in `js/`.
