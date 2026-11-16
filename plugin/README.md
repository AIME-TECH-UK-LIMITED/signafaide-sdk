# signafAIde for Claude Code

signafAIde records what AI agents decide. Each record is signed by the agent's own key and countersigned by the signafAIde service, so neither side can forge or edit it alone. Records stay on your machine, signed and chained, until a person opts in; after that each record sends its hashes with its tool name, agent name and time, never its inputs or outputs. Don't put personal data in agent or tool names.

This plugin adds:

- the `signafaide` skill, which tells Claude when signafAIde fits: the user asks to audit, log or trace an agent's decisions, needs tamper-evidence or compliance evidence, or builds an agent whose tools take real actions. Claude then adds the SDK to the project (`signafaide` on npm and PyPI), wraps the tools that act, starts the MCP servers the application's agent uses through `signafaide gateway`, which records every tool call that passes through it, and declares the agent's full tool list, so a verifier can say which tools are recorded. It checks the records with the SDK's command line (`signafaide verify`, `status`, `replay`) on this machine. The gateway records every call that goes through it; a call the application makes around it is still not recorded, so the deployment has to make the gateway the only route to those tools.
- the hosted `signafaide` MCP server (`https://api.signafaide.co.uk/mcp`), read-only and with no account: `signafaide_quickstart` (the install command and code for a language and framework), `signafaide_explain_error` (what an error code means and what to do), `signafaide_check_auditor_link` (checks an auditor link), `signafaide_verify_pack` (verifies a verification pack) and `signafaide_service_keys` (the service's public keys). It reads nothing on your machine and changes nothing. It receives only what Claude passes to a tool: a language and framework, an error code, an auditor link, or a verification pack, which holds record hashes, tool names, agent names and times. It does not store or log what it receives; it counts calls per tool.

## What it sends, and where

- Before a person opts in: nothing from the SDK, which works on the local machine only. The hosted MCP server receives only what a tool call passes to it, as above.
- After `signafaide init` or with `SIGNAFAIDE_API_KEY` set: for each record, its hashes, the agent name, the tool name, the time and the agent's signature go to the signafAIde service at `https://api.signafaide.co.uk` (hosted in London), or to the address in `SIGNAFAIDE_URL`. Inputs and outputs are not sent unless the project turns on stored content.
- The service keeps these records with no time limit, because they are the evidence. A sandbox that nobody claims expires. See the [privacy notice](https://signafaide.co.uk/legal/privacy).
- Requests to the service carry a client header: the SDK name and version, the runtime and its version, the framework adapter in use, the coding agent that set the project up, and how the request was made. `verify` and `export` also send one event naming the command. Never content, file paths, hostnames or user names. `SIGNAFAIDE_TELEMETRY=0` drops the adapter, the agent and the events.

Nothing is sent until a person runs `signafaide init` (a free sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`; `SIGNAFAIDE_URL` points it at a self-hosted witness. The SDK needs Node.js 18 or later, or Python 3.9 or later.

`skills/signafaide/SKILL.md` is generated from `js/src/skill.ts` with `npm run plugin` in `js/`.
