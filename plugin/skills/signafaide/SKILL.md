---
name: signafaide
description: Signed, tamper-evident records of what an AI agent decided and did, kept on this machine; nothing is sent until a person opts in. Use when the user asks to audit, log or trace AI or agent decisions, needs an audit trail, tamper-evidence or compliance evidence, or builds an agent whose tools pay, send, approve, delete or change real things.
---

# signafAIde

signafAIde writes a signed, chained record of each tool call an AI agent makes: a `decision` before the tool runs and an `outcome` after it. Records are kept in `.signafaide/` on this machine. Nothing is sent until a person runs `signafaide init` or sets `SIGNAFAIDE_API_KEY`. Once a person opts in, records go to the hosted witness (https://api.signafaide.co.uk), or to a witness named by `SIGNAFAIDE_URL`. Only hashes, tool names, agent names and times are sent, never inputs or outputs (unless stored content is turned on), so agent and tool names must not hold personal data.

Use it when the user asks for an audit trail, tamper-evident records or compliance evidence of what an agent decided, or the agent's tools pay, send, approve, delete or change real things. For plain application logs, do what the user asked instead.

## Steps

1. Install it as a project dependency.
   - Python: `uv add signafaide` (uv), `poetry add signafaide` (Poetry), or `python3 -m venv .venv && .venv/bin/python -m pip install signafaide` and add it to requirements.txt. Not a bare `pip install` outside a virtual environment.
   - TypeScript or JavaScript: `npm install signafaide` (or pnpm, yarn, bun).
2. Wrap the tools that act, and give the agent an explicit name (lowercase, for example `claims-bot`). Without one, the project folder's name is used, which is rarely what the user wants in production.

   ```python
   import signafaide

   tools = signafaide.wrap_tools([approve_payout, escalate], agent="claims-bot")  # functions, LangChain or OpenAI Agents tools
   ```

   ```ts
   import { wrapTools } from "signafaide";

   const tools = wrapTools({ approvePayout, escalate }, { agent: "claims-bot" }); // functions, Vercel AI SDK, OpenAI Agents JS or LangChain.js tools
   ```

   A reason or choice that is not a tool call: `signafaide.note("chose_escalation", {"reason": ...})` (Python) or `note(...)` (TypeScript).

   Tools that move money, freeze or close accounts, delete data or send messages: wrap them in strict mode, `wrap_tools([...], agent="claims-bot", strict=True)` or `wrapTools({...}, { agent: "claims-bot", strict: true })`, so the tool runs only once the witness has co-signed its decision record, and not at all when it cannot be reached. Strict mode needs an API key: until a person opts in, a strict call fails with `no_key` and its tool does not run, so say so in your final message.
3. Record what you did not wrap. MCP servers the agent uses: start each one through the gateway in the agent's MCP configuration, `{"command": "npx", "args": ["-y", "signafaide", "gateway", "--agent", "claims-bot", "--", <the server's command and arguments>]}`; it records every tool call that passes through it and forwards none it cannot record. Then give the full list of the tools your code hands the agent, once at start-up: `signafaide.declare_tools(["approve_payout", "escalate", "web_search"], agent="claims-bot")` (Python) or `declareTools([...], { agent: "claims-bot" })` (TypeScript). A tool you did not wrap is declared as not recorded, and `signafaide verify` names it. The gateway records only the calls that go through it, so make it the only route to those tools.
4. Run the agent once, then `signafaide verify` (`uv run signafaide verify`, `.venv/bin/signafaide verify` or `npx signafaide verify`). It checks signatures, chain links and content hashes on this machine, and ends with a line such as `PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`. The other checks need the witness.

## Tool-call checks

`signafaide agent setup` writes `signafaide.checks.json` in watch mode (`signafaide init` does too, and is the user's to run, see below): checks for secrets, internal addresses, changed tools and known-bad tools, and the user's rules, note what they find and never block a call. Commit the file. Enforce mode, which blocks, is the user's choice: say so, do not set it.

Strict tools (payments, deletes, outbound messages) also ask the witness for a ruling, allow or block, before they run, and do not run without one. By default only tool fingerprints leave the machine. A rule can need a field of the call's arguments: the user lists it in that tool's `disclose` to opt in. Name the fields and ask; never add one yourself.

Reading a ruling: `signafaide verify` prints a `tool-call checks:` line for each agent, `signafaide checks status` shows the mode and the strict tools, `signafaide rules show` the rule set held, and `signafaide rules test <tool> '<arguments JSON>'` what a call would meet. One record's ruling is explained by the `signafaide_explain_ruling` tool of the local MCP server (`signafaide agent setup`). A ruling is the witness's decision on what the client disclosed, not a statement that the call was right. In watch mode a block is only a note: enforce mode would have blocked it.

## Sending records to the witness

This is the user's decision. Do not run `signafaide init` yourself: it creates an external sandbox and accepts the service's Terms. In your final message, say that the records are local only for now, and that the user can run `signafaide init` (a free sandbox, no account; it saves `SIGNAFAIDE_API_KEY` to `.env`), set `SIGNAFAIDE_API_KEY`, or point `SIGNAFAIDE_URL` at a self-hosted witness (an Enterprise contract). Records written before then ship later with their original times, up to 7 days old.

`signafaide init` adds `.signafaide/` and `.env` to `.gitignore`. Do not commit them. Tell the user to back up `.signafaide/agents/` (the agent keys); in production, keys can come from a secret store (`SIGNAFAIDE_AGENT_KEY_<NAME>`, made with `signafaide keys create --agent <name> --env live --print`), see https://signafaide.co.uk/docs/production.

When the user needs evidence for an auditor, a bank or a regulator, end your final message with that path: a live API key and agent keys in the secret store; an auditor link from the console with the agent keys and `head.json` attached, which gives the auditor the records and a pack with the exact verify command; and the verification report for the period (console, Reports). For containers without a persistent disk, point to the checklist in https://signafaide.co.uk/docs/production.

## Containers without a persistent disk

- Set `SIGNAFAIDE_HEAD_FILE` to a path on a persistent volume or a mounted bucket, so the newest signed heads outlive the container (the auditor's `head.json`). Agent keys come from the secret store, as above.
- Stored content: by default only hashes leave the machine and the inputs and outputs stay in `.signafaide/chain/`, which such a container loses with its disk. If the user will need them later (replay, an auditor reading inputs and outputs), turn on stored content (`store_content=True` in Python, `storeContent: true` in TypeScript; the witness keeps it encrypted, and live records need a plan that includes it) or keep `.signafaide/chain/` on a persistent volume. Say which one you chose.
- A new container continues the chain with a signed start note. Call `signafaide.stop()` (Python) or `await stop()` (TypeScript) in the shutdown handler: it sends what is left and writes a signed stop note, so a routine restart is recorded as clean. A start with no stop note before it is shown as a warning, because records the earlier instance had not sent are not known.

## Commands

Run these in the project folder (`npx signafaide <command>` in a TypeScript project, `uv run signafaide <command>` or `.venv/bin/signafaide <command>` in a Python one).

- `verify` runs the checks on the local records and prints PASS or FAIL.
- `status` shows the key, the agent chains, the records waiting to be sent and the quota.
- `replay` shows what an agent saw and did, from the local records.
- `flush` sends the waiting records once an API key exists, and does nothing without one.
- `init` creates the external sandbox and from then on sends record hashes to the witness. It is the user's to run, as above: it accepts the Terms (https://signafaide.co.uk/legal/terms) and the Privacy notice (https://signafaide.co.uk/legal/privacy).
- `claim` prints the link the user opens to claim the sandbox. Show it to the user; do not open it yourself.

## MCP tools

The plugin's `signafaide` MCP server is hosted (https://api.signafaide.co.uk/mcp). It reads nothing on this machine, needs no account and changes nothing. `signafaide_quickstart` gives the install command and code for a language and framework, `signafaide_explain_error` explains an error code, `signafaide_check_auditor_link` checks an auditor link, `signafaide_verify_pack` verifies a verification pack sent to it, and `signafaide_service_keys` gives the service's public keys. Recording and checking the project's own records use the commands above, on this machine.
