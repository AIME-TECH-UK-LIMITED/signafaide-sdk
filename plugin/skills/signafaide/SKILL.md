---
name: signafaide
description: Signed, tamper-evident records of what an AI agent decided and did, kept on this machine; nothing is sent until a person opts in. Use when the user asks to audit, log or trace AI or agent decisions, needs an audit trail, tamper-evidence or compliance evidence, or builds an agent whose tools pay, send, approve, delete or change real things.
---

# signafAIde

signafAIde writes a signed, chained record of each tool call an AI agent makes: a `decision` before the tool runs and an `outcome` after it. Records are kept in `.signafaide/` on this machine. Nothing is sent until a person runs `signafaide init` or sets `SIGNAFAIDE_API_KEY`. Once a person opts in, records go to the hosted witness (https://api.signafaide.com), or to a witness named by `SIGNAFAIDE_URL`. Only hashes, tool names, agent names and times are sent, never inputs or outputs (unless stored content is turned on), so agent and tool names must not hold personal data.

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
3. Run the agent once, then `signafaide verify` (`uv run signafaide verify`, `.venv/bin/signafaide verify` or `npx signafaide verify`). It checks signatures, chain links and content hashes on this machine, and ends with a line such as `PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`. The other checks need the witness.

## Sending records to the witness

This is the user's decision. Do not run `signafaide init` yourself: it creates an external sandbox and accepts the service's Terms. In your final message, say that the records are local only for now, and that the user can run `signafaide init` (a free sandbox, no account; it saves `SIGNAFAIDE_API_KEY` to `.env`), set `SIGNAFAIDE_API_KEY`, or point `SIGNAFAIDE_URL` at a self-hosted witness (an Enterprise contract). Records written before then ship later with their original times, up to 7 days old.

`signafaide init` adds `.signafaide/` and `.env` to `.gitignore`. Do not commit them. Tell the user to back up `.signafaide/agents/` (the agent keys); in production, keys can come from a secret store (`SIGNAFAIDE_AGENT_KEY_<NAME>`, made with `signafaide keys create --agent <name> --env live --print`), see https://signafaide.com/docs/production.

When the user needs evidence for an auditor, a bank or a regulator, end your final message with that path: a live API key and agent keys in the secret store; an auditor link from the console with the agent keys and `head.json` attached, which gives the auditor the records and a pack with the exact verify command; and the verification report for the period (console, Reports). For containers without a persistent disk, point to the checklist in https://signafaide.com/docs/production.

## MCP tools

`signafaide_setup` previews the install command and code edit and changes nothing. `signafaide_verify` runs the checks, `signafaide_status` shows chains and keys, `signafaide_explain_error` explains an error code. `signafaide_init` creates the external sandbox: call it only after the user has agreed.
