# Starter templates

Two small agents with signafAIde already in place: the project note for coding agents (`AGENTS.md`, and `CLAUDE.md` that reads it), the checks file (`signafaide.checks.json`) and one protected tool. Each test runs out of the box on your machine with no account and no key: a scripted model stands in for a real one, the rule is kept on this machine, and the test runs in test mode (records in a temporary folder, nothing sent).

| folder | framework | run | test |
|---|---|---|---|
| [`vercel-ai-agent`](vercel-ai-agent) | Vercel AI SDK (TypeScript) | `npm install && npm start` | `npm test` |
| [`openai-agents-python`](openai-agents-python) | OpenAI Agents SDK (Python) | `uv sync && uv run python run.py` | `uv run python smoke.py && uv run signafaide check --ci` |

Copy one out to start a project, for example `npx degit AIME-TECH-UK-LIMITED/signafaide-sdk/templates/vercel-ai-agent my-agent`. Both depend on the released `signafaide` 0.5.1 or later.

In both, `approve_payout` pays money and is protected (`"protect": true` in `signafaide.checks.json`, so `signafaide checks status` lists it as a protected tool), with the rule "Block approve_payout when amount is above 1,000" On, kept on this machine. `lookup_invoice` only reads and is recorded. The test pays 800, sees 1,200 blocked before the tool runs, and runs `signafaide check --ci`, the check that fails a pull request adding a risky tool without protection.

A protected tool asks signafAIde for a ruling on every call the rule on this machine lets through. Outside the test, with no key or sandbox, a call of 1,200 is still blocked here, and a call of 800 stops with `no_key` until a person runs `signafaide init` (a free sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`.
