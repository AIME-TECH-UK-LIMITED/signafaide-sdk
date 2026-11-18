# Payout agent: OpenAI Agents SDK

An OpenAI Agents SDK agent with two tools. `approve_payout` pays money, so it runs only when the rule in `signafaide.checks.json` allows it; `lookup_invoice` only reads, so it is recorded. Every call is signed and recorded on this machine in `.signafaide/`; nothing is sent and no account is made.

```sh
uv sync
uv run python run.py                                    # the scripted model asks to pay 1,200: blocked
uv run python run.py Pay Ashgrove Catering Ltd 800 GBP
uv run python smoke.py && uv run signafaide check --ci  # pays 800, 1,200 blocked, then the CI check
```

(`pip install signafaide openai-agents` in a virtual environment works too.) The test prints:

```text
ok   Pay Ashgrove Catering Ltd 800 GBP.
     paid 800 GBP to Ashgrove Catering Ltd
ok   Pay Ashgrove Catering Ltd 1200 GBP.
     approve_payout did not run: the rule on this machine blocked it ("Block approve_payout when amount is above 1,000"); signafAIde did not rule on it. To allow it, change the rule in signafaide.checks.json.
signafaide check --ci: passed. 1 risky tool: 1 protected, 0 allowed (Python, 2 tools found).
```

## What is where

| file | what |
|---|---|
| `payout_agent/tools.py` | the tools: `@function_tool` above `@signafaide.record(...)`, `declare_tools(...)` with the full tool list, and `say_why`, which tells the model why a call was blocked (the Agents SDK otherwise says only that an error occurred) |
| `payout_agent/agent.py` | one `Runner.run_sync` with the tools, up to five turns |
| `payout_agent/scripted_model.py` | a stand-in model: it calls `approve_payout` with the amount in the prompt |
| `signafaide.checks.json` | the rule, kept on this machine; `"mode": "enforce"` is On, `"watch"` is Calibrating (it only notes "Would have blocked") |
| `AGENTS.md`, `CLAUDE.md` | the note that tells coding agents to protect the next tool that pays, deletes, sends, runs commands or pushes code |

## A real model

Set `OPENAI_API_KEY` and `AGENT_MODEL` (a model name), then `uv run python run.py`.

## Then

- `uv run signafaide status`: one line per tool, `uv run signafaide verify`: the records' signatures and chain.
- `uv run signafaide check approve_payout amount=1200`: a dry run, exit 1 when the rule would block.
- `uv run signafaide protect`: at a terminal, to protect another tool or change the rule. To have signafAIde co-sign and timestamp the records, a person runs `uv run signafaide init` (a free sandbox: no account, email or card).
