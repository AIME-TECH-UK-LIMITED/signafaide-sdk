# Payout agent: OpenAI Agents SDK

An OpenAI Agents SDK agent with two tools. `approve_payout` pays money, so it is protected (`"protect": true` in `signafaide.checks.json`): the rule kept there blocks it above 1,000, and a call the rule lets through runs only when signafAIde rules allow it. `lookup_invoice` only reads, so it is recorded. Every call is signed and recorded on this machine in `.signafaide/`.

```sh
uv sync
uv run python smoke.py && uv run signafaide check --ci  # pays 800, 1,200 blocked, then the CI check
uv run python run.py                                    # the scripted model asks to pay 1,200: blocked here
uv run signafaide init                                  # a person, once: a free sandbox that rules on calls
uv run python run.py Pay Ashgrove Catering Ltd 800 GBP
```

(`pip install signafaide openai-agents` in a virtual environment works too.) `smoke.py` runs in test mode (`SIGNAFAIDE_TEST=1`, set before the tools are imported): records go to a temporary folder and nothing is sent, so the protected tool runs without a ruling, as under pytest, and the rule on this machine still blocks 1,200. The test prints:

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
| `smoke.py` | the test, in test mode |
| `payout_agent/scripted_model.py` | a stand-in model: it calls `approve_payout` with the amount in the prompt |
| `signafaide.checks.json` | `"protect": true` for `approve_payout` (`uv run signafaide checks status` lists it as a protected tool) and the rule, kept on this machine; `"mode": "enforce"` is On, `"watch"` is Calibrating (it only notes "Would have blocked") |
| `AGENTS.md`, `CLAUDE.md` | the note that tells coding agents to protect the next tool that pays, deletes, sends, runs commands or pushes code |

## A real model

Set `OPENAI_API_KEY` and `AGENT_MODEL` (a model name), then `uv run python run.py`.

## Then

- `uv run signafaide status`: one line per tool, `uv run signafaide verify`: the records' signatures and chain.
- `uv run signafaide check approve_payout amount=1200`: a dry run, exit 1 when the rule would block.
- `uv run signafaide protect`: at a terminal, to protect another tool or change the rule.
- Outside the test, a protected call the rule here lets through asks signafAIde for a ruling. With no key or sandbox it stops with `no_key` ("protected tools stop until a person runs `signafaide protect` in this project"). A person runs `uv run signafaide init` once (a free sandbox: no account, email or card), or sets `SIGNAFAIDE_API_KEY`; then calls are ruled on, co-signed and timestamped.
