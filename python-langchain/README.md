# langchain-signafaide

signafAIde for LangChain: a signed, tamper-evident record of every tool call an agent makes.

Each tool call writes a `decision` record before the tool runs and an `outcome` record after it. Records are signed with the agent's own key and chained on the machine that wrote them, in `.signafaide/`. Once a person opts in, a witness (the signafAIde service, or one you host) co-signs them and timestamps them publicly, so neither side can forge or edit a record alone. An auditor can verify the records without trusting either side. Records attest integrity and timing, never whether a decision was right.

## Quickstart

To protect the agent's `@tool` functions with rules (block above an amount, On or Calibrating), run this in the agent's folder, at a terminal:

```bash
uv add langchain-signafaide
uv run signafaide protect
```

It finds the `@tool` functions, asks which to protect and what to block, shows the change (`@signafaide.protect(agent=...)` under `@tool`) and asks before writing it, makes a free sandbox if you say yes and saves your rules. Without a terminal, `uv run signafaide protect --yes` protects every tool that pays, deletes, sends messages, runs commands, pushes code or edits secrets or config, with a default rule that starts Calibrating (it blocks nothing until a person turns it On); see the [signafaide README](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/tree/main/python#without-a-terminal-protect---yes). A tool with `@signafaide.protect` in code is protected with or without `signafaide.checks.json`. Then `uv run signafaide check <tool> field=value` (a dry run), `signafaide pull` (the console's rules), `signafaide prove <tool>` (the auditor link) and `signafaide login` (a person's sign-in for saving rules). The middleware below records every tool call the agent makes, whatever protect found.

## Install

```bash
uv add langchain-signafaide      # or, in a virtual environment: python -m pip install langchain-signafaide
```

Needs Python 3.10 or later and LangChain 1.x, and installs `signafaide` 0.4 or later (below 1.0).

## Middleware

```python
from langchain.agents import create_agent
from langchain_signafaide import SignafaideMiddleware

agent = create_agent(
    model="openai:gpt-5",
    tools=[get_weather, refund],
    middleware=[SignafaideMiddleware(agent="support-bot", tools=[get_weather, refund])],
)
agent.invoke({"messages": [("user", "Refund order A1")]})
```

Then check the records:

```bash
signafaide verify
```

| Argument | What it does |
|---|---|
| `agent` | The name of the record chain. Use one name per running agent instance in production. Default: the project folder's name. |
| `tools` | Every tool the agent can call (tools or names). They are declared in the chain as recorded, so a verifier can report that all of the agent's tools are covered. Without it, a tool is declared when it is first called. |
| `strict` | Protects the tool: it runs only once its decision has a receipt from the witness. If the witness cannot be reached, the call raises `NotRecorded` and the tool does not run. |
| `store_content` | Also send inputs and outputs to the witness, encrypted. Default: hashes only. |

The middleware works with `invoke` and `ainvoke`. A tool that raises is recorded with its error and the exception is raised unchanged.

Under pytest nothing is sent and a protected tool runs without a ruling (test mode, from the start of the run), never with a live key. When a proxy or network policy refuses the witness, the error says so in one sentence: allow `signafaide.co.uk` and `api.signafaide.co.uk` in the environment's network settings.

## Tools outside an agent

For tools you call yourself, or pass to something other than `create_agent`:

```python
from langchain_signafaide import wrap_tools

tools = wrap_tools([get_weather, refund], agent="support-bot")
```

Use the middleware or `wrap_tools` for an agent's tools, not both, or each call is recorded twice.

## What is sent, and where

- Before a person opts in: nothing. Records are signed, chained and verified locally.
- After `signafaide init` (a free sandbox: no account, email or card) or with `SIGNAFAIDE_API_KEY` set: each record sends its content hash with its tool name, agent name and time to `https://api.signafaide.co.uk` (hosted in London), or to the address in `SIGNAFAIDE_URL`. Inputs and outputs are not sent unless stored content is turned on. Do not put personal data in tool or agent names.
- The middleware records the tool calls that go through the agent it is attached to. A call your application makes around the agent is not recorded.

## Links

- Documentation: https://signafaide.co.uk/docs/frameworks/langchain
- Privacy notice: https://signafaide.co.uk/legal/privacy
- Support: https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/issues or sales@signafaide.co.uk
- Source: the `python-langchain/` folder of the signafAIde SDK repository. Apache-2.0.
