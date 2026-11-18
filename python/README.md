# signafaide

Audit evidence of what your AI agents did, for EU AI Act record-keeping, ISO/IEC 42001 and SOC 2. Each record is signed with the agent's own key and chained on your machine; once you opt in, a witness (the signafAIde service, or one you host) co-signs and publicly timestamps it, so neither side can forge or edit a record alone.

- Nothing is sent until a person says yes to the sandbox in `signafaide protect` (or runs `signafaide init`), or sets `SIGNAFAIDE_API_KEY`. After that each record sends its content hash with its tool name, agent name and time (and its chain links), never its inputs or outputs unless you turn on stored content. Tool and agent names are sent as you write them, so don't put personal data in them. Each content hash is salted with 16 random bytes that stay on your machine with the content, so the hash alone cannot be used to guess the content, even when it has only a few possible values.
- The sandbox needs no account, email or card.
- To keep the evidence in your environment, self-host the witness and set `SIGNAFAIDE_URL` ([self-host](https://signafaide.co.uk/docs/self-host)).
- Apache-2.0, with a public protocol spec and an independent verifier.

## Quickstart: one command

In your agent's folder, at a terminal:

```bash
uv run signafaide protect         # or .venv/bin/signafaide protect
```

It finds your agent's tools (LangChain `@tool`, OpenAI Agents `@function_tool`, MCP `@mcp.tool()`, `StructuredTool.from_function`, a list or dict named like `tools`, the methods of a class named like tools, the functions of files named like tools), lists every one with what it does, and asks which to protect and what to block: an amount, a currency, a number of calls a minute, each On (it blocks) or Calibrating (it only notes "Would have blocked"). It shows the change to your code as a diff and asks before writing it: `@signafaide.protect(agent=...)` on the tools you protect, `@signafaide.record(agent=...)` on the others (under a framework's decorator), and `signafaide.declare_tools(...)` once. A tool that takes one dataclass, TypedDict or model gets rules on its fields. It writes `signafaide.checks.json` (commit it), makes a free sandbox if you say yes (no account, email or card) and saves your rules. A run without a terminal says exactly what it did not do and the command to finish.

```bash
uv run signafaide check approve_payout amount=1200 currency=GBP   # a dry run: exit 1 when it would block
uv run signafaide status                                            # one line per tool: recorded, protected, proof
uv run signafaide prove approve_payout                              # a read-only link for your auditor
```

A protected tool asks signafAIde before it runs, every call, and signafAIde rules with the newest rules, so a limit changed in the console applies from the next call. If signafAIde can't be reached it retries for the ruling timeout (10 s), then stops (Stop, the default; Let it run is a person's choice in the console). Checks on this machine (a secret in the arguments, a private address, hidden instructions, a changed tool) block here, before signafAIde is asked. A blocked call raises `signafaide.SignafaideBlocked`: one sentence with the rule in words and a link.

- `signafaide pull` fetches the rules saved in the console and asks before any new field of a protected tool leaves the machine.
- `signafaide prove [tool] [--days N] [--files]` asks for a 30-day link, or the longest your plan allows, reuses an active link for the same tool, and sends the agent's public keys with it, so the auditor's browser check is complete. `--files` writes a pack instead.
- `signafaide login` signs you in (a code you approve in the console): after you keep the sandbox, rules are saved by a person, never by the agent's API key.

A runnable example: [`examples/payout-agent`](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/tree/main/examples/payout-agent).

## Install

```bash
uv add signafaide                 # a uv project
poetry add signafaide             # a Poetry project
python3 -m venv .venv && .venv/bin/python -m pip install signafaide   # otherwise, then add it to requirements.txt
```

Not a bare `pip install`: most systems' Python refuses it outside a virtual environment (PEP 668, "externally-managed-environment"). The drand check of `verify` needs the `bls` extra (`signafaide[bls]`, about 23 MB); without it that one check says not checked, never passed.

## Recording without protecting

With no API key, records are signed, chained and kept in `.signafaide/`, and nothing is sent. `signafaide verify` checks every signature, chain link and content hash and ends with a result line that says how many of the 12 checks ran, for example `PASS (local checks only): 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`. A check that was not run is never counted as passed. It also says what still needs the witness:

```
co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)
```

## Sending hashes to a witness

Co-signature and the public timestamp need a witness. A person opts in once:

- `signafaide init` creates a free sandbox (no account, email or card), saves `SIGNAFAIDE_API_KEY` to `.env`, adds `.env` to `.gitignore` and prints a link to claim it, with what claiming gives and how long an unclaimed sandbox is kept (below); or
- set `SIGNAFAIDE_API_KEY` (a live key from the console), with `SIGNAFAIDE_URL` for a self-hosted witness. `SIGNAFAIDE_URL` alone sends nothing.

`init` says what the claim link is for and how long it is good for:

```
sandbox ready at https://api.signafaide.co.uk, key saved to /work/claims/.env; claim it at https://signafaide.co.uk/app/claim/3fK9...
claiming is free and needs no card: the sandbox moves into your own organisation and stops expiring, and you get the console, live keys and auditor links
30 days left: an unclaimed sandbox and its records on the service are deleted on 15 December 2026. Records on this machine are kept and still verify
```

`signafaide status`, `signafaide claim` and a passing `signafaide verify` repeat the link with the days left, counted from what the witness says (`expires_at`); a witness that does not say gets no line about days. `verify --json` has the same as data (`sandbox: {claim_url, claimed, expires_at, days_left}`). Once the sandbox is claimed, `status` shows `claim: done (this sandbox belongs to an organisation now)` and nothing counts down. An unclaimed sandbox past its date is deleted from the service within a day and its key is then refused (`invalid_key`); the records on this machine are kept and still verify, and the same commands say how to carry on: remove `SIGNAFAIDE_API_KEY` from `.env`, run `signafaide init` for a new sandbox and claim it.

Records written before the opt-in ship afterwards with their original times. The service accepts records up to 7 days old (an agent key's `valid_from` is at most 7 days before its registration); a local chain that starts earlier stays local, still verifies, and `signafaide flush` reports it as `too_old`. `signafaide.init()` in code only configures: it never creates a sandbox.

## What a call records

1. A `decision` record before the function runs: the tool name, plus `{"input": {<argument>: <value>}, "meta": {...}}`.
2. The function runs.
3. An `outcome` record after it: `{"output": ...}`, or `{"error": {"type", "message"}}`. The error is raised again unchanged.

Records are signed and chained locally in `.signafaide/` (synchronously, in a couple of milliseconds), then, once you opted in, shipped in the background. Sync and async functions both work.

```python
@signafaide.record(agent="claims-bot", name="approve_payout", meta={"model": "gpt-x"})
def approve(claim_id: str, amount: float): ...

signafaide.note("policy_loaded", {"version": 3})   # anything that is not a tool call
```

Give each agent an explicit name, for example `@signafaide.record(agent="claims-bot")`; without one it is the project folder's name. It must match `^[a-z0-9][a-z0-9._-]{0,63}$`. In production, one agent name is one chain written by one running instance.

## Frameworks

```python
tools = signafaide.wrap_tools({"lookup_order": lookup_order, "refund": refund})   # dict: key = name
tools = signafaide.wrap_tools([lookup_order, refund])                             # list
```

`wrap_tools` (and `wrap_tool` for one) also takes:

- **LangChain** tools (`@tool` or any `BaseTool`). The copy records each `invoke` / `ainvoke`, including tool calls, and still converts for `bind_tools`. The outcome holds the tool's own return value, not the `ToolMessage` LangChain wraps it in.
- **OpenAI Agents SDK** `FunctionTool`s (`@function_tool`). The copy records `on_invoke_tool`.

```python
from agents import Agent, function_tool

@function_tool
def lookup_order(order_id: str) -> str: ...

agent = Agent(name="support", tools=signafaide.wrap_tools([lookup_order]))
```

Neither framework is a dependency: `wrap_tools` recognises the objects by their shape.

## Recording everything an agent can call

Wrapping records the tools you wrap. Two things cover the rest: the gateway records every MCP tool call with no wrapper at all, and a tool declaration says in the chain which tools the agent has and which of them are recorded.

MCP tools: the gateway. It is part of the `signafaide` npm package (Node.js 18 or later) and works with an agent written in any language. In the agent's MCP configuration, start the gateway in place of the server:

```json
{"command": "npx", "args": ["-y", "signafaide", "gateway", "--agent", "support-bot", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]}
```

It runs the server, relays every message unchanged, declares the server's tools as recorded, and writes a `decision` before each `tools/call` is forwarded and an `outcome` when the answer arrives, into the same `.signafaide/` folder this SDK uses. A call that cannot be recorded is not forwarded. `--strict` (or `--strict-tools a,b`) protects every tool (or the named tools): a call is forwarded only once the witness has co-signed its decision; `--name-prefix github.` keeps the tool names of several servers apart; `--store-content` sends inputs and outputs too. A remote (HTTP) server goes behind a stdio bridge such as [`mcp-remote`](https://github.com/geelen/mcp-remote):

```bash
npx -y signafaide gateway --agent support-bot -- npx -y mcp-remote https://mcp.example.com/mcp
```

Framework tools: tool declarations. `wrap_tools` declares the tools it wraps as recorded, with the first recorded call. Give the full list of the tools your code hands the agent, and the ones you did not wrap are declared as not recorded:

```python
tools = signafaide.wrap_tools([refund, lookup_order], agent="support-bot")
signafaide.declare_tools(["refund", "lookup_order", "web_search"], agent="support-bot")   # web_search is not wrapped
```

`signafaide verify` then has a coverage line for each agent: `all 3 declared tools are recorded`, or `1 declared tool is not recorded: web_search`, or that no tool list was declared. It is a note, never a failure. A declaration is one signed note for the list and one for each tool in the agent's chain, so n tools are n + 1 records, counted like every other record, each time a process starts or the list changes. `declare_tools=False` or `SIGNAFAIDE_DECLARE_TOOLS=0` turns off the one `wrap_tools` writes.

What this shows, and what it does not. The gateway records every call that goes through it; a call the application makes around it is still not recorded, so the deployment has to make the gateway the only route to those tools. A declaration is the program's own signed statement of its tools: evidence of what it said it had, not proof that the list is complete. A tool list is as fresh as its last declaration: a source that stops (a gateway that is removed, a program that ends) leaves the list at its clean exit, or within 24 hours after a crash.

## OpenTelemetry: records from the traces you already have

An agent that is already traced with OpenTelemetry gets records with no tool wrapping. Install the extra and add one span processor where tracing is set up:

```bash
uv add "signafaide[otel]"         # or .venv/bin/python -m pip install "signafaide[otel]"
```

```python
from signafaide.otel import SignafaideSpanProcessor

provider.add_span_processor(SignafaideSpanProcessor())   # provider: your TracerProvider
```

To record every call, give the provider an always-on sampler, `TracerProvider(sampler=ALWAYS_ON)`: no span is dropped, and no sampling note is written.

The processor runs inside your process and exports nothing: it reads each span where it is, and its records are signed, chained, kept and sent exactly as a wrapped tool's are (hashes only, after the opt-in). It records the spans that are tool calls by one of three conventions:

| convention | a span is a tool call when | used by, for example |
|---|---|---|
| OpenTelemetry GenAI | `gen_ai.operation.name` is `execute_tool` | Pydantic AI, OpenLLMetry, LangSmith's OpenTelemetry tracing |
| OpenInference | `openinference.span.kind` is `TOOL` | the OpenInference instrumentors |
| OpenLLMetry | `traceloop.span.kind` is `tool` | the OpenLLMetry (Traceloop) instrumentations |

Each tool call gives a `decision` (the tool's name and the arguments the span holds) and an `outcome` (the result the span holds, or `{"error": {"type", "message"}}` when the span's status is an error). What the instrumentation does not put in the span is not in the record.

- **Before or after.** When a span says at its start that it is a tool call, the decision is written then, before the tool runs. Pydantic AI does this. When a span says so only at its end, the decision and the outcome are both written then, after the tool ran. The LangChain instrumentations of OpenInference and of OpenLLMetry do this: they set a span's attributes after it has started. LangSmith's OpenTelemetry tracing does too: it builds a span once the run has finished. Every record says which it was: in its signed content (`meta.telemetry.decision_written` is `before` or `after`), and in a signed note in the chain that a hash-only verifier reads too. `signafaide verify` and `signafaide status` show it per tool: `2 tools are recorded from telemetry spans: lookup_order (decision written before the tool ran), refund (decision written after the tool ran)`.
- **Sampling.** A span the sampler drops never reaches the processor, so its tool call has no record. The processor writes one signed note per process that says what the sampler can leave out, and `verify` and `status` repeat it as a note, never a failure. OpenTelemetry's default sampler (parent-based with an always-on root) keeps every trace your program starts and follows the caller's decision for a trace that arrives from another service: `telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded`. A sampler that can drop your own traces (ratio-based, always-off, parent-based with another root, a custom one): `records come from sampled telemetry: some tool calls may not be recorded`. A plain always-on sampler gets no note.
- **Protecting a tool needs the SDK.** "Do not run the tool unless it is recorded" is a feature of wrapping the tool with the SDK (`@signafaide.protect`), not of the telemetry processor. The processor never raises into your application and never waits for the network: when a record cannot be written the tool still runs, and one warning is logged.
- **One record per call.** A tool that is also wrapped with the SDK, or runs through the LangChain middleware, gives one decision and one outcome, not two: the wrapper's records stand, and a protected wrapper still waits for its receipt. This also holds when the span arrives after the call has ended, as with a tracing tool that builds its spans from finished runs: the span is matched to the wrapper's call by the tool call id when both have one, otherwise by the tool's name and the span's own start and end times. A tool that an MCP gateway on the same machine records for the same agent is left to the gateway, by tool name.
- **Agent name.** `SignafaideSpanProcessor(agent="support-bot")` names the chain. Without it the name is the tracer resource's `service.name`, made into a valid agent name, and without that the project folder's name.
- **Tools.** Each tool seen in a span is declared as one of the agent's recorded tools, as `wrap_tools` declares the tools it wraps. That is the list of tools seen so far, not the agent's full tool list: give that with `signafaide.declare_tools([...])`. `declare_tools=False` turns the declaration off. `store_content=True` sends inputs and outputs too.

## Reference: wrapping by hand

`protect` writes this for you; this is what it writes, and how to write it yourself.

```python
import signafaide

@signafaide.protect(agent="payout-bot")          # asks signafAIde first
def approve_payout(payee: str, amount: float, currency: str): ...

@signafaide.record(agent="payout-bot")           # recorded only
def lookup_invoice(invoice_id: str): ...

signafaide.declare_tools(["approve_payout", "lookup_invoice"], agent="payout-bot")
```

Arguments are named by the signature, so a rule finds `amount` by its name; a dataclass argument `payout` gives `payout.amount` (`/payout/amount`). Framework tools: `signafaide.wrap_tools([...], agent="payout-bot", strict=True)`.

Older code wrote `@signafaide.record(strict=True)`: it still works, and asks the witness as `protect` does. The decision is shipped first, and the function runs only after the witness has returned its receipt and ruling. If the service can't be reached or refuses the record, or there is no API key (`no_key`), the call raises and the function does not run. Agent frameworks often turn a tool's error into a failed tool call and print nothing, so the first time a protected tool is refused in a process the SDK writes one warning line to stderr with the tool's name and the fix.

## Hash-only

By default the service receives only the envelope: the name, the time, the chain links and `content_hash`. The hash is `sha256(salt || JCS(content))` with a random 16-byte salt per record, kept next to the content in the local chain, so the service cannot confirm a guess of the content from the hash. When you store content with the service, the salt goes with it, so anyone holding the pack can check the content against the hash. Your inputs and outputs stay in `.signafaide/chain/<project>/<env>/<agent>.jsonl` (`.signafaide/chain/_pending/nokey/<agent>.jsonl` before the opt-in), which is your evidence store. To send the content too (encrypted at rest; live records need the Team plan):

```python
signafaide.init(store_content=True)        # everything
@signafaide.record(store_content=True)     # one tool
```

## Offline

Nothing waits on the network unless you protect a tool: writing a record never makes a request, and a wrong key or an unreachable witness is a warning, never an exception in your tool. A malformed `SIGNAFAIDE_API_KEY` is caught here and never sent. With an API key, records go to `.signafaide/outbox/` and are shipped in batches by a background thread: every 2 seconds, every 100 records, and once more on exit (at most 3 seconds). If the service can't be reached, they stay on disk and are retried with backoff; a refusal retrying cannot fix (quota used up, a revoked key) stops sending until the configuration changes. They ship on the next run or with `signafaide flush`. Records are never lost on exit. The delay shows as the gap between a record's `time` and its batch's `server_time`.

## Containers that restart

A container with no persistent disk continues its chain after the witness's head, and its first record is a signed start note. So that a routine restart is not read as a possible loss, end the instance with `signafaide.stop()`: it ships what is left and then writes a signed stop note. A start right after a stop note is a clean restart; a start with no stop note before it (a crash, a kill, an unreachable witness) is shown as a warning, because records the earlier instance had not sent are not known.

```python
import signal, sys, signafaide

def on_term(signum, frame):
    signafaide.stop()  # {shipped, left, errors, stopped}
    sys.exit(0)

signal.signal(signal.SIGTERM, on_term)
```

A program that ends by itself with `SIGNAFAIDE_HEAD_FILE` set writes the stop note at exit, within the exit limit above. `SIGNAFAIDE_INSTANCE_STOP=0` turns that off; `=1` turns it on without a head file.

## Errors

Service errors raise or log `signafaide.SignafaideError`. Its message is the service's one-sentence fix, word for word, and `.code` is the error code. A `chain_conflict` (the service's chain for an agent differs from yours) is reported with the service's head and blocks shipping for that agent. The local chain is never rewritten. Run `signafaide verify` and `signafaide status` to see why.

## Verify

```bash
signafaide verify                       # the local .signafaide state
signafaide verify pack.json             # a pack from `signafaide export`
signafaide verify pack.json --keys keys.json --json
```

There is one line per check (schema, hashes, signatures, chains, Merkle proofs, batch and head signatures, drand, anchors, OpenTimestamps, content), then the result line: `PASS` or `FAIL` and how many checks passed, are pending and were not checked, for example `PASS: 11 of 12 checks passed, 1 pending (public timestamp)`. Pending means co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms within a few hours); pending and not checked are never counted as passed. The exit code is 0 for PASS, 1 for FAIL and 2 when an input can't be read. Locally, a chain the witness refuses for good (or that an older SDK wrote with time going back) shows as `BLOCKED` with the reason and the next step, and always exits 1; `--fail-on-pending-send` also fails while records wait to be co-signed, for CI. Locally, before anything was co-signed, the witness's checks show `NOT CHECKED` ("nothing co-signed yet") and no request is made. Service keys come from `--keys <file|url>`, or by default from the service's `/.well-known/signafaide-keys.json`. `--trust-embedded-keys` uses the keys inside the pack and prints a warning. The drand BLS signature is checked through `py_ecc`, from the `bls` extra (`pip install 'signafaide[bls]'`); without it that one check says not checked, never passed. A pack's rounds are checked together, so it takes well under a second.

```python
report = signafaide.verify("pack.json", keys="keys.json")
print(report)        # the same lines
report.ok            # True / False
```


**For an auditor** the agent keys must come from you, not from the pack (otherwise a service could add a key of its own): `signafaide keys export -o agent-keys.json` writes every agent key, each signed by itself. The auditor runs `npx signafaide verify pack.json --keys <witness>/.well-known/signafaide-keys.json --agent-keys agent-keys.json --head head.json` (or the Python CLI with the same arguments; `head.json` is your `.signafaide/head.json`, which catches records cut off at the end). Without `--agent-keys` the client-signature check says `NOT INDEPENDENT` and the result is FAIL; `--trust-embedded-agent-keys` accepts the pack's keys and says so in the result line. On your own machine, `signafaide verify pack.json` uses this project's agent keys automatically. Public timestamps are checked online (`--timestamp-check <url>`, default `https://mempool.space/api`); with `--offline` they show `NOT CHECKED`, never confirmed. `signafaide keys rotate --agent X` gives an agent a new key; the SDK signs the registration of the new key with the old one.

## Replay

```bash
signafaide replay --agent claims-bot --from 2026-11-01 --to 2026-11-13 --html replay.html
signafaide replay --agent claims-bot --record 3fa2b1c9
```

Shows the agent's decisions and outcomes in order, with their inputs and outputs from the local chain. Each record is checked against its `content_hash`, its signature and the service's receipt first, so an edited line shows as `FAIL`. `--html` also writes a self-contained page. In code: `r = signafaide.replay(agent="claims-bot", since="2026-11-01")`, then `print(r)`, `r.to_html()`, `r.ok`.

## Experiments: A/B on past decisions

```python
def approve(claim_id, amount):             # same arguments as the recorded tool
    return {"approved": amount < 300}

report = signafaide.compare(approve, agent="claims-bot", name="approve_payout", since="2026-11-01", limit=500)
print(report)            # n, agreed, changed, errors, then the changed decisions
report.upload()          # optional: hash-only unless content is stored with the service
```

The chain is verified first; then each recorded decision with a co-signed outcome is re-run with your candidate, on your machine, with your own models and keys, and compared with the recorded `output` (exact canonical-JSON equality, or `same=lambda recorded, candidate: ...`). A candidate that raises counts as an error. **Candidates must be side-effect free:** compare never writes records, and a recorded tool called from a candidate raises instead of running. CLI: `signafaide compare --module candidate.py:approve --name approve_payout --upload`.

## CLI

| command | does |
|---|---|
| `signafaide protect [tool] [--tool <name>] [--limit-field <field> --above <number>] [--local] [--yes]` | finds the tools, asks what to block, shows the code change and writes it, writes the checks file, adds the project note to AGENTS.md / CLAUDE.md if you say yes, makes a free sandbox if you say yes, saves the rules; `--limit-field` and `--above` give the limit without asking, and without a terminal every rule starts Calibrating |
| `signafaide check <tool> field=value...` | a dry run of a call against the rules: what would block, what is sent; exit 1 when it would block |
| `signafaide pull` | fetches the project's rules; asks before a new field of a protected tool is sent |
| `signafaide prove [tool] [--days N] [--files] [--all]` | the auditor link (or files), with the calls, the rules in words and what ran before protection |
| `signafaide login` / `signafaide logout` | a person's sign-in for saving rules from the command line |
| `signafaide start-fresh <agent>` | proofs of the agent start from now; the old record is kept |
| `signafaide init` | the opt-in: creates a free sandbox if there is no key (no account, email or card), prints the claim link, what claiming gives and when an unclaimed sandbox is deleted |
| `signafaide status` | key and env, agents, last receipt, outbox size, quota; BLOCKED chains (exit 1) |
| `signafaide repair [--agent X] [--dry-run]` | sets aside records no witness can take (kept in `.signafaide/held/`, still verified), gives the agent a new key and starts a new segment |
| `signafaide verify [pack.json] [--keys ...] [--agent-keys ...] [--head ...] [--offline] [--fail-on-pending-send] [--json]` | verifies; exit 0 PASS, 1 FAIL or BLOCKED, 2 unreadable input |
| `signafaide keys export [-o agent-keys.json]` / `signafaide keys rotate [--agent X] [--env test\|live]` | the agent-key file for auditors / a new key for an agent |
| `signafaide keys create [--agent X] [--env test\|live] [--print]` | a new key, registered with the witness, for a secret store; writes no record (`--print`: prints the key file and saves nothing here) |
| `signafaide export [--agent X] [--from T] [--to T] [-o pack.json]` | downloads a verification pack of the whole project (every agent); `--agent` narrows it to one |
| `signafaide replay [--agent X] [--from T] [--to T] [--record H] [--html out.html] [--json]` | the verified timeline from the local chain; exit 1 on FAIL |
| `signafaide compare --module file.py:fn [--agent X] [--name N] [--from T] [--to T] [--limit N] [--upload [--values]]` | re-runs recorded decisions with a candidate and compares; `--values` sends the values too (stored-content decisions only) |
| `signafaide claim` | prints the claim link again, what claiming gives and how many days an unclaimed sandbox has left |
| `signafaide flush` | ships the outbox now (with no key it sends nothing and says so) |

## What is sent besides records

Every request carries one header:

```
X-Signafaide-Client: signafaide-python/0.5.0 (python 3.12.3; adapter=none; agent=claude-code; via=sdk)
```

It holds the SDK and its version, the Python runtime and its version, and the framework adapter in use (`langchain`, `openai-agents`, `otel` for the OpenTelemetry processor, or `none`). It also holds the coding agent that set the project up (`claude-code`, `codex`, `cursor`, `gemini-cli`, `copilot`, `windsurf` or `unknown`) and how the call was made (`sdk`, `cli` or `mcp`). The agent is found from that tool's environment variables when the project is set up (`signafaide init`) and kept in `.signafaide/config.json`; it is never guessed per process. `signafaide verify` and `signafaide export` also send `POST /v1/events {"name": "verify"}` (or `"export"`) when there is an API key. If that fails, the command is not affected. With no API key nothing at all is sent.

The header and the events hold no content, file paths, hostnames or user names. `SIGNAFAIDE_TELEMETRY=0` removes the adapter, the coding agent and the protected-tool flag from the header, stops the coding agent being saved in `.signafaide/config.json`, and turns the events off. The SDK and its version, the runtime and its version, and how the call was made (`via`) are still sent.

## Configuration

| variable | default |
|---|---|
| `SIGNAFAIDE_API_KEY` | read from the environment, then `.env`; created by `signafaide init`; none: local only |
| `SIGNAFAIDE_URL` | `https://api.signafaide.co.uk`; a self-hosted witness, or `http://127.0.0.1:7474` for a local dev server. Alone it sends nothing |
| `SIGNAFAIDE_HOME` | `.signafaide/` in the project root; a mounted volume or `/tmp/signafaide` in production |
| `SIGNAFAIDE_AGENT_KEY_<NAME>` | an agent's key file content from a secret store (or `key_provider=` in `signafaide.init`); live keys can use `SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>`, made with `signafaide keys create --env live --print` |
| `SIGNAFAIDE_HEAD_FILE` | unset: a file outside `.signafaide/` (a persistent volume) that also keeps the newest signed heads, for containers whose disk does not last; or `on_head=` in `signafaide.init` |
| `SIGNAFAIDE_INSTANCE_STOP` | unset: a signed stop note is written at a clean exit when a head file is set; `1` always, `0` never (see Containers that restart) |
| `SIGNAFAIDE_EXIT_FLUSH_MS` | `3000`: the longest a finished program is kept open to send; `0` never |
| `SIGNAFAIDE_TEST` | test mode is on by itself under pytest (records in a temporary folder, nothing sent), except with a live API key (`sfa_live_`); `1` forces it, `0` turns it off |
| `SIGNAFAIDE_DISABLED` | `1`: wrapped functions run and nothing is recorded |
| `SIGNAFAIDE_DECLARE_TOOLS` | `0`: `wrap_tools` does not declare the tools it wraps (`declare_tools()` still does) |
| `SIGNAFAIDE_SEGMENT_BYTES` | `67108864`: a shipped chain file larger than this rolls into a sealed segment |
| `SIGNAFAIDE_TELEMETRY` | `0` turns off the adapter, agent and protected fields and the events |

Running in containers, with replicas, on read-only or ephemeral disks, on serverless or in CI: see the [production guide](https://signafaide.co.uk/docs/production). A record's time never goes back along its chain: if the clock steps back, the record keeps the previous record's time and the clock's reading goes in `meta.wall_time`.

Each project and env has its own chain per agent. A new key, for example a live key replacing the sandbox key, starts a fresh chain at seq 1. The old chain stays on disk, and `signafaide status` lists every chain.

The project root is the nearest folder with `.signafaide/`, `.git`, `pyproject.toml` or `package.json`. `signafaide init` adds `.signafaide/` to `.gitignore` (never a running program). Agent keys live in `.signafaide/agents/<agent>.key` (sandbox) and `.signafaide/agents/live/<agent>.key` (live), mode 0600, and never leave the machine. Back them up.

Python 3.9+. Dependency: `cryptography`. The `bls` extra adds `py_ecc` (the drand check of `verify`). The `otel` extra adds `opentelemetry-sdk`.
