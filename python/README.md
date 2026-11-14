# signafaide

Signed, chained records of what your AI agents decided. Each record is signed with the agent's own key and chained on your machine; once you opt in, a witness (the signafAIde service, or one you host) co-signs and publicly timestamps it, so neither side can forge or edit a record alone.

- Nothing is sent until a person runs `signafaide init` or sets `SIGNAFAIDE_API_KEY`. After that each record sends its content hash with its tool name, agent name and time (and its chain links), never its inputs or outputs unless you turn on stored content. Tool and agent names are sent as you write them, so don't put personal data in them. Each content hash is salted with 16 random bytes that stay on your machine with the content, so the hash alone cannot be used to guess the content, even when it has only a few possible values.
- The sandbox `init` creates needs no account, email or card.
- To keep the evidence in your environment, self-host the witness and set `SIGNAFAIDE_URL` ([self-host](https://signafaide.com/docs/self-host)).
- Apache-2.0, with a public protocol spec and an independent verifier.

```bash
uv add signafaide                 # a uv project
poetry add signafaide             # a Poetry project
python3 -m venv .venv && .venv/bin/python -m pip install signafaide   # otherwise, then add it to requirements.txt
```

Not a bare `pip install`: most systems' Python refuses it outside a virtual environment (PEP 668, "externally-managed-environment").

```python
import signafaide

@signafaide.record
def approve_payout(claim_id: str, amount: float): ...
```

```bash
signafaide verify                 # or .venv/bin/signafaide verify, uv run signafaide verify
```

That's it. With no API key, records are signed, chained and kept in `.signafaide/`, and nothing is sent. `signafaide verify` checks every signature, chain link and content hash and ends with a result line that says how many of the 12 checks ran, for example `PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`. A check that was not run is never counted as passed. It also says what still needs the witness:

```
co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)
```

## Sending hashes to a witness

Co-signature and the public timestamp need a witness. A person opts in once:

- `signafaide init` creates a free sandbox (no account, email or card), saves `SIGNAFAIDE_API_KEY` to `.env`, adds `.env` to `.gitignore` and prints a link to claim it; or
- set `SIGNAFAIDE_API_KEY` (a live key from the console), with `SIGNAFAIDE_URL` for a self-hosted witness. `SIGNAFAIDE_URL` alone sends nothing.

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

## Strict mode: no receipt, no action

```python
@signafaide.record(strict=True)
def wire_funds(account: str, amount: float): ...
```

The decision is shipped first, and the function runs only after the service has returned its receipt. If the service can't be reached or refuses the record, or there is no API key (`no_key`), `signafaide.NotRecorded` is raised and the function does not run.

## Hash-only

By default the service receives only the envelope: the name, the time, the chain links and `content_hash`. The hash is `sha256(salt || JCS(content))` with a random 16-byte salt per record, kept next to the content in the local chain, so the service cannot confirm a guess of the content from the hash. When you store content with the service, the salt goes with it, so anyone holding the pack can check the content against the hash. Your inputs and outputs stay in `.signafaide/chain/<project>/<env>/<agent>.jsonl` (`.signafaide/chain/_pending/nokey/<agent>.jsonl` before the opt-in), which is your evidence store. To send the content too (encrypted at rest; live records need the Team plan):

```python
signafaide.init(store_content=True)        # everything
@signafaide.record(store_content=True)     # one tool
```

## Offline

Nothing waits on the network unless you use strict mode: writing a record never makes a request, and a wrong key or an unreachable witness is a warning, never an exception in your tool. A malformed `SIGNAFAIDE_API_KEY` is caught here and never sent. With an API key, records go to `.signafaide/outbox/` and are shipped in batches by a background thread: every 2 seconds, every 100 records, and once more on exit (at most 3 seconds). If the service can't be reached, they stay on disk and are retried with backoff; a refusal retrying cannot fix (quota used up, a revoked key) stops sending until the configuration changes. They ship on the next run or with `signafaide flush`. Records are never lost on exit. The delay shows as the gap between a record's `time` and its batch's `server_time`.

## Errors

Service errors raise or log `signafaide.SignafaideError`. Its message is the service's one-sentence fix, word for word, and `.code` is the error code. A `chain_conflict` (the service's chain for an agent differs from yours) is reported with the service's head and blocks shipping for that agent. The local chain is never rewritten. Run `signafaide verify` and `signafaide status` to see why.

## Verify

```bash
signafaide verify                       # the local .signafaide state
signafaide verify pack.json             # a pack from `signafaide export`
signafaide verify pack.json --keys keys.json --json
```

There is one line per check (schema, hashes, signatures, chains, Merkle proofs, batch and head signatures, drand, anchors, OpenTimestamps, content), then the result line: `PASS` or `FAIL` and how many checks passed, are pending and were not checked, for example `PASS: 11 of 12 checks passed, 1 pending (public timestamp)`. Pending means waiting for something that has not happened yet (an hourly anchor, or a public timestamp confirming); pending and not checked are never counted as passed. The exit code is 0 for PASS, 1 for FAIL and 2 when an input can't be read. Locally, a chain the witness refuses for good (or that an older SDK wrote with time going back) shows as `BLOCKED` with the reason and the next step, and always exits 1; `--fail-on-pending-send` also fails while records wait to be co-signed, for CI. Locally, before anything was co-signed, the witness's checks show `NOT CHECKED` ("nothing co-signed yet") and no request is made. Service keys come from `--keys <file|url>`, or by default from the service's `/.well-known/signafaide-keys.json`. `--trust-embedded-keys` uses the keys inside the pack and prints a warning. The drand BLS signature is checked too, through `py_ecc` (a dependency, as `@noble/curves` is for the TypeScript SDK), so both SDKs count the same checks. A pack's rounds are checked together, so it takes well under a second.

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
| `signafaide init` | the opt-in: creates a free sandbox if there is no key (no account, email or card), prints the claim link |
| `signafaide status` | key and env, agents, last receipt, outbox size, quota; BLOCKED chains (exit 1) |
| `signafaide repair [--agent X] [--dry-run]` | sets aside records no witness can take (kept in `.signafaide/held/`, still verified), gives the agent a new key and starts a new segment |
| `signafaide verify [pack.json] [--keys ...] [--agent-keys ...] [--head ...] [--offline] [--fail-on-pending-send] [--json]` | verifies; exit 0 PASS, 1 FAIL or BLOCKED, 2 unreadable input |
| `signafaide keys export [-o agent-keys.json]` / `signafaide keys rotate [--agent X] [--env test\|live]` | the agent-key file for auditors / a new key for an agent |
| `signafaide export [--agent X] [--from T] [--to T] [-o pack.json]` | downloads a verification pack of the whole project (every agent); `--agent` narrows it to one |
| `signafaide replay [--agent X] [--from T] [--to T] [--record H] [--html out.html] [--json]` | the verified timeline from the local chain; exit 1 on FAIL |
| `signafaide compare --module file.py:fn [--agent X] [--name N] [--from T] [--to T] [--limit N] [--upload [--values]]` | re-runs recorded decisions with a candidate and compares; `--values` sends the values too (stored-content decisions only) |
| `signafaide claim` | prints the claim link again |
| `signafaide flush` | ships the outbox now (with no key it sends nothing and says so) |

## What is sent besides records

Every request carries one header:

```
X-Signafaide-Client: signafaide-python/0.1.0 (python 3.12.3; adapter=none; agent=claude-code; via=sdk)
```

It holds the SDK and its version, the Python runtime and its version, and the framework adapter in use (`langchain`, `openai-agents` or `none`). It also holds the coding agent that set the project up (`claude-code`, `codex`, `cursor`, `gemini-cli`, `copilot`, `windsurf` or `unknown`) and how the call was made (`sdk`, `cli` or `mcp`). The agent is found from that tool's environment variables when the project is set up (`signafaide init`) and kept in `.signafaide/config.json`; it is never guessed per process. `signafaide verify` and `signafaide export` also send `POST /v1/events {"name": "verify"}` (or `"export"`) when there is an API key. If that fails, the command is not affected. With no API key nothing at all is sent.

The header and the events hold no content, file paths, hostnames or user names. `SIGNAFAIDE_TELEMETRY=0` removes the adapter, the coding agent and the strict-mode flag from the header, stops the coding agent being saved in `.signafaide/config.json`, and turns the events off. The SDK and its version, the runtime and its version, and how the call was made (`via`) are still sent.

## Configuration

| variable | default |
|---|---|
| `SIGNAFAIDE_API_KEY` | read from the environment, then `.env`; created by `signafaide init`; none: local only |
| `SIGNAFAIDE_URL` | `https://api.signafaide.com`; a self-hosted witness, or `http://127.0.0.1:7474` for a local dev server. Alone it sends nothing |
| `SIGNAFAIDE_HOME` | `.signafaide/` in the project root; a mounted volume or `/tmp/signafaide` in production |
| `SIGNAFAIDE_AGENT_KEY_<NAME>` | an agent's key file content from a secret store (or `key_provider=` in `signafaide.init`) |
| `SIGNAFAIDE_EXIT_FLUSH_MS` | `3000`: the longest a finished program is kept open to send; `0` never |
| `SIGNAFAIDE_TEST` | test mode is on by itself under pytest (records in a temporary folder, nothing sent); `1` forces it, `0` turns it off |
| `SIGNAFAIDE_DISABLED` | `1`: wrapped functions run and nothing is recorded |
| `SIGNAFAIDE_SEGMENT_BYTES` | `67108864`: a shipped chain file larger than this rolls into a sealed segment |
| `SIGNAFAIDE_TELEMETRY` | `0` turns off the adapter, agent and strict fields and the events |

Running in containers, with replicas, on read-only or ephemeral disks, on serverless or in CI: see the [production guide](https://signafaide.com/docs/production). A record's time never goes back along its chain: if the clock steps back, the record keeps the previous record's time and the clock's reading goes in `meta.wall_time`.

Each project and env has its own chain per agent. A new key, for example a live key replacing the sandbox key, starts a fresh chain at seq 1. The old chain stays on disk, and `signafaide status` lists every chain.

The project root is the nearest folder with `.signafaide/`, `.git`, `pyproject.toml` or `package.json`. `signafaide init` adds `.signafaide/` to `.gitignore` (never a running program). Agent keys live in `.signafaide/agents/<agent>.key` (sandbox) and `.signafaide/agents/live/<agent>.key` (live), mode 0600, and never leave the machine. Back them up.

Python 3.9+. Dependencies: `cryptography` and `py_ecc` (drand BLS).
