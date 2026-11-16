# signafaide

Audit evidence of what your AI agents did, for EU AI Act record-keeping, ISO/IEC 42001 and SOC 2. Each record is signed with the agent's own key and chained on your machine; once you opt in, a witness (the signafAIde service, or one you host) co-signs and publicly timestamps it, so neither side can forge or edit a record alone.

- Nothing is sent until a person runs `npx signafaide init` or sets `SIGNAFAIDE_API_KEY`. After that each record sends its content hash with its tool name, agent name and time (and its chain links), never its inputs or outputs unless you turn on stored content. Tool and agent names are sent as you write them, so don't put personal data in them. Each content hash is salted with 16 random bytes that stay on your machine with the content, so the hash alone cannot be used to guess the content, even when it has only a few possible values.
- The sandbox `init` creates needs no account, email or card.
- To keep the evidence in your environment, self-host the witness and set `SIGNAFAIDE_URL` ([self-host](https://signafaide.co.uk/docs/self-host)).
- Apache-2.0, with a public protocol spec and an independent verifier.

```bash
npm install signafaide
```

```ts
import { record } from "signafaide";

const approvePayout = record(async (claimId: string, amount: number) => { /* ... */ }, { name: "approve_payout" });
```

```bash
npx signafaide verify
```

That's it. With no API key, records are signed, chained and kept in `.signafaide/`, and nothing is sent. `signafaide verify` checks every signature, chain link and content hash and ends with a result line that says how many of the 12 checks ran, for example `PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`. A check that was not run is never counted as passed. It also says what still needs the witness:

```
co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)
```

## Sending hashes to a witness

Co-signature and the public timestamp need a witness. A person opts in once:

- `npx signafaide init` creates a free sandbox (no account, email or card), saves `SIGNAFAIDE_API_KEY` to `.env`, adds `.env` to `.gitignore` and prints a link to claim it, with what claiming gives and how long an unclaimed sandbox is kept (below); or
- set `SIGNAFAIDE_API_KEY` (a live key from the console), with `SIGNAFAIDE_URL` for a self-hosted witness. `SIGNAFAIDE_URL` alone sends nothing.

`init` says what the claim link is for and how long it is good for:

```
sandbox ready at https://api.signafaide.co.uk, key saved to /work/claims/.env; claim it at https://signafaide.co.uk/app/claim/3fK9...
claiming is free and needs no card: the sandbox moves into your own organisation and stops expiring, and you get the console, live keys and auditor links
30 days left: an unclaimed sandbox and its records on the service are deleted on 15 December 2026. Records on this machine are kept and still verify
```

`signafaide status`, `signafaide claim` and a passing `signafaide verify` repeat the link with the days left, counted from what the witness says (`expires_at`); a witness that does not say gets no line about days. `verify --json` has the same as data (`sandbox: {claim_url, claimed, expires_at, days_left}`). Once the sandbox is claimed, `status` shows `claim: done (this sandbox belongs to an organisation now)` and nothing counts down. An unclaimed sandbox past its date is deleted from the service within a day and its key is then refused (`invalid_key`); the records on this machine are kept and still verify, and the same commands say how to carry on: remove `SIGNAFAIDE_API_KEY` from `.env`, run `signafaide init` for a new sandbox and claim it.

Records written before the opt-in ship afterwards with their original times. The service accepts records up to 7 days old (an agent key's `valid_from` is at most 7 days before its registration); a local chain that starts earlier stays local, still verifies, and `signafaide flush` reports it as `too_old`. The SDK's `init()` only configures: it never creates a sandbox.

## What a call records

1. A `decision` record before the function runs: the name, plus `{"input": <the argument, or the argument list if there are several>, "meta": {...}}`.
2. The function runs.
3. An `outcome` record after it: `{"output": ...}`, or `{"error": {"type", "message"}}`. The error is thrown again unchanged.

Records are signed and chained locally in `.signafaide/` (synchronously), then shipped in the background. Sync functions stay sync, and async functions stay async. Named functions don't need `name`.

```ts
const approve = record(approvePayout, { agent: "claims-bot", name: "approve_payout", meta: { model: "gpt-x" } });
note("policy_loaded", { version: 3 }); // anything that is not a tool call
```

Give each agent an explicit name, for example `wrapTools(tools, { agent: "claims-bot" })`; without one it is the project folder's name. It must match `^[a-z0-9][a-z0-9._-]{0,63}$`. In production, one agent name is one chain written by one running instance.

## Frameworks

```ts
import { wrapTools } from "signafaide";

const tools = wrapTools({ approvePayout, escalate }); // object: key = name
const list = wrapTools([lookupOrder, refund]);        // array
```

`wrapTools` (and `wrapTool` for one) also takes:

- **Vercel AI SDK** tools (objects with `execute`). It records `execute(input)`; the options argument (messages, abort signal) is not recorded.
  ```ts
  const result = await generateText({ model, tools: wrapTools({ weather: tool({ inputSchema, execute }) }), prompt });
  ```
- **OpenAI Agents JS** function tools (`tool({...})` from `@openai/agents`). It records `invoke`.
  ```ts
  const agent = new Agent({ name: "support", tools: wrapTools([lookupOrder]) });
  ```
- **LangChain.js** tools (`tool()`, `DynamicStructuredTool`, `StructuredTool` subclasses). Every `invoke` is recorded, including tool calls, and the wrapped copy is still a `StructuredTool`.

None of them is a dependency: `wrapTools` recognises the objects by their shape.

## Recording everything an agent can call

Wrapping records the tools you wrap. Two things cover the rest: the gateway records every MCP tool call with no wrapper at all, and a tool declaration says in the chain which tools the agent has and which of them are recorded.

MCP tools: the gateway. In the agent's MCP configuration, start the gateway in place of the server:

```json
{"command": "npx", "args": ["-y", "signafaide", "gateway", "--agent", "support-bot", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]}
```

It runs the server, relays every message unchanged, declares the server's tools as recorded, and writes a `decision` before each `tools/call` is forwarded and an `outcome` when the answer arrives. A call that cannot be recorded is not forwarded. `--strict` (or `--strict-tools a,b`) forwards a call only once the witness has co-signed its decision; `--name-prefix github.` keeps the tool names of several servers apart; `--store-content` sends inputs and outputs too. A remote (HTTP) server goes behind a stdio bridge such as [`mcp-remote`](https://github.com/geelen/mcp-remote):

```bash
npx -y signafaide gateway --agent support-bot -- npx -y mcp-remote https://mcp.example.com/mcp
```

Framework tools: tool declarations. `wrapTools` declares the tools it wraps as recorded, with the first recorded call. Give the full list of the tools your code hands the agent, and the ones you did not wrap are declared as not recorded:

```ts
import { declareTools, wrapTools } from "signafaide";

const tools = wrapTools({ refund, lookupOrder }, { agent: "support-bot" });
declareTools(["refund", "lookupOrder", "web_search"], { agent: "support-bot" }); // web_search is not wrapped
```

`signafaide verify` then has a coverage line for each agent: `all 3 declared tools are recorded`, or `1 declared tool is not recorded: web_search`, or that no tool list was declared. It is a note, never a failure. A declaration is one signed note for the list and one for each tool in the agent's chain, so n tools are n + 1 records, counted like every other record, each time a process starts or the list changes. `{ declareTools: false }` or `SIGNAFAIDE_DECLARE_TOOLS=0` turns off the one `wrapTools` writes.

What this shows, and what it does not. The gateway records every call that goes through it; a call the application makes around it is still not recorded, so the deployment has to make the gateway the only route to those tools. A declaration is the program's own signed statement of its tools: evidence of what it said it had, not proof that the list is complete. A tool list is as fresh as its last declaration: a source that stops (a gateway that is removed, a program that ends) leaves the list at its clean exit, or within 24 hours after a crash.

## OpenTelemetry: records from the traces you already have

An agent that is already traced with OpenTelemetry gets records with no tool wrapping. Add one span processor where tracing is set up:

```ts
import { SignafaideSpanProcessor } from "signafaide/otel";

const provider = new NodeTracerProvider({ spanProcessors: [new SignafaideSpanProcessor()] });
```

To record every call, give the provider an always-on sampler, `sampler: new AlwaysOnSampler()`: no span is dropped, and no sampling note is written.

`signafaide/otel` needs `@opentelemetry/api`, which every OpenTelemetry set-up already has; it is an optional peer dependency, and the rest of the package works without it. Node.js only.

The processor runs inside your process and exports nothing: it reads each span where it is, and its records are signed, chained, kept and sent exactly as a wrapped tool's are (hashes only, after the opt-in). It records the spans that are tool calls by one of three conventions:

| convention | a span is a tool call when | used by, for example |
|---|---|---|
| OpenTelemetry GenAI | `gen_ai.operation.name` is `execute_tool` | the Vercel AI SDK (`@ai-sdk/otel`), OpenLLMetry |
| OpenInference | `openinference.span.kind` is `TOOL` | the OpenInference instrumentors |
| OpenLLMetry | `traceloop.span.kind` is `tool` | the OpenLLMetry (Traceloop) instrumentations |

Each tool call gives a `decision` (the tool's name and the arguments the span holds) and an `outcome` (the result the span holds, or `{"error": {"type", "message"}}` when the span's status is an error). What the instrumentation does not put in the span is not in the record. OpenLLMetry's LangChain instrumentation names a tool span after the tool's class (`DynamicStructuredTool`); the record takes the tool's own name from the LangChain tool message the span carries as its result, so a call that ends in an error, which has no result, is recorded under the class name.

- **Before or after.** When a span says at its start that it is a tool call, the decision is written then, before the tool runs. The Vercel AI SDK's OpenTelemetry integration does this. When a span says so only at its end, the decision and the outcome are both written then, after the tool ran. The LangChain instrumentations of OpenInference and of OpenLLMetry do this: they set a span's attributes after it has started. Every record says which it was: in its signed content (`meta.telemetry.decision_written` is `before` or `after`), and in a signed note in the chain that a hash-only verifier reads too. `signafaide verify` and `signafaide status` show it per tool: `2 tools are recorded from telemetry spans: lookup_order (decision written before the tool ran), refund (decision written after the tool ran)`.
- **Sampling.** A span the sampler drops never reaches the processor, so its tool call has no record. The processor writes one signed note per process that says what the sampler can leave out, and `verify` and `status` repeat it as a note, never a failure. OpenTelemetry's default sampler (parent-based with an always-on root) keeps every trace your program starts and follows the caller's decision for a trace that arrives from another service: `telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded`. A sampler that can drop your own traces (ratio-based, always-off, parent-based with another root, a custom one): `records come from sampled telemetry: some tool calls may not be recorded`. A plain always-on sampler gets no note. A span does not name its sampler, so the processor reads it from the registered global tracer provider (`provider.register()`, or the Node SDK). For a provider that is not registered globally, pass the provider's sampler, whichever kind it is: `new SignafaideSpanProcessor({ sampler })`. When the processor has neither, it cannot tell whether spans are sampled and writes no note.
- **Strict mode needs the SDK.** "Do not run the tool unless it is recorded" is a feature of wrapping the tool with the SDK (`strict: true`), not of the telemetry processor. The processor never throws into your application and never waits for the network: when a record cannot be written the tool still runs, and one warning is logged.
- **One record per call.** A tool that is also wrapped with the SDK gives one decision and one outcome, not two: the wrapper's records stand, and a strict wrapper still waits for its receipt. A tool that an MCP gateway on the same machine records for the same agent is left to the gateway. Calls are matched by tool name.
- **Agent name.** `new SignafaideSpanProcessor({ agent: "support-bot" })` names the chain. Without it the name is the tracer resource's `service.name`, made into a valid agent name, and without that the project folder's name.
- **Tools.** Each tool seen in a span is declared as one of the agent's recorded tools, as `wrapTools` declares the tools it wraps. That is the list of tools seen so far, not the agent's full tool list: give that with `declareTools([...])`. `declareTools: false` turns the declaration off. `storeContent: true` sends inputs and outputs too.

## Strict mode: no receipt, no action

```ts
const wireFunds = record(sendWire, { strict: true }); // now returns a Promise
```

The decision is shipped first, and the function runs only after the service has returned its receipt. If the service can't be reached or refuses the record, or there is no API key (`no_key`), the call rejects with `NotRecorded` and the function does not run. Agent frameworks often turn a tool's error into a failed tool call and print nothing, so the first time a strict tool is refused in a process the SDK writes one warning line to stderr with the tool's name and the fix.

## Hash-only

By default the service receives only the envelope: the name, the time, the chain links and `content_hash`. The hash is `sha256(salt || JCS(content))` with a random 16-byte salt per record, kept next to the content in the local chain, so the service cannot confirm a guess of the content from the hash. When you store content with the service, the salt goes with it, so anyone holding the pack can check the content against the hash. Your inputs and outputs stay in `.signafaide/chain/<project>/<env>/<agent>.jsonl` (`.signafaide/chain/_pending/nokey/<agent>.jsonl` before the opt-in), which is your evidence store. To send the content too (encrypted at rest; live records need the Team plan):

```ts
await init({ storeContent: true });           // everything
record(fn, { name: "x", storeContent: true }); // one tool
```

## Offline

Nothing waits on the network unless you use strict mode. With an API key, records go to `.signafaide/outbox/` and are shipped in batches, one request at a time: every 2 seconds, every 100 records, and once more when the process is about to exit, for at most 3 seconds (`exitFlushMs`, `SIGNAFAIDE_EXIT_FLUSH_MS`). If the service can't be reached, they stay on disk and are retried with a backoff that grows to a minute; a refusal retrying cannot fix (quota used up, a wrong or revoked key) stops sending until the configuration changes. A malformed `SIGNAFAIDE_API_KEY` is caught here and never sent. They ship on the next run or with `signafaide flush`. Records are never lost on exit, and background requests never keep your process alive.

## Containers that restart

A container with no persistent disk continues its chain after the witness's head, and its first record is a signed start note. So that a routine restart is not read as a possible loss, end the instance with `await stop()`: it ships what is left and then writes a signed stop note. A start right after a stop note is a clean restart; a start with no stop note before it (a crash, a kill, an unreachable witness) is shown as a warning, because records the earlier instance had not sent are not known.

```ts
import { stop } from "signafaide";

process.on("SIGTERM", async () => {
  await stop(); // { shipped, left, errors, stopped }
  process.exit(0);
});
```

A program that ends by itself with `SIGNAFAIDE_HEAD_FILE` set writes the stop note at exit, within the exit limit above. `SIGNAFAIDE_INSTANCE_STOP=0` turns that off; `=1` turns it on without a head file.

## Errors

Service errors are `SignafaideError`. Its `message` is the service's one-sentence fix, word for word, and `code` is the error code. A `chain_conflict` is reported with the service's head and blocks shipping for that agent. The local chain is never rewritten.

## Verify

```bash
signafaide verify                     # the local .signafaide state
signafaide verify pack.json           # a pack from `signafaide export`
signafaide verify pack.json --keys keys.json --json
```

There is one line per check, then the result line: `PASS` or `FAIL` and how many checks passed, are pending and were not checked, for example `PASS: 11 of 12 checks passed, 1 pending (public timestamp)`. Pending means co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms within a few hours); pending and not checked are never counted as passed. The exit code is 0 for PASS, 1 for FAIL and 2 when an input can't be read. Locally, a chain the witness refuses for good (or that an older SDK wrote with time going back) shows as `BLOCKED` with the reason and the next step, and always exits 1; `--fail-on-pending-send` also fails while records wait to be co-signed, for CI. Locally, before anything was co-signed, the witness's checks show `NOT CHECKED` ("nothing co-signed yet") and no request is made. Service keys come from `--keys <file|url>`, or by default from the service's `/.well-known/signafaide-keys.json`. `--trust-embedded-keys` uses the keys inside the pack and prints a warning. The drand BLS signature is checked too (through `@noble/curves`, a dependency).

```ts
import { verify } from "signafaide";
const report = await verify("pack.json", { keys: "keys.json" });
console.log(String(report)); // the same lines
report.ok;
```

### Browsers and edge runtimes

`signafaide/core` has no Node APIs. It provides JCS, hashing, Ed25519 keys and signatures, Merkle proofs, the HTTP client and `verifyPack`:

```ts
import { verifyPack, loadDrandVerifier } from "signafaide/core";
const report = verifyPack(pack, serviceKeys, { drand: await loadDrandVerifier() });
```

`record`, `wrapTools` and the CLI need Node 18+ because they keep local state on disk.


**For an auditor** the agent keys must come from you, not from the pack (otherwise a service could add a key of its own): `signafaide keys export -o agent-keys.json` writes every agent key, each signed by itself. The auditor runs `npx signafaide verify pack.json --keys <witness>/.well-known/signafaide-keys.json --agent-keys agent-keys.json --head head.json` (`head.json` is your `.signafaide/head.json`, which catches records cut off at the end). Without `--agent-keys` the client-signature check says `NOT INDEPENDENT` and the result is FAIL; `--trust-embedded-agent-keys` accepts the pack's keys and says so in the result line. On your own machine, `signafaide verify pack.json` uses this project's agent keys automatically. Public timestamps are checked online (`--timestamp-check <url>`, default `https://mempool.space/api`); with `--offline` they show `NOT CHECKED`, never confirmed. `signafaide keys rotate --agent X` gives an agent a new key; the SDK signs the registration of the new key with the old one.

## Replay

```bash
npx signafaide replay --agent claims-bot --from 2026-11-01 --to 2026-11-13 --html replay.html
npx signafaide replay --agent claims-bot --record 3fa2b1c9
```

Shows the agent's decisions and outcomes in order, with their inputs and outputs from the local chain. Each record is checked against its `content_hash`, its signature and the service's receipt first, so an edited line shows as `FAIL`. `--html` also writes a self-contained page. In code: `const r = await replay({ agent: "claims-bot", since: "2026-11-01" })`, then `String(r)`, `r.toHtml()`, `r.ok`.

## Experiments: A/B on past decisions

```ts
import { compare } from "signafaide";

const report = await compare(async (input) => ({ approved: input.amount < 300 }), { agent: "claims-bot", name: "approve_payout", since: "2026-11-01", limit: 500 });
console.log(String(report)); // n, agreed, changed, errors, then the changed decisions
await report.upload();       // optional: hash-only unless content is stored with the service
```

The chain is verified first; then each recorded decision with a co-signed outcome is re-run with your candidate, on your machine, with your own models and keys, and compared with the recorded `output` (exact canonical-JSON equality, or `same: (recorded, candidate) => ...`). The candidate gets the input as recorded: the single argument, or the argument list. A candidate that throws counts as an error. **Candidates must be side-effect free:** compare never writes records, and a recorded tool called from a candidate throws instead of running. CLI: `npx signafaide compare --module ./candidate.mjs:approve --name approve_payout --upload`.

## CLI

| command | does |
|---|---|
| `signafaide init` | the opt-in: creates a free sandbox if there is no key (no account, email or card), prints the claim link, what claiming gives and when an unclaimed sandbox is deleted |
| `signafaide status` | key and env, agents, last receipt, outbox size, quota; BLOCKED chains (exit 1) |
| `signafaide repair [--agent X] [--dry-run]` | sets aside records no witness can take (kept in `.signafaide/held/`, still verified), gives the agent a new key and starts a new segment |
| `signafaide verify [pack.json] [--keys ...] [--agent-keys ...] [--head ...] [--offline] [--fail-on-pending-send] [--json]` | verifies; exit 0 PASS, 1 FAIL or BLOCKED, 2 unreadable input |
| `signafaide keys export [-o agent-keys.json]` / `signafaide keys rotate [--agent X] [--env test\|live]` | the agent-key file for auditors / a new key for an agent |
| `signafaide keys create [--agent X] [--env test\|live] [--print]` | a new key, registered with the witness, for a secret store; writes no record (`--print`: prints the key file and saves nothing here) |
| `signafaide export [--agent X] [--from T] [--to T] [-o pack.json]` | downloads a verification pack of the whole project (every agent); `--agent` narrows it to one |
| `signafaide replay [--agent X] [--from T] [--to T] [--record H] [--html out.html] [--json]` | the verified timeline from the local chain; exit 1 on FAIL |
| `signafaide compare --module file.mjs:fn [--agent X] [--name N] [--from T] [--to T] [--limit N] [--upload [--values]]` | re-runs recorded decisions with a candidate and compares; `--values` sends the values too (stored-content decisions only) |
| `signafaide claim` | prints the claim link again, what claiming gives and how many days an unclaimed sandbox has left |
| `signafaide flush` | ships the outbox now (with no key it sends nothing and says so) |
| `signafaide gateway [--agent X] [--name-prefix P] [--strict \| --strict-tools a,b] [--store-content] -- <command> [args...]` | runs an MCP server behind a recording proxy: every tool call that passes through is recorded, and one that cannot be recorded is not forwarded (see "Recording everything an agent can call") |
| `signafaide agent setup [--agent <name>]... [--url <witness>] [--dry-run] [--dir <project>]` | installs the MCP server and the skill in your coding agents; `--url` sets `SIGNAFAIDE_URL` in each MCP entry |
| `signafaide mcp` | runs the MCP server over stdio, when the separate `signafaide-mcp` package is installed (`agent setup` configures `npx -y signafaide-mcp@<version>` instead) |

## Coding agents

```bash
npx signafaide agent setup
```

finds the coding agents installed or in use and, for each one, adds the signafAIde MCP server (`npx -y signafaide-mcp@<this version>`, a separate package so the SDK's own install stays small) and a short skill that says when signafAIde fits, in that agent's own format. It merges into existing files, never overwrites what is there, and running it twice changes nothing. `--agent` picks agents (`claude-code`, `codex`, `cursor`, `gemini-cli`, `copilot`, `windsurf` or `all`); `--dry-run` shows what would change; `--url <witness url>` writes `SIGNAFAIDE_URL` into each agent's MCP entry (a self-hosted witness). It also adds `.signafaide/` to `.gitignore` and remembers which coding agent set the project up. It ends with what is sent (nothing until a person opts in, then hashes only), where the content stays, and a reminder to give agents explicit names.

| agent | MCP server | instructions |
|---|---|---|
| Claude Code | `.mcp.json` | `.claude/skills/signafaide/SKILL.md` and a `CLAUDE.md` section |
| Codex | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`, shared by all projects) | `AGENTS.md` section |
| Cursor | `.cursor/mcp.json` | `.cursor/rules/signafaide.mdc` |
| Gemini CLI | `.gemini/settings.json` | `GEMINI.md` section |
| GitHub Copilot (VS Code) | `.vscode/mcp.json` | `.github/copilot-instructions.md` section |
| Windsurf | `.devin/mcp_config.json` | `AGENTS.md` section |

The MCP tools: `signafaide_setup` (a preview that changes, creates and sends nothing: the language and framework, the install command, the code edit and what a sandbox would send), `signafaide_init` (creates the external sandbox, and nothing unless the agent passes `confirm_user_agreed: true` and `user_words`, what the person wrote when they agreed), `signafaide_quickstart` (a reference snippet for a language and framework the agent names; it reads nothing in the project), `signafaide_verify` (runs the checks; with a key it ships waiting records first), `signafaide_status` (key, chains, outbox, quota and the claim step; it contacts the service only when a key exists), `signafaide_records` (lists and searches the records on this machine by agent, time or record hash; metadata only, never the inputs or outputs), `signafaide_flush` (sends the waiting records now, like `signafaide flush`; without an API key it sends nothing and never creates a sandbox), `signafaide_explain_error` and `signafaide_claim_link` (for when the person only needs the claim link). The three that return the claim link (`signafaide_init`, `signafaide_status`, `signafaide_claim_link`) return it with what claiming gives and the days an unclaimed sandbox has left, for the agent to pass on to the person. The MCP server needs Node.js 20 or later.

## What is sent besides records

Every request carries one header:

```
X-Signafaide-Client: signafaide-js/0.3.4 (node 22.22.0; adapter=vercel-ai; agent=cursor; via=sdk)
```

It holds the SDK and its version, the JavaScript runtime and its version, and the framework adapter in use (`langchain`, `openai-agents`, `vercel-ai`, `otel` for the OpenTelemetry processor, or `none`). It also holds the coding agent that set the project up (`claude-code`, `codex`, `cursor`, `gemini-cli`, `copilot`, `windsurf` or `unknown`) and how the call was made (`sdk`, `cli` or `mcp`). The agent is found from that tool's environment variables when the project is set up (`signafaide init`, `signafaide agent setup`) and kept in `.signafaide/config.json`; it is never guessed per process, so a program started from a terminal inside a coding agent is not labelled as that agent. `signafaide verify` and `signafaide export` also send `POST /v1/events {"name": "verify"}` (or `"export"`) when there is an API key. If that fails, the command is not affected. With no API key nothing at all is sent.

The header and the events hold no content, file paths, hostnames or user names. `SIGNAFAIDE_TELEMETRY=0` removes the adapter, the coding agent and the strict-mode flag from the header, stops the coding agent being saved in `.signafaide/config.json`, and turns the events off. The SDK and its version, the runtime and its version, and how the call was made (`via`) are still sent.

## Configuration

| variable | default |
|---|---|
| `SIGNAFAIDE_API_KEY` | read from the environment, then `.env`; created by `signafaide init`; none: local only |
| `SIGNAFAIDE_URL` | `https://api.signafaide.co.uk`; a self-hosted witness, or `http://127.0.0.1:7474` for a local dev server. Alone it sends nothing |
| `SIGNAFAIDE_HOME` | `.signafaide/` in the project root; a mounted volume or `/tmp/signafaide` in production |
| `SIGNAFAIDE_AGENT_KEY_<NAME>` | an agent's key file content from a secret store (or `keyProvider` in code); live keys can use `SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>`, made with `signafaide keys create --env live --print` |
| `SIGNAFAIDE_HEAD_FILE` | unset: a file outside `.signafaide/` (a persistent volume) that also keeps the newest signed heads, for containers whose disk does not last; or `onHead` in `configure()` |
| `SIGNAFAIDE_INSTANCE_STOP` | unset: a signed stop note is written at a clean exit when a head file is set; `1` always, `0` never (see Containers that restart) |
| `SIGNAFAIDE_EXIT_FLUSH_MS` | `3000`: the longest a finished program is kept open to send; `0` never |
| `SIGNAFAIDE_TEST` | test mode is on by itself under Vitest, Jest and `node --test` (records in a temporary folder, nothing sent); `1` forces it, `0` turns it off |
| `SIGNAFAIDE_DISABLED` | `1`: wrapped functions run and nothing is recorded |
| `SIGNAFAIDE_DECLARE_TOOLS` | `0`: `wrapTools` does not declare the tools it wraps (`declareTools()` still does) |
| `SIGNAFAIDE_SEGMENT_BYTES` | `67108864`: a shipped chain file larger than this rolls into a sealed segment |
| `SIGNAFAIDE_TELEMETRY` | `0` turns off the adapter, agent and strict fields and the events |

Running in containers, with replicas, on read-only or ephemeral disks, on serverless or in CI: see the [production guide](https://signafaide.co.uk/docs/production). A record's time never goes back along its chain: if the clock steps back, the record keeps the previous record's time and the clock's reading goes in `meta.wall_time`.

Each project and env has its own chain per agent. A new key, for example a live key replacing the sandbox key, starts a fresh chain at seq 1. The old chain stays on disk, and `signafaide status` lists every chain.

The project root is the nearest folder with `.signafaide/`, `.git`, `pyproject.toml` or `package.json`. `signafaide init` and `agent setup` add `.signafaide/` to `.gitignore` (never a running program). Agent keys live in `.signafaide/agents/<agent>.key` (sandbox) and `.signafaide/agents/live/<agent>.key` (live), mode 0600, and never leave the machine. Back them up. The Python and TypeScript SDKs share this folder and its formats.

ESM and CommonJS, with types. Dependencies: `@noble/ed25519`, `@noble/hashes` and `@noble/curves` (drand). `signafaide/otel` uses `@opentelemetry/api`, an optional peer dependency. The MCP server is the separate `signafaide-mcp` package, with the MCP SDK and `zod`, so `npm install signafaide` stays small.
