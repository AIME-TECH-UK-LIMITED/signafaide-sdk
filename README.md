# signafAIde SDK

[![CI](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/signafaide)](https://www.npmjs.com/package/signafaide) [![PyPI](https://img.shields.io/pypi/v/signafaide)](https://pypi.org/project/signafaide/) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

signafAIde checks each risky AI agent tool call before it runs, and proves what your agents did.

- **Record:** every tool call is signed with the agent's own key and chained on the machine that made it.
- **Protect:** an independent witness allows or blocks risky calls (pay, delete, send, run a command, push code) under your published rules; protect a tool with `npx signafaide protect` or one click in the console.
- **Prove:** share a link your auditor checks offline, without trusting you or us.

- **Free on its own:** the SDK and the verifiers are Apache-2.0 and need no account. On their own they give you a signed, chained, offline-verifiable record of every tool call, on your machine. The service adds what one party cannot give itself: an independent second signature, two public time bounds, and a check that no record is missing.
- **Local first:** with no API key, records are signed, chained and verified in `.signafaide/`, and nothing is sent. Sending starts only when a person runs `signafaide init` (a sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`.
- **Hashes, not content:** after the opt-in, each record sends its content hash with its tool name, agent name and time (and its chain links), never its inputs or outputs, unless you turn on stored content. Tool and agent names are sent as you write them, so don't put personal data in them. Each content hash is salted with 16 random bytes that stay on your machine with the content, so the hash alone cannot be used to guess the content, even when it has only a few possible values.
- **Your environment:** the default witness is the hosted service (`https://api.signafaide.co.uk`). A self-hosted witness, under an Enterprise contract, is set with `SIGNAFAIDE_URL` ([self-host guide](https://signafaide.co.uk/docs/self-host)). Running in production: [production guide](https://signafaide.co.uk/docs/production).
- **Independent checks:** the protocol is a public spec with test vectors, and the verifier checks a verification pack without our service.

## What is here

| path | what |
|---|---|
| [`spec/SPEC.md`](spec/SPEC.md) | the protocol: records, batches, receipts, anchors, the HTTP API, verification packs, local state |
| [`spec/vectors.json`](spec/vectors.json) | test vectors every implementation reproduces byte for byte |
| [`python/`](python/README.md) | the Python SDK and CLI (`signafaide` on PyPI) |
| [`python-langchain/`](python-langchain/README.md) | `langchain-signafaide`: a LangChain agent middleware that records every tool call the agent makes |
| [`js/`](js/README.md) | the TypeScript SDK, CLI and `agent setup` for coding agents (`signafaide` on npm), and the MCP server (`signafaide-mcp`, in `js/mcp`) |
| [`CHANGELOG.md`](CHANGELOG.md) | what changed in each release; every release is a git tag (`v0.5.3`) |
| [`verifier/`](verifier) | `signafaide-verify`, the standalone Rust verifier of a pack (also builds to WebAssembly) |
| [`core/`](core) | the Rust protocol core shared by the verifier and the service |
| [`plugin/`](plugin/README.md) | the Claude Code plugin: the MCP server and the skill |

## Quick start

In your agent's folder, at a terminal:

```bash
npx signafaide protect            # TypeScript or JavaScript
uv run signafaide protect         # Python (after uv add signafaide; or .venv/bin/signafaide protect)
```

`protect` finds the agent's tools, asks which to protect and what to block (On or Calibrating), shows the code change and asks before writing it, makes a free sandbox if you say yes and saves your rules. Then:

```bash
npx signafaide check approve_payout amount=1200 currency=GBP   # a dry run: exit 1 when it would block
npx signafaide status                                            # one line per tool: recorded, protected, proof
npx signafaide prove approve_payout                              # a read-only link for your auditor
```

`pull` fetches the rules saved in the console, `login` signs a person in to save rules after the sandbox is kept. A runnable example: [`examples/payout-agent`](examples/payout-agent); starters with a protected tool in place: [`templates/`](templates). To wrap tools by hand, see the reference sections of the [Python](python/README.md) and [TypeScript](js/README.md) READMEs.

- **Protected in code is protected.** A tool wrapped with `protect()` (or `@signafaide.protect`) runs every check on this machine On even without `signafaide.checks.json`, asks signafAIde for a ruling, and counts as protected in `status`, `prove`, `verify`, `check --ci` and the console.
- **Without a terminal** (a coding agent, a script, CI), `protect --yes` protects every tool that pays, deletes, sends messages, runs commands, pushes code or edits secrets or config, and gives each a default rule that starts Calibrating (it blocks nothing until a person turns it On): above 1,000 for a tool that pays and has an amount, else a number of calls a minute. The rules are saved in a sandbox nobody has kept yet, kept in `signafaide.checks.json` with no key, or, on a project an API key cannot save rules in, kept there with one console link per tool where a person adds the rule with one click. A field a rule needs is sent only after a person approves it with `signafaide pull` at a terminal. Details: [TypeScript](js/README.md#without-a-terminal-protect---yes), [Python](python/README.md#without-a-terminal-protect---yes).
- **Tests.** Under pytest, Vitest, Jest and `node --test` a protected tool runs without a ruling and nothing is sent; never with a live key.
- **Networks that block the witness.** When a proxy or network policy refuses it, the SDK says so in one sentence: allow `signafaide.co.uk` and `api.signafaide.co.uk` in the environment's network settings. Both SDKs go through `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` (TypeScript also `ALL_PROXY`).

## Add the MCP server to a coding agent

The MCP server (`signafaide-mcp`, Node.js 20 or later) lets a coding agent preview the setup, verify records and show status. It sends nothing until a person agrees to create a sandbox. In a project, `npx signafaide agent setup` writes this for each coding agent it finds. To add it by hand, put this in the agent's MCP configuration (Cline, Cursor, Windsurf, Kiro, Zed and others use the same shape):

```json
{
  "mcpServers": {
    "signafaide": { "command": "npx", "args": ["-y", "signafaide-mcp@0.5.3"] }
  }
}
```

- Claude Code: `claude mcp add signafaide -- npx -y signafaide-mcp@0.5.3`
- Gemini CLI: `gemini extensions install https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk`
- Kiro: [![Add to Kiro](https://kiro.dev/images/add-to-kiro.svg)](https://kiro.dev/launch/mcp/add?name=signafaide&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22signafaide-mcp%400.5.3%22%5D%2C%22disabled%22%3Afalse%2C%22autoApprove%22%3A%5B%5D%7D)

There are no API keys or other settings. To check it works, ask the agent to call `signafaide_status`.

## Recording everything an agent can call

Wrapping records the tools a developer wraps. Three things cover the rest.

- MCP tools: `signafaide gateway -- <the MCP server's command>` (in the `signafaide` npm package) runs an MCP server behind a recording proxy. The agent's MCP client starts the gateway in place of the server, for example `npx -y signafaide gateway --agent support-bot -- npx -y @modelcontextprotocol/server-filesystem /data`. Every tool call that passes through is recorded, a decision before the call is forwarded and an outcome when the answer arrives, and a call that cannot be recorded is not forwarded. A remote (HTTP) server goes behind a stdio bridge: `npx -y signafaide gateway -- npx -y mcp-remote https://mcp.example.com/mcp`.
- Traced agents: an agent already traced with OpenTelemetry is recorded with no wrapping, by one span processor added where tracing is set up (`SignafaideSpanProcessor`, in `signafaide.otel` for Python and `signafaide/otel` for TypeScript). It reads tool-call spans by the OpenTelemetry GenAI, OpenInference and OpenLLMetry conventions and exports nothing. Each record says that it comes from telemetry and whether its decision was written before the tool ran or after it, and what the tracing sampler can leave out is reported as a note. Running a tool only once it is recorded (a protected tool) needs the SDK's wrappers. See the [Python](python/README.md#opentelemetry-records-from-the-traces-you-already-have) and [TypeScript](js/README.md#opentelemetry-records-from-the-traces-you-already-have) READMEs.
- Framework tools: `wrap_tools` / `wrapTools` declare the tools they wrap as recorded, and `declare_tools([...])` / `declareTools([...])` takes the agent's full tool list, so the tools that are not wrapped are declared as not recorded. The declaration is a signed note per tool in the agent's chain (ordinary records, counted like any other), and every verifier reports it per agent, for example `all 4 declared tools are recorded` or `1 declared tool is not recorded: web_search`. It is a note, never a failure.

What this shows, and what it does not: the gateway records every call that goes through it; a call the application makes around it is still not recorded, so the deployment has to make the gateway the only route to those tools. A declaration is the program's own signed statement of its tools: evidence of what it said it had, not proof that the list is complete. A tool list is as fresh as its last declaration: a source that stops (a gateway that is removed, a program that ends) leaves the list at its clean exit, or within 24 hours after a crash. Details: [TypeScript](js/README.md), [Python](python/README.md), spec §2.6, §7 and §8.

## Verify without our service

```bash
cargo run --manifest-path verifier/Cargo.toml -- pack.json --keys keys.json --agent-keys agent-keys.json --head head.json --offline
```

The service keys come from the witness's `/.well-known/signafaide-keys.json` (or a file). The agent keys, `agent-keys.json`, come from the customer, who runs `signafaide keys export` and hands the file over with the pack. `--head` is optional: the customer's newest signed head (`.signafaide/head.json`), which proves no record was dropped from the end. `--offline` skips the public timestamp lookup, so that check is reported as not checked, never as passed. The result line says how many of the 12 checks passed, are pending (a public timestamp that has not confirmed yet) and were not checked, for example `PASS: 11 of 12 checks passed, 1 pending (public timestamp)`. The Python and TypeScript SDKs run the same checks (`signafaide verify pack.json`). Every verifier gives the same check ids, statuses and result for the same inputs (spec §7).

## Privacy and support

- Privacy: [privacy notice](https://signafaide.co.uk/legal/privacy)
- Support: [open an issue](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/issues) or email sales@signafaide.co.uk
- Security reports: see the [security page](https://signafaide.co.uk/security)

## License

Apache-2.0, see [LICENSE](LICENSE).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout and how to run the checks. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
