# signafAIde SDK

signafAIde gives you audit evidence of what your AI agents did, for EU AI Act record-keeping, ISO/IEC 42001 and SOC 2. Each tool call is recorded, signed with the agent's own key and chained on the machine that wrote it. Once a person opts in, an independent witness (the signafAIde service, or one you host) co-signs it and timestamps it publicly, so neither side can forge, edit or remove a record alone, and an auditor can check it offline without trusting either. It attests integrity and timing, never whether a decision was right.

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
| [`CHANGELOG.md`](CHANGELOG.md) | what changed in each release; every release is a git tag (`v0.3.2`) |
| [`verifier/`](verifier) | `signafaide-verify`, the standalone Rust verifier of a pack (also builds to WebAssembly) |
| [`core/`](core) | the Rust protocol core shared by the verifier and the service |
| [`plugin/`](plugin/README.md) | the Claude Code plugin: the MCP server and the skill |

## Quick start

```bash
uv add signafaide                 # Python, in a uv project; or: python3 -m venv .venv && .venv/bin/python -m pip install signafaide
npm install signafaide            # TypeScript or JavaScript
```

Wrap the tools that act, run the agent, then `signafaide verify` (`npx signafaide verify` for TypeScript). See the [Python](python/README.md) and [TypeScript](js/README.md) READMEs.

## Add the MCP server to a coding agent

The MCP server (`signafaide-mcp`, Node.js 20 or later) lets a coding agent preview the setup, verify records and show status. It sends nothing until a person agrees to create a sandbox. In a project, `npx signafaide agent setup` writes this for each coding agent it finds. To add it by hand, put this in the agent's MCP configuration (Cline, Cursor, Windsurf, Kiro, Zed and others use the same shape):

```json
{
  "mcpServers": {
    "signafaide": { "command": "npx", "args": ["-y", "signafaide-mcp@0.3.2"] }
  }
}
```

- Claude Code: `claude mcp add signafaide -- npx -y signafaide-mcp@0.3.2`
- Gemini CLI: `gemini extensions install https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk`
- Kiro: [![Add to Kiro](https://kiro.dev/images/add-to-kiro.svg)](https://kiro.dev/launch/mcp/add?name=signafaide&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22signafaide-mcp%400.3.2%22%5D%2C%22disabled%22%3Afalse%2C%22autoApprove%22%3A%5B%5D%7D)

There are no API keys or other settings. To check it works, ask the agent to call `signafaide_status`.

## Recording everything an agent can call

Wrapping records the tools a developer wraps. Two things cover the rest.

- MCP tools: `signafaide gateway -- <the MCP server's command>` (in the `signafaide` npm package) runs an MCP server behind a recording proxy. The agent's MCP client starts the gateway in place of the server, for example `npx -y signafaide gateway --agent support-bot -- npx -y @modelcontextprotocol/server-filesystem /data`. Every tool call that passes through is recorded, a decision before the call is forwarded and an outcome when the answer arrives, and a call that cannot be recorded is not forwarded. A remote (HTTP) server goes behind a stdio bridge: `npx -y signafaide gateway -- npx -y mcp-remote https://mcp.example.com/mcp`.
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
