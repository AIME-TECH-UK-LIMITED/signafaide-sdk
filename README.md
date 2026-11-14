# signafAIde SDK

signafAIde records the decisions AI agents make. Each record is signed with the agent's own key and chained on the machine that wrote it. Once a person opts in, a witness (the signafAIde service, or one you host) co-signs it and timestamps it publicly, so neither side can forge or edit a record alone. It attests integrity and timing, never whether a decision was right.

- **Local first:** with no API key, records are signed, chained and verified in `.signafaide/`, and nothing is sent. Sending starts only when a person runs `signafaide init` (a sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`.
- **Hashes, not content:** after the opt-in, each record sends its content hash with its tool name, agent name and time (and its chain links), never its inputs or outputs, unless you turn on stored content. Tool and agent names are sent as you write them, so don't put personal data in them. Each content hash is salted with 16 random bytes that stay on your machine with the content, so the hash alone cannot be used to guess the content, even when it has only a few possible values.
- **Your environment:** the default witness is the hosted service (`https://api.signafaide.com`). A self-hosted witness, under an Enterprise contract, is set with `SIGNAFAIDE_URL` ([self-host guide](https://signafaide.com/docs/self-host)). Running in production: [production guide](https://signafaide.com/docs/production).
- **Independent checks:** the protocol is a public spec with test vectors, and the verifier checks a verification pack without our service.

## What is here

| path | what |
|---|---|
| [`spec/SPEC.md`](spec/SPEC.md) | the protocol: records, batches, receipts, anchors, the HTTP API, verification packs, local state |
| [`spec/vectors.json`](spec/vectors.json) | test vectors every implementation reproduces byte for byte |
| [`python/`](python/README.md) | the Python SDK and CLI (`signafaide` on PyPI) |
| [`js/`](js/README.md) | the TypeScript SDK, CLI and `agent setup` for coding agents (`signafaide` on npm), and the MCP server (`signafaide-mcp`, in `js/mcp`) |
| [`scripts/release-check.mjs`](scripts/release-check.mjs) | run before a release: the default witness is the hosted service, versions agree, and the npm and PyPI names are claimed |
| [`verifier/`](verifier) | `signafaide-verify`, the standalone Rust verifier of a pack (also builds to WebAssembly) |
| [`core/`](core) | the Rust protocol core shared by the verifier and the service |
| [`plugin/`](plugin/README.md) | the Claude Code plugin: the MCP server and the skill |

## Quick start

```bash
uv add signafaide                 # Python, in a uv project; or: python3 -m venv .venv && .venv/bin/python -m pip install signafaide
npm install signafaide            # TypeScript or JavaScript
```

Wrap the tools that act, run the agent, then `signafaide verify` (`npx signafaide verify` for TypeScript). See the [Python](python/README.md) and [TypeScript](js/README.md) READMEs.

## Verify without our service

```bash
cargo run --manifest-path verifier/Cargo.toml -- pack.json --keys keys.json --agent-keys agent-keys.json --head head.json --offline
```

The service keys come from the witness's `/.well-known/signafaide-keys.json` (or a file). The agent keys, `agent-keys.json`, come from the customer, who runs `signafaide keys export` and hands the file over with the pack. `--head` is optional: the customer's newest signed head (`.signafaide/head.json`), which proves no record was dropped from the end. `--offline` skips the public timestamp lookup, so that check is reported as not checked, never as passed. The result line says how many of the 12 checks passed, are pending (a public timestamp that has not confirmed yet) and were not checked, for example `PASS: 11 of 12 checks passed, 1 pending (public timestamp)`. The Python and TypeScript SDKs run the same checks (`signafaide verify pack.json`). Every verifier gives the same check ids, statuses and result for the same inputs (spec §7).

## License

Apache-2.0, see [LICENSE](LICENSE).
