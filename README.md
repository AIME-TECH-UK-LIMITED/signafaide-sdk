# signafAIde SDK

signafAIde records the decisions AI agents make. Each record is signed with the agent's own key and chained on the machine that wrote it. Once a person opts in, a witness (the signafAIde service, or one you host) co-signs it and timestamps it publicly, so neither side can forge or edit a record alone. It attests integrity and timing, never whether a decision was right.

- **Local first:** with no API key, records are signed, chained and verified in `.signafaide/`, and nothing is sent. Sending starts only when a person runs `signafaide init` (a sandbox: no account, email or card) or sets `SIGNAFAIDE_API_KEY`.
- **Hashes only:** after the opt-in, only hashes leave the machine (plus each record's tool name, agent name and time), never inputs, outputs or personal data, unless you turn on stored content.
- **Your environment:** self-host the witness and point the SDKs at it with `SIGNAFAIDE_URL` ([self-host guide](https://signafaide.com/docs/self-host)).
- **Independent checks:** the protocol is a public spec with test vectors, and the verifier checks a verification pack without our service.

## What is here

| path | what |
|---|---|
| [`spec/SPEC.md`](spec/SPEC.md) | the protocol: records, batches, receipts, anchors, the HTTP API, verification packs, local state |
| [`spec/vectors.json`](spec/vectors.json) | test vectors every implementation reproduces byte for byte |
| [`python/`](python/README.md) | the Python SDK and CLI (`signafaide` on PyPI) |
| [`js/`](js/README.md) | the TypeScript SDK, CLI, MCP server and `agent setup` for coding agents (`signafaide` on npm) |
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
cargo run --manifest-path verifier/Cargo.toml -- pack.json --keys keys.json --agent-keys agent-keys.json --offline
```

The service keys come from the witness's `/.well-known/signafaide-keys.json` (or a file), the agent keys from the customer's `signafaide keys export`. The Python and TypeScript SDKs run the same checks (`signafaide verify pack.json`). Every verifier gives the same check ids, statuses and result for the same inputs (spec §7).

## License

Apache-2.0, see [LICENSE](LICENSE).
