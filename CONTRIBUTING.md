# Contributing

Issues and pull requests are welcome. For anything larger than a small fix, open an issue first so we can agree the approach.

## Layout

| path | what | language |
|---|---|---|
| `spec/` | the protocol (`SPEC.md`) and the test vectors (`vectors.json`) every implementation must reproduce | |
| `core/` | the protocol core: canonical JSON, hashing, signatures, Merkle proofs, pack verification, the vector generator | Rust |
| `verifier/` | `signafaide-verify`, the standalone pack verifier (also builds to WebAssembly) | Rust |
| `js/src/` | the TypeScript SDK and CLI; `js/mcp/` is the MCP server package | TypeScript |
| `python/src/signafaide/` | the Python SDK and CLI | Python |
| `python-langchain/` | `langchain-signafaide`, the LangChain agent middleware | Python |
| `action/` | the GitHub Action | JavaScript |
| `plugin/`, `agents/`, `templates/`, `examples/` | the coding-agent plugin and skill, agent setup files, starter projects and CI examples | |

The TypeScript and Python SDKs implement the same spec and mirror each other module for module (`crypto`, `jcs`, `records`, `state`, `runtime`, `checks`, `verifier`, `http`, `cli`). A change to one usually needs the same change in the other, and both must still reproduce `spec/vectors.json`.

Good places to start reading: `js/src/record.ts` (what happens on one tool call), `js/src/verifier.ts` (how a pack is checked) and `spec/SPEC.md` §2.

## Running the checks

Run from the repository root. CI runs the same steps on every pull request.

```bash
# Rust: format, lint, tests (the core tests check spec/vectors.json)
for c in core verifier; do
  cargo fmt --manifest-path $c/Cargo.toml --check
  cargo clippy --manifest-path $c/Cargo.toml --all-targets -- -D warnings
  cargo test --manifest-path $c/Cargo.toml
done

# Python (uv): lint, format, tests
uvx ruff@0.15.7 check python python-langchain
uvx ruff@0.15.7 format --check python python-langchain
(cd python && uv sync && uv run pytest -q)
(cd python-langchain && uv sync && uv run pytest -q)

# TypeScript: building and the tests need Node 22.18+ (22.x from 22.18, 24.11+, or 26+, as tsup 9
# requires); the published packages run on Node 20 or later (the CI job "Packed package on
# Node 20" checks that). The cross-check tests also use the Rust verifier and the
# Python environment, so build those first.
cargo build --manifest-path verifier/Cargo.toml
(cd js && npm ci \
  && npx prettier --check "src/**/*.ts" "test/**/*.{ts,mjs}" ../action/*.mjs ../scripts/*.mjs \
  && npx tsc --noEmit -p . && npm test)

# Release checks: versions agree, default witness URL, verifier build
node scripts/release-check.mjs --offline
```

## Changes to the protocol

A change to records, packs or verification goes in `spec/SPEC.md` first, then in `core/`, then in both SDKs. Regenerate the vectors with `cargo run --manifest-path core/Cargo.toml --bin gen-vectors`; they are never edited by hand, and a core test fails when they are stale.

## Style

- Formatting is enforced: Prettier for TypeScript, `ruff format` for Python, `rustfmt` for Rust, all at 120 columns.
- Comments say why, not what. Cite the spec section (`§8`) when code implements it.
- User-facing messages are plain sentences that say what happened and what to do next.
- Add a line to `CHANGELOG.md` under `Unreleased` for anything a user would notice.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, as the rest of the repository.
