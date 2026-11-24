# Contributing

Issues and pull requests are welcome. For anything larger than a small fix, open an issue first so we can agree the approach.

## Layout

| path | what | language |
|---|---|---|
| `spec/` | the protocol (`SPEC.md`) and the test vectors (`vectors.json`) every implementation must reproduce | |
| `core/` | the protocol core: canonical JSON, hashing, signatures, Merkle proofs, pack verification, the vector generator | Rust |
| `verifier/` | `signafaide-verify`, the standalone pack verifier (also builds to WebAssembly); `pyproject.toml` describes the PyPI package (its wheels are the release binaries, its sdist builds from source) | Rust |
| `js/verify/` | `signafaide-verify` on npm: `js/src/verify-bin.ts` and the SDK's verifier bundled into one file | TypeScript |
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

# The standalone verifiers: the PyPI wheel (the Rust binary), the npm package, and the spec
# vectors through them and the Rust binary, with the same output from each
cargo build --release --locked --manifest-path verifier/Cargo.toml
python3 scripts/binary-wheel.py verifier/target/release/signafaide-verify linux_x86_64 /tmp/wheels
python3 -m venv /tmp/verify-venv && /tmp/verify-venv/bin/pip install --no-index /tmp/wheels/*.whl
(cd js && npx tsup --config tsup.verify.config.ts)
cargo build --release --locked --manifest-path verifier/Cargo.toml --features test-keys-url --target-dir verifier/target/test-keys-url
node scripts/verify-vectors.mjs verifier/target/release/signafaide-verify js/verify/dist/cli.js /tmp/verify-venv/bin/signafaide-verify \
  --test verifier/target/test-keys-url/release/signafaide-verify --test js/verify/dist-test/cli.js

# Release checks: versions agree, default witness URL, verifier build, the standalone verifiers
# agree (VERIFY_COMMANDS adds the installed wheel's command)
VERIFY_COMMANDS=/tmp/verify-venv/bin/signafaide-verify node scripts/release-check.mjs --offline
```

## Releasing the verifier

`signafaide-verify` is released by `.github/workflows/release.yml`, started by hand on `main` (Actions, Release verifier, Run workflow, branch `main`, version `X.Y.Z`), so it always runs main's copy of the workflow. Its preflight job checks every prerequisite below and fails before anything is built for release or uploaded. Then it builds the binaries, wheels, sdist and npm package and runs the vectors through each on its own platform. In the `release` environment it makes the tag `vX.Y.Z` at that commit, writes `SHA256SUMS`, attests every file (Sigstore) and creates the GitHub release with `LICENSE` and `THIRD-PARTY-NOTICES.md`. Then it publishes to PyPI and npm, each in its own environment, both through trusted publishing (OIDC): no token is stored anywhere.

### One-time settings (repository owner)

GitHub, Settings, Environments. Create `release`, `pypi` and `npm`, each with:
- Required reviewers: at least one person (not the one who starts the run, if you can: tick "Prevent self-review").
- Deployment branches and tags: "Selected branches and tags", with one rule: branch `main`. No tag rules.
- No secrets.

PyPI (pypi.org, project `signafaide-verify`, Publishing): a trusted publisher with owner `AIME-TECH-UK-LIMITED`, repository `signafaide-sdk`, workflow `release.yml`, environment `pypi`.

npm (npmjs.com, package `signafaide-verify`, Settings, Trusted publishing): add GitHub Actions with organization or user `AIME-TECH-UK-LIMITED`, repository `signafaide-sdk`, workflow filename `release.yml`, environment `npm`. Then, under "Publishing access", choose "Require two-factor authentication and disallow tokens", so only the trusted publisher can publish. The workflow publishes with the npm that comes with its pinned Node.js (11.19.1 with Node.js 24.22.3), which supports trusted publishing.

### What the preflight checks
- The run is on `main` (`refs/heads/main`) and its commit is on main, with successful `ci.yml` and `verify-node20.yml` push runs.
- The version asked for is the one in `verifier/Cargo.toml`, `js/verify/package.json` and `js/package.json`.
- No tag `vX.Y.Z` yet and `signafaide-verify` at `X.Y.Z` on neither npm nor PyPI, or the tag already at this commit (a re-run); the npm name's maintainers are `aimetech` alone; the PyPI project exists.
- `release`, `pypi` and `npm` exist, each with a required reviewer and only branch `main` allowed.
- `verifier/THIRD-PARTY-NOTICES.md` is what cargo-about (pinned by version and checksum) makes from `verifier/Cargo.lock` with `verifier/about.toml`.

After the preflight, an upload can still fail at a registry (for example a trusted publisher whose settings do not match). npm publishes first and PyPI only after npm succeeded, so a failure on npm leaves PyPI untouched. To finish a release after fixing the cause, either re-run the failed jobs of the same run, or run the workflow again on the same main commit with the same version. On a new run, the preflight accepts the existing tag when it is at this commit (at another commit it stops). The release job finds the existing release, checks it has every file and changes nothing (releases are immutable). npm skips the version when it already has it. PyPI uploads only the files it does not have yet (`skip-existing`), then checks that every wheel and the sdist are there, and fails if one is missing. Both publish jobs always take the files of the GitHub release, checked against its `SHA256SUMS`, never a rebuild.

### The order of a release
1. A PR that bumps every version to `X.Y.Z` (the release check lists each file) and moves the CHANGELOG entries under `## vX.Y.Z`, merged to main with CI green.
2. Run Release verifier on main with `X.Y.Z`; approve the `release`, `pypi` and `npm` deployments.
3. `node scripts/release-check.mjs` (online), which now passes: `signafaide-verify X.Y.Z` is on npm and PyPI.
4. Publish the SDK packages (`signafaide`, `signafaide-mcp`): they print `npx`/`uvx signafaide-verify@X.Y.Z` for auditors.
5. Publish the GitHub Action: copy `action.yml`, `check.mjs`, `runs.mjs`, `README.md` and `DOCS.md` from `action/` to [signafaide-action](https://github.com/AIME-TECH-UK-LIMITED/signafaide-action) (its README keeps its own first paragraph and the `signafaide-action@vX.Y.Z` usage line), commit, tag `vX.Y.Z` there, and create its GitHub release with "Publish this Action to the GitHub Marketplace" ticked. Then move the pinned commit in `action/README.md`, `action/DOCS.md` and `examples/ci/` to that tag's commit.

### Pinned keys, notices and test files
- The pinned service keys are `spec/service-keys.json`; `js/service-keys.json`, `python/src/signafaide/service-keys.json` and `verifier/service-keys.json` are copies the release check keeps identical. Keys are append-only (§5): a key is never removed from these files and its `key_id`, `public_key` and `valid_from` never change (the release check compares with the last release's file); new fields never go on a key entry. A key rotation goes in this order (the service's `docs/ops/production.md` has the same steps, with a week between them): (1) the witness publishes the new key with a future `valid_from` (`signafaide-server keys add`), and it goes into these four files; (2) release the verifiers pinning both keys; (3) at or after `valid_from` the witness restarts with the new seed, which retires the old key. Keep a spare next key published and pinned at all times, its seed offline, so a compromise can switch at once. Older releases keep working: a retired pinned key has its `valid_to` applied, and a pack made since the newer key became valid is named as needing a newer release. A key that must not be trusted is revoked (§5 `revoked`, after switching away from it): it stays in the list, every release applies the revocation from the published list (nothing it signed verifies) and names it, and the next release adds it to `revoked` in these four files too, where it is applied even offline. A revoked id is never removed from them (the release check and CI compare with the last release's file).
- `verifier/THIRD-PARTY-NOTICES.md`: after any change to `verifier/Cargo.lock`, run `cargo about generate --manifest-path verifier/Cargo.toml verifier/about.hbs -o verifier/THIRD-PARTY-NOTICES.md` (cargo-about 0.9.3). The npm package's notices are made at pack time from the bundle (`js/verify/prepack.mjs`).
- `SIGNAFAIDE_VERIFY_KEYS_URL` exists only in the tests' builds: the Rust feature `test-keys-url` and `js/verify/dist-test` (never packed). Release builds do not contain it, and the release check and the release workflow check that.
- `scripts/verify-vectors.mjs` makes a certificate for `127.0.0.1` from a test-only CA with `openssl` at the start of each run, in its temporary folder, and deletes the CA's private key once it has signed; only that run trusts it, for its local https explorer and key lists. `openssl` must be on the PATH (it is on GitHub's Linux, macOS and Windows runners).

## Changes to the protocol

A change to records, packs or verification goes in `spec/SPEC.md` first, then in `core/`, then in both SDKs. Regenerate the vectors with `cargo run --manifest-path core/Cargo.toml --bin gen-vectors`; they are never edited by hand, and a core test fails when they are stale.

## Style

- Formatting is enforced: Prettier for TypeScript, `ruff format` for Python, `rustfmt` for Rust, all at 120 columns.
- Comments say why, not what. Cite the spec section (`§8`) when code implements it.
- User-facing messages are plain sentences that say what happened and what to do next.
- Add a line to `CHANGELOG.md` under `Unreleased` for anything a user would notice.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, as the rest of the repository.
