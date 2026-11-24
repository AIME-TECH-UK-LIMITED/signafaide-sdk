# signafaide-verify

Checks a signafAIde verification pack on your own machine, without an account, the SDK or the signafAIde console. It runs the 12 checks of the protocol spec (§7) and prints one line per check and a result line.

It comes three ways. Pin the release your customer's `signafaide prove` names:

- PyPI: `uvx signafaide-verify@0.5.6 ...` or `pipx install signafaide-verify==0.5.6`. The wheels hold the release binaries below, file for file, with no Python dependencies. On a platform without a wheel, pip builds the Rust verifier from the sdist, which needs a Rust toolchain.
- npm: `npx signafaide-verify@0.5.6 ...` (Node.js 20 or later). This is the TypeScript verifier in one file with no dependencies; the bundled `@noble` libraries' licences are in `THIRD-PARTY-NOTICES.md`.
- A single program for Linux (static), macOS and Windows on [GitHub Releases](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/releases), with `SHA256SUMS` and signed build provenance.

The PyPI package and the binaries are the Rust verifier; the npm package is the TypeScript one. They give the same check ids, statuses and result line for the same inputs, which CI checks with the spec's test vectors and the same input cases.

## What you need

From the company whose agents you are checking:

- `pack.json`: the verification pack.
- `agent-keys.json`: their agents' public keys (`signafaide keys export`).
- `head.json` (optional): their newest signed head, which shows no record was cut from the end.

You do not need the service's keys: each release has the hosted witness's public keys pinned in it.

## Run it

```bash
signafaide-verify pack.json --agent-keys agent-keys.json --head head.json
```

The service keys: the release verifies with the keys pinned in it. Online, it also reads the list published at `https://signafaide.co.uk/.well-known/signafaide-keys.json`: keys are never removed or changed, so every pinned key must be there with the same bytes. A key retired there (a `valid_to`) or revoked there (under `revoked`: nothing it signed verifies) is applied, named on the `service keys:` line, and the run goes on; newer keys and unknown fields are fine (a pack made since a newer key became valid needs a newer release). If a pinned key is missing or changed, or `revoked` is malformed, the run stops with `KEYS DIFFER` and exit code 2. If the list cannot be read, it verifies with the pinned keys and the line above the result says `not cross-checked (published list unreachable)`. With `--offline` no network request is made: the line says `not cross-checked (--offline)` and the public timestamp check is reported as not checked, never as passed. `--keys <file|url>` uses other keys, for example a self-hosted witness's `https://<its address>/.well-known/signafaide-keys.json`; a key that document lists as revoked is never used, and when they are not exactly the pinned set (any entry differs, including its dates, or a revocation), the result line says `service keys from --keys differ from the pinned set`.

`--json` prints the report as JSON for other tools, with `service_keys_source`, `service_keys_cross_check` and `service_keys_pinned_set`. Redirects are never followed. Behind a TLS-inspecting proxy, set `SSL_CERT_FILE` (binary and PyPI) or `NODE_EXTRA_CA_CERTS` (npm) to its CA certificates. `--help` lists every option.

## Check a downloaded binary

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify signafaide-verify-linux-x86_64 \
  --repo AIME-TECH-UK-LIMITED/signafaide-sdk \
  --signer-workflow AIME-TECH-UK-LIMITED/signafaide-sdk/.github/workflows/release.yml \
  --source-ref refs/heads/main
```

On macOS use `shasum -a 256`; on Windows compare `Get-FileHash` with `SHA256SUMS`. The macOS programs are not notarised by Apple yet, so macOS may refuse to open them: on a Mac, use the npm or PyPI package instead.

## Read the result

The last line is the result, for example:

```
PASS: 12 of 12 checks passed; export of every agent, all records, generated 2026-11-20T09:00:00.000Z
```

- `PASS` or `FAIL` is the result. Exit code 0 is PASS, 1 is FAIL, 2 means an input could not be read or the keys differ.
- Only checks that passed are counted as passed. A check can also be `pending` (a public timestamp that has not confirmed yet, usually within a few hours) or `not checked` (for example with `--offline`). Neither makes the pack fail.
- When a key did not come from an independent source, a note in brackets after PASS says so.

The lines above the result say what each check found, and which tools each agent declared and recorded.

## Building from source

```bash
cargo build --release --manifest-path verifier/Cargo.toml
```

The binary is `verifier/target/release/signafaide-verify`. Apache-2.0; the licences of the crates in the binary are in `THIRD-PARTY-NOTICES.md`.
