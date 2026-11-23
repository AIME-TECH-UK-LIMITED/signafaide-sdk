# Changelog

Notable changes to the signafAIde SDK: the TypeScript and Python packages, the MCP server, the Rust core and verifier, the Claude Code plugin and the protocol spec.
Every release shares one version number and is a git tag; changes to the spec (`spec/SPEC.md`) are noted with the release that made them.
Records and packs written by a version verify with that version and later ones, unless an entry says otherwise.

## v0.5.5 (2026-11-23)

Spec stays 1.1; records do not change. Release fix: v0.5.4 was tagged but never published to npm or PyPI (a publish path bug); 0.5.5 is the first published `signafaide-verify` and has v0.5.4's changes below, with the fix and the changes in this entry.

- Breaking: Python 3.9 is no longer supported (end of life October 2025); Python 3.10 or later is required.
- Breaking: Node.js 18 is no longer supported (end of life April 2025); the npm packages need Node.js 20 or later.
- `release.yml` publishes the npm package from `./dist/...`: without the `./`, npm read the path as a GitHub repository and the v0.5.4 publish failed before npm or PyPI had it.
- Supply chain: OpenSSF Scorecard and CodeQL run on the repository, every GitHub Action is pinned to a commit, Dependabot proposes weekly updates, and the remaining vulnerability findings in the lockfiles are cleared. SECURITY.md gives the security@ address and response targets.
- The packages are built with tsup 9 (building needs Node.js 22.18 or later); CI installs the packed `signafaide`, `signafaide-mcp` and `signafaide-verify` packages on Node.js 20 and runs them there.
- README: a recorded demo of the payout example, a diagram of how a call is checked and proved, and how to protect a tool in code; a code of conduct, issue forms and a pull request template.

## v0.5.4 (2026-11-20)

Spec stays 1.1; records do not change. The new standalone `signafaide-verify` packages start at this version.

- `signafaide-verify` for auditors, on its own: on PyPI (the release binaries in wheels, no Python dependencies; an sdist elsewhere, which needs a Rust toolchain), on npm (the TypeScript verifier in one file, no dependencies, Node.js 20 or later), and as single binaries for Linux (static), macOS and Windows on GitHub Releases, with `SHA256SUMS`, signed build provenance, `LICENSE` and `THIRD-PARTY-NOTICES.md`.
- Spec §5 and §7 (1.1, additive): an optional `revoked` list in the service keys document. Without `--keys`, `signafaide-verify` verifies with the hosted witness's keys pinned in its release. Keys are append-only (never removed, their id, public key and `valid_from` never changed; key entries never gain fields), and a revoked key stays in the list and in `keys_hash`, only barred from verifying. Online, it checks that every pinned key is in `https://signafaide.co.uk/.well-known/signafaide-keys.json` with the same bytes; a retirement (`valid_to`) or revocation there is applied and named and the run goes on, newer keys and unknown fields are allowed; a missing or changed pinned key, or a malformed `revoked`, stops it with `KEYS DIFFER` and exit code 2. Every verifier (the Rust core and binary, the npm command, the SDKs' `signafaide verify`) reads keys with one loader: the whole list for `keys_hash` and the revoked ids; a revoked entry needs only `key_id`. With `--keys`, a key that document revokes verifies nothing, and keys that are not exactly the pinned set (any entry's id, public key, `valid_from` or `valid_to` differs, or a revocation) are named in the result line: `PASS (service keys from --keys differ from the pinned set): ...`. When the list cannot be read it verifies with the pinned keys and says so; `--offline` makes no request. A `service keys:` line above the result line, and `service_keys_source` and `service_keys_cross_check` in `--json`, say where the keys came from.
- Every `signafaide-verify` refuses service keys that are not `{"keys": [...]}`, follows no redirect, and reads at most 1 MiB of a key list (`--keys`, `--agent-keys`, the published list) and at most 64 KiB of an explorer answer, in the Rust binary and the npm package alike. Content files skip draft lines and lines whose content is not an object, and a content directory may hold JSON array files.
- Tool-call checks: the default witness's keys and revoked ids come from the package's `service-keys.json`; the published key list is read again 10 minutes after a good read and 60 s after a failed one (one `tried` time in `checks/keys.json`, shared by every process), before a rule set, a list item or a ruling is judged. Revocations are never refused or dropped: from any valid key list the client keeps exactly the revoked ids naming a key it holds (for the default witness also up to 64 naming keys not pinned yet); a self-hosted witness's keys are merged, never dropped, up to 64, and a list that drops or changes a held key or passes the limit has its key changes refused, its revocations applied. Keep, then fail closed: each held rule set and the held list has a state file (`<env>.state.json`, `fingerprints.state.json`); when its signer is revoked or no longer held, or a signed replacement is refused, it is enforced as held for 7 days (`REVOKED_GRACE_MS`) from when the client first learned it, shown in `checks status` (`STALE ...; enforced as held until <UTC>`, exit 0, then `PROBLEM ...; protected calls are refused`, exit 1) with words by cause, said once a day and noted once per agent once the mark outlives a pull; after that, or at once for a copy that is unreadable or fails its own signature, every protected call is refused (`rules_unavailable`, its decision still written), except in test mode. Only writing a verified object clears it; unsigned answers, network errors and key list changes never do. While stale the rule set is fetched without `If-None-Match` and the list from a snapshot; the list is written once, at the end of a clean pull. A refused signed item waits 60 s doubling to an hour (also with nothing held; an `until` further ahead counts as an hour from now), and a strict ruling naming a refused newer version wakes no fetch meanwhile; a clean pull, another SDK version, and `signafaide pull` / `signafaide rules pull` (the key list, the rule set and the list, at once) end the wait. A broken copy keeps protecting the tools its last verified version protected from the console (kept in `<env>.protect.json`: written after the copy, kept in step with every verified copy read, union-only); with no record for its version the protection list is unknown and every checked call is refused ("protection list unknown: every checked call is refused until the rule set verifies; run `signafaide pull`"), while the gateway still lists tools; a strict ruling naming the refused version wakes nothing, a newer one is fetched at once (at most once a minute per version and 3 a minute in all, kept on disk); a protect record without a version never counts; `signafaide check` and `rules test` apply the same refusal (exit 1); status reads and writes only this witness's state files.
- Sending: an explicit `flush` of a recorder whose background sender stopped on a project-wide refusal (`quota_exceeded`, `invalid_key`, `plan_required`) keeps that stop while it runs and ends it only after a flush that sent records and met no refusal or failure (a network error or an unresolved project keeps it), or, with nothing to ship, after one `GET /v1/project` the witness accepts (within the flush's timeout); before, the stop ended at the flush's start and the background sender could send alongside it. In Python, `close()` also stops the rule set and list fetcher (as in TypeScript).
- `prove --files` and `keys export` print the one auditor command, `npx` or `uvx signafaide-verify@0.5.4`, with `--keys` only for a self-hosted witness.
- The Rust verifier says "signature does not verify" for a bad signature, as the Python and TypeScript verifiers do.
- Releases of `signafaide-verify` are made by `release.yml`, run by hand on main after a preflight of every prerequisite, and published to PyPI and npm through trusted publishing only (CONTRIBUTING.md).
- `scripts/verify-vectors.mjs` runs the spec vectors and the input cases through every `signafaide-verify`, with the public timestamp vectors and the published key lists served by a local https server. CI and the release check run it, and the release check requires `signafaide-verify` at the release's version on npm and PyPI before the SDK is published.

## v0.5.3 (2026-11-20)

- README openings and package descriptions now say what signafAIde does: checks risky tool calls before they run, signs every call, verifies offline.
- They no longer name EU AI Act, ISO/IEC 42001 or SOC 2.
- The CLI's upgrade hints link to the pricing page instead of quoting prices.
- Python exports `TOOL_SOURCE_MAX_AGE_MS` and `TOOL_SOURCE_REFRESH_MS` in `__all__`; the Rust verifier names its Bitcoin header map type `BitcoinHeaders`.
- No protocol or record change.

## v0.5.2 (2026-11-18)

Spec stays 1.1; records do not change.

### Added
- Rule sets gain an optional `protect` map (`{"<tool>": {"fail": "closed" | "open"}}`), written by the console's Protect button.
- A tool protected from the console behaves as with `signafaide protect` or `protect: true`: a ruling before each call, all local checks On.
- Clients pick up console protection at start and on the 60 s rule fetch; a process's first call waits up to 300 ms for it.
- Strict decisions carry `meta.protected_by` (`code`, `checks_file`, `console`); `status`, `prove` and the verifiers say where protection comes from.

### Changed
- Console protection approves no field: `checks status` says which field to approve with `signafaide pull`.
- Breaking: a client before 0.5.2 refuses a rule set version with `protect` and protects nothing from the console. Upgrade before using Protect.

## v0.5.1 (2026-11-18)

### Changed
- `protect --yes` without a terminal saves a default Calibrating rule for every risky tool and lists each rule it saved.
- Breaking: a tool wrapped with `protect()` or `@signafaide.protect` runs every local check On and asks for a ruling, even without a checks file; with no key it is refused. `record()`-only tools are unchanged.
- Default rules from `protect --yes`: a tool that pays blocks above 1000 (with an amount field) or 5 calls a minute; delete, run, push or config tools above 5 calls a minute; send tools above 20.
- On a project an API key cannot save rules in, `protect --yes` keeps the rules locally, prints one console link per tool and exits 1.
- `protect` writes `declare_tools` / `declareTools` where it runs (before `__main__` or `main()`), and runs no git command.
- `https://signafaide.co.uk` and `https://api.signafaide.co.uk` are treated as the same hosted witness.

### Fixed
- When a proxy or network policy blocks the witness, errors and `flush` say which hosts to allow, and protected calls stop retrying.
- The TypeScript transport honours `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`.
- State files are written atomically, so concurrent first calls never read a half-written key.
- Secret check finds AWS keys joined to names with `_` or `-`; rate rules print as the console says them.

## v0.5.0 (2026-11-18)

Spec 1.1. The record envelope is unchanged.

### Added
- `signafaide protect` finds tools that pay, delete or send, writes the wrapping code and a checks file, and sets a rule for each.
- Rules have a state: On blocks, Calibrating only notes. New rules start Calibrating. Rules can list exceptions. Checks file format `signafaide-checks/2`.
- `signafaide prove` makes an auditor link or a pack; also `check`, `pull`, `start-fresh`, `rules publish`, and `login` / `logout` / `whoami`.
- `signafaide check --ci` fails when a risky tool is unprotected, with a GitHub Action in `action/` and example workflows.
- Wider checks: text normalisation, decoded hex/base64, secrets in results, more secret kinds, tool fingerprinting at every `tools/list`.
- Agent notes for AGENTS.md / CLAUDE.md, team-wide instruction files in `agents/team/`, and starter projects in `templates/`.

### Changed
- Breaking: a v0.4.0 verifier cannot check 1.1 records or packs, and a v0.4.0 SDK refuses 1.1 rule sets, so a project using 1.1 rules needs v0.5.0 on every machine. Records and packs from v0.4.0 and earlier still verify.
- A possible hidden instruction is a note (`possible_hidden_instruction`) and never blocks; callers get it through `onNote` / `on_note`, `notes(result)` and the gateway's `_meta`.
- A blocked protected call raises `SignafaideBlocked`.
- `langchain-signafaide` 0.1.2 accepts `signafaide>=0.4,<1` and checks tool descriptions and schemas.

### Fixed
- Security: sign-in, `rules publish` and `protect` never take the witness from `.env`; sign-in checks the verification address; the browser opens only a checked http(s) address, without a shell; sessions go only to their own witness and are kept in the credential store; seed phrases are matched as whole phrases with their checksum.

## v0.4.0 (2026-11-17)

Tool-call checks (spec sections 8, 10 and 11).

### Added
- Each tool call can be checked before it runs (secrets, data leaving, changed tools, known-harmful fingerprints, hidden instructions); results are signed.
- `init` and `agent setup` write a checks file in watch mode; strictness is chosen per tool, and a strict call waits for the witness's ruling.
- Signed rule sets with a shared rule language, fetched every 60 s, plus a signed shared list of harmful tool fingerprints.
- Argument values are sent only for fields listed under `disclose`; otherwise only hashes leave the machine.
- New commands: `checks status`, `checks approve`, `rules pull`, `rules show`, `rules test`; new MCP tools `signafaide_explain_ruling` and `signafaide_show_rules`.
- The gateway checks every `tools/call` and fingerprints `tools/list`; the OpenTelemetry processor writes checks in watch mode.

### Changed
- Breaking: records with `checks`, rulings or rule sets need a v0.4.0 verifier. `python-langchain` 0.1.1 needs `signafaide>=0.4.0,<0.5`.

### Fixed
- Security: witness public keys are pinned in the SDKs, and a strict call fails closed at a cold start.

## v0.3.5 (2026-11-16)

### Fixed
- OpenTelemetry: a span that arrives after its call ended (LangSmith) no longer gives a duplicate record when the tool is also wrapped.
- Python: the sampling note is also written when the first decision is written at span end.
- Tool arguments and results are also read from `gen_ai.prompt` and `gen_ai.completion` (LangSmith spans).

## v0.3.4 (2026-11-16)

Spec gains four reserved note names (§2.7).

### Added
- `SignafaideSpanProcessor` (Python `signafaide.otel`, TypeScript `signafaide/otel`) records tool-call spans as signed records with no tool wrapping.
- It reads the OpenTelemetry GenAI, OpenInference and OpenLLMetry conventions; OpenTelemetry stays an optional dependency.
- Records made from spans say so in signed data, including whether the decision was written before or after the tool ran.
- `signafaide verify` and `status` print `telemetry:` lines per agent (JSON `telemetry`), including sampling notes.
- A tool also wrapped by the SDK or behind a gateway still gives one decision and one outcome.

## v0.3.3 (2026-11-16)

### Added
- MCP tool `signafaide_records`: lists and searches local records by agent, time window or hash (metadata only).
- MCP tool `signafaide_flush`: sends waiting records now, as `signafaide flush` does.

### Changed
- Every MCP tool carries annotations (read-only, destructive, idempotent, open-world); tool descriptions are clearer.

## v0.3.2 (2026-11-15)

### Added
- `POST /v1/sandbox` and `GET /v1/project` return `expires_at` for unclaimed sandboxes (SPEC §6).
- `init`, `status`, `claim`, `verify` and the MCP tools say what claiming gives and how many days are left.
- `verify --json` includes a `sandbox` object for projects on a sandbox key.

### Changed
- After a sandbox expires, the commands say so and how to carry on; `signafaide claim` exits 1.

## v0.3.1 (2026-11-14)

- `signafaide-mcp` carries `mcpName` and `js/mcp/server.json` for the official MCP Registry.
- The Claude Code plugin gains an icon, project links and a README section on what it sends.

## v0.3.0 (2026-11-14)

Spec gains tool declarations (§2.6) and tool coverage (§7).

### Added
- `signafaide gateway`: an MCP stdio proxy that records every `tools/call`, with `--strict` / `--strict-tools` to forward only co-signed calls.
- `declare_tools` / `declareTools` declare an agent's full tool list; `wrap_tools` / `wrapTools` declare wrapped tools automatically.
- Verifiers report tool coverage per agent (JSON `coverage`); the Rust core has `signafaide_core::coverage`.

### Changed
- Automatic declarations add notes that count towards the quota; turn off with `SIGNAFAIDE_DECLARE_TOOLS=0`.

## v0.2.1 (2026-11-14)

- First release published to npm and PyPI.
- Package metadata added; no code or protocol change from v0.2.0.

## v0.2.0 (2026-11-14)

### Added
- Clean restarts: a signed stop note (`signafaide.instance_stop`) and `stop()` in both SDKs; verifiers no longer warn after one.
- `signafaide-verify --version` and `--help`.

### Changed
- Breaking: the default witness is now `https://api.signafaide.co.uk`; update the SDK if you relied on the old default.
- MCP `signafaide_init` creates nothing without `confirm_user_agreed: true` and `user_words`.
- The first refused strict call in a process prints one warning on stderr.

## v0.1.5 (2026-11-14)

- `signafaide keys create` makes a key for a secret store without writing a record.
- `SIGNAFAIDE_HEAD_FILE` and `onHead` / `on_head` keep signed heads outside ephemeral containers.
- A new instance continuing a chain it does not hold writes a signed `signafaide.instance_start` note.
- Fixed a spurious "no answer within 10 s" line at exit.

## v0.1.4 (2026-11-14)

- An empty `SIGNAFAIDE_HOME` with a known project continues after the witness's head.
- A new agent's chain starts at seq 1, so `signafaide flush` right after `init` ships.
- Verifiers use one word, pending, for co-signed records awaiting their public timestamp.

## v0.1.3 (2026-11-14)

- Pack format addition: packs name their project, signed in the export statement.
- Verify reports pending separately; refused chains show as BLOCKED, and `signafaide repair` continues them.
- Background sender keeps one request in flight with backoff; records keep monotonic time.
- The MCP server moved to its own package, `signafaide-mcp`.

## v0.1.2 (2026-11-13)

- Breaking record format: content hashes are salted; records from v0.1.0 and v0.1.1 do not verify with this version or later.
- The result line says how many of the 12 checks passed.

## v0.1.1 (2026-11-13)

- A key rotated while a process runs is registered without a restart.
- `init` shows the Terms and Privacy links; the docs say exactly what is sent.

## v0.1.0 (2026-11-13)

- First version: protocol spec with test vectors, Rust core and verifier (also WebAssembly), Python and TypeScript SDKs and CLI, MCP server, `agent setup`.
