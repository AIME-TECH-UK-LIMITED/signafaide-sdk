# Changelog

Every release of the signafAIde SDK (the TypeScript and Python packages, the MCP server, the Rust
core and verifier, the Claude Code plugin and the protocol spec) has one version and one git tag.
Each fix round bumps the version, adds an entry here and is tagged; `node scripts/release-check.mjs`
fails when one of the three is missing.

The record format changed between v0.1.1 and v0.1.2 (salted content hashes) and again in v0.1.3
(packs name their project), before any public release. Records and packs written by a version
verify with that version and later ones unless an entry below says otherwise.

## v0.2.1 (2026-11-14)

First release published to npm and PyPI.

- Package metadata: repository, homepage, issue tracker and keywords for `signafaide`, `signafaide-mcp` and the Python package.
- No code or protocol change from v0.2.0.

## v0.2.0 (2026-11-14)

Fix round 6.

- Clean restarts. An instance that ends with nothing left to send writes a signed stop note
  (`signafaide.instance_stop`). A new instance that continues the chain right after it is a clean
  restart: the verifiers (Rust, Python, TypeScript) report it as one and no longer warn that
  earlier unsent records are not known. A start with no stop note right before it keeps the
  warning. Spec sections 7 and 8, with three new vectors.
- `stop()` in both SDKs (`signafaide.stop()`, `await stop()`): ship everything, then write and
  ship the stop note. A program that ends by itself with `SIGNAFAIDE_HEAD_FILE` set does it at
  exit; `SIGNAFAIDE_INSTANCE_STOP=0` turns that off, `=1` turns it on without a head file.
- Strict mode: the first time a strict tool is refused in a process (for example `no_key`), one
  warning line on stderr names the tool and the fix. Agent frameworks that swallow tool errors no
  longer hide it.
- MCP `signafaide_init` creates nothing unless it is called with `confirm_user_agreed: true` and
  `user_words` (what the user wrote when they agreed). The description alone was not a gate.
- `signafaide-verify --version` and `--help` (exit 0). The release check builds the verifier and
  fails when its version or its flags differ from the source.
- The release check also fails when the version was not bumped since the last tag or this file has
  no entry for it. The Rust crates carry the same version as the packages.
- The skill covers containers without a persistent disk: `SIGNAFAIDE_HEAD_FILE`, stored content,
  and `stop()`.
- Domain: the service is on signafaide.co.uk. The default witness is now
  `https://api.signafaide.co.uk`, and every docs link, email address and example in the SDKs, the
  skill, the plugin and the READMEs uses that domain. The .com name is not ours and nothing points
  at it; the release check fails on any reference to it, in the repository or in a built package.
  A project that relied on the old default witness URL must update the SDK (the old host was never
  in service).

## v0.1.5 (2026-11-14)

Fix round 5.

- `signafaide keys create --agent <a> --env test|live [--print]`: a key for a secret store,
  registered without writing a record.
- `SIGNAFAIDE_HEAD_FILE` and the `onHead` / `on_head` hook keep the newest signed heads outside an
  ephemeral container.
- A new instance that continues a chain its disk does not hold writes a signed
  `signafaide.instance_start` note first; the verifiers name it under agent chains.
- The skill tells agents to wrap tools that move money or delete data in strict mode, and ends
  with the path to auditor evidence.
- No spurious "no answer within 10 s" line when the exit flush takes over a background request.

## v0.1.4 (2026-11-14)

Fix round 4.

- An empty `SIGNAFAIDE_HOME` with a known project (keys from a secret store) writes drafts until
  the witness's head is known, then continues after it; the signed head is kept as
  `<chain>.base.json`.
- No head for a new agent starts the chain at seq 1, so `signafaide flush` right after `init` ships.
- One word, pending, for a record that is co-signed and waits for its public timestamp, in every
  verifier and in the docs.

## v0.1.3 (2026-11-14)

Fix round 3.

- Verify reports pending apart from passed and not checked. Packs name their project, signed in
  the export statement (a pack format addition).
- Records keep monotonic time; a wall clock that stepped back goes in `meta.wall_time`.
- The background sender keeps one request in flight, backs off, and stops on a refusal that
  retrying cannot fix. The exit flush is capped.
- Chains the witness refuses show as BLOCKED with the next step; `signafaide repair` sets the
  records aside and continues the chain.
- Live agent keys from the environment or a key provider; sealed chain segments.
- The MCP server moved to its own package, `signafaide-mcp`. Python bundles the BLS check.
- `scripts/release-check.mjs` checks that the package names are claimed.

## v0.1.2 (2026-11-13)

- Record format change: `content_hash = sha256(salt || JCS(content))` with a random 16-byte salt
  per record, kept with the content. Records written by v0.1.0 and v0.1.1 do not verify with this
  version or later ones.
- The result line always says how many of the 12 checks passed, for example
  `PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`.
- The READMEs and the skill give the full verify command with `--agent-keys` and `--head`.

## v0.1.1 (2026-11-13)

- A key rotated while a process runs (`signafaide keys rotate`) is registered by that process; it
  used to be refused until a restart.
- `signafaide init` and the MCP `signafaide_init` tool show the Terms and Privacy notice links.
- The READMEs and the skill say exactly what is sent: hashes, tool name, agent name and time.

## v0.1.0 (2026-11-13)

The first version: the protocol spec with test vectors, the Rust core and the standalone verifier
(also WebAssembly), the Python and TypeScript SDKs with their CLI, the MCP server, and
`agent setup` for coding agents.
