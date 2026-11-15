# Changelog

Every release of the signafAIde SDK (the TypeScript and Python packages, the MCP server, the Rust
core and verifier, the Claude Code plugin and the protocol spec) has one version and one git tag.
Each fix round bumps the version, adds an entry here and is tagged; `node scripts/release-check.mjs`
fails when one of the three is missing.

The record format changed between v0.1.1 and v0.1.2 (salted content hashes) and again in v0.1.3
(packs name their project), before any public release. Records and packs written by a version
verify with that version and later ones unless an entry below says otherwise.

## v0.3.2 (2026-11-15)

The claim step says why to claim a sandbox and how long is left. No change to records, packs or the verifiers.

- `POST /v1/sandbox` and `GET /v1/project` carry `expires_at` (SPEC §6): the moment the service deletes
  an unclaimed sandbox and its records. `GET /v1/project` has it only while the sandbox is unclaimed.
  The SDKs save it in `sandbox.json`; for a sandbox made by an earlier SDK, `signafaide status` learns it
  from `GET /v1/project`. A witness that does not send it (an older or self-hosted one) gets no line
  about days: the SDKs never assume a number.
- `signafaide init`, `status`, `claim` and a passing `verify` (TypeScript and Python, the same words),
  and the MCP tools `signafaide_init`, `signafaide_claim_link` and `signafaide_status`, say with the
  claim link that claiming is free and needs no card, what it gives (the sandbox moves into your own
  organisation and stops expiring; the console, live keys and auditor links), and how long is left, for
  example "12 days left: an unclaimed sandbox and its records on the service are deleted on
  15 December 2026. Records on this machine are kept and still verify".
- `signafaide claim` still prints the link alone on its first line; the other lines follow it. Once the
  sandbox is claimed it prints `claim: done` like `status`, and nothing counts down.
- After the date: the claim link no longer works, the service deletes the sandbox within a day and then
  refuses its key (`invalid_key`). The commands say so, that local records are kept and still verify,
  and how to carry on (remove `SIGNAFAIDE_API_KEY`, run `signafaide init` again). `signafaide claim`
  then exits 1.
- `signafaide verify --json` has `sandbox: {claim_url, claimed, expires_at, days_left}` when the project
  uses a sandbox key; no prose is added to JSON output.
- `signafaide init` run again with a claimed sandbox says `claim: done` in place of a link that can no
  longer be used.

## v0.3.1 (2026-11-14)

Listing metadata only; no change to the SDKs, the verifiers or the protocol.

- `signafaide-mcp` carries `mcpName` (`uk.co.signafaide/signafaide`) and `js/mcp/server.json`, for the official MCP Registry.
- The Claude Code plugin has an icon, its homepage, repository, documentation, support, privacy and terms links, and a README section on what it sends and where.

## v0.3.0 (2026-11-14)

Recording everything an agent can call: the gateway for MCP tools, and tool declarations.

- `signafaide gateway [--agent X] [--name-prefix P] [--strict | --strict-tools a,b] [--store-content] -- <command> [args...]`
  (TypeScript CLI): an MCP stdio proxy. The agent's MCP client starts the gateway in place of the
  MCP server; the gateway runs the server, relays every JSON-RPC line unchanged in both
  directions, and writes a `decision` before each `tools/call` is forwarded and an `outcome` when
  the answer arrives (the result, a JSON-RPC error, an `isError` result, a cancellation, or the
  server exiting first). A call that cannot be recorded is not forwarded: the client gets a
  JSON-RPC error that says so. `--strict` and `--strict-tools` forward a call only once the
  witness has co-signed its decision. It ends with the server's exit code or signal, and writes
  only protocol lines to stdout. A remote (HTTP) server goes behind a stdio bridge, for example
  `signafaide gateway -- npx -y mcp-remote https://mcp.example.com/mcp`.
- Tool declarations (spec section 2.6). Three reserved `note` names say which tools an agent has
  and which of them are recorded: `signafaide.tools` starts a declaration,
  `signafaide.tool/<tool name>` is a recorded tool and `signafaide.tool_unrecorded/<tool name>`
  one that is not. Only the envelopes carry it, so it works for hash-only records. The gateway
  declares the tools of its server, from the `tools/list` answers the client was shown.
- `declare_tools(names, unrecorded=[...])` (Python) and `declareTools(names, { unrecorded: [...] })`
  (TypeScript) take the agent's full tool list: a tool is declared recorded when the SDK wrapped
  it in this process, and not recorded otherwise.
- `wrap_tools` and `wrapTools` (with the LangChain, OpenAI Agents and Vercel AI adapters) now
  declare the tools they wrap as recorded, with the first recorded call. This adds one note for
  the list and one for each tool to the agent's chain each time a process starts or the list
  changes; they are ordinary records and count towards the quota. `declare_tools=False`,
  `declareTools: false` or `SIGNAFAIDE_DECLARE_TOOLS=0` turns it off.
- The verifiers (Rust, Python, TypeScript) report tool coverage per agent, as notes that never
  fail a pack: `coverage: <agent>: all 4 declared tools are recorded` (`the 1 declared tool is recorded` for one), `... 1 declared tool is not
  recorded: web_search`, `... 2 recorded tools are not in the declared tool list: ...`, or that no
  tool list was declared. The JSON output has a `coverage` object. The Rust core has
  `signafaide_core::coverage` for the same result from envelopes alone.
- Local state: `.signafaide/tools/<agent>.json` keeps the tools each source (the application, each
  gateway) last declared, so every declaration lists the agent's whole tool list. The Python and
  TypeScript SDKs share the format. A running source refreshes its entry every hour; a source
  that ends cleanly removes its entry, and an entry not refreshed for 24 hours is dropped, with a
  new declaration when that changes the list. So a gateway that was removed does not stay in
  later declarations as recorded.
- Spec: section 2.6 (tool declarations), tool coverage in section 7, the client rules and the
  gateway in section 8, `via=gateway` in the client header. Vectors: eight new variants, a
  `tool_names` list, and `expect.coverage` and `expect.coverage_lines` on the pack and every
  variant. No existing vector changed.
- What it shows and what it does not: the gateway records every call that goes through it; a call
  the application makes around it is still not recorded, so the deployment has to make the
  gateway the only route to those tools. A declaration is the program's own signed statement of
  its tools, not proof that the list is complete.
- The skill, the plugin and the MCP server's setup steps tell a coding agent to put the gateway in
  front of the MCP servers the application's agent uses and to declare the full tool list.

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
