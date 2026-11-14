# signafAIde protocol, v1

signafAIde records decisions made by AI agents. Each record is signed by the agent and covered by a signature from the service, so neither side can forge or edit a record alone. The service attests **integrity and timing, never whether a decision was right.**

This document is the single contract for every component (Rust core, server, verifier, Python SDK, TypeScript SDK, CLI, MCP server). If code and this document disagree, the code is wrong. Change this document only on purpose, and update `vectors.json` with it.

## 1. Encoding rules

- **Canonical JSON:** RFC 8785 (JCS). Every hash below is over JCS bytes. Numbers are judged by their literal: an integer literal (no fraction, no exponent) must lie within ±(2^53−1) or the input is rejected; every other literal is read as an IEEE 754 double and written per RFC 8785 (`1e21` → `1e+21`, `1.0` → `1`, `-0` → `0`). A verifier judges literals as written, so it parses JSON with a literal-aware parser (the TypeScript SDK has one; plain `JSON.parse` would turn `1.0` into `1` and merge big integers with their neighbours). For values JavaScript code builds itself, which have no literal, the SDK rejects integer-valued numbers with 2^53 ≤ |x| < 10^21.
- **Hash:** SHA-256, written as 64 lowercase hex characters.
- **Signatures:** Ed25519 (RFC 8032). Signatures and public keys are written as base64url without padding.
- **Key id:** the first 16 hex characters of SHA-256(raw 32-byte public key).
- **Signed message:** the UTF-8 bytes of `signafaide/v1/<domain>\n`, then the 32 raw bytes of the hash being signed. The domains are `record`, `batch`, `head`, `anchor`, `register` (§2.4), `rotate` (§2.4), `agent_key` (§2.5), `export` (§7) and `draft` (§8, local only). A signature for one domain never verifies for another.
- **Time:** RFC 3339 UTC with milliseconds, for example `2026-11-13T10:00:00.000Z`, years 0001 to 9999 (year 0000 is invalid). Every time that is signed or hashed (envelopes, batches, heads, anchors, keys, packs) is written exactly so. A time a person or program passes to the HTTP API outside a record (a query parameter such as `from` and `to`, or a request field such as an auditor link's `expires_at`) is any RFC 3339 time with or without fractional seconds and with `Z` or a numeric offset (`2026-12-14T23:59:59Z`, `2026-12-14T23:59:59.5+01:00`); the service reads it as that instant and writes it back in the form above.
- **Ids:** `agent` matches `^[a-z0-9][a-z0-9._-]{0,63}$`. `project` is `prj_` followed by 26 Crockford base32 characters (a ULID). Every pattern in this document matches the whole string: a trailing newline is not allowed, and digits are ASCII `0`-`9`.

## 2. Records (written by the client)

### 2.1 Content
Content is any JSON object. It stays with the client by default (**hash-only mode**). The recommended shape:

```json
{"input": {...}, "output": {...}, "model": "...", "reason": "...", "meta": {...}}
```

`content_hash = sha256(salt || JCS(content))`

- `salt` is 16 random bytes, drawn by the client from a cryptographically secure source, new for every record. It is written as 32 lowercase hex characters; the hash input is the 16 raw bytes followed by the JCS bytes.
- The client keeps the salt with the content (§8). It sends the salt only together with stored content (§2.3); a hash-only record sends neither.
- Without the salt, nobody who sees `content_hash` (the service, or anyone holding a pack) can confirm a guess of the content by hashing candidates, even for content with few possible values such as `{"approved": true}`. Whoever holds the content and its salt can show that they match.

### 2.2 Envelope
Every field below is required, and no other field is allowed:

| field | type | rule |
|---|---|---|
| `v` | int | `1` |
| `kind` | string | `decision` (what the agent decided, written BEFORE the action runs) or `outcome` (what happened after) or `note` |
| `project` | string | the project the record belongs to (§1 ids) |
| `env` | string | `test` or `live`; with `project`, this binds the signature to one project and env, so a signed record cannot be replayed into another |
| `agent` | string | the agent's chain name |
| `seq` | int | 1, 2, 3... per (project, env, agent) |
| `prev` | hex or null | `record_hash` of seq-1; null if and only if seq = 1 |
| `time` | string | when the client wrote it. Never earlier than the `time` of seq-1 or the signing key's `valid_from`, and at most `MAX_CLOCK_SKEW` (300 s) after the service received it (§3.1 `server_time`). See "Monotonic time" below |
| `name` | string | 1 to 128 characters, the action or tool name, e.g. `approve_payout`. It is sent and stored in plain text, so it must never hold personal data |
| `content_hash` | hex | §2.1 |
| `ref` | hex or null | for `outcome`, the `record_hash` of its decision; null otherwise |

`record_hash = sha256(JCS(envelope))`

**Monotonic time.** A client never writes a chain that goes back in time. The `time` of a new record is the machine's clock, raised to the `time` of the previous record in the chain and to the `valid_from` (§2.4) of the key that signs it when the clock reads earlier, for example after an NTP step back or a resumed virtual machine: `time = max(clock, previous time, valid_from)`. When the time was raised, the client keeps the clock's own reading in the content, as `meta.wall_time` (the content's `meta` object, created if absent; a top-level `wall_time` when `meta` is not an object), so it is signed through `content_hash` and nothing is lost. `vectors.json` `time_clamp` has cases. A chain that already goes back (written by an earlier client) can never be accepted from that record on; the client reports it as BLOCKED (§8) and `signafaide repair` sets those records aside.

### 2.3 Signed record
```json
{"envelope": {...}, "key_id": "...", "sig": "<Ed25519 over domain 'record' and record_hash>", "content": {...}, "salt": "<32 hex>"}
```
`content` and `salt` are present only when the client chooses to store content with the service (`store_content`), and always together: one without the other is `invalid_record`. When they are present, the service checks `sha256(salt || JCS(content))` against `content_hash` (`content_mismatch` if it differs) and keeps the salt with the content.

### 2.4 Agent keys
Each agent has its own Ed25519 key, generated by the client. The private key never leaves the client. Keys are registered with `POST /v1/agents`. An agent may have several keys over time. A record verifies against any key of that agent that was active at the record's `time`. A key is active from its `valid_from` until its `valid_to` (null while active). A key ends in one of two ways: a developer or admin revokes it in the console (`valid_to` = that moment), or a rotation retires it (below). An ended key adds no new records, whatever time they carry; a record it signed that the service already accepted keeps its receipt when re-sent.

A registration is the object `{"project", "env", "agent", "public_key", "valid_from"}`; `registration_hash = sha256(JCS(registration))`.

- **Proof of possession:** the request carries `proof`, the new key's signature over domain `register` and `registration_hash`. Without it nobody can register a public key they do not hold, so nobody can replay another customer's signed records under their own project.
- **`valid_from`** is required. It is the key's creation time (records signed offline before registering verify), no earlier than 7 days before the registration and no later than 60 s after it.
- **Rotation:** when the agent already has an active key in that project and env, the request also carries `rotation: {"key_id", "sig"}`, a signature by one of those active keys over domain `rotate` and the same `registration_hash`. Without it the key is refused, unless a developer or admin first revokes the active key in the console. So an API key alone cannot add a key to an agent.
- **A rotation retires the key that signed it.** The service sets that key's `valid_to` to the time it received the rotation, or to 1 ms after the newest `time` among the records it accepted under that key when that is later (a client clock ahead of the service), so every record the key signed before still verifies. A retired key can no longer add records or sign a rotation.
- The answer is `{agent, key_id, retired}`: `retired` lists every ended key of the agent as `{key_id, valid_to}`, so the client can record the retirement time in its manifest (§2.5).

### 2.5 Agent-key manifest
The customer's agent public keys, independent of the service, for auditors (`signafaide keys export`, §7 `--agent-keys`):

```json
{"format": "signafaide-agent-keys/1", "keys": [{"agent", "key_id", "public_key", "valid_from", "valid_to", "sig"}]}
```

`valid_to` is null for a current key and, for a retired key, the time the service retired it (§2.4, as the registration answer said). `sig` is the key's own signature over domain `agent_key` and `sha256(JCS({"agent", "key_id", "public_key", "valid_from", "valid_to"}))`, so the retirement time is self-signed too. A verifier rejects a manifest with any entry whose self-signature, `key_id` or times do not check. The manifest lists every key the client has used for each agent, retired keys included.

## 3. Batches and receipts (written by the service)

### 3.1 Batch
The service accepts records in batches. One `POST /v1/records` call gives one batch.

```json
{"v":1,"project":"prj_...","env":"test|live","seq":12,"prev":"<batch_hash of seq-1 or null>",
 "root":"<merkle root of record_hashes>","size":3,"server_time":"...",
 "drand":{"chain":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","round":123,"randomness":"<hex>","signature":"<hex>"}}
```

- `batch_hash = sha256(JCS(batch))`
- `batch_sig` is the service's signature over domain `batch` and `batch_hash`.
- Batches form their own chain per (project, env). That chain is the service's independent copy.
- `drand` is the newest round of drand **quicknet** (period 3 s, genesis 1692803367) that the service holds. It proves the batch was not written before that round ("not before"): `server_time` is at or after the round's publication time (`1692803367 + (round − 1) × 3` s) and at most 120 s after it. A round below 1 or above 83,903,165,811 (whose publication time would be after year 9999) fails; every verifier checks the range before any arithmetic. The service drops a round that does not fit (and writes `drand: null`) rather than sign a batch that would fail. If the beacon is unreachable, `drand` is null, and the console and verifier show that.
- `server_time` never goes back along the batch chain.
- A batch holds records in request order. All of them must be valid, or the whole request is rejected.

### 3.2 Merkle tree (RFC 6962)
- Leaf: `sha256(0x00 || raw record_hash)`.
- Node: `sha256(0x01 || left || right)`.
- The tree is the RFC 6962 split: k is the largest power of two less than n.
- The root of one leaf is its leaf hash.
- An audit path is a list of hex hashes, from the leaf upward.

### 3.3 Signed head
Returned after every accepted batch, once per agent touched:

```json
{"project":"...","env":"...","agent":"...","seq":42,"record_hash":"...","server_time":"..."}
```
`head_hash = sha256(JCS(head))`. `head_sig` is the service's signature over domain `head`. Its `server_time` is the batch's `server_time`. The client keeps the newest head it was given. If the service later shows a shorter chain, that proves truncation.

### 3.4 Receipt (one per record)
```json
{"record_hash":"...","index":0,"proof":["..."],"batch":{...},"batch_hash":"...","batch_sig":"...",
 "service_key_id":"...","head":{...},"head_sig":"..."}
```

## 4. Anchors (public, "not after")
Every `ANCHOR_INTERVAL` (default 3600 s), the service builds one RFC 6962 tree over every `batch_hash` created since the last anchor, in both envs (live and the sandbox). The order is the global creation order, across all projects and envs, so there is one submission per interval whatever the number of projects.

```json
{"v":1,"seq":7,"prev":"<anchor_hash or null>","root":"...","size":40,"created":"...","keys_hash":"...",
 "ots":"<base64 of the OpenTimestamps .ots proof for root>","status":"pending|confirmed","bitcoin_block":null}
```

- `anchor_hash = sha256(JCS(anchor without ots, status, bitcoin_block))`. `anchor_sig` is the service's signature over domain `anchor`.
- The public timestamp covers `anchor_hash` (not only the root), so it fixes `keys_hash`, `created` and `prev` along with the root: the service key history is fixed by the public timestamp.
- `created` is at or after the `server_time` of every batch it covers.
- `keys_hash` commits to the service key history (§5): `sha256(JCS(list))` where the list holds every service key whose `valid_from` is at or before `created`, each as `{"key_id", "public_key", "valid_from"}`, ordered by `valid_from` then `key_id`. (`valid_to` is left out: it is set later, when a key is retired.) A later rewrite of a key's `valid_from`, or a key added with an earlier one, contradicts every anchor signed since, and the verifier fails it.
- `anchor_hash` is submitted to the public OpenTimestamps calendars; `ots` is a proof for that digest. The service upgrades the proof until it is confirmed in Bitcoin. It sets `status = confirmed` only after checking each Bitcoin attestation against the real block header at that height (§7 check 11); an upgrade it cannot check stays pending.
- A proof is at most 65,536 bytes with at most 1,024 operations and attestations in total; anything larger is invalid.
- The service publishes only `anchor_hash`, never customer data.
- Every batch is anchored within `ANCHOR_WINDOW` (2 h) of its `server_time`. A verifier reports an older batch that no anchor in the pack covers as **not timestamped** (§7 check 10).
- Each batch gets an inclusion path into its anchor: the §3.2 tree with `batch_hash` as the item, written as `{"index": <leaf index>, "path": [...]}`.
- `ots` uses the standard base64 alphabet with padding.
- Sandbox (`env=test`) batches are anchored the same way, with the same inclusion paths. Deleting an unclaimed sandbox later is fine: only the root was published.
- When a project, organization or sandbox is deleted, the service keeps, for each of its batches already in an anchor, only the `batch_hash`, its index and its inclusion path (no envelope, project or env), so the anchor's tree can still be rebuilt; other projects' proofs never need anything of it.

Together, the three give the combined claim: the drand round says "not before", the anchor says "not after", and the two signatures say "both agreed".

## 5. Service keys
`GET /.well-known/signafaide-keys.json` returns:

```json
{"keys":[{"key_id":"...","public_key":"...","valid_from":"...","valid_to":null}]}
```

Old keys stay listed for as long as any record they signed may exist.

## 6. HTTP API (JSON, `Authorization: Bearer <api key>`)

API keys are `sfa_test_<32 base62>` for the sandbox and `sfa_live_<32 base62>` for live. The prefix sets the env. Keys are stored only as hashes.

| method and path | auth | purpose |
|---|---|---|
| `POST /v1/sandbox` | none (rate-limited per IP) | creates an anonymous sandbox project: no account, email or card. Returns `{project, api_key, claim_url, free_quota, terms_url, privacy_url, notice}` (`free_quota` in records per month; `terms_url` and `privacy_url` are the service's Terms and Privacy notice, which creating a sandbox accepts, and `notice` says so in one line that clients show the person). Clients call it only on an explicit human opt-in (`signafaide init`, the MCP `signafaide_init` tool); recording never calls it (§8) |
| `GET /v1/project` | key | `{project, env, claimed, name}` of the key, so a client can sign envelopes (§2.2) before its first record is accepted; `claimed` says whether a sandbox now belongs to an organisation (its claim link can no longer be used); `name` is the project's name, which `signafaide status` shows |
| `POST /v1/agents` | key | `{name, public_key, valid_from, proof, rotation?}` (§2.4) returns `{agent, key_id, retired}`. Idempotent. A missing or wrong `proof` or `rotation` is `bad_signature`; a key already registered to another agent, or a `valid_from` out of range, is `invalid_record` |
| `POST /v1/records` | key | `{records:[signed record...]}` (at most 1000) returns `{receipts:[...], heads:[{head, head_sig}]}` |
| `GET /v1/heads/{agent}` | key | returns the current signed head `{head, head_sig}`, or `not_found` when the agent has no records (registered or not). A client whose local chain is gone (an ephemeral disk) continues after it (§8); on `not_found` (or `unknown_agent` from an older witness) the chain starts at seq 1 |
| `GET /v1/records/{record_hash}` | key | returns `{record, receipt, anchor}`: the signed record, its receipt, and `{anchor, anchor_sig, path}` (path as in §4) once anchored, else null |
| `GET /v1/export?agent=&from=&to=` | key | returns a verification pack (§7) of the key's project and env: every agent by default, only `agent` when given, records with `from <= envelope.time < to`. The pack names the filter, holds the newest signed head of each agent that has records in it, and carries the service's signed export statement (§7); all of it is read in one database snapshot. At most 50,000 records; a larger export is `bad_request` and is split with `agent`, `from` and `to` |
| `GET /v1/anchors?after=` | none | public list of anchors: `{anchors:[{anchor, anchor_sig}]}` with `seq > after`, oldest first, at most 100 |
| `GET /v1/usage` | key | `{period, used, quota, contract, plan}`: `quota` is the plan's included records for live keys (a limit only on Free) and the sandbox's for test keys. On Enterprise it is the contract's allowance (`contract: true`), or null when the contract sets none |
| `POST /v1/events` | key | `{name}` where name is `verify` or `export`: the SDK reports that the client ran one (for the service's adoption metrics). Returns 202 |
| `GET /.well-known/signafaide-keys.json` | none | §5 |
| `GET /healthz` | none | `ok` |

**Client header:** SDKs, the CLI and the MCP server send `X-Signafaide-Client: <sdk>/<version> (<language> <runtime version>; adapter=<name|none>; agent=<claude-code|codex|cursor|gemini-cli|copilot|windsurf|unknown>; via=<sdk|cli|mcp>)`, optionally with `; strict=1` when strict mode is on. The service parses it leniently and uses it only for usage metrics.

**Errors** are `{"error":{"code":"...","message":"one sentence that says how to fix it","docs":"<url>"}}`. The codes are:

| code | status | when |
|---|---|---|
| `chain_conflict` | 409 | the error object also holds the service's head for the conflicting agent: `"head":{agent, seq, record_hash}` (`seq` 0 and `record_hash` null when it has no records) |
| `bad_signature` | 400 | |
| `unknown_agent` | 400 | |
| `content_mismatch` | 400 | |
| `quota_exceeded` | 429 | the Free plan's monthly allowance (or the sandbox's) is used up; paid plans never get it for live records |
| `plan_required` | 402 | the organization's plan does not include the feature, for example `content` on live records on Free. The message names the plan and the console billing URL |
| `invalid_key` | 401 | |
| `invalid_record` | 400 | |
| `rate_limited` | 429 | |
| `not_found` | 404 | the record, agent head or route does not exist |
| `bad_request` | 400 | a query parameter or request body (other than a record) is invalid |

**Client behaviour on errors.** A client sends one request at a time per process. After a `network`, `rate_limited` or 5xx error it backs off (doubling, to at most 60 s). After an error retrying cannot fix (`quota_exceeded`, `invalid_key`, `plan_required`, `bad_signature`, `invalid_record`, `content_mismatch`, `chain_conflict`) it stops sending in the background until its configuration (API key, witness URL, agent keys) changes; an explicit `signafaide flush` always tries again. A malformed API key (§6 key format) is never sent. Outside strict mode, nothing in a recorded call waits for the network or raises because of it.

**Idempotency:** re-sending an already accepted record returns its original receipt. In a request that mixes accepted and new records, only the new ones form the new batch.

**Ingest rules** (`POST /v1/records`, `invalid_record` unless noted): `envelope.project` and `envelope.env` are the key's; `envelope.time` is at most `MAX_CLOCK_SKEW` (300 s) after the service's clock and not earlier than the previous record's `time` in that agent's chain; the key is active at `envelope.time` and not revoked at the moment the service receives the record (`bad_signature`).

## 7. Verification pack
A single JSON file:

```json
{"format":"signafaide-pack/1","generated":"...","project":"...","project_name?":"...","env":"...",
 "service_keys":[...],"agent_keys":[{"agent","key_id","public_key","valid_from","valid_to"}],
 "filter":{"agents":null,"from":null,"to":null},
 "heads":[{"head","head_sig"}],
 "records":[{"envelope","key_id","sig","content?","salt?","receipt"}],
 "anchors":[{"anchor","anchor_sig","paths":{"<batch_hash>":{"index":0,"path":["..."]}}}],
 "export_sig":"..."}
```

`project_name` is optional: the project's name as the customer named it (1 to 200 characters, no control characters). When present it is part of the export statement, so it is signed; a verifier names the project with it in its first line. `filter` is the export's filter (`agents`: null for every agent, or the agent names; `from` and `to`: null or a time). `heads` holds the newest signed head, at export time, of each agent that has records in the pack. Every key entry has a valid `valid_from` time and a `valid_to` that is null or a time; anything else makes the pack malformed.

**Export statement.** The service signs what the pack covers, so nobody who holds the pack can change it unnoticed:

```json
{"project","project_name?","env","generated","filter","heads":[<each heads[i].head, in pack order>],"records_hash":"..."}
```

`project_name` is in the statement exactly when it is in the pack. `records_hash = sha256(JCS(list))` of every record's `receipt.record_hash`, in pack order. `export_sig` is the service's signature over domain `export` and `sha256(JCS(statement))`, by a service key active at `generated`. Every export head's `server_time` is at or before `generated`.

**Inputs besides the pack.** The service keys must come from a source independent of the pack (`--keys <file|url>`). The agent keys must too (`--agent-keys <file|url>`, the customer's §2.5 manifest from `signafaide keys export`); a key's `valid_to` is the earlier of the manifest's (the customer's signed retirement) and the pack's `agent_keys` entry for the same key (the service's record of a revocation or retirement): each can only narrow the window. Keys over plain `http://` are accepted only from a loopback address (`localhost`, `127.0.0.0/8`, `::1`), with a warning, and then do not count as independent; from any other host they are refused (exit 2). Optional: `--head <file>`, the client's §8 `head.json` (the SDK CLIs use the project's own `.signafaide/head.json` by default); `--content`; `--timestamp-check <url>`, an Esplora-style explorer API that confirms public timestamps (default `https://mempool.space/api`; `https://blockstream.info/api` also works), or `--offline`. An explorer over plain `http://` is never asked: check 11 is then not checked.

The verifier checks, in order:
1. Each envelope's schema, and that it names the pack's project and env. A pack with no records fails here with `no records`: an empty pack proves nothing.
2. `record_hash`.
3. The client signature, with a key of the independent agent-key set that was active at the record's `time` and not revoked before its batch's `server_time`. Without independent agent keys this check fails with `NOT INDEPENDENT: agent keys came from the pack`, unless `--trust-embedded-agent-keys` is given.
4. The chain links (`seq`, `prev`) per agent; `time` never goes back along a chain; no record's `time` is more than 300 s after its batch's `server_time`. A gap inside a chain fails. A chain that starts after seq 1 fails unless the export declared a `from` filter that is after the earliest `valid_from` of the agent's keys (otherwise every record of the agent is inside the window).
5. The Merkle proof to the batch root.
6. `batch_hash` and `batch_sig`.
7. The batch chain, and that `server_time` never goes back along it. (A gap between batches is a note: another agent's batches are not in an agent-filtered pack.)
   A `note` named `signafaide.instance_start` or `signafaide.instance_stop` (§8) passes like any record. For each start note the verifier looks at the record right before it in the agent's chain (seq - 1):
   - When that record is in the pack and is a `note` named `signafaide.instance_stop`, the start is a **clean restart**. It adds the note `a new instance continued the chain right after the earlier instance's signed stop note (a clean restart, nothing to warn about): <agent> after seq <n>, ...` and no warning.
   - Otherwise (any other record before it, or the record before it is outside the pack because the export's `from` cut the chain there) it adds the note `a new instance continued the chain, so records an earlier instance wrote but had not sent are not known: <agent> after seq <n>, ...`, so a chain with such a start is never presented as complete without saying so.

   Each note has one entry per such record, in chain order; `<n>` is the start note's seq - 1. Only the envelopes decide this (kind, name, seq, prev), never the notes' content, so it holds for hash-only records. The local `verify` (§8) applies the same rule; for a chain that begins at the start note it uses the stop note kept in `<chain>.base.json`.
8. The export statement and the heads:
   - `export_sig` verifies with a service key active at `generated` over the statement rebuilt from the pack. Any change to `project`, `env`, `generated`, `filter`, `heads` or the records (dropped, added, reordered) fails.
   - Every record is inside the filter: its agent is in `filter.agents` (when set), and `from <= time < to` (each bound when set).
   - The head signatures, in each receipt, the export `heads`, and the `--head` file. An export or client head naming a different record at a held seq fails.
   - Each export head's `server_time` is at or before `generated`, and its agent is in the filter. Every agent with records has an export head; its records never go beyond it, and end exactly at it unless `to` is set and the head's `server_time` + 300 s is at or after `to` (its record may be after `to`). An export head whose agent has no records in the pack fails.
   - A client head (`--head`) for an agent in the filter, with `server_time` at or before `generated`, applies when the agent has records in the pack or the window holds all of the agent's records (no `from`, or `from` at or before the agent's first key), unless `to` is set and the head's `server_time` + 300 s is at or after `to`. When it applies, the agent's records must reach its seq. A client head newer than `generated` is noted, not applied.
9. The drand round: its `server_time` bounds (§3.1), and its BLS signature (quicknet) when the library is available. If BLS is not available, it reports "not checked", never "pass".
10. The anchor paths, `anchor_sig`, `keys_hash` against the supplied service keys, `created` against the covered batches' `server_time`, and the anchor chain. Two different signed anchors with the same `seq` fail. A batch whose `server_time` is more than `ANCHOR_WINDOW` (2 h) before `generated` and that no anchor in the pack covers makes the check `not checked`, with the note "not timestamped". A younger one, or a pack with no anchors and no such older batch, makes the check `pending` ("not yet anchored").
11. OTS: the proof's digest is `anchor_hash` (§4), within the size limits (§4). For each block attestation (§4), the explorer is asked for the block hash at that height (`GET /block-height/{h}`) and the raw 80-byte header (`GET /block/{hash}/header`, hex). The header is trusted only when `sha256(sha256(header))`, read as a big-endian number in display byte order, equals that block hash and is at or below the target of the header's `nBits` (compact form; a negative, zero or overflowing target is invalid). The message the proof's operations lead to must equal the header's Merkle root (bytes 36 to 68, header byte order). It reports `pending` (the check's status is `pending`, and its value `pending`) while a proof is not confirmed yet, and also when the pack has no proofs because its batches wait for their anchor (check 10 `pending`); `confirmed@block` only when every attestation was checked against a trusted header; `not checked` with the claimed block when a header could not be had or trusted (`--offline`, an `http://` explorer, a failed lookup, a header that does not hash to its block or lacks its proof of work); or fails when a trusted header's Merkle root differs. Explorer requests follow no redirects.
12. When content is supplied, either in the pack or as a local content file, `content_hash = sha256(salt || JCS(content))` (§2.1). Content without its salt, or a salt without content, fails: it cannot be matched to the hash. A local content file holds JSON lines (or a JSON array) of `{envelope, content, salt}` objects, as in §8 `chain/<project>/<env>/<agent>.jsonl`; a directory means every `*.jsonl` file below it.

Two different records (or batches) with the same `seq`, or a `prev` that does not match the item before it, fail.

**Output:** one line per check group, a final result line, and exit code 0 or 1 (2 when the inputs cannot be read). Each check is `pass`, `fail`, `pending` (it ran, found nothing wrong, and waits for something that has not happened yet: an anchor, or a public timestamp that has not confirmed) or `not_checked` (it could not run). Whenever a check is pending, the text output says what pending means in one line under the checks: `pending: co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms within a few hours); never counted as passed`. Every product surface (CLI, console, audit pack, verification report, docs) uses this one word and definition for a record with no public timestamp yet. Only `pass` counts as passed: a pending or unchecked check is never counted as passed, so the result line always says how many checks passed. A pending check does not fail the pack. It is `PASS` or `FAIL`; on `PASS`, when keys were not independent, a parenthesis says why: `(agent keys taken from the pack, not independent)`, `(service keys fetched over plain http, not independent)`, `(service keys and agent keys taken from the pack, not independent)`, or, when the service checks a pack it built with its own key registry (console replay, audit packs), `(checked by the service with its own key registry; not independent)`. Then `: ` and the counts:
- on `PASS`: `<p> of 12 checks passed`, followed, when some are pending, by `, <k> pending (<names>)`, and, when some were not checked, by `, <n> not checked (<names>)`;
- on `FAIL`: `<f> of 12 checks failed (<names>)`, then `, <p> passed`, `, <k> pending` and `, <n> not checked` when not zero.

The names, in check order, are: envelope schema, record hashes, client signatures, agent chains, Merkle proofs, batch signatures, batch chain, signed heads, drand rounds, anchors, public timestamp, content hashes. The local `verify` of a client's own state (§8), while no record has a receipt, writes `nothing co-signed yet` in place of the names of the checks that need the witness (record hashes, Merkle proofs, batch signatures, batch chain, signed heads, drand rounds, anchors, public timestamp), followed by the names of any other unchecked ones. For a readable pack, `; ` and what it covers follow, from the signed statement: `export of <every agent | agent a | agents a, b>, <all records | records from F | records before T | records from F before T>, generated <generated>`. For example `PASS: 11 of 12 checks passed, 1 pending (public timestamp); export of every agent, all records, generated 2026-11-13T12:00:00.000Z`, `PASS: 11 of 12 checks passed, 1 not checked (public timestamp); ...` (offline, a confirmed proof), or, locally, `PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)`. A pack that cannot be read at all gives `FAIL: 1 of 12 checks failed (envelope schema), 11 not checked`. With `--json`, the output is machine-readable, with `result`, `result_line`, `generated`, `filter`, `project_name` (when the pack has one) and `independent: {service_keys, agent_keys}`. The first text line names the pack: `signafAIde pack of project <project_name> (<project>, <env>), <n> records`, or `signafAIde pack <project> (<env>), <n> records` without a name.

**Local state (SDK CLIs).** The local `verify` also reports chains that cannot ship (§8 BLOCKED): one `BLOCKED <chain>: <reason>; <n> records cannot ship. Next: <step>` line each, and the result becomes `BLOCKED` (or `FAIL` when a check failed too), with `<n> chain(s) cannot ship (<chains>); ` before the counts. BLOCKED always exits 1. `--fail-on-pending-send` also fails (exit 1, result `FAIL`, `<n> records not sent yet (--fail-on-pending-send); ` before the counts) while any record has no receipt, for CI. Records set aside by `signafaide repair` (§8 `held/`) are checked for their signatures, links and content hashes, and failures count in checks 3, 4 and 12. Every verifier (Rust, Python, TypeScript) gives the same check ids, statuses and result for the same inputs.

Using the service keys embedded in the pack requires `--trust-embedded-keys`, and the output then warns that it did.

## 8. Client local state (SDKs)
The SDK keeps a `.signafaide/` folder in the project root (or `SIGNAFAIDE_HOME`). `signafaide init` and `signafaide agent setup` add it to `.gitignore`; the SDK never edits `.gitignore` while a program records, so a CI checkout stays clean. The Python and TypeScript SDKs share this layout and its formats, so either can read what the other wrote. JSON files written by the SDK are JCS unless noted.

**Local first.** Without an API key, recording works fully locally: every record is signed with the agent's key, chained and stored here, and the local `verify` checks the chain links, the signatures and the content hashes. Nothing is sent: no record, no registration, no usage event, no request for the service keys, and no sandbox is created. Sending starts only after an explicit human opt-in: `signafaide init` (creates the sandbox, §6, and prints its claim link), or setting `SIGNAFAIDE_API_KEY` (with `SIGNAFAIDE_URL` for a self-hosted witness; `SIGNAFAIDE_URL` alone sends nothing). Records written before the opt-in then ship with their original `time`s. The service accepts them when they are at most 7 days old (§2.4: a key's `valid_from` is at most 7 days before its registration); a chain whose first record is older stays local, still verifies locally, and the SDK reports it with the error code `too_old`, and that agent's new records start a new chain. Strict mode needs a receipt, so without a key a strict call fails with `no_key` and its function does not run. `SIGNAFAIDE_DISABLED=1` turns recording off: wrapped functions run and nothing is written. Test mode (`SIGNAFAIDE_TEST=1`, and on by itself under pytest, Vitest, Jest and `node --test` unless `SIGNAFAIDE_TEST=0`) writes to a temporary folder, deleted when the process ends, and sends nothing; strict calls then run without a receipt. The local `verify` says which checks need the witness: for records without a receipt, "co-signature, public timestamp: not yet", and the checks of the witness's part (record hashes against receipts, Merkle proofs, batches, heads) are `not checked`, with "nothing co-signed yet", while no record has a receipt. Local state holds no anchors: a co-signed batch younger than `ANCHOR_WINDOW` (judged at the time of the check) makes checks 10 and 11 `pending`, as in a pack; an older one makes check 10 `not checked` (verify an export to check it). A chain that continues after a witness head (`<chain>.base.json`, below) passes check 4 with the note `continues after a co-signed record this machine does not hold`, and the base head's signature counts in check 8.

**Chains.** The service chains records per (project, env, agent), so the client does too. A chain id is `<project>/<env>/<agent>`, for example `prj_01JCZQ8Z5X3V7N2M4K6H8G0F1D/live/claims-bot`. A new API key whose project the client does not know yet writes to `_pending/<key fingerprint>/<agent>`. With no API key at all, records go to `_pending/nokey/<agent>`. The key fingerprint is the first 16 hex characters of SHA-256 of the API key. The client learns a key's project from the `POST /v1/sandbox` response or from `GET /v1/project`, and checks that every receipt's `batch.project` and `batch.env` match it. Since an envelope names its project (§2.2), a record in a pending chain is a **draft**: the line is `{"draft": true, "envelope": {v, kind, agent, seq, prev, time, name, content_hash, ref}, "key_id", "sig", "content", "salt", "store_content"}`: the envelope without `project` and `env` (its `prev` is the previous draft's hash, `sha256(JCS(draft envelope))`), signed by the agent's key over domain `draft` and that hash, and with no outbox file. A draft is never sent. When the project becomes known, the client signs every draft in order (seq numbers and times kept, `prev` recomputed, a `ref` to an earlier draft rewritten to that draft's signed `record_hash`) into `<project>/<env>/<agent>.jsonl` with its outbox, and keeps the draft-to-record hash map in `<project>/<env>/<agent>.drafts.json` so an outcome written later still refers to its decision. The chain keeps its seq numbers: it is the start of that project's chain. A pending chain is never merged into a chain that already exists there; it stays pending and the SDK reports it. When the local chain file for that agent is missing but the service holds a chain for it (`GET /v1/heads/{agent}` answers a head, for example after an ephemeral disk was lost), the drafts continue after the service's head, behind an instance-start note (below): seq numbers offset by the head's `seq` + 1, and the note's `prev` is the head's `record_hash`. The client keeps that signed head in `<project>/<env>/<agent>.base.json` beside the chain (`{head, head_sig}`, plus `stop` after a clean restart, below), for the local `verify`. **Instance start.** The first record of a chain continued after such a head is a `note` named `signafaide.instance_start`, signed with the agent's key and dated like the first draft: seq = the head's `seq` + 1, `prev` = the head's `record_hash`, content `{"continues_after_seq": <head seq>, "continues_after": "<head record_hash>", "earlier_unsent": "unknown"}`; the drafts follow it (seq offset by the head's `seq` + 1). An earlier instance may have written records it never sent before its disk was lost, and nothing can show whether it did: the note makes that visible in the chain, to the verifier (§7 check 4), the console and auditors. A chain that starts at seq 1 has no such note. **Instance stop.** An instance that ends with nothing left to send says so, so that a routine restart is not read as a possible loss: after its outbox is empty and every record of the chain has a receipt, it writes a `note` named `signafaide.instance_stop` as the chain's next record, content `{"stopped_after_seq": <seq of the record before it>, "stopped_after": "<that record's record_hash>", "outbox": "empty"}`, and ships it. The SDKs do this in `stop()` (`signafaide.stop()` in Python, `stop()` in TypeScript), which a program calls in its shutdown handler, and by themselves when a program ends normally with a head file set (`SIGNAFAIDE_HEAD_FILE`; `SIGNAFAIDE_INSTANCE_STOP=1` turns it on without one, `=0` off). It is written only for agents the process wrote records for, and never while any record is unsent; when the stop note itself cannot be shipped, the witness's head stays at the record before it, and the next start counts as one with no stop. A start note whose `prev` is a stop note is a **clean restart**: the earlier instance signed that it had sent everything, and the chain shows that nothing lies between the two notes. When a new instance asks for the witness's head, it also asks for the record the head names (`GET /v1/records/{record_hash}`): when that is a stop note of the same agent, the start note's content says `"earlier_unsent": "none"` and the client keeps the stop note's `{envelope, key_id, sig}` as `stop` in `<chain>.base.json`; otherwise, or when the witness does not answer, it says `"unknown"`. The verifier never relies on that content: it decides from the chain (§7 check 4). A start with no stop note right before it (the earlier instance crashed, was killed, or could not send) keeps the warning; such starts are counted as unclean starts wherever the service sums up chains (console, auditor view, reports). The same applies when the project is already known (for example `init` learned it) but this disk has no chain file for the agent: its records are written as drafts in the pending chain until the shipper has asked for the head (`not_found`: seq 1), so writing never waits for the network. One agent name must then have one writer. Before starting a new chain, a writer first moves any pending chain for the same agent into place, so a new chain never overtakes a pending one. A new key, for example a live key replacing the sandbox key, therefore starts its own chain at seq 1 and never conflicts with the old one. The old chain stays on disk.

- `agents/<agent>.key`: the agent's private key, file mode 0600, for sandbox and draft chains; live chains use a separate key, `agents/live/<agent>.key`, so a key used while testing never signs live records. A new live key made to sign drafts (below) takes the first draft's time as `created`, so it is valid for them. A key can instead come from the environment, `SIGNAFAIDE_AGENT_KEY_<NAME>` (the agent name in capitals, every character other than a letter or digit as `_`; a live chain tries `SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>` first), or a key provider in code, holding the key file's JSON; no key file is then written. Each file is `{"agent", "key_id", "public_key", "private_key", "created"}`. `public_key` and `private_key` are base64url without padding (the 32-byte Ed25519 public key and 32-byte seed). `created` (§1 time) is sent as `valid_from` when the key is registered (§2.4), raised to 7 days before the registration when it is older, and lowered to the clock's reading when it is later (a key made while the clock was ahead registers once the clock is right). The SDK signs the registration's `proof` itself.
- `signafaide keys create --agent <a> --env test|live [--print]` makes a key for a secret store without writing a record: it generates a key, registers it (§2.4, `valid_from` = now) under the API key, which must be of that env, and prints the key file JSON on one line with `--print` (nothing is saved on the machine; the line goes into `SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>` for live, `SIGNAFAIDE_AGENT_KEY_<NAME>` for test), or saves it as the agent's key file without it. The witness refuses it (`bad_signature`) when the agent already has an active key there: `keys rotate` where that key is, or revoke it in the console first.
- `agents/retired/<agent>.<key_id>.key` (`agents/live/retired/` for live keys): keys replaced by `signafaide keys rotate`, same format, plus `"retired": "<time>"` once the service has said when it retired the key (§2.4 `retired`). When an agent's current key is registered and a retired key of that agent is active on the service, the SDK signs the `rotation` with the newest retired key. Records a retired key signed before the rotation are shipped first, before the new key is registered (registering it retires the old key). `signafaide keys export` writes the §2.5 manifest of every current and retired key, retired keys with their `valid_to`, and the local `verify` uses them.
- `chain/<project>/<env>/<agent>.jsonl` (or `chain/_pending/<fp>/<agent>.jsonl`): one JCS line per record, in seq order, written with monotonic time (§2.2). A file larger than `SIGNAFAIDE_SEGMENT_BYTES` (default 64 MiB) whose last line has a receipt rolls into `<agent>.segments/` beside it, as `<first seq>-<last seq>.jsonl` (12 digits each), sealed; readers take the segments in order, then the file. Each line is `{envelope, key_id, sig, content, salt, receipt?}`, in seq order. `salt` is the record's content salt (§2.1): without it the content can no longer be shown to match the record, so it is kept as long as the content. This is the customer's evidence store. Lines are only appended, except that `receipt` is added to the trailing lines that do not have one yet once the service returns them. That rewrite goes through a journal so a crash never loses a line. The client writes `<agent>.jsonl.tail` (first line: the byte offset where the rewritten tail starts, then the new tail lines), flushes it to disk, truncates the chain file at that offset, appends the tail and deletes the journal. A writer that finds a journal finishes it before doing anything else.
- `chain/<chain id>.lock`: a per-chain lock file (created exclusively, holding `<pid> <boot id> <monotonic seconds>`; a lock older than 10 seconds is stale and is taken over). Its age is read on the machine's monotonic clock when the boot id matches (`/proc/sys/kernel/random/boot_id`), so a wall-clock step never frees a held lock; otherwise from the file's modification time. Every write to a chain or its outbox happens under it, so several processes can record for the same agent without forking its chain.
- `outbox/<chain id>/<seq, 12 digits>.json`: the signed records not yet accepted by the service, as sent: `{envelope, key_id, sig}`, plus `content` and `salt` when the content is stored with the service. They are shipped in the background, in seq order per chain, and kept on failure (offline mode). A record leaves the outbox once its receipt is in the chain file. Only the outbox of the current API key's project is shipped; the outbox of another project waits until that project's key is used again. The delay shows as the gap between `envelope.time` and `batch.server_time`.
- `held/<project>/<env>/<agent>/<first seq>-<last seq>.jsonl`: records `signafaide repair` set aside because no witness can take them (a chain that goes back in time, a record signed by a key after it ended, a record dated ahead of the witness's clock, or a record the witness refused for good). The repair moves the chain's records from the first such record to the end (none of them has a receipt) here, flushing this file before cutting the chain file; gives the agent a new key (§2.4 rotation, unless the key comes from the environment); and appends a `note` named `signafaide.repair` to the chain, whose content holds `held` (the file), `from_seq`, `to_seq`, `records`, `records_hash` (`sha256(JCS(list))` of the held records' hashes), `code` and `reason`. Once co-signed, that note fixes the held records in time no later than the repair. Co-signed records are never moved.
- `blocked.json`: chains the witness refused for good, `{"<chain id>": {"code", "message", "at", "seq"}}` (pretty-printed JSON), cleared when the chain next ships. `signafaide status`, `verify` and `replay` show such chains, and chains found wedged on this machine, as BLOCKED with the reason and the next step, and exit 1.
- `head.json`: the newest signed head per chain, `{"<project>": {"<env>": {"<agent>": {head, head_sig}}}}` (pretty-printed JSON). A head with a lower `seq` than the one kept is not stored and is reported: it proves truncation. The local `verify` of a pack uses it as `--head` by default. Where `.signafaide/` does not outlive the process (an ephemeral container), `SIGNAFAIDE_HEAD_FILE=<path>` keeps a copy elsewhere (a persistent volume, a mounted bucket): after every accepted batch the client merges the new heads into that file, in the same format, under `<path>.lock` (§8 lock rules), keeping the higher `seq` per chain, so several processes can share one file. An `onHead` (TypeScript) or `on_head` (Python) hook receives the same heads to keep anywhere else. That file is the `head.json` an auditor is given.
- `.gitignore`: `*`, written when the folder is created, so nothing in it (the agent keys above all) is committed even before `signafaide init` edits the project's `.gitignore`.
- `config.json`: `{"agent": "<coding agent>", "projects": {"<key fingerprint>": {"project", "env"}}, "upgrade_hint"?: "<time>"}` (pretty-printed JSON; `upgrade_hint`: when the CLI last printed its one-line plan note after `verify`, at most once a week). `agent` is the coding agent detected when the project was set up (§6 client header): by `signafaide init` and `signafaide agent setup` only, never guessed per process. It is not stored when `SIGNAFAIDE_TELEMETRY=0`. `projects` maps API keys to their project. Neither holds an API key.
- `sandbox.json`: written when the SDK creates a sandbox (`signafaide init`): `{"project", "claim_url", "free_quota", "url", "created", "terms_url", "privacy_url", "claimed"?}` (`claimed`: true once `GET /v1/project` said so; the claim link is then not shown) (pretty-printed JSON), so the claim link and the Terms and Privacy notice links can be shown again. A client prints the Terms and Privacy notice links when it creates a sandbox; when the service sends none, or anything but an `http(s)` URL, it uses `<url>/legal/terms` and `<url>/legal/privacy`.
- The API key itself lives in `SIGNAFAIDE_API_KEY`, read from the environment, then from `.env` in the project root. When the SDK saves a key to `.env` (it does so only when it creates a sandbox, on `signafaide init`), it appends `SIGNAFAIDE_API_KEY=...` to `.env` (created with file mode 0600), never changes other lines, and adds `.env` to `.gitignore` the same way as `.signafaide/`, so the key is not committed. A project with no `.env` (local only, or a key set in the environment) has nothing to add. The SDK never trusts the service's values for paths or files: an API key must match `^sfa_(test|live)_[0-9A-Za-z]{32}$`, a project id §1, and an env `test` or `live`, before anything is written to `.env` or used in a path.

## 9. Free quota and sandbox (defaults, configurable)
- Sandbox: free, `SANDBOX_MONTHLY_RECORDS=5000` test records a month per sandbox project, rate-limited, anchored hourly like live data, data deleted after 30 days unless claimed.
- Live free tier: `FREE_MONTHLY_RECORDS=25000` per organisation. Hash-only records are kept with no time limit on the free tier.
- Team and Enterprise: 250,000 live records a month per organisation included, then metered overage; live records are never refused for volume. Storing `content` with live records needs Team (`plan_required` on Free); stored content is encrypted at rest and kept for one year, envelopes and hashes with no time limit. The sandbox may store content on any plan.
