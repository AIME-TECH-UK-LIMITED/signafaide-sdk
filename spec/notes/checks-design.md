# Tool-call checks and rulings: design note

Phase 1 of epic #58 (specification). This note says what was decided in `spec/SPEC.md` (§1, §2.2, §2.3, §2.8, §3.4, §3.5, §6, §7, §8, §9, §10, §11), why, and what was rejected. The owner's and the overseer's answers to the open questions of the first draft are listed at the end, under Decided.

Sources: our own SPEC, and public standards only: RFC 8785 (JCS), RFC 6901 (JSON Pointer), the WHATWG URL Standard (host parsing), RFC 1918, 6598, 3927, 4193 and 4291 (address ranges), JSON Schema keyword names, and the token formats the issuing services document publicly. No other project's code, specs, docs or blog posts were read.

## Decisions

### 1. Check results live in the envelope, as an optional `checks` field
The decision record's envelope gains one optional field, `checks` (§2.8). The agent signs it, the witness co-signs it, and verifiers and the service read it in hash-only mode.
- Rejected: results inside the content (`meta.checks`). Content is hash-only by default, so neither the service (console counts, rulings page) nor a verifier could see them.
- Rejected: a companion `note` record per call, as tool declarations do. It doubles the records of every checked call, and records are metered; the plan says checks add no new meter.
- Rejected: a separate agent-signed object next to the record. The witness would not co-sign it, so a client could swap it later for one that says something else.
- Cost: verifiers older than this change fail check 1 on packs whose records carry `checks`. Records without `checks` hash exactly as before, so every existing vector and pack is unchanged. Records with `checks` stay `v: 1`; the release that ships checks says in its release note that verifying such packs needs the new SDK or verifier.
- `checks` is plain text like `name`: check ids, results, rule ids, pointers, versions and hashes only, never argument values.

### 2. The ruling is its own object on the receipt, signed under a new domain `ruling`
`{v, record_hash, batch_hash, server_time, ruling, mode, enforce_ruling?, basis, matched, missing, rules, fingerprints, reason}`, signed by the batch's service key (§3.5).
- It names the co-signed record and the batch that holds it, so it is tied to an anchored batch and to the record's own signature.
- Rejected: committing rulings inside the batch hash (a Merkle root of rulings in the batch). It changes the batch format, needs a second audit path in every receipt, and breaks for agent-filtered packs. The gain (the ruling itself inside the public timestamp) is small: the client keeps the receipt it was given at decision time, the verifier fails two different rulings for one record, and a later forged ruling contradicts the client's copy, as with heads.
- Rejected: reusing the `batch` or `head` domain. One domain per signed object is the house rule (§1).
- The witness rules only on strict decisions not already blocked on the client, once per record; a re-send returns the original ruling. It evaluates only the rule set and the shared fingerprint list, never the client's secret and address checks.
- `missing` names the needed fields the client did not disclose (basis `fields_missing`), as pointers only, so the client's error can name exactly what to add to `disclose`.
- A project with no rule set gets rulings in enforce mode: a shared fingerprint match blocks, everything else is allowed. Under a rule set in watch mode the match is `allow` with `enforce_ruling: block`.
- The witness always rules with its newest published rule set version. A client cannot pick an older, weaker version. A client that held an older version and did not disclose a field the newer one needs gets `block` (`fields_missing`); a client naming a version newer than the witness holds gets `block` (`rules_version`).

### 3. Rule language
Rules: `tools` / `agents` filters, up to 16 conditions, `action` allow or block, optional `limit` on block rules. Operators: `eq ne lt le gt ge in not_in prefix suffix contains present absent type` (§10.1).
- Equality is JCS byte equality: one definition for all three languages, no float or key-order surprises.
- No regular expressions: Rust, Python and JavaScript engines differ, and patterns invite slow-match attacks. `prefix`, `suffix` and `contains` cover the common cases.
- Fields are JSON Pointers (RFC 6901): a standard, with exact escaping and array rules.
- An operator applied to a value of the wrong type is an error, and an error blocks. Otherwise an agent could step around `amount > 1000` by sending `"5000"`. Conditions short-circuit in order, so a `type` condition placed first lets an author choose the other behaviour on purpose.
- An absent field is no match and no error.
- Any block wins: errors, then block rules, then allow rules, then the default. Allow rules matter only under `default: block` (an allow list), and never override a block.
- Rate limits are counted only by the witness, over its own earlier `allow` rulings in a sliding window. A client cannot count reliably (several processes, several machines), so clients skip `limit` rules.
- Rule `tools` are exact declared names, with no wildcards, and string operators are case-sensitive, with no case-insensitive variant, in v1.
- Unknown keys, operators, actions and types make the whole document invalid, in the console, on the client and in the local checks file. Nothing loads "OK" while ignoring a key.

### 4. Rule set documents and their distribution
One rule set per project and env (test and live separate, as batch chains are), a version per publish, chained through `prev`, signed under domain `rules` (§10). The chain is the signed rule history.
- Client acceptance is ordered and named (§10.2): schema, project/env, signature, then against the held version: same set, not older, same hash for the same version, `issued` not earlier, `prev` for the next version. Gaps are allowed (no need to fetch every version).
- Clients poll every 60 s with `If-None-Match`, and fetch at once when a ruling names a newer version. New versions apply from the next call, without a restart. Offline, a client keeps the last version it verified: going offline never drops rules.

### 5. Shared fingerprint list
Numbered, hash-chained updates plus signed snapshots, each carrying `state_hash` of the whole list after it (§11.2). A client detects a sequence gap, a broken chain and a diverged state, and a new client starts from a snapshot instead of every update.
- Domain name: `fingerprints`, not `feed` as the epic's checklist proposed. Domain names in §1 name the object they sign, and the spec calls it the shared fingerprint list.
- Sandbox projects read the same live list and report into the same review queue, marked as sandbox. A report may carry the tool's description text, only when the reporter chooses; staff see it for review only, it is never shared, and it is deleted once the report is reviewed.
- Kinds: `tool` (name, description, schema), `description` (catches a malicious description reused under another name), `server` (MCP `serverInfo`). The `schema` fingerprint strips `description` and `title` keywords, so the `changed_tool` check can tell a wording change (note, re-approve) from a capability change (block until re-approved).

### 6. Field disclosure
The fields a rule set version needs are computed from it: exactly the pointers its applying rules name (§10.4). A field leaves the machine only when the developer lists it in the tool's `disclose` in the checks file; the default list is empty, so by default only fingerprints leave. A needed field not listed gives `fields_missing` (block), and the error, `signafaide checks status` and `rules test` name the exact pointers to add.
- Disclosed values are kept 30 days on every plan (`DISCLOSED_DAYS`), visible only to the project's admins, and never shared across customers or projects.
- Disclosed values are bound in the envelope by `disclosed_hash` with their own salt, never the content salt, so disclosing never lets the witness test guesses of the content.
- When content is supplied, the verifier checks the disclosed values against `content.input` (check 12): the client disclosed what the call really held.
- Without a rule set nothing is needed; only fingerprints reach the witness.

### 7. Modes, strictness and fail mode
- Two sources of mode: the checks file's `mode` for the client's own checks and local rules, and the rule set's `mode` for central rules. Watch mode never blocks: a block becomes a note with `enforce_result` (client) or an `allow` with `enforce_ruling` (witness). These record what enforce mode would have done; they are information, not a level between allow and block.
- A client never overrides a witness `block` with its local watch mode: the rule set's own mode already decided.
- Strictness is the developer's choice: a tool is strict only by code, gateway options or the checks file. The rule set cannot make a tool strict. Its `fail` map (renamed from `strict`) sets the fail mode of tools the developer has already made strict, and there it wins over the checks file. It does not bind whoever can change the project itself (Decided 26).
- Central rules never block a call that is not strict. The client still evaluates the held rule set on such a call, but always writes its entry in watch mode (a `block` becomes a note with `enforce_result`), so the developer sees what enforce mode would do on that tool. Local rules and the client's own checks follow the checks file mode as before.
- Fail mode default `closed`, which is what strict mode does today without a receipt. `open` runs the call and records `ruling: none`.
- `RULING_TIMEOUT_MS` stays 10 s; a client sets its own with the checks file's optional `ruling_timeout_ms` (1 to 60,000), so the timeout is committed with the code and the file stays strictly checked.
- The OpenTelemetry processor writes every entry in watch mode and is never strict: its tools already run.

### 8. Errors
`blocked`, `no_ruling` and `rules_unavailable` are client codes (status 0). The service never refuses a record because of a ruling: a blocked decision is accepted and co-signed as evidence. When the witness cannot rule it says so in an unsigned `ruling_error` on the receipt. The §6 service error table keeps its 11 rows (a JS test also pins that count). A client that cannot verify a rule set or list update reports the existing `bad_response`.

### 9. Verifier
- No thirteenth check: every result line in every product and vector says "of 12 checks". Ruling signatures and consistency join check 6, rule set signatures and the statement's `rule_sets` join check 8, disclosed values join check 12, `checks` schema joins check 1.
- Behaviour (blocked calls that ran anyway, strict calls without a ruling) is reported as `tool-call checks:` lines, never as a failure. The service attests integrity and timing, not whether a decision was right; a pack that shows a call ran after a block is an authentic pack showing exactly that. The console raises an alert for each call that ran after a block.
- Rule set versions are kept as long as any kept record names them, and still go into packs, so an auditor can always see the version a ruling names.
- Rulings are not re-evaluated by the verifier: rate limits depend on the witness's history across the project, which a pack does not hold.

### 10. Vectors: first in a separate file, now in `vectors.json` under `checks`
Phase 1 wrote the tool-call checks vectors to `spec/vectors-checks.json` with a throwaway generator, because `core/tests/vectors.rs::file_is_up_to_date` compares `vectors.json` to the output of the Rust generator and core code was outside that phase. Phase 3 ported the generator into `core/src/vectors.rs`: it reproduces that file's content and writes it into `vectors.json` as the object `checks`, and `vectors-checks.json` is gone.
- `checks` keeps every section of the old file. The new domains' `signatures` and `cross_domain` stay inside it, so implementations that do not know the new domains yet still read the top-level lists. `spec` and `keys_document` were dropped: the top level has the same values.
- Every signature is made by the core's own crypto and JCS. Expected values the core can compute (conditions, evaluation, rulings, rule set updates, the fingerprint list, envelopes, the verifier lines) are written by hand and recomputed by the core; the generator stops when the two disagree. The local checks (`secret`, `address`, `hidden_instruction`) run only in the clients, so their expected values are written by hand and checked by each SDK's tests.
- The secret-check vectors hold made-up tokens in real formats. So that GitHub push protection and other secret scanners never stop a push, each whole token is written as a `<format id>` placeholder and rebuilt from `checks.local_checks.tokens` (its parts and its SHA-256).

### 11. Local checks specified exactly
Tokenising with whole-token matches, a fixed entropy threshold (4.5 bits per character over at least 32 characters, a note only), WHATWG host parsing and fixed address ranges, so the Python and TypeScript SDKs (and the gateway) give the same result for the same call. Patterns use no look-around (the Rust `regex` crate has none). The issuing-service exemption needs a known destination and every destination to be an issuer: no host is exempt as such.

## Measured

Cost of the local tool-call checks of one call, from `bench/checks-bench.ts` (TypeScript) and `bench/checks_bench.py` (Python); both print a table or one JSON line (`--json`). Each row is 20,000 calls after 2,000 warm-up calls, one call at a time, microseconds.

What a call is: typical arguments (an email-like call, about 400 bytes of JSON, one URL), all five decision checks on (`secret`, `address`, `changed_tool`, `fingerprint`, `rule`), a 50-rule local rule set in the checks file, and a held shared fingerprint list. "decision" is `plan()`: everything a call costs before the tool runs, including building the `checks` of its record. "result" is the sixth check, `hidden_instruction`, on a typical result after the call. The signing and writing of the records is not included. The connected rows add a held project rule set of 50 rules (so two `rule` entries).

Machine: AMD Ryzen 7 5800X3D (8 cores, 16 threads), Linux 7.0, Node 22.22.0, Python 3.14.3; a shared workstation with other work running, each bench under a 8 GB memory cap.

| SDK | case | decision p50 | p95 | p99 | result p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| TypeScript | 50 local rules, list of 1,000 | 151 | 179 | 281 | 5.2 | 5.7 | 8.5 |
| TypeScript | 50 local + 50 held rules, list of 1,000 | 119 | 133 | 242 | 5.2 | 5.5 | 7.7 |
| TypeScript | the same, list of 20,000 | 118 | 139 | 231 | 5.2 | 5.5 | 7.6 |
| Python | 50 local rules, list of 1,000 | 387 | 413 | 500 | 37.5 | 42.5 | 51.3 |
| Python | 50 local + 50 held rules, list of 1,000 | 420 | 450 | 539 | 37.4 | 44.0 | 52.2 |
| Python | the same, list of 20,000 | 420 | 438 | 465 | 37.2 | 39.9 | 44.0 |

Every p95 is under 1 ms: 0.18 ms or less in TypeScript, 0.45 ms or less in Python. The number to publish is "well under 1 ms per call" with these figures behind it, and the machine above.

**What the first run found, and the fix.** The first measurement was over the budget by a wide margin (200 to 300 calls per row, same cases):

| SDK | case | decision p50 | p95 | p99 |
|---|---|---|---|---|
| TypeScript | 50 local rules, list of 1,000 | 1,654 | 1,821 | 1,888 |
| TypeScript | 50 local + 50 held rules, list of 1,000 | 3,609 | 3,827 | 4,025 |
| TypeScript | the same, list of 20,000 | 31,855 | 33,716 | 36,427 |
| Python | 50 local rules, list of 1,000 | 2,980 | 3,058 | 3,189 |
| Python | 50 local + 50 held rules, list of 1,000 | 6,957 | 7,369 | 7,785 |
| Python | the same, list of 20,000 | 41,694 | 43,059 | 45,354 |

The checks themselves were never the cost. Each call read and parsed the held rule set from disk and verified its signature again, read the shared list from disk, validated every entry of it and built a set of all its entries, hashed the rule set and the local rules again, and read the approvals file. Cost grew with the size of the list (about 1.5 ms per 1,000 entries in TypeScript), so a real list would have made every call slow. Both SDKs now keep what they made of each of those files until the file changes (inode, size or modification time, one `stat` per file per call; the rule set also depends on the service keys file, which is part of its key), keep the set of list entries and the hashes with the parsed copy, and read again on any change. A tampered rule set file still fails its signature at the next call, and a new version fetched by `rules pull` or the background refresh is used at the next call, as before. Tests in both SDKs cover the change and tamper cases.

Not measured: the witness round trip of a strict call (a network call, bounded by `ruling_timeout_ms`), the `address` check with `resolve: true` (a name lookup, off by default), and the first call of a process (loads the files once).

## Patent boundary check
- Rulings are `allow` or `block` only; notes are local findings that do not stop a call. Nothing delays, escalates or recommends.
- Nothing changes what an agent may do from measured outcomes or track record. Rules are written by admins; approvals are explicit; fingerprints come from reviewed reports.
- No named-signer ceilings.
- Rate limits (`limit` rules) count an agent's earlier allowed calls in a window. Decided: that is call volume under a fixed admin rule, not outcomes or track record, so it is inside the boundary.

## Out of scope for this phase
Enterprise org-wide mandatory rules, private sharing groups, and starter and industry rule sets are not specified here. They are parked to the Enterprise work. Rule suggestions are a console feature over recorded calls and need no protocol support.

## Decided
1. Strictness from the console: strictness stays a developer choice; the rule set cannot add strict tools, and its fail mode wins for tools already strict (owner). Central rules never block a non-strict call: on the client the rule set's entry for such a call is always in watch mode (overseer, from the owner's words).
2. Shared fingerprint list without a rule set: a match blocks by default (ruling `block`, mode `enforce`); under a watch-mode rule set it is `allow` with `enforce_ruling: block`; on the client the `fingerprint` check follows the checks file mode (owner).
3. Disclosure consent: each field needs an explicit local opt-in in `disclose`, default empty; a needed field not listed gives `fields_missing`, and the error, `checks status` and `rules test` name the fields to add (owner).
4. Retention of disclosed values: 30 days on every plan, visible only to the project's admins, never shared across customers or projects (owner).
5. Rule set versions past the history period: kept as long as any kept record names them, and still put in packs (overseer).
6. A call that ran after a block: stays a `tool-call checks:` report line, not a failure; the console raises an alert (overseer).
7. Rate limits and the patent boundary: a fixed admin rule on call volume, inside the boundary (overseer).
8. Enterprise org-wide rules, private sharing groups, starter and industry rule sets: out of scope for this phase, parked to the Enterprise work (overseer).
9. Rule suggestions: a console feature, no protocol support (overseer).
10. Description text on fingerprint reports: optional, sent only when the reporter chooses, staff review only, never shared, deleted once reviewed (overseer).
11. Sandbox and the shared list: sandbox projects read the live list and report into the same review queue, marked as sandbox (overseer).
12. Wildcards in rule `tools`: none in v1 (overseer).
13. Case-insensitive operators: none in v1 (overseer).
14. Witness checks: rules and fingerprints only, not the secret and address checks (overseer).
15. Protocol version: records with `checks` stay `v: 1`; older verifiers need an SDK upgrade, said in a release note (overseer).
16. Rule sets per env: one per project and env (overseer).
17. `RULING_TIMEOUT_MS`: stays 10 s, configurable per client with the checks file key `ruling_timeout_ms` (overseer).
18. The shared list's domain: stays `fingerprints` (overseer).
19. Ingest and rule set hashes: a record whose `checks.rules` names a version of the project's rule set that the service holds with a different `rules_hash` is refused as `invalid_record`; a pack holding both would fail check 8 (overseer).
20. Ingest and disclosed values: ingest checks only that the disclosed values hash to `checks.disclosed_hash`; it never compares them with stored content. Only the verifier does (check 12) (overseer).
21. Where disclosed values go: only into the key holder's own export (`GET /v1/export`). Auditor links, the console, replay and report packs leave them out (admins only, §9); `disclosed_hash` in the envelope still binds them, and check 12 skips disclosed values a pack does not carry (overseer).
22. Rule history and plans: the rule history period runs from when a newer version replaced a version. A new rule set starts in watch mode, and a later version keeps the previous version's mode unless the admin sets another. Free and Solo: one live rule set per organisation; test envs are not limited. A reviewed fingerprint report keeps its row (entry, reason, outcome, reviewer) and loses its description (overseer).
23. Strict by the checks file in TypeScript: a plain synchronous wrapped function never changes its return type, so the checks file cannot make it strict; every call fails with `state` naming the tool and the fix (make it async, or strict in code), `checks status` reports it, and a live edit that makes it strict is refused with the previous version kept in force. Framework adapters, async functions and functions strict in code wait for the ruling as before (overseer).
24. Fail mode at a cold start: with an API key and no rule set held (a first start, or the held rule set or keys file removed or no longer verifying), a strict call waits for a fetch of the rule set within its ruling timeout; with still no rule set and no ruling it fails closed whatever the checks file says. Only when the witness answered that the project has no rule set does the checks file's fail mode stand, since there is then no rule set `fail` to weaken (overseer).
25. The witness's keys: the default witness's public key set ships with the SDK and is pinned for the default URL (a new key reaches clients with a release); for any other URL the client refuses a fetched key set that keeps none of the keys it held for that URL, and keeps its keys; when the URL comes from `SIGNAFAIDE_URL` in the project's `.env`, not the code or the environment, the client says so once on stderr (overseer).
26. Trust boundary: "nothing local can weaken the fail mode" was overstated. The rule set's `fail` binds the checks file; anyone who can write the project's code, checks file, `.env` or `.signafaide/` folder is inside the boundary and can turn checks off, drop strictness or point at another witness. §8 says so. The checks file is stamped by inode, size and modification time, as the other held files (overseer).
27. Shared-list false positives: the rule set document gains an optional `fingerprint_exceptions` list (§10.1), `{kind, fingerprint, reason}` each, at most 1,000; the client's `fingerprint` check and the witness's ruling skip a shared-list match the held version excepts. The console adds one when an admin re-approves a tool the shared list stops, with the admin's reason. A per-project exception never changes the shared list or another project's rulings (overseer).
