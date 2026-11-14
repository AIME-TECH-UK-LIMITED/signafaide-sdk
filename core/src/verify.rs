//! The §7 verification-pack verifier. Pure: no I/O, so it also runs in a browser (wasm32).

use crate::bitcoin::{check_header, BlockHeader};
use crate::coverage::{coverage, coverage_lines, Coverage};
use crate::drand::{check_round_time, verify_beacon, BeaconCheck};
use crate::merkle::verify_path;
use crate::model::*;
use crate::ots::{DetachedFile, OtsStatus};
use crate::sign::{self, Domain};
use crate::{plural, time, Error, Hash, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The twelve check groups, in §7 order: (id, title).
pub const CHECKS: [(&str, &str); 12] = [
    ("schema", "Envelope schema"),
    ("record_hash", "Record hashes"),
    ("record_sig", "Client signatures"),
    ("chain", "Agent chains"),
    ("merkle", "Merkle proofs"),
    ("batch_sig", "Batch hashes and signatures"),
    ("batch_chain", "Batch chain"),
    ("head_sig", "Signed heads"),
    ("drand", "drand rounds"),
    ("anchor", "Anchors"),
    ("ots", "OpenTimestamps"),
    ("content", "Content hashes"),
];

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    NotChecked,
    /// Ran, found nothing wrong, and waits for something that has not happened yet: an anchor or
    /// a public timestamp that is not confirmed yet (§7). Never counted as passed.
    Pending,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub item: String,
    pub message: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Check {
    pub n: usize,
    pub id: &'static str,
    pub title: &'static str,
    pub status: Status,
    /// How many items (records, batches, heads, rounds, anchors) were examined.
    pub checked: usize,
    pub detail: String,
    /// Check-specific result, e.g. `pending` or `confirmed@812345` for OTS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub failures: Vec<Failure>,
}

/// The one definition of "pending" (§7), printed under the checks whenever one is pending.
pub const PENDING_MEANS: &str =
    "pending: co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms within a few hours); never counted as passed";

/// Whether the keys came from a source independent of the pack.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Independent {
    pub service_keys: bool,
    pub agent_keys: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Report {
    /// `PASS` or `FAIL`.
    pub result: &'static str,
    /// The final line of the text output (§7): the result, why keys are not independent, and
    /// what the pack covers.
    pub result_line: String,
    pub project: Option<String>,
    /// The project's name from the signed export statement, when the pack has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    pub env: Option<Env>,
    pub records: usize,
    /// When the service made the pack (the signed export statement).
    pub generated: Option<String>,
    /// The export's filter (the signed export statement).
    pub filter: Option<PackFilter>,
    pub warnings: Vec<String>,
    pub independent: Independent,
    pub checks: Vec<Check>,
    /// Tool coverage per agent (§7): the agent's current tool declaration and the recorded tools
    /// it does not list. A note, never a failure.
    pub coverage: BTreeMap<String, Coverage>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.result == "PASS"
    }

    pub fn check(&self, id: &str) -> &Check {
        self.checks.iter().find(|c| c.id == id).expect("known check id")
    }

    /// The lowest-numbered failing check, if any.
    pub fn first_failed(&self) -> Option<&'static str> {
        self.checks.iter().find(|c| c.status == Status::Fail).map(|c| c.id)
    }

    /// Human-readable output: one line per check group, then `PASS` or `FAIL`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        if let (Some(p), Some(e)) = (&self.project, self.env) {
            match &self.project_name {
                Some(n) => out += &format!("signafAIde pack of project {n} ({p}, {}), {}\n", e.as_str(), plural(self.records as u64, "record", "records")),
                None => out += &format!("signafAIde pack {p} ({}), {}\n", e.as_str(), plural(self.records as u64, "record", "records")),
            }
        }
        for w in &self.warnings {
            out += &format!("WARNING: {w}\n");
        }
        for c in &self.checks {
            let status = match (c.status, &c.value) {
                (Status::Fail, _) => "FAIL".to_string(),
                (Status::NotChecked, _) => "NOT CHECKED".to_string(),
                (Status::Pending, _) => "PENDING".to_string(),
                (Status::Pass, Some(v)) if v.starts_with("confirmed@") => "CONFIRMED".to_string(),
                (Status::Pass, Some(v)) => v.to_uppercase(),
                (Status::Pass, None) => "PASS".to_string(),
            };
            out += &format!("{:>2}. {:<28} {:<12} {}\n", c.n, c.title, status, c.detail);
            for f in c.failures.iter().take(20) {
                out += &format!("      - {}: {}\n", f.item, f.message);
            }
            if c.failures.len() > 20 {
                out += &format!("      ... and {} more\n", c.failures.len() - 20);
            }
        }
        if self.checks.iter().any(|c| c.status == Status::Pending) {
            out += PENDING_MEANS;
            out.push('\n');
        }
        for line in self.coverage_lines() {
            out += &format!("coverage: {line}\n");
        }
        out += &self.result_line();
        out.push('\n');
        out
    }

    /// Tool coverage in words (§7), agent by agent: what each agent declared, then the recorded
    /// tools its declaration does not list.
    pub fn coverage_lines(&self) -> Vec<String> {
        self.coverage.iter().flat_map(|(agent, c)| coverage_lines(agent, c)).collect()
    }

    /// For example `PASS: export of every agent, all records, generated 2026-11-13T12:00:00.000Z`,
    /// or `PASS (agent keys taken from the pack, not independent): export of ...`.
    pub fn result_line(&self) -> String {
        self.result_line.clone()
    }
}

/// Where a set of keys came from, when not from an independent source (§7 result line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    Independent,
    /// Taken from the pack itself (`--trust-embedded-keys`, `--trust-embedded-agent-keys`).
    Pack,
    /// Fetched over plain http from a local address.
    PlainHttp,
}

/// The reasons the keys were not independent, in result-line wording.
fn key_reasons(service: KeySource, agent: KeySource) -> Option<String> {
    let how = |s: KeySource| match s {
        KeySource::Independent => None,
        KeySource::Pack => Some("taken from the pack"),
        KeySource::PlainHttp => Some("fetched over plain http"),
    };
    match (how(service), how(agent)) {
        (None, None) => None,
        (Some(a), Some(b)) if a == b => Some(format!("service keys and agent keys {a}")),
        (Some(a), Some(b)) => Some(format!("service keys {a} and agent keys {b}")),
        (Some(a), None) => Some(format!("service keys {a}")),
        (None, Some(b)) => Some(format!("agent keys {b}")),
    }
}

/// What a pack covers, for the result line: `export of every agent, all records, generated <t>`.
pub fn scope_text(filter: &PackFilter, generated: &str) -> String {
    let agents = match &filter.agents {
        None => "every agent".to_string(),
        Some(a) if a.len() == 1 => format!("agent {}", a[0]),
        Some(a) => format!("agents {}", a.join(", ")),
    };
    let window = match (&filter.from, &filter.to) {
        (None, None) => "all records".to_string(),
        (Some(f), None) => format!("records from {f}"),
        (None, Some(t)) => format!("records before {t}"),
        (Some(f), Some(t)) => format!("records from {f} before {t}"),
    };
    format!("export of {agents}, {window}, generated {generated}")
}

/// The short name of a check in the result line (§7).
pub fn check_short_name(id: &str) -> &'static str {
    match id {
        "schema" => "envelope schema",
        "record_hash" => "record hashes",
        "record_sig" => "client signatures",
        "chain" => "agent chains",
        "merkle" => "Merkle proofs",
        "batch_sig" => "batch signatures",
        "batch_chain" => "batch chain",
        "head_sig" => "signed heads",
        "drand" => "drand rounds",
        "anchor" => "anchors",
        "ots" => "public timestamp",
        "content" => "content hashes",
        _ => "unknown check",
    }
}

/// How many checks passed, failed, are pending and were not checked (§7 result line): `12 of 12
/// checks passed`, `11 of 12 checks passed, 1 pending (public timestamp)`, `10 of 12 checks
/// passed, 2 not checked (public timestamp, content hashes)`, or `1 of 12 checks failed (record
/// hashes), 9 passed, 1 pending, 1 not checked`.
pub fn counts_text(checks: &[(&str, Status)]) -> String {
    let total = checks.len();
    let names = |st: Status| checks.iter().filter(|c| c.1 == st).map(|c| check_short_name(c.0)).collect::<Vec<_>>();
    let (failed, pending, unchecked) = (names(Status::Fail), names(Status::Pending), names(Status::NotChecked));
    let passed = total - failed.len() - pending.len() - unchecked.len();
    if failed.is_empty() {
        let mut out = format!("{passed} of {total} checks passed");
        if !pending.is_empty() {
            out += &format!(", {} pending ({})", pending.len(), pending.join(", "));
        }
        if !unchecked.is_empty() {
            out += &format!(", {} not checked ({})", unchecked.len(), unchecked.join(", "));
        }
        out
    } else {
        let mut out = format!("{} of {total} checks failed ({})", failed.len(), failed.join(", "));
        if passed > 0 {
            out += &format!(", {passed} passed");
        }
        if !pending.is_empty() {
            out += &format!(", {} pending", pending.len());
        }
        if !unchecked.is_empty() {
            out += &format!(", {} not checked", unchecked.len());
        }
        out
    }
}

/// The final line of the text output (shared wording for every verifier): `PASS` or `FAIL`; on
/// PASS, why keys were not independent; then how many checks ran (`counts`), and what the pack
/// covers, when known. For example `PASS: 10 of 12 checks passed, 2 not checked (public
/// timestamp, content hashes); export of every agent, all records, generated <t>`.
pub fn result_line(result: &str, service: KeySource, agent: KeySource, by_service: bool, counts: &str, scope: Option<&str>) -> String {
    let mut out = result.to_string();
    if result == "PASS" {
        if by_service {
            out += " (checked by the service with its own key registry; not independent)";
        } else if let Some(r) = key_reasons(service, agent) {
            out += &format!(" ({r}, not independent)");
        }
    }
    out += &format!(": {counts}");
    if let Some(s) = scope {
        out += &format!("; {s}");
    }
    out
}

/// Why a pack without records fails (§7): an empty pack proves nothing.
pub const NO_RECORDS: &str = "no records: an empty pack proves nothing";
/// Check 3 without independent agent keys (§7).
pub const NOT_INDEPENDENT: &str =
    "NOT INDEPENDENT: agent keys came from the pack; pass --agent-keys <file|url> (the customer's `signafaide keys export`), or --trust-embedded-agent-keys";
/// A record's `time` may be at most this far after its batch's `server_time` (§2.2, §7).
pub const MAX_CLOCK_SKEW_MS: i64 = 300_000;
/// A batch is anchored within this time of its `server_time` (§4); an older batch that no anchor
/// in the pack covers is reported as not timestamped.
pub const ANCHOR_WINDOW_MS: i64 = 7_200_000;

/// A record's content held locally (`--content`), with its salt when the file has one.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalContent {
    pub content: Value,
    pub salt: Option<String>,
}

/// Bitcoin block headers for check 11, fetched by the caller (this crate does no I/O).
#[derive(Clone, Debug, Default)]
pub enum Bitcoin {
    /// Not looked up: a Bitcoin attestation is reported NOT CHECKED.
    #[default]
    Offline,
    /// Height -> the block hash and raw header an explorer gave, or why they could not be fetched.
    Checked(BTreeMap<u64, std::result::Result<BlockHeader, String>>),
}

/// Verifier inputs besides the pack.
#[derive(Default, Clone)]
pub struct Options {
    /// Service keys from a source independent of the pack (`--keys`).
    pub service_keys: Option<Vec<KeyEntry>>,
    /// Use the keys embedded in the pack when `service_keys` is `None` (warned about).
    pub trust_embedded_keys: bool,
    /// The customer's agent keys, independent of the pack (`--agent-keys`, §2.5).
    pub agent_keys: Option<Vec<AgentKeyEntry>>,
    /// Use the agent keys embedded in the pack when `agent_keys` is `None` (warned about).
    pub trust_embedded_agent_keys: bool,
    /// The client's newest signed heads (`--head`, §8 head.json).
    pub heads: Option<Vec<SignedHead>>,
    pub bitcoin: Bitcoin,
    /// Locally held content and its salt (§2.1), by `record_hash`.
    pub contents: HashMap<Hash, LocalContent>,
    /// `service_keys` were fetched over plain http from a local address: warned, not independent.
    pub service_keys_plain_http: bool,
    /// `agent_keys` were fetched over plain http from a local address: warned, not independent.
    pub agent_keys_plain_http: bool,
    /// The service checks a pack it built with its own key registry (`service_keys`, and the agent
    /// keys inside the pack): never independent, and the result line says so.
    pub by_service: bool,
}

#[derive(Default)]
struct Acc {
    checked: usize,
    failures: Vec<Failure>,
    notes: Vec<String>,
    not_checked: bool,
    pending: bool,
    value: Option<String>,
}

impl Acc {
    fn fail(&mut self, item: impl Into<String>, message: impl std::fmt::Display) {
        self.failures.push(Failure { item: item.into(), message: message.to_string() });
    }
}

struct Rec {
    label: String,
    r: PackRecord,
    hash: Hash,
}

/// The service keys a verification uses.
struct Keys<'a>(&'a [KeyEntry]);

impl Keys<'_> {
    fn active(&self, key_id: &str, at: &str) -> Result<&KeyEntry> {
        let k = self.0.iter().find(|k| k.key_id == key_id).ok_or_else(|| Error::new(format!("unknown service key {key_id}")))?;
        if !key_active(&k.valid_from, k.valid_to.as_deref(), time::parse(at)?) {
            return Err(Error::new(format!("service key {key_id} was not active at {at}")));
        }
        Ok(k)
    }

    /// Any key active at `at` verifies `sig`.
    fn any(&self, domain: Domain, hash: &Hash, sig: &str, at: &str) -> bool {
        let Ok(at) = time::parse(at) else { return false };
        self.0.iter().any(|k| key_active(&k.valid_from, k.valid_to.as_deref(), at) && sign::verify(&k.public_key, domain, hash, sig).is_ok())
    }
}

/// What one anchor's OTS proof shows (check 11).
enum Ots {
    Pending,
    Confirmed(u64),
    /// Claims this lowest block height; the header could not be checked, and why.
    Unchecked(u64, String),
}

/// Verify a pack. `Err` only when no service keys were supplied and embedded keys are not
/// trusted; every problem with the pack itself is reported as a failing check.
pub fn verify_pack(pack_json: &Value, opts: &Options) -> Result<Report> {
    let mut acc: Vec<Acc> = (0..CHECKS.len()).map(|_| Acc::default()).collect();
    let mut service_src = if opts.service_keys.is_none() {
        KeySource::Pack
    } else if opts.service_keys_plain_http {
        KeySource::PlainHttp
    } else {
        KeySource::Independent
    };
    let mut agent_src = if opts.agent_keys.is_none() {
        KeySource::Pack
    } else if opts.agent_keys_plain_http {
        KeySource::PlainHttp
    } else {
        KeySource::Independent
    };
    if opts.by_service {
        (service_src, agent_src) = (KeySource::Pack, KeySource::Pack);
    }
    let independent = Independent { service_keys: service_src == KeySource::Independent, agent_keys: agent_src == KeySource::Independent };
    let pack: Pack = match from_value::<Pack>(pack_json) {
        Ok(p) if p.format != PACK_FORMAT => return Ok(malformed(format!("format is '{}', expected '{PACK_FORMAT}'", p.format), independent)),
        Ok(p) => match p.validate() {
            Ok(()) => p,
            Err(e) => return Ok(malformed(e.0, independent)),
        },
        Err(e) => return Ok(malformed(e.0, independent)),
    };
    let mut warnings = Vec::new();
    let service_keys = match (&opts.service_keys, opts.trust_embedded_keys) {
        (Some(k), _) => k.clone(),
        (None, true) if !opts.by_service => {
            warnings.push("service keys were taken from the pack itself (--trust-embedded-keys); this does not prove the service signed it".into());
            pack.service_keys.clone()
        }
        _ => return Err(Error::new("service keys are required: pass --keys <file|url>, or --trust-embedded-keys to use the keys inside the pack")),
    };
    if service_src == KeySource::PlainHttp {
        warnings.push("service keys were fetched over plain http, which anyone on the network path can alter: not independent".into());
    }
    if agent_src == KeySource::PlainHttp {
        warnings.push("agent keys were fetched over plain http, which anyone on the network path can alter: not independent".into());
    }
    let keys = Keys(&service_keys);
    let agent_keys: Vec<AgentKey> = match (&opts.agent_keys, opts.trust_embedded_agent_keys || opts.by_service) {
        (Some(list), _) if !opts.by_service => list
            .iter()
            .map(|e| {
                // A retirement or revocation can only narrow the window: the earlier of the
                // customer's signed retirement (§2.5) and the service's record (§7) wins.
                let held = pack
                    .agent_keys
                    .iter()
                    .find(|k| k.agent == e.agent && k.key_id == e.key_id && k.public_key == e.public_key)
                    .and_then(|k| k.valid_to.clone());
                AgentKey {
                    agent: e.agent.clone(),
                    key_id: e.key_id.clone(),
                    public_key: e.public_key.clone(),
                    valid_from: e.valid_from.clone(),
                    valid_to: earliest(e.valid_to.clone(), held),
                }
            })
            .collect(),
        (_, trust) => {
            // The service's own registry (by_service) is said in the result line instead.
            if trust && !opts.by_service {
                warnings.push("agent keys were taken from the pack itself (--trust-embedded-agent-keys); this does not prove the customer's agents signed it".into());
            } else if !trust {
                acc[2].fail("agent keys", NOT_INDEPENDENT);
            }
            pack.agent_keys.clone()
        }
    };
    // The earliest any key of each agent was valid: no record of that agent is older (check 3).
    let mut first_key: BTreeMap<&str, i64> = BTreeMap::new();
    for k in &agent_keys {
        if let Ok(f) = time::parse(&k.valid_from) {
            let e = first_key.entry(k.agent.as_str()).or_insert(f);
            *e = (*e).min(f);
        }
    }
    let generated_ms = time::parse(&pack.generated).unwrap_or(i64::MAX);
    let from_ms = pack.filter.from.as_deref().map(|t| time::parse(t).unwrap_or(i64::MIN));
    let to_ms = pack.filter.to.as_deref().map(|t| time::parse(t).unwrap_or(i64::MAX));
    // A chain may start after seq 1 only when the export's `from` is after the agent's first
    // key: otherwise every record of the agent is inside the window.
    let from_cuts = |agent: &str| matches!((from_ms, first_key.get(agent)), (Some(f), Some(&k)) if f > k);
    // A head's record may be cut off by `to` only when the head's record could be at or after
    // `to`: its time is at most 300 s after the head's server_time.
    let to_may_cut = |h: &Head| to_ms.is_some_and(|t| time::parse(&h.server_time).map_or(true, |s| s + MAX_CLOCK_SKEW_MS >= t));

    // 1. schema
    if pack.records.is_empty() {
        acc[0].fail("pack", NO_RECORDS);
    }
    let mut recs: Vec<Rec> = Vec::new();
    for (i, raw) in pack.records.iter().enumerate() {
        let parsed = from_value::<PackRecord>(raw).and_then(|r| {
            r.envelope.validate()?;
            consistent(&r, &pack)?;
            Ok(r)
        });
        acc[0].checked += 1;
        match parsed.and_then(|r| Ok((r.envelope.record_hash()?, r))) {
            Ok((hash, r)) => recs.push(Rec { label: format!("{}#{}", r.envelope.agent, r.envelope.seq), r, hash }),
            Err(e) => acc[0].fail(format!("record[{i}]"), e),
        }
    }

    // 2. record_hash
    for x in &recs {
        acc[1].checked += 1;
        if x.hash != x.r.receipt.record_hash {
            acc[1].fail(&x.label, format!("envelope hashes to {}, receipt says {}", x.hash, x.r.receipt.record_hash));
        }
    }

    // 3. client signatures
    for x in &recs {
        acc[2].checked += 1;
        if let Err(e) = check_client_sig(x, &agent_keys) {
            acc[2].fail(&x.label, e);
        }
    }

    // 4. agent chains: links, gaps, time order, and time against the batch
    let mut chains: BTreeMap<&str, BTreeMap<u64, &Rec>> = BTreeMap::new();
    for x in &recs {
        let chain = chains.entry(x.r.envelope.agent.as_str()).or_default();
        match chain.get(&x.r.envelope.seq) {
            Some(other) if other.hash != x.hash => acc[3].fail(&x.label, "two different records with the same seq (fork)"),
            _ => {
                chain.insert(x.r.envelope.seq, x);
            }
        }
    }
    let mut edge = 0;
    let (mut starts, mut clean): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for (agent, chain) in &chains {
        acc[3].checked += chain.len();
        let mut prev: Option<&Rec> = None;
        for (&seq, x) in chain {
            let e = &x.r.envelope;
            match prev {
                Some(p) if p.r.envelope.seq + 1 == seq => {
                    if e.prev != Some(p.hash) {
                        acc[3].fail(&x.label, format!("prev does not equal the record_hash of seq {}", seq - 1));
                    }
                    if e.time_ms() < p.r.envelope.time_ms() {
                        acc[3].fail(&x.label, format!("time {} is earlier than the time of seq {} ({})", e.time, seq - 1, p.r.envelope.time));
                    }
                }
                Some(p) => acc[3].fail(&x.label, format!("the pack is missing seq {}..{} of agent {agent} (a gap inside the chain)", p.r.envelope.seq + 1, seq - 1)),
                None if seq > 1 && from_cuts(agent) => edge += 1,
                None if seq > 1 && from_ms.is_some() => acc[3].fail(
                    &x.label,
                    format!("the pack is missing seq 1..{} of agent {agent}; its export's from filter is not after the agent's first key, so they belong in it", seq - 1),
                ),
                None if seq > 1 => acc[3].fail(&x.label, format!("the pack is missing seq 1..{} of agent {agent} and its export declares no from filter", seq - 1)),
                None => {}
            }
            if e.kind == Kind::Note && e.name == INSTANCE_START {
                // Clean only when the record right before it is in the pack and is a stop note.
                let after_stop = matches!(prev, Some(p) if p.r.envelope.seq + 1 == seq && p.r.envelope.kind == Kind::Note && p.r.envelope.name == INSTANCE_STOP);
                let list = if after_stop { &mut clean } else { &mut starts };
                list.push(format!("{agent} after seq {}", seq - 1));
            }
            let server = &x.r.receipt.batch.server_time;
            if e.time_ms() > time::parse(server).unwrap_or(i64::MAX - MAX_CLOCK_SKEW_MS) + MAX_CLOCK_SKEW_MS {
                acc[3].fail(&x.label, format!("time {} is more than 300 s after its batch's server_time {server}", e.time));
            }
            prev = Some(x);
        }
    }
    if edge > 0 {
        acc[3].notes.push(format!("{} start after seq 1, as the export's from filter allows", plural(edge as u64, "chain", "chains")));
    }
    if !starts.is_empty() {
        acc[3].notes.push(format!("{INSTANCE_NOTE}: {}", starts.join(", ")));
    }
    if !clean.is_empty() {
        acc[3].notes.push(format!("{CLEAN_RESTART_NOTE}: {}", clean.join(", ")));
    }

    // 5. Merkle proofs
    for x in &recs {
        acc[4].checked += 1;
        let rc = &x.r.receipt;
        if !verify_path(&x.hash, rc.index, rc.batch.size, &rc.proof, &rc.batch.root) {
            acc[4].fail(&x.label, format!("proof does not lead to the root of batch {}", rc.batch.seq));
        }
    }

    // 6. batch hashes and signatures (once per distinct batch)
    let mut batches: BTreeMap<(u64, Hash), &Receipt> = BTreeMap::new();
    let mut seen_batch_sigs = BTreeSet::new();
    for x in &recs {
        let rc = &x.r.receipt;
        let computed = match rc.batch.hash() {
            Ok(h) => h,
            Err(e) => {
                acc[5].fail(format!("batch {}", rc.batch.seq), e);
                continue;
            }
        };
        if !seen_batch_sigs.insert((computed, rc.batch_hash, rc.batch_sig.clone(), rc.service_key_id.clone())) {
            continue;
        }
        acc[5].checked += 1;
        let item = format!("batch {}", rc.batch.seq);
        if computed != rc.batch_hash {
            acc[5].fail(&item, format!("batch hashes to {computed}, receipt says {}", rc.batch_hash));
        }
        if let Err(e) = keys.active(&rc.service_key_id, &rc.batch.server_time).and_then(|k| sign::verify(&k.public_key, Domain::Batch, &computed, &rc.batch_sig)) {
            acc[5].fail(&item, format!("batch_sig: {e}"));
        }
        batches.insert((rc.batch.seq, computed), rc);
    }

    // 7. batch chain: links, and server_time never going back
    let mut by_seq: BTreeMap<u64, (Hash, &Batch)> = BTreeMap::new();
    for ((seq, hash), rc) in &batches {
        acc[6].checked += 1;
        if let Some((other, _)) = by_seq.get(seq) {
            if other != hash {
                acc[6].fail(format!("batch {seq}"), "two different batches with the same seq (fork)");
            }
            continue;
        }
        by_seq.insert(*seq, (*hash, &rc.batch));
    }
    let mut batch_gaps = 0;
    let mut prev: Option<(u64, Hash, &Batch)> = None;
    for (&seq, (hash, b)) in &by_seq {
        if (seq == 1) != b.prev.is_none() {
            acc[6].fail(format!("batch {seq}"), "prev must be null exactly when seq is 1");
        }
        if let Some((ps, ph, pb)) = prev {
            if ps + 1 == seq && b.prev != Some(ph) {
                acc[6].fail(format!("batch {seq}"), format!("prev does not equal the batch_hash of batch {ps}"));
            } else if ps + 1 != seq {
                batch_gaps += 1;
            }
            if time::parse(&b.server_time).unwrap_or(0) < time::parse(&pb.server_time).unwrap_or(0) {
                acc[6].fail(format!("batch {seq}"), format!("server_time {} is earlier than the server_time of batch {ps} ({})", b.server_time, pb.server_time));
            }
        }
        prev = Some((seq, *hash, b));
    }
    if batch_gaps > 0 {
        acc[6].notes.push(format!("{} between batches held in the pack", plural(batch_gaps as u64, "gap", "gaps")));
    }

    // 8. signed heads: in receipts, the export's heads, and the client's head file
    let mut head_sigs: BTreeSet<(Hash, String)> = BTreeSet::new();
    let held = |agent: &str, seq: u64| chains.get(agent).and_then(|c| c.get(&seq)).map(|x| x.hash);
    let last_held = |agent: &str| chains.get(agent).and_then(|c| c.keys().next_back().copied()).unwrap_or(0);
    for x in &recs {
        let rc = &x.r.receipt;
        let item = format!("head {}#{}", rc.head.agent, rc.head.seq);
        let hh = match rc.head.hash() {
            Ok(h) => h,
            Err(e) => {
                acc[7].fail(&item, e);
                continue;
            }
        };
        if head_sigs.insert((hh, rc.head_sig.clone())) {
            if let Err(e) = keys.active(&rc.service_key_id, &rc.head.server_time).and_then(|k| sign::verify(&k.public_key, Domain::Head, &hh, &rc.head_sig)) {
                acc[7].fail(&item, format!("head_sig: {e}"));
            }
            if held(&rc.head.agent, rc.head.seq).is_some_and(|h| h != rc.head.record_hash) {
                acc[7].fail(&item, "head names a different record than the pack holds at that seq");
            }
        }
        if rc.head.seq < x.r.envelope.seq {
            acc[7].fail(&item, format!("head is older than record seq {} it was issued with", x.r.envelope.seq));
        }
    }
    // The service's signed export statement: project, env, generated, filter, heads, records.
    match pack.statement().and_then(|st| st.hash()) {
        Ok(h) if keys.any(Domain::Export, &h, &pack.export_sig, &pack.generated) => {}
        Ok(_) => acc[7].fail(
            "export statement",
            "export_sig does not verify with any service key active at generated: the pack's filter, heads, generated time or records were changed after the service signed it",
        ),
        Err(e) => acc[7].fail("export statement", e),
    }
    let in_filter = |agent: &str| pack.filter.agents.as_ref().is_none_or(|a| a.iter().any(|x| x == agent));
    for x in &recs {
        let (e, t) = (&x.r.envelope, x.r.envelope.time_ms());
        if !in_filter(&e.agent) {
            acc[7].fail(&x.label, "the record's agent is not in the export's filter");
        } else if from_ms.is_some_and(|f| t < f) {
            acc[7].fail(&x.label, format!("time {} is before the export's from filter", e.time));
        } else if to_ms.is_some_and(|to| t >= to) {
            acc[7].fail(&x.label, format!("time {} is not before the export's to filter", e.time));
        }
    }
    let mut export_heads: BTreeMap<&str, &Head> = BTreeMap::new();
    for sh in &pack.heads {
        let h = &sh.head;
        let item = format!("export head {}#{}", h.agent, h.seq);
        if h.project != pack.project || h.env != pack.env {
            acc[7].fail(&item, "the export head belongs to another project or env");
            continue;
        }
        let Ok(hh) = h.hash() else {
            acc[7].fail(&item, "the export head cannot be hashed");
            continue;
        };
        if head_sigs.insert((hh, sh.head_sig.clone())) && !keys.any(Domain::Head, &hh, &sh.head_sig, &h.server_time) {
            acc[7].fail(&item, "head_sig does not verify with any service key active at its server_time");
        }
        if time::parse(&h.server_time).map_or(true, |s| s > generated_ms) {
            acc[7].fail(&item, format!("the export head's server_time {} is after the pack was generated ({})", h.server_time, pack.generated));
        }
        if !in_filter(&h.agent) {
            acc[7].fail(&item, "the export head is for an agent outside the export's filter");
        }
        if held(&h.agent, h.seq).is_some_and(|x| x != h.record_hash) {
            acc[7].fail(&item, "the export head names a different record than the pack holds at that seq");
        }
        if export_heads.insert(&h.agent, h).is_some() {
            acc[7].fail(&item, "two export heads for the same agent");
        }
    }
    for agent in chains.keys() {
        let have = last_held(agent);
        match export_heads.get(agent) {
            None => acc[7].fail(format!("agent {agent}"), "the pack has no export head for this agent, so records cut off at the end cannot be detected"),
            Some(h) if have > h.seq => {
                acc[7].fail(format!("export head {agent}#{}", h.seq), format!("the pack holds seq {have}, beyond the export head seq {}", h.seq))
            }
            Some(h) if have < h.seq && !to_may_cut(h) => acc[7].fail(
                format!("export head {agent}#{}", h.seq),
                format!("the pack ends at seq {have} but the service's head at export was seq {} (records missing at the end)", h.seq),
            ),
            _ => {}
        }
    }
    for (agent, h) in &export_heads {
        if !chains.contains_key(agent) {
            acc[7].fail(format!("export head {agent}#{}", h.seq), "the pack holds none of this agent's records, but the export names its head");
        }
    }
    let mut newer = 0;
    for sh in opts.heads.iter().flatten().filter(|sh| sh.head.project == pack.project && sh.head.env == pack.env) {
        let h = &sh.head;
        if !in_filter(&h.agent) {
            continue;
        }
        let item = format!("head file {}#{}", h.agent, h.seq);
        let Ok(hh) = h.hash() else {
            acc[7].fail(&item, "the client's head cannot be hashed");
            continue;
        };
        if head_sigs.insert((hh, sh.head_sig.clone())) && !keys.any(Domain::Head, &hh, &sh.head_sig, &h.server_time) {
            acc[7].fail(&item, "head_sig does not verify with any service key active at its server_time");
        }
        if held(&h.agent, h.seq).is_some_and(|x| x != h.record_hash) {
            acc[7].fail(&item, "the client's head names a different record than the pack holds at that seq");
        }
        if time::parse(&h.server_time).map_or(true, |s| s > generated_ms) {
            newer += 1;
            continue;
        }
        let have = last_held(&h.agent);
        // Records of this agent must reach the client's head when the agent has records in the
        // pack (time never goes back along a chain), or when the window holds all its records.
        let applies = (have > 0 || !from_cuts(&h.agent)) && !to_may_cut(h);
        if applies && have < h.seq {
            acc[7].fail(&item, format!("the client's head is seq {} but the pack ends at seq {have} (records missing at the end)", h.seq));
        }
    }
    if newer > 0 {
        acc[7].notes.push(format!("{} newer than the export, not applied", plural(newer as u64, "client head", "client heads")));
    }
    acc[7].checked = head_sigs.len();

    // 9. drand: the round's signature, and server_time against the round's time
    let mut nulls = 0;
    let mut rounds: BTreeMap<(u64, String), BeaconCheck> = BTreeMap::new();
    for rc in batches.values() {
        match &rc.batch.drand {
            None => nulls += 1,
            Some(d) => {
                let item = format!("batch {} round {}", rc.batch.seq, d.round);
                if let Err(e) = check_round_time(time::parse(&rc.batch.server_time).unwrap_or(0), d.round) {
                    acc[8].fail(&item, e);
                }
                if let std::collections::btree_map::Entry::Vacant(slot) = rounds.entry((d.round, d.signature.clone())) {
                    let r = verify_beacon(d);
                    if let BeaconCheck::Invalid(e) = &r {
                        acc[8].fail(&item, e);
                    }
                    slot.insert(r);
                }
            }
        }
    }
    acc[8].checked = rounds.len();
    if nulls > 0 {
        acc[8].notes.push(format!("{} without a drand round (beacon unreachable when written)", plural(nulls as u64, "batch", "batches")));
    }
    if rounds.is_empty() || rounds.values().any(|r| *r == BeaconCheck::NotChecked) {
        acc[8].not_checked = true;
        if !rounds.is_empty() {
            acc[8].notes.push("built without BLS support".into());
        }
    }

    // 10. anchors and 11. OTS
    let batch_times: HashMap<Hash, (u64, &str)> = batches.iter().map(|((seq, h), rc)| (*h, (*seq, rc.batch.server_time.as_str()))).collect();
    let mut anchored: BTreeSet<Hash> = BTreeSet::new();
    let mut anchors: BTreeMap<u64, (Hash, Anchor)> = BTreeMap::new();
    let mut proofs: Vec<Ots> = Vec::new();
    for (i, raw) in pack.anchors.iter().enumerate() {
        acc[9].checked += 1;
        let pa: PackAnchor = match from_value::<PackAnchor>(raw).and_then(|a| time::parse(&a.anchor.created).map(|_| a)) {
            Ok(a) => a,
            Err(e) => {
                acc[9].fail(format!("anchors[{i}]"), e);
                continue;
            }
        };
        let a = &pa.anchor;
        let item = format!("anchor {}", a.seq);
        let (Ok(ah), Ok(created)) = (a.hash(), time::parse(&a.created)) else {
            acc[9].fail(&item, "the anchor cannot be hashed");
            continue;
        };
        if !keys.any(Domain::Anchor, &ah, &pa.anchor_sig, &a.created) {
            acc[9].fail(&item, "anchor_sig does not verify with any service key active at its creation");
        }
        if service_keys_hash(&service_keys, created).ok() != Some(a.keys_hash) {
            acc[9].fail(&item, "keys_hash does not match the service keys supplied: the key list was changed after this anchor was signed");
        }
        for (bh, p) in &pa.paths {
            if verify_path(bh, p.index, a.size, &p.path, &a.root) {
                anchored.insert(*bh);
                if let Some((bseq, bt)) = batch_times.get(bh) {
                    if created < time::parse(bt).unwrap_or(i64::MIN) {
                        acc[9].fail(&item, format!("created {} is before the server_time of batch {bseq} ({bt}) it covers", a.created));
                    }
                }
            } else {
                acc[9].fail(&item, format!("path for batch {bh} does not lead to the anchor root"));
            }
        }
        match anchors.get(&a.seq) {
            Some((other, _)) if *other != ah => acc[9].fail(&item, "two different signed anchors with the same seq"),
            Some(_) => {}
            None => {
                anchors.insert(a.seq, (ah, a.clone()));
            }
        }

        acc[10].checked += 1;
        match ots_check(a, &ah, &opts.bitcoin) {
            Ok(o) => proofs.push(o),
            Err(e) => acc[10].fail(&item, e),
        }
    }
    let mut prev: Option<(u64, Hash)> = None;
    for (&seq, (h, a)) in &anchors {
        if let Some((ps, ph)) = prev {
            if ps + 1 == seq && a.prev != Some(ph) {
                acc[9].fail(format!("anchor {seq}"), format!("prev does not equal the anchor_hash of anchor {ps}"));
            }
        }
        prev = Some((seq, *h));
    }
    let (mut stale, mut young) = (0u64, 0u64);
    for ((_, h), rc) in &batches {
        if !anchored.contains(h) {
            if time::parse(&rc.batch.server_time).map_or(true, |t| t + ANCHOR_WINDOW_MS < generated_ms) {
                stale += 1;
            } else {
                young += 1;
            }
        }
    }
    if stale > 0 {
        acc[9].not_checked = true;
        acc[9].notes.push(format!("{} not timestamped: older than the 2-hour anchor window, and no anchor in the pack covers them", plural(stale, "batch", "batches")));
    }
    if pack.anchors.is_empty() && stale == 0 {
        acc[9].pending = true;
        acc[9].notes.push("no anchors in the pack yet (an anchor is made every hour)".into());
    } else if young > 0 {
        acc[9].pending = true;
        acc[9].notes.push(format!("{} not yet anchored", plural(young, "batch", "batches")));
    }
    let unchecked: Vec<(u64, &str)> = proofs.iter().filter_map(|o| if let Ots::Unchecked(h, why) = o { Some((*h, why.as_str())) } else { None }).collect();
    if proofs.is_empty() {
        // No proof yet because the batches wait for their anchor: pending, not unchecked.
        if acc[9].pending && !acc[9].not_checked {
            acc[10].pending = true;
            acc[10].notes.push("waiting for the anchor".into());
        } else {
            acc[10].not_checked = true;
        }
    } else if !unchecked.is_empty() {
        acc[10].not_checked = true;
        let blocks: Vec<String> = unchecked.iter().map(|(h, _)| h.to_string()).collect();
        acc[10].notes.push(format!("public timestamp not checked ({}); claims block {}", unchecked[0].1, blocks.join(", ")));
    } else if proofs.iter().all(|o| matches!(o, Ots::Confirmed(_))) {
        let h = proofs.iter().filter_map(|o| if let Ots::Confirmed(h) = o { Some(*h) } else { None }).max().unwrap();
        acc[10].value = Some(format!("confirmed@{h}"));
        acc[10].notes.push(format!("each public timestamp checked against its public record (block {h})"));
    } else {
        acc[10].value = Some("pending".into());
        acc[10].pending = true;
        let waiting = proofs.iter().filter(|o| matches!(o, Ots::Pending)).count();
        acc[10].notes.push(format!("waiting for the public timestamp to confirm (usually within a few hours): {waiting} of {}", proofs.len()));
    }

    // 12. content
    for x in &recs {
        let local = opts.contents.get(&x.hash);
        let (content, salt) = match (&x.r.content, &x.r.salt, local) {
            (None, None, Some(l)) => (Some(&l.content), l.salt.as_deref()),
            (c, s, _) => (c.as_ref(), s.as_deref()),
        };
        if content.is_none() && salt.is_none() {
            continue;
        }
        acc[11].checked += 1;
        match check_content(content, salt, &x.r.envelope.content_hash) {
            Ok(None) => {}
            Ok(Some(h)) => acc[11].fail(&x.label, format!("content hashes to {h}, envelope says {}", x.r.envelope.content_hash)),
            Err(e) => acc[11].fail(&x.label, e),
        }
    }
    if acc[11].checked == 0 {
        acc[11].not_checked = true;
        acc[11].notes.push("no content supplied (hash-only records)".into());
    }

    // Tool coverage (§7): a note per agent, read from the envelopes of its chain in seq order.
    let tool_coverage: BTreeMap<String, Coverage> = chains
        .iter()
        .map(|(agent, chain)| (agent.to_string(), coverage(chain.iter().map(|(&seq, x)| (seq, x.r.envelope.kind, x.r.envelope.name.as_str())))))
        .collect();

    let units = [("record", "records"), ("record", "records"), ("record", "records"), ("record", "records"), ("record", "records"), ("batch", "batches"), ("batch", "batches"), ("head", "heads"), ("round", "rounds"), ("anchor", "anchors"), ("proof", "proofs"), ("record", "records")];
    let checks: Vec<Check> = acc
        .into_iter()
        .enumerate()
        .map(|(i, a)| {
            let status = if !a.failures.is_empty() {
                Status::Fail
            } else if a.not_checked {
                Status::NotChecked
            } else if a.pending {
                Status::Pending
            } else {
                Status::Pass
            };
            let mut detail = plural(a.checked as u64, units[i].0, units[i].1);
            for n in &a.notes {
                detail += &format!("; {n}");
            }
            Check { n: i + 1, id: CHECKS[i].0, title: CHECKS[i].1, status, checked: a.checked, detail, value: a.value, failures: a.failures }
        })
        .collect();
    let ok = checks.iter().all(|c| c.status != Status::Fail);
    let result = if ok { "PASS" } else { "FAIL" };
    let scope = scope_text(&pack.filter, &pack.generated);
    let counts = counts_text(&checks.iter().map(|c| (c.id, c.status)).collect::<Vec<_>>());
    Ok(Report {
        result,
        result_line: result_line(result, service_src, agent_src, opts.by_service, &counts, Some(&scope)),
        project_name: pack.project_name.clone(),
        project: Some(pack.project),
        env: Some(pack.env),
        records: pack.records.len(),
        generated: Some(pack.generated),
        filter: Some(pack.filter),
        warnings,
        independent,
        checks,
        coverage: tool_coverage,
    })
}

/// The earlier of two optional times (protocol times sort as text).
fn earliest(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if time::parse(&b).unwrap_or(i64::MAX) < time::parse(&a).unwrap_or(i64::MAX) { b } else { a }),
        (a, b) => a.or(b),
    }
}

/// A record must belong to the pack's project and env, and its receipt to the record's agent.
fn consistent(r: &PackRecord, pack: &Pack) -> Result<()> {
    let (e, b, h) = (&r.envelope, &r.receipt.batch, &r.receipt.head);
    if e.project != pack.project || e.env != pack.env {
        return Err(Error::new("envelope belongs to another project or env"));
    }
    if b.v != 1 || b.project != pack.project || b.env != pack.env {
        return Err(Error::new("receipt batch belongs to another project or env, or has v != 1"));
    }
    if h.project != pack.project || h.env != pack.env || h.agent != e.agent {
        return Err(Error::new("receipt head belongs to another project, env or agent"));
    }
    time::parse(&b.server_time)?;
    time::parse(&h.server_time)?;
    Ok(())
}

fn check_client_sig(x: &Rec, agent_keys: &[AgentKey]) -> Result<()> {
    let e = &x.r.envelope;
    let k = agent_keys
        .iter()
        .find(|k| k.agent == e.agent && k.key_id == x.r.key_id)
        .ok_or_else(|| Error::new(format!("no key {} for agent {} in the agent keys", x.r.key_id, e.agent)))?;
    if sign::key_id(&sign::parse_public_key(&k.public_key)?) != k.key_id {
        return Err(Error::new("agent key_id does not match its public key"));
    }
    if !key_active(&k.valid_from, k.valid_to.as_deref(), e.time_ms()) {
        return Err(Error::new(format!("key {} was not active at {}", k.key_id, e.time)));
    }
    if let Some(to) = &k.valid_to {
        let server = &x.r.receipt.batch.server_time;
        if time::parse(server)? >= time::parse(to)? {
            return Err(Error::new(format!("key {} was revoked at {to}, before the service received this record at {server}", k.key_id)));
        }
    }
    sign::verify(&k.public_key, Domain::Record, &x.hash, &x.r.sig)
}

/// Check 11 for one anchor: the proof's digest (the anchor hash, §4) and status, and each
/// Bitcoin attestation against its block header when headers were supplied.
fn ots_check(a: &Anchor, anchor_hash: &Hash, bitcoin: &Bitcoin) -> Result<Ots> {
    let bytes = STANDARD.decode(&a.ots).map_err(|_| Error::new("ots is not standard base64"))?;
    let f = DetachedFile::parse(&bytes)?;
    if f.digest != anchor_hash.0 {
        return Err(Error::new("OTS proof is for a different digest than the anchor hash"));
    }
    let height = match f.timestamp.status() {
        OtsStatus::Confirmed(h) => Some(h),
        OtsStatus::Pending => None,
        OtsStatus::Empty => return Err(Error::new("OTS proof has no attestation")),
    };
    match (a.status, height, a.bitcoin_block) {
        (AnchorStatus::Confirmed, None, _) => return Err(Error::new("anchor says confirmed but the proof is still pending")),
        (AnchorStatus::Confirmed, Some(h), Some(b)) if h != b => return Err(Error::new(format!("anchor says block {b} but the proof attests block {h}"))),
        _ => {}
    }
    let Some(lowest) = height else { return Ok(Ots::Pending) };
    let attested = f.timestamp.bitcoin_attestations()?;
    let Bitcoin::Checked(headers) = bitcoin else { return Ok(Ots::Unchecked(lowest, "offline".into())) };
    // A header is trusted only when it hashes to its block and meets its own proof of work.
    let roots: BTreeMap<u64, std::result::Result<[u8; 32], String>> =
        headers.iter().map(|(h, r)| (*h, r.as_ref().map_err(Clone::clone).and_then(check_header))).collect();
    for (h, msg) in &attested {
        if let Some(Ok(root)) = roots.get(h) {
            if root != msg {
                return Err(Error::new(format!("the timestamp claims block {h}, but its Merkle root does not match that block's header")));
            }
        }
    }
    for (h, _) in &attested {
        match roots.get(h) {
            Some(Ok(_)) => {}
            Some(Err(why)) => return Ok(Ots::Unchecked(lowest, why.clone())),
            None => return Ok(Ots::Unchecked(lowest, format!("block {h} was not looked up"))),
        }
    }
    Ok(Ots::Confirmed(lowest))
}

/// The Bitcoin block heights the pack's OTS proofs claim, for the caller to look up.
pub fn bitcoin_heights(pack_json: &Value) -> Vec<u64> {
    let mut out = BTreeSet::new();
    for a in pack_json.get("anchors").and_then(Value::as_array).into_iter().flatten() {
        let Some(ots) = a.pointer("/anchor/ots").and_then(Value::as_str) else { continue };
        let Ok(bytes) = STANDARD.decode(ots) else { continue };
        if let Ok(list) = DetachedFile::parse(&bytes).and_then(|f| f.timestamp.bitcoin_attestations()) {
            out.extend(list.into_iter().map(|(h, _)| h));
        }
    }
    out.into_iter().collect()
}

/// A block header as an explorer serves it: the block hash (display hex) and the raw header (hex).
pub fn block_header_from_hex(hash: &str, header_hex: &str) -> std::result::Result<BlockHeader, String> {
    let header = hex::decode(header_hex.trim()).map_err(|_| "the block header is not hex".to_string())?;
    Ok(BlockHeader { hash: hash.trim().to_ascii_lowercase(), header })
}

/// The client's head file (§8 `head.json`): `{project: {env: {agent: {head, head_sig}}}}`.
pub fn heads_from_text(text: &str) -> Result<Vec<SignedHead>> {
    let v: Value = serde_json::from_str(text).map_err(|e| Error::new(format!("head file: {e}")))?;
    let mut out = Vec::new();
    let obj = |v: &Value, what: &str| v.as_object().cloned().ok_or_else(|| Error::new(format!("head file: {what} must be an object")));
    for (_, envs) in obj(&v, "the file")? {
        for (_, agents) in obj(&envs, "each project")? {
            for (_, sh) in obj(&agents, "each env")? {
                let sh: SignedHead = from_value(&sh).map_err(|e| Error::new(format!("head file: {e}")))?;
                time::parse(&sh.head.server_time).map_err(|e| Error::new(format!("head file: {e}")))?;
                out.push(sh);
            }
        }
    }
    Ok(out)
}

/// An agent-key manifest (§2.5, `signafaide keys export`); every entry's self-signature is checked.
pub fn agent_keys_from_text(text: &str) -> Result<Vec<AgentKeyEntry>> {
    let v: Value = serde_json::from_str(text).map_err(|e| Error::new(format!("agent keys: {e}")))?;
    let doc: AgentKeysDocument = from_value(&v).map_err(|e| Error::new(format!("agent keys: {e}")))?;
    if doc.format != AGENT_KEYS_FORMAT {
        return Err(Error::new(format!("agent keys: format is '{}', expected '{AGENT_KEYS_FORMAT}'", doc.format)));
    }
    for k in &doc.keys {
        k.validate().map_err(|e| Error::new(format!("agent keys: {e}")))?;
    }
    Ok(doc.keys)
}

fn malformed(why: String, independent: Independent) -> Report {
    let checks = CHECKS
        .iter()
        .enumerate()
        .map(|(i, (id, title))| Check {
            n: i + 1,
            id,
            title,
            status: if i == 0 { Status::Fail } else { Status::NotChecked },
            checked: 0,
            detail: if i == 0 { "the pack itself is malformed".into() } else { "pack unreadable".into() },
            value: None,
            failures: if i == 0 { vec![Failure { item: "pack".into(), message: why.clone() }] } else { vec![] },
        })
        .collect();
    Report {
        result: "FAIL",
        result_line: format!("FAIL: {}", counts_text(&CHECKS.iter().enumerate().map(|(i, c)| (c.0, if i == 0 { Status::Fail } else { Status::NotChecked })).collect::<Vec<_>>())),
        project: None,
        project_name: None,
        env: None,
        records: 0,
        generated: None,
        filter: None,
        warnings: vec![],
        independent,
        checks,
        coverage: BTreeMap::new(),
    }
}

/// Local content (`--content`): JSON lines, or a JSON array, of objects holding `envelope`,
/// `content` and `salt`, such as the SDK's `.signafaide/chain/<agent>.jsonl`. Keyed by record_hash.
pub fn contents_from_text(text: &str) -> Result<HashMap<Hash, LocalContent>> {
    let items: Vec<Value> = match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(a)) => a,
        Ok(v @ Value::Object(_)) => vec![v],
        _ => text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).map_err(|e| Error::new(format!("content line: {e}"))))
            .collect::<Result<_>>()?,
    };
    let mut out = HashMap::new();
    for item in items {
        if let (Some(env), Some(content)) = (item.get("envelope"), item.get("content")) {
            if content.is_null() {
                continue;
            }
            let e: Envelope = from_value(env)?;
            let salt = item.get("salt").and_then(Value::as_str).map(String::from);
            out.insert(e.record_hash()?, LocalContent { content: content.clone(), salt });
        }
    }
    Ok(out)
}
