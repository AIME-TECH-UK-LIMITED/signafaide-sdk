//! Typed protocol objects (§2 to §7). Every object rejects unknown fields and requires every
//! field, so a parsed object re-serializes to exactly the JSON it came from.

use crate::hash::hash_json;
use crate::{bail, jcs, sha256, time, Error, Hash, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Makes an `Option` field required (present, possibly `null`) instead of defaulting to `None`.
fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

/// An optional field that, when present, keeps its value, `null` included, so that a field that
/// must be absent rather than null (`checks`, §2.2) is caught by validation instead of dropped.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// Parse a JSON value into a strict protocol type.
pub fn from_value<T: DeserializeOwned>(v: &Value) -> Result<T> {
    T::deserialize(v).map_err(|e| Error::new(e.to_string()))
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Decision,
    Outcome,
    Note,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Decision => "decision",
            Kind::Outcome => "outcome",
            Kind::Note => "note",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "decision" => Some(Kind::Decision),
            "outcome" => Some(Kind::Outcome),
            "note" => Some(Kind::Note),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Env {
    Test,
    Live,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Test => "test",
            Env::Live => "live",
        }
    }

    pub fn parse(s: &str) -> Option<Env> {
        match s {
            "test" => Some(Env::Test),
            "live" => Some(Env::Live),
            _ => None,
        }
    }
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`
pub fn valid_agent_name(s: &str) -> bool {
    let b = s.as_bytes();
    let ok = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=64).contains(&b.len()) && ok(&b[0]) && b[1..].iter().all(|c| ok(c) || matches!(c, b'.' | b'_' | b'-'))
}

/// `prj_` followed by a 26-character ULID in Crockford base32.
pub fn valid_project_id(s: &str) -> bool {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    s.len() == 30
        && s.starts_with("prj_")
        && s.as_bytes()[4] <= b'7'
        && s.as_bytes()[4..].iter().all(|c| CROCKFORD.contains(c))
}

/// §2.2 record envelope.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    pub kind: Kind,
    /// The project and env the record belongs to (§2.2), so a signed record cannot be
    /// replayed into another project or env.
    pub project: String,
    pub env: Env,
    pub agent: String,
    pub seq: u64,
    #[serde(deserialize_with = "required")]
    pub prev: Option<Hash>,
    pub time: String,
    pub name: String,
    pub content_hash: Hash,
    #[serde(rename = "ref", deserialize_with = "required")]
    pub reference: Option<Hash>,
    /// What the tool-call checks of this call found (§2.8); absent (never null) when the client
    /// ran none. An envelope without it hashes exactly as before checks existed.
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub checks: Option<Value>,
}

impl Envelope {
    /// Parse and validate every §2.2 rule.
    pub fn parse(v: &Value) -> Result<Envelope> {
        let e: Envelope = from_value(v)?;
        e.validate()?;
        Ok(e)
    }

    pub fn validate(&self) -> Result<()> {
        if self.v != 1 {
            bail!("v must be 1");
        }
        if !valid_project_id(&self.project) {
            bail!("project must be prj_ followed by a 26-character ULID");
        }
        if !valid_agent_name(&self.agent) {
            bail!("agent must match ^[a-z0-9][a-z0-9._-]{{0,63}}$");
        }
        if self.seq == 0 || self.seq > jcs::MAX_SAFE_INTEGER {
            bail!("seq must be an integer from 1 to 2^53-1");
        }
        if (self.seq == 1) != self.prev.is_none() {
            bail!("prev must be null when seq is 1 and a record_hash otherwise");
        }
        time::parse(&self.time)?;
        let n = self.name.chars().count();
        if !(1..=128).contains(&n) {
            bail!("name must be 1 to 128 characters");
        }
        match (self.kind, self.reference.is_some()) {
            (Kind::Outcome, false) => bail!("an outcome must set ref to the record_hash of its decision"),
            (Kind::Decision | Kind::Note, true) => bail!("ref must be null unless kind is outcome"),
            _ => {}
        }
        if let Some(c) = &self.checks {
            crate::checks::envelope::validate(self.kind, &self.name, c).map_err(Error::new)?;
        }
        Ok(())
    }

    pub fn time_ms(&self) -> i64 {
        time::parse(&self.time).unwrap_or(i64::MIN)
    }

    /// `sha256(JCS(envelope))`
    pub fn record_hash(&self) -> Result<Hash> {
        hash_json(self)
    }
}

/// A content salt (§2.1): 16 random bytes, written as 32 lowercase hex characters.
pub fn parse_salt(salt: &str) -> Result<[u8; 16]> {
    if salt.len() != 32 || !salt.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        bail!("salt must be 32 lowercase hex characters (16 bytes)");
    }
    let mut out = [0u8; 16];
    hex::decode_to_slice(salt, &mut out).map_err(|e| Error::new(format!("salt: {e}")))?;
    Ok(out)
}

/// `sha256(salt || JCS(content))` (§2.1): `salt` is the record's 16-byte salt as 32 lowercase
/// hex characters; content must be a JSON object.
pub fn content_hash(content: &Value, salt: &str) -> Result<Hash> {
    if !content.is_object() {
        bail!("content must be a JSON object");
    }
    let mut bytes = parse_salt(salt)?.to_vec();
    bytes.extend_from_slice(jcs::canonicalize(content)?.as_bytes());
    Ok(sha256(&bytes))
}

/// §2.3 signed record, as sent by a client.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub envelope: Envelope,
    pub key_id: String,
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    /// The content's salt (§2.1), sent only together with `content`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// The values a strict call disclosed to the witness (§2.3, §10.4), `{pointer: value}`.
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub disclosed: Option<Value>,
    /// The disclosed values' own salt (§2.3), never the content's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed_salt: Option<String>,
}

impl SignedRecord {
    /// `content` and `salt` come together or not at all (§2.3); when present they must hash to
    /// `envelope.content_hash`. `Ok(Some(h))` is a mismatch: the content hashes to `h`.
    pub fn check_content(&self) -> Result<Option<Hash>> {
        check_content(self.content.as_ref(), self.salt.as_deref(), &self.envelope.content_hash)
    }
}

/// The §2.3 content rule shared by signed records and pack records.
pub fn check_content(content: Option<&Value>, salt: Option<&str>, expected: &Hash) -> Result<Option<Hash>> {
    match (content, salt) {
        (None, None) => Ok(None),
        (Some(_), None) => bail!("content is present without its salt"),
        (None, Some(_)) => bail!("salt is present without content"),
        (Some(c), Some(s)) => {
            let h = content_hash(c, s)?;
            Ok((h != *expected).then_some(h))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Drand {
    pub chain: String,
    pub round: u64,
    pub randomness: String,
    pub signature: String,
}

/// §3.1 batch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub v: u8,
    pub project: String,
    pub env: Env,
    pub seq: u64,
    #[serde(deserialize_with = "required")]
    pub prev: Option<Hash>,
    pub root: Hash,
    pub size: u64,
    pub server_time: String,
    #[serde(deserialize_with = "required")]
    pub drand: Option<Drand>,
}

impl Batch {
    pub fn hash(&self) -> Result<Hash> {
        hash_json(self)
    }
}

/// §3.3 head.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub project: String,
    pub env: Env,
    pub agent: String,
    pub seq: u64,
    pub record_hash: Hash,
    pub server_time: String,
}

impl Head {
    pub fn hash(&self) -> Result<Hash> {
        hash_json(self)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedHead {
    pub head: Head,
    pub head_sig: String,
}

/// §3.4 receipt.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub record_hash: Hash,
    pub index: u64,
    pub proof: Vec<Hash>,
    pub batch: Batch,
    pub batch_hash: Hash,
    pub batch_sig: String,
    pub service_key_id: String,
    pub head: Head,
    pub head_sig: String,
    /// The witness's ruling (§3.5) on a decision that asked for one, kept as sent: check 6
    /// validates it field by field.
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub ruling: Option<Value>,
    /// The service's signature over domain `ruling` and `ruling_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruling_sig: Option<String>,
    /// Why the witness could not rule (`rules_unavailable`); not signed (§3.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruling_error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AnchorStatus {
    Pending,
    Confirmed,
}

/// §4 anchor.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub v: u8,
    pub seq: u64,
    #[serde(deserialize_with = "required")]
    pub prev: Option<Hash>,
    pub root: Hash,
    pub size: u64,
    pub created: String,
    /// `service_keys_hash` of the service keys at `created` (§4), signed with the anchor.
    pub keys_hash: Hash,
    pub ots: String,
    pub status: AnchorStatus,
    #[serde(deserialize_with = "required")]
    pub bitcoin_block: Option<u64>,
}

/// The signed part of an anchor: everything except `ots`, `status` and `bitcoin_block`.
#[derive(Serialize, Clone, Debug)]
pub struct AnchorCore<'a> {
    pub v: u8,
    pub seq: u64,
    pub prev: Option<Hash>,
    pub root: Hash,
    pub size: u64,
    pub created: &'a str,
    pub keys_hash: Hash,
}

impl Anchor {
    pub fn core(&self) -> AnchorCore<'_> {
        AnchorCore { v: self.v, seq: self.seq, prev: self.prev, root: self.root, size: self.size, created: &self.created, keys_hash: self.keys_hash }
    }

    /// `sha256(JCS(anchor without ots, status, bitcoin_block))`
    pub fn hash(&self) -> Result<Hash> {
        hash_json(&self.core())
    }
}

/// A batch's inclusion path into an anchor tree.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorPath {
    pub index: u64,
    pub path: Vec<Hash>,
}

/// §5 service key entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub key_id: String,
    pub public_key: String,
    pub valid_from: String,
    #[serde(deserialize_with = "required")]
    pub valid_to: Option<String>,
}

impl KeyEntry {
    /// `valid_from` is a protocol time and `valid_to` is null or one.
    pub fn validate(&self) -> Result<()> {
        validate_window(&self.valid_from, self.valid_to.as_deref()).map_err(|e| Error::new(format!("service key {}: {e}", self.key_id)))
    }
}

fn validate_window(valid_from: &str, valid_to: Option<&str>) -> Result<()> {
    time::parse(valid_from).map_err(|e| Error::new(format!("valid_from: {e}")))?;
    if let Some(t) = valid_to {
        time::parse(t).map_err(|e| Error::new(format!("valid_to: {e}")))?;
    }
    Ok(())
}

/// One entry of the anchor's `keys_hash` (§4): the immutable part of a service key.
#[derive(Serialize)]
struct KeyCommit<'a> {
    key_id: &'a str,
    public_key: &'a str,
    valid_from: &'a str,
}

/// `keys_hash` (§4): sha256(JCS(list)) over the service keys whose `valid_from` is at or
/// before `created_ms`, each as `{key_id, public_key, valid_from}`, ordered by `valid_from`
/// then `key_id`. `valid_to` is left out: it is set later, when a key is retired.
pub fn service_keys_hash(keys: &[KeyEntry], created_ms: i64) -> Result<Hash> {
    let mut list: Vec<KeyCommit> = keys
        .iter()
        .filter(|k| time::parse(&k.valid_from).is_ok_and(|f| f <= created_ms))
        .map(|k| KeyCommit { key_id: &k.key_id, public_key: &k.public_key, valid_from: &k.valid_from })
        .collect();
    list.sort_by(|a, b| (a.valid_from, a.key_id).cmp(&(b.valid_from, b.key_id)));
    hash_json(&list)
}

/// The `/.well-known/signafaide-keys.json` document.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeysDocument {
    pub keys: Vec<KeyEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentKey {
    pub agent: String,
    pub key_id: String,
    pub public_key: String,
    pub valid_from: String,
    #[serde(deserialize_with = "required")]
    pub valid_to: Option<String>,
}

impl AgentKey {
    pub fn validate(&self) -> Result<()> {
        validate_window(&self.valid_from, self.valid_to.as_deref()).map_err(|e| Error::new(format!("agent key {}: {e}", self.key_id)))
    }
}

/// §2.4 agent key registration, signed by the new key (domain `register`) and, when the
/// agent already has an active key, by that key too (domain `rotate`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub project: String,
    pub env: Env,
    pub agent: String,
    pub public_key: String,
    pub valid_from: String,
}

impl Registration {
    pub fn hash(&self) -> Result<Hash> {
        hash_json(self)
    }
}

/// §2.5 one entry of an agent-key manifest (`signafaide keys export`), self-signed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyEntry {
    pub agent: String,
    pub key_id: String,
    pub public_key: String,
    pub valid_from: String,
    /// When the key was retired (the time the service ended it, §2.4); null for a current key.
    #[serde(deserialize_with = "required")]
    pub valid_to: Option<String>,
    /// The key's own signature (domain `agent_key`) over
    /// `sha256(JCS({agent, key_id, public_key, valid_from, valid_to}))`.
    pub sig: String,
}

#[derive(Serialize)]
struct AgentKeySigned<'a> {
    agent: &'a str,
    key_id: &'a str,
    public_key: &'a str,
    valid_from: &'a str,
    valid_to: Option<&'a str>,
}

impl AgentKeyEntry {
    /// The hash the entry's `sig` covers.
    pub fn signed_hash(&self) -> Result<Hash> {
        hash_json(&AgentKeySigned {
            agent: &self.agent,
            key_id: &self.key_id,
            public_key: &self.public_key,
            valid_from: &self.valid_from,
            valid_to: self.valid_to.as_deref(),
        })
    }

    /// Every rule: agent name, key id of the public key, time, and the self-signature.
    pub fn validate(&self) -> Result<()> {
        if !valid_agent_name(&self.agent) {
            bail!("agent {} is not a valid agent name", self.agent);
        }
        let raw = crate::sign::parse_public_key(&self.public_key)?;
        if crate::sign::key_id(&raw) != self.key_id {
            bail!("key_id {} does not match its public key", self.key_id);
        }
        validate_window(&self.valid_from, self.valid_to.as_deref())?;
        crate::sign::verify(&self.public_key, crate::sign::Domain::AgentKey, &self.signed_hash()?, &self.sig)
            .map_err(|_| Error::new(format!("the self-signature of key {} for {} does not verify", self.key_id, self.agent)))
    }
}

pub const AGENT_KEYS_FORMAT: &str = "signafaide-agent-keys/1";

/// The name of the note a new instance writes first when it continues a chain its disk does not
/// hold (§8): records an earlier instance wrote but had not sent are not in the chain.
pub const INSTANCE_START: &str = "signafaide.instance_start";

/// The name of the note an instance writes last on a clean stop (§8): its outbox was empty, so
/// it had sent every record it wrote. An instance start right after it is a clean restart.
pub const INSTANCE_STOP: &str = "signafaide.instance_stop";

/// The check 4 note (§7) naming the instance starts with no stop note right before them.
pub const INSTANCE_NOTE: &str = "a new instance continued the chain, so records an earlier instance wrote but had not sent are not known";

/// The check 4 note (§7) naming the instance starts right after a stop note (clean restarts).
pub const CLEAN_RESTART_NOTE: &str = "a new instance continued the chain right after the earlier instance's signed stop note (a clean restart, nothing to warn about)";

/// §2.5 the agent-key manifest a customer gives auditors (`--agent-keys`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentKeysDocument {
    pub format: String,
    pub keys: Vec<AgentKeyEntry>,
}

/// True when a key with this validity window was active at `at_ms`.
pub fn key_active(valid_from: &str, valid_to: Option<&str>, at_ms: i64) -> bool {
    let from = time::parse(valid_from).map(|f| f <= at_ms).unwrap_or(false);
    let to = valid_to.map(|t| time::parse(t).map(|t| at_ms < t).unwrap_or(false)).unwrap_or(true);
    from && to
}

/// One record inside a verification pack.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackRecord {
    pub envelope: Envelope,
    pub key_id: String,
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// Disclosed values (§2.3), only in the key holder's own export (§7).
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub disclosed: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed_salt: Option<String>,
    pub receipt: Receipt,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackAnchor {
    pub anchor: Anchor,
    pub anchor_sig: String,
    pub paths: BTreeMap<Hash, AnchorPath>,
}

pub const PACK_FORMAT: &str = "signafaide-pack/1";

/// §7 the export filter a pack was made with. `agents` null means every agent of the project.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PackFilter {
    #[serde(deserialize_with = "required")]
    pub agents: Option<Vec<String>>,
    #[serde(deserialize_with = "required")]
    pub from: Option<String>,
    #[serde(deserialize_with = "required")]
    pub to: Option<String>,
}

/// §7 verification pack. Records and anchors stay raw so one malformed entry is reported
/// on its own instead of failing the whole file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub format: String,
    pub generated: String,
    pub project: String,
    /// The project's name, as the customer named it in the console (optional; signed in the
    /// export statement when present, §7), so a verifier can show it next to the id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    pub env: Env,
    pub service_keys: Vec<KeyEntry>,
    pub agent_keys: Vec<AgentKey>,
    pub filter: PackFilter,
    /// The newest signed head of each exported agent at export time.
    pub heads: Vec<SignedHead>,
    pub records: Vec<Value>,
    pub anchors: Vec<Value>,
    /// The signed rule set versions (§10) the records name or that were in force meanwhile (§7),
    /// each `{rules, sig, service_key_id}`; present when the project has a rule set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_sets: Option<Vec<Value>>,
    /// Spec 1.1: the local rules (§8) that records of the pack name, each `{hash, rules}`, added
    /// by the client that holds them (the service never does). Bound by the agent-signed
    /// `checks.rules` hashes, not by the export statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_rules: Option<Vec<Value>>,
    /// The service's signature (domain `export`) over the export statement (§7).
    pub export_sig: String,
}

/// §7 the export statement the service signs: what was exported, when, and which records.
#[derive(Serialize, Clone, Debug)]
pub struct ExportStatement<'a> {
    pub project: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_name: Option<&'a str>,
    pub env: Env,
    pub generated: &'a str,
    pub filter: &'a PackFilter,
    pub heads: Vec<&'a Head>,
    pub records_hash: Hash,
    /// The `rules_hash` of each `rule_sets` entry of the pack, in pack order; present exactly
    /// when the pack has `rule_sets`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_sets: Option<Vec<Hash>>,
}

impl ExportStatement<'_> {
    pub fn hash(&self) -> Result<Hash> {
        hash_json(self)
    }
}

/// `records_hash` (§7): sha256(JCS(list)) of every record's `receipt.record_hash`, in pack order.
pub fn records_hash(record_hashes: &[&str]) -> Result<Hash> {
    hash_json(&record_hashes)
}

impl Pack {
    /// The export statement of this pack (§7); `Err` when a record has no `receipt.record_hash` string.
    pub fn statement(&self) -> Result<ExportStatement<'_>> {
        let list: Vec<&str> = self
            .records
            .iter()
            .map(|r| r.pointer("/receipt/record_hash").and_then(Value::as_str).ok_or_else(|| Error::new("a record has no receipt.record_hash")))
            .collect::<Result<_>>()?;
        Ok(ExportStatement {
            project: &self.project,
            project_name: self.project_name.as_deref(),
            env: self.env,
            generated: &self.generated,
            filter: &self.filter,
            heads: self.heads.iter().map(|h| &h.head).collect(),
            records_hash: records_hash(&list)?,
            rule_sets: match &self.rule_sets {
                None => None,
                Some(sets) => Some(sets.iter().map(|s| s.get("rules").ok_or_else(|| Error::new("a rule_sets entry has no rules")).and_then(hash_json)).collect::<Result<_>>()?),
            },
        })
    }

    /// Pack-level rules beyond the field types.
    pub fn validate(&self) -> Result<()> {
        if !valid_project_id(&self.project) {
            bail!("project is not a valid project id");
        }
        if let Some(n) = &self.project_name {
            if n.is_empty() || n.chars().count() > 200 || n.chars().any(char::is_control) {
                bail!("project_name must be 1 to 200 characters, without control characters");
            }
        }
        time::parse(&self.generated).map_err(|e| Error::new(format!("generated: {e}")))?;
        for k in &self.service_keys {
            k.validate()?;
        }
        for k in &self.agent_keys {
            k.validate()?;
        }
        for (name, t) in [("from", &self.filter.from), ("to", &self.filter.to)] {
            if let Some(t) = t {
                time::parse(t).map_err(|e| Error::new(format!("filter.{name}: {e}")))?;
            }
        }
        if let Some(agents) = &self.filter.agents {
            if agents.iter().any(|a| !valid_agent_name(a)) {
                bail!("filter.agents holds an invalid agent name");
            }
        }
        for h in &self.heads {
            if !valid_agent_name(&h.head.agent) || time::parse(&h.head.server_time).is_err() {
                bail!("heads holds an invalid head");
            }
        }
        Ok(())
    }
}
