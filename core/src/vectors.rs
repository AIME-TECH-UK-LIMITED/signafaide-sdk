//! Deterministic test vectors (`spec/vectors.json`) shared by every implementation.
//! Keys come from fixed seeds and every time is fixed, so the output is byte-for-byte stable.

use crate::bitcoin::{mine_header, BlockHeader};
use crate::merkle::Tree;
use crate::ots::{Attestation, DetachedFile, Op, Timestamp};
use crate::sign::{Domain, Keypair};
use crate::verify::{self, Options, CHECKS};
use crate::*;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const PROJECT: &str = "prj_01JCZQ8Z5X3V7N2M4K6H8G0F1D";
pub const AGENT: &str = "agent-a";
const AGENT_KEY_FROM: &str = "2026-11-13T09:00:00.000Z";
const SERVICE_KEY_FROM: &str = "2026-11-01T00:00:00.000Z";
const CALENDAR: &str = "https://a.pool.opentimestamps.org";

fn seed(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

/// Agent key: seed bytes 0x00..0x1f.
pub fn agent_key() -> Keypair {
    Keypair::from_seed(&seed(0x00))
}

/// Service key: seed bytes 0x20..0x3f.
pub fn service_key() -> Keypair {
    Keypair::from_seed(&seed(0x20))
}

/// An unrelated key used to forge signatures: seed bytes 0x40..0x5f.
pub fn other_key() -> Keypair {
    Keypair::from_seed(&seed(0x40))
}

/// drand quicknet round 33920212, published at 2026-11-13T10:00:00.000Z (the vectors' time).
pub fn drand_vector_round() -> Drand {
    let signature = "b09e838e2d800efdb10a24554d8223c2c5103c5f6a7c87e6b37734487b1d1fd3191f99e64d2d0dc4fc00867118df261b";
    Drand {
        chain: drand::QUICKNET_CHAIN.into(),
        round: 33_920_212,
        randomness: sha256(&hex::decode(signature).unwrap()).hex(),
        signature: signature.into(),
    }
}

/// drand quicknet round 123 (public, verifiable offline).
pub fn drand_round_123() -> Drand {
    let signature = "b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92";
    Drand {
        chain: drand::QUICKNET_CHAIN.into(),
        round: 123,
        randomness: sha256(&hex::decode(signature).unwrap()).hex(),
        signature: signature.into(),
    }
}

pub fn service_key_entry() -> KeyEntry {
    let k = service_key();
    KeyEntry { key_id: k.key_id(), public_key: k.public_key_b64(), valid_from: SERVICE_KEY_FROM.into(), valid_to: None }
}

/// A self-signed agent-key manifest entry (§2.5).
pub fn agent_key_entry(agent: &str, k: &Keypair, valid_from: &str, valid_to: Option<&str>) -> AgentKeyEntry {
    let mut e = AgentKeyEntry {
        agent: agent.into(),
        key_id: k.key_id(),
        public_key: k.public_key_b64(),
        valid_from: valid_from.into(),
        valid_to: valid_to.map(String::from),
        sig: String::new(),
    };
    e.sig = k.sign(Domain::AgentKey, &e.signed_hash().unwrap());
    e
}

/// The customer's manifest for the vectors' agent: `signafaide keys export`.
pub fn agent_keys_document() -> AgentKeysDocument {
    AgentKeysDocument { format: AGENT_KEYS_FORMAT.into(), keys: vec![agent_key_entry(AGENT, &agent_key(), AGENT_KEY_FROM, None)] }
}

/// A head signed by the vectors' service key.
pub fn signed_head(agent: &str, seq: u64, record_hash: Hash, server_time: &str) -> SignedHead {
    let head = Head { project: PROJECT.into(), env: Env::Live, agent: agent.into(), seq, record_hash, server_time: server_time.into() };
    let head_sig = service_key().sign(Domain::Head, &head.hash().unwrap());
    SignedHead { head, head_sig }
}

/// The Merkle root (header byte order) a synthetic confirmed proof commits to.
pub fn confirmed_block_root(digest: &Hash) -> [u8; 32] {
    let m1 = Op::Prepend(vec![0x11; 32]).apply(&digest.0).unwrap();
    Op::Sha256.apply(&m1).unwrap().try_into().unwrap()
}

/// The Merkle root a synthetic confirmed proof commits to, as an explorer shows it.
pub fn confirmed_block_root_display(digest: &Hash) -> String {
    let mut m2 = confirmed_block_root(digest);
    m2.reverse();
    hex::encode(m2)
}

/// A block header holding `root`, with valid (regtest-easy) proof of work, as an explorer serves it.
pub fn header_json(root: &[u8; 32]) -> Value {
    let h = mine_header(root, 1_763_028_000);
    json!({"hash": h.hash, "header": hex::encode(&h.header)})
}

/// A header holding `root` whose hash does not meet the target its nBits claims.
pub fn header_without_work_json(root: &[u8; 32]) -> Value {
    let mut h: BlockHeader = mine_header(root, 1_763_028_000);
    for nonce in 0u32.. {
        h.header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let mut id = sha256(&sha256(&h.header).0).0;
        id.reverse();
        if id[0] >= 0x80 {
            return json!({"hash": hex::encode(id), "header": hex::encode(&h.header)});
        }
    }
    unreachable!()
}

/// Sign a pack's export statement with the vectors' service key (§7): what the service does
/// when it builds a pack, and what a holder of the pack cannot do.
pub fn sign_export(pack: &mut Value) {
    pack["export_sig"] = json!("");
    let p: Pack = from_value(pack).unwrap();
    let h = p.statement().unwrap().hash().unwrap();
    pack["export_sig"] = json!(service_key().sign(Domain::Export, &h));
}

/// A proof with more attestations than `ots::MAX_NODES` allows (a memory bomb in miniature).
pub fn oversized_ots(digest: &Hash) -> Vec<u8> {
    let leaf = |i: usize| Attestation::Pending { uri: format!("https://c{i}.example") };
    let ts = Timestamp { msg: digest.0.to_vec(), attestations: (0..=crate::ots::MAX_NODES).map(leaf).collect(), ops: vec![] };
    DetachedFile { digest: digest.0, timestamp: ts }.serialize()
}

/// A pending OTS proof: digest → append(nonce) → sha256 → pending calendar attestation.
pub fn pending_ots(digest: &Hash) -> Vec<u8> {
    let nonce: Vec<u8> = (0xa0..0xb0).collect();
    let m1 = Op::Append(nonce.clone()).apply(&digest.0).unwrap();
    let m2 = Op::Sha256.apply(&m1).unwrap();
    let leaf = Timestamp { msg: m2, attestations: vec![Attestation::Pending { uri: CALENDAR.into() }], ops: vec![] };
    let mid = Timestamp { msg: m1, attestations: vec![], ops: vec![(Op::Sha256, leaf)] };
    let ts = Timestamp { msg: digest.0.to_vec(), attestations: vec![], ops: vec![(Op::Append(nonce), mid)] };
    DetachedFile { digest: digest.0, timestamp: ts }.serialize()
}

/// A synthetic confirmed proof (structure only: the Bitcoin attestation is invented).
pub fn confirmed_ots(digest: &Hash, height: u64) -> Vec<u8> {
    let m1 = Op::Prepend(vec![0x11; 32]).apply(&digest.0).unwrap();
    let m2 = Op::Sha256.apply(&m1).unwrap();
    let leaf = Timestamp { msg: m2, attestations: vec![Attestation::Bitcoin { height }], ops: vec![] };
    let mid = Timestamp { msg: m1, attestations: vec![], ops: vec![(Op::Sha256, leaf)] };
    let ts = Timestamp { msg: digest.0.to_vec(), attestations: vec![], ops: vec![(Op::Prepend(vec![0x11; 32]), mid)] };
    DetachedFile { digest: digest.0, timestamp: ts }.serialize()
}

/// A tamper applied while the pack is built, re-signing everything downstream so only
/// the targeted check fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Build {
    Valid,
    ForkedPrev,
    ForkedBatchPrev,
    WrongDrandRound,
    OtsForOtherDigest,
    /// Seq 3 is signed with a time before seq 2's.
    TimeBackwards,
    /// Seq 4 is dated 5 minutes after its batch's server_time.
    TimeAfterBatch,
    /// Batch 2's server_time is before batch 1's.
    BatchTimeBackwards,
    /// Batch 1's server_time is before its drand round was published.
    BatchBeforeRound,
    /// The anchor is dated before batch 2, which it covers.
    AnchorBeforeBatch,
    /// The anchor's proof is a (synthetic) confirmed one.
    Confirmed,
    /// Seq 4 belongs to a second agent, `agent-b` (its seq 1).
    TwoAgents,
    /// Batch 1 claims a drand round far beyond any protocol time.
    HugeRound,
    /// Seq 3 is an instance-start note (§8): a new instance continued after seq 2.
    InstanceStart,
}

pub struct Fixture {
    pub records: Vec<(SignedRecord, Hash)>,
    pub receipts: Vec<Receipt>,
    pub batches: Vec<(Batch, Hash, String)>,
    pub anchor: PackAnchor,
    pub pack: Value,
}

/// Record `i`'s content salt: the first 16 bytes of sha256("salt-<i>"), as 32 hex characters.
pub fn sample_salt(i: usize) -> String {
    hex::encode(&sha256(format!("salt-{i}").as_bytes()).0[..16])
}

fn sample_contents() -> Vec<(Kind, &'static str, &'static str, Value, bool)> {
    vec![
        (
            Kind::Decision,
            "approve_payout",
            "2026-11-13T10:00:00.000Z",
            json!({"input": {"invoice": "INV-1001", "amount": 1250.5}, "output": {"approved": true},
                   "model": "model-x", "reason": "Within the approval limit.",
                   "meta": {"tags": ["finance", "\u{e9}t\u{e9}", "\u{1F600}"], "ratio": 0.1, "big": 1e21, "zero": -0.0}}),
            true,
        ),
        (Kind::Outcome, "approve_payout", "2026-11-13T10:00:00.500Z", json!({"output": {"paid": true, "amount": 1250.5}}), true),
        (Kind::Note, "nightly_summary", "2026-11-13T10:00:01.000Z", json!({"text": "line1\nline2\t\"quoted\" \\ \u{1f}"}), false),
        (Kind::Decision, "reject_refund", "2026-11-13T10:04:59.000Z", json!({"input": {"order": "A-9"}, "output": {"refund": false}}), false),
    ]
}

fn build(mode: Build) -> Fixture {
    let (ak, sk) = (agent_key(), service_key());
    let mut records: Vec<(SignedRecord, Hash)> = Vec::new();
    let mut prev = None;
    for (i, (kind, name, time, mut content, store)) in sample_contents().into_iter().enumerate() {
        let name = if mode == Build::InstanceStart && i == 2 {
            content = json!({"continues_after_seq": 2, "continues_after": records[1].1, "earlier_unsent": "unknown"});
            INSTANCE_START
        } else {
            name
        };
        let time = match (mode, i) {
            (Build::TimeBackwards, 2) => "2026-11-13T10:00:00.200Z",
            (Build::TimeAfterBatch, 3) => "2026-11-13T10:10:00.001Z",
            _ => time,
        };
        let second = mode == Build::TwoAgents && i == 3;
        let mut envelope = Envelope {
            v: 1,
            kind,
            project: PROJECT.into(),
            env: Env::Live,
            agent: if second { "agent-b".into() } else { AGENT.into() },
            seq: if second { 1 } else { i as u64 + 1 },
            prev: if second { None } else { prev },
            time: time.into(),
            name: name.into(),
            content_hash: content_hash(&content, &sample_salt(i)).unwrap(),
            reference: (kind == Kind::Outcome).then(|| records[0].1),
        };
        if mode == Build::ForkedPrev && i == 3 {
            envelope.prev = Some(sha256(b"forged prev"));
        }
        let hash = envelope.record_hash().unwrap();
        let sig = ak.sign(Domain::Record, &hash);
        records.push((SignedRecord { envelope, key_id: ak.key_id(), sig, content: store.then_some(content), salt: store.then(|| sample_salt(i)) }, hash));
        prev = Some(hash);
    }

    let groups: [(std::ops::Range<usize>, &str, Option<Drand>); 2] = [
        (0..3, if mode == Build::BatchBeforeRound { "2026-11-13T09:59:59.000Z" } else { "2026-11-13T10:00:01.250Z" }, Some(drand_vector_round())),
        (3..4, if mode == Build::BatchTimeBackwards { "2026-11-13T10:00:01.000Z" } else { "2026-11-13T10:05:00.000Z" }, None),
    ];
    let (mut batches, mut receipts) = (Vec::new(), Vec::new());
    let mut prev_batch: Option<Hash> = None;
    for (seq, (range, server_time, mut drand)) in groups.into_iter().enumerate() {
        let seq = seq as u64 + 1;
        let hashes: Vec<Hash> = records[range.clone()].iter().map(|r| r.1).collect();
        let tree = Tree::new(&hashes).unwrap();
        if let Some(d) = drand.as_mut() {
            match mode {
                Build::WrongDrandRound => d.round = 124,
                Build::HugeRound => d.round = 4_000_000_000_000_000,
                _ => {}
            }
        }
        let mut batch = Batch {
            v: 1,
            project: PROJECT.into(),
            env: Env::Live,
            seq,
            prev: prev_batch,
            root: tree.root(),
            size: hashes.len() as u64,
            server_time: server_time.into(),
            drand,
        };
        if mode == Build::ForkedBatchPrev && seq == 2 {
            batch.prev = Some(sha256(b"forged batch"));
        }
        let bh = batch.hash().unwrap();
        let bsig = sk.sign(Domain::Batch, &bh);
        let last = &records[range.end - 1];
        let head = Head {
            project: PROJECT.into(),
            env: Env::Live,
            agent: last.0.envelope.agent.clone(),
            seq: last.0.envelope.seq,
            record_hash: last.1,
            server_time: server_time.into(),
        };
        let head_sig = sk.sign(Domain::Head, &head.hash().unwrap());
        for (i, h) in hashes.iter().enumerate() {
            receipts.push(Receipt {
                record_hash: *h,
                index: i as u64,
                proof: tree.path(i),
                batch: batch.clone(),
                batch_hash: bh,
                batch_sig: bsig.clone(),
                service_key_id: sk.key_id(),
                head: head.clone(),
                head_sig: head_sig.clone(),
            });
        }
        batches.push((batch, bh, bsig));
        prev_batch = Some(bh);
    }

    let batch_hashes: Vec<Hash> = batches.iter().map(|b| b.1).collect();
    let tree = Tree::new(&batch_hashes).unwrap();
    let created = if mode == Build::AnchorBeforeBatch { "2026-11-13T10:04:00.000Z" } else { "2026-11-13T11:00:00.000Z" };
    let confirmed = mode == Build::Confirmed;
    let mut anchor = Anchor {
        v: 1,
        seq: 1,
        prev: None,
        root: tree.root(),
        size: batch_hashes.len() as u64,
        created: created.into(),
        keys_hash: service_keys_hash(&[service_key_entry()], time::parse(created).unwrap()).unwrap(),
        ots: String::new(),
        status: if confirmed { AnchorStatus::Confirmed } else { AnchorStatus::Pending },
        bitcoin_block: confirmed.then_some(900_000),
    };
    // The public timestamp covers the anchor hash (§4), so it fixes keys_hash and created too.
    let anchor_hash = anchor.hash().unwrap();
    let ots_digest = if mode == Build::OtsForOtherDigest { tree.root() } else { anchor_hash };
    anchor.ots = STANDARD.encode(if confirmed { confirmed_ots(&ots_digest, 900_000) } else { pending_ots(&ots_digest) });
    let anchor_sig = sk.sign(Domain::Anchor, &anchor_hash);
    let paths: BTreeMap<Hash, AnchorPath> = batch_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, AnchorPath { index: i as u64, path: tree.path(i) }))
        .collect();
    let anchor = PackAnchor { anchor, anchor_sig, paths };

    let pack_records: Vec<Value> = records
        .iter()
        .zip(&receipts)
        .map(|((r, _), rc)| {
            serde_json::to_value(PackRecord {
                envelope: r.envelope.clone(),
                key_id: r.key_id.clone(),
                sig: r.sig.clone(),
                content: r.content.clone(),
                salt: r.salt.clone(),
                receipt: rc.clone(),
            })
            .unwrap()
        })
        .collect();
    let agents: &[&str] = if mode == Build::TwoAgents { &[AGENT, "agent-b"] } else { &[AGENT] };
    let heads = if mode == Build::TwoAgents { vec![&receipts[2], &receipts[3]] } else { vec![&receipts[3]] };
    let mut pack = serde_json::to_value(Pack {
        format: PACK_FORMAT.into(),
        generated: "2026-11-13T12:00:00.000Z".into(),
        project: PROJECT.into(),
        project_name: None,
        env: Env::Live,
        service_keys: vec![service_key_entry()],
        agent_keys: agents
            .iter()
            .map(|a| AgentKey { agent: (*a).into(), key_id: ak.key_id(), public_key: ak.public_key_b64(), valid_from: AGENT_KEY_FROM.into(), valid_to: None })
            .collect(),
        filter: PackFilter::default(),
        heads: heads.iter().map(|rc| SignedHead { head: rc.head.clone(), head_sig: rc.head_sig.clone() }).collect(),
        records: pack_records,
        anchors: vec![serde_json::to_value(&anchor).unwrap()],
        export_sig: String::new(),
    })
    .unwrap();
    sign_export(&mut pack);
    Fixture { records, receipts, batches, anchor, pack }
}

pub fn valid_fixture() -> Fixture {
    build(Build::Valid)
}

/// Inputs for a tampered pack or a variant besides the pack: the default is the vectors'
/// `keys_document`, `agent_keys_document`, no head file and offline Bitcoin.
#[derive(Default)]
pub struct Inputs {
    pub keys: Option<Value>,
    /// `Some(Value::Null)`: no agent keys at all (NOT INDEPENDENT).
    pub agent_keys: Option<Value>,
    pub trust_embedded_agent_keys: bool,
    pub head: Option<Value>,
    /// height -> `{hash, header}` as an explorer serves them.
    pub bitcoin: Option<Value>,
    /// The service checks its own pack with its own key registry.
    pub by_service: bool,
    /// The service keys came over plain http from a local address.
    pub service_keys_plain_http: bool,
}

impl Inputs {
    pub fn to_json(&self, into: &mut Value) {
        for (k, v) in [("keys", &self.keys), ("agent_keys", &self.agent_keys), ("head", &self.head), ("bitcoin", &self.bitcoin)] {
            if let Some(v) = v {
                into[k] = v.clone();
            }
        }
        for (k, on) in [
            ("trust_embedded_agent_keys", self.trust_embedded_agent_keys),
            ("by_service", self.by_service),
            ("service_keys_plain_http", self.service_keys_plain_http),
        ] {
            if on {
                into[k] = json!(true);
            }
        }
    }

    /// Verifier options from a vector entry (`keys`, `agent_keys`, `trust_embedded_agent_keys`, `head`, `bitcoin`).
    pub fn options(entry: &Value, defaults: &Value) -> Options {
        let flag = |k: &str| entry.get(k).and_then(Value::as_bool).unwrap_or(false);
        let keys: KeysDocument = from_value(entry.get("keys").unwrap_or(&defaults["keys_document"])).unwrap();
        let agent_keys = match entry.get("agent_keys") {
            Some(Value::Null) => None,
            Some(v) => Some(verify::agent_keys_from_text(&v.to_string()).unwrap()),
            None => Some(verify::agent_keys_from_text(&defaults["agent_keys_document"].to_string()).unwrap()),
        };
        let bitcoin = match entry.get("bitcoin") {
            Some(Value::Object(m)) => verify::Bitcoin::Checked(
                m.iter()
                    .map(|(h, r)| (h.parse().unwrap(), verify::block_header_from_hex(r["hash"].as_str().unwrap(), r["header"].as_str().unwrap())))
                    .collect(),
            ),
            _ => verify::Bitcoin::Offline,
        };
        Options {
            service_keys: Some(keys.keys),
            agent_keys,
            trust_embedded_agent_keys: entry.get("trust_embedded_agent_keys").and_then(Value::as_bool).unwrap_or(false),
            heads: entry.get("head").map(|h| verify::heads_from_text(&h.to_string()).unwrap()),
            bitcoin,
            by_service: flag("by_service"),
            service_keys_plain_http: flag("service_keys_plain_http"),
            ..Default::default()
        }
    }
}

fn head_file(heads: &[SignedHead]) -> Value {
    let mut agents = serde_json::Map::new();
    for h in heads {
        agents.insert(h.head.agent.clone(), serde_json::to_value(h).unwrap());
    }
    json!({PROJECT: {"live": agents}})
}

/// One tampered pack per rule: (check id, what was changed, pack, other inputs). In each, the
/// named check is the lowest-numbered one that fails.
pub fn tampered_packs() -> Vec<(&'static str, &'static str, Value, Inputs)> {
    let valid = valid_fixture().pack;
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut p = valid.clone();
        f(&mut p);
        p
    };
    let drop_seq = |seqs: &[u64]| edit(&|p| p["records"].as_array_mut().unwrap().retain(|r| !seqs.contains(&r["envelope"]["seq"].as_u64().unwrap())));
    let other = other_key();
    let none = Inputs::default;
    let root = valid_fixture().anchor.anchor.root;
    let confirmed = build(Build::Confirmed).pack;
    let mut moved_keys = json!({"keys": [service_key_entry()]});
    moved_keys["keys"][0]["valid_from"] = json!("2020-01-01T00:00:00.000Z");
    let fx = valid_fixture();
    let newer = signed_head(AGENT, 5, sha256(b"a fifth record"), "2026-11-13T10:06:00.000Z");
    // The service re-signs the export statement: a change the service itself makes.
    let signed = |f: &dyn Fn(&mut Value)| {
        let mut p = valid.clone();
        f(&mut p);
        sign_export(&mut p);
        p
    };
    let pop = |p: &mut Value| {
        p["records"].as_array_mut().unwrap().pop();
    };
    let receipt_head = |p: &mut Value, i: usize| {
        let rc = p["records"][i]["receipt"].clone();
        p["heads"] = json!([{"head": rc["head"], "head_sig": rc["head_sig"]}]);
    };
    let final_head = SignedHead { head: fx.receipts[3].head.clone(), head_sig: fx.receipts[3].head_sig.clone() };
    let two = build(Build::TwoAgents).pack;
    let two_from = {
        let mut p = two.clone();
        p["filter"]["from"] = json!("2026-11-13T09:30:00.000Z");
        sign_export(&mut p);
        p
    };
    let two_agents = || Inputs {
        agent_keys: Some(json!(AgentKeysDocument {
            format: AGENT_KEYS_FORMAT.into(),
            keys: vec![agent_key_entry(AGENT, &agent_key(), AGENT_KEY_FROM, None), agent_key_entry("agent-b", &agent_key(), AGENT_KEY_FROM, None)],
        })),
        ..Inputs::default()
    };
    let retired_at = |t: &str| Inputs {
        agent_keys: Some(json!(AgentKeysDocument { format: AGENT_KEYS_FORMAT.into(), keys: vec![agent_key_entry(AGENT, &agent_key(), AGENT_KEY_FROM, Some(t))] })),
        ..Inputs::default()
    };
    // A second, different anchor with seq 1, over batch 1 alone, signed by the service.
    let duplicate_anchor = {
        let (_, bh, _) = &fx.batches[0];
        let tree = Tree::new(&[*bh]).unwrap();
        let created = "2026-11-13T11:30:00.000Z";
        let anchor = Anchor {
            v: 1,
            seq: 1,
            prev: None,
            root: tree.root(),
            size: 1,
            created: created.into(),
            keys_hash: service_keys_hash(&[service_key_entry()], time::parse(created).unwrap()).unwrap(),
            ots: STANDARD.encode(pending_ots(&tree.root())),
            status: AnchorStatus::Pending,
            bitcoin_block: None,
        };
        let anchor_sig = service_key().sign(Domain::Anchor, &anchor.hash().unwrap());
        serde_json::to_value(PackAnchor { anchor, anchor_sig, paths: [(*bh, AnchorPath { index: 0, path: vec![] })].into() }).unwrap()
    };
    vec![
        ("schema", "an unknown field was added to an envelope", edit(&|p| p["records"][0]["envelope"]["extra"] = json!(1)), none()),
        ("schema", "an envelope names another project", edit(&|p| p["records"][0]["envelope"]["project"] = json!("prj_01JCZQ8Z5X3V7N2M4K6H8G0F1E")), none()),
        ("record_hash", "an envelope's name was changed after signing", edit(&|p| p["records"][1]["envelope"]["name"] = json!("approve_payout_x")), none()),
        ("record_sig", "a record was re-signed with a key that is not the agent's", edit(&|p| {
            let h = Hash::from_hex(p["records"][2]["receipt"]["record_hash"].as_str().unwrap()).unwrap();
            p["records"][2]["sig"] = json!(other.sign(Domain::Record, &h));
        }), none()),
        ("record_sig", "the agent's key is not in the customer's agent keys (a key the service added)", valid.clone(), Inputs {
            agent_keys: Some(json!(AgentKeysDocument { format: AGENT_KEYS_FORMAT.into(), keys: vec![agent_key_entry(AGENT, &other, AGENT_KEY_FROM, None)] })),
            ..none()
        }),
        ("record_sig", "no independent agent keys: they would come from the pack (NOT INDEPENDENT)", valid.clone(), Inputs { agent_keys: Some(Value::Null), ..none() }),
        ("record_sig", "the key was revoked before the service received seq 4", edit(&|p| p["agent_keys"][0]["valid_to"] = json!("2026-11-13T10:04:59.500Z")), none()),
        ("chain", "the agent re-signed seq 4 with a prev that skips seq 3 (a fork)", build(Build::ForkedPrev).pack, none()),
        ("chain", "seq 3 was dropped from the middle of the chain", drop_seq(&[3]), none()),
        ("chain", "seq 1 was dropped and the export declares no from filter", drop_seq(&[1]), none()),
        ("chain", "seq 3 is dated before seq 2", build(Build::TimeBackwards).pack, none()),
        ("chain", "seq 4 is dated more than 300 s after its batch's server_time", build(Build::TimeAfterBatch).pack, none()),
        ("merkle", "a Merkle proof hash was replaced", edit(&|p| p["records"][0]["receipt"]["proof"][0] = json!(sha256(b"x").hex())), none()),
        ("batch_sig", "a batch_sig was made with a key that is not the service's", edit(&|p| {
            let h = Hash::from_hex(p["records"][3]["receipt"]["batch_hash"].as_str().unwrap()).unwrap();
            p["records"][3]["receipt"]["batch_sig"] = json!(other.sign(Domain::Batch, &h));
        }), none()),
        ("batch_chain", "the service signed batch 2 with a prev that is not batch 1", build(Build::ForkedBatchPrev).pack, none()),
        ("batch_chain", "batch 2's server_time is before batch 1's", build(Build::BatchTimeBackwards).pack, none()),
        ("head_sig", "a signed head's server_time was changed", edit(&|p| p["records"][0]["receipt"]["head"]["server_time"] = json!("2026-11-13T10:00:02.000Z")), none()),
        ("head_sig", "seq 4 was dropped from the end (the export head is seq 4)", drop_seq(&[4]), none()),
        ("head_sig", "the client's head file holds seq 5, which the pack lacks", valid.clone(), Inputs { head: Some(head_file(&[newer.clone()])), ..none() }),
        ("drand", "batch 1 claims the next drand round with this round's signature", build(Build::WrongDrandRound).pack, none()),
        ("drand", "batch 1's server_time is before its drand round was published", build(Build::BatchBeforeRound).pack, none()),
        ("anchor", "a hash in a batch's anchor path was replaced", edit(&|p| {
            let paths = p["anchors"][0]["paths"].as_object_mut().unwrap();
            let first = paths.values_mut().next().unwrap();
            first["path"][0] = json!(sha256(b"x").hex());
        }), none()),
        ("anchor", "the service key's valid_from was moved back after the anchor (keys_hash)", valid.clone(), Inputs { keys: Some(moved_keys), ..none() }),
        ("anchor", "the anchor is dated before a batch it covers", build(Build::AnchorBeforeBatch).pack, none()),
        ("anchor", "two different signed anchors with the same seq", edit(&|p| p["anchors"].as_array_mut().unwrap().push(duplicate_anchor.clone())), none()),
        ("ots", "the OTS proof timestamps the anchor root, not the anchor hash (which commits to keys_hash)", build(Build::OtsForOtherDigest).pack, none()),
        ("ots", "the OTS proof has more operations and attestations than allowed", edit(&|p| p["anchors"][0]["anchor"]["ots"] = json!(STANDARD.encode(oversized_ots(&root)))), none()),
        ("ots", "the proof claims a Bitcoin block whose header has another Merkle root", confirmed.clone(), Inputs {
            bitcoin: Some(json!({"900000": header_json(&sha256(b"another block").0)})),
            ..none()
        }),
        ("schema", "the pack holds no records (an empty export)", edit(&|p| {
            p["records"] = json!([]);
            p["agent_keys"] = json!([]);
            p["anchors"] = json!([]);
            p["heads"] = json!([]);
        }), none()),
        ("content", "stored content was edited after the record was signed", edit(&|p| p["records"][0]["content"]["reason"] = json!("Edited later.")), none()),
        ("content", "the stored content's salt was replaced", edit(&|p| p["records"][0]["salt"] = json!(sample_salt(9))), none()),
        ("content", "stored content without its salt", edit(&|p| {
            p["records"][0].as_object_mut().unwrap().remove("salt");
        }), none()),
        // H2: completeness games by anyone who hands the pack on (the export statement is not re-signed).
        ("head_sig", "the last record was dropped and the export head swapped for the receipt head of the last kept record", edit(&|p| {
            pop(p);
            receipt_head(p, 2);
        }), none()),
        ("head_sig", "the last record was dropped and the filter's to set to 2099, with the client's head", edit(&|p| {
            pop(p);
            p["filter"]["to"] = json!("2099-01-01T00:00:00.000Z");
        }), Inputs { head: Some(head_file(&[final_head.clone()])), ..none() }),
        ("head_sig", "the last record was dropped and the filter's agents set to another agent, so the client's head is skipped", edit(&|p| {
            pop(p);
            receipt_head(p, 2);
            p["filter"]["agents"] = json!(["zz-unrelated"]);
        }), Inputs { head: Some(head_file(&[final_head.clone()])), ..none() }),
        ("chain", "seq 1 to 3 were dropped and the filter's from set to 1970", edit(&|p| {
            p["records"].as_array_mut().unwrap().drain(0..3);
            p["filter"]["from"] = json!("1970-01-01T00:00:00.000Z");
        }), none()),
        ("head_sig", "with a from filter, a whole agent's records were dropped", {
            let mut p = two_from.clone();
            p["records"].as_array_mut().unwrap().pop();
            p
        }, two_agents()),
        // The export statement itself.
        ("head_sig", "export_sig was made with a key that is not the service's", edit(&|p| {
            let st: Pack = from_value(p).unwrap();
            p["export_sig"] = json!(other.sign(Domain::Export, &st.statement().unwrap().hash().unwrap()));
        }), none()),
        ("head_sig", "generated was changed after the service signed the export", edit(&|p| p["generated"] = json!("2026-11-13T13:00:00.000Z")), none()),
        ("head_sig", "project_name was changed after the service signed the export", edit(&|p| {
            p["project_name"] = json!("claims automation");
            sign_export(p);
            p["project_name"] = json!("someone else's project");
        }), none()),
        // What the service signs must still hold together.
        ("chain", "the service signed an export whose from filter is before the agent's first key, and the chain starts at seq 4", signed(&|p| {
            p["records"].as_array_mut().unwrap().drain(0..3);
            p["filter"]["from"] = json!("2026-11-13T08:00:00.000Z");
        }), none()),
        ("head_sig", "the service signed an export holding a record outside its filter", signed(&|p| p["filter"]["to"] = json!("2026-11-13T10:04:00.000Z")), none()),
        ("head_sig", "the service signed an export head newer than the pack's generated time", signed(&|p| p["generated"] = json!("2026-11-13T10:04:59.000Z")), none()),
        ("head_sig", "the service signed an export head for an agent with no records in the pack", signed(&|p| {
            let h = signed_head("agent-z", 1, sha256(b"agent-z"), "2026-11-13T10:05:00.000Z");
            p["heads"].as_array_mut().unwrap().push(json!(h));
        }), none()),
        ("head_sig", "the service signed an export cut at the end whose to filter is more than 300 s after the head", signed(&|p| {
            pop(p);
            p["filter"]["to"] = json!("2026-11-13T10:20:00.000Z");
        }), Inputs { head: Some(head_file(&[final_head.clone()])), ..none() }),
        // Key retirement (§2.5): the customer's manifest ends the key.
        ("record_sig", "seq 4 was signed after the agent's key was retired (the customer's manifest)", valid.clone(), retired_at("2026-11-13T10:04:00.000Z")),
        // Encoding edges every verifier must treat alike.
        ("schema", "generated is in year 0000", edit(&|p| p["generated"] = json!("0000-01-01T00:00:00.000Z")), none()),
        ("schema", "filter.agents holds an agent name with a trailing newline", edit(&|p| p["filter"]["agents"] = json!(["agent-a\n"])), none()),
        ("drand", "batch 1 claims a drand round far beyond any protocol time", build(Build::HugeRound).pack, none()),
    ]
}

/// Packs and inputs that must pass, with the expected check values.
pub fn variants() -> Vec<(&'static str, Value, Inputs)> {
    let fx = valid_fixture();
    let valid = fx.pack.clone();
    let none = Inputs::default;
    let root = fx.anchor.anchor.root;
    let confirmed = build(Build::Confirmed).pack;
    let _ = root;
    let signed = |f: &dyn Fn(&mut Value)| {
        let mut p = valid.clone();
        f(&mut p);
        sign_export(&mut p);
        p
    };
    let from = signed(&|p| {
        p["records"].as_array_mut().unwrap().remove(0);
        p["filter"]["from"] = json!("2026-11-13T10:00:00.500Z");
    });
    let to = signed(&|p| {
        p["records"].as_array_mut().unwrap().pop();
        p["filter"]["to"] = json!("2026-11-13T10:04:00.000Z");
    });
    let last = &fx.receipts[3];
    let client_head = || Some(head_file(&[SignedHead { head: last.head.clone(), head_sig: last.head_sig.clone() }]));
    let confirmed_root = confirmed_block_root(&build(Build::Confirmed).anchor.anchor.hash().unwrap());
    let mut two = build(Build::TwoAgents).pack;
    two["filter"]["from"] = json!("2026-11-13T09:30:00.000Z");
    sign_export(&mut two);
    let two_agents = Inputs {
        agent_keys: Some(json!(AgentKeysDocument {
            format: AGENT_KEYS_FORMAT.into(),
            keys: vec![agent_key_entry(AGENT, &agent_key(), AGENT_KEY_FROM, None), agent_key_entry("agent-b", &agent_key(), AGENT_KEY_FROM, None)],
        })),
        ..none()
    };
    let unanchored = signed(&|p| {
        p["anchors"] = json!([]);
        p["generated"] = json!("2026-11-13T13:00:00.000Z");
    });
    let named = signed(&|p| {
        p["project_name"] = json!("claims automation");
    });
    let not_yet_anchored = signed(&|p| {
        p["anchors"] = json!([]);
    });
    let instance_start = build(Build::InstanceStart).pack;
    vec![
        ("independent service and agent keys, offline", valid.clone(), none()),
        ("young batches no anchor covers yet: anchors and public timestamp pending", not_yet_anchored, none()),
        ("a pack that names its project (signed in the export statement)", named, none()),
        ("agent keys from the pack, trusted explicitly", valid.clone(), Inputs { agent_keys: Some(Value::Null), trust_embedded_agent_keys: true, ..none() }),
        ("a confirmed proof checked against its block header", confirmed.clone(), Inputs { bitcoin: Some(json!({"900000": header_json(&confirmed_root)})), ..none() }),
        ("a confirmed proof, offline", confirmed.clone(), none()),
        ("a block header that does not meet its own proof of work is not trusted: not checked", confirmed.clone(), Inputs {
            bitcoin: Some(json!({"900000": header_without_work_json(&confirmed_root)})),
            ..none()
        }),
        ("a block header that does not hash to the block it was served for is not trusted: not checked", confirmed, Inputs {
            bitcoin: Some({
                let mut h = header_json(&confirmed_root);
                h["hash"] = json!(sha256(b"another block").hex());
                json!({"900000": h})
            }),
            ..none()
        }),
        ("an export from a time: the chain starts mid-way", from, none()),
        ("an export up to a time: the chain ends before the head", to.clone(), none()),
        ("an export up to a time, with the client's head after it", to, Inputs { head: client_head(), ..none() }),
        ("the client's head file matches the pack", valid.clone(), Inputs { head: client_head(), ..none() }),
        ("two agents, exported from a time", two, two_agents),
        ("a retired key's records from before its retirement (the customer's manifest)", valid.clone(), Inputs {
            agent_keys: Some(json!(AgentKeysDocument {
                format: AGENT_KEYS_FORMAT.into(),
                keys: vec![agent_key_entry(AGENT, &agent_key(), AGENT_KEY_FROM, Some("2026-11-13T10:05:30.000Z"))],
            })),
            ..none()
        }),
        ("batches older than the anchor window that no anchor covers: not timestamped", unanchored, none()),
        ("checked by the service with its own key registry", valid.clone(), Inputs { agent_keys: Some(Value::Null), by_service: true, ..none() }),
        ("service keys fetched over plain http from a local address", valid, Inputs { service_keys_plain_http: true, ..none() }),
        ("a new instance continued the chain after seq 2 (an instance-start note)", instance_start, none()),
    ]
}

/// §2.2 monotonic time: the client's time for a new record, from its clock, the previous record's
/// time and the key's valid_from (`time::clamp`).
fn time_clamp_cases() -> Vec<Value> {
    let cases: [(&str, &str, Option<&str>, Option<&str>); 5] = [
        ("clock ahead of the previous record", "2026-11-13T10:00:10.000Z", Some("2026-11-13T10:00:05.000Z"), Some("2026-11-13T09:00:00.000Z")),
        ("clock stepped back 5 s", "2026-11-13T10:00:00.000Z", Some("2026-11-13T10:00:05.000Z"), Some("2026-11-13T09:00:00.000Z")),
        ("same millisecond as the previous record", "2026-11-13T10:00:05.000Z", Some("2026-11-13T10:00:05.000Z"), None),
        ("first record, clock before the key was made", "2026-11-13T09:59:59.999Z", None, Some("2026-11-13T10:00:00.000Z")),
        ("first record, nothing to clamp to", "2026-11-13T10:00:00.000Z", None, None),
    ];
    cases
        .iter()
        .map(|(name, wall, prev, from)| {
            let (t, raised) = time::clamp(wall, *prev, *from).unwrap();
            json!({"name": name, "wall": wall, "prev": prev, "valid_from": from, "time": t, "raised": raised})
        })
        .collect()
}

fn expected(report: &verify::Report) -> Value {
    let mut checks = serde_json::Map::new();
    for c in &report.checks {
        checks.insert(c.id.into(), json!(c.value.clone().unwrap_or_else(|| serde_json::to_value(c.status).unwrap().as_str().unwrap().to_string())));
    }
    json!({"result": report.result, "result_line": report.result_line(), "checks": checks})
}

fn jcs_cases() -> Vec<Value> {
    let ok = [
        ("literals", r#"[null,true,false]"#),
        ("empty containers", r#"{"a":{},"b":[]}"#),
        ("key order by UTF-16 code units (RFC 8785 3.2.3)", r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#),
        ("nested sorting", r#"{"b":[{"z":1,"a":2}],"a":{"d":4,"c":3}}"#),
        ("short escapes", r#""\b\t\n\f\r\"\\""#),
        ("other control characters", r#""\u0000\u0001\u001f""#),
        ("not escaped: solidus, DEL, U+2028, non-ASCII", r#""/\u007f\u2028é\u00e9😀 ""#),
        ("surrogate pair escape becomes the character", r#""\ud83d\ude00""#),
        ("RFC 8785 3.2.2.3 numbers", r#"[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]"#),
        ("zero and negative zero", r#"[0,-0,0.0,-0.0]"#),
        ("integers", r#"[1,-1,1.0,100,9007199254740991,-9007199254740991]"#),
        ("decimal fractions", r#"[0.1,0.5,1.5,-1.5,123.456]"#),
        ("exponent boundaries", r#"[1e20,1e21,1e-6,1e-7,1.2345678901234568e20,0.000001234,100000000000000000000.0]"#),
        ("extremes", r#"[5e-324,1.7976931348623157e308,-1.7976931348623157e308,2.2250738585072014e-308]"#),
        ("float literals beyond 2^53 are doubles", r#"[9007199254740993.0,1e300]"#),
        ("an integer-valued float literal at 2^53 is a double", r#"[9007199254740992.0,-9007199254740992.0]"#),
        ("exponent literals are doubles, even when integral", r#"[1E2,1e0,25e-1,1E+21]"#),
        ("float literals of integers inside objects", r#"{"a":1.0,"b":{"c":[2.50,-0.0]}}"#),
        ("RFC 8785 appendix sample", r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#),
    ];
    let mut out: Vec<Value> = ok
        .iter()
        .map(|(name, input)| json!({"name": name, "input": input, "output": jcs::canonicalize_str(input).unwrap()}))
        .collect();
    for (name, input) in [
        ("integer 2^53 is rejected", "9007199254740992"),
        ("integer -2^53 is rejected", "-9007199254740992"),
        ("integer 2^53+1 is rejected", "[9007199254740993]"),
        ("integer 2^64-1 is rejected", "18446744073709551615"),
        ("integer literal 123456789012345680000 is rejected", "123456789012345680000"),
        ("an unsafe integer nested in an object is rejected", r#"{"a":{"b":[1,123456789012345678901]}}"#),
        ("integer 2^53+2 next to a safe one is rejected", "[9007199254740991,9007199254740994]"),
    ] {
        assert!(jcs::canonicalize_str(input).is_err());
        out.push(json!({"name": name, "input": input, "error": "unsafe_integer", "exact_integer_only": true}));
    }
    for (name, input) in [("1e400 overflows a double", "[1e400]"), ("-1e400 overflows a double", "-1e400")] {
        assert!(jcs::canonicalize_str(input).is_err());
        out.push(json!({"name": name, "input": input, "error": "number_out_of_range"}));
    }
    out
}

fn key_json(name: &str, seed_start: u8, k: &Keypair) -> Value {
    json!({"name": name, "seed_hex": hex::encode(seed(seed_start)), "public_key": k.public_key_b64(), "key_id": k.key_id()})
}

type Mutation = Box<dyn Fn(&mut Value)>;

fn invalid_envelopes(valid: &Value) -> Vec<Value> {
    let cases: Vec<(&str, Mutation)> = vec![
        ("unknown field", Box::new(|e| e["extra"] = json!(true))),
        ("missing ref", Box::new(|e| { e.as_object_mut().unwrap().remove("ref"); })),
        ("missing prev", Box::new(|e| { e.as_object_mut().unwrap().remove("prev"); })),
        ("v is 2", Box::new(|e| e["v"] = json!(2))),
        ("unknown kind", Box::new(|e| e["kind"] = json!("action"))),
        ("seq is 0", Box::new(|e| e["seq"] = json!(0))),
        ("seq is a float", Box::new(|e| e["seq"] = json!(1.5))),
        ("seq is the float literal 1.0", Box::new(|e| e["seq"] = serde_json::from_str("1.0").unwrap())),
        ("seq is an unsafe integer", Box::new(|e| e["seq"] = json!(9_007_199_254_740_992u64))),
        ("missing project", Box::new(|e| { e.as_object_mut().unwrap().remove("project"); })),
        ("project is not a project id", Box::new(|e| e["project"] = json!("prj_lowercase"))),
        ("env is not test or live", Box::new(|e| e["env"] = json!("prod"))),
        ("prev set at seq 1", Box::new(|e| e["prev"] = json!(sha256(b"p").hex()))),
        ("prev null at seq 2", Box::new(|e| e["seq"] = json!(2))),
        ("agent has uppercase", Box::new(|e| e["agent"] = json!("Agent-A"))),
        ("agent starts with a dot", Box::new(|e| e["agent"] = json!(".agent"))),
        ("agent ends with a newline", Box::new(|e| e["agent"] = json!("agent-a\n"))),
        ("time without milliseconds", Box::new(|e| e["time"] = json!("2026-11-13T10:00:00Z"))),
        ("time with offset", Box::new(|e| e["time"] = json!("2026-11-13T10:00:00.000+01:00"))),
        ("empty name", Box::new(|e| e["name"] = json!(""))),
        ("name of 129 characters", Box::new(|e| e["name"] = json!("x".repeat(129)))),
        ("uppercase hex", Box::new(|e| e["content_hash"] = json!(sha256(b"c").hex().to_uppercase()))),
        ("ref on a decision", Box::new(|e| e["ref"] = json!(sha256(b"r").hex()))),
        ("outcome without ref", Box::new(|e| e["kind"] = json!("outcome"))),
    ];
    cases
        .into_iter()
        .map(|(name, f)| {
            let mut e = valid.clone();
            f(&mut e);
            assert!(Envelope::parse(&e).is_err(), "{name}");
            json!({"name": name, "envelope": e})
        })
        .collect()
}

/// Every vector, as written to `spec/vectors.json`.
pub fn generate() -> Value {
    let fx = valid_fixture();
    let (ak, sk, ok) = (agent_key(), service_key(), other_key());
    let probe = sha256(b"signafaide");

    let signatures: Vec<Value> = [Domain::Record, Domain::Batch, Domain::Head, Domain::Anchor, Domain::Draft]
        .iter()
        .map(|&d| {
            json!({"domain": d.as_str(), "key": "service", "hash": probe.hex(),
                   "message_hex": hex::encode(sign::message(d, &probe)), "sig": sk.sign(d, &probe)})
        })
        .collect();
    let record_sig = sk.sign(Domain::Record, &probe);
    let cross_domain: Vec<Value> = ["batch", "head", "anchor", "draft"]
        .iter()
        .map(|d| json!({"sig_domain": "record", "verify_domain": d, "key": "service", "hash": probe.hex(), "sig": record_sig, "valid": false}))
        .collect();

    let records: Vec<Value> = fx
        .records
        .iter()
        .zip(sample_contents())
        .enumerate()
        .map(|(i, ((r, h), (_, _, _, content, store)))| {
            let ev = serde_json::to_value(&r.envelope).unwrap();
            json!({
                "content": content,
                "content_jcs": jcs::canonicalize(&content).unwrap(),
                "salt": sample_salt(i),
                "content_hash": r.envelope.content_hash,
                "stored": store,
                "envelope": ev,
                "envelope_jcs": jcs::canonicalize(&ev).unwrap(),
                "record_hash": h,
                "key_id": r.key_id,
                "sig": r.sig,
            })
        })
        .collect();

    let trees: Vec<Value> = (1..=7usize)
        .map(|n| {
            let items: Vec<Hash> = (0..n).map(|i| sha256(format!("item-{i}").as_bytes())).collect();
            let t = Tree::new(&items).unwrap();
            json!({
                "items": items,
                "leaf_hashes": items.iter().map(merkle::leaf_hash).collect::<Vec<_>>(),
                "root": t.root(),
                "paths": (0..n).map(|i| t.path(i)).collect::<Vec<_>>(),
            })
        })
        .collect();

    let (b1, b1h, b1sig) = &fx.batches[0];
    let b1v = serde_json::to_value(b1).unwrap();
    let rc0 = &fx.receipts[0];
    let headv = serde_json::to_value(&rc0.head).unwrap();
    let anchor = &fx.anchor.anchor;
    let anchor_core = serde_json::to_value(anchor.core()).unwrap();
    let root = anchor.root;

    let defaults = json!({"keys_document": {"keys": [service_key_entry()]}, "agent_keys_document": agent_keys_document()});
    let report = verify::verify_pack(&fx.pack, &Inputs::options(&json!({}), &defaults)).unwrap();
    assert!(report.passed(), "{}", report.to_text());
    let tampered: Vec<Value> = tampered_packs()
        .into_iter()
        .map(|(check, what, pack, inputs)| {
            let mut t = json!({"check": check, "tamper": what, "first_failed": check, "pack": pack});
            inputs.to_json(&mut t);
            let r = verify::verify_pack(&t["pack"], &Inputs::options(&t, &defaults)).unwrap();
            assert_eq!(r.first_failed(), Some(check), "{what}\n{}", r.to_text());
            t
        })
        .collect();
    let variants: Vec<Value> = variants()
        .into_iter()
        .map(|(name, pack, inputs)| {
            let mut t = json!({"name": name, "pack": pack});
            inputs.to_json(&mut t);
            let r = verify::verify_pack(&t["pack"], &Inputs::options(&t, &defaults)).unwrap();
            assert!(r.passed(), "{name}\n{}", r.to_text());
            t["expect"] = expected(&r);
            // The instance-start note (§7 check 4) is part of the expected chain detail.
            if let Some(n) = r.checks[3].detail.split("; ").find(|n| n.starts_with(INSTANCE_NOTE)) {
                t["expect"]["chain_note"] = json!(n);
            }
            t
        })
        .collect();
    let pk: Pack = from_value(&fx.pack).unwrap();
    let st = pk.statement().unwrap();
    let export_statement = serde_json::to_value(&st).unwrap();
    let export_records_hash = st.records_hash;
    let export_hash = st.hash().unwrap();
    let registration = Registration { project: PROJECT.into(), env: Env::Live, agent: AGENT.into(), public_key: ak.public_key_b64(), valid_from: AGENT_KEY_FROM.into() };
    let rv = serde_json::to_value(&registration).unwrap();
    let rh = registration.hash().unwrap();
    let keys_created = "2026-11-13T11:00:00.000Z";
    let two_keys = vec![
        KeyEntry { key_id: ok.key_id(), public_key: ok.public_key_b64(), valid_from: "2026-12-01T00:00:00.000Z".into(), valid_to: None },
        service_key_entry(),
    ];

    json!({
        "spec": "signafaide/v1",
        "about": "Generated by signafaide-core (cargo run --bin gen-vectors). Every implementation must reproduce these values byte for byte. Strings named *_jcs are the exact canonical UTF-8 text. A tampered entry's or variant's inputs: keys, agent_keys (null: none), trust_embedded_agent_keys, head, bitcoin (height -> {hash, header} as an explorer serves them), by_service, service_keys_plain_http.",
        "jcs": jcs_cases(),
        "jcs_note": "Numbers are judged by their literal: an integer literal (no fraction, no exponent) beyond ±(2^53-1) is rejected; every other literal is a double. Entries with exact_integer_only need a parser that keeps integer literals (Python json, a BigInt-aware JS parser); plain JSON.parse cannot run them. A JavaScript SDK canonicalizing its own values rejects integer-valued numbers with 2^53 <= |x| < 1e21, because JSON.stringify writes those as integer literals.",
        "sha256": [
            {"utf8": "", "hex": sha256(b"").hex()},
            {"utf8": "abc", "hex": sha256(b"abc").hex()},
            {"utf8": "signafaide", "hex": probe.hex()},
        ],
        "time": [
            {"input": "2026-11-13T10:00:00.000Z", "unix_ms": time::parse("2026-11-13T10:00:00.000Z").unwrap()},
            {"input": "2024-02-29T23:59:59.999Z", "unix_ms": time::parse("2024-02-29T23:59:59.999Z").unwrap()},
            {"input": "2026-11-13T10:00:00Z", "error": "invalid_time"},
            {"input": "2025-02-29T00:00:00.000Z", "error": "invalid_time"},
            {"input": "2026-11-13T10:00:00.000+00:00", "error": "invalid_time"},
            {"input": "0000-01-01T00:00:00.000Z", "error": "invalid_time"},
        ],
        "time_clamp": time_clamp_cases(),
        "agent_names": {
            "valid": ["a", "agent-a", "billing.bot_2", "0", "a".repeat(64)],
            "invalid": ["", "Agent", "-a", ".a", "_a", "a b", "a/b", "a".repeat(65), "a\n", "agent-a\n"],
        },
        "project_ids": {"valid": [PROJECT], "invalid": ["prj_01jczq8z5x3v7n2m4k6h8g0f1d", "prj_01JCZQ8Z5X3V7N2M4K6H8G0F1", "prj_81JCZQ8Z5X3V7N2M4K6H8G0F1D", "prj_01JCZQ8Z5X3V7N2M4K6H8G0F1U"]},
        "keys": [key_json("agent", 0x00, &ak), key_json("service", 0x20, &sk), key_json("other", 0x40, &ok)],
        "signatures": signatures,
        "cross_domain": cross_domain,
        "records": records,
        "invalid_envelopes": invalid_envelopes(&serde_json::to_value(&fx.records[0].0.envelope).unwrap()),
        "merkle": {"trees": trees},
        "batch": {
            "batch": b1v,
            "batch_jcs": jcs::canonicalize(&b1v).unwrap(),
            "batch_hash": b1h,
            "batch_sig": b1sig,
            "record_hashes": fx.records[..3].iter().map(|r| r.1).collect::<Vec<_>>(),
            "root": b1.root,
            "proofs": fx.receipts[..3].iter().map(|r| json!({"index": r.index, "proof": r.proof})).collect::<Vec<_>>(),
        },
        "head": {"head": headv, "head_jcs": jcs::canonicalize(&headv).unwrap(), "head_hash": rc0.head.hash().unwrap(), "head_sig": rc0.head_sig},
        "receipts": fx.receipts,
        "anchor": {
            "anchor": anchor,
            "signed_part_jcs": jcs::canonicalize(&anchor_core).unwrap(),
            "anchor_hash": anchor.hash().unwrap(),
            "anchor_sig": fx.anchor.anchor_sig,
            "paths": fx.anchor.paths,
        },
        "ots": [
            {"name": "pending (calendar promise)", "digest": root, "base64": STANDARD.encode(pending_ots(&root)), "status": "pending", "calendars": [CALENDAR]},
            {"name": "confirmed (synthetic Bitcoin attestation)", "digest": root, "base64": STANDARD.encode(confirmed_ots(&root, 900_000)), "status": "confirmed@900000",
             "bitcoin": [{"height": 900_000, "merkle_root": confirmed_block_root_display(&root)}]},
            {"name": "more operations and attestations than allowed", "digest": root, "base64": STANDARD.encode(oversized_ots(&root)), "error": "ots_limit"},
        ],
        "ots_limits": {"max_proof_bytes": crate::ots::MAX_PROOF_BYTES, "max_nodes": crate::ots::MAX_NODES},
        "drand": [
            {"beacon": drand_round_123(), "valid": true},
            {"beacon": drand_vector_round(), "valid": true},
            {"beacon": {"chain": drand::QUICKNET_CHAIN, "round": 124, "randomness": drand_round_123().randomness, "signature": drand_round_123().signature}, "valid": false},
        ],
        "drand_time": [
            {"round": 33_920_212, "server_time": "2026-11-13T10:00:01.250Z", "valid": true},
            {"round": 33_920_212, "server_time": "2026-11-13T10:02:00.000Z", "valid": true},
            {"round": 33_920_212, "server_time": "2026-11-13T10:02:00.001Z", "valid": false},
            {"round": 33_920_212, "server_time": "2026-11-13T09:59:59.999Z", "valid": false},
            {"round": 4_000_000_000_000_000u64, "server_time": "2026-11-13T10:00:00.000Z", "valid": false},
            {"round": 0, "server_time": "2026-11-13T10:00:00.000Z", "valid": false},
        ],
        "keys_document": {"keys": [service_key_entry()]},
        "agent_keys_document": agent_keys_document(),
        "registration": {
            "registration": rv,
            "registration_jcs": jcs::canonicalize(&rv).unwrap(),
            "registration_hash": rh,
            "proof": ak.sign(Domain::Register, &rh),
            "rotation": {"key": "other", "key_id": ok.key_id(), "sig": ok.sign(Domain::Rotate, &rh)},
        },
        "keys_hash": {
            "keys": two_keys,
            "created": keys_created,
            "committed_jcs": jcs::canonicalize(&json!([{"key_id": service_key_entry().key_id, "public_key": service_key_entry().public_key, "valid_from": SERVICE_KEY_FROM}])).unwrap(),
            "keys_hash": service_keys_hash(&two_keys, time::parse(keys_created).unwrap()).unwrap(),
        },
        "max_clock_skew_ms": verify::MAX_CLOCK_SKEW_MS,
        "anchor_window_ms": verify::ANCHOR_WINDOW_MS,
        "drand_max_round": drand::MAX_ROUND,
        "export": {
            "statement": export_statement,
            "statement_jcs": jcs::canonicalize(&export_statement).unwrap(),
            "records_hash": export_records_hash,
            "statement_hash": export_hash,
            "export_sig": fx.pack["export_sig"],
            "result_line": report.result_line(),
        },
        "block_headers": [
            {"name": "Bitcoin's genesis block", "hash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
             "header": "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
             "merkle_root": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "valid": true},
            {"name": "the genesis header with its nonce changed", "hash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
             "header": "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7d", "valid": false},
            {"name": "a header without the work its nBits claims", "hash": header_without_work_json(&[7; 32])["hash"], "header": header_without_work_json(&[7; 32])["header"], "valid": false},
        ],
        "pack": {"pack": fx.pack, "expect": expected(&report)},
        "tampered": tampered,
        "variants": variants,
        "check_ids": CHECKS.iter().map(|c| c.0).collect::<Vec<_>>(),
    })
}
