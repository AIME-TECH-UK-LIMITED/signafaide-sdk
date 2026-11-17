//! The shared fingerprint list (§11.2): numbered, hash-chained updates and snapshots, each
//! carrying the `state_hash` of the whole list after it, signed over domain `fingerprints`.

use serde_json::{json, Value};
use crate::{jcs, sha256};
use std::collections::BTreeSet;

pub const FORMAT: &str = "signafaide-fingerprints/1";
/// An update adds and removes at most this many entries in all (§11.2).
pub const MAX_CHANGES: usize = 10_000;

/// A list entry, ordered by kind, then fingerprint (Unicode code point order).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    pub kind: String,
    pub fingerprint: String,
}

impl Entry {
    pub fn parse(v: &Value) -> Result<Entry, String> {
        let o = v.as_object().filter(|o| o.len() == 2).ok_or("an entry is {kind, fingerprint}")?;
        let kind = o.get("kind").and_then(Value::as_str).filter(|k| matches!(*k, "tool" | "description" | "server")).ok_or("kind is tool, description or server")?;
        if !o.get("fingerprint").is_some_and(super::is_hex64) {
            return Err("fingerprint is 64 lowercase hex characters".into());
        }
        Ok(Entry { kind: kind.into(), fingerprint: o["fingerprint"].as_str().unwrap().into() })
    }

    pub fn json(&self) -> Value {
        json!({"kind": self.kind, "fingerprint": self.fingerprint})
    }
}

fn list(entries: &BTreeSet<Entry>) -> Vec<Value> {
    entries.iter().map(Entry::json).collect()
}

/// `sha256(JCS(the whole list))`, entries in order (§11.2).
pub fn state_hash(entries: &BTreeSet<Entry>) -> String {
    sha256(jcs::canonicalize(&Value::Array(list(entries))).expect("plain strings").as_bytes()).hex()
}

/// `list_hash = sha256(JCS(object))`.
pub fn list_hash(doc: &Value) -> String {
    sha256(jcs::canonicalize(doc).expect("plain strings").as_bytes()).hex()
}

/// Update `seq` after `prev` (the `list_hash` of update seq − 1, or None for update 1), applied to
/// `held`. Adds only entries the list does not hold and removes only entries it holds (§11.2).
/// Returns the document and the list after it.
pub fn update(held: &BTreeSet<Entry>, seq: i64, prev: Option<&str>, issued: &str, add: &[Entry], remove: &[Entry]) -> Result<(Value, BTreeSet<Entry>), String> {
    let (add, remove): (BTreeSet<Entry>, BTreeSet<Entry>) = (add.iter().cloned().collect(), remove.iter().cloned().collect());
    if add.is_empty() && remove.is_empty() {
        return Err("an update adds or removes at least one entry".into());
    }
    if add.len() + remove.len() > MAX_CHANGES {
        return Err(format!("an update changes at most {MAX_CHANGES} entries"));
    }
    if let Some(e) = add.iter().find(|e| held.contains(e)) {
        return Err(format!("the list already holds the {} fingerprint {}", e.kind, e.fingerprint));
    }
    if let Some(e) = remove.iter().find(|e| !held.contains(e)) {
        return Err(format!("the list does not hold the {} fingerprint {}", e.kind, e.fingerprint));
    }
    let mut after: BTreeSet<Entry> = held.difference(&remove).cloned().collect();
    after.extend(add.iter().cloned());
    let doc = json!({
        "format": FORMAT, "list": "shared", "type": "update", "seq": seq, "prev": prev,
        "issued": issued, "add": list(&add), "remove": list(&remove), "state_hash": state_hash(&after),
    });
    Ok((doc, after))
}

/// The snapshot of the whole list after update `seq` (`last`: that update's `list_hash`; seq 0
/// and null for the empty list before any update).
pub fn snapshot(entries: &BTreeSet<Entry>, seq: i64, last: Option<&str>, issued: &str) -> Value {
    json!({
        "format": FORMAT, "list": "shared", "type": "snapshot", "seq": seq, "last": last,
        "issued": issued, "entries": list(entries), "state_hash": state_hash(entries),
    })
}

/// What a client holds (§11.2).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Held {
    pub seq: i64,
    pub last: Option<String>,
    pub entries: BTreeSet<Entry>,
}

/// A client's acceptance of one served item (§11.2), without the signature step: the name of
/// the refusal (`state`, `older`, `gap`, `prev`, `invalid`), or the list held after it. The
/// witness uses it to check every list it serves; the clients carry their own copy.
pub fn apply(held: &Held, doc: &Value) -> Result<Held, &'static str> {
    let entries = |k: &str| -> Result<Vec<Entry>, &'static str> { doc[k].as_array().ok_or("invalid")?.iter().map(|e| Entry::parse(e).map_err(|_| "invalid")).collect() };
    let seq = doc["seq"].as_i64().ok_or("invalid")?;
    if doc["type"] == "snapshot" {
        let e: BTreeSet<Entry> = entries("entries")?.into_iter().collect();
        if doc["state_hash"].as_str() != Some(state_hash(&e).as_str()) {
            return Err("state");
        }
        if seq < held.seq {
            return Err("older");
        }
        return Ok(Held { seq, last: doc["last"].as_str().map(String::from), entries: e });
    }
    if seq <= held.seq {
        return Err("older");
    }
    if seq != held.seq + 1 {
        return Err("gap");
    }
    if doc["prev"].as_str() != held.last.as_deref() {
        return Err("prev");
    }
    let (add, remove) = (entries("add")?, entries("remove")?);
    if add.iter().any(|e| held.entries.contains(e)) || remove.iter().any(|e| !held.entries.contains(e)) {
        return Err("invalid");
    }
    let mut after: BTreeSet<Entry> = held.entries.iter().filter(|e| !remove.contains(e)).cloned().collect();
    after.extend(add);
    if doc["state_hash"].as_str() != Some(state_hash(&after).as_str()) {
        return Err("state");
    }
    Ok(Held { seq, last: Some(list_hash(doc)), entries: after })
}

/// A client's acceptance of one item as `GET /v1/fingerprints` serves it (§11.2),
/// `{list, sig, service_key_id}`: first the signature, by a service key active at the item's
/// `issued` (`signature`), then [`apply`].
pub fn accept(held: &Held, item: &Value, service_keys: &[crate::KeyEntry]) -> Result<Held, &'static str> {
    let doc = &item["list"];
    let issued = doc["issued"].as_str().and_then(|t| crate::time::parse(t).ok());
    let key = service_keys.iter().find(|k| Some(k.key_id.as_str()) == item["service_key_id"].as_str());
    let signed = match (key, issued) {
        (Some(k), Some(at)) => {
            crate::key_active(&k.valid_from, k.valid_to.as_deref(), at)
                && crate::hash::hash_json(doc).is_ok_and(|h| crate::sign::verify(&k.public_key, crate::sign::Domain::Fingerprints, &h, item["sig"].as_str().unwrap_or("")).is_ok())
        }
        _ => false,
    };
    if !signed {
        return Err("signature");
    }
    if doc["format"] != FORMAT || doc["list"] != "shared" {
        return Err("invalid");
    }
    apply(held, doc)
}

impl Held {
    /// The held list's `state_hash` (§11.2).
    pub fn state_hash(&self) -> String {
        state_hash(&self.entries)
    }

    /// Whether `fingerprint` is on the list with `kind`.
    pub fn listed(&self, kind: &str, fingerprint: &str) -> bool {
        self.entries.contains(&Entry { kind: kind.into(), fingerprint: fingerprint.into() })
    }
}
