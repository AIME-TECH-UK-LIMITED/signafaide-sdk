//! Service key documents (spec §5, §7): the one loader every Rust verifier uses, and the
//! cross-check of a release's pinned keys against the published list. The vectors'
//! `key_lifecycle.cross_check` cases are made by `cross_check`, and every other implementation
//! (the npm command, "Verify in your browser") must give the same results.

use crate::hash::Hash;
use crate::sign::Domain;
use crate::{Error, KeyEntry, KeysDocument, Result};
use serde_json::{json, Value};

/// The whole key list of a keys document (every key, revoked ones too, as the anchors' `keys_hash`
/// covers them) and the ids of the revoked keys (no signature by one of them verifies). Each key
/// entry is validated; a revoked entry needs only `key_id` (`revoked_at` and `reason` null or strings).
pub fn load(text: &str) -> Result<(Vec<KeyEntry>, Vec<String>)> {
    let v: Value = serde_json::from_str(text).map_err(|e| Error::new(format!("keys: {e}")))?;
    let doc: KeysDocument = serde_json::from_value(v).map_err(|e| Error::new(format!("keys: {e}")))?;
    for k in &doc.keys {
        k.validate().map_err(|e| Error::new(format!("keys: {e}")))?;
    }
    Ok((doc.keys, doc.revoked.into_iter().map(|r| r.key_id).collect()))
}

/// What the cross-check found when the pinned keys are all in the published list unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossChecked {
    /// Keys listed there that this release does not pin.
    pub newer: Vec<String>,
    /// Pinned keys retired there (or earlier there than pinned): (key id, the valid_to applied).
    pub retired: Vec<(String, String)>,
    /// Pinned keys revoked there and not already revoked in the pinned file (named on the keys line).
    pub revoked: Vec<String>,
    /// The keys document to verify with: the pinned keys with the retirements applied, and
    /// `revoked` the union of the pinned file's and the published list's revoked ids.
    pub keys_document: Value,
}

/// The published list against the pinned keys. Outer `Err`: the published list cannot be read
/// (not JSON, not `{"keys": [...]}`), so the pinned keys are used, not cross-checked. Inner `Err`:
/// the problems that make it KEYS DIFFER (a pinned key missing or changed, an invalid `valid_to` on
/// a pinned key's entry, a malformed `revoked`).
pub fn cross_check(pinned_text: &str, published: &str) -> Result<std::result::Result<CrossChecked, Vec<String>>> {
    let doc: Value = serde_json::from_str(published).map_err(|e| Error::new(format!("not JSON: {e}")))?;
    let listed = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| Error::new("not {\"keys\": [...]}"))?;
    let field = |k: &Value, f: &str| k.get(f).and_then(|v| v.as_str()).map(String::from);
    let entry = |x: &Value| {
        x.is_object()
            && field(x, "key_id").is_some()
            && ["revoked_at", "reason"]
                .iter()
                .all(|f| x.get(*f).is_none_or(|v| v.is_null() || v.is_string()))
    };
    let revoked: Vec<String> = match doc.get("revoked") {
        None => Vec::new(),
        Some(Value::Array(r)) if r.iter().all(entry) => r.iter().filter_map(|x| field(x, "key_id")).collect(),
        Some(_) => return Ok(Err(vec!["its `revoked` is not a list of entries with a key_id".into()])),
    };
    let (pinned, pinned_revoked) = load(pinned_text)?;
    let mut pinned_doc: Value = serde_json::from_str(pinned_text).map_err(|e| Error::new(e.to_string()))?;
    let mut problems = Vec::new();
    let mut retired = Vec::new();
    for (i, p) in pinned.iter().enumerate() {
        let Some(k) = listed
            .iter()
            .find(|k| field(k, "key_id").as_deref() == Some(p.key_id.as_str()))
        else {
            problems.push(format!("{} is not in the published list", p.key_id));
            continue;
        };
        if field(k, "public_key").as_deref() != Some(p.public_key.as_str()) {
            problems.push(format!("{} has another public key there", p.key_id));
        } else if field(k, "valid_from").as_deref() != Some(p.valid_from.as_str()) {
            problems.push(format!("{} has another valid_from there", p.key_id));
        } else if let Some(v) = k.get("valid_to").filter(|v| !v.is_null()) {
            // A valid_to that is not a protocol time string makes the document malformed (§7).
            let Some(to_ms) = v.as_str().and_then(|t| crate::time::parse(t).ok()) else {
                problems.push(format!("{} has an invalid valid_to there", p.key_id));
                continue;
            };
            let to = v.as_str().unwrap().to_string();
            // The earlier of the two retirements applies (a later one there never widens the pin).
            let earlier = match &p.valid_to {
                Some(mine) => crate::time::parse(mine)? > to_ms,
                None => true,
            };
            if earlier {
                pinned_doc["keys"][i]["valid_to"] = Value::String(to.clone());
                retired.push((p.key_id.clone(), to));
            }
        }
    }
    if !problems.is_empty() {
        return Ok(Err(problems));
    }
    let named: Vec<String> = pinned
        .iter()
        .filter(|p| revoked.contains(&p.key_id) && !pinned_revoked.contains(&p.key_id))
        .map(|p| p.key_id.clone())
        .collect();
    let mut applied = pinned_revoked.clone();
    for id in &revoked {
        if !applied.contains(id) {
            applied.push(id.clone());
        }
    }
    pinned_doc["revoked"] = Value::Array(applied.iter().map(|id| json!({ "key_id": id })).collect());
    let newer = listed
        .iter()
        .filter_map(|k| field(k, "key_id"))
        .filter(|id| !pinned.iter().any(|p| &p.key_id == id))
        .collect();
    Ok(Ok(CrossChecked {
        newer,
        retired,
        revoked: named,
        keys_document: pinned_doc,
    }))
}

/// A cross-check's outcome as the vectors hold it: `{"unreadable": true}`, `{"differ": [...]}`, or
/// `{"newer", "retired", "revoked", "keys", "applied_revoked"}`.
pub fn cross_check_json(pinned_text: &str, published: &str) -> Value {
    match cross_check(pinned_text, published) {
        Err(_) => json!({"unreadable": true}),
        Ok(Err(problems)) => json!({"differ": problems}),
        Ok(Ok(c)) => {
            let (keys, applied) = load(&c.keys_document.to_string()).expect("the pinned keys load");
            json!({"newer": c.newer, "retired": c.retired, "revoked": c.revoked, "keys": keys, "applied_revoked": applied})
        }
    }
}

/// Which service key may verify a signature made at `at` (spec §5), judged in the one order every
/// implementation uses: `unknown_key`, `revoked`, `not_active` (outside valid_from..valid_to).
pub fn key_status<'a>(
    keys: &'a [KeyEntry],
    revoked: &[String],
    key_id: &str,
    at: &str,
) -> std::result::Result<&'a KeyEntry, &'static str> {
    let k = keys.iter().find(|k| k.key_id == key_id).ok_or("unknown_key")?;
    if revoked.iter().any(|r| r == key_id) {
        return Err("revoked");
    }
    match crate::time::parse(at) {
        Ok(t) if crate::key_active(&k.valid_from, k.valid_to.as_deref(), t) => Ok(k),
        _ => Err("not_active"),
    }
}

/// One service key signature judged (spec §5): `key_status`, then the signature (`signature`);
/// `None` when it verifies. The verifier, the tool-call checks (rule sets, the shared list, rulings)
/// and the vectors all use this.
pub fn key_problem(
    keys: &[KeyEntry],
    revoked: &[String],
    key_id: &str,
    at: &str,
    domain: Domain,
    hash: &Hash,
    sig: &str,
) -> Option<&'static str> {
    match key_status(keys, revoked, key_id, at) {
        Err(why) => Some(why),
        Ok(k) => crate::sign::verify(&k.public_key, domain, hash, sig)
            .err()
            .map(|_| "signature"),
    }
}

/// Whether any service key verifies a signature made at `at` that names no key (heads, exports,
/// anchors): a key not revoked, active at `at`, whose signature it is (spec §5).
pub fn any_key_verifies(
    keys: &[KeyEntry],
    revoked: &[String],
    at: &str,
    domain: Domain,
    hash: &Hash,
    sig: &str,
) -> bool {
    let Ok(t) = crate::time::parse(at) else { return false };
    keys.iter().any(|k| {
        !revoked.iter().any(|r| r == &k.key_id)
            && crate::key_active(&k.valid_from, k.valid_to.as_deref(), t)
            && crate::sign::verify(&k.public_key, domain, hash, sig).is_ok()
    })
}
