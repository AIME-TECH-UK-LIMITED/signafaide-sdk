//! The envelope field `checks` (§2.8) and the disclosed values beside it (§2.3), as the witness
//! accepts them. Any other key, check id, code or value makes the record `invalid_record`.

use super::{is_hex64, is_pointer, is_rule_id, is_set_id, safe_int, DISCLOSED_MAX_BYTES};
use serde_json::{Map, Value};
use crate::{jcs, Kind};

const DECISION_KEYS: [&str; 10] = ["results", "result", "rules", "fingerprints", "tool", "strict", "fail", "disclosed", "disclosed_hash", "call_id"];
const OUTCOME_KEYS: [&str; 4] = ["ran", "ruling", "results", "result"];
const TOOL_KEYS: [&str; 4] = ["tool", "description", "schema", "server"];

/// The `found` codes of each check (§2.8 table; the secret formats of §8).
fn found_codes(check: &str) -> &'static [&'static str] {
    match check {
        "secret" => &[
            "github_token",
            "aws_access_key",
            "stripe_key",
            "slack_token",
            "anthropic_key",
            "openai_key",
            "google_api_key",
            "signafaide_key",
            "private_key",
            "wallet_private_key",
            "seed_phrase",
            // spec 1.1, benchmark batch 2: secrets known by where they stand (arguments only)
            "bearer_token",
            "jwt",
            "named_secret",
            "card_number",
            "high_entropy",
            "wallet_address",
        ],
        "address" => &["loopback", "private", "shared", "link_local", "unique_local", "unspecified", "metadata", "internal_name"],
        "changed_tool" => &["description_changed", "schema_changed", "not_approved"],
        "fingerprint" => &["tool", "description", "server"],
        "hidden_instruction" => &["invisible_characters", "instruction_phrase", "encoded_content", "tool_shadowing", "look_alike_name", "possible_hidden_instruction"],
        _ => &[],
    }
}

fn rank(result: &str) -> Option<u8> {
    match result {
        "allow" => Some(0),
        "note" => Some(1),
        "block" => Some(2),
        _ => None,
    }
}

fn exact_keys(o: &Map<String, Value>, keys: &[&str], what: &str) -> Result<(), String> {
    if let Some(k) = o.keys().find(|k| !keys.contains(&k.as_str())) {
        return Err(format!("{what} has the unknown key '{k}'"));
    }
    if let Some(k) = keys.iter().find(|k| !o.contains_key(**k)) {
        return Err(format!("{what} lacks the key '{k}'"));
    }
    Ok(())
}

fn str_in<'a>(v: &'a Value, allowed: &[&str]) -> Option<&'a str> {
    v.as_str().filter(|s| allowed.contains(s))
}

/// Validate `checks` of an envelope of `kind` named `name` (§2.8). The message names what is wrong.
pub fn validate(kind: Kind, name: &str, checks: &Value) -> Result<(), String> {
    if !matches!(kind, Kind::Decision | Kind::Outcome) || name.starts_with("signafaide.") {
        return Err("checks is allowed only on a decision or outcome whose name does not start with 'signafaide.'".into());
    }
    let o = checks.as_object().ok_or("checks must be an object")?;
    if kind == Kind::Outcome {
        exact_keys(o, &OUTCOME_KEYS, "the checks of an outcome")?;
        let ran = o["ran"].as_bool().ok_or("checks.ran must be true or false")?;
        let ruling = str_in(&o["ruling"], &["allow", "block", "none", "not_asked"]).ok_or("checks.ruling must be allow, block, none or not_asked")?;
        if ran && ruling == "block" {
            return Err("checks.ran is true but checks.ruling is block: a call ruled block never runs".into());
        }
        let n = results(o, kind)?;
        if !ran && n > 0 {
            return Err("checks.results must be empty when the tool did not run".into());
        }
        return Ok(());
    }
    exact_keys(o, &DECISION_KEYS, "the checks of a decision")?;
    // tool fingerprints (§11.1)
    let t = o["tool"].as_object().ok_or("checks.tool must be an object")?;
    exact_keys(t, &TOOL_KEYS, "checks.tool")?;
    if !["tool", "description", "schema"].iter().all(|k| is_hex64(&t[*k])) || !(t["server"].is_null() || is_hex64(&t["server"])) {
        return Err("checks.tool holds 64-hex fingerprints (server may be null)".into());
    }
    // rule sets applied: at most the project's and the local rules
    let rs = o["rules"].as_array().filter(|a| a.len() <= 2).ok_or("checks.rules must be a list of at most 2 entries")?;
    let (mut local, mut project) = (0, 0);
    for r in rs {
        let r = r.as_object().ok_or("each checks.rules entry is {set, version, hash}")?;
        exact_keys(r, &["set", "version", "hash"], "a checks.rules entry")?;
        if !is_hex64(&r["hash"]) {
            return Err("checks.rules[].hash must be 64 lowercase hex".into());
        }
        match r["set"].as_str() {
            Some("local") if r["version"].is_null() => local += 1,
            Some(s) if is_set_id(s) && safe_int(&r["version"]).is_some_and(|v| v >= 1) => project += 1,
            _ => return Err("checks.rules[] names the project's rule set (rs_..., version 1 or above) or the local rules (local, version null)".into()),
        }
    }
    if local > 1 || project > 1 {
        return Err("checks.rules holds at most one entry for the project's rule set and one for the local rules".into());
    }
    if !(o["fingerprints"].is_null() || safe_int(&o["fingerprints"]).is_some_and(|n| n >= 0)) {
        return Err("checks.fingerprints must be null or the seq of the shared list".into());
    }
    let strict = o["strict"].as_bool().ok_or("checks.strict must be true (Protected) or false (Not protected)")?;
    match (strict, &o["fail"]) {
        (true, f) if str_in(f, &["open", "closed"]).is_some() => {}
        (false, Value::Null) => {}
        _ => return Err("checks.fail is \"open\" (Let it run) or \"closed\" (Stop) when checks.strict is true (Protected), and null otherwise".into()),
    }
    let d = o["disclosed"].as_array().filter(|a| a.len() <= 64).ok_or("checks.disclosed must be a list of at most 64 pointers")?;
    let mut prev: Option<&str> = None;
    for p in d {
        let p = p.as_str().filter(|p| is_pointer(p)).ok_or("checks.disclosed holds JSON Pointers (§10.1)")?;
        // Unicode code point order is UTF-8 byte order.
        if prev.is_some_and(|q| q >= p) {
            return Err("checks.disclosed must be in Unicode code point order, without repeats".into());
        }
        prev = Some(p);
    }
    if !d.is_empty() && !strict {
        return Err("checks.disclosed must be empty on a call that is not protected".into());
    }
    if d.is_empty() != o["disclosed_hash"].is_null() || !(o["disclosed_hash"].is_null() || is_hex64(&o["disclosed_hash"])) {
        return Err("checks.disclosed_hash is 64 hex exactly when checks.disclosed is not empty, and null otherwise".into());
    }
    let id_ok = match &o["call_id"] {
        Value::Null => true,
        Value::String(s) => (1..=128).contains(&s.chars().count()),
        v @ Value::Number(_) => safe_int(v).is_some(),
        _ => false,
    };
    if !id_ok {
        return Err("checks.call_id must be null, a string of 1 to 128 characters, or an integer within ±(2^53−1)".into());
    }
    results(o, kind)?;
    Ok(())
}

/// Validate `results` and `result`; returns the number of entries.
fn results(o: &Map<String, Value>, kind: Kind) -> Result<usize, String> {
    let list = o["results"].as_array().filter(|a| a.len() <= 32).ok_or("checks.results must be a list of at most 32 entries")?;
    let mut seen: Vec<(String, Option<String>)> = Vec::new();
    let mut strongest = 0;
    for e in list {
        let e = e.as_object().ok_or("each checks.results entry is an object")?;
        let check = e.get("check").and_then(Value::as_str).ok_or("each entry names its check")?;
        let allowed: &[&str] = match kind {
            Kind::Decision => &["secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction"],
            _ => &["secret", "hidden_instruction"],
        };
        if !allowed.contains(&check) {
            return Err(format!("the check '{check}' is not a check of {}", if kind == Kind::Decision { "a decision" } else { "an outcome" }));
        }
        let watch = e.get("mode").and_then(Value::as_str) == Some("watch");
        let mut keys = vec!["check", "result", "mode"];
        if watch {
            keys.push("enforce_result");
        }
        if check == "rule" {
            keys.extend(["set", "matched"]);
            // Spec 1.1: written only when not empty.
            for k in ["would_block", "excepted"] {
                if e.contains_key(k) {
                    keys.push(k);
                }
            }
        } else {
            keys.push("found");
        }
        exact_keys(e, &keys, &format!("the '{check}' entry"))?;
        if str_in(&e["mode"], &["watch", "enforce"]).is_none() {
            return Err("an entry's `mode` is \"watch\" (Calibrating) or \"enforce\" (On)".into());
        }
        let result = e["result"].as_str().filter(|r| rank(r).is_some()).ok_or("an entry's result is allow, note or block")?;
        if watch {
            let er = e["enforce_result"].as_str().filter(|r| rank(r).is_some()).ok_or("enforce_result is allow, note or block")?;
            if result != if er == "block" { "note" } else { er } {
                return Err("when an entry's `mode` is \"watch\" (Calibrating), its result equals its enforce_result, except that block is written as note".into());
            }
        }
        if kind == Kind::Outcome && check == "hidden_instruction" && (result == "block" || e.get("enforce_result").and_then(Value::as_str) == Some("block")) {
            return Err("hidden_instruction never blocks on a result".into());
        }
        let set = if check == "rule" {
            let set = e["set"].as_str().filter(|s| *s == "local" || is_set_id(s)).ok_or("a rule entry's set is local or the rule set's id")?;
            let m = e["matched"].as_array().filter(|a| a.len() <= 16).ok_or("a rule entry's matched is a list of at most 16 rule ids")?;
            if !m.iter().all(|r| r.as_str().is_some_and(is_rule_id)) {
                return Err("a rule entry's matched holds rule ids".into());
            }
            let mut lists: Vec<(&str, Vec<&str>)> = vec![("matched", m.iter().filter_map(Value::as_str).collect())];
            for k in ["would_block", "excepted"] {
                let Some(l) = e.get(k) else { continue };
                let l = l.as_array().filter(|l| (1..=16).contains(&l.len())).ok_or_else(|| format!("a rule entry's {k} is a list of 1 to 16 rule ids, written only when not empty"))?;
                let ids: Vec<&str> = l.iter().filter_map(|x| x.as_str().filter(|s| is_rule_id(s))).collect();
                if ids.len() != l.len() || ids.iter().enumerate().any(|(i, x)| ids[..i].contains(x)) {
                    return Err(format!("a rule entry's {k} holds rule ids, each once"));
                }
                lists.push((k, ids));
            }
            for (i, (a, x)) in lists.iter().enumerate() {
                for (b, y) in &lists[i + 1..] {
                    if let Some(id) = x.iter().find(|id| y.contains(id)) {
                        return Err(format!("the rule {id} is in both {a} and {b} of a rule entry"));
                    }
                }
            }
            Some(set.to_string())
        } else {
            let f = e["found"].as_array().filter(|a| a.len() <= 8).ok_or("an entry's found is a list of at most 8 codes")?;
            let codes = found_codes(check);
            for (i, c) in f.iter().enumerate() {
                let c = c.as_str().filter(|c| codes.contains(c)).ok_or_else(|| format!("the '{check}' entry has an unknown found code"))?;
                if f[..i].iter().any(|x| x.as_str() == Some(c)) {
                    return Err(format!("the '{check}' entry repeats a found code"));
                }
            }
            // Spec 1.1, benchmark batch 2: a hidden instruction in arguments or a result is a note.
            let er = e.get("enforce_result").and_then(Value::as_str);
            if check == "hidden_instruction" && f.iter().any(|c| c.as_str() == Some("possible_hidden_instruction")) && (result != "note" || (watch && er != Some("note"))) {
                return Err("a hidden_instruction entry with possible_hidden_instruction (arguments or a result) is a note, never a block".into());
            }
            None
        };
        let key = (check.to_string(), set);
        if seen.contains(&key) {
            return Err(format!("the '{check}' check appears twice (rule appears once per rule set)"));
        }
        seen.push(key);
        strongest = strongest.max(rank(result).unwrap());
    }
    let want = ["allow", "note", "block"][strongest as usize];
    if o["result"].as_str() != Some(want) {
        return Err(format!("checks.result must be the strongest result among the entries ({want})"));
    }
    Ok(list.len())
}

/// Whether a decision's checks ask the witness for a ruling: strict, and not blocked on the client (§3.5).
pub fn asks_for_ruling(checks: &Value) -> bool {
    checks["strict"] == Value::Bool(true) && checks["result"] != "block"
}

/// The §2.3 rules for `disclosed` and `disclosed_salt` beside an envelope's `checks`. Returns
/// the JCS text of `disclosed` when the record carries it; the caller compares its hash with
/// `checks.disclosed_hash` (`content_mismatch`). `Err` is `invalid_record`.
pub fn disclosed_jcs(checks: Option<&Value>, disclosed: Option<&Value>, salt: Option<&Value>) -> Result<Option<String>, String> {
    let wants = checks.is_some_and(|c| !c["disclosed_hash"].is_null() && c.get("disclosed_hash").is_some());
    match (disclosed, salt) {
        (None, None) if !wants => Ok(None),
        (None, None) => Err("checks.disclosed_hash is set, so the record must carry disclosed and disclosed_salt (spec §2.3)".into()),
        (Some(_), None) | (None, Some(_)) => Err("disclosed and disclosed_salt come together (spec §2.3)".into()),
        (Some(_), Some(_)) if !wants => Err("disclosed and disclosed_salt are allowed only when checks.disclosed_hash is set (spec §2.3)".into()),
        (Some(d), Some(s)) => {
            let s = s.as_str().ok_or("disclosed_salt must be 32 lowercase hex characters")?;
            if s.len() != 32 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err("disclosed_salt must be 32 lowercase hex characters".into());
            }
            let d = d.as_object().ok_or("disclosed must be an object of {pointer: value}")?;
            let listed = checks.unwrap()["disclosed"].as_array().cloned().unwrap_or_default();
            if let Some(k) = d.keys().find(|k| !listed.iter().any(|p| p.as_str() == Some(k.as_str()))) {
                return Err(format!("disclosed holds '{k}', which checks.disclosed does not list"));
            }
            let text = jcs::canonicalize(&Value::Object(d.clone())).map_err(|e| format!("disclosed: {e}"))?;
            if text.len() > DISCLOSED_MAX_BYTES {
                return Err(format!("JCS(disclosed) is {} bytes, more than DISCLOSED_MAX_BYTES ({DISCLOSED_MAX_BYTES})", text.len()));
            }
            Ok(Some(text))
        }
    }
}

/// `sha256(disclosed_salt || JCS(disclosed))` (§2.3), hex.
pub fn disclosed_hash(salt_hex: &str, disclosed_jcs: &str) -> String {
    let mut b = hex::decode(salt_hex).unwrap_or_default();
    b.extend_from_slice(disclosed_jcs.as_bytes());
    crate::sha256(&b).hex()
}

/// Check 12 (§7): with the record's content supplied and its `input` an object, each disclosed
/// value has the same JCS bytes as the field at its pointer in `content.input`, and each pointer
/// of `checks.disclosed` that `disclosed` leaves out is absent there.
pub fn disclosed_match_input(checks: &Value, disclosed: &Map<String, Value>, content: &Value) -> Result<(), String> {
    let Some(input) = content.get("input").filter(|i| i.is_object()) else { return Ok(()) };
    for p in checks["disclosed"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let field = super::rules::resolve(input, p);
        match (disclosed.get(p), field) {
            (Some(d), Some(f)) if jcs::canonicalize(d).ok() == jcs::canonicalize(f).ok() => {}
            (None, None) => {}
            (Some(_), _) => return Err(format!("the disclosed value at {p} differs from the call's input")),
            (None, Some(_)) => return Err(format!("{p} was left out of the disclosed values as absent, but the call's input holds it")),
        }
    }
    Ok(())
}
