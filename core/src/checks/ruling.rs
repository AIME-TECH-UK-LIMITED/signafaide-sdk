//! The witness's ruling on a strict decision (§3.5): `allow` or `block`, nothing between. In
//! watch mode the ruling is always `allow`, and `enforce_ruling` records what enforce mode
//! would have ruled. The witness evaluates only the project's rule set and the shared list.

use super::rules::{self, Action, Basis, Mode, RuleSet};
use serde_json::{json, Map, Value};

/// The project's rule set as the witness holds it: its newest published version.
pub struct Held<'a> {
    pub rule_set: &'a RuleSet,
    pub rules_hash: &'a str,
}

/// What the witness decided, before it names the record, batch and time.
#[derive(Clone, Debug, PartialEq)]
pub struct Decided {
    pub ruling: Action,
    pub mode: Mode,
    pub enforce_ruling: Option<Action>,
    pub basis: &'static str,
    pub matched: Vec<String>,
    pub missing: Vec<String>,
    /// `{set, version, hash}`, or null without a rule set.
    pub rules: Value,
    pub fingerprints: i64,
    pub reason: String,
    /// Spec 1.1 (§3.5): the `calibrating` rules that would have blocked the call, the ones that
    /// could not be evaluated for a field not disclosed, and the rules an exception kept from
    /// matching. Each is written only when it is not empty.
    pub would_block: Vec<String>,
    pub not_calibrated: Vec<String>,
    pub excepted: Vec<String>,
}

impl Decided {
    /// The ruling object (§3.5) for a record in a batch.
    pub fn object(&self, record_hash: &str, batch_hash: &str, server_time: &str) -> Value {
        let mut v = json!({
            "v": 1,
            "record_hash": record_hash,
            "batch_hash": batch_hash,
            "server_time": server_time,
            "ruling": self.ruling.as_str(),
            "mode": self.mode.as_str(),
            "basis": self.basis,
            "matched": self.matched,
            "missing": self.missing,
            "rules": self.rules,
            "fingerprints": self.fingerprints,
            "reason": self.reason,
        });
        if let Some(e) = self.enforce_ruling {
            v["enforce_ruling"] = json!(e.as_str());
        }
        for (k, ids) in [("would_block", &self.would_block), ("not_calibrated", &self.not_calibrated), ("excepted", &self.excepted)] {
            if !ids.is_empty() {
                v[k] = json!(ids);
            }
        }
        v
    }
}

/// "rule a", "rules a, b", "rules a, b, c and 2 more".
fn rule_list(ids: &[String]) -> String {
    let shown = ids.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let more = if ids.len() > 3 { format!(" and {} more", ids.len() - 3) } else { String::new() };
    format!("{} {shown}{more}", if ids.len() == 1 { "rule" } else { "rules" })
}

fn field_list(ptrs: &[String]) -> String {
    let shown = ptrs.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let more = if ptrs.len() > 3 { format!(" and {} more", ptrs.len() - 3) } else { String::new() };
    format!("{shown}{more}")
}

/// One sentence of 1 to 300 characters (§3.5), cut at a character boundary when longer.
fn sentence(s: String) -> String {
    if s.chars().count() <= 300 {
        return s;
    }
    let mut out: String = s.chars().take(296).collect();
    out.push_str(" ...");
    out
}

/// Decide the ruling on a strict decision (§3.5), in the order the spec gives: the rule set
/// version, the needed fields, the shared fingerprint list, then the evaluation of §10.3 over
/// the disclosed values. `listed(kind, fingerprint)` looks the shared list up; `count` counts
/// the witness's earlier `allow` rulings for a `limit` rule (§10.3).
#[allow(clippy::too_many_arguments)]
pub fn decide<E>(
    held: Option<&Held>,
    agent: &str,
    tool: &str,
    checks: &Value,
    disclosed: &Map<String, Value>,
    fingerprint_seq: i64,
    listed: &dyn Fn(&str, &str) -> bool,
    count: rules::Count<'_, E>,
) -> Result<Decided, E> {
    let fps = &checks["tool"];
    // A shared-list match on a fingerprint the rule set excepts (§10.1) is no match.
    let excepted = |k: &str, f: &str| held.is_some_and(|h| h.rule_set.excepts(k, f));
    let hits: Vec<&str> = ["tool", "description", "server"].into_iter().filter(|k| fps[*k].as_str().is_some_and(|f| listed(k, f) && !excepted(k, f))).collect();
    let fingerprint_cause = || format!("the tool's {} fingerprint is on the shared fingerprint list", hits.join(" and "));
    const FINGERPRINT_FIX: &str = "remove or replace the tool";

    let Some(h) = held else {
        // No rule set: enforce mode; a shared fingerprint match blocks, everything else is allowed.
        let (ruling, basis, reason) = if hits.is_empty() {
            (Action::Allow, "default", "Allowed: the project has no rule set, and the tool is not on the shared fingerprint list.".to_string())
        } else {
            (Action::Block, "fingerprint", format!("Blocked: {}; {FINGERPRINT_FIX}.", fingerprint_cause()))
        };
        return Ok(Decided {
            ruling,
            mode: Mode::Enforce,
            enforce_ruling: None,
            basis,
            matched: vec![],
            missing: vec![],
            rules: Value::Null,
            fingerprints: fingerprint_seq,
            reason: sentence(reason),
            would_block: vec![],
            not_calibrated: vec![],
            excepted: vec![],
        });
    };
    let rs = h.rule_set;
    let v = rs.version;
    let client_version = checks["rules"].as_array().into_iter().flatten().find(|r| r["set"] == rs.set.as_str()).and_then(|r| r["version"].as_i64());
    let disclosed_list: Vec<&str> = checks["disclosed"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut missing: Vec<String> = rs.needed(agent, tool).into_iter().filter(|p| !disclosed_list.contains(&p.as_str())).collect();
    missing.truncate(64);

    // (result, basis, matched, cause of a block or reason of an allow, fix of a block, evaluation)
    let mut calib: Option<rules::Evaluation> = None;
    let (result, basis, matched, cause, fix): (Action, &'static str, Vec<String>, String, &str) = if let Some(cv) = client_version.filter(|cv| *cv > v) {
        (Action::Block, "rules_version", vec![], format!("the call names rule set version {cv}, newer than version {v} the witness holds"), "fetch the rule set again with signafaide rules pull")
    } else if !missing.is_empty() {
        let n = missing.len();
        (
            Action::Block,
            "fields_missing",
            vec![],
            format!("rule set version {v} needs {} for this tool, and the call did not disclose {}", field_list(&missing), if n == 1 { "it" } else { "them" }),
            if n == 1 { "add it to the tool's disclose list in the checks file" } else { "add them to the tool's disclose list in the checks file" },
        )
    } else if !hits.is_empty() {
        (Action::Block, "fingerprint", vec![], fingerprint_cause(), FINGERPRINT_FIX)
    } else {
        let field = |p: &str| disclosed.get(p).cloned();
        let available = |p: &str| disclosed_list.contains(&p);
        let e = rules::evaluate(rs, agent, tool, &field, Some(&available), Some(count))?;
        let (cause, fix) = match (e.basis, e.result) {
            (Basis::Error, _) => (
                format!("{} of rule set version {v} met a field of the wrong type", rule_list(&e.matched)),
                "send the field with the type the rule expects, or change the rule in the console",
            ),
            (Basis::Rule, Action::Block) => (format!("{} of rule set version {v} matched", rule_list(&e.matched)), "change the rule in the console to allow such calls"),
            (_, Action::Allow) if !e.excepted.is_empty() => (format!("Allowed by an exception to {} of rule set version {v}.", rule_list(&e.excepted)), ""),
            (Basis::Rule, Action::Allow) => (format!("Allowed by {} of rule set version {v}.", rule_list(&e.matched)), ""),
            (Basis::Default, Action::Block) => (format!("no rule of rule set version {v} allows the call, and its default is block"), "add an allow rule in the console"),
            (Basis::Default, Action::Allow) => (format!("Allowed: no rule of rule set version {v} matched, and its default is allow."), ""),
        };
        let out = (e.result, e.basis.as_str(), e.matched.clone(), cause, fix);
        calib = Some(e);
        out
    };
    let (ruling, enforce_ruling, mut reason) = match (rs.mode, result) {
        (Mode::Enforce, Action::Block) => (Action::Block, None, format!("Blocked: {cause}; {fix}.")),
        (Mode::Enforce, Action::Allow) => (Action::Allow, None, cause),
        (Mode::Watch, Action::Block) => (Action::Allow, Some(Action::Block), format!("Allowed because the rule set is Calibrating; On would block the call: {cause}.")),
        (Mode::Watch, Action::Allow) => (Action::Allow, Some(Action::Allow), cause),
    };
    let (would_block, not_calibrated, excepted) = calib.map(|e| (e.would_block, e.not_calibrated, e.excepted)).unwrap_or_default();
    if !would_block.is_empty() {
        // "...; Calibrating rule x would have blocked it."
        reason.pop();
        reason.push_str(&format!("; Calibrating {} would have blocked it.", rule_list(&would_block)));
    }
    Ok(Decided {
        ruling,
        mode: rs.mode,
        enforce_ruling,
        basis,
        matched,
        missing: if basis == "fields_missing" { missing } else { vec![] },
        rules: json!({"set": rs.set, "version": v, "hash": h.rules_hash}),
        fingerprints: fingerprint_seq,
        reason: sentence(reason),
        would_block,
        not_calibrated,
        excepted,
    })
}

/// The bases that always block in enforce mode (§3.5).
const BLOCKING_BASES: [&str; 4] = ["rules_version", "fields_missing", "fingerprint", "error"];

/// Whether a ruling object follows §3.5 field by field (check 6). It does not re-evaluate the
/// ruling: rate limits depend on the witness's history, which a pack does not hold.
pub fn validate(r: &Value) -> Result<(), String> {
    let o = r.as_object().ok_or("a ruling is an object")?;
    let watch = o.get("mode").and_then(Value::as_str) == Some("watch");
    let mut keys = vec!["v", "record_hash", "batch_hash", "server_time", "ruling", "mode", "basis", "matched", "missing", "rules", "fingerprints", "reason"];
    if watch {
        keys.push("enforce_ruling");
    }
    const OPTIONAL: [&str; 3] = ["would_block", "not_calibrated", "excepted"];
    if let Some(k) = o.keys().find(|k| !keys.contains(&k.as_str()) && !OPTIONAL.contains(&k.as_str())) {
        return Err(format!("the ruling has the unknown field '{k}'"));
    }
    if let Some(k) = keys.iter().find(|k| !o.contains_key(**k)) {
        return Err(format!("the ruling lacks the field '{k}'"));
    }
    if super::safe_int(&o["v"]) != Some(1) {
        return Err("the ruling's v must be 1".into());
    }
    if !super::is_hex64(&o["record_hash"]) || !super::is_hex64(&o["batch_hash"]) {
        return Err("the ruling's record_hash and batch_hash are 64 lowercase hex".into());
    }
    if o["server_time"].as_str().is_none_or(|t| crate::time::parse(t).is_err()) {
        return Err("the ruling's server_time is not a protocol time".into());
    }
    let ruling = o["ruling"].as_str().filter(|r| matches!(*r, "allow" | "block")).ok_or("ruling is allow or block")?;
    if !matches!(o["mode"].as_str(), Some("watch" | "enforce")) {
        return Err("the ruling is allow or block, and its `mode` is \"watch\" (Calibrating) or \"enforce\" (On)".into());
    }
    let enforce = if watch {
        if ruling != "allow" {
            return Err("when the ruling's `mode` is \"watch\" (Calibrating) the ruling is always allow".into());
        }
        o["enforce_ruling"].as_str().filter(|r| matches!(*r, "allow" | "block")).ok_or("enforce_ruling is allow or block")?
    } else {
        ruling
    };
    let basis = o["basis"].as_str().filter(|b| matches!(*b, "rules_version" | "fields_missing" | "fingerprint" | "error" | "rule" | "default")).ok_or("basis is rules_version, fields_missing, fingerprint, error, rule or default")?;
    if BLOCKING_BASES.contains(&basis) && enforce != "block" {
        return Err(format!("basis {basis} always blocks when On (`mode` is \"enforce\")"));
    }
    let matched = o["matched"].as_array().filter(|m| m.len() <= 16).ok_or("matched is a list of at most 16 rule ids")?;
    if !matched.iter().all(|m| m.as_str().is_some_and(super::is_rule_id)) {
        return Err("matched holds rule ids".into());
    }
    if matched.is_empty() == matches!(basis, "error" | "rule") {
        return Err("matched names the rules exactly for basis error and rule".into());
    }
    let missing = o["missing"].as_array().filter(|m| m.len() <= 64).ok_or("missing is a list of at most 64 pointers")?;
    let mut prev: Option<&str> = None;
    for p in missing {
        let p = p.as_str().filter(|p| super::is_pointer(p)).ok_or("missing holds JSON Pointers")?;
        if prev.is_some_and(|q| q >= p) {
            return Err("missing is in Unicode code point order, without repeats".into());
        }
        prev = Some(p);
    }
    if missing.is_empty() == (basis == "fields_missing") {
        return Err("missing lists the pointers exactly for basis fields_missing".into());
    }
    match &o["rules"] {
        Value::Null => {
            if watch || !matches!(basis, "fingerprint" | "default") {
                return Err("without a rule set a ruling has `mode` \"enforce\" (On), with basis fingerprint or default".into());
            }
        }
        Value::Object(m) => {
            let ok = m.len() == 3
                && m.get("set").and_then(Value::as_str).is_some_and(super::is_set_id)
                && m.get("version").and_then(super::safe_int).is_some_and(|v| v >= 1)
                && m.get("hash").is_some_and(super::is_hex64);
            if !ok {
                return Err("the ruling's rules is null or {set, version, hash}".into());
            }
        }
        _ => return Err("the ruling's rules is null or {set, version, hash}".into()),
    }
    if super::safe_int(&o["fingerprints"]).is_none_or(|n| n < 0) {
        return Err("the ruling's fingerprints is the seq of the shared list".into());
    }
    if !o["reason"].as_str().is_some_and(|r| (1..=300).contains(&r.chars().count())) {
        return Err("the ruling's reason is 1 to 300 characters".into());
    }
    // Spec 1.1: would_block, not_calibrated and excepted, each written only when not empty.
    let mut lists: Vec<(&str, Vec<&str>)> = vec![("matched", matched.iter().filter_map(Value::as_str).collect())];
    for k in OPTIONAL {
        let Some(l) = o.get(k) else { continue };
        let l = l.as_array().filter(|l| (1..=16).contains(&l.len())).ok_or_else(|| format!("the ruling's {k} is a list of 1 to 16 rule ids, written only when not empty"))?;
        let ids: Vec<&str> = l.iter().filter_map(|x| x.as_str().filter(|s| super::is_rule_id(s))).collect();
        if ids.len() != l.len() {
            return Err(format!("the ruling's {k} holds rule ids"));
        }
        if ids.iter().enumerate().any(|(i, x)| ids[..i].contains(x)) {
            return Err(format!("the ruling's {k} names a rule twice"));
        }
        if !matches!(basis, "error" | "rule" | "default") || o["rules"].is_null() {
            return Err(format!("the ruling's {k} comes only from the evaluation of a rule set (basis error, rule or default)"));
        }
        if k != "excepted" && watch {
            return Err(format!("the ruling's {k} is about Calibrating rules of a rule set that is On (`mode` is \"enforce\")"));
        }
        lists.push((k, ids));
    }
    for (i, (a, x)) in lists.iter().enumerate() {
        for (b, y) in &lists[i + 1..] {
            if let Some(id) = x.iter().find(|id| y.contains(id)) {
                return Err(format!("the rule {id} is in both {a} and {b} of the ruling"));
            }
        }
    }
    Ok(())
}
