//! Rule set documents (§10.1), their evaluation (§10.3) and the fields a call needs (§10.4).
//! Unknown is an error: a document with any field, operator, action, type name or `per` that
//! §10.1 does not list, or a value of the wrong type, is invalid as a whole.

use super::{is_hex64, is_pointer, is_rule_id, is_set_id, safe_int};
use serde_json::{Map, Value};
use crate::{jcs, time, valid_agent_name, valid_project_id};
use std::collections::BTreeSet;

pub const FORMAT: &str = "signafaide-rules/1";
/// A rule set's JCS form is at most 1 MiB (§9).
pub const MAX_DOCUMENT_BYTES: usize = 1 << 20;
const TOP_KEYS: [&str; 13] = ["format", "project", "env", "set", "version", "prev", "issued", "mode", "default", "fail", "addresses", "approved", "rules"];
const TYPES: [&str; 7] = ["string", "number", "integer", "boolean", "null", "object", "array"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Block => "block",
        }
    }

    fn parse(v: &Value) -> Option<Action> {
        match v.as_str()? {
            "allow" => Some(Action::Allow),
            "block" => Some(Action::Block),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Watch,
    Enforce,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "watch" => Some(Mode::Watch),
            "enforce" => Some(Mode::Enforce),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Watch => "watch",
            Mode::Enforce => "enforce",
        }
    }
}

/// A rule's state (§10.1, spec 1.1): `on` takes part in the result; `calibrating` never
/// blocks, and a call it would have blocked is noted (`would_block`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Calibrating,
    On,
}

impl State {
    pub fn parse(s: &str) -> Option<State> {
        match s {
            "calibrating" => Some(State::Calibrating),
            "on" => Some(State::On),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            State::Calibrating => "calibrating",
            State::On => "on",
        }
    }

    /// The state a rule has when its document omits `state`: from the rule set's mode, so a
    /// document written before spec 1.1 means what it meant.
    pub fn from_mode(mode: Mode) -> State {
        match mode {
            Mode::Watch => State::Calibrating,
            Mode::Enforce => State::On,
        }
    }

    /// The word people read: `On` or `Calibrating`.
    pub fn word(self) -> &'static str {
        match self {
            State::Calibrating => "Calibrating",
            State::On => "On",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
    Prefix,
    Suffix,
    Contains,
    Present,
    Absent,
    Type,
}

impl Op {
    fn parse(s: &str) -> Option<Op> {
        Some(match s {
            "eq" => Op::Eq,
            "ne" => Op::Ne,
            "lt" => Op::Lt,
            "le" => Op::Le,
            "gt" => Op::Gt,
            "ge" => Op::Ge,
            "in" => Op::In,
            "not_in" => Op::NotIn,
            "prefix" => Op::Prefix,
            "suffix" => Op::Suffix,
            "contains" => Op::Contains,
            "present" => Op::Present,
            "absent" => Op::Absent,
            "type" => Op::Type,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Per {
    Agent,
    Tool,
    AgentTool,
}

#[derive(Clone, Debug)]
pub struct Limit {
    pub calls: i64,
    pub seconds: i64,
    pub per: Per,
}

#[derive(Clone, Debug)]
pub struct Condition {
    pub field: String,
    pub op: Op,
    pub value: Value,
}

/// An exception to a block rule (§10.1, spec 1.1): the rule does not match a call whose field
/// at `field` is present and equal (JCS) to `value`. `reason` is the admin's, `since` the
/// version that added it.
#[derive(Clone, Debug)]
pub struct Exception {
    pub field: String,
    pub value: Value,
    pub reason: String,
    pub since: i64,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub about: String,
    pub action: Action,
    pub tools: Option<Vec<String>>,
    pub agents: Option<Vec<String>>,
    pub when: Vec<Condition>,
    pub limit: Option<Limit>,
    /// `state` as written; `None` when the document omits it (§10.1).
    pub state: Option<State>,
    /// `exceptions`, empty when the document has none.
    pub exceptions: Vec<Exception>,
}

impl Rule {
    /// The rule's state in a rule set of `mode`: as written, else from the mode.
    pub fn state_in(&self, mode: Mode) -> State {
        self.state.unwrap_or(State::from_mode(mode))
    }

    /// The fields of the rule's conditions, each once, in condition order.
    pub fn condition_fields(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for c in &self.when {
            if !out.contains(&c.field.as_str()) {
                out.push(&c.field);
            }
        }
        out
    }

    /// §10.3: the rule applies when its `tools` is null or holds the tool, and its `agents` is
    /// null or holds the agent.
    pub fn applies(&self, agent: &str, tool: &str) -> bool {
        self.tools.as_ref().is_none_or(|t| t.iter().any(|x| x == tool)) && self.agents.as_ref().is_none_or(|a| a.iter().any(|x| x == agent))
    }
}

/// A valid rule set document.
#[derive(Clone, Debug)]
pub struct RuleSet {
    pub project: String,
    pub env: String,
    pub set: String,
    pub version: i64,
    pub issued: String,
    pub mode: Mode,
    pub default: Action,
    pub rules: Vec<Rule>,
    /// `fingerprint_exceptions` (§10.1): the `(kind, fingerprint)` pairs this project accepts
    /// despite the shared list; empty when the document has none.
    pub fingerprint_exceptions: BTreeSet<(String, String)>,
}

impl RuleSet {
    /// Whether the rule set excepts the shared-list entry `kind` `fingerprint` (§10.1).
    pub fn excepts(&self, kind: &str, fingerprint: &str) -> bool {
        self.fingerprint_exceptions.contains(&(kind.to_string(), fingerprint.to_string()))
    }
}

pub(crate) fn exact(o: &Map<String, Value>, keys: &[&str], optional: &[&str], what: &str) -> Result<(), String> {
    if let Some(k) = o.keys().find(|k| !keys.contains(&k.as_str()) && !optional.contains(&k.as_str())) {
        return Err(format!("{what} has the unknown field '{k}'"));
    }
    if let Some(k) = keys.iter().find(|k| !o.contains_key(**k)) {
        return Err(format!("{what} lacks the field '{k}'"));
    }
    Ok(())
}

pub(crate) fn declared_name(v: &Value) -> bool {
    v.as_str().is_some_and(|s| (1..=101).contains(&s.chars().count()))
}

pub(crate) fn host_pattern(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    let name = s.strip_prefix("*.").unwrap_or(s);
    !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_'))
}

pub(crate) fn cidr(v: &Value) -> bool {
    let Some((addr, len)) = v.as_str().and_then(|s| s.split_once('/')) else { return false };
    let Ok(len) = len.parse::<u8>() else { return false };
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => len <= 32,
        Ok(std::net::IpAddr::V6(_)) => len <= 128,
        Err(_) => false,
    }
}

impl RuleSet {
    /// Parse and validate a whole document (§10.1). The message names the first problem.
    pub fn parse(doc: &Value) -> Result<RuleSet, String> {
        let o = doc.as_object().ok_or("a rule set is a JSON object")?;
        exact(o, &TOP_KEYS, &["fingerprint_exceptions"], "the rule set")?;
        let text = jcs::canonicalize(doc).map_err(|e| format!("the rule set is not canonical JSON: {e}"))?;
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(format!("the rule set's JCS form is {} bytes, more than 1 MiB", text.len()));
        }
        if o["format"] != FORMAT {
            return Err(format!("format must be {FORMAT}"));
        }
        let project = o["project"].as_str().filter(|p| valid_project_id(p)).ok_or("project must be a project id")?;
        let env = o["env"].as_str().filter(|e| matches!(*e, "test" | "live")).ok_or("env must be test or live")?;
        let set = o["set"].as_str().filter(|s| is_set_id(s)).ok_or("set must be rs_ followed by 26 Crockford base32 characters")?;
        let version = safe_int(&o["version"]).filter(|v| *v >= 1).ok_or("version must be an integer of at least 1")?;
        match (&o["prev"], version) {
            (Value::Null, 1) => {}
            (p, v) if v > 1 && is_hex64(p) => {}
            _ => return Err("prev is the rules_hash of version - 1, and null exactly when version is 1".into()),
        }
        let issued = o["issued"].as_str().filter(|t| time::parse(t).is_ok()).ok_or("issued must be a time such as 2026-11-17T09:00:00.000Z")?;
        let mode = match o["mode"].as_str() {
            Some("watch") => Mode::Watch,
            Some("enforce") => Mode::Enforce,
            _ => return Err("`mode` must be \"watch\" (Calibrating) or \"enforce\" (On)".into()),
        };
        let default = Action::parse(&o["default"]).ok_or("default must be allow or block")?;
        let fail = o["fail"].as_object().filter(|f| f.len() <= 1000).ok_or("fail must be an object of at most 1,000 tools")?;
        for (name, f) in fail {
            if !declared_name(&Value::String(name.clone())) || !matches!(f.as_str(), Some("open" | "closed")) {
                return Err("fail maps declared tool names to open or closed".into());
            }
        }
        let a = o["addresses"].as_object().ok_or("addresses must be {hosts, cidrs}")?;
        exact(a, &["hosts", "cidrs"], &[], "addresses")?;
        let hosts = a["hosts"].as_array().filter(|h| h.len() <= 1000).ok_or("addresses.hosts must be a list of at most 1,000 names")?;
        if !hosts.iter().all(host_pattern) {
            return Err("addresses.hosts holds lowercase names, or *. and a suffix".into());
        }
        let cidrs = a["cidrs"].as_array().filter(|c| c.len() <= 1000).ok_or("addresses.cidrs must be a list of at most 1,000 networks")?;
        if !cidrs.iter().all(cidr) {
            return Err("addresses.cidrs holds IPv4 or IPv6 networks in CIDR form".into());
        }
        match &o["approved"] {
            Value::Null => {}
            Value::Object(m) if m.len() <= 10_000 => {
                for (name, e) in m {
                    let e = e.as_object().ok_or("approved maps declared tool names to {description, schema}")?;
                    exact(e, &["description", "schema"], &[], "an approved entry")?;
                    if !declared_name(&Value::String(name.clone())) || !is_hex64(&e["description"]) || !is_hex64(&e["schema"]) {
                        return Err("approved maps declared tool names to {description, schema} fingerprints".into());
                    }
                }
            }
            _ => return Err("approved must be null or an object of at most 10,000 tools".into()),
        }
        let mut fingerprint_exceptions = BTreeSet::new();
        if let Some(xs) = o.get("fingerprint_exceptions") {
            let xs = xs.as_array().filter(|x| x.len() <= 1000).ok_or("fingerprint_exceptions must be a list of at most 1,000 entries")?;
            for x in xs {
                let e = x.as_object().ok_or("a fingerprint exception is {kind, fingerprint, reason}")?;
                if e.len() != 3 || !["kind", "fingerprint", "reason"].iter().all(|k| e.contains_key(*k)) {
                    return Err("a fingerprint exception is {kind, fingerprint, reason}".into());
                }
                let kind = e["kind"].as_str().filter(|k| matches!(*k, "tool" | "description" | "server"));
                let (Some(kind), true) = (kind, is_hex64(&e["fingerprint"])) else {
                    return Err("a fingerprint exception names a kind (tool, description or server) and a 64 lowercase hex fingerprint".into());
                };
                if e["reason"].as_str().is_none_or(|r| !(1..=200).contains(&r.chars().count())) {
                    return Err("a fingerprint exception's reason is text of 1 to 200 characters".into());
                }
                let fp = e["fingerprint"].as_str().unwrap();
                if !fingerprint_exceptions.insert((kind.to_string(), fp.to_string())) {
                    return Err(format!("the fingerprint exception {kind} {fp} is listed twice"));
                }
            }
        }
        let rules = parse_rules(&o["rules"], Some(version))?;
        if mode == Mode::Watch {
            if let Some(r) = rules.iter().find(|r| r.state == Some(State::On)) {
                return Err(format!("rule '{}': a rule set whose `mode` is \"watch\" (Calibrating) never blocks, so no rule in it is On", r.id));
            }
        }
        Ok(RuleSet { project: project.into(), env: env.into(), set: set.into(), version, issued: issued.into(), mode, default, rules, fingerprint_exceptions })
    }

    /// The local rules of a checks file (§8): `{"default", "rules"}`, the rules as §10.1 writes
    /// them but without `limit`, `state` and `exceptions`. The result is a rule set in enforce
    /// mode named `local`; the checks file's mode for the tool decides how its entry is written.
    pub fn parse_local(obj: &Value) -> Result<RuleSet, String> {
        let o = obj.as_object().ok_or("rules must be null or {default, rules}")?;
        exact(o, &["default", "rules"], &[], "rules")?;
        let default = Action::parse(&o["default"]).ok_or("rules.default must be allow or block")?;
        let rules = parse_rules(&o["rules"], None)?;
        if let Some(r) = rules.iter().find(|r| r.limit.is_some()) {
            return Err(format!("rule '{}': local rules may not use limit: only the witness counts calls", r.id));
        }
        Ok(RuleSet {
            project: String::new(),
            env: String::new(),
            set: "local".into(),
            version: 0,
            issued: String::new(),
            mode: Mode::Enforce,
            default,
            rules,
            fingerprint_exceptions: BTreeSet::new(),
        })
    }

    /// Whether the rule `r` takes part in the result (§10.3): every rule of a rule set in watch
    /// mode (whose result is then written as watch mode writes it), and the `on` rules of a rule
    /// set in enforce mode. A `calibrating` rule in enforce mode never does.
    pub fn takes_part(&self, r: &Rule) -> bool {
        self.mode == Mode::Watch || r.state_in(self.mode) == State::On
    }

    /// §10.4: the fields a call **needs**: the `field` of every condition of every rule that
    /// applies to the call and takes part in the result (§10.3), `limit` rules included, each
    /// once, in Unicode code point order. A `calibrating` rule's fields and the fields of
    /// exceptions are never needed.
    pub fn needed(&self, agent: &str, tool: &str) -> Vec<String> {
        let set: BTreeSet<&str> = self.rules.iter().filter(|r| r.applies(agent, tool) && self.takes_part(r)).flat_map(|r| r.when.iter().map(|c| c.field.as_str())).collect();
        set.into_iter().map(String::from).collect()
    }

    /// §10.4: the fields a call **can send**: the `field` of every condition of every rule that
    /// applies to the call, whatever its state, and the `field` of each of their exceptions,
    /// each once, in Unicode code point order. Every needed field is one of them.
    pub fn sendable(&self, agent: &str, tool: &str) -> Vec<String> {
        let set: BTreeSet<&str> = self
            .rules
            .iter()
            .filter(|r| r.applies(agent, tool))
            .flat_map(|r| r.when.iter().map(|c| c.field.as_str()).chain(r.exceptions.iter().map(|e| e.field.as_str())))
            .collect();
        set.into_iter().map(String::from).collect()
    }

    /// Whether the document uses a key of spec 1.1 (a rule's `state` or `exceptions`).
    pub fn uses_states_or_exceptions(&self) -> bool {
        self.rules.iter().any(|r| r.state.is_some() || !r.exceptions.is_empty())
    }
}

/// The `rules` list of a rule set document (`version` Some) or of a checks file's local rules
/// (`version` None: no `state` and no `exceptions`).
fn parse_rules(v: &Value, version: Option<i64>) -> Result<Vec<Rule>, String> {
    let list = v.as_array().filter(|r| r.len() <= 1000).ok_or("rules must be a list of at most 1,000 rules")?;
    let mut rules = Vec::with_capacity(list.len());
    let mut ids = BTreeSet::new();
    for r in list {
        let rule = parse_rule(r, version)?;
        if !ids.insert(rule.id.clone()) {
            return Err(format!("the rule id '{}' is used twice", rule.id));
        }
        rules.push(rule);
    }
    Ok(rules)
}

fn parse_rule(r: &Value, version: Option<i64>) -> Result<Rule, String> {
    let o = r.as_object().ok_or("each rule is an object")?;
    let optional: &[&str] = if version.is_some() { &["limit", "state", "exceptions"] } else { &["limit"] };
    exact(o, &["id", "about", "action", "tools", "agents", "when"], optional, "a rule")?;
    let id = o["id"].as_str().filter(|i| is_rule_id(i)).ok_or("a rule id matches ^[a-z0-9][a-z0-9._-]{0,63}$")?.to_string();
    let at = |m: &str| format!("rule '{id}': {m}");
    if o["about"].as_str().is_none_or(|a| a.chars().count() > 200) {
        return Err(at("about is text of at most 200 characters"));
    }
    let action = Action::parse(&o["action"]).ok_or_else(|| at("action must be allow or block"))?;
    let names = |k: &str, ok: fn(&Value) -> bool| -> Result<Option<Vec<String>>, String> {
        match &o[k] {
            Value::Null => Ok(None),
            Value::Array(a) if (1..=256).contains(&a.len()) && a.iter().all(ok) => Ok(Some(a.iter().map(|v| v.as_str().unwrap().to_string()).collect())),
            _ => Err(at(&format!("{k} is null or a list of 1 to 256 names"))),
        }
    };
    let tools = names("tools", declared_name)?;
    let agents = names("agents", |v| v.as_str().is_some_and(valid_agent_name))?;
    let when = o["when"].as_array().filter(|w| w.len() <= 16).ok_or_else(|| at("when is a list of at most 16 conditions"))?;
    let when = when.iter().map(|c| parse_condition(c).map_err(|e| at(&e))).collect::<Result<Vec<_>, _>>()?;
    let limit = match o.get("limit") {
        None => None,
        Some(l) => {
            if action != Action::Block {
                return Err(at("limit is allowed only on a block rule"));
            }
            let l = l.as_object().ok_or_else(|| at("limit is {calls, seconds, per}"))?;
            exact(l, &["calls", "seconds", "per"], &[], &at("limit"))?;
            let calls = safe_int(&l["calls"]).filter(|c| (1..=1_000_000).contains(c)).ok_or_else(|| at("limit.calls is 1 to 1,000,000"))?;
            let seconds = safe_int(&l["seconds"]).filter(|s| (1..=86_400).contains(s)).ok_or_else(|| at("limit.seconds is 1 to 86,400"))?;
            let per = match l["per"].as_str() {
                Some("agent") => Per::Agent,
                Some("tool") => Per::Tool,
                Some("agent_tool") => Per::AgentTool,
                _ => return Err(at("limit.per is agent, tool or agent_tool")),
            };
            Some(Limit { calls, seconds, per })
        }
    };
    let state = match o.get("state") {
        None => None,
        Some(v) => Some(v.as_str().and_then(State::parse).ok_or_else(|| at("state must be calibrating or on"))?),
    };
    let mut exceptions = Vec::new();
    if let Some(xs) = o.get("exceptions") {
        if action != Action::Block {
            return Err(at("exceptions are allowed only on a block rule"));
        }
        let xs = xs.as_array().filter(|x| (1..=256).contains(&x.len())).ok_or_else(|| at("exceptions is a list of 1 to 256 exceptions"))?;
        let doc_version = version.unwrap_or(0);
        for x in xs {
            let e = x.as_object().ok_or_else(|| at("an exception is {field, value, reason, since}"))?;
            exact(e, &["field", "value", "reason", "since"], &[], &at("an exception"))?;
            let field = e["field"].as_str().filter(|f| is_pointer(f)).ok_or_else(|| at("an exception's field must be a JSON Pointer of at most 256 characters, ~ only as ~0 or ~1"))?;
            let reason = e["reason"].as_str().filter(|r| (1..=200).contains(&r.chars().count())).ok_or_else(|| at("an exception's reason is text of 1 to 200 characters"))?;
            let since = safe_int(&e["since"]).filter(|s| (1..=doc_version).contains(s)).ok_or_else(|| at("an exception's since is the version that added it, 1 to this version"))?;
            let value = e["value"].clone();
            let text = jcs::canonicalize(&value).map_err(|err| at(&format!("an exception's value is not canonical JSON: {err}")))?;
            if exceptions.iter().any(|x: &Exception| x.field == field && jcs::canonicalize(&x.value).ok().as_deref() == Some(text.as_str())) {
                return Err(at(&format!("the exception {field} {text} is listed twice")));
            }
            exceptions.push(Exception { field: field.into(), value, reason: reason.into(), since });
        }
    }
    let about = o["about"].as_str().unwrap_or_default().to_string();
    Ok(Rule { id, about, action, tools, agents, when, limit, state, exceptions })
}

pub fn parse_condition(c: &Value) -> Result<Condition, String> {
    let o = c.as_object().ok_or("a condition is {field, op, value}")?;
    let op_name = o.get("op").and_then(Value::as_str).ok_or("a condition has an op")?;
    let op = Op::parse(op_name).ok_or_else(|| format!("unknown operator '{op_name}'"))?;
    if matches!(op, Op::Present | Op::Absent) {
        exact(o, &["field", "op"], &[], "a present or absent condition")?;
    } else {
        exact(o, &["field", "op", "value"], &[], "a condition")?;
    }
    let field = o["field"].as_str().filter(|f| is_pointer(f)).ok_or("field must be a JSON Pointer of at most 256 characters, ~ only as ~0 or ~1")?;
    let value = o.get("value").cloned().unwrap_or(Value::Null);
    let ok = match op {
        Op::Lt | Op::Le | Op::Gt | Op::Ge => value.is_number(),
        Op::In | Op::NotIn => value.as_array().is_some_and(|a| a.len() <= 256),
        Op::Prefix | Op::Suffix | Op::Contains => value.is_string(),
        Op::Type => value.as_str().is_some_and(|t| TYPES.contains(&t)),
        _ => true,
    };
    if !ok {
        return Err(format!("the value of '{op_name}' has the wrong type"));
    }
    Ok(Condition { field: field.into(), op, value })
}

/// Resolve an RFC 6901 pointer in `doc` (§10.1): `None` when the field is absent.
pub fn resolve<'a>(doc: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut cur = doc;
    for raw in pointer.strip_prefix('/')?.split('/') {
        let tok = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(m) => m.get(&tok)?,
            Value::Array(a) => {
                let ok = tok == "0" || (!tok.is_empty() && !tok.starts_with('0') && tok.bytes().all(|b| b.is_ascii_digit()));
                if !ok {
                    return None;
                }
                a.get(tok.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holds {
    Yes,
    No,
    Error,
}

fn jcs_eq(a: &Value, b: &Value) -> bool {
    match (jcs::canonicalize(a), jcs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// One condition against the field it names (`None`: absent) (§10.1 operators).
pub fn condition(c: &Condition, field: Option<&Value>) -> Holds {
    let yes = |b: bool| if b { Holds::Yes } else { Holds::No };
    let Some(v) = field else { return yes(c.op == Op::Absent) };
    match c.op {
        Op::Present => Holds::Yes,
        Op::Absent => Holds::No,
        Op::Eq => yes(jcs_eq(v, &c.value)),
        Op::Ne => yes(!jcs_eq(v, &c.value)),
        Op::Lt | Op::Le | Op::Gt | Op::Ge => match (v.as_number().and_then(|n| n.as_f64()), c.value.as_f64()) {
            (Some(a), Some(b)) => yes(match c.op {
                Op::Lt => a < b,
                Op::Le => a <= b,
                Op::Gt => a > b,
                _ => a >= b,
            }),
            _ => Holds::Error,
        },
        Op::In | Op::NotIn => {
            let any = c.value.as_array().is_some_and(|l| l.iter().any(|w| jcs_eq(v, w)));
            yes(any == (c.op == Op::In))
        }
        Op::Prefix | Op::Suffix | Op::Contains => match (v.as_str(), c.value.as_str()) {
            (Some(s), Some(w)) => yes(match c.op {
                Op::Prefix => s.starts_with(w),
                Op::Suffix => s.ends_with(w),
                _ => s.contains(w),
            }),
            _ => Holds::Error,
        },
        Op::Type => yes(match c.value.as_str().unwrap_or("") {
            "string" => v.is_string(),
            "number" => v.is_number(),
            "integer" => v.as_number().and_then(|n| n.as_f64()).is_some_and(|f| f.is_finite() && f.fract() == 0.0),
            "boolean" => v.is_boolean(),
            "null" => v.is_null(),
            "object" => v.is_object(),
            "array" => v.is_array(),
            _ => false,
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    Error,
    Rule,
    Default,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Error => "error",
            Basis::Rule => "rule",
            Basis::Default => "default",
        }
    }
}

/// The witness's count of its earlier `allow` rulings for a `limit` rule (§10.3).
pub type Count<'a, E> = &'a mut dyn FnMut(&Limit) -> Result<i64, E>;

/// The enforce-mode result of §10.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub result: Action,
    pub basis: Basis,
    pub matched: Vec<String>,
    /// The `calibrating` rules (in enforce mode) that would have blocked the call: in error, or
    /// a matching `block` rule. In document order, at most 16.
    pub would_block: Vec<String>,
    /// The `calibrating` rules (in enforce mode) that could not be evaluated because a field
    /// they need was not available (at the witness: not in `checks.disclosed`). In document
    /// order, at most 16.
    pub not_calibrated: Vec<String>,
    /// The rules taking part in the result whose conditions all held but that an exception
    /// kept from matching. In document order, at most 16.
    pub excepted: Vec<String>,
}

/// Evaluate a call (§10.3). `field` looks up a pointer (`None`: absent). `available` says
/// whether a pointer can be looked up at all: a client has the whole call (`None`: every field
/// is available); the witness has only the pointers of `checks.disclosed`. `count` is the
/// witness's count of its earlier `allow` rulings for a `limit` rule; without it (a client)
/// `limit` rules are skipped.
pub fn evaluate<E>(
    rs: &RuleSet,
    agent: &str,
    tool: &str,
    field: &dyn Fn(&str) -> Option<Value>,
    available: Option<&dyn Fn(&str) -> bool>,
    mut count: Option<Count<'_, E>>,
) -> Result<Evaluation, E> {
    let avail = |p: &str| available.is_none_or(|a| a(p));
    let (mut errors, mut blocks, mut allows) = (Vec::new(), Vec::new(), Vec::new());
    let (mut would_block, mut not_calibrated, mut excepted) = (Vec::new(), Vec::new(), Vec::new());
    for r in rs.rules.iter().filter(|r| r.applies(agent, tool)) {
        if r.limit.is_some() && count.is_none() {
            continue;
        }
        let part = rs.takes_part(r);
        if !part && r.condition_fields().iter().any(|p| !avail(p)) {
            not_calibrated.push(r.id.clone());
            continue;
        }
        let mut status = Holds::Yes;
        for c in &r.when {
            status = condition(c, field(&c.field).as_ref());
            if status != Holds::Yes {
                break;
            }
        }
        match status {
            Holds::Error => {
                if part { &mut errors } else { &mut would_block }.push(r.id.clone());
                continue;
            }
            Holds::No => continue,
            Holds::Yes => {}
        }
        // An exception applies only to a field that is available and present (§10.1).
        let is_excepted = r.exceptions.iter().any(|e| avail(&e.field) && field(&e.field).is_some_and(|v| jcs_eq(&v, &e.value)));
        if is_excepted {
            if part {
                excepted.push(r.id.clone());
            }
            continue;
        }
        if let (Some(l), Some(count)) = (&r.limit, count.as_mut()) {
            if count(l)? < l.calls {
                continue;
            }
        }
        match (part, r.action) {
            (true, Action::Block) => blocks.push(r.id.clone()),
            (true, Action::Allow) => allows.push(r.id.clone()),
            (false, Action::Block) => would_block.push(r.id.clone()),
            (false, Action::Allow) => {}
        }
    }
    let take = |mut v: Vec<String>| {
        v.truncate(16);
        v
    };
    let (result, basis, matched) = if !errors.is_empty() {
        (Action::Block, Basis::Error, take(errors))
    } else if !blocks.is_empty() {
        (Action::Block, Basis::Rule, take(blocks))
    } else if !allows.is_empty() {
        (Action::Allow, Basis::Rule, take(allows))
    } else {
        (rs.default, Basis::Default, vec![])
    };
    Ok(Evaluation { result, basis, matched, would_block: take(would_block), not_calibrated: take(not_calibrated), excepted: take(excepted) })
}

/// A check result as an entry writes it in `mode` (§2.8): in watch mode `block` is written as
/// `note`, with `enforce_result` holding what enforce mode would have given.
pub fn apply_mode(result: &str, mode: Mode) -> Map<String, Value> {
    let mut m = Map::new();
    match mode {
        Mode::Enforce => {
            m.insert("result".into(), Value::from(result));
        }
        Mode::Watch => {
            m.insert("result".into(), Value::from(if result == "block" { "note" } else { result }));
            m.insert("enforce_result".into(), Value::from(result));
        }
    }
    m
}

/// The mode of a client's `rule` entry (§2.8, §8): the project's rule set is ruled on by the
/// witness, never by the client, so its entry is always in watch mode (a call that is not strict
/// is not bound by it; a strict call waits for the witness's ruling, and the client decides alone
/// only when it has none); local rules follow the checks file's mode (`own`) on every call.
/// `strict` no longer changes the mode (spec 1.1, protected calls always ask the witness).
pub fn entry_mode(own: Mode, _strict: bool, local: bool) -> Mode {
    if local {
        own
    } else {
        Mode::Watch
    }
}

/// A client's `rule` entry for one rule set (§2.8, §8): the evaluation of §10.3 as a client
/// (`limit` rules skipped) over the call's arguments, written in `mode`, with `would_block` and
/// `excepted` when they are not empty. `set` is the rule set's
/// id, or `local`.
pub fn client_entry(rs: &RuleSet, mode: Mode, set: &str, agent: &str, tool: &str, args: &Value) -> Value {
    let field = |p: &str| resolve(args, p).cloned();
    let e = evaluate::<()>(rs, agent, tool, &field, None, None).expect("a client evaluation never counts");
    let mut m = Map::new();
    m.insert("check".into(), Value::from("rule"));
    m.extend(apply_mode(e.result.as_str(), mode));
    m.insert("mode".into(), Value::from(mode.as_str()));
    m.insert("set".into(), Value::from(set));
    m.insert("matched".into(), Value::from(e.matched));
    // Spec 1.1: present only when not empty, so an entry without them reads as before.
    if !e.would_block.is_empty() {
        m.insert("would_block".into(), Value::from(e.would_block));
    }
    if !e.excepted.is_empty() {
        m.insert("excepted".into(), Value::from(e.excepted));
    }
    Value::Object(m)
}

/// The name of the first §10.2 step that refuses a fetched version (`schema`, `project`,
/// `signature`, `set`, `older`, `conflict`, `issued`, `prev`), or `None` when the client accepts
/// it. `held` is the document the client holds; `item` is `{rules, sig, service_key_id}` as
/// `GET /v1/rules` serves it.
pub fn accept(held: Option<&Value>, item: &Value, service_keys: &[crate::KeyEntry], project: &str, env: &str) -> Option<&'static str> {
    let doc = &item["rules"];
    let Ok(rs) = RuleSet::parse(doc) else { return Some("schema") };
    if rs.project != project || rs.env != env {
        return Some("project");
    }
    let Ok(issued_ms) = time::parse(&rs.issued) else { return Some("schema") };
    let key = service_keys.iter().find(|k| Some(k.key_id.as_str()) == item["service_key_id"].as_str());
    let signed = key.is_some_and(|k| {
        crate::key_active(&k.valid_from, k.valid_to.as_deref(), issued_ms)
            && crate::hash::hash_json(doc).is_ok_and(|h| crate::sign::verify(&k.public_key, crate::sign::Domain::Rules, &h, item["sig"].as_str().unwrap_or("")).is_ok())
    });
    if !signed {
        return Some("signature");
    }
    let held = held?;
    let hash = |v: &Value| crate::hash::hash_json(v).map(|h| h.hex()).unwrap_or_default();
    let held_version = held["version"].as_i64().unwrap_or(0);
    if held["set"].as_str() != Some(rs.set.as_str()) {
        return Some("set");
    }
    if rs.version < held_version {
        return Some("older");
    }
    if rs.version == held_version {
        return (hash(doc) != hash(held)).then_some("conflict");
    }
    if time::parse(&rs.issued).ok() < held["issued"].as_str().and_then(|t| time::parse(t).ok()) {
        return Some("issued");
    }
    if rs.version == held_version + 1 && doc["prev"].as_str() != Some(hash(held).as_str()) {
        return Some("prev");
    }
    None
}
