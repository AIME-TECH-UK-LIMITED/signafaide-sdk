//! Rules in words (§10.5, spec 1.1): the one canonical English sentence of every rule,
//! condition, exception and default, so every verifier, the console's auditor view and the CLI
//! print a rule set version the same way. The words never change what a rule does; the
//! document stays the rule (§10.1).

use super::rules::{Action, Condition, Exception, Op, Per, Rule, RuleSet, State};
use crate::{jcs, plural};
use serde::Serialize;
use serde_json::Value;

/// A number as people read it: its JCS literal, with the integer part grouped by threes with
/// `,` when the literal has no exponent (`1000` → `1,000`, `-1234.5` → `-1,234.5`, `1e+21` as is).
pub fn number(literal: &str) -> String {
    if literal.contains(['e', 'E']) {
        return literal.to_string();
    }
    let (sign, rest) = literal.strip_prefix('-').map_or(("", literal), |r| ("-", r));
    let (int, frac) = rest.split_once('.').map_or((rest, None), |(i, f)| (i, Some(f)));
    let digits: Vec<char> = int.chars().collect();
    let mut grouped = String::new();
    for (i, c) in digits.iter().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(*c);
    }
    match frac {
        Some(f) => format!("{sign}{grouped}.{f}"),
        None => format!("{sign}{grouped}"),
    }
}

/// A JSON value in words: a number as [`number`]; a string as its JCS string literal (in double
/// quotes, escaped as JCS escapes it); `true`, `false`, `null`; an object or array as its JCS text.
pub fn value(v: &Value) -> String {
    let text = jcs::canonicalize(v).unwrap_or_default();
    match v {
        Value::Number(_) => number(&text),
        _ => text,
    }
}

/// A field in words: the JSON Pointer without its leading `/` (`/payee/id` → `payee/id`), its
/// escapes kept; the pointer `/` (the empty key) is `(the empty key)`.
pub fn field(pointer: &str) -> String {
    match pointer.strip_prefix('/').unwrap_or(pointer) {
        "" => "(the empty key)".to_string(),
        f => f.to_string(),
    }
}

/// Items joined as `a`, `a or b`, `a, b or c`; `(no values)` when there are none.
fn either(items: &[String]) -> String {
    match items.len() {
        0 => "(no values)".to_string(),
        1 => items[0].clone(),
        n => format!("{} or {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

/// A condition in words (§10.5 table).
pub fn condition(c: &Condition) -> String {
    let f = field(&c.field);
    let list = || {
        either(
            &c.value
                .as_array()
                .map(|l| l.iter().map(value).collect::<Vec<_>>())
                .unwrap_or_default(),
        )
    };
    match c.op {
        Op::Eq => format!("{f} is {}", value(&c.value)),
        Op::Ne => format!("{f} is not {}", value(&c.value)),
        Op::Lt => format!("{f} is below {}", value(&c.value)),
        Op::Le => format!("{f} is at most {}", value(&c.value)),
        Op::Gt => format!("{f} is above {}", value(&c.value)),
        Op::Ge => format!("{f} is at least {}", value(&c.value)),
        Op::In => format!("{f} is one of {}", list()),
        Op::NotIn => format!("{f} is not one of {}", list()),
        Op::Prefix => format!("{f} starts with {}", value(&c.value)),
        Op::Suffix => format!("{f} ends with {}", value(&c.value)),
        Op::Contains => format!("{f} contains {}", value(&c.value)),
        Op::Present => format!("{f} is present"),
        Op::Absent => format!("{f} is absent"),
        Op::Type => {
            let t = match c.value.as_str().unwrap_or("") {
                "string" => "a string",
                "number" => "a number",
                "integer" => "an integer",
                "boolean" => "true or false",
                "null" => "null",
                "object" => "an object",
                _ => "an array",
            };
            format!("{f} is {t}")
        }
    }
}

/// An exception in words: `<field> is <value>`.
pub fn exception(e: &Exception) -> String {
    format!("{} is {}", field(&e.field), value(&e.value))
}

/// A rule in words, without its state: `Block approve_payout when amount is above 1,000`.
pub fn rule(r: &Rule) -> String {
    let action = match r.action {
        Action::Block => "Block",
        Action::Allow => "Allow",
    };
    let tools = match &r.tools {
        None => "any tool".to_string(),
        Some(t) => either(t),
    };
    let agents = match &r.agents {
        None => String::new(),
        Some(a) if a.len() == 1 => format!(" for agent {}", a[0]),
        Some(a) => format!(" for agents {}", either(a)),
    };
    let mut parts: Vec<String> = r.when.iter().map(condition).collect();
    if let Some(l) = &r.limit {
        let per = match l.per {
            Per::Agent => "by the same agent",
            Per::Tool => "to the same tool",
            Per::AgentTool => "by the same agent to the same tool",
        };
        parts.push(format!(
            "more than {} in {} {per}",
            plural_number(l.calls, "call", "calls"),
            window(l.seconds)
        ));
    }
    let when = if parts.is_empty() {
        String::new()
    } else {
        format!(" when {}", parts.join(" and "))
    };
    let except = if r.exceptions.is_empty() {
        String::new()
    } else {
        format!(
            ", except when {}",
            r.exceptions.iter().map(exception).collect::<Vec<_>>().join(" or ")
        )
    };
    format!("{action} {tools}{agents}{when}{except}")
}

/// A limit's window as the console says it: `1 minute` for 60 seconds, `2 hours`, `90 seconds`.
pub fn window(seconds: i64) -> String {
    if seconds % 3600 == 0 {
        plural_number(seconds / 3600, "hour", "hours")
    } else if seconds % 60 == 0 {
        plural_number(seconds / 60, "minute", "minutes")
    } else {
        plural_number(seconds, "second", "seconds")
    }
}

fn plural_number(n: i64, one: &str, many: &str) -> String {
    format!("{} {}", number(&n.to_string()), if n == 1 { one } else { many })
}

/// The default in words: `Allow every call that no rule matches` or `Block ...`.
pub fn default(a: Action) -> String {
    match a {
        Action::Allow => "Allow every call that no rule matches".to_string(),
        Action::Block => "Block every call that no rule matches".to_string(),
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct RuleWords {
    pub id: String,
    /// `on` or `calibrating`; null for local rules, whose mode is the checks file's for each tool.
    pub state: Option<&'static str>,
    pub sentence: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ExceptionWords {
    pub rule: String,
    pub since: i64,
    pub sentence: String,
    pub reason: String,
}

/// One rule set version (or one local rules object) in words (§7 JSON output `rules`).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct RuleSetWords {
    /// The rule set's id, or `local`.
    pub set: String,
    /// Null for local rules.
    pub version: Option<i64>,
    pub hash: String,
    /// Null for local rules.
    pub issued: Option<String>,
    pub rules: Vec<RuleWords>,
    /// The default in words, and its state (`on`, `calibrating` in watch mode; null for local).
    pub default: RuleWords,
    pub exceptions: Vec<ExceptionWords>,
    /// SDK 0.5.2: the tools the version protects from the console (`protect`, §10.1), in code
    /// point order; left out of the JSON for a version without `protect` (and for local rules).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect: Option<Vec<ProtectWords>>,
}

/// One tool a rule set version protects from the console (§7 JSON output `rules[].protect`).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtectWords {
    pub tool: String,
    /// `closed` (Stop) or `open` (Let it run).
    pub fail: &'static str,
}

/// A fail mode in words, as the console says it: `closed` is Stop, `open` is Let it run.
pub fn fail_mode(fail: &str) -> &'static str {
    if fail == "open" {
        "Let it run"
    } else {
        "Stop"
    }
}

/// A valid rule set version, or local rules (`local` true), in words.
pub fn rule_set(rs: &RuleSet, hash: &str, local: bool) -> RuleSetWords {
    let state = |s: State| (!local).then_some(s.as_str());
    RuleSetWords {
        set: if local { "local".into() } else { rs.set.clone() },
        version: (!local).then_some(rs.version),
        hash: hash.to_string(),
        issued: (!local).then(|| rs.issued.clone()),
        rules: rs
            .rules
            .iter()
            .map(|r| RuleWords {
                id: r.id.clone(),
                state: state(r.state_in(rs.mode)),
                sentence: rule(r),
            })
            .collect(),
        default: RuleWords {
            id: "default".into(),
            state: state(State::from_mode(rs.mode)),
            sentence: default(rs.default),
        },
        exceptions: rs
            .rules
            .iter()
            .flat_map(|r| {
                r.exceptions.iter().map(|e| ExceptionWords {
                    rule: r.id.clone(),
                    since: e.since,
                    sentence: exception(e),
                    reason: e.reason.clone(),
                })
            })
            .collect(),
        protect: (!local && !rs.protect.is_empty()).then(|| {
            let mut tools: Vec<&String> = rs.protect.keys().collect();
            tools.sort_by(|a, b| a.chars().cmp(b.chars()));
            tools
                .into_iter()
                .map(|t| ProtectWords {
                    tool: t.clone(),
                    fail: rs.protect[t],
                })
                .collect()
        }),
    }
}

/// The report lines of one rule set version or local rules (§7), without the `rules: ` prefix.
pub fn lines(w: &RuleSetWords) -> Vec<String> {
    let label = match w.version {
        Some(v) => format!("{} version {v}", w.set),
        None => format!("local {}", &w.hash[..8.min(w.hash.len())]),
    };
    let word = |s: Option<&str>| match s.and_then(State::parse) {
        Some(st) => format!(" ({})", st.word()),
        None => String::new(),
    };
    let mut out = Vec::new();
    let n = plural(w.rules.len() as u64, "rule", "rules");
    match &w.issued {
        Some(t) => out.push(format!("{label}, issued {t}: {n}")),
        None => out.push(format!("{label}: {n}")),
    }
    for r in &w.rules {
        out.push(format!("{label}: rule {}: {}{}", r.id, r.sentence, word(r.state)));
    }
    out.push(format!("{label}: {}{}", w.default.sentence, word(w.default.state)));
    for e in &w.exceptions {
        let reason = jcs::canonicalize(&Value::String(e.reason.clone())).unwrap_or_default();
        out.push(format!(
            "{label}: exception to rule {} since version {}: {}, reason {reason}",
            e.rule, e.since, e.sentence
        ));
    }
    for p in w.protect.iter().flatten() {
        out.push(format!(
            "{label}: protected from the console: {}, if signafAIde can't be reached: {}",
            p.tool,
            fail_mode(p.fail)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(number("1000"), "1,000");
        assert_eq!(number("100"), "100");
        assert_eq!(number("-1234567.25"), "-1,234,567.25");
        assert_eq!(number("1e+21"), "1e+21");
        assert_eq!(number("0.5"), "0.5");
    }
}
