//! The checks file (§8): `signafaide-checks/1` and, from spec 1.1, `signafaide-checks/2`, as a
//! client reads it, and what it means for each tool: whether calls are strict, their fail mode,
//! the mode of the client's own checks and local rules, and the fields the developer approved
//! for sending. Unknown is an error in both formats; a version 1 file keeps its meaning.

use super::rules::{cidr, declared_name, exact, host_pattern, Mode, RuleSet};
use super::{is_pointer, safe_int};
use crate::hash::hash_json;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const FORMAT_1: &str = "signafaide-checks/1";
pub const FORMAT_2: &str = "signafaide-checks/2";
/// The checks a checks file turns on or off (`rule` is on whenever rules are held).
pub const FILE_CHECKS: [&str; 5] = ["secret", "address", "changed_tool", "fingerprint", "hidden_instruction"];

/// What the checks file says for one tool (§8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolSettings {
    /// Whether the checks file makes calls of the tool strict (version 1 `strict`, version 2
    /// `protect`). The code can make a tool strict too.
    pub strict: bool,
    /// The fail mode the checks file gives a strict tool (`open` or `closed`); the held rule
    /// set's `fail` wins over it (§8). `closed` for a tool that is not strict.
    pub fail: &'static str,
    /// The mode of the client's own checks and the local rules on calls of the tool.
    pub mode: Mode,
    /// The fields the developer approved for sending to the witness, in file order.
    pub disclose: Vec<String>,
    /// Whether the file names the tool's `mode` itself (a version 2 entry with `mode`).
    pub mode_given: bool,
}

/// A valid checks file.
#[derive(Clone, Debug)]
pub struct ChecksFile {
    /// 1 or 2.
    pub version: u8,
    /// Version 1: the file's `mode` for every tool. Version 2: `watch`, the mode of a tool the
    /// file does not list.
    pub mode: Mode,
    pub checks: BTreeMap<String, bool>,
    pub tools: BTreeMap<String, ToolSettings>,
    pub rules: Option<Value>,
    pub ruling_timeout_ms: Option<i64>,
}

fn pointers(v: &Value, what: &str, once: bool) -> Result<Vec<String>, String> {
    let l = v
        .as_array()
        .filter(|l| l.len() <= 64)
        .ok_or_else(|| format!("{what} must be a list of at most 64 JSON Pointers"))?;
    let mut out: Vec<String> = Vec::new();
    for p in l {
        let p = p
            .as_str()
            .filter(|p| is_pointer(p))
            .ok_or_else(|| format!("{what} must be a list of at most 64 JSON Pointers"))?;
        if once && out.iter().any(|q| q == p) {
            return Err(format!("{what} lists {p} twice"));
        }
        out.push(p.to_string());
    }
    Ok(out)
}

impl ChecksFile {
    /// Parse and validate a whole checks file (§8). The message names the first problem.
    pub fn parse(doc: &Value) -> Result<ChecksFile, String> {
        let o = doc.as_object().ok_or("the file is not a JSON object")?;
        let version = match o.get("format").and_then(Value::as_str) {
            Some(FORMAT_1) => 1,
            Some(FORMAT_2) => 2,
            _ => return Err(format!("format must be {FORMAT_1} or {FORMAT_2}")),
        };
        if version == 1 {
            exact(
                o,
                &["format", "mode", "checks", "tools", "addresses", "rules"],
                &["ruling_timeout_ms", "ci"],
                "the checks file",
            )?;
        } else {
            exact(
                o,
                &["format", "checks", "tools", "addresses", "rules"],
                &["ruling_timeout_ms", "ci", "proposed"],
                "the checks file",
            )?;
        }
        let mode = if version == 1 {
            o["mode"]
                .as_str()
                .and_then(Mode::parse)
                .ok_or("mode must be watch or enforce")?
        } else {
            Mode::Watch
        };
        let c = o["checks"]
            .as_object()
            .ok_or("checks must be an object of the five checks")?;
        exact(c, &FILE_CHECKS, &[], "checks")?;
        let mut checks = BTreeMap::new();
        for k in FILE_CHECKS {
            checks.insert(
                k.to_string(),
                c[k].as_bool()
                    .ok_or_else(|| format!("checks.{k} must be true or false"))?,
            );
        }
        let tools_obj = o["tools"]
            .as_object()
            .ok_or("tools must be an object of declared tool names")?;
        let mut tools = BTreeMap::new();
        for (name, t) in tools_obj {
            if !declared_name(&Value::String(name.clone())) {
                return Err(format!(
                    "tools: '{name}' is not a declared tool name (1 to 101 characters)"
                ));
            }
            let settings = if version == 1 {
                tool_1(name, t, mode)?
            } else {
                tool_2(name, t)?
            };
            tools.insert(name.clone(), settings);
        }
        let a = o["addresses"]
            .as_object()
            .ok_or("addresses must be {hosts, cidrs, resolve}")?;
        exact(a, &["hosts", "cidrs", "resolve"], &[], "addresses")?;
        if !a["hosts"].as_array().is_some_and(|h| h.iter().all(host_pattern)) {
            return Err("addresses.hosts holds lowercase names, or *. and a suffix".into());
        }
        if !a["cidrs"].as_array().is_some_and(|c| c.iter().all(cidr)) {
            return Err("addresses.cidrs holds IPv4 or IPv6 networks in CIDR form".into());
        }
        if !a["resolve"].is_boolean() {
            return Err("addresses.resolve must be true or false".into());
        }
        let rules = match &o["rules"] {
            Value::Null => None,
            r => {
                RuleSet::parse_local(r)?;
                Some(r.clone())
            }
        };
        let ruling_timeout_ms = match o.get("ruling_timeout_ms") {
            None => None,
            Some(v) => Some(
                safe_int(v)
                    .filter(|t| (1..=60_000).contains(t))
                    .ok_or("ruling_timeout_ms must be an integer from 1 to 60,000")?,
            ),
        };
        Ok(ChecksFile {
            version,
            mode,
            checks,
            tools,
            rules,
            ruling_timeout_ms,
        })
    }

    /// What the file says for the tool with this declared name (§8).
    pub fn tool(&self, name: &str) -> ToolSettings {
        self.tools.get(name).cloned().unwrap_or(ToolSettings {
            strict: false,
            fail: "closed",
            mode: self.mode,
            disclose: vec![],
            mode_given: false,
        })
    }

    /// The `hash` of the local rules' `checks.rules` entry (§2.8): sha256(JCS(rules object)).
    pub fn local_rules_hash(&self) -> Option<String> {
        self.rules
            .as_ref()
            .map(|r| hash_json(r).expect("a parsed rules object is canonical").hex())
    }
}

fn tool_1(name: &str, t: &Value, mode: Mode) -> Result<ToolSettings, String> {
    let t: &Map<String, Value> = t.as_object().ok_or_else(|| format!("tools.{name} must be {{strict, fail?, disclose?}}: `strict` is true (Protected) or false (Not protected), `fail` is \"closed\" (if signafAIde can't be reached: Stop) or \"open\" (Let it run)"))?;
    exact(t, &["strict"], &["fail", "disclose"], &format!("tools.{name}"))?;
    let strict = t["strict"]
        .as_bool()
        .ok_or_else(|| format!("tools.{name}.strict must be true (Protected) or false (Not protected)"))?;
    let fail = match t.get("fail") {
        None => "closed",
        Some(f) => match f.as_str() {
            Some("open") => "open",
            Some("closed") => "closed",
            _ => {
                return Err(format!(
                    "tools.{name}.fail must be \"closed\" (Stop) or \"open\" (Let it run)"
                ))
            }
        },
    };
    let disclose = match t.get("disclose") {
        None => vec![],
        Some(d) => pointers(d, &format!("tools.{name}.disclose"), false)?,
    };
    Ok(ToolSettings {
        strict,
        fail: if strict { fail } else { "closed" },
        mode,
        disclose: if strict { disclose } else { vec![] },
        mode_given: false,
    })
}

fn tool_2(name: &str, t: &Value) -> Result<ToolSettings, String> {
    let t: &Map<String, Value> = t.as_object().ok_or_else(|| format!("tools.{name} must be {{protect, mode?, disclose?}}: `protect` is true (Protected) or false (Not protected), `mode` is \"enforce\" (On) or \"watch\" (Calibrating)"))?;
    exact(t, &["protect"], &["mode", "disclose"], &format!("tools.{name}"))?;
    let protect = t["protect"]
        .as_bool()
        .ok_or_else(|| format!("tools.{name}.protect must be true (Protected) or false (Not protected)"))?;
    let mode = match t.get("mode") {
        None if protect => Mode::Enforce,
        None => Mode::Watch,
        Some(m) => m
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| format!("tools.{name}.mode must be \"watch\" (Calibrating) or \"enforce\" (On)"))?,
    };
    let disclose = match t.get("disclose") {
        None => vec![],
        Some(_) if !protect => return Err(format!("tools.{name}.disclose is allowed only on a protected tool: only protected calls send fields (set `protect` to true to protect the tool)")),
        Some(d) => pointers(d, &format!("tools.{name}.disclose"), true)?,
    };
    Ok(ToolSettings {
        strict: protect,
        fail: "closed",
        mode,
        disclose,
        mode_given: t.contains_key("mode"),
    })
}

/// §10.4: what a strict call of `tool` sends under the held rule set version, given the fields
/// the developer approved (`disclose`): `sent`, the sendable fields it lists; `missing`, the
/// needed fields it does not list (a ruling then blocks with basis `fields_missing`); and
/// `unsent`, the fields only Calibrating rules or exceptions use that it does not list (nothing
/// blocks for them: those rules are not calibrated, and those exceptions do not apply).
/// Each in Unicode code point order.
pub fn disclosure(
    rs: &RuleSet,
    agent: &str,
    tool: &str,
    disclose: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let listed = |p: &String| disclose.contains(p);
    let needed = rs.needed(agent, tool);
    let sendable = rs.sendable(agent, tool);
    let sent = sendable.iter().filter(|p| listed(p)).cloned().collect();
    let missing = needed.iter().filter(|p| !listed(p)).cloned().collect();
    let unsent = sendable
        .iter()
        .filter(|p| !listed(p) && !needed.contains(p))
        .cloned()
        .collect();
    (sent, missing, unsent)
}

/// What protects a tool and how its calls are checked (§8, SDK 0.5.2): the code (`code`: a
/// wrapper's strict mode, `protect(fn)`, the gateway's `--strict` or `--strict-tools`), the checks
/// file, and the held rule set's `protect` (a person, in the console).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protection {
    /// Whether the tool's calls are strict (ask the witness for a ruling).
    pub strict: bool,
    /// The fail mode of a strict call: the rule set's `fail` or `protect`, else the checks file's,
    /// else `closed`; null when not strict.
    pub fail: Option<&'static str>,
    /// The mode of the client's own checks and the local rules on the tool's calls.
    pub mode: Mode,
    /// What protects it, each of `code`, `checks_file`, `console`, in that order (`meta.protected_by`).
    pub sources: Vec<&'static str>,
    /// The fields the developer approved for sending (`disclose`); the console approves none.
    pub disclose: Vec<String>,
}

/// The protection of `tool` (a declared name), or `None` when its calls are not checked at all
/// (no checks file, and neither the code nor the rule set protects it).
pub fn protection(rs: Option<&RuleSet>, file: Option<&ChecksFile>, code: bool, tool: &str) -> Option<Protection> {
    let console = rs.is_some_and(|r| r.protect.contains_key(tool));
    if file.is_none() && !code && !console {
        return None;
    }
    let ts = file.map(|f| f.tool(tool));
    let in_file = ts.as_ref().is_some_and(|t| t.strict);
    let mut sources = Vec::new();
    for (on, name) in [(code, "code"), (in_file, "checks_file"), (console, "console")] {
        if on {
            sources.push(name);
        }
    }
    let strict = !sources.is_empty();
    // Without a file a protected tool runs every check On; a tool the file protects keeps the
    // file's mode for it; one protected only from the console is On unless the file names its mode.
    let mode = match &ts {
        None => Mode::Enforce,
        Some(t) if in_file || !console => t.mode,
        Some(t) if t.mode_given => t.mode,
        Some(_) => Mode::Enforce,
    };
    let fail = strict.then(|| {
        rs.and_then(|r| r.fail_of(tool))
            .unwrap_or_else(|| ts.as_ref().filter(|_| in_file).map_or("closed", |t| t.fail))
    });
    let disclose = ts.map(|t| t.disclose).unwrap_or_default();
    Some(Protection {
        strict,
        fail,
        mode,
        sources,
        disclose,
    })
}
