//! The verifier's tool-call checks report (§7): what the checks of each agent's records found,
//! and the rulings on their receipts. It never fails a pack and changes no check: a record and
//! its ruling are authentic or not (checks 1, 6, 8, 12); what the agent did with them is
//! reported, not judged.

use super::CHECK_IDS;
use crate::{plural, Kind};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// One record of an agent's chain as the report reads it.
pub struct Item<'a> {
    pub seq: u64,
    pub kind: Kind,
    pub checks: Option<&'a Value>,
    /// For an outcome: the seq of its decision (the record its `ref` names) when the pack holds it.
    pub decision_seq: Option<u64>,
    /// The ruling on the record's receipt.
    pub ruling: Option<&'a Value>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ruled {
    pub allow: u64,
    pub block: u64,
    pub watch_would_block: u64,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct NoRuling {
    pub ran: u64,
    pub not_run: u64,
    pub no_outcome: u64,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleSetUsed {
    pub set: String,
    pub version: Option<i64>,
    pub hash: String,
}

/// The tool-call checks of one agent (§7 JSON output `checks`).
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentChecks {
    pub checked: u64,
    pub allowed: u64,
    pub noted: u64,
    pub blocked_here: u64,
    pub blocked_by_witness: u64,
    pub notes: BTreeMap<String, u64>,
    pub ruled: Ruled,
    pub no_ruling: NoRuling,
    pub ran_after_block: Vec<u64>,
    pub rule_sets: Vec<RuleSetUsed>,
}

fn rule_set_used(v: &Value) -> Option<RuleSetUsed> {
    Some(RuleSetUsed { set: v["set"].as_str()?.into(), version: v["version"].as_i64(), hash: v["hash"].as_str()?.into() })
}

/// The report of one agent from its records, or `None` when it would have no line.
pub fn agent_checks(items: &[Item<'_>]) -> Option<AgentChecks> {
    let mut j = AgentChecks::default();
    let outcomes: BTreeMap<u64, &Item> = items.iter().filter(|i| i.kind == Kind::Outcome).filter_map(|i| i.decision_seq.map(|d| (d, i))).collect();
    let mut sets: BTreeSet<RuleSetUsed> = BTreeSet::new();
    for d in items.iter().filter(|i| i.kind == Kind::Decision) {
        let Some(c) = d.checks else { continue };
        j.checked += 1;
        let result = c["result"].as_str().unwrap_or("allow");
        let asked = c["strict"] == Value::Bool(true) && result != "block";
        let g = d.ruling;
        let g_ruling = g.and_then(|g| g["ruling"].as_str());
        if result == "block" {
            j.blocked_here += 1;
        } else if g_ruling == Some("block") {
            j.blocked_by_witness += 1;
        } else if result == "note" {
            j.noted += 1;
        } else {
            j.allowed += 1;
        }
        for r in c["rules"].as_array().into_iter().flatten() {
            sets.extend(rule_set_used(r));
        }
        if let Some(g) = g {
            if !g["rules"].is_null() {
                sets.extend(rule_set_used(&g["rules"]));
            }
            match g_ruling {
                Some("allow") => j.ruled.allow += 1,
                Some("block") => j.ruled.block += 1,
                _ => {}
            }
            if g["mode"] == "watch" && g["enforce_ruling"] == "block" {
                j.ruled.watch_would_block += 1;
            }
        }
        let o = outcomes.get(&d.seq);
        let oc = o.and_then(|o| o.checks);
        let o_ran = oc.and_then(|c| c["ran"].as_bool()).unwrap_or(true);
        let o_none = oc.is_some_and(|c| c["ruling"] == "none");
        if asked && (g.is_none() || o_none) {
            match o {
                None => j.no_ruling.no_outcome += 1,
                Some(_) if o_ran => j.no_ruling.ran += 1,
                Some(_) => j.no_ruling.not_run += 1,
            }
        }
        let blocked = result == "block" || g_ruling == Some("block");
        if blocked && o.is_some() && o_ran && !o_none {
            j.ran_after_block.push(d.seq);
        }
    }
    for i in items {
        for e in i.checks.and_then(|c| c["results"].as_array()).into_iter().flatten() {
            if e["result"] == "note" {
                if let Some(c) = e["check"].as_str() {
                    *j.notes.entry(c.to_string()).or_default() += 1;
                }
            }
        }
    }
    j.ran_after_block.sort_unstable();
    let mut sets: Vec<RuleSetUsed> = sets.into_iter().collect();
    sets.sort_by(|a, b| (&a.set, a.version.unwrap_or(-1), &a.hash).cmp(&(&b.set, b.version.unwrap_or(-1), &b.hash)));
    j.rule_sets = sets;
    (!lines(".", &j).is_empty()).then_some(j)
}

/// The report lines of one agent (§7), without the `tool-call checks: ` prefix.
pub fn lines(agent: &str, j: &AgentChecks) -> Vec<String> {
    let mut out = Vec::new();
    if j.checked > 0 {
        let mut parts = vec![format!("{} allowed", j.allowed)];
        for (n, what) in [(j.noted, "with notes"), (j.blocked_here, "blocked here"), (j.blocked_by_witness, "blocked by the witness")] {
            if n > 0 {
                parts.push(format!("{n} {what}"));
            }
        }
        out.push(format!("{agent}: {} checked: {}", plural(j.checked, "tool call", "tool calls"), parts.join(", ")));
    }
    if !j.notes.is_empty() {
        let parts: Vec<String> = CHECK_IDS.iter().filter_map(|c| j.notes.get(*c).map(|k| format!("{c} {k}"))).collect();
        out.push(format!("{agent}: notes: {}", parts.join(", ")));
    }
    let ruled = j.ruled.allow + j.ruled.block;
    if ruled > 0 {
        let mut p = vec![format!("{} allowed", j.ruled.allow)];
        if j.ruled.block > 0 {
            p.push(format!("{} blocked", j.ruled.block));
        }
        if j.ruled.watch_would_block > 0 {
            p.push(format!("{} in watch mode that enforce mode would have blocked", j.ruled.watch_would_block));
        }
        out.push(format!("{agent}: {} ruled by the witness: {}", plural(ruled, "strict call", "strict calls"), p.join(", ")));
    }
    let nr = &j.no_ruling;
    let total = nr.ran + nr.not_run + nr.no_outcome;
    if total > 0 {
        let mut p = Vec::new();
        for (n, what) in [(nr.ran, "ran (fail open)"), (nr.not_run, "did not run"), (nr.no_outcome, "have no outcome in the pack")] {
            if n > 0 {
                p.push(format!("{n} {what}"));
            }
        }
        let had = if total == 1 { "had no ruling when it was decided" } else { "had no ruling when they were decided" };
        out.push(format!("{agent}: {} {had}: {}", plural(total, "strict call", "strict calls"), p.join(", ")));
    }
    if !j.ran_after_block.is_empty() {
        let seqs: Vec<String> = j.ran_after_block.iter().map(u64::to_string).collect();
        out.push(format!("{agent}: {} ran after a block: seq {}", plural(seqs.len() as u64, "call", "calls"), seqs.join(", ")));
    }
    if !j.rule_sets.is_empty() {
        let parts: Vec<String> = j
            .rule_sets
            .iter()
            .map(|r| if r.set == "local" { format!("local {}", &r.hash[..8.min(r.hash.len())]) } else { format!("{} version {}", r.set, r.version.unwrap_or(0)) })
            .collect();
        out.push(format!("{agent}: rule sets used: {}", parts.join(", ")));
    }
    out
}
