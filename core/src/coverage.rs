//! Tool declarations (§2.6) and the coverage they give (§7): which of an agent's tools are
//! recorded, read from envelopes alone (kind, name, seq), so it holds for hash-only records.
//!
//! Coverage is a note, never a failure, and never a claim of completeness: a declaration is the
//! client's own signed statement of the tools the agent has.

use crate::model::Kind;
use crate::plural;
use crate::sha256;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The name of the note that starts a new tool declaration for the agent's chain (§2.6).
pub const TOOLS: &str = "signafaide.tools";
/// `signafaide.tool/<tool name>`: the agent has this tool and calls to it are recorded.
pub const TOOL_PREFIX: &str = "signafaide.tool/";
/// `signafaide.tool_unrecorded/<tool name>`: the agent has this tool and calls to it are not recorded.
pub const TOOL_UNRECORDED_PREFIX: &str = "signafaide.tool_unrecorded/";
/// The names the SDK reserves: a record named so is never a tool.
pub const RESERVED_PREFIX: &str = "signafaide.";
/// The longest tool name a declaration holds as it is, in characters (Unicode code points): an
/// envelope name is at most 128 and the longer prefix takes 27.
pub const MAX_DECLARED_NAME: usize = 101;
/// A longer tool name keeps this many characters, then `~` and 8 hex characters.
const KEPT: usize = MAX_DECLARED_NAME - 9;

/// A tool's name as a declaration holds it (§2.6): the name itself when it has at most 101
/// characters, else its first 92 characters, `~`, and the first 8 hex characters of
/// sha256(UTF-8 tool name). A name that is already short maps to itself, so applying it twice
/// changes nothing.
pub fn declared_name(tool: &str) -> String {
    if tool.chars().count() <= MAX_DECLARED_NAME {
        return tool.to_string();
    }
    let kept: String = tool.chars().take(KEPT).collect();
    format!("{kept}~{}", &sha256(tool.as_bytes()).hex()[..8])
}

/// The envelope name of the note that declares `tool` (§2.6).
pub fn tool_note_name(tool: &str, recorded: bool) -> String {
    format!(
        "{}{}",
        if recorded { TOOL_PREFIX } else { TOOL_UNRECORDED_PREFIX },
        declared_name(tool)
    )
}

/// What a record says about the agent's tool list, from its kind and name alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolNote<'a> {
    /// `signafaide.tools`: a new declaration starts here.
    Header,
    /// The agent has this tool; `recorded` says whether calls to it are recorded.
    Tool { name: &'a str, recorded: bool },
}

/// Read a record as a tool-declaration note, or `None` when it is not one. Only a `note` can be
/// one, and a tool note with an empty tool name is not one.
pub fn tool_note(kind: Kind, name: &str) -> Option<ToolNote<'_>> {
    if kind != Kind::Note {
        return None;
    }
    if name == TOOLS {
        return Some(ToolNote::Header);
    }
    let (rest, recorded) = match (
        name.strip_prefix(TOOL_PREFIX),
        name.strip_prefix(TOOL_UNRECORDED_PREFIX),
    ) {
        (Some(rest), _) => (rest, true),
        (None, Some(rest)) => (rest, false),
        (None, None) => return None,
    };
    (!rest.is_empty()).then_some(ToolNote::Tool { name: rest, recorded })
}

/// One tool of a declaration.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DeclaredTool {
    pub name: String,
    pub recorded: bool,
}

/// What one agent's records show about its tools (§7 tool coverage).
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The tools of the agent's current declaration, in name order; empty when there is none.
    pub declared: Vec<DeclaredTool>,
    /// The names of decision records that are not in the current declaration, in name order;
    /// empty when there is no declaration.
    pub undeclared_recorded: Vec<String>,
    /// The seq of the `signafaide.tools` note that starts the current declaration, or `None`
    /// when the records hold none.
    pub declared_at_seq: Option<u64>,
}

/// The coverage of one agent's records, given as (seq, kind, name) in seq order. The current
/// declaration is the one started by the last `signafaide.tools` note; tool notes before the
/// first such note belong to a declaration the records do not hold and are ignored. Inside a
/// declaration a later note for the same tool replaces an earlier one. A `decision` counts as a
/// recorded tool unless its name starts with `signafaide.`; it is compared by its declared name.
pub fn coverage<'a>(records: impl IntoIterator<Item = (u64, Kind, &'a str)>) -> Coverage {
    let mut at: Option<u64> = None;
    let mut tools: BTreeMap<&str, bool> = BTreeMap::new();
    let mut called: BTreeSet<String> = BTreeSet::new();
    for (seq, kind, name) in records {
        match tool_note(kind, name) {
            Some(ToolNote::Header) => {
                at = Some(seq);
                tools.clear();
            }
            Some(ToolNote::Tool { name, recorded }) if at.is_some() => {
                tools.insert(name, recorded);
            }
            Some(ToolNote::Tool { .. }) => {}
            None if kind == Kind::Decision && !name.starts_with(RESERVED_PREFIX) => {
                called.insert(declared_name(name));
            }
            None => {}
        }
    }
    if at.is_none() {
        return Coverage::default();
    }
    Coverage {
        undeclared_recorded: called.into_iter().filter(|n| !tools.contains_key(n.as_str())).collect(),
        declared: tools
            .into_iter()
            .map(|(name, recorded)| DeclaredTool {
                name: name.to_string(),
                recorded,
            })
            .collect(),
        declared_at_seq: at,
    }
}

/// `1 declared tool is`, `2 declared tools are`.
fn count_is(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", plural(n as u64, one, many), if n == 1 { "is" } else { "are" })
}

/// The coverage of `agent` in words (§7), one line each: what was declared, then the recorded
/// tools the declaration does not list. The same wording in every verifier and in the service.
pub fn coverage_lines(agent: &str, c: &Coverage) -> Vec<String> {
    if c.declared_at_seq.is_none() {
        return vec![format!(
            "{agent}: no tool list was declared, so the pack cannot show which of the agent's tools are recorded"
        )];
    }
    let unrecorded: Vec<&str> = c
        .declared
        .iter()
        .filter(|t| !t.recorded)
        .map(|t| t.name.as_str())
        .collect();
    let mut out = Vec::new();
    if c.declared.is_empty() {
        out.push(format!("{agent}: the declared tool list is empty"));
    } else if unrecorded.is_empty() {
        // One tool: "the 1 declared tool is recorded".
        let all = if c.declared.len() == 1 { "the" } else { "all" };
        out.push(format!(
            "{agent}: {all} {} recorded",
            count_is(c.declared.len(), "declared tool", "declared tools")
        ));
    } else {
        out.push(format!(
            "{agent}: {} not recorded: {}",
            count_is(unrecorded.len(), "declared tool", "declared tools"),
            unrecorded.join(", ")
        ));
    }
    if !c.undeclared_recorded.is_empty() {
        out.push(format!(
            "{agent}: {} not in the declared tool list: {}",
            count_is(c.undeclared_recorded.len(), "recorded tool", "recorded tools"),
            c.undeclared_recorded.join(", ")
        ));
    }
    out
}

// --- telemetry notes (§2.7) ----------------------------------------------------------

/// `signafaide.telemetry/start/<tool name>`: the decisions of this tool that follow were derived
/// from telemetry spans and written when the span started, before the tool ran.
pub const TELEMETRY_START_PREFIX: &str = "signafaide.telemetry/start/";
/// `signafaide.telemetry/end/<tool name>`: the decisions of this tool that follow were derived
/// from telemetry spans and written when the span ended, after the tool ran.
pub const TELEMETRY_END_PREFIX: &str = "signafaide.telemetry/end/";
/// The records of this agent come from sampled telemetry: some tool calls may not be recorded.
pub const TELEMETRY_SAMPLED: &str = "signafaide.telemetry_sampled";
/// The telemetry sampler follows the caller's decision and keeps every trace this program
/// starts: only a tool call inside a trace that arrives marked as not sampled is not recorded.
pub const TELEMETRY_PARENT_SAMPLED: &str = "signafaide.telemetry_parent_sampled";
/// What a verifier says for an agent whose chain holds a `signafaide.telemetry_sampled` note.
pub const SAMPLED_LINE: &str = "records come from sampled telemetry: some tool calls may not be recorded";
/// What a verifier says for an agent whose chain holds a `signafaide.telemetry_parent_sampled` note.
pub const PARENT_SAMPLED_LINE: &str = "telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded";

/// When the decisions of a tool recorded from telemetry spans were written.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DecisionWritten {
    /// At span start, before the tool ran.
    Before,
    /// At span end, after the tool ran.
    After,
    /// The records hold notes of both kinds for the tool.
    Both,
}

impl DecisionWritten {
    fn words(self) -> &'static str {
        match self {
            DecisionWritten::Before => "decision written before the tool ran",
            DecisionWritten::After => "decision written after the tool ran",
            DecisionWritten::Both => "decisions written before and after the tool ran",
        }
    }
}

/// What a record says about telemetry, from its kind and name alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelemetryNote<'a> {
    /// `signafaide.telemetry_sampled`.
    Sampled,
    /// `signafaide.telemetry_parent_sampled`.
    ParentSampled,
    /// The tool is recorded from telemetry spans; `decision` is `Before` or `After`.
    Tool { name: &'a str, decision: DecisionWritten },
}

/// The envelope name of the note that says how `tool` is recorded from telemetry (§2.7).
pub fn telemetry_note_name(tool: &str, at_start: bool) -> String {
    format!(
        "{}{}",
        if at_start {
            TELEMETRY_START_PREFIX
        } else {
            TELEMETRY_END_PREFIX
        },
        declared_name(tool)
    )
}

/// Read a record as a telemetry note, or `None` when it is not one. Only a `note` can be one,
/// and a tool note with an empty tool name is not one.
pub fn telemetry_note(kind: Kind, name: &str) -> Option<TelemetryNote<'_>> {
    if kind != Kind::Note {
        return None;
    }
    if name == TELEMETRY_SAMPLED {
        return Some(TelemetryNote::Sampled);
    }
    if name == TELEMETRY_PARENT_SAMPLED {
        return Some(TelemetryNote::ParentSampled);
    }
    let (rest, decision) = match (
        name.strip_prefix(TELEMETRY_START_PREFIX),
        name.strip_prefix(TELEMETRY_END_PREFIX),
    ) {
        (Some(rest), _) => (rest, DecisionWritten::Before),
        (None, Some(rest)) => (rest, DecisionWritten::After),
        (None, None) => return None,
    };
    (!rest.is_empty()).then_some(TelemetryNote::Tool { name: rest, decision })
}

/// One tool recorded from telemetry spans.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TelemetryTool {
    pub name: String,
    pub decision: DecisionWritten,
}

/// What one agent's records say about telemetry (§7).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Telemetry {
    /// The tools recorded from telemetry spans, in name order.
    pub tools: Vec<TelemetryTool>,
    /// The records hold a `signafaide.telemetry_sampled` note.
    pub sampled: bool,
    /// The records hold a `signafaide.telemetry_parent_sampled` note.
    pub parent_sampled: bool,
}

/// What one agent's records, given as (kind, name), say about telemetry, or `None` when they
/// hold no telemetry note. A tool with notes of both kinds is `Both`.
pub fn telemetry<'a>(records: impl IntoIterator<Item = (Kind, &'a str)>) -> Option<Telemetry> {
    let mut tools: BTreeMap<&str, DecisionWritten> = BTreeMap::new();
    let mut sampled = false;
    let mut parent_sampled = false;
    for (kind, name) in records {
        match telemetry_note(kind, name) {
            Some(TelemetryNote::Sampled) => sampled = true,
            Some(TelemetryNote::ParentSampled) => parent_sampled = true,
            Some(TelemetryNote::Tool { name, decision }) => {
                let held = tools.entry(name).or_insert(decision);
                if *held != decision {
                    *held = DecisionWritten::Both;
                }
            }
            None => {}
        }
    }
    if tools.is_empty() && !sampled && !parent_sampled {
        return None;
    }
    Some(Telemetry {
        tools: tools
            .into_iter()
            .map(|(name, decision)| TelemetryTool {
                name: name.to_string(),
                decision,
            })
            .collect(),
        sampled,
        parent_sampled,
    })
}

/// The telemetry notes of `agent` in words (§7): the tools recorded from telemetry spans and
/// when their decisions were written, then what the telemetry's sampling leaves out.
pub fn telemetry_lines(agent: &str, t: &Telemetry) -> Vec<String> {
    let mut out = Vec::new();
    if !t.tools.is_empty() {
        let names: Vec<String> = t
            .tools
            .iter()
            .map(|x| format!("{} ({})", x.name, x.decision.words()))
            .collect();
        out.push(format!(
            "{agent}: {} recorded from telemetry spans: {}",
            count_is(t.tools.len(), "tool", "tools"),
            names.join(", ")
        ));
    }
    if t.sampled {
        out.push(format!("{agent}: {SAMPLED_LINE}"));
    }
    if t.parent_sampled {
        out.push(format!("{agent}: {PARENT_SAMPLED_LINE}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_are_kept_and_long_names_are_cut() {
        assert_eq!(declared_name("send_email"), "send_email");
        let exact = "x".repeat(101);
        assert_eq!(declared_name(&exact), exact);
        let long = "x".repeat(102);
        let d = declared_name(&long);
        assert_eq!(d.chars().count(), 101);
        assert!(d.starts_with(&"x".repeat(92)) && d.as_bytes()[92] == b'~');
        assert_eq!(declared_name(&d), d);
        assert_eq!(tool_note_name(&long, false).chars().count(), 128);
    }

    #[test]
    fn the_last_header_starts_the_current_declaration() {
        let recs = [
            (1, Kind::Note, "signafaide.tool/orphan"),
            (2, Kind::Note, "signafaide.tools"),
            (3, Kind::Note, "signafaide.tool/a"),
            (4, Kind::Note, "signafaide.tools"),
            (5, Kind::Note, "signafaide.tool/b"),
            (6, Kind::Note, "signafaide.tool_unrecorded/c"),
            (7, Kind::Note, "signafaide.tool/c"),
            (8, Kind::Decision, "a"),
            (9, Kind::Decision, "b"),
            (10, Kind::Decision, "signafaide.tool/b"),
            (11, Kind::Note, "signafaide.tool/"),
        ];
        let c = coverage(recs);
        assert_eq!(c.declared_at_seq, Some(4));
        assert_eq!(
            c.declared,
            vec![
                DeclaredTool {
                    name: "b".into(),
                    recorded: true
                },
                DeclaredTool {
                    name: "c".into(),
                    recorded: true
                }
            ]
        );
        assert_eq!(c.undeclared_recorded, vec!["a".to_string()]);
        assert_eq!(
            coverage_lines("bot", &c),
            vec![
                "bot: all 2 declared tools are recorded",
                "bot: 1 recorded tool is not in the declared tool list: a"
            ]
        );
    }

    #[test]
    fn wording() {
        let none = coverage([(1, Kind::Decision, "a")]);
        assert_eq!(
            coverage_lines("bot", &none),
            vec!["bot: no tool list was declared, so the pack cannot show which of the agent's tools are recorded"]
        );
        let one = coverage([
            (1, Kind::Note, TOOLS),
            (2, Kind::Note, "signafaide.tool_unrecorded/z"),
            (3, Kind::Note, "signafaide.tool/a"),
        ]);
        assert_eq!(
            coverage_lines("bot", &one),
            vec!["bot: 1 declared tool is not recorded: z"]
        );
        let empty = coverage([(1, Kind::Note, TOOLS)]);
        assert_eq!(
            coverage_lines("bot", &empty),
            vec!["bot: the declared tool list is empty"]
        );
    }

    #[test]
    fn telemetry_notes() {
        assert_eq!(
            telemetry([
                (Kind::Decision, "a"),
                (Kind::Note, "signafaide.tools"),
                (Kind::Decision, TELEMETRY_SAMPLED)
            ]),
            None
        );
        assert_eq!(telemetry_note(Kind::Note, "signafaide.telemetry/start/"), None);
        assert_eq!(telemetry_note_name(&"x".repeat(102), true).chars().count(), 128);
        let t = telemetry([
            (Kind::Note, "signafaide.telemetry/start/b"),
            (Kind::Note, TELEMETRY_SAMPLED),
            (Kind::Note, "signafaide.telemetry/end/a"),
            (Kind::Note, "signafaide.telemetry/end/b"),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&t).unwrap(),
            serde_json::json!({"tools": [{"name": "a", "decision": "after"}, {"name": "b", "decision": "both"}], "sampled": true, "parent_sampled": false})
        );
        assert_eq!(
            telemetry_lines("bot", &t),
            vec![
                "bot: 2 tools are recorded from telemetry spans: a (decision written after the tool ran), b (decisions written before and after the tool ran)",
                "bot: records come from sampled telemetry: some tool calls may not be recorded",
            ]
        );
        let one = telemetry([
            (Kind::Note, "signafaide.telemetry/start/a"),
            (Kind::Note, TELEMETRY_PARENT_SAMPLED),
        ])
        .unwrap();
        assert!(one.parent_sampled && !one.sampled);
        assert_eq!(
            telemetry_lines("bot", &one),
            vec![
                "bot: 1 tool is recorded from telemetry spans: a (decision written before the tool ran)",
                "bot: telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded",
            ]
        );
    }
}
