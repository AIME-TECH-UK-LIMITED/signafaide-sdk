//! Tool-call checks (SPEC §2.3, §2.8, §3.4, §3.5, §7, §10, §11): the `checks` a record carries,
//! the rule language and its evaluation (for a client and for the witness), the witness's
//! rulings, signed rule set versions, the shared fingerprint list, tool fingerprints, and the
//! verifier's tool-call checks report.
//!
//! Rulings are `allow` or `block`, nothing between; watch mode records what enforce mode would
//! have done. The secret, address, changed_tool and hidden_instruction checks run in the clients
//! only and are not here.

pub mod envelope;
pub mod fingerprints;
pub mod report;
pub mod rules;
pub mod ruling;
pub mod words;
pub mod file;

use crate::hash::hash_json;
use crate::{jcs, sha256, Hash};
use serde_json::{json, Map, Value};

/// `DISCLOSED_MAX_BYTES` (§9): the largest JCS(`disclosed`) a record may carry.
pub const DISCLOSED_MAX_BYTES: usize = 16_384;
/// `DISCLOSED_DAYS` (§9): disclosed values and their salt are kept this long.
pub const DISCLOSED_DAYS: i64 = 30;
/// `RULING_TIMEOUT_MS` (§9): how long a strict call waits for its ruling by default.
pub const RULING_TIMEOUT_MS: u64 = 10_000;
/// `RULES_REFRESH_MS` (§9).
pub const RULES_REFRESH_MS: u64 = 60_000;
/// `FINGERPRINTS_REFRESH_MS` (§9).
pub const FINGERPRINTS_REFRESH_MS: u64 = 60_000;
/// `FINGERPRINT_UPDATES_DAYS` (§9).
pub const FINGERPRINT_UPDATES_DAYS: i64 = 30;

/// The check ids, in the order of the §2.8 table.
pub const CHECK_IDS: [&str; 6] = ["secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction"];

/// A JSON integer literal (no fraction, no exponent) within ±(2^53−1) (§1).
pub fn safe_int(v: &Value) -> Option<i64> {
    let n = v.as_number()?;
    let i = n.as_i64()?;
    (i.unsigned_abs() <= jcs::MAX_SAFE_INTEGER).then_some(i)
}

/// 64 lowercase hex characters.
pub fn is_hex64(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// `rs_` and 26 Crockford base32 characters (§10.1).
pub fn is_set_id(s: &str) -> bool {
    s.len() == 29 && s.starts_with("rs_") && s[3..].bytes().all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U')))
}

/// A rule id (§10.1): `^[a-z0-9][a-z0-9._-]{0,63}$`.
pub fn is_rule_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && matches!(b[0], b'a'..=b'z' | b'0'..=b'9') && b.iter().all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// A JSON Pointer as §10.1 allows it: starts with `/`, at most 256 characters, `~` only as `~0` or `~1`.
pub fn is_pointer(s: &str) -> bool {
    if !s.starts_with('/') || s.chars().count() > 256 {
        return false;
    }
    let b = s.as_bytes();
    b.iter().enumerate().all(|(i, &c)| c != b'~' || matches!(b.get(i + 1), Some(b'0' | b'1')))
}

/// `sha256(disclosed_salt || JCS(disclosed))` (§2.3). `salt` is 32 lowercase hex characters.
pub fn disclosed_hash(disclosed: &Value, salt: &str) -> crate::Result<Hash> {
    let mut bytes = crate::model::parse_salt(salt)?.to_vec();
    bytes.extend_from_slice(jcs::canonicalize(disclosed)?.as_bytes());
    Ok(sha256(&bytes))
}

const SCHEMA_MAPS: [&str; 5] = ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"];
const SCHEMA_LISTS: [&str; 4] = ["allOf", "anyOf", "oneOf", "prefixItems"];
const SCHEMA_ONE: [&str; 11] = ["items", "additionalItems", "additionalProperties", "unevaluatedItems", "unevaluatedProperties", "contains", "propertyNames", "not", "if", "then", "else"];

/// §11.1 `strip`: the schema without the members `description` and `title`, in it and in every
/// schema inside it. A property named `description` inside `properties` stays.
pub fn strip_schema(s: &Value) -> Value {
    let Value::Object(o) = s else { return s.clone() };
    let mut out = Map::new();
    for (k, v) in o {
        if k == "description" || k == "title" {
            continue;
        }
        let stripped = match v {
            Value::Object(m) if SCHEMA_MAPS.contains(&k.as_str()) => Value::Object(m.iter().map(|(n, x)| (n.clone(), strip_schema(x))).collect()),
            Value::Array(a) if SCHEMA_LISTS.contains(&k.as_str()) => Value::Array(a.iter().map(strip_schema).collect()),
            Value::Array(a) if SCHEMA_ONE.contains(&k.as_str()) => Value::Array(a.iter().map(strip_schema).collect()),
            _ if SCHEMA_ONE.contains(&k.as_str()) => strip_schema(v),
            _ => v.clone(),
        };
        out.insert(k.clone(), stripped);
    }
    Value::Object(out)
}

/// A tool's fingerprints (§11.1): `{tool, description, schema, server}`, each 64 hex; `server` is
/// null for a tool that does not come from an MCP server (`server_info` None).
pub fn tool_fingerprints(name: &str, description: &str, input_schema: &Value, server_info: Option<&Value>) -> crate::Result<Value> {
    let server = match server_info {
        None => Value::Null,
        Some(si) => json!(hash_json(&json!({"name": si["name"], "version": si["version"]}))?.hex()),
    };
    Ok(json!({
        "tool": hash_json(&json!({"name": name, "description": description, "input_schema": input_schema}))?.hex(),
        "description": sha256(description.as_bytes()).hex(),
        "schema": hash_json(&strip_schema(input_schema))?.hex(),
        "server": server,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_pointers() {
        assert!(is_set_id("rs_01JD2K8Z5X3V7N2M4K6H8G0F1A"));
        assert!(!is_set_id("rs_01JD2K8Z5X3V7N2M4K6H8G0F1"));
        assert!(!is_set_id("rs_01JD2K8Z5X3V7N2M4K6H8G0F1I"));
        assert!(is_rule_id("payout-limit") && !is_rule_id("Payout") && !is_rule_id("-a"));
        assert!(is_pointer("/a~1b/m~0n") && !is_pointer("/a~2") && !is_pointer("a") && !is_pointer("/a~"));
        assert_eq!(safe_int(&json!(3)), Some(3));
        assert_eq!(safe_int(&serde_json::from_str("3.0").unwrap()), None);
        assert_eq!(safe_int(&serde_json::from_str("9007199254740992").unwrap()), None);
    }
}
