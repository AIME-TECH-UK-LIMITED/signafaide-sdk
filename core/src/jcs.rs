//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Numbers follow the ECMAScript `Number.prototype.toString` rules. An integer literal (no
//! fraction or exponent) must lie within ±(2^53 − 1): a larger one cannot round-trip through
//! an IEEE 754 double, would hash identically to its neighbour, and is rejected. Any other
//! literal is a double and is serialized at any magnitude (`1e21` → `1e+21`).

use crate::{bail, Result};
use serde_json::{Number, Value};

pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Canonical form of `value` as a string (its UTF-8 bytes are what gets hashed).
pub fn canonicalize(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Parse JSON text, then canonicalize it.
pub fn canonicalize_str(json: &str) -> Result<String> {
    let v: Value = serde_json::from_str(json).map_err(|e| crate::Error::new(e.to_string()))?;
    canonicalize(&v)
}

fn write_value(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2: escape `"`, `\` and U+0000..U+001F (short forms where JSON has them,
/// otherwise `\u00xx` in lowercase hex); every other character is written as itself.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// RFC 8785 §3.2.2.3 number serialization, decided on the number's literal text:
/// an integer literal (no fraction, no exponent) must lie within ±(2^53 − 1); any other
/// literal is read as an IEEE 754 double and must be finite.
pub fn number(n: &Number) -> Result<String> {
    let text = n.to_string();
    if !text.contains(['.', 'e', 'E']) {
        return match text.parse::<i64>() {
            Ok(i) if i.unsigned_abs() <= MAX_SAFE_INTEGER => Ok(i.to_string()),
            _ => bail!("integer {text} is outside ±(2^53-1) and cannot be canonicalized exactly"),
        };
    }
    match text.parse::<f64>() {
        Ok(f) if f.is_finite() => Ok(format_double(f)),
        _ => bail!("number {text} is not a finite IEEE 754 double"),
    }
}

/// ECMAScript Number::toString for a finite double.
pub fn format_double(f: f64) -> String {
    if f == 0.0 {
        return "0".into(); // also -0
    }
    // Rust's `{:e}` yields the shortest digit string that round-trips: "d[.ddd]e<exp>".
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').expect("exponent form");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp.parse::<i32>().expect("exponent") + 1; // value = 0.digits × 10^n
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let mant = if k == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!("{mant}e{sign}{}", e.abs())
    };
    if f < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> String {
        canonicalize_str(s).unwrap()
    }

    #[test]
    fn rfc8785_numbers() {
        let cases = [
            ("0", "0"),
            ("-0", "0"),
            ("-0.0", "0"),
            ("1.0", "1"),
            ("0.1", "0.1"),
            ("4.50", "4.5"),
            ("2e-3", "0.002"),
            ("1e21", "1e+21"),
            ("1e20", "100000000000000000000"),
            ("1E30", "1e+30"),
            ("0.000001", "0.000001"),
            ("1e-7", "1e-7"),
            ("333333333.33333329", "333333333.3333333"),
            ("0.000000000000000000000000001", "1e-27"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("-1.5e-10", "-1.5e-10"),
            ("1.2345678901234568e20", "123456789012345680000"),
            ("9007199254740991", "9007199254740991"),
            ("-9007199254740991", "-9007199254740991"),
            ("9007199254740993.0", "9007199254740992"),
            ("295147905179352830000.0", "295147905179352830000"),
        ];
        for (input, want) in cases {
            assert_eq!(c(input), want, "input {input}");
        }
    }

    #[test]
    fn unsafe_integers_rejected() {
        for s in [
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551615",
            "123456789012345680000",
            "1e400",
        ] {
            assert!(canonicalize_str(s).is_err(), "{s}");
        }
    }

    #[test]
    fn rfc8785_sorting_and_strings() {
        // RFC 8785 §3.2.3 sorting example.
        let input = r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#;
        let want = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(c(input), want);
        assert_eq!(c(r#""\u0000\u001f\u007f/\u2028""#), "\"\\u0000\\u001f\u{7f}/\u{2028}\"");
        assert_eq!(c(r#""\b\t\n\f\r\"\\""#), r#""\b\t\n\f\r\"\\""#);
    }
}
