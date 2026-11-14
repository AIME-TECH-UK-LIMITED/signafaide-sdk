//! Protocol time: RFC 3339 UTC with exactly three fractional digits, e.g. `2026-11-13T10:00:00.000Z`,
//! years 0001 to 9999.

use crate::{bail, Result};

/// Milliseconds since the Unix epoch for a strict protocol timestamp.
pub fn parse(s: &str) -> Result<i64> {
    let b = s.as_bytes();
    let shape_ok = b.len() == 24
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'.',
            23 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    if !shape_ok {
        bail!("time must look like 2026-11-13T10:00:00.000Z (UTC, milliseconds)");
    }
    let num = |a: usize, z: usize| s[a..z].parse::<i64>().unwrap();
    let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
    let (h, mi, sec, ms) = (num(11, 13), num(14, 16), num(17, 19), num(20, 23));
    if y < 1 || !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || sec > 59 {
        bail!("time {s} is not a valid UTC date and time");
    }
    Ok((days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec) * 1000 + ms)
}

/// Format milliseconds since the epoch as a protocol timestamp.
pub fn format(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s, milli) = (rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
}

/// §2.2 monotonic time: the `time` a client writes for a new record. It is the machine's clock
/// (`wall`), raised to the previous record's `time` in the chain and to the signing key's
/// `valid_from` when the clock reads earlier (an NTP step back, a VM resumed). Returns the time
/// and whether it was raised; when it was, the client keeps `wall` in the content's
/// `meta.wall_time`, so the reading is not lost. A chain written this way never goes back.
pub fn clamp(wall: &str, prev: Option<&str>, valid_from: Option<&str>) -> Result<(String, bool)> {
    let w = parse(wall)?;
    let mut t = w;
    for floor in [prev, valid_from].into_iter().flatten() {
        t = t.max(parse(floor)?);
    }
    Ok((format(t), t != w))
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil-calendar algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for s in ["1970-01-01T00:00:00.000Z", "2026-11-13T10:00:00.000Z", "2024-02-29T23:59:59.999Z", "2000-03-01T00:00:00.001Z"] {
            assert_eq!(format(parse(s).unwrap()), s);
        }
        assert_eq!(parse("1970-01-01T00:00:01.000Z").unwrap(), 1000);
    }

    #[test]
    fn clamp_never_goes_back() {
        let (t, raised) = clamp("2026-11-13T10:00:00.000Z", Some("2026-11-13T10:00:05.000Z"), Some("2026-11-13T09:00:00.000Z")).unwrap();
        assert_eq!((t.as_str(), raised), ("2026-11-13T10:00:05.000Z", true));
        let (t, raised) = clamp("2026-11-13T10:00:10.000Z", Some("2026-11-13T10:00:05.000Z"), None).unwrap();
        assert_eq!((t.as_str(), raised), ("2026-11-13T10:00:10.000Z", false));
        let (t, raised) = clamp("2026-11-13T10:00:00.000Z", None, Some("2026-11-13T10:00:00.001Z")).unwrap();
        assert_eq!((t.as_str(), raised), ("2026-11-13T10:00:00.001Z", true));
    }

    #[test]
    fn rejects() {
        for s in ["2026-11-13T10:00:00Z", "2026-11-13T10:00:00.000+00:00", "2025-02-29T00:00:00.000Z", "2026-11-13 10:00:00.000Z", "2026-11-13T24:00:00.000Z", "2026-11-13T10:00:60.000Z", "0000-01-01T00:00:00.000Z"] {
            assert!(parse(s).is_err(), "{s}");
        }
    }
}
