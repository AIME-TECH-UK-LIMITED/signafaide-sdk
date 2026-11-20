//! signafaide-verify <pack.json> --agent-keys <file|url> [--keys <file|url>] [--head head.json]
//!   [--content <dir|file>] [--timestamp-check <explorer API>] [--offline] [--json]
//!
//! signafaide-verify --version | --help
//!
//! Without --keys the service keys are the ones pinned in this release (service-keys.json, the
//! same file as the SDK packages'); online they are also compared with the hosted witness's
//! published list, and any difference stops the run (§7). Exit code 0 = PASS, 1 = FAIL, 2 = the
//! inputs could not be read or the pinned keys differ from the published ones.

use signafaide_verify::{
    clean_line, heights_in, is_loopback_url, load_service_keys, parse_keys_document, verify_text, Inputs,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: signafaide-verify <pack.json> --agent-keys <file|url> [--keys <file|url>] [--head head.json] [--content <dir|file>] [--timestamp-check <explorer API URL>] [--offline] [--trust-embedded-keys] [--trust-embedded-agent-keys] [--json]\n       signafaide-verify --version | --help\n\nWithout --keys, the service keys pinned in this release are used and, unless --offline, checked against the hosted witness's published keys; a difference stops the run.";
/// The SDK release this binary was built from (the release check compares it with the packages).
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Esplora-style API (`GET /block-height/{h}`, `GET /block/{hash}/header`); blockstream.info/api works too.
const DEFAULT_BITCOIN: &str = "https://mempool.space/api";
/// The hosted witness's service keys, as published in this release (the release check keeps it
/// equal to spec/service-keys.json and the SDK packages' copies).
const PINNED_KEYS: &str = include_str!("../service-keys.json");

/// The pinned keys document. Only the `test-keys-url` feature (the conformance tests' build, never a
/// release) reads another from the file named by SIGNAFAIDE_VERIFY_KEYS_URL_PINNED, so the tests can
/// pin revocations; a release build ignores that variable.
fn pinned_text() -> Result<String, String> {
    #[cfg(feature = "test-keys-url")]
    if let Ok(f) = std::env::var("SIGNAFAIDE_VERIFY_KEYS_URL_PINNED") {
        return std::fs::read_to_string(&f).map_err(|e| format!("SIGNAFAIDE_VERIFY_KEYS_URL_PINNED {f}: {e}"));
    }
    Ok(PINNED_KEYS.to_string())
}
/// Where the hosted witness publishes its service keys; the pinned copy is checked against it.
const PUBLISHED_KEYS_URL: &str = "https://signafaide.co.uk/.well-known/signafaide-keys.json";

struct Args {
    pack: String,
    keys: Option<String>,
    agent_keys: Option<String>,
    head: Option<String>,
    trust_embedded: bool,
    trust_embedded_agent_keys: bool,
    content: Option<String>,
    bitcoin: String,
    offline: bool,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut a = Args {
        pack: String::new(),
        keys: None,
        agent_keys: None,
        head: None,
        trust_embedded: false,
        trust_embedded_agent_keys: false,
        content: None,
        bitcoin: DEFAULT_BITCOIN.into(),
        offline: false,
        json: false,
    };
    let mut pack = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--keys" => a.keys = Some(it.next().ok_or("--keys needs a file or URL")?),
            "--agent-keys" => {
                a.agent_keys = Some(
                    it.next()
                        .ok_or("--agent-keys needs a file or URL (from `signafaide keys export`)")?,
                )
            }
            "--head" => a.head = Some(it.next().ok_or("--head needs the client's .signafaide/head.json")?),
            "--content" => a.content = Some(it.next().ok_or("--content needs a directory or file")?),
            "--timestamp-check" | "--bitcoin" => {
                a.bitcoin = it
                    .next()
                    .ok_or("--timestamp-check needs an explorer API URL such as https://mempool.space/api")?
            }
            "--offline" => a.offline = true,
            "--trust-embedded-keys" => a.trust_embedded = true,
            "--trust-embedded-agent-keys" => a.trust_embedded_agent_keys = true,
            "--json" => a.json = true,
            "-h" | "--help" => {
                println!("signafaide-verify {VERSION}\n{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("signafaide-verify {VERSION}");
                std::process::exit(0);
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}\n{USAGE}")),
            s if pack.is_none() => pack = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}\n{USAGE}")),
        }
    }
    a.pack = pack.ok_or(USAGE)?;
    Ok(a)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// The CA certificates to trust for https: Mozilla's roots, or, when SSL_CERT_FILE names a PEM
/// file (a TLS-inspecting proxy, a test explorer), the certificates in it instead. Said on stderr.
fn tls() -> Result<ureq::tls::TlsConfig, String> {
    let builder = ureq::tls::TlsConfig::builder();
    let Some(file) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(builder.build());
    };
    let path = file.to_string_lossy().into_owned();
    let pem = std::fs::read(&path).map_err(|e| format!("SSL_CERT_FILE {path}: {e}"))?;
    let certs: Vec<_> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(Ok(c)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_, _>>()
        .map_err(|e| format!("SSL_CERT_FILE {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("SSL_CERT_FILE {path}: no certificate in it"));
    }
    eprintln!("WARNING: trusting the CA certificates in {path} for https");
    Ok(builder
        .root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(certs)))
        .build())
}

fn agent(tls: &ureq::tls::TlsConfig) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .tls_config(tls.clone())
        .build()
        .into()
}

/// GET `url` as text: no redirect is followed (an answer that is one is refused), at most `limit` bytes.
fn get(tls: &ureq::tls::TlsConfig, url: &str, limit: u64) -> Result<String, String> {
    let mut r = agent(tls).get(url).call().map_err(|e| format!("{url}: {e}"))?;
    let status = r.status().as_u16();
    if (300..400).contains(&status) {
        return Err(format!(
            "{url} answered a redirect (HTTP {status}); redirects are not followed, give the final address"
        ));
    }
    r.body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|e| format!("{url}: {e}"))
}

/// A file, or an http(s) URL, and whether it came over plain http. Plain http can be altered
/// in transit: it is accepted only from a loopback address, with a warning, and the keys then
/// do not count as independent.
fn fetch(tls: &ureq::tls::TlsConfig, flag: &str, src: &str) -> Result<(String, bool), String> {
    if src.starts_with("https://") || src.starts_with("http://") {
        let plain = src.starts_with("http://");
        if plain && !is_loopback_url(src) {
            return Err(format!("{flag} {src} uses plain http://, which anyone on the network path can alter; use https:// (plain http is accepted only from this machine, e.g. http://127.0.0.1)"));
        }
        if plain {
            eprintln!("WARNING: {flag} {src} uses plain http:// on this machine; the keys do not count as independent");
        }
        Ok((get(tls, src, 1 << 20)?, plain))
    } else {
        Ok((read(src)?, false))
    }
}

/// The content files: one file, or every *.jsonl file under a directory (for example
/// `.signafaide/chain`), in path order. Each file is read on its own (JSON lines or one array).
fn read_content(src: &str) -> Result<Vec<String>, String> {
    let path = Path::new(src);
    if path.is_file() {
        return Ok(vec![read(src)?]);
    }
    let mut files = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if matches!(p.extension().and_then(|e| e.to_str()), Some("jsonl")) {
                files.push(p);
            }
        }
    }
    files.sort();
    files.iter().map(|p| read(&p.to_string_lossy())).collect()
}

/// Why a plain-http explorer is not asked (§7 check 11).
const PLAIN_HTTP_EXPLORER: &str =
    "the explorer URL uses plain http, which anyone on the network path can alter; use https";

/// The block hash at `height` and its raw 80-byte header (hex) from an Esplora-style API; the
/// core checks the header against the hash and its proof of work.
fn block_header(tls: &ureq::tls::TlsConfig, base: &str, height: u64) -> Result<(String, String), String> {
    let base = base.trim_end_matches('/');
    let hash = get(tls, &format!("{base}/block-height/{height}"), 1 << 16)?
        .trim()
        .to_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{base}: no block at height {height}"));
    }
    let header = get(tls, &format!("{base}/block/{hash}/header"), 1 << 16)?
        .trim()
        .to_lowercase();
    Ok((hash, header))
}

/// Where the pinned keys are checked: the hosted witness's published list. A build with the
/// `test-keys-url` feature (the conformance tests' build, never a release) reads another https
/// address from SIGNAFAIDE_VERIFY_KEYS_URL; a release build ignores that variable.
fn published_keys_url() -> Result<String, String> {
    #[cfg(feature = "test-keys-url")]
    if let Ok(u) = std::env::var("SIGNAFAIDE_VERIFY_KEYS_URL") {
        if !u.starts_with("https://") {
            return Err(format!("SIGNAFAIDE_VERIFY_KEYS_URL {u} is not an https:// address"));
        }
        return Ok(u);
    }
    Ok(PUBLISHED_KEYS_URL.to_string())
}

/// What the check of the pinned keys against the published list found (§7).
enum CrossCheck {
    /// Every pinned key is in the list with the same bytes. `keys` is the keys document to verify
    /// with: the pinned keys with the list's retirements (valid_to) applied and its revocations of
    /// pinned keys listed under `revoked`; `retired` and `revoked` name them; `newer` are listed keys
    /// that are not pinned.
    Matched {
        url: String,
        newer: Vec<String>,
        retired: Vec<(String, String)>,
        revoked: Vec<String>,
        keys: String,
    },
    /// The list could not be had or read: the pinned keys are used, and the output says so.
    Unreachable {
        url: String,
        why: String,
    },
    Offline,
}

/// What the published list adds to the pinned keys: (newer keys, retirements applied, pinned keys
/// revoked there, the keys document to verify with).
type Compared = (Vec<String>, Vec<(String, String)>, Vec<String>, String);

/// The published list against the pinned keys (§5, §7). Keys are append-only: a pinned key must be
/// listed with the same key_id, public key and valid_from, or the run stops (KEYS DIFFER). A
/// valid_to there retires it (the earlier one applies); a `revoked` entry there bars it (no
/// signature by it verifies; it stays in the key list and in keys_hash). Both are applied and
/// named, and the run goes on. Newer keys and unknown fields are allowed. A `revoked` that is not a
/// list of entries with a key_id is malformed: KEYS DIFFER. Err: the list could not be read.
fn compare_keys(published: &str) -> Result<Result<Compared, Vec<String>>, String> {
    compare_with(&pinned_text()?, published)
}

/// `compare_keys` against the pinned document `pinned_text` (the release's, or a test's): the
/// core's one cross-check (`signafaide_core::keyset::cross_check`).
fn compare_with(pinned_text: &str, published: &str) -> Result<Result<Compared, Vec<String>>, String> {
    Ok(signafaide_core::keyset::cross_check(pinned_text, published)
        .map_err(|e| e.0)?
        .map(|c| (c.newer, c.retired, c.revoked, c.keys_document.to_string())))
}

/// The pinned keys and what checking them against the published list found. Err only when they
/// differ (KEYS DIFFER): nothing is verified then.
fn pinned_keys(tls: &ureq::tls::TlsConfig, offline: bool) -> Result<CrossCheck, String> {
    let url = published_keys_url()?;
    if offline {
        return Ok(CrossCheck::Offline);
    }
    let text = match get(tls, &url, 1 << 20) {
        Ok(t) => t,
        Err(why) => return Ok(CrossCheck::Unreachable { url, why }),
    };
    match compare_keys(&text) {
        Err(why) => Ok(CrossCheck::Unreachable {
            url: url.clone(),
            why: format!("{url}: {why}"),
        }),
        Ok(Ok((newer, retired, revoked, keys))) => Ok(CrossCheck::Matched {
            url,
            newer,
            retired,
            revoked,
            keys,
        }),
        Ok(Err(problems)) => Err(format!(
            "KEYS DIFFER: the service keys pinned in signafaide-verify {VERSION} do not match the ones published at {url}: {}. Nothing was verified. Use the newest signafaide-verify, or pass --keys with keys you have checked yourself",
            problems.join("; ")
        )),
    }
}

/// What the result line says when the keys given with --keys are not exactly the pinned set (§7).
const NOT_PINNED_SET: &str = "service keys from --keys differ from the pinned set";

/// True when the keys given are exactly the pinned set: the same entries (key id, public key,
/// valid_from, valid_to) and the same revocations as the pinned file. Anything else, a retirement or a moved valid_from too,
/// is a difference the result line names.
fn is_pinned_set(text: &str) -> bool {
    let entries = |t: &str| {
        parse_keys_document(t).map(|d| {
            let mut v: Vec<KeyFields> = d
                .keys
                .into_iter()
                .map(|k| (k.key_id, k.public_key, k.valid_from, k.valid_to))
                .collect();
            v.sort();
            let mut r: Vec<String> = d.revoked.into_iter().map(|r| r.key_id).collect();
            r.sort();
            (v, r)
        })
    };
    let pinned = pinned_text().unwrap_or_else(|_| PINNED_KEYS.to_string());
    matches!((entries(text), entries(&pinned)), (Ok(a), Ok(b)) if a == b)
}

/// One service key: (key id, public key, valid from, valid to).
type KeyFields = (String, String, String, Option<String>);

fn run() -> Result<bool, String> {
    let args = parse_args()?;
    let tls = tls()?;
    let pack = read(&args.pack)?;
    // (keys text, over plain http, the sentence for the output, the cross-check in a word,
    //  whether --keys gave other keys than the pinned set)
    let (keys, keys_plain_http, keys_source, cross_check, other_keys) = match args.keys.as_deref() {
        Some(k) => {
            let (text, plain) = fetch(&tls, "--keys", k)?;
            let other = !is_pinned_set(&text);
            (Some(text), plain, format!("{k} (--keys)"), "not_applicable", other)
        }
        None if args.trust_embedded => (
            None,
            false,
            "taken from the pack (--trust-embedded-keys)".to_string(),
            "not_applicable",
            false,
        ),
        None => {
            let pinned = format!("pinned in signafaide-verify {VERSION}");
            let (source, word, keys) = match pinned_keys(&tls, args.offline)? {
                CrossCheck::Offline => (
                    format!("{pinned}, not cross-checked (--offline)"),
                    "not_done_offline",
                    pinned_text()?,
                ),
                CrossCheck::Unreachable { url, why } => {
                    eprintln!("signafaide-verify: could not read the published service keys at {url} ({why}); the pinned keys are used, not cross-checked");
                    (
                        format!("{pinned}, not cross-checked (published list unreachable)"),
                        "unreachable",
                        pinned_text()?,
                    )
                }
                CrossCheck::Matched {
                    url,
                    newer,
                    retired,
                    revoked,
                    keys,
                } => {
                    let mut line = format!("{pinned}, cross-checked with {url}");
                    for (id, to) in &retired {
                        line += &format!("; {id} retired there at {to}, applied");
                    }
                    for id in &revoked {
                        line += &format!("; {id} revoked there, applied (no signature by it verifies)");
                    }
                    if !newer.is_empty() {
                        line += &format!(
                            "; newer keys there, not pinned in this release: {} (a pack made since one of them became valid needs a newer signafaide-verify)",
                            newer.join(", ")
                        );
                    }
                    (line, "matched", keys)
                }
            };
            (Some(keys), false, source, word, false)
        }
    };
    let (agent_keys, agent_keys_plain_http) = match args
        .agent_keys
        .as_deref()
        .map(|k| fetch(&tls, "--agent-keys", k))
        .transpose()?
    {
        Some((k, plain)) => (Some(k), plain),
        None => (None, false),
    };
    if agent_keys.is_none() && !args.trust_embedded_agent_keys {
        eprintln!("signafaide-verify: no --agent-keys: check 3 fails as NOT INDEPENDENT. Ask the customer for `signafaide keys export -o agent-keys.json` and pass --agent-keys agent-keys.json");
    }
    let head = args.head.as_deref().map(read).transpose()?;
    let contents = args
        .content
        .as_deref()
        .map(read_content)
        .transpose()?
        .unwrap_or_default();
    let plain = args.bitcoin.starts_with("http://");
    if plain && !args.offline {
        eprintln!("WARNING: --timestamp-check {} uses plain http://, which anyone on the network path can alter: public timestamps are not checked; use https://", args.bitcoin);
    }
    let bitcoin = (!args.offline).then(|| {
        heights_in(&pack)
            .into_iter()
            .map(|h| {
                (
                    h,
                    if plain {
                        Err(PLAIN_HTTP_EXPLORER.to_string())
                    } else {
                        block_header(&tls, &args.bitcoin, h)
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    });
    let inputs = Inputs {
        keys: keys.as_deref(),
        trust_embedded_keys: args.trust_embedded,
        // The release's pinned revocations always apply, whatever the keys' source (spec §7).
        revoked: load_service_keys(&pinned_text()?).map_err(|e| e.0)?.1,
        agent_keys: agent_keys.as_deref(),
        trust_embedded_agent_keys: args.trust_embedded_agent_keys,
        head: head.as_deref(),
        contents: contents.iter().map(String::as_str).collect(),
        bitcoin,
        keys_plain_http,
        agent_keys_plain_http,
    };
    let mut report = verify_text(&pack, &inputs).map_err(|e| e.0)?;
    if other_keys {
        // Into the report's own result line (text and JSON alike), never by editing printed text.
        report.qualify(NOT_PINNED_SET);
    }
    if args.json {
        let mut v = serde_json::to_value(&report).expect("report serializes");
        v["service_keys_source"] = serde_json::Value::String(keys_source);
        v["service_keys_cross_check"] = serde_json::Value::String(cross_check.into());
        // True when the keys used are the pinned set (pinned, or the same keys given with --keys).
        let pinned_set = if args.keys.is_some() {
            !other_keys
        } else {
            !args.trust_embedded
        };
        v["service_keys_pinned_set"] = serde_json::Value::Bool(pinned_set);
        println!("{}", serde_json::to_string_pretty(&v).expect("report serializes"));
    } else {
        // The report's lines with the key source just above the result line; every line cleaned
        // (clean_line), so nothing from the pack can make a line of its own.
        let mut lines = report.lines();
        let result = lines.pop().expect("the result line");
        lines.push(format!("service keys: {keys_source}"));
        lines.push(result);
        for l in &lines {
            println!("{}", clean_line(l));
        }
    }
    Ok(report.passed())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("signafaide-verify: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned0() -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(PINNED_KEYS).unwrap()["keys"][0].clone()
    }

    /// A pinned key retired in the published list: the cross-check passes and the keys used for
    /// verification carry that valid_to, so records the key signed after it fail check 6.
    #[test]
    fn retirement_and_revocation_are_applied_changes_differ() {
        let mut k = pinned0();
        k["valid_to"] = "2026-12-01T00:00:00.000Z".into();
        let doc = serde_json::json!({"keys": [k.clone()]}).to_string();
        let (_, retired, _, keys) = compare_keys(&doc).unwrap().unwrap();
        assert_eq!(
            retired,
            vec![(
                k["key_id"].as_str().unwrap().to_string(),
                "2026-12-01T00:00:00.000Z".into()
            )]
        );
        let used = signafaide_verify::parse_keys(&keys).unwrap();
        assert_eq!(used[0].valid_to.as_deref(), Some("2026-12-01T00:00:00.000Z"));
        // A revocation there is applied: the key stays in the list (and in keys_hash) and is
        // listed under `revoked` in the keys verified with; unknown fields in the entry are ignored.
        let revoked = serde_json::json!({"keys": [pinned0()], "revoked": [{"key_id": k["key_id"], "reason": "compromised", "later": 1}]});
        let (_, _, ids, keys) = compare_keys(&revoked.to_string()).unwrap().unwrap();
        assert_eq!(ids, vec![k["key_id"].as_str().unwrap().to_string()]);
        let (all, barred) = signafaide_verify::load_service_keys(&keys).unwrap();
        assert_eq!((all.len(), barred), (1, ids));
        // Changed bytes or a missing key: KEYS DIFFER.
        let mut changed = pinned0();
        changed["public_key"] = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".into();
        assert!(compare_keys(&serde_json::json!({"keys": [changed]}).to_string())
            .unwrap()
            .is_err());
        assert!(compare_keys(r#"{"keys": []}"#).unwrap().is_err());
        // A `revoked` that is not a list of entries with a key_id fails; it never reads as "none".
        for bad in [
            serde_json::json!({}),
            serde_json::Value::Null,
            serde_json::json!([{"reason": "x"}]),
            serde_json::json!([{"key_id": "x", "revoked_at": 5}]),
            serde_json::json!([{"key_id": "x", "reason": ["x"]}]),
        ] {
            let doc = serde_json::json!({"keys": [pinned0()], "revoked": bad});
            assert!(compare_keys(&doc.to_string()).unwrap().is_err(), "{doc}");
        }
        // null revoked_at and reason are read as absent (the core's Option fields).
        let nulls =
            serde_json::json!({"keys": [pinned0()], "revoked": [{"key_id": "x", "revoked_at": null, "reason": null}]});
        assert!(compare_keys(&nulls.to_string()).unwrap().is_ok());
        // A valid_to that is not a protocol time string makes the document malformed.
        for to in [
            serde_json::json!(5),
            serde_json::json!("tomorrow"),
            serde_json::json!({}),
        ] {
            let mut k = pinned0();
            k["valid_to"] = to;
            let doc = serde_json::json!({"keys": [k]});
            assert!(compare_keys(&doc.to_string()).unwrap().is_err(), "{doc}");
        }
        let mut k = pinned0();
        k["valid_to"] = serde_json::Value::Null;
        assert!(compare_keys(&serde_json::json!({"keys": [k]}).to_string())
            .unwrap()
            .is_ok());
    }

    /// The vectors' key_lifecycle.cross_check cases through this binary's cross-check.
    #[test]
    fn cross_check_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../spec/vectors.json")).unwrap();
        for t in v["key_lifecycle"]["cross_check"].as_array().unwrap() {
            let (pinned, published) = (t["pinned"].to_string(), t["published"].to_string());
            let got = match compare_with(&pinned, &published) {
                Err(_) => serde_json::json!({"unreadable": true}),
                Ok(Err(problems)) => serde_json::json!({"differ": problems}),
                Ok(Ok((newer, retired, revoked, keys))) => {
                    let (all, applied) = signafaide_verify::load_service_keys(&keys).unwrap();
                    serde_json::json!({"newer": newer, "retired": retired, "revoked": revoked, "keys": all, "applied_revoked": applied})
                }
            };
            assert_eq!(got, t["expect"], "{}", t["name"]);
        }
    }
}
