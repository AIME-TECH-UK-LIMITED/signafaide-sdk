//! Runs the built CLI against the shared vectors.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_signafaide-verify");

fn vectors() -> serde_json::Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn tmp(name: &str, v: &serde_json::Value) -> String {
    let dir = std::env::temp_dir().join(format!("signafaide-verify-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, v.to_string()).unwrap();
    p.to_string_lossy().into_owned()
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

const SCOPE: &str = ": 11 of 12 checks passed, 1 pending (public timestamp); export of every agent, all records, generated 2026-11-13T12:00:00.000Z";

/// A one-thread fake server: `path` answers `body`, anything else 404. Counts the requests.
fn serve(path: &'static str, body: String) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let h = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            loop {
                let mut x = String::new();
                if r.read_line(&mut x).unwrap() <= 2 {
                    break;
                }
            }
            let got = line.split(' ').nth(1).unwrap_or("").to_string();
            let b = if got == path { body.clone() } else { String::new() };
            let status = if b.is_empty() { "404 Not Found" } else { "200 OK" };
            let _ = write!(s.try_clone().unwrap(), "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}", b.len());
        }
    });
    (url, hits)
}

/// A one-thread fake Esplora API: every block-height maps to one hash whose merkle_root is `root`.
#[allow(dead_code)]
fn esplora(height: u64, root: String) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap() <= 2 {
                    break;
                }
            }
            let path = line.split(' ').nth(1).unwrap_or("").to_string();
            let hash = "ab".repeat(32);
            let body = if path == format!("/block-height/{height}") {
                hash
            } else if path == format!("/block/{hash}") {
                serde_json::json!({"id": hash, "height": height, "merkle_root": root}).to_string()
            } else {
                String::new()
            };
            let status = if body.is_empty() { "404 Not Found" } else { "200 OK" };
            let _ = write!(s.try_clone().unwrap(), "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        }
    });
    url
}

#[test]
fn valid_pack_passes_with_independent_keys() {
    let v = vectors();
    let pack = tmp("pack.json", &v["pack"]["pack"]);
    let keys = tmp("keys.json", &v["keys_document"]);
    let agents = tmp("agents.json", &v["agent_keys_document"]);
    let (code, out) = run(&[&pack, "--keys", &keys, "--agent-keys", &agents, "--offline"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.trim_end().ends_with(&format!("PASS{SCOPE}")), "{out}");
    assert!(out.contains("PENDING"), "ots line shows pending: {out}");
    assert_eq!(out.lines().filter(|l| l.trim_start().chars().next().is_some_and(|c| c.is_ascii_digit())).count(), 12);

    let (code, out) = run(&[&pack, "--keys", &keys, "--agent-keys", &agents, "--offline", "--json"]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["result"], "PASS");
    assert_eq!(report["result_line"], format!("PASS{SCOPE}"));
    assert_eq!(report["generated"], "2026-11-13T12:00:00.000Z");
    assert_eq!(report["checks"].as_array().unwrap().len(), 12);
}

#[test]
fn keys_are_required_and_agent_keys_must_be_independent() {
    let v = vectors();
    let pack = tmp("pack2.json", &v["pack"]["pack"]);
    let agents = tmp("agents2.json", &v["agent_keys_document"]);
    assert_eq!(run(&[&pack, "--agent-keys", &agents, "--offline"]).0, 2);
    let (code, out) = run(&[&pack, "--trust-embedded-keys", "--agent-keys", &agents, "--offline"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("WARNING") && out.trim_end().ends_with(&format!("PASS (service keys taken from the pack, not independent){SCOPE}")));
    // No agent keys: NOT INDEPENDENT, FAIL, and the CLI says how to get them.
    let keys = tmp("keys2.json", &v["keys_document"]);
    let (code, out) = run(&[&pack, "--keys", &keys, "--offline"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("NOT INDEPENDENT") && out.contains("signafaide keys export"), "{out}");
    let (code, out) = run(&[&pack, "--keys", &keys, "--trust-embedded-agent-keys", "--offline"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.trim_end().ends_with(&format!("PASS (agent keys taken from the pack, not independent){SCOPE}")), "{out}");
    // A manifest whose self-signature is broken is unreadable input.
    let mut bad = v["agent_keys_document"].clone();
    bad["keys"][0]["valid_from"] = serde_json::json!("2020-01-01T00:00:00.000Z");
    let bad = tmp("agents-bad.json", &bad);
    assert_eq!(run(&[&pack, "--keys", &keys, "--agent-keys", &bad, "--offline"]).0, 2);
}

#[test]
fn tampered_packs_fail_with_exit_1() {
    let v = vectors();
    for (i, t) in v["tampered"].as_array().unwrap().iter().enumerate() {
        let pack = tmp(&format!("t{i}.json"), &t["pack"]);
        let keys = tmp(&format!("t{i}-keys.json"), t.get("keys").unwrap_or(&v["keys_document"]));
        let mut args = vec![pack, "--keys".into(), keys, "--json".into()];
        match t.get("agent_keys") {
            Some(serde_json::Value::Null) => {}
            Some(a) => args.extend(["--agent-keys".into(), tmp(&format!("t{i}-agents.json"), a)]),
            None => args.extend(["--agent-keys".into(), tmp(&format!("t{i}-agents.json"), &v["agent_keys_document"])]),
        }
        if let Some(h) = t.get("head") {
            args.extend(["--head".into(), tmp(&format!("t{i}-head.json"), h)]);
        }
        if t.get("bitcoin").is_some() {
            continue; // header checks need https; the core tests run them with the headers given
        }
        args.push("--offline".into());
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, out) = run(&args);
        assert_eq!(code, 1, "{}: {out}", t["tamper"]);
        let json: Vec<&str> = out.lines().skip_while(|l| !l.starts_with('{')).collect();
        let end = json.iter().position(|l| *l == "}").unwrap();
        let report: serde_json::Value = serde_json::from_str(&json[..=end].join("\n")).unwrap();
        let first = report["checks"].as_array().unwrap().iter().find(|c| c["status"] == "fail").unwrap();
        assert_eq!(first["id"], t["check"], "{}", t["tamper"]);
    }
}

#[test]
fn public_timestamps_are_not_checked_offline_or_over_plain_http() {
    let v = vectors();
    let variant = v["variants"].as_array().unwrap().iter().find(|t| t.get("bitcoin").is_some()).unwrap();
    let pack = tmp("confirmed.json", &variant["pack"]);
    let keys = tmp("keys5.json", &v["keys_document"]);
    let agents = tmp("agents5.json", &v["agent_keys_document"]);
    let (h, hd) = variant["bitcoin"].as_object().unwrap().iter().next().unwrap();
    let (api, hits) = serve("/block-height/900000", hd["hash"].as_str().unwrap().into());
    assert_eq!(h, "900000");
    let (code, out) = run(&[&pack, "--keys", &keys, "--agent-keys", &agents, "--timestamp-check", &api]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("NOT CHECKED") && out.contains("plain http"), "{out}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "a plain-http explorer is never asked");
    let (code, out) = run(&[&pack, "--keys", &keys, "--agent-keys", &agents, "--offline"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("NOT CHECKED") && out.contains("claims block 900000"), "{out}");
}

#[test]
fn keys_over_plain_http_only_from_this_machine_and_not_independent() {
    let v = vectors();
    let pack = tmp("pack6.json", &v["pack"]["pack"]);
    let agents = tmp("agents6.json", &v["agent_keys_document"]);
    let (url, _) = serve("/keys.json", v["keys_document"].to_string());
    let (code, out) = run(&[&pack, "--keys", &format!("{url}/keys.json"), "--agent-keys", &agents, "--offline"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("WARNING") && out.contains(&format!("\nPASS (service keys fetched over plain http, not independent){SCOPE}\n")), "{out}");
    let (code, out) = run(&[&pack, "--keys", "http://192.0.2.1/keys.json", "--agent-keys", &agents, "--offline"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("plain http"), "{out}");
    for (u, ok) in [("http://127.0.0.1:1/x", true), ("http://localhost/x", true), ("http://[::1]:8/x", true), ("http://127.0.0.1@evil.example/x", false), ("http://example.com/x", false), ("https://127.0.0.1/x", false)] {
        assert_eq!(signafaide_verify::is_loopback_url(u), ok, "{u}");
    }
}

#[test]
fn content_from_a_chain_directory() {
    let v = vectors();
    let mut pack = v["pack"]["pack"].clone();
    for r in pack["records"].as_array_mut().unwrap() {
        r.as_object_mut().unwrap().remove("content");
        r.as_object_mut().unwrap().remove("salt");
    }
    let pack = tmp("pack4.json", &pack);
    let keys = tmp("keys4.json", &v["keys_document"]);
    let agents = tmp("agents4.json", &v["agent_keys_document"]);
    let dir = std::env::temp_dir().join(format!("signafaide-verify-chain-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("chain")).unwrap();
    let lines: Vec<String> = v["records"].as_array().unwrap().iter()
        .map(|r| serde_json::json!({"envelope": r["envelope"], "key_id": r["key_id"], "sig": r["sig"], "content": r["content"], "salt": r["salt"]}).to_string())
        .collect();
    std::fs::write(dir.join("chain/agent-a.jsonl"), lines.join("\n")).unwrap();
    let (code, out) = run(&[&pack, "--keys", &keys, "--agent-keys", &agents, "--offline", "--content", &dir.to_string_lossy(), "--json"]);
    assert_eq!(code, 0, "{out}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["checks"][11]["checked"], 4);
}

/// Round 6 (#50): the binary names its release and lists every flag, so a stale build is caught.
#[test]
fn version_and_help_name_the_release_and_every_flag() {
    let (code, out) = run(&["--version"]);
    assert_eq!((code, out.trim()), (0, concat!("signafaide-verify ", env!("CARGO_PKG_VERSION"))));
    let (code, help) = run(&["--help"]);
    assert_eq!(code, 0, "{help}");
    assert!(help.starts_with(concat!("signafaide-verify ", env!("CARGO_PKG_VERSION"), "\n")), "{help}");
    for flag in ["--keys", "--agent-keys", "--head", "--content", "--timestamp-check", "--offline", "--trust-embedded-keys", "--trust-embedded-agent-keys", "--json", "--version", "--help"] {
        assert!(help.contains(flag), "--help lacks {flag}: {help}");
    }
}

/// Round 6 (#51): a clean restart (a start note right after a stop note) is reported as such; a
/// start with no stop note before it keeps the warning.
#[test]
fn clean_and_unclean_restarts_are_told_apart() {
    let v = vectors();
    let keys = tmp("keys-r6.json", &v["keys_document"]);
    let agent_keys = tmp("agent-keys-r6.json", &v["agent_keys_document"]);
    let find = |name: &str| v["variants"].as_array().unwrap().iter().find(|c| c["name"].as_str().unwrap().starts_with(name)).unwrap()["pack"].clone();
    let run_pack = |file: &str, pack: serde_json::Value| run(&[&tmp(file, &pack), "--keys", &keys, "--agent-keys", &agent_keys, "--offline"]);
    let (code, out) = run_pack("clean.json", find("a clean restart: the start note"));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("a clean restart, nothing to warn about): agent-a after seq 2") && !out.contains("had not sent are not known"), "{out}");
    let (code, out) = run_pack("unclean.json", find("a new instance continued the chain after seq 2"));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("had not sent are not known: agent-a after seq 2") && !out.contains("clean restart"), "{out}");
    let (code, out) = run_pack("cut.json", find("a clean restart exported from its start note on"));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("had not sent are not known: agent-a after seq 2"), "{out}");
}
