//! Checks `spec/vectors.json` against the library, independently of the generator, and runs
//! the verifier over the valid pack and every tampered pack.

use base64::Engine;
use serde_json::{json, Value};
use signafaide_core::hash::hash_json;
use signafaide_core::merkle::{self, Tree};
use signafaide_core::ots::DetachedFile;
use signafaide_core::sign::{self, Domain};
use signafaide_core::verify::{contents_from_text, verify_pack, Options, Status};
use signafaide_core::*;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("run `cargo run --bin gen-vectors` first")).unwrap()
}

fn h(v: &Value) -> Hash {
    Hash::from_hex(v.as_str().unwrap()).unwrap()
}

/// The default inputs: the vectors' service keys and agent-key manifest, offline.
fn keys(v: &Value) -> Options {
    vectors::Inputs::options(&json!({}), v)
}

#[test]
fn file_is_up_to_date() {
    assert!(
        vectors() == vectors::generate(),
        "spec/vectors.json is stale: run `cargo run --bin gen-vectors`"
    );
}

#[test]
fn jcs_vectors() {
    for c in vectors()["jcs"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        match c.get("output") {
            Some(out) => assert_eq!(
                jcs::canonicalize_str(input).unwrap(),
                out.as_str().unwrap(),
                "{}",
                c["name"]
            ),
            None => assert!(jcs::canonicalize_str(input).is_err(), "{}", c["name"]),
        }
    }
}

#[test]
fn record_vectors() {
    let v = vectors();
    let agent = &v["keys"][0];
    for r in v["records"].as_array().unwrap() {
        assert_eq!(
            jcs::canonicalize(&r["content"]).unwrap(),
            r["content_jcs"].as_str().unwrap()
        );
        let mut salted = hex::decode(r["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salted.len(), 16);
        salted.extend_from_slice(r["content_jcs"].as_str().unwrap().as_bytes());
        assert_eq!(sha256(&salted), h(&r["content_hash"]));
        assert_eq!(
            content_hash(&r["content"], r["salt"].as_str().unwrap()).unwrap(),
            h(&r["content_hash"])
        );
        // Unsalted, or with another salt, the content no longer gives the hash (§2.1).
        assert_ne!(
            sha256(r["content_jcs"].as_str().unwrap().as_bytes()),
            h(&r["content_hash"])
        );
        let e = Envelope::parse(&r["envelope"]).unwrap();
        assert_eq!(
            jcs::canonicalize(&r["envelope"]).unwrap(),
            r["envelope_jcs"].as_str().unwrap()
        );
        assert_eq!(e.record_hash().unwrap(), h(&r["record_hash"]));
        sign::verify(
            agent["public_key"].as_str().unwrap(),
            Domain::Record,
            &h(&r["record_hash"]),
            r["sig"].as_str().unwrap(),
        )
        .unwrap();
    }
    for bad in v["invalid_envelopes"].as_array().unwrap() {
        assert!(Envelope::parse(&bad["envelope"]).is_err(), "{}", bad["name"]);
    }
}

#[test]
fn key_and_signature_vectors() {
    let v = vectors();
    for k in v["keys"].as_array().unwrap() {
        let seed: [u8; 32] = hex::decode(k["seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let kp = sign::Keypair::from_seed(&seed);
        assert_eq!(kp.public_key_b64(), k["public_key"].as_str().unwrap());
        assert_eq!(kp.key_id(), k["key_id"].as_str().unwrap());
    }
    let service = v["keys"][1]["public_key"].as_str().unwrap();
    for s in v["signatures"].as_array().unwrap() {
        let d = match s["domain"].as_str().unwrap() {
            "record" => Domain::Record,
            "batch" => Domain::Batch,
            "head" => Domain::Head,
            "anchor" => Domain::Anchor,
            "draft" => Domain::Draft,
            other => panic!("unknown domain {other}"),
        };
        assert_eq!(
            hex::encode(sign::message(d, &h(&s["hash"]))),
            s["message_hex"].as_str().unwrap()
        );
        sign::verify(service, d, &h(&s["hash"]), s["sig"].as_str().unwrap()).unwrap();
    }
    for s in v["cross_domain"].as_array().unwrap() {
        let d = match s["verify_domain"].as_str().unwrap() {
            "batch" => Domain::Batch,
            "head" => Domain::Head,
            "anchor" => Domain::Anchor,
            "draft" => Domain::Draft,
            other => panic!("unknown domain {other}"),
        };
        assert!(sign::verify(service, d, &h(&s["hash"]), s["sig"].as_str().unwrap()).is_err());
    }
}

#[test]
fn merkle_and_batch_vectors() {
    let v = vectors();
    for t in v["merkle"]["trees"].as_array().unwrap() {
        let items: Vec<Hash> = t["items"].as_array().unwrap().iter().map(h).collect();
        let tree = Tree::new(&items).unwrap();
        assert_eq!(tree.root(), h(&t["root"]));
        for (i, p) in t["paths"].as_array().unwrap().iter().enumerate() {
            let path: Vec<Hash> = p.as_array().unwrap().iter().map(h).collect();
            assert!(merkle::verify_path(
                &items[i],
                i as u64,
                items.len() as u64,
                &path,
                &tree.root()
            ));
        }
    }
    let b = &v["batch"];
    assert_eq!(sha256(b["batch_jcs"].as_str().unwrap().as_bytes()), h(&b["batch_hash"]));
    let batch: Batch = from_value(&b["batch"]).unwrap();
    assert_eq!(batch.hash().unwrap(), h(&b["batch_hash"]));
    sign::verify(
        v["keys"][1]["public_key"].as_str().unwrap(),
        Domain::Batch,
        &h(&b["batch_hash"]),
        b["batch_sig"].as_str().unwrap(),
    )
    .unwrap();
    let hd: Head = from_value(&v["head"]["head"]).unwrap();
    assert_eq!(hd.hash().unwrap(), h(&v["head"]["head_hash"]));
    let a: Anchor = from_value(&v["anchor"]["anchor"]).unwrap();
    assert_eq!(
        sha256(v["anchor"]["signed_part_jcs"].as_str().unwrap().as_bytes()),
        a.hash().unwrap()
    );
}

#[test]
fn ots_and_drand_vectors() {
    let v = vectors();
    for o in v["ots"].as_array().unwrap() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(o["base64"].as_str().unwrap())
            .unwrap();
        if o.get("error").is_some() {
            assert!(DetachedFile::parse(&bytes).is_err(), "{}", o["name"]);
            continue;
        }
        let f = DetachedFile::parse(&bytes).unwrap();
        for b in o.get("bitcoin").and_then(Value::as_array).into_iter().flatten() {
            let att = f.timestamp.bitcoin_attestations().unwrap();
            let mut want: [u8; 32] = hex::decode(b["merkle_root"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            want.reverse();
            assert_eq!(att, vec![(b["height"].as_u64().unwrap(), want)]);
        }
        assert_eq!(f.serialize(), bytes);
        assert_eq!(Hash(f.digest), h(&o["digest"]));
        let status = match f.timestamp.status() {
            ots::OtsStatus::Confirmed(n) => format!("confirmed@{n}"),
            ots::OtsStatus::Pending => "pending".into(),
            ots::OtsStatus::Empty => "empty".into(),
        };
        assert_eq!(status, o["status"].as_str().unwrap());
    }
    for b in v["block_headers"].as_array().unwrap() {
        let hd = verify::block_header_from_hex(b["hash"].as_str().unwrap(), b["header"].as_str().unwrap()).unwrap();
        match bitcoin::check_header(&hd) {
            Ok(mut root) => {
                assert!(b["valid"].as_bool().unwrap(), "{}", b["name"]);
                root.reverse();
                assert_eq!(hex::encode(root), b["merkle_root"].as_str().unwrap());
            }
            Err(_) => assert!(!b["valid"].as_bool().unwrap(), "{}", b["name"]),
        }
    }
    for d in v["drand"].as_array().unwrap() {
        let beacon: Drand = from_value(&d["beacon"]).unwrap();
        assert_eq!(
            drand::verify_beacon(&beacon) == drand::BeaconCheck::Valid,
            d["valid"].as_bool().unwrap()
        );
    }
    for d in v["drand_time"].as_array().unwrap() {
        let t = time::parse(d["server_time"].as_str().unwrap()).unwrap();
        assert_eq!(
            drand::check_round_time(t, d["round"].as_u64().unwrap()).is_ok(),
            d["valid"].as_bool().unwrap(),
            "{d}"
        );
    }
}

#[test]
fn registration_agent_keys_and_keys_hash_vectors() {
    let v = vectors();
    let r = &v["registration"];
    let reg: Registration = from_value(&r["registration"]).unwrap();
    assert_eq!(
        jcs::canonicalize(&r["registration"]).unwrap(),
        r["registration_jcs"].as_str().unwrap()
    );
    assert_eq!(reg.hash().unwrap(), h(&r["registration_hash"]));
    sign::verify(
        &reg.public_key,
        Domain::Register,
        &reg.hash().unwrap(),
        r["proof"].as_str().unwrap(),
    )
    .unwrap();
    assert!(sign::verify(
        &reg.public_key,
        Domain::Record,
        &reg.hash().unwrap(),
        r["proof"].as_str().unwrap()
    )
    .is_err());
    sign::verify(
        v["keys"][2]["public_key"].as_str().unwrap(),
        Domain::Rotate,
        &reg.hash().unwrap(),
        r["rotation"]["sig"].as_str().unwrap(),
    )
    .unwrap();

    let keys = signafaide_core::verify::agent_keys_from_text(&v["agent_keys_document"].to_string()).unwrap();
    assert_eq!(keys[0].key_id, v["keys"][0]["key_id"].as_str().unwrap());
    let mut forged = v["agent_keys_document"].clone();
    forged["keys"][0]["valid_from"] = json!("2020-01-01T00:00:00.000Z");
    assert!(
        signafaide_core::verify::agent_keys_from_text(&forged.to_string()).is_err(),
        "valid_from is covered by the self-signature"
    );

    let mut retired = v["agent_keys_document"].clone();
    retired["keys"][0]["valid_to"] = json!("2026-11-13T10:04:00.000Z");
    assert!(
        signafaide_core::verify::agent_keys_from_text(&retired.to_string()).is_err(),
        "valid_to is covered by the self-signature"
    );

    let e = &v["export"];
    let pack: Pack = from_value(&v["pack"]["pack"]).unwrap();
    let st = pack.statement().unwrap();
    assert_eq!(
        jcs::canonicalize(&serde_json::to_value(&st).unwrap()).unwrap(),
        e["statement_jcs"].as_str().unwrap()
    );
    assert_eq!(st.records_hash, h(&e["records_hash"]));
    assert_eq!(st.hash().unwrap(), h(&e["statement_hash"]));
    sign::verify(
        v["keys"][1]["public_key"].as_str().unwrap(),
        Domain::Export,
        &h(&e["statement_hash"]),
        e["export_sig"].as_str().unwrap(),
    )
    .unwrap();

    let k = &v["keys_hash"];
    let list: Vec<KeyEntry> = from_value(&k["keys"]).unwrap();
    assert_eq!(
        sha256(k["committed_jcs"].as_str().unwrap().as_bytes()),
        h(&k["keys_hash"])
    );
    assert_eq!(
        service_keys_hash(&list, time::parse(k["created"].as_str().unwrap()).unwrap()).unwrap(),
        h(&k["keys_hash"])
    );
}

#[test]
fn variants_pass_with_their_values() {
    let v = vectors();
    let variants = v["variants"].as_array().unwrap();
    assert!(variants.len() >= 7);
    for t in variants {
        let r = verify_pack(&t["pack"], &vectors::Inputs::options(t, &v)).unwrap();
        assert!(r.passed(), "{}\n{}", t["name"], r.to_text());
        assert_eq!(r.result_line(), t["expect"]["result_line"].as_str().unwrap());
        for (id, want) in t["expect"]["checks"].as_object().unwrap() {
            let c = r.check(id);
            let got = c
                .value
                .clone()
                .unwrap_or_else(|| serde_json::to_value(c.status).unwrap().as_str().unwrap().to_string());
            assert_eq!(&json!(got), want, "{} check {id}", t["name"]);
        }
        if let Some(n) = t["expect"]["chain_note"].as_str() {
            assert!(r.check("chain").detail.contains(n), "{}\n{}", t["name"], r.to_text());
        }
        // Tool coverage (§7): the same object and the same lines in every verifier.
        assert_eq!(
            serde_json::to_value(&r.coverage).unwrap(),
            t["expect"]["coverage"],
            "{}",
            t["name"]
        );
        assert_eq!(
            json!(r.coverage_lines()),
            t["expect"]["coverage_lines"],
            "{}",
            t["name"]
        );
        for line in r.coverage_lines() {
            assert!(
                r.to_text().contains(&format!("coverage: {line}\n")),
                "{}\n{}",
                t["name"],
                r.to_text()
            );
        }
        // Telemetry notes (§2.7, §7): likewise.
        assert_eq!(
            serde_json::to_value(&r.telemetry).unwrap(),
            t["expect"]["telemetry"],
            "{}",
            t["name"]
        );
        assert_eq!(
            json!(r.telemetry_lines()),
            t["expect"]["telemetry_lines"],
            "{}",
            t["name"]
        );
        for line in r.telemetry_lines() {
            assert!(
                r.to_text().contains(&format!("telemetry: {line}\n")),
                "{}\n{}",
                t["name"],
                r.to_text()
            );
        }
        // Tool-call checks (§7): likewise.
        assert_eq!(
            serde_json::to_value(&r.tool_checks).unwrap(),
            t["expect"]["tool_call_checks"],
            "{}",
            t["name"]
        );
        assert_eq!(
            json!(r.tool_checks_lines()),
            t["expect"]["tool_call_checks_lines"],
            "{}",
            t["name"]
        );
        for line in r.tool_checks_lines() {
            assert!(
                r.to_text().contains(&format!("tool-call checks: {line}\n")),
                "{}\n{}",
                t["name"],
                r.to_text()
            );
        }
        // Rules in words (§7, §10.5, spec 1.1): likewise.
        assert_eq!(
            serde_json::to_value(&r.rules).unwrap(),
            t["expect"]["rules"],
            "{}",
            t["name"]
        );
        assert_eq!(json!(r.rules_lines()), t["expect"]["rules_lines"], "{}", t["name"]);
        for line in r.rules_lines() {
            assert!(
                r.to_text().contains(&format!("rules: {line}\n")),
                "{}\n{}",
                t["name"],
                r.to_text()
            );
        }
    }
    // The instance-start note (§8) names the chain and the seq it continues after.
    let notes: Vec<&str> = variants
        .iter()
        .filter_map(|t| t["expect"]["chain_note"].as_str())
        .collect();
    assert_eq!(
        notes,
        vec![
            format!("{INSTANCE_NOTE}: agent-a after seq 2").as_str(),
            format!("{CLEAN_RESTART_NOTE}: agent-a after seq 2").as_str(),
            // The stop note is outside the exported window: the pack cannot show it.
            format!("{INSTANCE_NOTE}: agent-a after seq 2").as_str(),
        ]
    );
}

/// Telemetry notes (§2.7, §7), written out here independently of the generator.
#[test]
fn telemetry_vectors() {
    let v = vectors();
    let variants = v["variants"].as_array().unwrap();
    let find = |name: &str| {
        variants
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("no variant {name}"))
    };
    let all =
        find("telemetry notes: tools recorded from sampled telemetry spans, decisions written before, after and both");
    assert_eq!(
        all["expect"]["telemetry"],
        json!({"agent-a": {"tools": [{"name": "approve_payout", "decision": "both"}, {"name": "send_email", "decision": "after"}], "sampled": true, "parent_sampled": false}})
    );
    assert_eq!(
        all["expect"]["telemetry_lines"],
        json!([
            "agent-a: 2 tools are recorded from telemetry spans: approve_payout (decisions written before and after the tool ran), send_email (decision written after the tool ran)",
            "agent-a: records come from sampled telemetry: some tool calls may not be recorded",
        ])
    );
    let before = find("telemetry notes: sampling that follows the caller, one tool with its decision written before the tool ran; a decision named like a telemetry note is not one");
    assert_eq!(
        before["expect"]["telemetry"],
        json!({"agent-a": {"tools": [{"name": "approve_payout", "decision": "before"}], "sampled": false, "parent_sampled": true}})
    );
    assert_eq!(
        before["expect"]["telemetry_lines"],
        json!([
            "agent-a: 1 tool is recorded from telemetry spans: approve_payout (decision written before the tool ran)",
            "agent-a: telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded",
        ])
    );
    // Every other variant, and the valid pack, holds no telemetry note: nothing is reported.
    assert_eq!(
        variants
            .iter()
            .filter(|t| t["expect"]["telemetry"] != json!({}))
            .count(),
        2
    );
    assert_eq!(v["pack"]["expect"]["telemetry"], json!({}));
    assert_eq!(v["pack"]["expect"]["telemetry_lines"], json!([]));
    assert!(variants.iter().all(|t| t["expect"]["telemetry_lines"].is_array()));
}

/// Tool declarations (§2.6) and coverage (§7), written out here independently of the generator.
#[test]
fn tool_coverage_vectors() {
    let v = vectors();
    let none = "no tool list was declared, so the pack cannot show which of the agent's tools are recorded";
    let want: Vec<(&str, Vec<String>, Option<u64>)> = vec![
        (
            "a tool declaration: every declared tool is recorded",
            vec!["agent-a: all 2 declared tools are recorded".into()],
            Some(1),
        ),
        (
            "a tool declaration with unrecorded tools, and recorded tools it does not list",
            vec![
                "agent-a: 2 declared tools are not recorded: delete_file, send_email".into(),
                "agent-a: 2 recorded tools are not in the declared tool list: escalate, reject_refund".into(),
            ],
            Some(1),
        ),
        (
            "a second tool declaration replaces the first; a tool in both forms takes the later note",
            vec!["agent-a: all 2 declared tools are recorded".into()],
            Some(4),
        ),
        (
            "a tool declaration with one tool, not recorded",
            vec![
                "agent-a: 1 declared tool is not recorded: send_email".into(),
                "agent-a: 1 recorded tool is not in the declared tool list: approve_payout".into(),
            ],
            Some(1),
        ),
        (
            "a tool declaration with no tools",
            vec![
                "agent-a: the declared tool list is empty".into(),
                "agent-a: 1 recorded tool is not in the declared tool list: approve_payout".into(),
            ],
            Some(1),
        ),
        (
            "a tool name too long for a declaration is cut and matched to its decision",
            vec!["agent-a: all 2 declared tools are recorded".into()],
            Some(1),
        ),
        (
            "a tool declaration exported from after its header: the tool note left is ignored",
            vec![format!("agent-a: {none}")],
            None,
        ),
        (
            "two agents: one declared its tools, the other did not",
            vec![
                "agent-a: the 1 declared tool is recorded".into(),
                format!("agent-b: {none}"),
            ],
            Some(1),
        ),
    ];
    let variants = v["variants"].as_array().unwrap();
    for (name, lines, at) in &want {
        let t = variants
            .iter()
            .find(|t| t["name"] == *name)
            .unwrap_or_else(|| panic!("no variant {name}"));
        assert_eq!(t["expect"]["coverage_lines"], json!(lines), "{name}");
        assert_eq!(
            t["expect"]["coverage"]["agent-a"]["declared_at_seq"],
            json!(at),
            "{name}"
        );
    }
    // Every other variant, and the valid pack, declares nothing.
    let declared = variants
        .iter()
        .filter(|t| {
            t["expect"]["coverage"]
                .as_object()
                .unwrap()
                .values()
                .any(|c| !c["declared_at_seq"].is_null())
        })
        .count();
    assert_eq!(declared, want.len() - 1);
    assert_eq!(
        v["pack"]["expect"]["coverage_lines"],
        json!([format!("agent-a: {none}")])
    );
    assert_eq!(
        v["pack"]["expect"]["coverage"],
        json!({"agent-a": {"declared": [], "undeclared_recorded": [], "declared_at_seq": null}})
    );
    let cut = variants.iter().find(|t| t["name"] == want[5].0).unwrap();
    let long = &cut["expect"]["coverage"]["agent-a"]["declared"][1]["name"];
    assert_eq!(long.as_str().unwrap().chars().count(), 101);

    for c in v["tool_names"].as_array().unwrap() {
        let tool = c["tool"].as_str().unwrap();
        let d = coverage::declared_name(tool);
        assert_eq!(d, c["declared_name"].as_str().unwrap(), "{}", c["name"]);
        assert!(d.chars().count() <= coverage::MAX_DECLARED_NAME);
        if tool.chars().count() <= 101 {
            assert_eq!(d, tool);
        } else {
            let kept: String = tool.chars().take(92).collect();
            assert_eq!(
                d,
                format!("{kept}~{}", &sha256(tool.as_bytes()).hex()[..8]),
                "{}",
                c["name"]
            );
        }
        assert_eq!(coverage::declared_name(&d), d);
        assert_eq!(c["recorded_note"], json!(format!("signafaide.tool/{d}")));
        assert_eq!(c["unrecorded_note"], json!(format!("signafaide.tool_unrecorded/{d}")));
        assert!(c["unrecorded_note"].as_str().unwrap().chars().count() <= 128);
        assert_eq!(
            coverage::tool_note(Kind::Note, c["recorded_note"].as_str().unwrap()),
            Some(coverage::ToolNote::Tool {
                name: &d,
                recorded: true
            })
        );
        assert_eq!(
            coverage::tool_note(Kind::Decision, c["recorded_note"].as_str().unwrap()),
            None
        );
    }
    assert_eq!(v["tool_names"].as_array().unwrap().len(), 10);
}

#[test]
fn valid_pack_passes() {
    let v = vectors();
    let report = verify_pack(&v["pack"]["pack"], &keys(&v)).unwrap();
    assert!(report.passed(), "{}", report.to_text());
    for (id, want) in v["pack"]["expect"]["checks"].as_object().unwrap() {
        let c = report.check(id);
        let got = c
            .value
            .clone()
            .unwrap_or_else(|| serde_json::to_value(c.status).unwrap().as_str().unwrap().to_string());
        assert_eq!(&json!(got), want, "check {id}");
    }
    assert_eq!(report.check("drand").status, Status::Pass);
    assert_eq!(report.check("ots").value.as_deref(), Some("pending"));
}

#[test]
fn time_clamp_vectors() {
    let v = vectors();
    let cases = v["time_clamp"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let (t, raised) = signafaide_core::time::clamp(
            c["wall"].as_str().unwrap(),
            c["prev"].as_str(),
            c["valid_from"].as_str(),
        )
        .unwrap();
        assert_eq!(
            (t.as_str(), raised),
            (c["time"].as_str().unwrap(), c["raised"].as_bool().unwrap()),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn every_tampered_pack_fails_at_its_check() {
    let v = vectors();
    let tampered = v["tampered"].as_array().unwrap();
    assert_eq!(tampered.len(), 59, "one tampered pack per rule");
    for id in v["check_ids"].as_array().unwrap() {
        assert!(tampered.iter().any(|t| t["check"] == *id), "no tampered pack for {id}");
    }
    for t in tampered {
        let report = verify_pack(&t["pack"], &vectors::Inputs::options(t, &v)).unwrap();
        assert!(!report.passed(), "{} should fail", t["check"]);
        assert_eq!(
            report.first_failed(),
            t["first_failed"].as_str(),
            "{}\n{}",
            t["tamper"],
            report.to_text()
        );
    }
}

#[test]
fn an_empty_pack_fails_with_no_records() {
    let v = vectors();
    let empty = v["tampered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["pack"]["records"] == json!([]))
        .expect("empty-pack vector");
    let report = verify_pack(&empty["pack"], &keys(&v)).unwrap();
    assert_eq!(report.result, "FAIL");
    let schema = report.check("schema");
    assert_eq!(
        (schema.failures[0].item.as_str(), schema.failures[0].message.as_str()),
        ("pack", verify::NO_RECORDS)
    );
    assert!(report.to_text().contains("pack: no records"));
}

#[test]
fn keys_are_required_and_embedded_keys_warn() {
    let v = vectors();
    let pack = &v["pack"]["pack"];
    assert!(verify_pack(pack, &Options::default()).is_err());
    let mut o = keys(&v);
    o.service_keys = None;
    o.trust_embedded_keys = true;
    let r = verify_pack(pack, &o).unwrap();
    assert!(r.passed() && r.warnings.len() == 1);
    let scope = ": 11 of 12 checks passed, 1 pending (public timestamp); export of every agent, all records, generated 2026-11-13T12:00:00.000Z";
    assert_eq!(
        r.result_line(),
        format!("PASS (service keys taken from the pack, not independent){scope}")
    );
    // Without independent agent keys check 3 fails, unless they are trusted explicitly.
    let r = verify_pack(
        pack,
        &Options {
            trust_embedded_keys: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r.first_failed(), Some("record_sig"));
    assert!(r.check("record_sig").failures[0].message.starts_with("NOT INDEPENDENT"));
    let r = verify_pack(
        pack,
        &Options {
            trust_embedded_keys: true,
            trust_embedded_agent_keys: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        r.result_line(),
        format!("PASS (service keys and agent keys taken from the pack, not independent){scope}")
    );
    // A service key that is unknown to the independent source fails the batch and head checks.
    let mut foreign = keys(&v);
    foreign.service_keys = Some(vec![from_value(&json!({"key_id": "0000000000000000", "public_key": v["keys"][2]["public_key"], "valid_from": "2026-01-01T00:00:00.000Z", "valid_to": null})).unwrap()]);
    let r = verify_pack(pack, &foreign).unwrap();
    assert_eq!(r.first_failed(), Some("batch_sig"));
}

#[test]
fn local_content_is_checked() {
    let v = vectors();
    let mut pack = v["pack"]["pack"].clone();
    for r in pack["records"].as_array_mut().unwrap() {
        r.as_object_mut().unwrap().remove("content");
        r.as_object_mut().unwrap().remove("salt");
    }
    let none = verify_pack(&pack, &keys(&v)).unwrap();
    assert_eq!(none.check("content").status, Status::NotChecked);

    let lines: Vec<String> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| json!({"envelope": r["envelope"], "content": r["content"], "salt": r["salt"]}).to_string())
        .collect();
    let mut opts = keys(&v);
    opts.contents = contents_from_text(&lines.join("\n")).unwrap();
    let r = verify_pack(&pack, &opts).unwrap();
    assert_eq!(
        (r.check("content").status, r.check("content").checked),
        (Status::Pass, 4)
    );

    let mut bad = v["records"][3].clone();
    bad["content"]["output"]["refund"] = json!(true);
    opts.contents = contents_from_text(
        &json!({"envelope": bad["envelope"], "content": bad["content"], "salt": bad["salt"]}).to_string(),
    )
    .unwrap();
    assert_eq!(verify_pack(&pack, &opts).unwrap().first_failed(), Some("content"));
    // Without its salt the content cannot be checked against the hash: a failure, never a pass.
    let good = &v["records"][3];
    opts.contents =
        contents_from_text(&json!({"envelope": good["envelope"], "content": good["content"]}).to_string()).unwrap();
    assert_eq!(verify_pack(&pack, &opts).unwrap().first_failed(), Some("content"));
}

#[test]
fn malformed_pack_is_a_failure_not_a_crash() {
    let v = vectors();
    let r = verify_pack(&json!({"format": "nope"}), &keys(&v)).unwrap();
    assert_eq!(r.first_failed(), Some("schema"));
}

// --- Tool-call checks (`checks`; §2.8, §3.5, §7, §10, §11), checked against the library ---------

use signafaide_core::checks::{self, envelope, fingerprints, report, rules, ruling};

fn domain(name: &str) -> Domain {
    match name {
        "ruling" => Domain::Ruling,
        "rules" => Domain::Rules,
        "fingerprints" => Domain::Fingerprints,
        "batch" => Domain::Batch,
        "head" => Domain::Head,
        other => panic!("unknown domain {other}"),
    }
}

fn service_keys(v: &Value) -> Vec<KeyEntry> {
    from_value::<KeysDocument>(&v["keys_document"]).unwrap().keys
}

#[test]
fn checks_signatures_and_domains() {
    let v = vectors();
    let service = v["keys"][1]["public_key"].as_str().unwrap();
    let c = &v["checks"];
    let names: Vec<&str> = c["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["domain"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ruling", "rules", "fingerprints"]);
    for s in c["signatures"].as_array().unwrap() {
        let d = domain(s["domain"].as_str().unwrap());
        assert_eq!(
            hex::encode(sign::message(d, &h(&s["hash"]))),
            s["message_hex"].as_str().unwrap()
        );
        sign::verify(service, d, &h(&s["hash"]), s["sig"].as_str().unwrap()).unwrap();
    }
    for s in c["cross_domain"].as_array().unwrap() {
        let d = domain(s["verify_domain"].as_str().unwrap());
        assert!(sign::verify(service, d, &h(&s["hash"]), s["sig"].as_str().unwrap()).is_err());
    }
}

#[test]
fn checks_conditions_and_evaluation() {
    let c = &vectors()["checks"];
    let input = &c["conditions"]["input"];
    for t in c["conditions"]["cases"].as_array().unwrap() {
        let cond = rules::parse_condition(&t["condition"]).unwrap();
        let got = match rules::condition(&cond, rules::resolve(input, &cond.field)) {
            rules::Holds::Yes => json!(true),
            rules::Holds::No => json!(false),
            rules::Holds::Error => json!("error"),
        };
        assert_eq!(got, t["expect"], "{}", t["name"]);
    }
    let now = time::parse(c["evaluation"]["now"].as_str().unwrap()).unwrap();
    for t in c["evaluation"]["cases"].as_array().unwrap() {
        let rs = rules::RuleSet::parse(&c["evaluation"]["rule_sets"][t["rule_set"].as_str().unwrap()]).unwrap();
        let (agent, tool) = (t["agent"].as_str().unwrap(), t["tool"].as_str().unwrap());
        let field = |p: &str| rules::resolve(&t["input"], p).cloned();
        let hist = t["history"].as_array().unwrap();
        let mut count = |l: &rules::Limit| -> Result<i64, ()> {
            Ok(hist
                .iter()
                .filter(|x| {
                    let same = match l.per {
                        rules::Per::Agent => x["agent"] == agent,
                        rules::Per::Tool => x["tool"] == tool,
                        rules::Per::AgentTool => x["agent"] == agent && x["tool"] == tool,
                    };
                    let at = time::parse(x["server_time"].as_str().unwrap()).unwrap();
                    same && now - l.seconds * 1000 < at && at <= now
                })
                .count() as i64)
        };
        let e = if t["where"] == "witness" {
            rules::evaluate(&rs, agent, tool, &field, None, Some(&mut count))
        } else {
            rules::evaluate(&rs, agent, tool, &field, None, None)
        }
        .unwrap();
        assert_eq!(
            json!({"result": e.result.as_str(), "basis": e.basis.as_str(), "matched": e.matched}),
            t["expect"],
            "{}",
            t["name"]
        );
    }
    for m in c["modes"].as_array().unwrap() {
        let mode = rules::Mode::parse(m["mode"].as_str().unwrap()).unwrap();
        assert_eq!(
            Value::Object(rules::apply_mode(m["check_result"].as_str().unwrap(), mode)),
            m["expect"]
        );
    }
    for t in c["client_rule_entries"]["cases"].as_array().unwrap() {
        let rs =
            rules::RuleSet::parse(&c["client_rule_entries"]["rule_sets"][t["rule_set"].as_str().unwrap()]).unwrap();
        let local = t["set"] == "local";
        let mode = rules::entry_mode(rs.mode, t["strict"].as_bool().unwrap(), local);
        let set = if local { "local".to_string() } else { rs.set.clone() };
        let e = rules::client_entry(
            &rs,
            mode,
            &set,
            t["agent"].as_str().unwrap(),
            t["tool"].as_str().unwrap(),
            &t["input"],
        );
        assert_eq!(e, t["expect"]["entry"], "{}", t["name"]);
        assert_eq!(
            e["result"] != "block",
            t["expect"]["runs"].as_bool().unwrap(),
            "{}",
            t["name"]
        );
    }
}

#[test]
fn checks_rule_set_documents_and_updates() {
    let v = vectors();
    let c = &v["checks"];
    let keys = service_keys(&v);
    for k in ["v1", "v2"] {
        let e = &c["rule_sets"][k];
        rules::RuleSet::parse(&e["rules"]).unwrap();
        assert_eq!(
            jcs::canonicalize(&e["rules"]).unwrap(),
            e["rules_jcs"].as_str().unwrap()
        );
        assert_eq!(sha256(e["rules_jcs"].as_str().unwrap().as_bytes()), h(&e["rules_hash"]));
        sign::verify(
            &keys[0].public_key,
            Domain::Rules,
            &h(&e["rules_hash"]),
            e["sig"].as_str().unwrap(),
        )
        .unwrap();
    }
    for t in c["rule_sets_invalid"].as_array().unwrap() {
        assert!(rules::RuleSet::parse(&t["rules"]).is_err(), "{}", t["name"]);
    }
    let u = &c["rule_set_updates"];
    for t in u["cases"].as_array().unwrap() {
        let held = (!t["held"].is_null()).then_some(&t["held"]);
        let got = rules::accept(
            held,
            &t["offered"],
            &keys,
            u["project"].as_str().unwrap(),
            u["env"].as_str().unwrap(),
        );
        assert_eq!(json!(got), t["expect"], "{}", t["name"]);
    }
    let v2 = rules::RuleSet::parse(&c["rule_sets"]["v2"]["rules"]).unwrap();
    let v1 = rules::RuleSet::parse(&c["rule_sets"]["v1"]["rules"]).unwrap();
    for t in c["disclosure"].as_array().unwrap() {
        let rs = if t["rules_version"] == 1 { &v1 } else { &v2 };
        let need = rs.needed(t["agent"].as_str().unwrap(), t["tool"].as_str().unwrap());
        let opt: Vec<&str> = t["disclose"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        let disclosed: Vec<&String> = need.iter().filter(|p| opt.contains(&p.as_str())).collect();
        let missing: Vec<&String> = need.iter().filter(|p| !opt.contains(&p.as_str())).collect();
        assert_eq!(
            json!({"disclosed": disclosed, "missing": missing}),
            t["expect"],
            "{}",
            t["name"]
        );
    }
    let d = &c["disclosed"];
    assert_eq!(
        jcs::canonicalize(&d["values"]).unwrap(),
        d["values_jcs"].as_str().unwrap()
    );
    assert_eq!(
        checks::disclosed_hash(&d["values"], d["salt"].as_str().unwrap()).unwrap(),
        h(&d["disclosed_hash"])
    );
    let a = &d["absent_field"];
    assert_eq!(
        checks::disclosed_hash(&a["values"], a["salt"].as_str().unwrap()).unwrap(),
        h(&a["disclosed_hash"])
    );
}

#[test]
fn checks_tool_fingerprints_and_shared_list() {
    let v = vectors();
    let c = &v["checks"];
    for t in c["tool_fingerprints"].as_array().unwrap() {
        let tool = &t["tool"];
        let si = (!t["server_info"].is_null()).then_some(&t["server_info"]);
        let got = checks::tool_fingerprints(
            tool["name"].as_str().unwrap(),
            tool["description"].as_str().unwrap(),
            &tool["input_schema"],
            si,
        )
        .unwrap();
        assert_eq!(got, t["expect"], "{}", t["name"]);
        if let Some(s) = t["stripped_schema_jcs"].as_str() {
            assert_eq!(
                jcs::canonicalize(&checks::strip_schema(&tool["input_schema"])).unwrap(),
                s
            );
        }
    }
    let keys = service_keys(&v);
    let l = &c["fingerprint_list"];
    for t in l["cases"].as_array().unwrap() {
        let mut held = fingerprints::Held::default();
        let mut err = None;
        for it in t["apply"].as_array().unwrap() {
            match fingerprints::accept(&held, it, &keys) {
                Ok(next) => held = next,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        assert_eq!(
            json!({"error": err, "seq": held.seq, "state_hash": held.state_hash()}),
            t["expect"],
            "{}",
            t["name"]
        );
    }
    for u in l["updates"].as_array().unwrap() {
        assert_eq!(hash_json(&u["list"]).unwrap(), h(&u["list_hash"]));
    }
}

#[test]
fn checks_rulings_and_ruled_record() {
    let v = vectors();
    let c = &v["checks"];
    let r = &c["rulings"];
    let held_list = fingerprints::Held {
        seq: 4,
        last: None,
        entries: r["fingerprint_entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| fingerprints::Entry::parse(e).unwrap())
            .collect(),
    };
    let now = time::parse(r["now"].as_str().unwrap()).unwrap();
    for t in r["cases"].as_array().unwrap() {
        let doc = t["rule_set"].as_str().map(|k| &r["rule_sets"][k]);
        let rs = doc.map(|d| rules::RuleSet::parse(d).unwrap());
        let hash = doc.map(|d| hash_json(d).unwrap().hex());
        let held = rs.as_ref().map(|rs| ruling::Held {
            rule_set: rs,
            rules_hash: hash.as_deref().unwrap(),
        });
        let hist = t["history"].as_array().unwrap();
        let mut count = |l: &rules::Limit| -> Result<i64, ()> {
            Ok(hist
                .iter()
                .filter(|x| {
                    let at = time::parse(x["server_time"].as_str().unwrap()).unwrap();
                    x["agent"] == "agent-a" && x["tool"] == "approve_payout" && now - l.seconds * 1000 < at && at <= now
                })
                .count() as i64)
        };
        let d = ruling::decide(
            held.as_ref(),
            "agent-a",
            "approve_payout",
            &t["checks"],
            t["disclosed"].as_object().unwrap(),
            4,
            &|k, f| held_list.listed(k, f),
            &mut count,
        )
        .unwrap();
        let mut got = d.object("", "", "");
        for k in ["v", "record_hash", "batch_hash", "server_time", "reason"] {
            got.as_object_mut().unwrap().remove(k);
        }
        assert_eq!(got, t["expect"], "{}", t["name"]);
    }
    let rr = &c["ruled_record"];
    let service = v["keys"][1]["public_key"].as_str().unwrap();
    let e = Envelope::parse(&rr["record"]["envelope"]).unwrap();
    assert_eq!(
        jcs::canonicalize(&rr["record"]["envelope"]).unwrap(),
        rr["envelope_jcs"].as_str().unwrap()
    );
    assert_eq!(e.record_hash().unwrap(), h(&rr["record_hash"]));
    let rec: SignedRecord = from_value(&rr["record"]).unwrap();
    assert_eq!(rec.check_content().unwrap(), None);
    let receipt: Receipt = from_value(&rr["receipt"]).unwrap();
    let g = receipt.ruling.as_ref().unwrap();
    ruling::validate(g).unwrap();
    assert_eq!(jcs::canonicalize(g).unwrap(), rr["ruling_jcs"].as_str().unwrap());
    assert_eq!(hash_json(g).unwrap(), h(&rr["ruling_hash"]));
    sign::verify(
        service,
        Domain::Ruling,
        &h(&rr["ruling_hash"]),
        receipt.ruling_sig.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(g["record_hash"], rr["record_hash"]);
    assert_eq!(
        checks::disclosed_hash(
            &rr["record"]["disclosed"],
            rr["record"]["disclosed_salt"].as_str().unwrap()
        )
        .unwrap(),
        h(&rr["record"]["envelope"]["checks"]["disclosed_hash"])
    );
    for t in rr["tampered"].as_array().unwrap() {
        let ok = sign::verify(
            service,
            Domain::Ruling,
            &hash_json(&t["ruling"]).unwrap(),
            t["ruling_sig"].as_str().unwrap(),
        )
        .is_ok()
            && t["ruling"]["record_hash"] == rr["record_hash"];
        assert!(!ok, "{}", t["name"]);
    }
}

#[test]
fn checks_envelopes_and_verifier_lines() {
    let c = &vectors()["checks"];
    for t in c["envelopes_with_checks"]["valid"].as_array().unwrap() {
        let e = Envelope::parse(&t["envelope"]).unwrap_or_else(|err| panic!("{}: {err}", t["name"]));
        assert_eq!(e.record_hash().unwrap(), h(&t["record_hash"]), "{}", t["name"]);
    }
    for t in c["envelopes_with_checks"]["invalid"].as_array().unwrap() {
        assert!(Envelope::parse(&t["envelope"]).is_err(), "{}", t["name"]);
    }
    // A checks object of null is not an absent one (§2.2).
    let mut e = c["envelopes_with_checks"]["valid"][3]["envelope"].clone();
    e["checks"] = Value::Null;
    assert!(Envelope::parse(&e).is_err());
    assert!(envelope::asks_for_ruling(
        &c["ruled_record"]["record"]["envelope"]["checks"]
    ));
    let vl = &c["verifier_lines"];
    let recs = vl["records"].as_array().unwrap();
    let (mut lines, mut json_out) = (Vec::new(), serde_json::Map::new());
    for agent in ["agent-a", "agent-b", "agent-c"] {
        let items: Vec<report::Item> = recs
            .iter()
            .filter(|r| r["record"]["agent"] == agent)
            .map(|r| report::Item {
                seq: r["record"]["seq"].as_u64().unwrap(),
                kind: Kind::parse(r["record"]["kind"].as_str().unwrap()).unwrap(),
                checks: r["record"].get("checks"),
                decision_seq: r["record"]["ref_seq"].as_u64(),
                ruling: (!r["ruling"].is_null()).then_some(&r["ruling"]),
            })
            .collect();
        if let Some(j) = report::agent_checks(&items) {
            lines.extend(report::lines(agent, &j));
            json_out.insert(agent.into(), serde_json::to_value(&j).unwrap());
        }
    }
    assert_eq!(json!(lines), vl["expect"]["checks_lines"]);
    assert_eq!(Value::Object(json_out), vl["expect"]["checks"]);
}

#[test]
fn checks_secret_tokens_rebuild() {
    let c = &vectors()["checks"];
    for (id, t) in c["local_checks"]["tokens"].as_object().unwrap() {
        let whole: String = t["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(sha256(whole.as_bytes()), h(&t["sha256"]), "{id}");
        assert!(t["parts"].as_array().unwrap().len() >= 2, "{id} is written in parts");
    }
    // No whole token is in the file (secret scanners).
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors.json")).unwrap();
    for t in c["local_checks"]["tokens"].as_object().unwrap().values() {
        let whole: String = t["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        let escaped = serde_json::to_string(&whole).unwrap();
        assert!(
            !text.contains(&escaped[1..escaped.len() - 1]),
            "a whole token is in vectors.json"
        );
    }
}

#[test]
fn checks_fingerprint_exceptions() {
    let v = vectors();
    let c = &v["checks"];
    let fe = &c["fingerprint_exceptions"];
    let held = fingerprints::Held {
        seq: 4,
        last: None,
        entries: fe["fingerprint_entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| fingerprints::Entry::parse(e).unwrap())
            .collect(),
    };
    for t in fe["cases"].as_array().unwrap() {
        // The exceptions as a held rule set carries them: the vectors' excepted version with this case's list.
        let rs = (!t["exceptions"].is_null()).then(|| {
            let mut doc = c["rulings"]["rule_sets"]["excepted"].clone();
            doc["fingerprint_exceptions"] = t["exceptions"].clone();
            rules::RuleSet::parse(&doc).unwrap()
        });
        let found: Vec<&str> = ["description", "server", "tool"]
            .into_iter()
            .filter(|k| {
                t["tool"][*k]
                    .as_str()
                    .is_some_and(|f| held.listed(k, f) && !rs.as_ref().is_some_and(|rs| rs.excepts(k, f)))
            })
            .collect();
        let got = serde_json::json!({"result": if found.is_empty() { "allow" } else { "block" }, "found": found});
        assert_eq!(got, t["expect"], "{}", t["name"]);
    }
}

/// Spec 1.1: rule states, exceptions, the ruling's new fields, the client's rule entry and
/// disclosure, recomputed from the vectors alone.
#[test]
fn spec_1_1_rule_states() {
    let v = vectors();
    let c = &v["checks"]["rule_states"];
    let doc = |k: &Value| rules::RuleSet::parse(&c["rule_sets"][k.as_str().unwrap()]).unwrap();
    for t in c["states"].as_array().unwrap() {
        let rs = doc(&t["rule_set"]);
        let got: serde_json::Map<String, Value> = rs
            .rules
            .iter()
            .map(|r| (r.id.clone(), json!(r.state_in(rs.mode).as_str())))
            .collect();
        assert_eq!(Value::Object(got), t["expect"], "{}", t["name"]);
    }
    for t in c["evaluation"].as_array().unwrap() {
        let rs = doc(&t["rule_set"]);
        let tool = t["tool"].as_str().unwrap();
        let e = if t["where"] == "witness" {
            let list: Vec<&str> = t["available"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap())
                .collect();
            let field = |p: &str| t["input"].get(p).cloned();
            let avail = |p: &str| list.contains(&p);
            let mut count = |_: &rules::Limit| -> Result<i64, ()> { Ok(0) };
            rules::evaluate(&rs, "agent-a", tool, &field, Some(&avail), Some(&mut count)).unwrap()
        } else {
            let field = |p: &str| rules::resolve(&t["input"], p).cloned();
            rules::evaluate::<()>(&rs, "agent-a", tool, &field, None, None).unwrap()
        };
        let got = json!({"result": e.result.as_str(), "basis": e.basis.as_str(), "matched": e.matched, "would_block": e.would_block, "not_calibrated": e.not_calibrated, "excepted": e.excepted});
        assert_eq!(got, t["expect"], "{}", t["name"]);
    }
    let held_list = fingerprints::Held {
        seq: 4,
        last: None,
        entries: c["fingerprint_entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| fingerprints::Entry::parse(e).unwrap())
            .collect(),
    };
    for t in c["rulings"].as_array().unwrap() {
        let d = &c["rule_sets"][t["rule_set"].as_str().unwrap()];
        let rs = rules::RuleSet::parse(d).unwrap();
        let hash = hash_json(d).unwrap().hex();
        let held = ruling::Held {
            rule_set: &rs,
            rules_hash: &hash,
        };
        let mut count = |_: &rules::Limit| -> Result<i64, ()> { Ok(0) };
        let r = ruling::decide(
            Some(&held),
            "agent-a",
            "approve_payout",
            &t["checks"],
            t["disclosed"].as_object().unwrap(),
            4,
            &|k, f| held_list.listed(k, f),
            &mut count,
        )
        .unwrap();
        let mut got = r.object("11", "22", "t");
        assert_eq!(got["reason"], t["reason"], "{}", t["name"]);
        for k in ["v", "record_hash", "batch_hash", "server_time", "reason"] {
            got.as_object_mut().unwrap().remove(k);
        }
        assert_eq!(got, t["expect"], "{}", t["name"]);
    }
    for t in c["ruling_shapes"]["valid"].as_array().unwrap() {
        ruling::validate(&t["ruling"]).unwrap_or_else(|e| panic!("{}: {e}", t["name"]));
    }
    for t in c["ruling_shapes"]["invalid"].as_array().unwrap() {
        assert!(ruling::validate(&t["ruling"]).is_err(), "{}", t["name"]);
    }
    for t in c["client_rule_entries"].as_array().unwrap() {
        let rs = doc(&t["rule_set"]);
        let mode = rules::entry_mode(rs.mode, t["strict"].as_bool().unwrap(), false);
        let e = rules::client_entry(&rs, mode, &rs.set, "agent-a", "approve_payout", &t["input"]);
        assert_eq!(e, t["expect"], "{}", t["name"]);
    }
    for t in c["disclosure"].as_array().unwrap() {
        let rs = doc(&t["rule_set"]);
        let approved: Vec<String> = t["disclose"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let (sent, missing, unsent) = checks::file::disclosure(&rs, "agent-a", "approve_payout", &approved);
        assert_eq!(
            json!({"sent": sent, "missing": missing, "unsent": unsent}),
            t["expect"],
            "{}",
            t["name"]
        );
    }
}

/// Spec 1.1: rules in words and the checks file.
#[test]
fn spec_1_1_words_and_checks_files() {
    let v = vectors();
    let w = &v["checks"]["rule_words"];
    for t in w["conditions"].as_array().unwrap() {
        assert_eq!(
            checks::words::condition(&rules::parse_condition(&t["condition"]).unwrap()),
            t["expect"].as_str().unwrap()
        );
    }
    for t in w["rules"].as_array().unwrap() {
        let doc = json!({"format": "signafaide-rules/1", "project": v["checks"]["rule_states"]["rule_sets"]["v3"]["project"], "env": "live",
            "set": "rs_01JD2K8Z5X3V7N2M4K6H8G0F1A", "version": 1, "prev": null, "issued": "2026-11-17T09:00:00.000Z", "mode": "enforce", "default": "allow",
            "fail": {}, "addresses": {"hosts": [], "cidrs": []}, "approved": null, "rules": [t["rule"].clone()]});
        let rs = rules::RuleSet::parse(&doc).unwrap_or_else(|e| panic!("{}: {e}", t["name"]));
        assert_eq!(
            checks::words::rule(&rs.rules[0]),
            t["expect"].as_str().unwrap(),
            "{}",
            t["name"]
        );
    }
    for t in w["rule_sets"].as_array().unwrap() {
        let (rs, hash, local) = match t.get("local_rules") {
            Some(l) => (
                rules::RuleSet::parse_local(&l["rules"]).unwrap(),
                l["hash"].as_str().unwrap(),
                true,
            ),
            None => (
                rules::RuleSet::parse(&t["rule_set"]["rules"]).unwrap(),
                t["rule_set"]["hash"].as_str().unwrap(),
                false,
            ),
        };
        let words = checks::words::rule_set(&rs, hash, local);
        assert_eq!(
            serde_json::to_value(&words).unwrap(),
            t["expect"]["words"],
            "{}",
            t["name"]
        );
        assert_eq!(
            json!(checks::words::lines(&words)),
            t["expect"]["lines"],
            "{}",
            t["name"]
        );
    }
    let f = &v["checks"]["checks_files"];
    for t in f["valid"].as_array().unwrap() {
        let file = checks::file::ChecksFile::parse(&t["file"]).unwrap_or_else(|e| panic!("{}: {e}", t["name"]));
        for (name, want) in t["expect"]["tools"].as_object().unwrap() {
            let s = file.tool(name);
            assert_eq!(
                json!({"strict": s.strict, "fail": s.fail, "mode": s.mode.as_str(), "disclose": s.disclose}),
                *want,
                "{} {name}",
                t["name"]
            );
        }
        assert_eq!(
            json!(file.local_rules_hash()),
            t["expect"]["local_rules_hash"],
            "{}",
            t["name"]
        );
    }
    for t in f["invalid"].as_array().unwrap() {
        assert!(checks::file::ChecksFile::parse(&t["file"]).is_err(), "{}", t["name"]);
    }
}

/// Spec 1.1 (§5): the default witness's public key set, published in the repository so a
/// verifier (a browser one above all) can pin it without asking the service.
#[test]
fn published_service_keys() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/service-keys.json");
    let text = std::fs::read_to_string(path).expect("spec/service-keys.json");
    let doc: KeysDocument = serde_json::from_str(&text).expect("spec/service-keys.json is a §5 key set");
    assert!(!doc.keys.is_empty());
    for k in &doc.keys {
        k.validate().unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&k.public_key)
            .unwrap();
        assert_eq!(
            k.key_id,
            sha256(&raw).hex()[..16],
            "key_id is the first 16 hex of sha256(public key)"
        );
    }
}
