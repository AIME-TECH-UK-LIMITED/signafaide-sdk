//! Checks `spec/vectors.json` against the library, independently of the generator, and runs
//! the verifier over the valid pack and every tampered pack.

use signafaide_core::merkle::{self, Tree};
use signafaide_core::ots::DetachedFile;
use signafaide_core::sign::{self, Domain};
use signafaide_core::verify::{contents_from_text, verify_pack, Options, Status};
use signafaide_core::*;
use base64::Engine;
use serde_json::{json, Value};

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
    assert!(vectors() == vectors::generate(), "spec/vectors.json is stale: run `cargo run --bin gen-vectors`");
}

#[test]
fn jcs_vectors() {
    for c in vectors()["jcs"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        match c.get("output") {
            Some(out) => assert_eq!(jcs::canonicalize_str(input).unwrap(), out.as_str().unwrap(), "{}", c["name"]),
            None => assert!(jcs::canonicalize_str(input).is_err(), "{}", c["name"]),
        }
    }
}

#[test]
fn record_vectors() {
    let v = vectors();
    let agent = &v["keys"][0];
    for r in v["records"].as_array().unwrap() {
        assert_eq!(jcs::canonicalize(&r["content"]).unwrap(), r["content_jcs"].as_str().unwrap());
        let mut salted = hex::decode(r["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salted.len(), 16);
        salted.extend_from_slice(r["content_jcs"].as_str().unwrap().as_bytes());
        assert_eq!(sha256(&salted), h(&r["content_hash"]));
        assert_eq!(content_hash(&r["content"], r["salt"].as_str().unwrap()).unwrap(), h(&r["content_hash"]));
        // Unsalted, or with another salt, the content no longer gives the hash (§2.1).
        assert_ne!(sha256(r["content_jcs"].as_str().unwrap().as_bytes()), h(&r["content_hash"]));
        let e = Envelope::parse(&r["envelope"]).unwrap();
        assert_eq!(jcs::canonicalize(&r["envelope"]).unwrap(), r["envelope_jcs"].as_str().unwrap());
        assert_eq!(e.record_hash().unwrap(), h(&r["record_hash"]));
        sign::verify(agent["public_key"].as_str().unwrap(), Domain::Record, &h(&r["record_hash"]), r["sig"].as_str().unwrap()).unwrap();
    }
    for bad in v["invalid_envelopes"].as_array().unwrap() {
        assert!(Envelope::parse(&bad["envelope"]).is_err(), "{}", bad["name"]);
    }
}

#[test]
fn key_and_signature_vectors() {
    let v = vectors();
    for k in v["keys"].as_array().unwrap() {
        let seed: [u8; 32] = hex::decode(k["seed_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
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
        assert_eq!(hex::encode(sign::message(d, &h(&s["hash"]))), s["message_hex"].as_str().unwrap());
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
            assert!(merkle::verify_path(&items[i], i as u64, items.len() as u64, &path, &tree.root()));
        }
    }
    let b = &v["batch"];
    assert_eq!(sha256(b["batch_jcs"].as_str().unwrap().as_bytes()), h(&b["batch_hash"]));
    let batch: Batch = from_value(&b["batch"]).unwrap();
    assert_eq!(batch.hash().unwrap(), h(&b["batch_hash"]));
    sign::verify(v["keys"][1]["public_key"].as_str().unwrap(), Domain::Batch, &h(&b["batch_hash"]), b["batch_sig"].as_str().unwrap()).unwrap();
    let hd: Head = from_value(&v["head"]["head"]).unwrap();
    assert_eq!(hd.hash().unwrap(), h(&v["head"]["head_hash"]));
    let a: Anchor = from_value(&v["anchor"]["anchor"]).unwrap();
    assert_eq!(sha256(v["anchor"]["signed_part_jcs"].as_str().unwrap().as_bytes()), a.hash().unwrap());
}

#[test]
fn ots_and_drand_vectors() {
    let v = vectors();
    for o in v["ots"].as_array().unwrap() {
        let bytes = base64::engine::general_purpose::STANDARD.decode(o["base64"].as_str().unwrap()).unwrap();
        if o.get("error").is_some() {
            assert!(DetachedFile::parse(&bytes).is_err(), "{}", o["name"]);
            continue;
        }
        let f = DetachedFile::parse(&bytes).unwrap();
        for b in o.get("bitcoin").and_then(Value::as_array).into_iter().flatten() {
            let att = f.timestamp.bitcoin_attestations().unwrap();
            let mut want: [u8; 32] = hex::decode(b["merkle_root"].as_str().unwrap()).unwrap().try_into().unwrap();
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
        assert_eq!(drand::verify_beacon(&beacon) == drand::BeaconCheck::Valid, d["valid"].as_bool().unwrap());
    }
    for d in v["drand_time"].as_array().unwrap() {
        let t = time::parse(d["server_time"].as_str().unwrap()).unwrap();
        assert_eq!(drand::check_round_time(t, d["round"].as_u64().unwrap()).is_ok(), d["valid"].as_bool().unwrap(), "{d}");
    }
}

#[test]
fn registration_agent_keys_and_keys_hash_vectors() {
    let v = vectors();
    let r = &v["registration"];
    let reg: Registration = from_value(&r["registration"]).unwrap();
    assert_eq!(jcs::canonicalize(&r["registration"]).unwrap(), r["registration_jcs"].as_str().unwrap());
    assert_eq!(reg.hash().unwrap(), h(&r["registration_hash"]));
    sign::verify(&reg.public_key, Domain::Register, &reg.hash().unwrap(), r["proof"].as_str().unwrap()).unwrap();
    assert!(sign::verify(&reg.public_key, Domain::Record, &reg.hash().unwrap(), r["proof"].as_str().unwrap()).is_err());
    sign::verify(v["keys"][2]["public_key"].as_str().unwrap(), Domain::Rotate, &reg.hash().unwrap(), r["rotation"]["sig"].as_str().unwrap()).unwrap();

    let keys = signafaide_core::verify::agent_keys_from_text(&v["agent_keys_document"].to_string()).unwrap();
    assert_eq!(keys[0].key_id, v["keys"][0]["key_id"].as_str().unwrap());
    let mut forged = v["agent_keys_document"].clone();
    forged["keys"][0]["valid_from"] = json!("2020-01-01T00:00:00.000Z");
    assert!(signafaide_core::verify::agent_keys_from_text(&forged.to_string()).is_err(), "valid_from is covered by the self-signature");

    let mut retired = v["agent_keys_document"].clone();
    retired["keys"][0]["valid_to"] = json!("2026-11-13T10:04:00.000Z");
    assert!(signafaide_core::verify::agent_keys_from_text(&retired.to_string()).is_err(), "valid_to is covered by the self-signature");

    let e = &v["export"];
    let pack: Pack = from_value(&v["pack"]["pack"]).unwrap();
    let st = pack.statement().unwrap();
    assert_eq!(jcs::canonicalize(&serde_json::to_value(&st).unwrap()).unwrap(), e["statement_jcs"].as_str().unwrap());
    assert_eq!(st.records_hash, h(&e["records_hash"]));
    assert_eq!(st.hash().unwrap(), h(&e["statement_hash"]));
    sign::verify(v["keys"][1]["public_key"].as_str().unwrap(), Domain::Export, &h(&e["statement_hash"]), e["export_sig"].as_str().unwrap()).unwrap();

    let k = &v["keys_hash"];
    let list: Vec<KeyEntry> = from_value(&k["keys"]).unwrap();
    assert_eq!(sha256(k["committed_jcs"].as_str().unwrap().as_bytes()), h(&k["keys_hash"]));
    assert_eq!(service_keys_hash(&list, time::parse(k["created"].as_str().unwrap()).unwrap()).unwrap(), h(&k["keys_hash"]));
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
            let got = c.value.clone().unwrap_or_else(|| serde_json::to_value(c.status).unwrap().as_str().unwrap().to_string());
            assert_eq!(&json!(got), want, "{} check {id}", t["name"]);
        }
        if let Some(n) = t["expect"]["chain_note"].as_str() {
            assert!(r.check("chain").detail.contains(n), "{}\n{}", t["name"], r.to_text());
        }
    }
    // The instance-start note (§8) names the chain and the seq it continues after.
    let notes: Vec<&str> = variants.iter().filter_map(|t| t["expect"]["chain_note"].as_str()).collect();
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

#[test]
fn valid_pack_passes() {
    let v = vectors();
    let report = verify_pack(&v["pack"]["pack"], &keys(&v)).unwrap();
    assert!(report.passed(), "{}", report.to_text());
    for (id, want) in v["pack"]["expect"]["checks"].as_object().unwrap() {
        let c = report.check(id);
        let got = c.value.clone().unwrap_or_else(|| serde_json::to_value(c.status).unwrap().as_str().unwrap().to_string());
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
        let (t, raised) = signafaide_core::time::clamp(c["wall"].as_str().unwrap(), c["prev"].as_str(), c["valid_from"].as_str()).unwrap();
        assert_eq!((t.as_str(), raised), (c["time"].as_str().unwrap(), c["raised"].as_bool().unwrap()), "{}", c["name"]);
    }
}

#[test]
fn every_tampered_pack_fails_at_its_check() {
    let v = vectors();
    let tampered = v["tampered"].as_array().unwrap();
    assert_eq!(tampered.len(), 49, "one tampered pack per rule");
    for id in v["check_ids"].as_array().unwrap() {
        assert!(tampered.iter().any(|t| t["check"] == *id), "no tampered pack for {id}");
    }
    for t in tampered {
        let report = verify_pack(&t["pack"], &vectors::Inputs::options(t, &v)).unwrap();
        assert!(!report.passed(), "{} should fail", t["check"]);
        assert_eq!(report.first_failed(), t["first_failed"].as_str(), "{}\n{}", t["tamper"], report.to_text());
    }
}

#[test]
fn an_empty_pack_fails_with_no_records() {
    let v = vectors();
    let empty = v["tampered"].as_array().unwrap().iter().find(|t| t["pack"]["records"] == json!([])).expect("empty-pack vector");
    let report = verify_pack(&empty["pack"], &keys(&v)).unwrap();
    assert_eq!(report.result, "FAIL");
    let schema = report.check("schema");
    assert_eq!((schema.failures[0].item.as_str(), schema.failures[0].message.as_str()), ("pack", verify::NO_RECORDS));
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
    assert_eq!(r.result_line(), format!("PASS (service keys taken from the pack, not independent){scope}"));
    // Without independent agent keys check 3 fails, unless they are trusted explicitly.
    let r = verify_pack(pack, &Options { trust_embedded_keys: true, ..Default::default() }).unwrap();
    assert_eq!(r.first_failed(), Some("record_sig"));
    assert!(r.check("record_sig").failures[0].message.starts_with("NOT INDEPENDENT"));
    let r = verify_pack(pack, &Options { trust_embedded_keys: true, trust_embedded_agent_keys: true, ..Default::default() }).unwrap();
    assert_eq!(r.result_line(), format!("PASS (service keys and agent keys taken from the pack, not independent){scope}"));
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
    assert_eq!((r.check("content").status, r.check("content").checked), (Status::Pass, 4));

    let mut bad = v["records"][3].clone();
    bad["content"]["output"]["refund"] = json!(true);
    opts.contents = contents_from_text(&json!({"envelope": bad["envelope"], "content": bad["content"], "salt": bad["salt"]}).to_string()).unwrap();
    assert_eq!(verify_pack(&pack, &opts).unwrap().first_failed(), Some("content"));
    // Without its salt the content cannot be checked against the hash: a failure, never a pass.
    let good = &v["records"][3];
    opts.contents = contents_from_text(&json!({"envelope": good["envelope"], "content": good["content"]}).to_string()).unwrap();
    assert_eq!(verify_pack(&pack, &opts).unwrap().first_failed(), Some("content"));
}

#[test]
fn malformed_pack_is_a_failure_not_a_crash() {
    let v = vectors();
    let r = verify_pack(&json!({"format": "nope"}), &keys(&v)).unwrap();
    assert_eq!(r.first_failed(), Some("schema"));
}
