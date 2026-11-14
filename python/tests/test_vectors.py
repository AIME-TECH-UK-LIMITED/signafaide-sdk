"""Every entry of spec/vectors.json, byte for byte.

The drand BLS checks use ``py_ecc`` (a dependency; also a dev
dependency here); without it they are skipped and check 9 says "not checked".
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest

import signafaide
from signafaide import jcs, ots
from signafaide.crypto import SigningKey, audit_path, b64url, content_hash, hash_json, leaf_hash, sha256_hex, merkle_root, signed_message, verify_inclusion, verify_sig
from signafaide.records import AGENT_RE, envelope_errors, parse_time, valid_project_id
from signafaide.drand import load_verifier as load_drand_verifier
from signafaide.bitcoin import check_header, roots_from_vector
from signafaide.records import manifest_entry
from signafaide.verifier import (
    ANCHOR_WINDOW_MS, DRAND_NOT_CHECKED, MAX_CLOCK_SKEW_MS, MAX_ROUND, NO_RECORDS, check_round_time, export_statement, load_agent_keys, load_heads,
    load_service_keys, records_hash, service_keys_hash, verify_pack,
)

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "vectors.json"
pytestmark = pytest.mark.skipif(not VECTORS.exists(), reason="spec/vectors.json not written yet")


@pytest.fixture(scope="module")
def v():
    return json.loads(VECTORS.read_text())


@pytest.fixture(scope="module")
def keys(v):
    return {k["name"]: SigningKey(bytes.fromhex(k["seed_hex"])) for k in v["keys"]}


def test_jcs(v):
    for case in v["jcs"]:
        value = json.loads(case["input"])  # Python's json keeps integer literals exact
        if "error" in case:
            with pytest.raises(ValueError):
                jcs.canonicalize(value)
        else:
            assert jcs.dumps(value) == case["output"], case["name"]


def test_sha256(v):
    for case in v["sha256"]:
        assert hashlib.sha256(case["utf8"].encode()).hexdigest() == case["hex"]


def test_keys(v, keys):
    for k in v["keys"]:
        sk = keys[k["name"]]
        assert b64url(sk.public_key) == k["public_key"] and sk.key_id == k["key_id"]


def test_signatures(v, keys):
    for case in v["signatures"]:
        assert signed_message(case["domain"], case["hash"]).hex() == case["message_hex"]
        assert keys[case["key"]].sign(case["domain"], case["hash"]) == case["sig"]
        assert verify_sig(b64url(keys[case["key"]].public_key), case["domain"], case["hash"], case["sig"])
    for case in v["cross_domain"]:
        ok = verify_sig(b64url(keys[case["key"]].public_key), case["verify_domain"], case["hash"], case["sig"])
        assert ok is case["valid"]


def test_merkle(v):
    for tree in v["merkle"]["trees"]:
        items = tree["items"]
        assert [leaf_hash(h).hex() for h in items] == tree["leaf_hashes"]
        assert merkle_root(items) == tree["root"]
        for i, path in enumerate(tree["paths"]):
            assert audit_path(items, i) == path
            assert verify_inclusion(items[i], i, len(items), path, tree["root"])


def test_records(v, keys):
    for r in v["records"]:
        assert jcs.dumps(r["content"]) == r["content_jcs"]
        assert content_hash(r["content"], r["salt"]) == r["content_hash"] == r["envelope"]["content_hash"]
        assert sha256_hex(bytes.fromhex(r["salt"]) + r["content_jcs"].encode()) == r["content_hash"]
        assert jcs.dumps(r["envelope"]) == r["envelope_jcs"]
        assert hash_json(r["envelope"]) == r["record_hash"]
        assert envelope_errors(r["envelope"]) == []
        assert keys["agent"].sign("record", r["record_hash"]) == r["sig"]
        assert r["key_id"] == keys["agent"].key_id


def test_batch_head_anchor_receipts(v, keys):
    svc = b64url(keys["service"].public_key)
    b = v["batch"]
    assert jcs.dumps(b["batch"]) == b["batch_jcs"] and hash_json(b["batch"]) == b["batch_hash"]
    assert verify_sig(svc, "batch", b["batch_hash"], b["batch_sig"])
    assert merkle_root(b["record_hashes"]) == b["root"] == b["batch"]["root"]
    for i, p in enumerate(b["proofs"]):
        assert verify_inclusion(b["record_hashes"][p["index"]], p["index"], len(b["record_hashes"]), p["proof"], b["root"]), i
    h = v["head"]
    assert jcs.dumps(h["head"]) == h["head_jcs"] and hash_json(h["head"]) == h["head_hash"]
    assert verify_sig(svc, "head", h["head_hash"], h["head_sig"])
    a = v["anchor"]
    core = {k: x for k, x in a["anchor"].items() if k not in ("ots", "status", "bitcoin_block")}
    assert jcs.dumps(core) == a["signed_part_jcs"] and hash_json(core) == a["anchor_hash"]
    assert verify_sig(svc, "anchor", a["anchor_hash"], a["anchor_sig"])
    for bh, p in a["paths"].items():
        assert verify_inclusion(bh, p["index"], a["anchor"]["size"], p["path"], a["anchor"]["root"])
    for rc in v["receipts"]:
        assert verify_inclusion(rc["record_hash"], rc["index"], rc["batch"]["size"], rc["proof"], rc["batch"]["root"])


def test_schema_ids_and_time(v):
    for case in v["invalid_envelopes"]:
        assert envelope_errors(case["envelope"]), case["name"]
    assert all(AGENT_RE.match(n) for n in v["agent_names"]["valid"])
    assert not any(AGENT_RE.match(n) for n in v["agent_names"]["invalid"])
    assert all(valid_project_id(p) for p in v["project_ids"]["valid"])
    assert not any(valid_project_id(p) for p in v["project_ids"]["invalid"])
    for case in v["time"]:
        if "error" in case:
            with pytest.raises(ValueError):
                parse_time(case["input"])
        else:
            assert int(parse_time(case["input"]).timestamp() * 1000) == case["unix_ms"]


def test_ots(v):
    for case in v["ots"]:
        data = base64.b64decode(case["base64"])
        if "error" in case:
            with pytest.raises(ots.OtsError):
                ots.parse(data)
            continue
        digest, height = ots.status(data)
        assert digest.hex() == case["digest"]
        assert (f"confirmed@{height}" if height is not None else "pending") == case["status"]
        for b in case.get("bitcoin", []):
            assert ots.bitcoin_attestations(data) == [(b["height"], bytes.fromhex(b["merkle_root"])[::-1])]
    assert (ots.MAX_PROOF_BYTES, ots.MAX_NODES) == (v["ots_limits"]["max_proof_bytes"], v["ots_limits"]["max_nodes"])


def test_registration_manifest_keys_hash_and_drand_time(v, keys):
    r = v["registration"]
    assert jcs.dumps(r["registration"]) == r["registration_jcs"] and hash_json(r["registration"]) == r["registration_hash"]
    assert keys["agent"].sign("register", r["registration_hash"]) == r["proof"]
    assert keys["other"].sign("rotate", r["registration_hash"]) == r["rotation"]["sig"]
    assert load_agent_keys(v["agent_keys_document"])[0]["key_id"] == keys["agent"].key_id
    assert manifest_entry("agent-a", keys["agent"], v["agent_keys_document"]["keys"][0]["valid_from"]) == v["agent_keys_document"]["keys"][0]
    forged = json.loads(json.dumps(v["agent_keys_document"]))
    forged["keys"][0]["valid_from"] = "2020-01-01T00:00:00.000Z"
    with pytest.raises(ValueError):
        load_agent_keys(forged)
    k = v["keys_hash"]
    created = int(parse_time(k["created"]).timestamp() * 1000)
    assert hashlib.sha256(k["committed_jcs"].encode()).hexdigest() == k["keys_hash"] == service_keys_hash(k["keys"], created)
    for case in v["drand_time"]:
        ms = int(parse_time(case["server_time"]).timestamp() * 1000)
        assert (check_round_time(ms, case["round"]) is None) is case["valid"], case
    assert (MAX_ROUND, ANCHOR_WINDOW_MS, MAX_CLOCK_SKEW_MS) == (v["drand_max_round"], v["anchor_window_ms"], v["max_clock_skew_ms"])
    retired = json.loads(json.dumps(v["agent_keys_document"]))
    retired["keys"][0]["valid_to"] = "2026-11-13T10:04:00.000Z"
    with pytest.raises(ValueError):
        load_agent_keys(retired)  # valid_to is covered by the self-signature


def test_export_statement(v, keys):
    e, pack = v["export"], v["pack"]["pack"]
    st = export_statement(pack)
    assert st == e["statement"] and jcs.dumps(st) == e["statement_jcs"]
    assert records_hash(pack["records"]) == e["records_hash"] and hash_json(st) == e["statement_hash"]
    assert keys["service"].sign("export", e["statement_hash"]) == e["export_sig"] == pack["export_sig"]


def test_block_headers(v):
    for case in v["block_headers"]:
        if case["valid"]:
            assert check_header(case["hash"], case["header"])[::-1].hex() == case["merkle_root"], case["name"]
        else:
            with pytest.raises(ValueError):
                check_header(case["hash"], case["header"])


@pytest.fixture(scope="module")
def bls():
    v = load_drand_verifier()
    if v is None:
        pytest.skip("the signafaide[bls] extra (py_ecc) is not installed")
    return v


def options(case, v, **kw):
    """verify_pack keyword arguments for a vector entry (keys, agent_keys, head, bitcoin)."""
    o = {"agent_keys": None if case.get("agent_keys", 0) is None else load_agent_keys(case.get("agent_keys") or v["agent_keys_document"]),
         "trust_embedded_agent_keys": case.get("trust_embedded_agent_keys", False),
         "heads": load_heads(case["head"]) if "head" in case else None,
         "bitcoin": roots_from_vector(case["bitcoin"]) if "bitcoin" in case else None,
         "by_service": case.get("by_service", False), "service_keys_plain_http": case.get("service_keys_plain_http", False)}
    o.update(kw)
    return load_service_keys(case.get("keys") or v["keys_document"]), o


def test_drand_bls(v, bls):
    for case in v["drand"]:
        assert bls(case["beacon"]) is case["valid"]


def test_pack(v, bls):
    keys, o = options({}, v, drand=bls)
    r = verify_pack(v["pack"]["pack"], keys, **o)
    assert r.result == v["pack"]["expect"]["result"] and r.result_line == v["pack"]["expect"]["result_line"], str(r)
    assert {c.id: c.value or c.status for c in r.checks} == v["pack"]["expect"]["checks"], str(r)


def test_variants(v, bls):
    for case in v["variants"]:
        keys, o = options(case, v, drand=bls)
        r = verify_pack(case["pack"], keys, **o)
        assert r.result_line == case["expect"]["result_line"], (case["name"], str(r))
        assert {c.id: c.value or c.status for c in r.checks} == case["expect"]["checks"], (case["name"], str(r))
        if "chain_note" in case["expect"]:
            assert case["expect"]["chain_note"] in r.check("chain").detail, (case["name"], str(r))
    assert sum(1 for c in v["variants"] if "chain_note" in c["expect"]) == 1


def test_pack_without_bls_says_not_checked(v):
    keys, o = options({}, v)
    r = verify_pack(v["pack"]["pack"], keys, **o)
    assert r.ok and r.check("drand").status == "not_checked" and "BLS library not installed" in r.check("drand").detail


def test_tampered_packs(v, bls):
    assert len(v["tampered"]) == 49
    for case in v["tampered"]:
        keys, o = options(case, v, drand=bls)
        r = verify_pack(case["pack"], keys, **o)
        assert r.first_failed() == case["first_failed"], (case["tamper"], str(r))
        assert not r.ok


def test_empty_pack_fails_with_no_records(v):
    case = next(c for c in v["tampered"] if c["pack"]["records"] == [])
    keys, o = options(case, v)
    r = verify_pack(case["pack"], keys, **o)
    assert not r.ok and r.first_failed() == "schema"
    assert r.check("schema").failures == [{"item": "pack", "message": NO_RECORDS}]
    assert "pack: no records" in str(r)


def test_verify_says_plainly_when_drand_is_not_checked(v, recorder, monkeypatch, tmp_path):
    monkeypatch.setattr(signafaide, "load_drand_verifier", lambda: None)
    r = signafaide.verify(v["pack"]["pack"], keys=v["keys_document"], agent_keys=v["agent_keys_document"], offline=True)
    assert r.ok and r.check("drand").status == "not_checked"
    assert DRAND_NOT_CHECKED == "drand: not checked (BLS library not installed; pip install py_ecc)"
    assert DRAND_NOT_CHECKED in str(r).splitlines()
