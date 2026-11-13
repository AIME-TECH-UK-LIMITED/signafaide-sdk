import re
import base64
import copy
import json

import pytest

import signafaide
from signafaide import ots
from helpers import chain_path
from signafaide.crypto import SigningKey, audit_path, b64url, hash_json, merkle_root
from signafaide.records import now
from signafaide.verifier import KeysRequired, service_keys_hash, verify_local, verify_pack as _verify_pack

AGENTS: list = []


def no_counts(line: str) -> str:
    """The result line without its check counts (§7), to compare the rest."""
    return re.sub(r": \d+ of 12 checks [^;]*; ", ": ", re.sub(r": \d+ of 12 checks [^;]*$", "", line))


def verify_pack(pack, keys, **kw):
    """The pack verifier with this project's own agent keys as the independent set."""
    kw.setdefault("agent_keys", AGENTS)
    return _verify_pack(pack, keys, **kw)


@pytest.fixture
def pack(recorder, service):
    approve = signafaide.record(lambda claim_id, amount: amount < 100, name="approve_payout")
    approve("c1", 10)
    signafaide.flush()
    approve("c2", 500)
    signafaide.note("shift_end", {"n": 2})
    signafaide.flush()
    p = recorder.client().export("claims-project")
    assert len(p["records"]) == 5
    AGENTS[:] = recorder.state.export_agent_keys()["keys"]
    return p


@pytest.fixture
def keys(service):
    return [service.key_doc]


SCOPE = ": export of agent claims-project, all records, generated "


def resign(pack, service):
    """What only the service can do: sign a changed pack's export statement again (§7)."""
    return service.sign_export(pack)


def statuses(report):
    return {c.id: c.status for c in report.checks}


def failed(report):
    return [c.id for c in report.checks if c.status == "fail"]


def test_clean_pack_passes(pack, keys):
    r = verify_pack(pack, keys)
    assert r.ok, str(r)
    s = statuses(r)
    assert [s[i] for i in ("schema", "record_hash", "record_sig", "chain", "merkle", "batch_sig", "batch_chain", "head_sig")] == ["pass"] * 8
    assert s["drand"] == s["anchor"] == s["ots"] == s["content"] == "not_checked"
    lines = str(r).splitlines()
    assert lines[0].startswith("signafAIde pack prj_") and no_counts(lines[-1]).startswith("PASS" + SCOPE) and len(lines) == 14
    assert lines[-1].endswith(pack["generated"])
    assert lines[1].startswith(" 1. Envelope schema") and "PASS" in lines[1]
    assert "no anchors in the pack yet" in r.check("anchor").detail


def test_agent_keys_must_be_independent(pack, keys):
    r = _verify_pack(pack, keys)
    assert failed(r) == ["record_sig"] and "NOT INDEPENDENT" in str(r)
    r = _verify_pack(pack, keys, trust_embedded_agent_keys=True)
    assert r.ok and no_counts(str(r).splitlines()[-1]).startswith("PASS (agent keys taken from the pack, not independent)" + SCOPE)
    stranger = [dict(AGENTS[0], key_id="0" * 16)]
    assert failed(_verify_pack(pack, keys, agent_keys=stranger)) == ["record_sig"]


def test_content_from_local_chain(pack, keys, recorder):
    content = signafaide.load_content(recorder.state.home / "chain")
    r = verify_pack(pack, keys, contents=content)
    assert r.check("content").status == "pass" and r.check("content").checked == 5


def test_tampered_envelope(pack, keys):
    pack["records"][1]["envelope"]["name"] = "deny_payout"
    r = verify_pack(pack, keys)
    assert not r.ok and no_counts(str(r).splitlines()[-1]).startswith("FAIL" + SCOPE)
    assert r.first_failed() == "record_hash"
    assert {"record_hash", "record_sig", "chain", "merkle"} <= set(failed(r))


def test_tampered_content(pack, keys):
    pack["records"][0]["content"] = {"input": {"claim_id": "c1", "amount": 99999}}
    assert failed(verify_pack(pack, keys)) == ["content"]


def test_tampered_signature(pack, keys):
    pack["records"][2]["sig"] = pack["records"][3]["sig"]
    assert failed(verify_pack(pack, keys)) == ["record_sig"]


def test_dropped_records_fail_unless_the_filter_explains_them(pack, keys, service):
    # Anyone who passes the pack on: the export statement no longer verifies.
    middle = copy.deepcopy(pack)
    del middle["records"][2]
    r = verify_pack(middle, keys)
    assert failed(r) == ["chain", "head_sig"] and "a gap inside the chain" in str(r) and "export_sig does not verify" in str(r)
    held = copy.deepcopy(pack)
    held["records"] = held["records"][:-1]
    held["filter"]["to"] = "2099-01-01T00:00:00.000Z"
    assert failed(verify_pack(held, keys)) == ["head_sig"]
    # What the service signs must hold together too.
    start = copy.deepcopy(pack)
    del start["records"][0:2]  # the first batch: what follows was written after a flush, well after the key
    assert failed(verify_pack(resign(start, service), keys)) == ["chain"]
    start["filter"]["from"] = start["records"][0]["envelope"]["time"]  # after the agent's key: an export from a time starts mid-chain
    assert verify_pack(resign(start, service), keys).ok
    end = copy.deepcopy(pack)
    del end["records"][-1]
    r = verify_pack(resign(end, service), keys)
    assert failed(r) == ["head_sig"] and "records missing at the end" in str(r)
    from signafaide.verifier import _epoch_ms, _fmt
    end["filter"]["to"] = _fmt(_epoch_ms(end["records"][-1]["envelope"]["time"]) + 1)  # every kept record is before it
    assert verify_pack(resign(end, service), keys).ok


def test_client_head_file_catches_truncation(pack, keys, recorder, service):
    heads = [h for envs in recorder.state.heads().values() for agents in envs.values() for h in agents.values()]
    assert verify_pack(pack, keys, heads=heads).ok
    short = copy.deepcopy(pack)
    del short["records"][-1]
    short["heads"] = [{"head": short["records"][-1]["receipt"]["head"], "head_sig": short["records"][-1]["receipt"]["head_sig"]}]
    r = verify_pack(resign(short, service), keys, heads=heads)  # even the service cannot cut the end
    assert failed(r) == ["head_sig"] and "client's head" in str(r)


def test_fork_fails(pack, keys, recorder, service):
    twin = copy.deepcopy(pack["records"][2])
    twin["envelope"]["name"] = "other"
    twin["sig"] = recorder.key("claims-project").sign("record", hash_json(twin["envelope"]))
    twin["receipt"]["record_hash"] = hash_json(twin["envelope"])
    pack["records"].append(twin)
    r = verify_pack(resign(pack, service), keys)
    assert "chain" in failed(r) and "fork" in str(r)


def test_wrong_service_key(pack):
    other = SigningKey.generate()
    fake = [{"key_id": pack["records"][0]["receipt"]["service_key_id"], "public_key": b64url(other.public_key), "valid_from": None, "valid_to": None}]
    assert failed(verify_pack(pack, fake)) == ["batch_sig", "head_sig"]


def test_tampered_batch(pack, keys):
    for rec in pack["records"]:
        if rec["receipt"]["batch"]["seq"] == 1:
            rec["receipt"]["batch"]["server_time"] = "2020-01-01T00:00:00.000Z"
    # batch 2 no longer links to it, and the records are now dated long after their batch
    assert failed(verify_pack(pack, keys)) == ["chain", "batch_sig", "batch_chain"]


def test_forked_batch_chain(pack, keys, service):
    rc = pack["records"][-1]["receipt"]
    b = dict(rc["batch"], prev="11" * 32)
    rc["batch"] = b
    rc["batch_hash"] = hash_json(b)
    rc["batch_sig"] = service.key.sign("batch", rc["batch_hash"])  # a service-signed fork
    assert failed(verify_pack(pack, keys)) == ["batch_chain"]


def test_bad_proof(pack, keys):
    pack["records"][0]["receipt"]["proof"] = ["00" * 32]
    assert failed(verify_pack(pack, keys)) == ["merkle"]


def test_no_keys_is_an_input_error(pack):
    with pytest.raises(KeysRequired, match="--keys"):
        verify_pack(pack, None)


def test_trust_embedded_keys_warns(pack):
    r = verify_pack(pack, None, trust_embedded_keys=True)
    assert r.ok
    assert "WARNING: service keys were taken from the pack itself" in str(r)


def test_key_validity_window(pack, service):
    expired = dict(service.key_doc, valid_to="2021-01-01T00:00:00.000Z")
    assert failed(verify_pack(pack, [expired])) == ["batch_sig", "head_sig"]


def test_not_a_pack():
    r = verify_pack({"format": "x"}, [])
    assert r.first_failed() == "schema" and "expected 'signafaide-pack/1'" in str(r)


def test_missing_receipt_fails_schema(pack, keys):
    del pack["records"][4]["receipt"]
    assert failed(verify_pack(pack, keys)) == ["schema", "head_sig"]  # and the export statement no longer verifies


def test_receipt_from_another_project_fails_schema(pack, keys):
    pack["project"] = "prj_01JD0000000000000000000000"
    assert verify_pack(pack, keys).first_failed() == "schema"


def _ots(digest_hex, height=None):
    def varbytes(b):
        return bytes([len(b)]) + b

    if height is None:
        att = ots.TAG_PENDING + varbytes(varbytes(b"https://calendar.example"))
    else:
        h = b""
        while True:
            h += bytes([(height & 0x7F) | (0x80 if height > 0x7F else 0)])
            height >>= 7
            if not height:
                break
        att = ots.TAG_BITCOIN + varbytes(h)
    raw = ots.MAGIC + b"\x01\x08" + bytes.fromhex(digest_hex) + b"\x00" + att
    return base64.b64encode(raw).decode()


def _anchor(pack, service, height=None, ots_digest=None):
    seqs = {}
    for r in pack["records"]:
        seqs[r["receipt"]["batch_hash"]] = r["receipt"]["batch"]["seq"]
    batch_hashes = sorted(seqs, key=seqs.get)
    leaves = batch_hashes + [hash_json("other project batch")]
    root = merkle_root(leaves)
    created = now()
    a = {"v": 1, "seq": 1, "prev": None, "root": root, "size": len(leaves), "created": created,
         "keys_hash": service_keys_hash([service.key_doc], int(signafaide.records.parse_time(created).timestamp() * 1000))}
    sig = service.key.sign("anchor", hash_json(a))
    paths = {h: {"index": i, "path": audit_path(leaves, i)} for i, h in enumerate(batch_hashes)}
    status = "pending" if height is None else "confirmed"
    # The public timestamp covers the anchor hash (§4).
    full = dict(a, ots=_ots(ots_digest or hash_json(a), height), status=status, bitcoin_block=height)
    return {"anchor": full, "anchor_sig": sig, "paths": paths}


def test_anchor_paths_and_ots(pack, keys, service):
    pack["anchors"] = [_anchor(pack, service)]
    r = verify_pack(pack, keys)
    assert r.ok, str(r)
    assert r.check("anchor").status == "pass" and r.check("anchor").checked == 1
    assert r.check("ots").value == "pending" and "PENDING" in str(r)
    pack["anchors"] = [_anchor(pack, service, height=900000)]
    r = verify_pack(pack, keys)
    assert r.check("ots").status == "not_checked" and "claims block 900000" in r.check("ots").detail  # offline
    a = pack["anchors"][0]["anchor"]
    digest = hash_json({k: v for k, v in a.items() if k not in ("ots", "status", "bitcoin_block")})
    r = verify_pack(pack, keys, bitcoin={900000: (True, _header(bytes.fromhex(digest)))})
    assert r.check("ots").value == "confirmed@900000" and "CONFIRMED" in str(r) and "Bitcoin" not in str(r)
    assert failed(verify_pack(pack, keys, bitcoin={900000: (True, _header(b"\0" * 32))})) == ["ots"]
    # A header that does not hash to its block, or an explorer that could not be asked: not checked.
    bad = dict(_header(bytes.fromhex(digest)), hash="00" * 32)
    assert verify_pack(pack, keys, bitcoin={900000: (True, bad)}).check("ots").status == "not_checked"
    assert verify_pack(pack, keys, bitcoin={900000: (False, "plain http")}).check("ots").status == "not_checked"


def _header(root: bytes) -> dict:
    """A block header (regtest-easy proof of work) whose Merkle root is ``root``, as an explorer serves it."""
    import hashlib
    from signafaide.bitcoin import target

    t = target(0x207FFFFF)
    for nonce in range(1 << 16):
        h = (0x20000000).to_bytes(4, "little") + b"\1" * 32 + root + (1763028000).to_bytes(4, "little") + (0x207FFFFF).to_bytes(4, "little") + nonce.to_bytes(4, "little")
        block_id = hashlib.sha256(hashlib.sha256(h).digest()).digest()[::-1]
        if int.from_bytes(block_id, "big") <= t:
            return {"hash": block_id.hex(), "header": h.hex()}
    raise AssertionError("no nonce")


def test_anchor_tamper(pack, keys, service):
    entry = _anchor(pack, service)
    first, second = list(entry["paths"])
    entry["paths"][first]["path"] = entry["paths"][second]["path"]
    pack["anchors"] = [entry]
    assert failed(verify_pack(pack, keys)) == ["anchor"]
    pack["anchors"] = [_anchor(pack, service)]
    pack["anchors"][0]["anchor"]["root"] = "00" * 32
    assert failed(verify_pack(pack, keys)) == ["anchor", "ots"]


def test_ots_for_another_digest(pack, keys, service):
    pack["anchors"] = [_anchor(pack, service, ots_digest="ab" * 32)]
    r = verify_pack(pack, keys)
    assert failed(r) == ["ots"] and "different digest" in str(r)


def test_json_report(pack, keys):
    d = verify_pack(pack, keys).to_dict()
    assert d["result"] == "PASS" and [c["id"] for c in d["checks"]][:3] == ["schema", "record_hash", "record_sig"]
    json.dumps(d)


# --- local state ------------------------------------------------------------------------


def test_local_state_passes_with_pending(recorder, service, keys):
    signafaide.note("a", {})
    signafaide.flush()
    signafaide.note("b", {})  # not shipped yet
    r = verify_local(recorder.state, keys)
    assert r.ok, str(r)
    assert "1 not yet shipped" in r.check("record_hash").detail
    assert r.check("content").status == "pass"


def test_local_truncation_is_caught(recorder, service, keys):
    for i in range(3):
        signafaide.note(f"n{i}", {})
    signafaide.flush()
    path = chain_path(recorder)
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:-1]))
    r = verify_local(recorder.state, keys)
    assert failed(r) == ["head_sig"] and "truncated" in str(r)


def test_local_gap_is_caught(recorder, keys):
    for i in range(3):
        signafaide.note(f"n{i}", {})
    path = chain_path(recorder)
    lines = path.read_text().splitlines(keepends=True)
    path.write_text(lines[0] + lines[2])
    r = verify_local(recorder.state, keys)
    assert failed(r) == ["chain"] and "missing seq 2..2" in str(r)


def test_local_edit_is_caught(recorder, service, keys):
    signafaide.note("a", {"amount": 1})
    signafaide.flush()
    path = chain_path(recorder)
    path.write_text(path.read_text().replace('"amount":1', '"amount":2'))
    assert failed(verify_local(recorder.state, keys)) == ["content"]


def test_verify_api_fetches_keys_from_service(recorder, service):
    signafaide.note("a", {})
    signafaide.flush()
    r = signafaide.verify()
    assert r.ok, str(r)
    assert any("service keys:" in n for n in r.notes)


def test_verify_api_unreachable_keys(recorder, service, dead_url):
    signafaide.note("a", {})
    recorder._url = dead_url
    assert signafaide.verify().ok  # nothing shipped yet: no service key needed
    recorder._url = service.url
    signafaide.flush()
    recorder._url = dead_url
    with pytest.raises(KeysRequired, match="could not load service keys"):
        signafaide.verify()


def test_pack_file_round_trip(pack, keys, tmp_path):
    f = tmp_path / "pack.json"
    f.write_text(json.dumps(pack))
    assert verify_pack(str(f), keys).ok
    bad = copy.deepcopy(pack)
    bad["records"][0]["envelope"]["seq"] = 9
    assert not verify_pack(bad, keys).ok


def test_rotation_retires_the_old_key(recorder, service, keys):
    signafaide.note("a", {})
    signafaide.flush()
    signafaide.note("b", {})  # signed by the first key, still in the outbox
    agent = recorder.default_agent
    old, new = recorder.state.rotate_key(agent)
    signafaide.note("c", {})  # signed by the new key
    assert signafaide.flush()["shipped"] == 2  # b goes first, under the old key; then the rotation retires it
    retired = recorder.state.retired_at(agent, old.key_id)
    assert retired is not None
    prj = next(iter(service.projects.values()))
    assert prj["agents"][agent][old.key_id]["valid_to"] == retired
    # The old key can no longer add records.
    from signafaide.records import make_record
    tip = prj["heads"][agent]["head"]
    forged = make_record(old, kind="note", project=prj["project"], env=prj["env"], agent=agent, seq=tip["seq"] + 1, prev=tip["record_hash"], name="late", content={})
    status, body = service.submit(prj, [{k: forged[k] for k in ("envelope", "key_id", "sig")}])
    assert status == 400 and body["error"]["code"] == "bad_signature"
    # The manifest carries the retirement, self-signed; the pack verifies with it.
    manifest = recorder.state.export_agent_keys()
    assert {k["key_id"]: k["valid_to"] for k in manifest["keys"]} == {old.key_id: retired, new.key_id: None}
    pack = recorder.client().export(agent)
    r = _verify_pack(pack, keys, agent_keys=signafaide.load_agent_keys(manifest))
    assert r.ok, str(r)


def test_rotation_in_a_running_process_registers_the_new_key(recorder, service):
    signafaide.note("a", {})
    assert signafaide.flush()["shipped"] == 1  # the first key is registered in this process
    agent = recorder.default_agent
    # What `signafaide keys rotate` does (from this process or another one): a new key file.
    old, new = recorder.state.rotate_key(agent)
    signafaide.note("b", {})  # signed by the new key
    r = signafaide.flush()
    assert r["errors"] == {} and r["shipped"] == 1, r
    prj = next(iter(service.projects.values()))
    assert prj["agents"][agent][new.key_id]["valid_to"] is None
    assert prj["agents"][agent][old.key_id]["valid_to"] == recorder.state.retired_at(agent, old.key_id)
    v = signafaide.verify()
    assert v.ok, str(v)
