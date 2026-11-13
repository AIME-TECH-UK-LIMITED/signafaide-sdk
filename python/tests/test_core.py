import hashlib
import json

import pytest

from signafaide import jcs
from signafaide.crypto import (
    SigningKey,
    audit_path,
    b64url,
    b64url_decode,
    hash_json,
    key_id,
    leaf_hash,
    merkle_root,
    signed_message,
    verify_inclusion,
    verify_sig,
)
from signafaide.records import agent_name, envelope_errors, make_record, record_errors, record_hash

# --- JCS (RFC 8785) ----------------------------------------------------------------


def test_jcs_rfc8785_example():
    value = json.loads(
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    assert jcs.dumps(value) == (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )


def test_jcs_sorts_keys_by_utf16_code_units():
    keys = ["€", "\r", "דּ", "1", "\U0001f600", "\u0080", "ö"]
    out = jcs.dumps({k: i for i, k in enumerate(keys)})
    order = list(json.loads(out))
    assert order == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


@pytest.mark.parametrize(
    "num,text",
    [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.5, "-1.5"),
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1.5e-7, "1.5e-7"),
        (0.1 + 0.2, "0.30000000000000004"),
        (5e-324, "5e-324"),
        (-1.7976931348623157e308, "-1.7976931348623157e+308"),
        (123456789012345680000.0, "123456789012345680000"),
        (9007199254740991, "9007199254740991"),
        (9007199254740992.0, "9007199254740992"),
        (2.0**64, "18446744073709552000"),
        (42, "42"),
    ],
)
def test_jcs_numbers_follow_ecmascript(num, text):
    assert jcs.dumps(num) == text


def test_jcs_literals_and_escapes():
    assert jcs.dumps([True, False, None]) == "[true,false,null]"
    assert jcs.dumps(" \x7f\x1f\b") == '" \x7f\\u001f\\b"'
    assert jcs.dumps({"a": [], "b": {}}) == '{"a":[],"b":{}}'


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), "\ud800", {1: 2}, object(), 2**53, -(2**53), 2**64])
def test_jcs_rejects_non_json(bad):
    with pytest.raises((ValueError, TypeError)):
        jcs.canonicalize(bad)


def test_signing_refuses_floats_written_as_unsafe_integers():
    for bad in (1e20, 2.0**53, -(2.0**64)):
        with pytest.raises(ValueError, match="unsafe_integer"):
            jcs.assert_portable_numbers({"a": [bad]})
        with pytest.raises(ValueError, match="unsafe_integer"):
            make_record(SigningKey.generate(), kind="note", project="prj_01JD0000000000000000000000", env="test", agent="a", seq=1, prev=None, name="n", content={"x": bad})
    jcs.assert_portable_numbers({"a": [2.0**53 - 1, 1e21, 0.5, 2**53 - 1]})


# --- hashes, keys, signatures -------------------------------------------------------


def test_hash_and_key_id():
    assert hash_json({"b": 1, "a": 2}) == hashlib.sha256(b'{"a":2,"b":1}').hexdigest()
    pk = bytes(range(32))
    assert key_id(pk) == hashlib.sha256(pk).hexdigest()[:16]


def test_b64url_round_trip_and_no_padding():
    for n in range(0, 70):
        data = bytes(range(n))
        s = b64url(data)
        assert "=" not in s and b64url_decode(s) == data
    with pytest.raises(ValueError):
        b64url_decode("AAA=")


def test_signed_message_layout():
    h = "ab" * 32
    assert signed_message("record", h) == b"signafaide/v1/record\n" + bytes.fromhex(h)
    with pytest.raises(ValueError):
        signed_message("other", h)


def test_rfc8032_test_vector_1():
    # RFC 8032 §7.1 TEST 1: our key derivation matches the standard.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    k = SigningKey(seed)
    assert k.public_key.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_signatures_are_domain_separated():
    k = SigningKey.generate()
    pk = b64url(k.public_key)
    h = hash_json({"x": 1})
    sig = k.sign("record", h)
    assert verify_sig(pk, "record", h, sig)
    for other in ("batch", "head", "anchor"):
        assert not verify_sig(pk, other, h, sig)
    assert not verify_sig(pk, "record", hash_json({"x": 2}), sig)
    assert not verify_sig(b64url(SigningKey.generate().public_key), "record", h, sig)
    assert not verify_sig(pk, "record", h, "not-a-sig")


# --- Merkle (RFC 6962) ----------------------------------------------------------------


def _ref_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _ref_root(leaves[:k]) + _ref_root(leaves[k:])).digest()


def test_merkle_root_and_single_leaf():
    hs = [hash_json(i) for i in range(7)]
    assert merkle_root(hs[:1]) == leaf_hash(hs[0]).hex() == hashlib.sha256(b"\x00" + bytes.fromhex(hs[0])).hexdigest()
    for n in range(1, 8):
        assert merkle_root(hs[:n]) == _ref_root([leaf_hash(h) for h in hs[:n]]).hex()


def test_merkle_three_leaves_shape():
    hs = [hash_json(i) for i in range(3)]
    l0, l1, l2 = (leaf_hash(h) for h in hs)
    n01 = hashlib.sha256(b"\x01" + l0 + l1).digest()
    assert merkle_root(hs) == hashlib.sha256(b"\x01" + n01 + l2).hexdigest()
    assert audit_path(hs, 2) == [n01.hex()]
    assert audit_path(hs, 0) == [l1.hex(), l2.hex()]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 13, 33])
def test_merkle_every_path_verifies(n):
    hs = [hash_json(i) for i in range(n)]
    root = merkle_root(hs)
    for i in range(n):
        path = audit_path(hs, i)
        assert verify_inclusion(hs[i], i, n, path, root)
        assert not verify_inclusion(hash_json("other"), i, n, path, root)
        if n > 1:
            assert not verify_inclusion(hs[i], (i + 1) % n, n, path, root)
        assert not verify_inclusion(hs[i], i, n, path + [hs[0]], root)


# --- envelopes ----------------------------------------------------------------------


def _rec(**kw):
    k = SigningKey.generate()
    args = dict(kind="decision", project="prj_01JD0000000000000000000000", env="live", agent="bot", seq=1, prev=None, name="act", content={"input": {}})
    args.update(kw)
    return make_record(k, **args)


def test_make_record_is_valid_and_signed():
    r = _rec()
    assert record_errors(r) == []
    assert set(r["envelope"]) == {"v", "kind", "project", "env", "agent", "seq", "prev", "time", "name", "content_hash", "ref"}
    assert r["envelope"]["content_hash"] == hash_json({"input": {}})
    assert len(r["envelope"]["time"]) == 24 and r["envelope"]["time"].endswith("Z")
    assert record_hash(r) == hash_json(r["envelope"])


@pytest.mark.parametrize(
    "change,needle",
    [
        ({"v": 2}, "v must be 1"),
        ({"v": True}, "v must be 1"),
        ({"kind": "action"}, "kind"),
        ({"agent": "Bad Name"}, "agent"),
        ({"seq": 0}, "seq"),
        ({"seq": 2, "prev": None}, "prev must be a record hash"),
        ({"prev": "ab" * 32}, "prev must be null"),
        ({"time": "2026-11-13T10:00:00Z"}, "milliseconds"),
        ({"name": ""}, "name"),
        ({"name": "x" * 129}, "name"),
        ({"content_hash": "AB" * 32}, "content_hash"),
        ({"ref": "ab" * 32}, "ref must be null"),
        ({"kind": "outcome"}, "ref must be the decision"),
        ({"extra": 1}, "unknown field"),
        ({"project": "prj_x"}, "project"),
        ({"env": "prod"}, "env must be"),
        ({"seq": 2**53}, "seq"),
    ],
)
def test_envelope_schema_errors(change, needle):
    env = dict(_rec()["envelope"])
    env.update(change)
    assert any(needle in e for e in envelope_errors(env)), envelope_errors(env)


def test_envelope_missing_field():
    env = dict(_rec()["envelope"])
    del env["ref"]
    assert envelope_errors(env) == ["missing ref"]


def test_agent_name_from_folder():
    assert agent_name("Claims Project") == "claims-project"
    assert agent_name("__My_Bot!!") == "my_bot"
    assert agent_name("???") == "agent"
    assert len(agent_name("a" * 100)) == 64
