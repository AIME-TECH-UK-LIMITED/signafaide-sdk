import json
import os
import stat
import threading

import pytest

from signafaide.crypto import SigningKey
from signafaide.records import make_draft, make_record, record_hash
from signafaide.state import (
    State,
    StateError,
    key_fingerprint,
    append_env_file,
    ensure_gitignore,
    find_root,
    read_env_file,
    wire_record,
)


BUCKET = "prj_01JC0000000000000000000000/test"
C = f"{BUCKET}/bot"


@pytest.fixture
def state(project):
    s = State.discover()
    s.ensure()
    return s


def _append(state, agent="bot", n=1, content=None):
    key = state.load_key(agent)
    out = []
    for _ in range(n):
        out.append(
            state.append(
                f"{BUCKET}/{agent}",
                lambda seq, prev, *_: make_record(
                    key,
                    kind="note",
                    project=BUCKET.split("/")[0],
                    env=BUCKET.split("/")[1],
                    agent=agent,
                    seq=seq,
                    prev=prev,
                    name="n",
                    content=content or {"i": 1},
                ),
                lambda r: wire_record(r, False),
            )
        )
    return out


def test_layout_gitignore_and_root(project, state):
    assert state.home == project / ".signafaide"
    assert not (project / ".gitignore").exists()  # never edited at runtime: a CI checkout stays clean
    state.ignore_in_git(".env")
    assert (project / ".gitignore").read_text() == ".signafaide/\n.env\n"
    (project / "sub").mkdir()
    assert find_root(project / "sub") == project
    state.ignore_in_git()
    assert (project / ".gitignore").read_text().count(".signafaide") == 1


def test_gitignore_appends_without_touching_lines(project):
    gi = project / ".gitignore"
    gi.write_text("node_modules\n*.pyc")
    ensure_gitignore(gi, ".signafaide/")
    assert gi.read_text() == "node_modules\n*.pyc\n.signafaide/\n"


def test_signafaide_home_override(project, monkeypatch, tmp_path):
    monkeypatch.setenv("SIGNAFAIDE_HOME", str(tmp_path / "elsewhere"))
    s = State.discover()
    s.ensure()
    assert s.home == tmp_path / "elsewhere" and (s.home / "chain").is_dir()
    assert not (project / ".gitignore").exists()


def test_key_file_is_private_and_stable(state):
    k1 = state.load_key("bot")
    path = state.key_path("bot")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert state.load_key("bot").key_id == k1.key_id
    doc = json.loads(path.read_text())
    assert doc["agent"] == "bot" and doc["key_id"] == k1.key_id and "private_key" in doc
    path.write_text("garbage")
    with pytest.raises(StateError, match="not a valid signafaide key file"):
        state.load_key("bot")


def test_append_chains_and_fills_outbox(state):
    recs = _append(state, n=3)
    assert [r["envelope"]["seq"] for r in recs] == [1, 2, 3]
    assert recs[0]["envelope"]["prev"] is None
    assert recs[1]["envelope"]["prev"] == record_hash(recs[0])
    assert state.tail(C) == (3, record_hash(recs[2]), recs[2]["envelope"]["time"])
    assert [json.loads(line) for line in state.chain_path(C).read_text().splitlines()] == recs
    box = state.outbox(C)
    assert [r["envelope"]["seq"] for r in box] == [1, 2, 3]
    assert all("content" not in r for r in box)  # hash-only on the wire
    assert state.outbox_size() == 3 and state.outbox_chains() == [C]


def test_concurrent_appends_never_fork(state):
    state.load_key("bot")
    threads = [threading.Thread(target=_append, args=(state, "bot", 10)) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    recs = list(state.read_chain(C))
    assert [r["envelope"]["seq"] for r in recs] == list(range(1, 51))
    for a, b in zip(recs, recs[1:]):
        assert b["envelope"]["prev"] == record_hash(a)


def test_apply_receipts_fills_only_the_tail(state):
    recs = _append(state, n=4)
    hashes = [record_hash(r) for r in recs]
    assert state.apply_receipts(C, {hashes[0]: {"n": 0}, hashes[1]: {"n": 1}}) == 2
    assert state.apply_receipts(C, {hashes[2]: {"n": 2}}) == 1
    lines = [json.loads(line) for line in state.chain_path(C).read_text().splitlines()]
    assert [line.get("receipt") for line in lines] == [{"n": 0}, {"n": 1}, {"n": 2}, None]
    assert [line["envelope"] for line in lines] == [r["envelope"] for r in recs]
    assert not state.chain_path(C).with_name("bot.jsonl.tail").exists()


def test_interrupted_receipt_rewrite_is_finished_by_next_writer(state):
    recs = _append(state, n=2)
    path = state.chain_path(C)
    lines = path.read_bytes().splitlines(keepends=True)
    offset = len(lines[0])
    second = dict(recs[1], receipt={"ok": 1})
    from signafaide import jcs

    path.with_name("bot.jsonl.tail").write_bytes(f"{offset}\n".encode() + (jcs.dumps(second) + "\n").encode())
    with open(path, "r+b") as f:  # simulate a crash right after truncation
        f.truncate(offset)
    _append(state, n=1)
    out = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["envelope"]["seq"] for r in out] == [1, 2, 3]
    assert out[1]["receipt"] == {"ok": 1}


def test_reconcile_requeues_lost_outbox_file(state):
    recs = _append(state, n=2)
    (state.outbox_dir(C) / "000000000002.json").unlink()
    assert state.reconcile_outbox(C, lambda r: wire_record(r, False)) == 1
    assert [record_hash(r) for r in state.outbox(C)] == [record_hash(r) for r in recs]


def test_stale_lock_is_taken_over(state):
    lock = state.home / "chain" / f"{C}.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text("999999")
    old = lock.stat().st_mtime - 60
    os.utime(lock, (old, old))
    _append(state, n=1)
    assert not lock.exists()


def test_damaged_chain_line_is_reported_not_repaired(state):
    _append(state, n=1)
    with open(state.chain_path(C), "a") as f:
        f.write('{"envelope": tor')
    with pytest.raises(StateError, match="damaged line"):
        state.tail(C)


def test_heads_keep_newest_and_flag_truncation(state):
    h = lambda seq: {
        "head": {"project": "prj_01JC0000000000000000000000", "env": "test", "agent": "bot", "seq": seq},
        "head_sig": "x",
    }  # noqa: E731
    assert state.update_heads([h(3)]) == []
    assert state.update_heads([h(5)]) == []
    warns = state.update_heads([h(4)])
    assert warns and "truncation" in warns[0]
    assert state.heads()["prj_01JC0000000000000000000000"]["test"]["bot"]["head"]["seq"] == 5
    assert list(state.chain_heads()) == [C]


def test_env_file_append_never_overwrites(project):
    env = project / ".env"
    env.write_text("# comment\nOTHER='x y'\nexport A=1")
    append_env_file(env, "SIGNAFAIDE_API_KEY", "sfa_test_k")
    assert env.read_text() == "# comment\nOTHER='x y'\nexport A=1\nSIGNAFAIDE_API_KEY=sfa_test_k\n"
    assert read_env_file(env) == {"OTHER": "x y", "A": "1", "SIGNAFAIDE_API_KEY": "sfa_test_k"}


def test_wire_record_content_only_when_stored():
    r = make_record(
        SigningKey.generate(),
        kind="note",
        project="prj_01JD0000000000000000000000",
        env="test",
        agent="a",
        seq=1,
        prev=None,
        name="n",
        content={"x": 1},
    )
    assert "content" not in wire_record(r, False)
    assert wire_record(r, True)["content"] == {"x": 1}


def test_buckets_follow_the_api_key(state):
    assert state.bucket(None) == "_pending/nokey"
    key = "sfa_live_" + "a" * 32
    fp = key_fingerprint(key)
    assert state.bucket(key) == f"_pending/{fp}"
    state.learn_project(key, "prj_01JD0000000000000000000000", "live")
    assert state.bucket(key) == "prj_01JD0000000000000000000000/live"
    assert key not in (state.home / "config.json").read_text()  # only the fingerprint is stored


def test_adopt_signs_drafts_into_the_project_chain(state):
    key = state.load_key("bot")
    draft = lambda seq, prev, *_, ref=None: make_draft(
        key, kind="note", agent="bot", seq=seq, prev=prev, name="n", content={}, ref=ref
    )  # noqa: E731
    d1 = state.append("_pending/nokey/bot", draft, lambda r: wire_record(r, False))
    state.append(
        "_pending/nokey/bot",
        lambda seq, prev, *_: make_draft(
            key, kind="outcome", agent="bot", seq=seq, prev=prev, name="n", content={}, ref=record_hash(d1)
        ),
        lambda r: wire_record(r, False),
    )
    assert (
        state.outbox_size() == 0
        and list(state.read_chain("_pending/nokey/bot")) == []
        and state.draft_count("_pending/nokey/bot") == 2
    )
    assert state.adopt("_pending/nokey", BUCKET, lambda a, *_: key, lambda r: wire_record(r, False)) == []
    assert state.chains() == [C] and state.outbox_chains() == [C] and state.tail(C)[0] == 2
    signed = list(state.read_chain(C))
    assert [r["envelope"]["project"] + "/" + r["envelope"]["env"] for r in signed] == [BUCKET] * 2
    assert (
        signed[1]["envelope"]["prev"] == record_hash(signed[0]) == signed[1]["envelope"]["ref"]
    )  # the ref follows its decision
    assert state.translate_ref(C, record_hash(d1)) == record_hash(signed[0])
    state.append("_pending/nokey/bot", draft, lambda r: wire_record(r, False))
    assert state.adopt("_pending/nokey", BUCKET, lambda a, *_: key, lambda r: wire_record(r, False)) == [
        ("_pending/nokey/bot", "exists")
    ]  # never merged into an existing chain


def test_adopt_keeps_a_chain_older_than_not_before_local(state):
    key = state.load_key("old")
    at = lambda t: (
        lambda seq, prev, *_: make_draft(
            key, kind="note", agent="old", seq=seq, prev=prev, name="n", content={}, time=t
        )
    )  # noqa: E731
    state.append("_pending/nokey/old", at("2026-01-01T00:00:00.000Z"), lambda r: r)
    state.append("_pending/nokey/old", at("2026-01-02T00:00:00.000Z"), lambda r: r)
    assert state.adopt(
        "_pending/nokey", BUCKET, lambda a, *_: key, lambda r: wire_record(r, False), "2026-01-01T12:00:00.000Z"
    ) == [("_pending/nokey/old", "2026-01-01T00:00:00.000Z")]
    assert state.chains() == ["_pending/nokey/old"] and state.outbox_size() == 0
    assert (
        state.adopt(
            "_pending/nokey", BUCKET, lambda a, *_: key, lambda r: wire_record(r, False), "2025-12-31T00:00:00.000Z"
        )
        == []
    )
    assert [r["envelope"]["time"] for r in state.read_chain(f"{BUCKET}/old")] == [
        "2026-01-01T00:00:00.000Z",
        "2026-01-02T00:00:00.000Z",
    ]


def test_env_file_is_private_and_single_line(project):
    env = project / ".env"
    append_env_file(env, "SIGNAFAIDE_API_KEY", "sfa_test_" + "a" * 32)
    assert env.stat().st_mode & 0o777 == 0o600
    with pytest.raises(StateError):
        append_env_file(env, "SIGNAFAIDE_API_KEY", "sfa_test_x\nNODE_OPTIONS=--require ./pwn.js")


def test_learn_project_refuses_paths(state):
    with pytest.raises(StateError):
        state.learn_project("sfa_test_" + "a" * 32, "../../../escaped", "test")
    with pytest.raises(StateError):
        state.learn_project("sfa_test_" + "a" * 32, "prj_01JD0000000000000000000000", "../x")


def test_rotate_and_export_agent_keys(state):
    old = state.load_key("bot")
    o, new = state.rotate_key("bot")
    assert o.key_id == old.key_id and new.key_id != old.key_id
    doc = state.export_agent_keys()
    assert {k["key_id"] for k in doc["keys"]} == {old.key_id, new.key_id}
    assert all(k["valid_to"] is None for k in doc["keys"])  # not retired on the service yet
    from signafaide.verifier import load_agent_keys

    assert len(load_agent_keys(doc)) == 2
    # Once the service says when it retired the old key, the manifest carries it, self-signed.
    assert state.mark_retired("bot", old.key_id, "2026-11-13T10:00:00.000Z")
    doc = state.export_agent_keys()
    assert {k["key_id"]: k["valid_to"] for k in doc["keys"]} == {
        old.key_id: "2026-11-13T10:00:00.000Z",
        new.key_id: None,
    }
    assert len(load_agent_keys(doc)) == 2
