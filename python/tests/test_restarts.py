"""The instance-stop note and clean restarts and one warning line when a
strict tool is refused."""

from __future__ import annotations

import atexit
import json
import shutil

import pytest

import signafaide
from signafaide import runtime
from signafaide._version import __version__
from signafaide.records import CLEAN_RESTART_NOTE, INSTANCE_NOTE, INSTANCE_START, INSTANCE_STOP
from signafaide.verifier import verify_pack


def _names(rec, chain):
    return [(x["envelope"]["seq"], x["envelope"]["name"]) for x in rec.state.read_all(chain)]


def test_stop_note_makes_the_next_start_a_clean_restart(recorder, service, project, monkeypatch, tmp_path):
    monkeypatch.setenv("SIGNAFAIDE_HEAD_FILE", str(tmp_path / "vol" / "head.json"))
    rec = runtime.configure(quiet=True, flush_interval=3600)
    assert rec.instance_stop is True  # a head file means an ephemeral instance
    st = rec.state
    st.load_key("risk-0")
    doc = json.loads(st.key_path("risk-0").read_text())
    rec.write("note", "a", {}, agent="risk-0")
    rec.write("note", "b", {}, agent="risk-0")
    chain = f"{st.bucket(rec.api_key)}/risk-0"
    s = rec.stop()
    assert s["errors"] == {} and (s["shipped"], s["left"], s["stopped"]) == (3, 0, [chain])
    recs = list(st.read_all(chain))
    assert _names(rec, chain) == [(1, "a"), (2, "b"), (3, INSTANCE_STOP)]
    assert recs[2]["content"] == {
        "stopped_after_seq": 2,
        "stopped_after": recs[2]["envelope"]["prev"],
        "outbox": "empty",
    }
    assert "receipt" in recs[2]
    s = rec.stop()  # nothing new was written: no second note
    assert (s["shipped"], s["stopped"]) == (0, []) and len(list(st.read_all(chain))) == 3

    # The container goes with its disk; a new one continues right after the stop note.
    rec._stopped = True
    shutil.rmtree(st.home)
    rec = signafaide.init(quiet=True, key_provider=lambda agent, scope: doc)
    rec.flush_interval = 3600
    rec.write("decision", "freeze_account", {"input": {"account": "A1"}}, agent="risk-0")
    assert rec.flush()["errors"] == {}
    assert _names(rec, chain) == [(4, INSTANCE_START), (5, "freeze_account")]
    assert next(iter(rec.state.read_all(chain)))["content"]["earlier_unsent"] == "none"
    assert rec.state.chain_base(chain)["stop"]["envelope"]["name"] == INSTANCE_STOP
    v = signafaide.verify()
    assert v.ok, str(v)
    assert f"{CLEAN_RESTART_NOTE}: {chain} after seq 3" in v.check("chain").detail
    assert INSTANCE_NOTE not in v.check("chain").detail
    # A stop note kept with the base that is not the head's record does not count.
    base_path = rec.state.chain_path(chain).with_name("risk-0.base.json")
    base = json.loads(base_path.read_text())
    forged = json.loads(json.dumps(base))
    forged["stop"]["envelope"]["name"] = "other"
    base_path.write_text(json.dumps(forged))
    assert f"{INSTANCE_NOTE}: {chain} after seq 3" in signafaide.verify().check("chain").detail
    base_path.write_text(json.dumps(base))

    # This instance is killed: no stop note. The next start is not clean.
    rec._stopped = True
    shutil.rmtree(rec.state.home)
    rec = signafaide.init(quiet=True, key_provider=lambda agent, scope: doc)
    rec.flush_interval = 3600
    rec.write("decision", "freeze_account", {"input": {"account": "A2"}}, agent="risk-0")
    assert rec.flush()["errors"] == {}
    assert _names(rec, chain) == [(6, INSTANCE_START), (7, "freeze_account")]
    assert next(iter(rec.state.read_all(chain)))["content"]["earlier_unsent"] == "unknown"
    v = signafaide.verify()
    assert f"{INSTANCE_NOTE}: {chain} after seq 5" in v.check("chain").detail
    assert CLEAN_RESTART_NOTE not in v.check("chain").detail

    # The whole chain as an auditor sees it: one clean restart, one with no stop before it.
    pack = rec.client().export("risk-0")
    pv = verify_pack(pack, [service.key_doc], agent_keys=rec.state.export_agent_keys()["keys"])
    assert pv.ok, str(pv)
    detail = pv.check("chain").detail
    assert f"{CLEAN_RESTART_NOTE}: risk-0 after seq 3" in detail and f"{INSTANCE_NOTE}: risk-0 after seq 5" in detail
    rec._stopped = True
    rec.instance_stop = False  # nothing to write when the test process ends


def test_no_stop_note_while_unsent_or_by_default_without_a_head_file(recorder, service, monkeypatch, tmp_path):
    assert recorder.instance_stop is False
    recorder.write("note", "a", {}, agent="risk-1")
    service.fail_always = (503, {"error": {"code": "unavailable", "message": "down"}})
    s = recorder.stop()
    assert s["stopped"] == [] and s["left"] == 1
    service.fail_always = None
    assert len(recorder.stop()["stopped"]) == 1  # an explicit stop() writes one once everything is sent
    monkeypatch.setenv("SIGNAFAIDE_HEAD_FILE", str(tmp_path / "h.json"))
    monkeypatch.setenv("SIGNAFAIDE_INSTANCE_STOP", "0")
    assert runtime.configure(quiet=True, flush_interval=3600).instance_stop is False


def test_exit_writes_the_stop_note_with_a_head_file(recorder, service, monkeypatch, tmp_path):
    monkeypatch.setenv("SIGNAFAIDE_HEAD_FILE", str(tmp_path / "vol" / "head.json"))
    rec = runtime.configure(quiet=True, flush_interval=3600)
    rec.write("note", "a", {}, agent="risk-2")
    rec.close()  # what runs when the program ends
    prj = next(iter(service.projects.values()))
    names = [r["envelope"]["name"] for r, _ in prj["records"].values()]
    assert names == ["a", INSTANCE_STOP]
    assert rec.state.outbox_size() == 0
    rec.close()  # nothing new was written: no second stop note
    assert len(prj["records"]) == 2
    atexit.unregister(rec.close)
    # The witness is away at exit: the record stays in the outbox and no stop note is written.
    rec = runtime.configure(quiet=True, flush_interval=3600)
    rec.write("note", "b", {}, agent="risk-2")
    service.fail_always = (503, {"error": {"code": "unavailable", "message": "down"}})
    rec.close()
    service.fail_always = None
    assert [x["envelope"]["name"] for x in rec.state.read_all(f"{rec.state.bucket(rec.api_key)}/risk-2")] == [
        "a",
        INSTANCE_STOP,
        "b",
    ]
    assert rec.state.outbox_size() == 1
    atexit.unregister(rec.close)  # the fake witness is gone when the test process ends


def test_strict_refused_for_no_key_prints_one_warning(local_recorder, service, capsys):
    ran = []

    @signafaide.record(name="refund_payment", strict=True)
    def refund():
        ran.append(1)

    @signafaide.record(name="freeze_account", strict=True)
    def freeze():
        ran.append(1)

    for tool in (refund, freeze, refund):
        with pytest.raises(
            signafaide.SignafaideBlocked
        ):  # a framework would swallow this; ruled as with a checks file (0.5.1)
            tool()
    err = capsys.readouterr().err
    lines = [line for line in err.splitlines() if "protected tool" in line]
    assert len(lines) == 1, err
    assert 'signafaide: protected tool "refund_payment" was refused and did not run (no_key)' in lines[0]
    assert "protected tools stop until a person runs `signafaide protect` in this project" in lines[0]
    assert "WARN" not in lines[0].upper()
    assert not ran and service.calls == []


def test_version_is_0_2_0():
    assert __version__ == "0.5.4"
