"""Fix round 5: keys create (#38), the head file and on_head hook (#39), the signed
instance-start note (#40)."""

from __future__ import annotations

import json
import shutil

import signafaide
from signafaide import runtime
from signafaide.cli import main
from signafaide.records import INSTANCE_NOTE, INSTANCE_START


def test_keys_create_print_registers_and_writes_nothing(recorder, service, monkeypatch, capsys):
    before = len(service.registrations)
    assert main(["keys", "create", "--agent", "reconciler-0", "--env", "test", "--print"]) == 0
    out, err = capsys.readouterr()
    doc = json.loads(out)
    assert list(doc) == ["agent", "key_id", "public_key", "private_key", "created"]
    assert "SIGNAFAIDE_AGENT_KEY_RECONCILER_0" in err and "no record was written" in err
    assert len(service.registrations) == before + 1
    assert not recorder.state.key_path("reconciler-0").exists()
    assert recorder.state.chains() == []
    # The printed line works as the key from the environment.
    monkeypatch.setenv("SIGNAFAIDE_AGENT_KEY_RECONCILER_0", out.strip())
    signafaide.note("first", {}, agent="reconciler-0")
    assert signafaide.flush()["errors"] == {}
    prj = next(iter(service.projects.values()))
    assert len(prj["agents"]["reconciler-0"]) == 1


def test_keys_create_print_on_a_clean_machine_writes_nothing(recorder, service, monkeypatch, tmp_path, capsys):
    live = "sfa_live_" + "L" * 32
    service.add_project(live, "live")
    d = tmp_path / "keyshop"
    (d / ".git").mkdir(parents=True)
    monkeypatch.chdir(d)
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", live)
    runtime.configure(quiet=True, flush_interval=3600)
    assert main(["keys", "create", "--agent", "reconciler-0", "--env", "live", "--print"]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out)["agent"] == "reconciler-0"
    assert "SIGNAFAIDE_AGENT_KEY_LIVE_RECONCILER_0" in err
    assert not (d / ".signafaide").exists()


def test_keys_create_saves_the_file_and_refuses_twice(recorder, capsys):
    assert main(["keys", "create", "--agent", "risk-0", "--env", "test"]) == 0
    assert "no record was written" in capsys.readouterr().out
    assert recorder.state.key_path("risk-0").exists()
    assert main(["keys", "create", "--agent", "risk-0", "--env", "test"]) != 0
    assert "keys rotate" in capsys.readouterr().err


def test_keys_create_refuses_an_active_key_and_the_other_env(recorder, capsys):
    signafaide.note("x", {}, agent="busy-bot")
    signafaide.flush()
    assert main(["keys", "create", "--agent", "busy-bot", "--env", "test", "--print"]) != 0
    assert "already has an active key on the witness" in capsys.readouterr().err
    assert main(["keys", "create", "--agent", "other", "--env", "live", "--print"]) != 0
    assert "needs a live key" in capsys.readouterr().err


def test_rotate_without_a_key_points_at_keys_create(recorder, capsys):
    assert main(["keys", "rotate", "--agent", "nobody", "--env", "live"]) != 0
    assert "keys create --agent nobody --env live --print" in capsys.readouterr().err


def test_head_file_hook_and_instance_start_note(recorder, service, project, monkeypatch, tmp_path):
    head_file = tmp_path / "vol" / "heads" / "head.json"
    monkeypatch.setenv("SIGNAFAIDE_HEAD_FILE", str(head_file))
    seen = []
    rec = runtime.configure(quiet=True, flush_interval=3600, on_head=seen.extend)
    st = rec.state
    st.load_key("risk-0")
    doc = json.loads(st.key_path("risk-0").read_text())
    rec.write("note", "a", {}, agent="risk-0")
    rec.write("note", "b", {}, agent="risk-0")
    assert rec.flush()["errors"] == {}
    assert len(seen) == 1
    kept = json.loads(head_file.read_text())
    (project_id,) = kept
    assert kept[project_id]["test"]["risk-0"]["head"]["seq"] == 2
    rec._stopped = True
    shutil.rmtree(st.home)  # the container goes, with its disk
    rec = signafaide.init(quiet=True, key_provider=lambda agent, scope: doc)
    rec.flush_interval = 3600
    rec.write("decision", "freeze_account", {"input": {"account": "A1"}}, agent="risk-0")
    assert rec.flush()["errors"] == {}
    chain = f"{rec.state.bucket(rec.api_key)}/risk-0"
    recs = list(rec.state.read_all(chain))
    assert [(x["envelope"]["seq"], x["envelope"]["kind"], x["envelope"]["name"]) for x in recs] == [
        (3, "note", INSTANCE_START), (4, "decision", "freeze_account")]
    assert recs[0]["content"] == {"continues_after_seq": 2, "continues_after": kept[project_id]["test"]["risk-0"]["head"]["record_hash"],
                                  "earlier_unsent": "unknown"}
    assert json.loads(head_file.read_text())[project_id]["test"]["risk-0"]["head"]["seq"] == 4
    v = signafaide.verify()
    assert v.ok, str(v)
    assert f"{INSTANCE_NOTE}: {chain} after seq 2" in v.check("chain").detail
    rec._stopped = True
    rec.instance_stop = False  # nothing to write when the test process ends


def test_on_head_that_raises_never_stops_recording(recorder, caplog):
    def boom(heads):
        raise RuntimeError("bucket down")

    rec = runtime.configure(quiet=True, flush_interval=3600, on_head=boom)
    rec.write("note", "a", {}, agent="hooked")
    assert rec.flush()["errors"] == {}
    assert "bucket down" in caplog.text
    rec._stopped = True


def test_a_chain_from_seq_one_has_no_note(recorder):
    signafaide.note("only", {}, agent="fresh")
    signafaide.flush()
    chain = next(c for c in recorder.state.chains() if c.endswith("/fresh"))
    assert [x["envelope"]["name"] for x in recorder.state.read_all(chain)] == ["only"]
