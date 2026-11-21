"""Monotonic time, a sender that never storms, a write path with no network,
BLOCKED chains and repair, clocks ahead, keys from the environment, ephemeral disks, segments,
test mode and the off switch, read-only folders, claim links and errors about the key."""

from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timedelta, timezone

import pytest

import signafaide
from signafaide import runtime
from signafaide.cli import main
from signafaide.http import DEFAULT_URL
from signafaide.records import clamp_time
from signafaide.state import State, StateError, agent_key_env_name

from helpers import chain_of, records


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def record_calls(service) -> int:
    return sum(1 for m, p in service.calls if (m, p) == ("POST", "/v1/records"))


# --- monotonic time -------------------------------------------------------------


def test_clock_step_back_never_writes_a_chain_that_goes_back(local_recorder, monkeypatch):
    clock = {"t": "2026-11-13T10:00:10.000Z"}
    monkeypatch.setattr(runtime, "now", lambda: clock["t"])
    monkeypatch.setattr(signafaide.state, "now", lambda: clock["t"])  # the key is made at the same clock
    signafaide.note("a", {"meta": {"by": "ops"}})
    clock["t"] = "2026-11-13T10:00:05.000Z"  # NTP steps the clock back 5 s
    signafaide.note("b", {"meta": {"by": "ops"}})
    signafaide.note("c", {})
    clock["t"] = "2026-11-13T10:00:11.000Z"
    signafaide.note("d", {})
    a, b, c, d = records(local_recorder)
    assert [r["envelope"]["time"] for r in (a, b, c, d)] == ["2026-11-13T10:00:10.000Z"] * 3 + [
        "2026-11-13T10:00:11.000Z"
    ]
    assert b["content"] == {"meta": {"by": "ops", "wall_time": "2026-11-13T10:00:05.000Z"}}
    assert c["content"] == {"meta": {"wall_time": "2026-11-13T10:00:05.000Z"}}
    assert a["content"] == {"meta": {"by": "ops"}}
    monkeypatch.undo()
    r = signafaide.verify()
    assert r.check("chain").status == "pass" and r.check("content").status == "pass", str(r)


def test_a_record_is_never_dated_before_its_key(local_recorder):
    st = local_recorder.state
    st.load_key("bot")
    doc = json.loads(st.key_path("bot").read_text())
    doc["created"] = iso(datetime.now(timezone.utc) + timedelta(minutes=1))
    st.key_path("bot").write_text(json.dumps(doc))
    signafaide.note("n", {}, agent="bot")
    (r,) = records(local_recorder, "bot")
    assert r["envelope"]["time"] == doc["created"] and r["content"]["meta"]["wall_time"] < doc["created"]


def test_clamp_time_vectors():
    from pathlib import Path

    v = json.loads((Path(__file__).resolve().parents[2] / "spec" / "vectors.json").read_text())
    assert len(v["time_clamp"]) == 5
    for c in v["time_clamp"]:
        assert clamp_time(c["wall"], c["prev"], c["valid_from"]) == (c["time"], c["raised"]), c["name"]


# --- the write path never waits for the network, never raises outside strict -------------------


def test_a_hanging_witness_never_blocks_a_tool_call(project, service, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    rec = runtime.configure(quiet=True, flush_interval=3600)
    rec.create_sandbox()
    rec.state.save_config(projects={})  # the key's project is not known yet: the old SDK asked the witness here
    service.hang = 3.0
    service.calls.clear()
    t0 = time.monotonic()
    out = signafaide.record(lambda: "done", name="pay")()
    took = time.monotonic() - t0
    assert out == "done" and took < 0.5, took
    assert service.calls == []  # nothing was asked while the tool ran
    service.hang = 0
    rec._stopped = True


def test_a_wrong_key_is_a_warning_never_an_exception_in_the_tool(project, service, monkeypatch, caplog):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", "sfa_test_" + "9" * 32)
    rec = runtime.configure(quiet=True, flush_interval=3600)
    assert signafaide.record(lambda: 7, name="pay")() == 7
    r = rec.flush()
    assert list(r["errors"]) == ["API key sfa_test_9999..."]
    signafaide.init(url=service.url, quiet=True)  # warns, does not raise
    rec._stopped = True


def test_a_malformed_key_is_caught_here_and_never_sent(project, service, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", "sk-openai-oops")
    rec = runtime.configure(quiet=True, flush_interval=3600)
    assert rec.api_key is None
    signafaide.note("n", {})
    rec.flush()
    assert service.calls == []
    assert rec.status()["api_key_invalid"] is True
    with pytest.raises(signafaide.SignafaideError, match="not a signafAIde key"):
        rec.create_sandbox()
    rec._stopped = True


# --- the background sender ----------------------------------------------------------------------


def _until(cond, seconds: float = 15.0) -> bool:
    """Wait for *cond* (an event the background sender causes), never for a fixed time: on a busy
    machine its first attempt (registration, then the batch) can take longer than any short sleep."""
    deadline = time.monotonic() + seconds
    while not cond():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


def test_an_explicit_flush_keeps_the_halt_while_it_runs(recorder, service, monkeypatch):
    """The background sender never sends alongside an explicit flush of a halted recorder: the halt
    ends only once an explicit flush succeeds (it used to end at the flush's start)."""
    import threading

    service.quota = 0
    recorder.flush_interval = 0.02
    for i in range(3):
        signafaide.note(f"n{i}", {})
    recorder._wake.set()
    assert _until(lambda: recorder._halted is not None), service.calls
    assert record_calls(service) == 1
    real = recorder._ship_chain
    me = threading.current_thread()

    def held(*a, **k):
        if threading.current_thread() is me:
            # The explicit flush is in the middle of its shipment: 5 rounds of the sender pass.
            rounds = recorder._ticks
            assert _until(lambda: recorder._ticks >= rounds + 5), recorder._ticks
        return real(*a, **k)

    monkeypatch.setattr(recorder, "_ship_chain", held)
    assert recorder.flush()["errors"]
    rounds = recorder._ticks
    assert _until(lambda: recorder._ticks >= rounds + 5), recorder._ticks
    assert record_calls(service) == 2, service.calls  # the explicit one only


@pytest.mark.parametrize("where", ["resolving the project", "shipping"])
def test_an_explicit_flush_that_fails_with_a_network_error_keeps_the_halt(recorder, service, where):
    from signafaide.http import SignafaideError

    service.quota = 0
    recorder.flush_interval = 0.02
    for i in range(3):
        signafaide.note(f"n{i}", {})
    recorder._wake.set()
    assert _until(lambda: recorder._halted is not None), service.calls
    assert record_calls(service) == 1

    def down(*a, **k):
        raise SignafaideError("Cannot reach the service.", code="network")

    name = "resolve_project" if where == "resolving the project" else "_ship_chain"
    real = getattr(recorder, name)
    setattr(recorder, name, down)
    try:
        errors = recorder.flush()["errors"]
    finally:
        setattr(recorder, name, real)
    assert [e.code for e in errors.values()] == ["network"]
    assert recorder._halted is not None
    rounds = recorder._ticks
    assert _until(lambda: recorder._ticks >= rounds + 5), recorder._ticks
    assert record_calls(service) == 1, service.calls  # the halt held: the sender sent nothing


def test_an_explicit_flush_with_nothing_to_ship_asks_once_and_ends_the_halt(recorder, service):
    service.quota = 0
    recorder.flush_interval = 0.02
    for i in range(3):
        signafaide.note(f"n{i}", {})
    recorder._wake.set()
    assert _until(lambda: recorder._halted is not None), service.calls
    service.quota = None
    cli = runtime.Recorder(url=service.url, quiet=True)  # `signafaide flush` in another process
    try:
        assert cli.flush()["left"] == 0
    finally:
        cli.close()
    before = len(service.calls)
    r = recorder.flush()
    assert (r["shipped"], r["left"], r["errors"]) == (0, 0, {})
    assert service.calls[before:] == [("GET", "/v1/project")]
    assert recorder._halted is None


def test_the_halt_probe_honours_the_flush_timeout(recorder, service):
    service.quota = 0
    recorder.flush_interval = 0.02
    for i in range(3):
        signafaide.note(f"n{i}", {})
    recorder._wake.set()
    assert _until(lambda: recorder._halted is not None), service.calls
    service.quota = None
    cli = runtime.Recorder(url=service.url, quiet=True)
    try:
        cli.flush()
    finally:
        cli.close()
    before = len(service.calls)
    recorder.flush(timeout=0.0)  # no time left for the probe
    assert service.calls[before:] == []
    assert recorder._halted is not None


def test_quota_exceeded_stops_sending_until_the_configuration_changes(recorder, service):
    service.quota = 0
    recorder.flush_interval = 0.02
    for i in range(5):
        signafaide.note(f"n{i}", {})
    recorder._wake.set()
    # The sender's first attempt is refused and it stops: wait for that, however long it takes.
    assert _until(lambda: recorder._halted is not None), service.calls
    # Then 30 rounds of the sender's loop (counted, not slept): a storm would send 30 requests.
    rounds = recorder._ticks
    assert _until(lambda: recorder._ticks >= rounds + 30), recorder._ticks
    assert record_calls(service) == 1, service.calls
    assert recorder.flush()["errors"]  # an explicit flush still tries, and the halt stays
    assert recorder._halted is not None
    rounds = recorder._ticks
    assert _until(lambda: recorder._ticks >= rounds + 5), recorder._ticks
    assert record_calls(service) == 2, service.calls
    service.quota = None
    os.utime(recorder.state.key_dir(""), (time.time(), time.time() + 5))  # the configuration changed
    assert _until(lambda: recorder.state.outbox_size() == 0), service.calls


def test_close_holds_the_process_at_most_the_exit_limit(recorder, service):
    signafaide.note("n", {})
    service.hang = 5.0
    recorder.exit_flush = 0.5
    t0 = time.monotonic()
    recorder.close()
    assert time.monotonic() - t0 < 1.5
    service.hang = 0


# --- BLOCKED chains and repair -----------------------------------------------------------------


def test_revoked_key_blocked_then_repaired(recorder, service, capsys):
    signafaide.note("a", {})
    signafaide.flush()
    prj = next(iter(service.projects.values()))
    key = next(iter(prj["agents"]["claims-project"].values()))
    from signafaide.records import now as _now

    key["valid_to"] = _now()  # revoked in the console
    signafaide.note("b", {})
    signafaide.note("c", {})
    (e,) = recorder.flush()["errors"].values()
    assert (
        "was revoked" in str(e) and "keys rotate" not in str(e) and "signafaide repair --agent claims-project" in str(e)
    )
    assert main(["status"]) == 1
    out = capsys.readouterr().out
    assert "BLOCKED" in out and "revoked" in out
    assert main(["verify"]) == 1
    assert main(["keys", "rotate"]) == 0
    signafaide.note("d", {})
    (e2,) = recorder.flush()["errors"].values()
    assert "after it was revoked or retired cannot be co-signed" in str(e2)
    capsys.readouterr()
    assert main(["repair"]) == 0
    assert "set aside 3 records" in capsys.readouterr().out
    r = recorder.flush()
    assert r["errors"] == {} and r["left"] == 0
    rep = signafaide.verify()
    assert rep.ok, str(rep)
    assert any("held aside by `signafaide repair`: 3 records in 1 segment" in x for x in rep.after)
    assert recorder.state.blocked() == {}
    last = records(recorder)[-1]
    assert last["envelope"]["name"] == "signafaide.repair" and last["content"]["records"] == 3


def test_clock_ahead_on_first_run(recorder, service, capsys):
    st = recorder.state
    st.load_key("claims-project")
    doc = json.loads(st.key_path("claims-project").read_text())
    doc["created"] = iso(datetime.now(timezone.utc) + timedelta(hours=1))  # made while the clock was an hour ahead
    st.key_path("claims-project").write_text(json.dumps(doc))
    signafaide.note("a", {})
    (e,) = recorder.flush()["errors"].values()
    assert ("POST", "/v1/agents") in service.calls  # registration was not refused
    assert (
        "ahead of the service clock" in str(e)
        and "This machine's clock is ahead" in str(e)
        and "signafaide repair" in str(e)
    )
    assert [b["code"] for b in recorder.diagnose()] == ["clock_ahead"]
    assert main(["repair"]) == 0
    assert recorder.flush()["errors"] == {}
    assert signafaide.verify().ok


# --- keys --------------------------------------------------------------------------------------


def test_agent_key_from_the_environment(local_recorder, project, monkeypatch):
    other = State(project / "elsewhere", project)
    k = other.load_key("env.bot-1")
    assert agent_key_env_name("env.bot-1") == "SIGNAFAIDE_AGENT_KEY_ENV_BOT_1"
    monkeypatch.setenv("SIGNAFAIDE_AGENT_KEY_ENV_BOT_1", other.key_path("env.bot-1").read_text())
    signafaide.note("n", {}, agent="env.bot-1")
    assert records(local_recorder, "env.bot-1")[0]["key_id"] == k.key_id
    assert not local_recorder.state.key_path("env.bot-1").exists()
    assert k.key_id in [e["key_id"] for e in local_recorder.state.export_agent_keys()["keys"]]
    with pytest.raises(StateError, match="comes from SIGNAFAIDE_AGENT_KEY_ENV_BOT_1"):
        local_recorder.state.rotate_key("env.bot-1")


def test_live_chains_have_their_own_key(local_recorder):
    st = local_recorder.state
    test_key = st.load_key("bot")
    live = st.load_key("bot", scope="live")
    assert live.key_id != test_key.key_id and (st.home / "agents" / "live" / "bot.key").exists()
    assert sorted(e["key_id"] for e in st.export_agent_keys()["keys"]) == sorted([test_key.key_id, live.key_id])


def test_ephemeral_disk_continues_the_witness_chain(recorder, service, project, monkeypatch):
    st = recorder.state
    st.load_key("worker-0")
    monkeypatch.setenv("SIGNAFAIDE_AGENT_KEY_WORKER_0", st.key_path("worker-0").read_text())
    signafaide.note("a", {}, agent="worker-0")
    signafaide.note("b", {}, agent="worker-0")
    signafaide.flush()
    shutil.rmtree(st.home)  # the disk is gone; the API key stays in .env
    rec = runtime.configure(quiet=True, flush_interval=3600)
    assert rec.state.bucket(rec.api_key).startswith("_pending/")
    signafaide.note("c", {}, agent="worker-0")
    assert rec.flush()["errors"] == {}
    prj = next(iter(service.projects.values()))
    assert prj["heads"]["worker-0"]["head"]["seq"] == 4  # seq 3 is the instance-start note
    rec._stopped = True


def test_segments_roll_and_keep_chaining(recorder, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_SEGMENT_BYTES", "4000")
    for i in range(12):
        signafaide.note(f"n{i}", {"i": i})
    signafaide.flush()
    chain = chain_of(recorder)
    assert recorder.state.segments(chain)
    assert recorder.state.tail(chain)[0] == 12
    for i in range(12):
        signafaide.note(f"m{i}", {"i": i})
    assert signafaide.flush()["errors"] == {}
    assert [r["envelope"]["seq"] for r in recorder.state.read_all(chain)] == list(range(1, 25))
    assert signafaide.verify().ok


# --- modes, folders, status ---------------------------------------------------------------------


def test_disabled_runs_the_function_and_writes_nothing(local_recorder, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_DISABLED", "1")
    assert signafaide.record(lambda x: x * 2, name="double")(21) == 42
    assert signafaide.note("n", {}) == ""
    assert local_recorder.state.chains() == []


def test_test_mode_under_pytest(project, monkeypatch):
    monkeypatch.delenv("SIGNAFAIDE_TEST", raising=False)
    assert runtime.test_mode()  # PYTEST_CURRENT_TEST is set
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", "sfa_test_" + "a" * 32)
    rec = runtime.configure(quiet=True)
    assert rec.test and rec.api_key is None
    rec.write("note", "n", {})
    assert not (project / ".signafaide").exists()
    monkeypatch.setenv("SIGNAFAIDE_TEST", "0")
    assert not runtime.test_mode()
    rec._stopped = True


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anywhere")
def test_read_only_folder_says_what_to_do(project, monkeypatch):
    ro = project / "ro"
    ro.mkdir()
    ro.chmod(0o555)
    try:
        rec = runtime.configure(quiet=True, home=str(ro / ".signafaide"))
        with pytest.raises(
            StateError, match=r"cannot write signafAIde's local state in .*\(permission denied\)\. Set SIGNAFAIDE_HOME"
        ):
            rec.write("note", "n", {})
        rec._stopped = True
    finally:
        ro.chmod(0o755)


def test_used_claim_link_is_hidden(recorder, service, capsys):
    main(["status"])
    assert "claim: http" in capsys.readouterr().out
    next(iter(service.projects.values()))["claimed"] = True
    main(["status"])
    out = capsys.readouterr().out
    assert "claim: done" in out and "claim: http" not in out


def test_gitignore_only_at_set_up(recorder, project):
    gi = project / ".gitignore"
    gi.write_text("node_modules\n")
    signafaide.note("a", {})
    signafaide.flush()
    assert gi.read_text() == "node_modules\n"
    assert main(["init"]) == 0
    assert ".signafaide/" in gi.read_text()


def test_default_witness_is_the_hosted_service():
    assert DEFAULT_URL == "https://api.signafaide.co.uk"
    host = DEFAULT_URL.split("://")[1].split("/")[0]
    assert host != "localhost" and not host.startswith("127.")
