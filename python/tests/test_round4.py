"""Fix round 4: an empty home with a known project continues the witness chain (#11), no head is
seq 1 (#12), the local verify of a short-lived instance (#13), one word for pending (#16), the
revoked-key and BLOCKED wording (#19), LangChain tool-call values (#20), and housekeeping (#22)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

import signafaide
from signafaide import runtime
from signafaide.cli import main
from signafaide.state import key_fingerprint, lock_age, lock_stamp

from fake_service import err
from helpers import chain_of


def fresh_home(monkeypatch, key_doc: dict) -> runtime.Recorder:
    """A new instance on an empty disk: the key from a provider, the project learned at init()."""
    rec = signafaide.init(quiet=True, key_provider=lambda agent, scope: key_doc)
    rec.flush_interval = 3600
    return rec


def test_empty_home_with_known_project_continues_the_witness_chain(recorder, service, project, monkeypatch):
    st = recorder.state
    st.load_key("lambda-bot")
    doc = json.loads(st.key_path("lambda-bot").read_text())
    for i in range(2):
        signafaide.note(f"a{i}", {"i": i}, agent="lambda-bot")
    assert signafaide.flush()["errors"] == {}
    shutil.rmtree(st.home)  # a cold start: the API key stays in .env, the disk is empty
    rec = fresh_home(monkeypatch, doc)
    bucket = rec.state.bucket(rec.api_key)
    assert not bucket.startswith("_pending/"), "init() learned the project"
    r = rec.write("note", "b", {}, agent="lambda-bot")
    assert r.get("draft") is True, "no chain on this disk: a draft until the witness's head is known"
    assert rec.flush()["errors"] == {}
    prj = next(iter(service.projects.values()))
    assert prj["heads"]["lambda-bot"]["head"]["seq"] == 3
    chain = f"{bucket}/lambda-bot"
    assert [x["envelope"]["seq"] for x in rec.state.read_all(chain)] == [3]
    assert rec.state.chain_base(chain)["head"]["seq"] == 2
    # #13: the local verify passes and says where the chain starts.
    v = signafaide.verify()
    assert v.ok, str(v)
    assert "continues after a co-signed record this machine does not hold" in v.check("chain").detail
    assert f"{chain} after seq 2" in v.check("chain").detail
    # Without the base the same chain fails check 4: the base is what makes it pass.
    rec.state._base_path(chain).unlink()
    assert not signafaide.verify().ok
    rec._stopped = True


def test_new_agent_with_no_head_starts_at_one_after_init(local_recorder, service, project, monkeypatch, capsys):
    """#12: records written before `signafaide init`, then `signafaide flush`. An older witness
    answers `unknown_agent` (400) for an agent with no head; both answers mean seq 1."""
    signafaide.note("before init", {}, agent="new-bot")
    service.heads_unknown_agent = True
    assert main(["init"]) == 0
    assert main(["flush"]) == 0, capsys.readouterr()
    prj = next(iter(service.projects.values()))
    assert prj["heads"]["new-bot"]["head"]["seq"] == 1


def test_local_pending_and_not_checked_by_age(recorder, service, monkeypatch):
    """#16: a co-signed batch younger than the anchor window is PENDING locally, as in a pack."""
    signafaide.note("n", {})
    signafaide.flush()
    v = signafaide.verify()
    assert (v.check("anchor").status, v.check("ots").status) == ("pending", "pending")
    assert "pending: co-signed, waiting for the public timestamp" in str(v)
    # Two hours later the local state still holds no anchor: not checked here, verify an export.
    real = time.time
    monkeypatch.setattr("signafaide.verifier.time.time", lambda: real() + 3 * 3600)
    v = signafaide.verify()
    assert v.check("anchor").status == "not_checked"
    assert "verify an export" in v.check("anchor").detail


def test_revoked_key_message_says_repair_only(recorder, service, monkeypatch):
    """#19: the message names `signafaide repair` alone, and the BLOCKED line has no '..' or '.;'."""
    signafaide.note("a", {})
    signafaide.flush()
    service.fail_always = err(400, "bad_signature", "agent key was revoked at 2026-11-14T10:00:00.000Z; records it signs are refused.")
    signafaide.note("b", {})
    e = next(iter(signafaide.flush()["errors"].values()))
    assert "signafaide repair --agent claims-project" in str(e)
    assert "keys rotate" not in str(e)
    (b,) = recorder.diagnose()
    line = f"BLOCKED {b['chain']}: {b['reason']}; 1 record cannot ship. Next: {b['next']}"
    assert ".." not in line and ".;" not in line, line


def test_clock_ahead_says_wait(recorder, service, monkeypatch):
    signafaide.note("a", {})
    signafaide.flush()
    service.fail_always = err(400, "invalid_record", "records[0]: time is 900 s ahead of the service clock.")
    signafaide.note("b", {})
    signafaide.flush()
    (b,) = recorder.diagnose()
    assert "wait until it catches up" in b["next"]


def test_langchain_tool_call_stores_the_return_value(local_recorder):
    """#20: invoked with a tool call, the outcome is the tool's value, not its JSON text."""
    lc = pytest.importorskip("langchain_core.tools")

    @lc.tool
    def send_email(to: str) -> dict:
        """Send an email."""
        return {"message_id": "m-1", "to": to}

    t = signafaide.wrap_tools([send_email], agent="mailer")[0]
    t.invoke({"name": "send_email", "args": {"to": "a@example.com"}, "id": "call_1", "type": "tool_call"})
    t.invoke({"to": "b@example.com"})
    outs = [r["content"]["output"] for r in local_recorder.state.read_all(chain_of(local_recorder, "mailer")) if r["envelope"]["kind"] == "outcome"]
    assert outs == [{"message_id": "m-1", "to": "a@example.com"}, {"message_id": "m-1", "to": "b@example.com"}]


def test_home_gitignore_lock_clock_and_test_folders(local_recorder, project, tmp_path):
    """#22: .signafaide/.gitignore holds '*'; locks age by the monotonic clock; test-mode
    folders are removed when the process ends."""
    signafaide.note("n", {})
    assert (local_recorder.state.home / ".gitignore").read_text() == "*\n"
    p = tmp_path / "x.lock"
    p.write_text(lock_stamp())
    os.utime(p, (time.time() - 3600, time.time() - 3600))  # a wall clock an hour off
    if Path("/proc/sys/kernel/random/boot_id").exists():
        assert lock_age(p) < 5, "monotonic, not the file time"
    p.write_text("12345")  # an older SDK's lock: the file time
    os.utime(p, (time.time() - 3600, time.time() - 3600))
    assert lock_age(p) > 3000
    code = "import signafaide, sys; r = signafaide.init(quiet=True); print(r.state.home); signafaide.note('n', {})"
    env = {k: v for k, v in os.environ.items() if not k.startswith("SIGNAFAIDE_")} | {"SIGNAFAIDE_TEST": "1"}
    home = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True).stdout.strip()
    assert "signafaide-test-" in home and not Path(home).exists()


def test_exit_timeout_names_the_real_limit(recorder, service, monkeypatch):
    signafaide.note("n", {})
    service.hang = 2.0
    recorder.exit_flush = 0.3
    t0 = time.monotonic()
    recorder._deadline = time.monotonic() + 0.3
    recorder._deadline_limit = 0.3
    try:
        r = recorder.flush(10, background=True)
    finally:
        recorder._deadline = None
        service.hang = 0
    assert time.monotonic() - t0 < 2
    msg = " ".join(str(e) for e in r["errors"].values())
    assert "no answer within the 0.3 s allowed at exit (SIGNAFAIDE_EXIT_FLUSH_MS)" in msg, msg


def test_replay_picks_the_only_agent(local_recorder, capsys):
    signafaide.note("n", {}, agent="only-bot")
    assert local_recorder.only_agent() == "only-bot"
    assert main(["replay", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["agent"] == "only-bot"


def test_status_shows_the_project_name(recorder, service, capsys):
    next(iter(service.projects.values()))["name"] = "Claims automation"
    signafaide.note("n", {})
    main(["status"])
    assert "1 record waiting" in capsys.readouterr().out, "a draft waiting for the witness's head counts as waiting"
    signafaide.flush()
    main(["status"])
    out = capsys.readouterr().out
    assert "project: Claims automation (prj_" in out
    assert "chain Claims automation/test/claims-project" in out, out


def test_upgrade_lines_never_in_json(recorder, service, project, monkeypatch, capsys):
    """Upgrade prompts: one plain line after a passing verify on a live Free key (once a week),
    and when a live key hits the limit; never in --json output."""
    live = "sfa_live_" + "1" * 32
    prj = service.add_project(live, env="live")
    prj["plan"] = "free"
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", live)
    rec = runtime.configure(quiet=True, flush_interval=3600)
    signafaide.note("n", {})
    rec.flush()
    capsys.readouterr()
    assert main(["verify", "--json"]) == 0
    assert "upgrade:" not in capsys.readouterr().out
    assert main(["verify"]) == 0
    assert capsys.readouterr().out.count("upgrade: Solo ($19 a month)") == 1
    assert main(["verify"]) == 0
    assert "upgrade:" not in capsys.readouterr().out, "at most once a week"
    service.fail_always = err(429, "quota_exceeded", "This request needs 1 record but only 0 of the 25000 monthly records are left.")
    signafaide.note("m", {})
    main(["flush"])
    assert capsys.readouterr().out.count("upgrade: Solo ($19 a month) takes 100,000 live records a month") == 1
    rec._stopped = True
