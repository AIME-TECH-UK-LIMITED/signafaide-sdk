"""Tool declarations (SPEC §2.6): ``wrap_tools`` declares what it wraps, ``declare_tools`` the
agent's full list."""

import atexit
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

import signafaide
from signafaide import runtime
from signafaide.coverage import tool_note, tool_note_name
from signafaide.records import record_hash
from signafaide.verifier import loads, verify_local, verify_pack


def end(rec):
    """Stop a recorder a test made itself (its shipper thread and exit hook)."""
    rec._stopped = True
    rec._wake.set()
    rec._tool_stop.set()
    atexit.unregister(rec.close)


def chain(rec, agent="claims-project"):
    return [r for c in rec.state.chains() if c.rsplit("/", 1)[1] == agent for r in rec.state.read_all(c)]


def names(rec, agent="claims-project"):
    return [f"{r['envelope']['kind']}:{r['envelope']['name']}" for r in chain(rec, agent)]


def coverage(rec):
    return [line.replace("_pending/nokey/", "", 1) for line in verify_local(rec.state, []).coverage_lines()]


# --- wrap_tools declares the tools it wraps ----------------------------------------------


def test_wrap_tools_declares_with_the_first_call(local_recorder):
    tools = signafaide.wrap_tools({"refund": lambda order: order, "lookup": lambda order: order}, agent="support-bot")
    assert local_recorder.state.chains() == []  # wrapping writes nothing
    tools["refund"]("o1")
    assert names(local_recorder, "support-bot") == ["note:signafaide.tools", "note:signafaide.tool/lookup", "note:signafaide.tool/refund", "decision:refund", "outcome:refund"]
    header, first, second, decision = chain(local_recorder, "support-bot")[:4]
    assert header["content"] == {"source": "wrap_tools", "tools": 2, "recorded": 2, "unrecorded": 0}
    assert first["content"] == {"tool": "lookup", "recorded": True}
    assert [r["envelope"]["seq"] for r in (header, first, second, decision)] == [1, 2, 3, 4]
    assert second["envelope"]["prev"] == record_hash(first)
    # Once per process for the same list.
    tools["lookup"]("o2")
    tools["refund"]("o3")
    assert names(local_recorder, "support-bot").count("note:signafaide.tools") == 1
    assert coverage(local_recorder) == ["support-bot: all 2 declared tools are recorded"]


def test_declares_again_when_the_list_grows_and_per_agent(local_recorder):
    def two():
        return 2

    a = signafaide.wrap_tools({"one": lambda: 1}, agent="bot-a")
    a["one"]()
    more = signafaide.wrap_tools([two], agent="bot-a")
    b = signafaide.wrap_tools({"other": lambda: 1}, agent="bot-b")
    more[0]()
    b["other"]()
    assert names(local_recorder, "bot-a") == [
        "note:signafaide.tools", "note:signafaide.tool/one", "decision:one", "outcome:one",
        "note:signafaide.tools", "note:signafaide.tool/one", "note:signafaide.tool/two", "decision:two", "outcome:two",
    ]
    assert names(local_recorder, "bot-b") == ["note:signafaide.tools", "note:signafaide.tool/other", "decision:other", "outcome:other"]


def test_a_new_recorder_declares_again(local_recorder, service):
    tools = signafaide.wrap_tools({"one": lambda: 1})
    tools["one"]()
    again = runtime.configure(quiet=True, flush_interval=3600)  # a new process instance
    try:
        tools["one"]()
        assert names(again).count("note:signafaide.tools") == 2
    finally:
        end(again)


def test_can_be_turned_off(local_recorder, monkeypatch):
    signafaide.wrap_tools({"quiet": lambda: 1}, declare_tools=False)["quiet"]()
    signafaide.wrap_tool(lambda: 2, name="single", declare_tools=False)()
    assert names(local_recorder) == ["decision:quiet", "outcome:quiet", "decision:single", "outcome:single"]
    monkeypatch.setenv("SIGNAFAIDE_DECLARE_TOOLS", "0")
    assert signafaide.auto_declare_tools() is False
    signafaide.wrap_tools({"loud": lambda: 1})["loud"]()
    assert names(local_recorder)[4:] == ["decision:loud", "outcome:loud"]
    monkeypatch.delenv("SIGNAFAIDE_DECLARE_TOOLS")
    assert signafaide.auto_declare_tools() is True


def test_record_alone_declares_nothing(local_recorder):
    signafaide.record(lambda: 1, name="approve")()
    assert names(local_recorder) == ["decision:approve", "outcome:approve"]
    assert coverage(local_recorder) == ["claims-project: no tool list was declared, so the pack cannot show which of the agent's tools are recorded"]


def test_a_failed_declaration_never_fails_the_tool_call(local_recorder, capsys):
    tools = signafaide.wrap_tools({"bad\x01name": lambda: "ran"})
    assert tools["bad\x01name"]() == "ran"
    assert tools["bad\x01name"]() == "ran"
    err = capsys.readouterr().err
    assert err.count("signafaide: could not write the tool declaration for claims-project: a tool name must be a non-empty string without control characters") == 1
    assert names(local_recorder) == ["decision:bad\x01name", "outcome:bad\x01name"] * 2


def test_langchain_and_openai_agents_tools_are_declared_by_their_names(local_recorder):
    lc = pytest.importorskip("langchain_core.tools")
    agents = pytest.importorskip("agents")

    @lc.tool
    def get_weather(city: str) -> str:
        """Weather for a city."""
        return f"sunny in {city}"

    @agents.function_tool
    def lookup_order(order_id: str) -> str:
        """Look an order up."""
        return f"order {order_id}"

    wrapped = signafaide.wrap_tools([get_weather, lookup_order], agent="support-bot")
    assert wrapped[0].invoke({"city": "Paris"}) == "sunny in Paris"
    assert names(local_recorder, "support-bot")[:3] == ["note:signafaide.tools", "note:signafaide.tool/get_weather", "note:signafaide.tool/lookup_order"]
    assert coverage(local_recorder) == ["support-bot: all 2 declared tools are recorded"]


# --- declare_tools: the agent's full tool list ------------------------------------------


def test_declare_tools_recorded_when_wrapped_here(local_recorder):
    tools = signafaide.wrap_tools({"refund": lambda: 1}, agent="support-bot")
    signafaide.record(lambda: 1, name="lookup", agent="support-bot")
    h = signafaide.declare_tools(["refund", "lookup", "send_email", "delete_account"], agent="support-bot")
    assert names(local_recorder, "support-bot") == [
        "note:signafaide.tools",
        "note:signafaide.tool_unrecorded/delete_account",
        "note:signafaide.tool/lookup",
        "note:signafaide.tool/refund",
        "note:signafaide.tool_unrecorded/send_email",
    ]
    header, first = chain(local_recorder, "support-bot")[:2]
    assert h == record_hash(header)
    assert header["content"] == {"source": "declared", "tools": 4, "recorded": 2, "unrecorded": 2}
    assert first["content"] == {"tool": "delete_account", "recorded": False}
    assert coverage(local_recorder) == ["support-bot: 2 declared tools are not recorded: delete_account, send_email"]
    # The same list again writes nothing; calls write no second declaration (the list given wins over wrap_tools' own).
    assert signafaide.declare_tools(["refund", "lookup", "send_email", "delete_account"], agent="support-bot") == h
    tools["refund"]()
    assert names(local_recorder, "support-bot").count("note:signafaide.tools") == 1


def test_declare_tools_unrecorded(local_recorder):
    signafaide.wrap_tools({"search": lambda: 1})
    signafaide.declare_tools(["search"], unrecorded=["search", "browser"])
    assert names(local_recorder) == ["note:signafaide.tools", "note:signafaide.tool_unrecorded/browser", "note:signafaide.tool_unrecorded/search"]
    assert coverage(local_recorder) == ["claims-project: 2 declared tools are not recorded: browser, search"]


def test_a_tool_wrapped_later_is_declared_again_as_recorded(local_recorder):
    signafaide.declare_tools(["refund", "lookup"])
    assert names(local_recorder) == ["note:signafaide.tools", "note:signafaide.tool_unrecorded/lookup", "note:signafaide.tool_unrecorded/refund"]
    tools = signafaide.wrap_tools({"refund": lambda: 1, "extra": lambda: 2})
    tools["refund"]()
    tools["extra"]()
    assert names(local_recorder)[3:] == [
        "note:signafaide.tools", "note:signafaide.tool_unrecorded/lookup", "note:signafaide.tool/refund",
        "decision:refund", "outcome:refund", "decision:extra", "outcome:extra",
    ]
    assert coverage(local_recorder) == ["claims-project: 1 declared tool is not recorded: lookup", "claims-project: 1 recorded tool is not in the declared tool list: extra"]


def test_declare_tools_names(local_recorder):
    with pytest.raises(TypeError, match="non-empty strings"):
        signafaide.declare_tools(["ok", ""])
    with pytest.raises(TypeError, match="non-empty strings"):
        signafaide.declare_tools([3])
    long = "report_" + "quarterly_figures_" * 8
    signafaide.wrap_tools({long: lambda: 1})
    signafaide.declare_tools([long, "short"])
    assert names(local_recorder) == ["note:signafaide.tools", f"note:{tool_note_name(long, True)}", "note:signafaide.tool_unrecorded/short"]
    assert len(tool_note_name(long, True)) == 117
    assert chain(local_recorder)[1]["content"] == {"tool": long, "recorded": True}


def test_disabled_writes_nothing(local_recorder, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_DISABLED", "1")
    assert signafaide.declare_tools(["a"]) == ""
    signafaide.wrap_tools({"a": lambda: 1})["a"]()
    assert local_recorder.state.chains() == []


def test_test_mode_keeps_declarations_in_the_temporary_folder(project, service, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_TEST", "1")
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    rec = runtime.configure(quiet=True, flush_interval=3600)
    try:
        assert rec.test is True
        signafaide.wrap_tools({"a": lambda: 1})["a"]()
        assert rec.state.home != project / ".signafaide"
        assert [r["envelope"]["name"] for r in rec.state.read_all("_pending/nokey/claims-project")] == ["signafaide.tools", "signafaide.tool/a", "a", "a"]
        assert rec.flush()["shipped"] == 0
        assert not (project / ".signafaide").exists() and service.calls == []
    finally:
        end(rec)
        runtime._default = None


# --- declarations in the chain -----------------------------------------------------------


def test_local_first_then_shipped_and_the_pack_shows_the_coverage(local_recorder, service):
    tools = signafaide.wrap_tools({"refund": lambda: 1, "lookup": lambda: 2}, agent="support-bot")
    signafaide.declare_tools(["refund", "lookup", "send_email"], agent="support-bot")
    tools["refund"]()
    assert service.calls == []
    assert all(r.get("draft") for r in chain(local_recorder, "support-bot"))
    local_recorder.create_sandbox()
    r = signafaide.flush()
    assert (r["shipped"], r["left"]) == (6, 0)  # the header and three tool notes count as records
    pack = loads(json.dumps(local_recorder.client().export("support-bot")))
    report = verify_pack(pack, [service.key_doc], agent_keys=local_recorder.state.export_agent_keys()["keys"])
    assert report.ok, str(report)
    assert report.coverage_lines() == ["support-bot: 1 declared tool is not recorded: send_email"]
    assert report.to_dict()["coverage"] == {
        "support-bot": {
            "declared": [{"name": "lookup", "recorded": True}, {"name": "refund", "recorded": True}, {"name": "send_email", "recorded": False}],
            "undeclared_recorded": [],
            "declared_at_seq": 1,
        }
    }
    assert all("content" not in x for x in pack["records"])  # hash-only: only the notes' envelopes left the machine


def test_several_sources_share_the_agents_tool_list(local_recorder):
    """The gateway (TypeScript) and this SDK keep one file per agent, in one format."""
    rec = local_recorder
    rec.declare_tools({"files.read": True, "files.write": True}, source="gateway:files.", origin="gateway")
    signafaide.wrap_tools({"refund": lambda: 1})
    signafaide.declare_tools(["refund", "files.read", "browser"])  # the application does not know the gateway records files.read
    last = chain(rec)[3:]
    assert [r["envelope"]["name"] for r in last] == ["signafaide.tools", "signafaide.tool_unrecorded/browser", "signafaide.tool/files.read", "signafaide.tool/files.write", "signafaide.tool/refund"]
    assert last[0]["content"] == {"source": "declared", "tools": 4, "recorded": 3, "unrecorded": 1}
    assert rec.state.tool_sources("claims-project") == {"gateway:files.": {"files.read": True, "files.write": True}, "sdk": {"refund": True, "files.read": False, "browser": False}}
    doc = json.loads(rec.state.tools_path("claims-project").read_text())
    assert set(doc) == {"sources"} and set(doc["sources"]["sdk"]) == {"at", "tools"} and doc["sources"]["sdk"]["at"].endswith("Z")
    again = runtime.Recorder(quiet=True)  # another process of one source declares again, and still lists the other's tools
    again.declare_tools({"files.read": True}, source="gateway:files.", origin="gateway")
    end(again)
    assert [r["envelope"]["name"] for r in chain(rec)[8:]] == ["signafaide.tools", "signafaide.tool_unrecorded/browser", "signafaide.tool/files.read", "signafaide.tool/refund"]
    assert coverage(rec) == ["claims-project: 1 declared tool is not recorded: browser"]


def test_a_declaration_is_one_uninterrupted_run(local_recorder, project):
    """Another process writes to the same chain while this one declares, again and again."""
    signafaide.note("first", {})  # the chain exists before both writers start
    code = "import signafaide\nfor i in range(300):\n    signafaide.note('other_writer', {'i': i})\n"
    env = {**os.environ, "SIGNAFAIDE_TEST": "0"}
    child = subprocess.Popen([sys.executable, "-c", code], cwd=project, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    tools = {f"tool_{i:02d}": True for i in range(25)}
    runs = 0
    while child.poll() is None and runs < 200:
        rec = runtime.Recorder(quiet=True)  # each one declares, as a new process would
        rec.declare_tools(tools, source="sdk", origin="declared")
        end(rec)
        runs += 1
        time.sleep(0.002)
    assert child.wait() == 0, child.stderr.read()
    everything = chain(local_recorder)
    assert sum(1 for r in everything if r["envelope"]["name"] == "other_writer") == 300
    headers = [i for i, r in enumerate(everything) if r["envelope"]["name"] == "signafaide.tools"]
    assert len(headers) == runs and runs > 3
    for i in headers:
        assert [r["envelope"]["name"] for r in everything[i + 1:i + 26]] == [f"signafaide.tool/{t}" for t in tools]
    first_other = next(i for i, r in enumerate(everything) if r["envelope"]["name"] == "other_writer")
    assert any(i > first_other for i in headers)  # both writers interleaved
    assert [r["envelope"]["seq"] for r in everything] == list(range(1, len(everything) + 1))
    assert sum(1 for r in everything if tool_note(r["envelope"]["kind"], r["envelope"]["name"])) == runs * 26
    assert verify_local(local_recorder.state, []).ok


# --- the agent's tool list stays fresh (SPEC §8) -------------------------------------------

HOUR = 3_600_000


def ago(ms):
    t = datetime.now(timezone.utc) - timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def leave(rec, sources):
    """Write tools/<agent>.json as other sources left it."""
    path = rec.state.tools_path("claims-project")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sources": sources}))


def entries(rec, agent="claims-project"):
    return json.loads(rec.state.tools_path(agent).read_text())["sources"]


def age_ms(at):
    return (datetime.now(timezone.utc) - datetime.strptime(at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)).total_seconds() * 1000


def test_the_two_durations():
    assert (signafaide.TOOL_SOURCE_REFRESH_MS, signafaide.TOOL_SOURCE_MAX_AGE_MS) == (HOUR, 24 * HOUR)


def test_a_declaration_drops_a_stale_source_and_keeps_a_fresh_one(local_recorder):
    live_at = ago(23 * HOUR)
    leave(local_recorder, {
        "gateway:gone": {"at": ago(25 * HOUR), "tools": {"gone.delete": True}},
        "gateway:live": {"at": live_at, "tools": {"live.read": True}},
        "gateway:broken": {"at": "not a time", "tools": {"broken.x": True}},
    })
    signafaide.wrap_tools({"refund": lambda: 1})["refund"]()
    assert names(local_recorder) == ["note:signafaide.tools", "note:signafaide.tool/live.read", "note:signafaide.tool/refund", "decision:refund", "outcome:refund"]
    got = entries(local_recorder)
    assert sorted(got) == ["gateway:live", "sdk"]
    assert got["gateway:live"]["at"] == live_at  # another source's time is not touched
    assert age_ms(got["sdk"]["at"]) < 60_000
    assert coverage(local_recorder) == ["claims-project: all 2 declared tools are recorded"]


def test_refresh_updates_the_time_and_a_stopped_source_drops_out_with_a_new_declaration(local_recorder):
    rec = local_recorder
    leave(rec, {"gateway:old": {"at": ago(2 * HOUR), "tools": {"old.delete": True}}})
    signafaide.wrap_tools({"refund": lambda: 1})["refund"]()
    assert names(rec)[:3] == ["note:signafaide.tools", "note:signafaide.tool/old.delete", "note:signafaide.tool/refund"]
    # Nothing changed: a refresh touches the file only.
    got = entries(rec)
    leave(rec, {**got, "sdk": {**got["sdk"], "at": ago(2 * HOUR)}})
    rec.refresh_tool_sources()
    assert age_ms(entries(rec)["sdk"]["at"]) < 60_000 and len(names(rec)) == 5
    # The gateway stopped without a clean exit: 25 hours later its entry is dropped at the next refresh.
    got = entries(rec)
    leave(rec, {**got, "gateway:old": {**got["gateway:old"], "at": ago(25 * HOUR)}})
    rec.refresh_tool_sources()
    assert sorted(entries(rec)) == ["sdk"]
    assert names(rec)[5:] == ["note:signafaide.tools", "note:signafaide.tool/refund"]
    assert chain(rec)[5]["content"] == {"source": "wrap_tools", "tools": 1, "recorded": 1, "unrecorded": 0}
    rec.refresh_tool_sources()  # and only once
    assert len(names(rec)) == 7
    assert coverage(rec) == ["claims-project: the 1 declared tool is recorded"]


def test_an_expired_source_whose_tools_are_still_declared_changes_nothing_in_the_chain(local_recorder):
    leave(local_recorder, {"gateway:old": {"at": ago(30 * HOUR), "tools": {"refund": True}}})
    signafaide.wrap_tools({"refund": lambda: 1})["refund"]()
    assert names(local_recorder) == ["note:signafaide.tools", "note:signafaide.tool/refund", "decision:refund", "outcome:refund"]
    leave(local_recorder, {**entries(local_recorder), "gateway:other": {"at": ago(30 * HOUR), "tools": {"refund": True}}})
    local_recorder.refresh_tool_sources()
    assert sorted(entries(local_recorder)) == ["sdk"] and len(names(local_recorder)) == 4


def test_a_clean_shutdown_removes_the_own_entry_and_writes_nothing(local_recorder):
    rec = local_recorder
    leave(rec, {"gateway:live": {"at": ago(HOUR), "tools": {"live.read": True}}})
    signafaide.declare_tools(["refund"], unrecorded=["refund"])
    assert sorted(entries(rec)) == ["gateway:live", "sdk"]
    assert rec._tool_thread is not None and rec._tool_thread.daemon  # the hourly refresh never keeps the program alive
    before = len(names(rec))
    rec.close(0)  # what the program's normal exit runs
    assert sorted(entries(rec)) == ["gateway:live"] and len(names(rec)) == before
    assert rec._tool_stop.is_set()
    rec.refresh_tool_sources()  # nothing left to refresh: the entry does not come back
    assert sorted(entries(rec)) == ["gateway:live"]


def test_a_program_that_ends_is_not_held_by_the_refresh_and_removes_its_entry(local_recorder, project):
    code = ("import signafaide\nfrom signafaide import runtime\nsignafaide.declare_tools(['b'], agent='child-bot')\n"
            "print(runtime.get().state.tools_path('child-bot').read_text())\n")
    p = subprocess.run([sys.executable, "-c", code], cwd=project, env={**os.environ, "SIGNAFAIDE_TEST": "0"}, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert sorted(json.loads(p.stdout)["sources"]) == ["sdk"]  # while it ran
    assert local_recorder.state.tool_sources("child-bot") == {}  # after its normal exit

