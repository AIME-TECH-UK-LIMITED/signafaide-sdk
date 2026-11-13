import asyncio
import dataclasses
import datetime
import json
import subprocess
import sys
import time

import pytest

import signafaide
from signafaide import runtime
from signafaide.crypto import content_hash, hash_json
from signafaide.records import make_draft, record_hash
from helpers import chain_of, chain_path, error_for, records


def chain(rec, agent="claims-project"):
    return records(rec, agent)


def test_sync_decision_then_outcome(recorder):
    @signafaide.record
    def approve_payout(claim_id: str, amount: float, note: str = "ok"):
        return {"approved": True, "amount": amount}

    assert approve_payout("c-1", 12.5) == {"approved": True, "amount": 12.5}
    d, o = chain(recorder)
    assert d["envelope"]["kind"] == "decision" and d["envelope"]["name"] == "approve_payout"
    assert d["envelope"]["agent"] == "claims-project"  # folder "Claims Project"
    assert d["content"]["input"] == {"claim_id": "c-1", "amount": 12.5, "note": "ok"}
    assert d["content"]["meta"]["sdk"].startswith("signafaide-python/")
    assert d["envelope"]["content_hash"] == content_hash(d["content"], d["salt"])
    assert o["envelope"]["kind"] == "outcome" and o["envelope"]["ref"] == record_hash(d)
    assert o["envelope"]["prev"] == record_hash(d)
    assert o["content"] == {"output": {"approved": True, "amount": 12.5}}


def test_named_agent_and_meta(recorder):
    @signafaide.record(agent="claims-bot", name="approve_payout", meta={"model": "m1"})
    def approve(x):
        return x

    approve(1)
    d, _ = chain(recorder, "claims-bot")
    assert d["envelope"]["name"] == "approve_payout"
    assert d["content"]["meta"]["model"] == "m1"


def test_errors_are_recorded_and_reraised_unchanged(recorder):
    class Boom(RuntimeError):
        pass

    @signafaide.record
    def fail():
        raise Boom("no funds")

    with pytest.raises(Boom, match="no funds"):
        fail()
    _, o = chain(recorder)
    assert o["content"] == {"error": {"type": "Boom", "message": "no funds"}}


def test_async_functions(recorder):
    @signafaide.record(name="lookup")
    async def lookup(q):
        await asyncio.sleep(0)
        return [q]

    @signafaide.record
    async def broken():
        raise ValueError("bad")

    async def main():
        assert await lookup("a") == ["a"]
        with pytest.raises(ValueError):
            await broken()

    asyncio.run(main())
    kinds = [(r["envelope"]["kind"], r["envelope"]["name"]) for r in chain(recorder)]
    assert kinds == [("decision", "lookup"), ("outcome", "lookup"), ("decision", "broken"), ("outcome", "broken")]
    assert chain(recorder)[3]["content"]["error"]["type"] == "ValueError"


def test_methods_drop_self_and_values_become_json(recorder):
    @dataclasses.dataclass
    class Claim:
        id: str
        when: datetime.date

    class Desk:
        @signafaide.record
        def decide(self, claim, tags=frozenset({"b", "a"}), **extra):
            return claim

    Desk().decide(Claim("c1", datetime.date(2026, 1, 2)), flag=b"\x00")
    d, o = chain(recorder)
    assert d["content"]["input"] == {"claim": {"id": "c1", "when": "2026-01-02"}, "tags": ["a", "b"], "flag": "AA=="}
    assert o["content"]["output"] == {"id": "c1", "when": "2026-01-02"}


def test_note(recorder):
    h = signafaide.note("policy_loaded", {"version": 3})
    (r,) = chain(recorder)
    assert record_hash(r) == h and r["envelope"]["kind"] == "note" and r["envelope"]["ref"] is None


def test_flush_ships_and_stores_receipts(recorder, service):
    signafaide.record(lambda x: x * 2, name="double")(2)
    assert recorder.state.outbox_size() == 2
    r = signafaide.flush()
    assert r == {"shipped": 2, "left": 0, "errors": {}}
    assert all("receipt" in x for x in chain(recorder))
    (sh,) = recorder.state.chain_heads().values()
    assert sh["head"]["seq"] == 2
    assert recorder.api_key.startswith("sfa_test_")  # the sandbox `signafaide init` made
    assert ("POST", "/v1/agents") in service.calls


def test_no_key_records_locally_and_sends_nothing(local_recorder, service, project, capsys):
    local_recorder.quiet = False
    signafaide.record(lambda x: x * 2, name="double")(2)
    signafaide.note("n", {})
    assert signafaide.flush() == {"shipped": 0, "left": 3, "errors": {}}
    assert service.calls == []  # no request at all, no sandbox
    assert not (project / ".env").exists() and local_recorder.state.sandbox() is None
    recs = chain(local_recorder)
    assert [r.get("draft") for r in recs] == [True, True, True]
    assert all(len(r["key_id"]) == 16 and r["sig"] for r in recs)  # signed locally (domain draft)
    assert capsys.readouterr().err.count("recording locally") == 1
    report = signafaide.verify()
    assert service.calls == []
    assert report.ok
    assert report.check("record_sig").checked == 3 and report.check("chain").checked == 3 and report.check("content").checked == 3
    assert report.check("merkle").status == "not_checked"
    assert "co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host" in str(report)


def test_local_verify_fails_an_edited_or_resigned_draft(local_recorder):
    signafaide.note("a", {"v": 1})
    signafaide.note("b", {"v": 2})
    p = chain_path(local_recorder)
    lines = p.read_text().splitlines()
    p.write_text(lines[0].replace('"v":1', '"v":9', 1) + "\n" + lines[1] + "\n")
    assert signafaide.verify().check("content").status == "fail"
    forged = json.loads(lines[1])
    forged["envelope"]["name"] = "other"
    p.write_text(lines[0] + "\n" + json.dumps(forged) + "\n")
    r = signafaide.verify()
    assert r.check("record_sig").status == "fail" and r.check("chain").status == "pass"


def test_records_before_the_opt_in_ship_with_their_times(local_recorder, service):
    signafaide.record(lambda x: x * 2, name="double")(2)
    times = [r["envelope"]["time"] for r in chain(local_recorder)]
    time.sleep(0.02)
    local_recorder.create_sandbox()
    assert signafaide.flush() == {"shipped": 2, "left": 0, "errors": {}}
    assert [r["envelope"]["time"] for r in chain(local_recorder)] == times
    assert all("receipt" in r for r in chain(local_recorder))


def test_too_old_local_records_stay_local_with_a_clear_error(local_recorder):
    key = local_recorder.key("claims-project")
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    local_recorder.state.append("_pending/nokey/claims-project",
                                lambda seq, prev: make_draft(key, kind="note", agent="claims-project", seq=seq, prev=prev, name="old", content={}, time=old),
                                lambda r: r)
    local_recorder.create_sandbox()
    e = error_for(signafaide.flush())
    assert e.code == "too_old"
    assert "more than 7 days ago" in str(e) and "stays local" in str(e) and "signafaide verify" in str(e)
    assert local_recorder.state.chains() == ["_pending/nokey/claims-project"]
    assert signafaide.verify().ok


def test_strict_without_a_key_refuses_and_sends_nothing(local_recorder, service):
    ran = []

    @signafaide.record(strict=True)
    def pay():
        ran.append(1)

    with pytest.raises(signafaide.NotRecorded, match="no API key"):
        pay()
    assert ran == [] and service.calls == []


def test_hash_only_by_default_and_store_content(recorder, service):
    f = signafaide.record(lambda: 1, name="a")
    g = signafaide.record(lambda: 2, name="b", store_content=True)
    f()
    g()
    signafaide.flush()
    prj = next(iter(service.projects.values()))
    stored = {r["envelope"]["name"]: "content" in r for r, _ in prj["records"].values()}
    assert stored == {"a": False, "b": True}
    assert all("content" in x for x in chain(recorder))  # the local chain always keeps it


def test_background_shipping(project, service, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    rec = runtime.configure(quiet=True, flush_interval=0.05)
    try:
        signafaide.record(lambda: None, name="tick")()
        deadline = time.time() + 5
        while rec.state.outbox_size() and time.time() < deadline:
            time.sleep(0.02)
        assert rec.state.outbox_size() == 0
    finally:
        rec._stopped = True
        rec._wake.set()


def test_offline_keeps_outbox_then_recovers(recorder, service, dead_url):
    recorder._url = dead_url
    f = signafaide.record(lambda: "ok", name="act")
    assert f() == "ok"  # never blocked by the network
    r = signafaide.flush()
    assert r["shipped"] == 0 and r["left"] == 2 and error_for(r).code == "network"
    recorder._url = service.url
    assert signafaide.flush()["shipped"] == 2


def test_strict_waits_for_receipt(recorder, service):
    ran = []

    @signafaide.record(strict=True)
    def pay():
        ran.append(len(service.projects) and next(iter(service.projects.values()))["used"])
        return "paid"

    assert pay() == "paid"
    assert ran == [1]  # the decision was accepted before the body ran


def test_strict_refuses_to_run_when_unrecorded(recorder, dead_url):
    recorder._api_key = "sfa_test_" + "x" * 32
    recorder._url = dead_url
    ran = []

    @signafaide.record(strict=True)
    def pay():
        ran.append(1)

    with pytest.raises(signafaide.NotRecorded, match="did not run"):
        pay()
    assert ran == []


def test_strict_async(recorder, dead_url):
    @signafaide.record(strict=True)
    async def pay():
        return 1

    assert asyncio.run(pay()) == 1
    recorder._url = dead_url
    with pytest.raises(signafaide.NotRecorded):
        asyncio.run(pay())


def test_chain_conflict_is_reported_not_rewritten(recorder, service):
    signafaide.note("a", {})
    signafaide.flush()
    service.fail = (409, {"error": {"code": "chain_conflict", "message": "Chain conflict, head attached.", "docs": "d", "head": {"agent": "claims-project", "seq": 7, "record_hash": "ab" * 32}}})
    signafaide.note("b", {})
    before = chain_path(recorder).read_text()
    r = signafaide.flush()
    e = error_for(r)
    assert e.code == "chain_conflict"
    assert "Chain conflict, head attached." in str(e) and "seq 7" in str(e) and "nothing was rewritten" in str(e)
    assert chain_path(recorder).read_text() == before
    assert recorder.state.outbox_size() == 1
    assert error_for(signafaide.flush()) is e  # stays blocked, no retry storm


def test_server_message_surfaces_verbatim(recorder, service):
    signafaide.note("a", {})
    recorder._api_key = "sfa_test_" + "0" * 32
    e = error_for(signafaide.flush())
    assert str(e) == "The API key is not valid; run `signafaide init` for a new sandbox key."


def test_unknown_agent_reregisters(recorder, service):
    signafaide.note("a", {})
    signafaide.flush()
    next(iter(service.projects.values()))["agents"].clear()  # service forgot the key
    signafaide.note("b", {})
    assert signafaide.flush()["shipped"] == 1


def test_init_never_creates_a_sandbox(project, service):
    signafaide.init(url=service.url, quiet=True)
    try:
        assert service.calls == [] and not (project / ".env").exists()
    finally:
        runtime._default = None


def test_create_sandbox_once(project, service, capsys):
    rec = runtime.configure(url=service.url)
    rec.create_sandbox()
    try:
        err = capsys.readouterr().err.strip().splitlines()
        assert len(err) == 1 and "claim it at" in err[0] and service.url in err[0]
        env = (project / ".env").read_text()
        assert env.count("SIGNAFAIDE_API_KEY=sfa_test_") == 1
        runtime.configure(url=service.url).create_sandbox()
        assert (project / ".env").read_text() == env
        assert capsys.readouterr().err == ""
        assert rec.state.sandbox()["claim_url"].startswith(service.url)
        assert {".signafaide/", ".env"} <= set((project / ".gitignore").read_text().splitlines())
    finally:
        runtime._default = None


def test_sandbox_adds_env_to_gitignore(recorder, project):
    signafaide.note("first", {})
    assert signafaide.flush()["shipped"] == 1
    assert (project / ".env").read_text().startswith("SIGNAFAIDE_API_KEY=sfa_test_")
    assert {".signafaide/", ".env"} <= set((project / ".gitignore").read_text().splitlines())


def test_sandbox_keeps_an_existing_env_entry(local_recorder, project):
    (project / ".gitignore").write_text("node_modules\n/.env\n")
    signafaide.note("first", {})
    local_recorder.create_sandbox()
    assert signafaide.flush()["shipped"] == 1
    ignore = (project / ".gitignore").read_text()
    assert ignore.startswith("node_modules\n/.env\n") and ignore.count(".env") == 1


def test_init_offline_does_not_raise(project, dead_url, capsys):
    signafaide.init(url=dead_url, api_key="sfa_test_" + "k" * 32)
    assert "Cannot reach" in capsys.readouterr().err
    runtime._default = None


def test_records_survive_process_exit(project, dead_url, service):
    """A child process records while offline and exits: nothing is lost."""
    code = (
        "import signafaide\n"
        "signafaide.record(lambda: 1, name='x')()\n"
    )
    rec = runtime.Recorder(url=service.url, quiet=True)
    rec.create_sandbox()  # a real sandbox key, saved to .env, which the child reads
    env = {"SIGNAFAIDE_URL": dead_url, "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, "-c", code], cwd=project, env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert "2 records kept" in p.stderr
    assert rec.state.outbox_size() == 2
    assert rec.flush()["shipped"] == 2


def test_no_key_child_process_sends_nothing(project, service):
    code = "import signafaide\nsignafaide.record(lambda: 1, name='x')()\nsignafaide.record(lambda: 2, name='y')()\n"
    env = {"SIGNAFAIDE_URL": service.url, "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, "-c", code], cwd=project, env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert service.calls == []
    assert p.stderr.count("recording locally") == 1
    assert not (project / ".env").exists()
    assert runtime.Recorder(quiet=True).state.draft_count("_pending/nokey/claims-project") == 4


def test_flush_on_exit_ships(project, service):
    runtime.Recorder(url=service.url, quiet=True).create_sandbox()
    code = "import signafaide\nsignafaide.record(lambda: 1, name='x')()\n"
    env = {"SIGNAFAIDE_URL": service.url, "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, "-c", code], cwd=project, env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert "recording locally" not in p.stderr
    assert runtime.Recorder(quiet=True).state.outbox_size() == 0
    assert ("POST", "/v1/records") in service.calls


def test_to_jsonable_keeps_unportable_numbers_as_text():
    assert signafaide.to_jsonable({"a": 2**64, "b": 1e20, "c": float("nan"), "d": 2**53 - 1, "e": 1.5}) == {
        "a": "18446744073709551616",
        "b": "1e+20",
        "c": "nan",
        "d": 2**53 - 1,
        "e": 1.5,
    }


def test_switching_keys_starts_a_fresh_chain(recorder, service):
    signafaide.note("a", {})
    signafaide.note("b", {})
    signafaide.flush()
    sandbox_chain = chain_of(recorder)
    live_key = "sfa_live_" + "L" * 32
    live = service.add_project(live_key, env="live")
    recorder._api_key = live_key
    signafaide.note("c", {})  # the new key's project is looked up first (GET /v1/project)
    assert not [c for c in recorder.state.chains() if c.startswith("_pending/")]
    r = signafaide.flush()
    assert r["errors"] == {} and r["shipped"] == 1
    live_chain = f"{live['project']}/live/claims-project"
    assert sorted(recorder.state.chains()) == sorted([sandbox_chain, live_chain])
    assert [x["envelope"]["seq"] for x in recorder.state.read_chain(live_chain)] == [1]
    assert all("receipt" in x for x in recorder.state.read_chain(live_chain))
    signafaide.note("d", {})  # now written straight to the live chain
    assert signafaide.flush()["shipped"] == 1
    assert [x["envelope"]["seq"] for x in recorder.state.read_chain(live_chain)] == [1, 2]
    assert [x["envelope"]["seq"] for x in recorder.state.read_chain(sandbox_chain)] == [1, 2]
    assert signafaide.verify().ok


def test_records_before_any_key_join_the_sandbox_chain(local_recorder, service):
    recorder = local_recorder
    approve = signafaide.record(lambda x: x, name="approve")
    approve(1)
    signafaide.note("a", {})
    assert recorder.state.chains() == ["_pending/nokey/claims-project"]
    assert recorder.state.outbox_size() == 0 and recorder.state.draft_count("_pending/nokey/claims-project") == 3
    assert signafaide.flush()["shipped"] == 0 and service.calls == []  # nothing sent before the opt-in
    recorder.create_sandbox()
    r = signafaide.flush()
    assert r["errors"] == {} and r["shipped"] == 3, r
    (c,) = recorder.state.chains()
    assert c.endswith("/test/claims-project") and not c.startswith("_pending")
    recs = list(recorder.state.read_chain(c))
    assert recs[1]["envelope"]["ref"] == hash_json(recs[0]["envelope"])  # the outcome still names its decision
    assert signafaide.verify().ok
