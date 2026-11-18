"""SDK 0.5.2 (SPEC §8, §10.1, issue #65): a person protects a tool from the console, and every
client that wraps the tool protects it from its next fetch of the rule set, as the checks file's
``protect: true`` would. Owner: "i expect when i press the protect button i activate protect same
as the cli command"."""

import asyncio
import json
import shutil

import pytest

import signafaide
from signafaide import checks as C
from signafaide import cli, runtime
from signafaide.checks_runtime import CheckError
from signafaide.protect_cli import ScriptedPrompter
from signafaide.tool_commands import run_pull, status_table

from conftest import _recorder, _stop

PAY_LIMIT = {"id": "limit", "about": "Big payouts.", "action": "block", "tools": ["pay"], "agents": None, "when": [{"field": "/amount", "op": "gt", "value": 1000}]}
PAY_RATE = {"id": "rate", "about": "At most 100 a minute.", "action": "block", "tools": ["pay"], "agents": None, "when": [],
            "limit": {"calls": 100, "seconds": 60, "per": "agent_tool"}}


@pytest.fixture
def online(project, service, monkeypatch):
    r = _recorder(service, monkeypatch, opt_in=True)
    yield r
    _stop(r)


def lines_of(rec):
    out = []
    for chain in rec.state.chains():
        out += list(rec.state.read_all(chain))
    return out


def pay_tool(ran=None):
    @signafaide.record(name="pay")
    def pay(amount):
        if ran is not None:
            ran.append(amount)
        return "paid"

    return pay


def test_takes_effect_after_a_fetch_with_no_checks_file(online, service, capsys):
    ran = []
    pay = pay_tool(ran)
    service.publish_rules(online.api_key, [PAY_RATE])
    online.checks.pull_rules()
    assert pay(5) == "paid"
    assert "checks" not in lines_of(online)[-2]["envelope"]  # version 1 does not protect pay: as in 1.1
    service.publish_rules(online.api_key, [PAY_RATE], protect={"pay": {"fail": "closed"}})
    online.checks.pull_rules()
    capsys.readouterr()
    assert pay(7) == "paid"
    assert "signafaide: pay is now protected from the console (rule set version 2)" in capsys.readouterr().err
    d, o = lines_of(online)[-2:]
    ch = d["envelope"]["checks"]
    assert ch["strict"] is True and ch["fail"] == "closed" and ch["rules"][0]["version"] == 2
    assert all(e["mode"] == "enforce" for e in ch["results"] if e["check"] != "rule")
    assert d["content"]["meta"]["protected_by"] == ["console"]
    assert d["receipt"]["ruling"]["ruling"] == "allow" and o["envelope"]["checks"]["ruling"] == "allow"
    assert ran == [5, 7]
    pay(8)
    assert "now protected" not in capsys.readouterr().err  # once per change


def test_unprotect_unless_the_code_protects_it(online, service, capsys):
    service.publish_rules(online.api_key, [], protect={"pay": {"fail": "closed"}, "refund": {"fail": "closed"}})
    online.checks.pull_rules()
    pay = pay_tool()

    @signafaide.protect(name="refund")
    def refund(amount):
        return "refunded"

    pay(1)
    assert lines_of(online)[-2]["envelope"]["checks"]["strict"] is True
    refund(1)
    assert lines_of(online)[-2]["content"]["meta"]["protected_by"] == ["code", "console"]
    service.publish_rules(online.api_key, [])
    online.checks.pull_rules()
    capsys.readouterr()
    pay(2)
    assert "signafaide: pay is no longer protected from the console (rule set version 2)" in capsys.readouterr().err
    assert "checks" not in lines_of(online)[-2]["envelope"]
    refund(2)
    assert "signafaide: refund is no longer protected from the console (rule set version 2); it stays protected by the code" in capsys.readouterr().err
    d = lines_of(online)[-2]
    assert d["envelope"]["checks"]["strict"] is True and d["content"]["meta"]["protected_by"] == ["code"]


@pytest.mark.parametrize("fail", ["closed", "open"])
def test_no_ruling_follows_the_consoles_fail_mode_over_the_checks_file(online, service, project, fail):
    service.publish_rules(online.api_key, [], protect={"pay": {"fail": fail}})
    online.checks.pull_rules()
    other = "closed" if fail == "open" else "open"
    (project / "signafaide.checks.json").write_text(json.dumps({**C.default_checks_file(), "tools": {"pay": {"strict": True, "fail": other}}}))
    service.no_ruling = True
    ran = []
    pay = pay_tool(ran)
    if fail == "closed":
        with pytest.raises(CheckError) as e:
            pay(1)
        assert e.value.code == "no_ruling" and ran == []
        assert lines_of(online)[-1]["envelope"]["checks"] == {"ran": False, "ruling": "none", "results": [], "result": "allow"}
    else:
        assert pay(1) == "paid"
        assert lines_of(online)[-1]["envelope"]["checks"]["ruling"] == "none"
    d = lines_of(online)[-2]
    assert d["envelope"]["checks"]["fail"] == fail
    assert d["content"]["meta"]["protected_by"] == ["checks_file", "console"]


def test_a_1_1_document_without_protect_changes_nothing(online, service, project):
    service.publish_rules(online.api_key, [PAY_LIMIT])
    online.checks.pull_rules()
    doc = online.checks.held_rules()
    assert "protect" not in doc
    (project / "signafaide.checks.json").write_text(json.dumps(C.default_checks_file()))
    pay = pay_tool()
    assert pay(5) == "paid"
    d = lines_of(online)[-2]
    assert d["envelope"]["checks"]["strict"] is False and d["envelope"]["checks"]["fail"] is None
    assert "protected_by" not in d["content"]["meta"]
    assert "protect" in C.rule_set_errors({**doc, "protect": {}})  # left out when none, never {}


def test_field_rules_still_need_pull(online, service, project):
    service.publish_rules(online.api_key, [PAY_LIMIT, PAY_RATE], protect={"pay": {"fail": "closed"}})
    online.checks.pull_rules()
    ran = []
    pay = pay_tool(ran)
    with pytest.raises(CheckError) as e:
        pay(5)
    assert e.value.code == "blocked" and e.value.missing == ["/amount"] and ran == []
    assert lines_of(online)[-2]["envelope"]["checks"]["disclosed"] == []
    text = "\n".join(online.checks.status()[0])
    assert "protected tool pay: rule set version 1 needs /amount: run `signafaide pull` to approve sending /amount" in text
    assert "protected from the console (rule set version 1)" in text
    out = []
    assert run_pull(online, ScriptedPrompter([True]), out.append) == 0
    assert "pay was protected from the console only; signafaide.checks.json now protects it too" in "\n".join(out)
    f = json.loads((project / "signafaide.checks.json").read_text())
    assert f["tools"]["pay"] == {"protect": True, "disclose": ["/amount"]} and C.checks_file_errors(f) is None
    online.checks.forget()
    assert pay(5) == "paid"
    d = lines_of(online)[-2]
    assert d["envelope"]["checks"]["disclosed"] == ["/amount"]
    assert d["content"]["meta"]["protected_by"] == ["checks_file", "console"]


def test_status_checks_status_and_prove_say_where_protection_comes_from(online, service, capsys):
    service.publish_rules(online.api_key, [PAY_RATE], protect={"pay": {"fail": "open"}, "ghost": {"fail": "closed"}})
    online.checks.pull_rules()
    pay = pay_tool()
    pay(5)
    online.flush()
    text = "\n".join(online.checks.status()[0])
    assert ("protected tool pay: if signafAIde can't be reached: Let it run, local checks On; discloses no field; "
            "protected from the console (rule set version 1)") in text
    assert "protected tool ghost: protected from the console (rule set version 1), but no record or declaration of this program names it yet" in text
    table = "\n".join(status_table(online))
    assert "1 of 1 rule On, from the console (rule set version 1)" in table
    assert "Off: protected from the console (rule set version 1), but not wrapped, so signafAIde never sees its calls" in table
    capsys.readouterr()
    cli.main(["prove", "pay"])
    assert "Protected  pay from the console (rule set version 1)" in capsys.readouterr().out


def test_at_start_a_fresh_process_waits_for_its_first_fetch(project, service, monkeypatch):
    r = _recorder(service, monkeypatch, opt_in=True)
    service.publish_rules(r.api_key, [], protect={"pay": {"fail": "closed"}})
    _stop(r)
    shutil.rmtree(r.state.home / "checks", ignore_errors=True)
    fresh = runtime.configure(quiet=True, flush_interval=3600)  # a new container: no version held
    try:
        pay = pay_tool()
        pay(3)
        d = lines_of(fresh)[-2]
        assert d["envelope"]["checks"]["strict"] is True and d["content"]["meta"]["protected_by"] == ["console"]
    finally:
        _stop(fresh)


def test_async_tool_protected_from_the_console(online, service):
    service.publish_rules(online.api_key, [], protect={"pay": {"fail": "closed"}})
    online.checks.pull_rules()

    @signafaide.record(name="pay")
    async def pay(amount):
        return "paid"

    assert asyncio.run(pay(2)) == "paid"
    d = lines_of(online)[-2]
    assert d["envelope"]["checks"]["strict"] is True and d["receipt"]["ruling"]["ruling"] == "allow"


def test_checks_off_nothing_is_protected_from_the_console(project, service, monkeypatch):
    r = _recorder(service, monkeypatch, opt_in=True)
    service.publish_rules(r.api_key, [], protect={"pay": {"fail": "closed"}})
    monkeypatch.setenv("SIGNAFAIDE_CHECKS", "0")
    fetches = len(service.rules_fetches)
    try:
        pay = pay_tool()
        assert pay(3) == "paid"
        assert "checks" not in lines_of(r)[-2]["envelope"]
        assert len(service.rules_fetches) == fetches
    finally:
        _stop(r)
