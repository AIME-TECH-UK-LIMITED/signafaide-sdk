"""Spec 1.1, the Record / Protect / Prove flow from the command line: ``protect`` finds the tools,
asks what to block, decorates the code, makes the sandbox and saves the rules; the protected tool
is then ruled; ``check``, ``status``, ``pull``, ``prove``, ``start-fresh``, ``login`` and ``logout``
say and do what the mockup shows. Every question is answered by a scripted person."""

import importlib.util
import json
import re
import stat

import pytest

from signafaide import cli, runtime
from signafaide import verify
from signafaide._version import __version__
from signafaide.checks_runtime import CheckError, SignafaideBlocked
from signafaide.decorator import protect, record
from signafaide.protect_cli import (
    FlagPrompter,
    ScriptedPrompter,
    code_changes,
    find_tools,
    next_draft,
    to_version2,
    tool_kind,
)
from signafaide.records import record_hash
from signafaide.session import load_session, login, logout, session_file
from signafaide.tool_commands import auditor_commands, parse_field_args

from conftest import _recorder, _stop

TOOLS_PY = '''"""Payout tools."""
from __future__ import annotations


def approve_payout(payee: str, amount: float, currency: str) -> str:
    return f"paid {amount} {currency} to {payee}"


def delete_payee(payee_id: str) -> str:
    return payee_id


def send_receipt(to: str, body: str) -> str:
    return to


def lookup_invoice(invoice_id: str) -> str:
    return invoice_id


tools = [approve_payout, delete_payee, send_receipt, lookup_invoice]
'''

#: The mockup's answers: approve_payout only, block above 1000, On, also calibrate currency not
#: GBP, a sandbox, write the code. Python names arguments by the signature: no question for that.
MOCKUP = [[True, False, False, False], 0, "1000", 0, [True, False], True, True]


@pytest.fixture
def flow(project, service, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    (project / "src").mkdir()
    (project / "src" / "tools.py").write_text(TOOLS_PY)
    (project / "pyproject.toml").write_text('[project]\nname = "payout-bot"\nversion = "1.0.0"\n')
    _recorder(service, monkeypatch, opt_in=False)
    yield project, service
    cli.make_prompter = None
    _stop(runtime.get())


def run(capsys, *argv, prompter=None):
    if prompter is not None:
        cli.make_prompter = lambda yes: prompter
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def load_tools(project):
    spec = importlib.util.spec_from_file_location(f"tools_{id(project)}", project / "src" / "tools.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def decisions(agent="payout-bot"):
    st = runtime.get().state
    chain = next(c for c in st.chains() if c.endswith(f"/{agent}"))
    return [r for r in st.read_all(chain) if r["envelope"]["kind"] == "decision"]


def test_find_and_rewrite(flow):
    project, _ = flow
    f = find_tools(project)
    assert f.collection and f.collection[1] == "tools"
    assert [(t.name, t.kind, t.params, [p for _, p in t.fields]) for t in f.tools] == [
        ("approve_payout", "pays", ["payee", "amount", "currency"], ["/payee", "/amount", "/currency"]),
        ("delete_payee", "deletes", ["payee_id"], ["/payee_id"]),
        ("send_receipt", "sends", ["to", "body"], ["/to", "/body"]),
        ("lookup_invoice", "reads", ["invoice_id"], ["/invoice_id"]),
    ]
    assert (
        tool_kind("refundOrder") == "pays"
        and tool_kind("get_weather") == "reads"
        and tool_kind("frobnicate") == "other"
    )
    [ch] = code_changes(f, {"approve_payout"}, "payout-bot", project)
    out = ch.after
    assert out.splitlines()[1] == "from __future__ import annotations"
    assert out.splitlines()[2] == "import signafaide"
    assert '@signafaide.protect(agent="payout-bot")\ndef approve_payout(' in out
    assert '@signafaide.record(agent="payout-bot")\ndef lookup_invoice(' in out
    assert (
        'signafaide.declare_tools(["approve_payout", "delete_payee", "send_receipt", "lookup_invoice"], agent="payout-bot")'
        in out
    )
    (project / "src" / "tools.py").write_text(out)
    again = find_tools(project)
    assert next(t for t in again.tools if t.name == "approve_payout").wrapped == "protect"
    assert code_changes(again, {"approve_payout"}, "payout-bot", project) == []
    # record -> protect replaces the decorator.
    [up] = code_changes(again, {"approve_payout", "delete_payee"}, "payout-bot", project)
    assert (
        '@signafaide.protect(agent="payout-bot")\ndef delete_payee(' in up.after
        and up.after.count("def delete_payee") == 1
    )


def test_version2_and_drafts():
    v1 = {
        "format": "signafaide-checks/1",
        "mode": "enforce",
        "checks": {k: True for k in ("secret", "address", "changed_tool", "fingerprint", "hidden_instruction")},
        "tools": {
            "pay": {"strict": True, "fail": "open", "disclose": ["/amount", "/amount"]},
            "look": {"strict": False},
        },
        "addresses": {"hosts": [], "cidrs": [], "resolve": False},
        "rules": None,
    }
    v2 = to_version2(v1)
    assert v2["format"] == "signafaide-checks/2"
    assert v2["tools"] == {
        "pay": {"protect": True, "mode": "enforce", "disclose": ["/amount"]},
        "look": {"protect": False, "mode": "enforce"},
    }
    held = {
        "mode": "watch",
        "default": "allow",
        "fail": {},
        "addresses": {"hosts": [], "cidrs": []},
        "approved": None,
        "rules": [],
    }
    assert next_draft(held, [{"id": "x", "state": "on"}])["rules"] == [{"id": "x", "state": "calibrating"}]
    assert parse_field_args(["amount=1200", "currency=GBP", "payee/name=Ashgrove Catering Ltd", "ok=true"]) == {
        "amount": 1200,
        "currency": "GBP",
        "payee": {"name": "Ashgrove Catering Ltd"},
        "ok": True,
    }
    with pytest.raises(ValueError):
        parse_field_args(["amount"])


def test_the_mockup_session(flow, capsys):
    project, service = flow
    p = ScriptedPrompter(MOCKUP)
    code, text = run(capsys, "protect", prompter=p)
    assert code == 0, text
    assert "Agent      payout-bot" in text
    assert "Found      4 tools in src/tools.py" in text
    assert re.search(r"approve_payout\s+pays money\s+protect", text)
    assert "Rule: Block approve_payout when amount is above 1,000" in text
    assert "Sends to signafAIde when approve_payout runs: amount, currency (the fields your 2 rules need)" in text
    assert "Never sent to signafAIde: payee." in text
    assert "Sandbox    made for you" in text
    assert "Rules      saved in your sandbox as version 1, signed by signafAIde" in text
    assert "signafaide check approve_payout amount=1200 currency=GBP" in text
    assert p.asked[0].startswith("Protect which tools?")
    # protect writes only the key to .env, never the witness URL (it is in the process environment).
    env_text = (project / ".env").read_text()
    assert re.fullmatch(r"SIGNAFAIDE_API_KEY=sfa_test_\w+\n", env_text)
    src = (project / "src" / "tools.py").read_text()
    assert '@signafaide.protect(agent="payout-bot")\ndef approve_payout(' in src
    f = json.loads((project / "signafaide.checks.json").read_text())
    assert f["format"] == "signafaide-checks/2"
    assert f["tools"] == {"approve_payout": {"protect": True, "disclose": ["/amount", "/currency"]}}
    assert service.published == [
        {"project": next(iter(service.projects.values()))["project"], "version": 1, "how": "sandbox_key", "who": None}
    ]
    rs = runtime.get().checks.held_rules()
    assert [(r["id"], r["state"]) for r in rs["rules"]] == [
        ("approve_payout-amount", "on"),
        ("approve_payout-currency", "calibrating"),
    ]

    # The rewritten code runs: 800 is paid, 1200 is blocked in words with the version and a link.
    mod = load_tools(project)
    assert mod.approve_payout("Ashgrove Catering Ltd", 800, "GBP") == "paid 800 GBP to Ashgrove Catering Ltd"
    with pytest.raises(SignafaideBlocked) as ei:
        mod.approve_payout("Ashgrove Catering Ltd", 1200, "GBP")
    b = ei.value
    assert isinstance(b, CheckError) and b.code == "blocked"
    # A protected call always asks the witness, also when the version held here would block it.
    assert re.match(
        r'^approve_payout did not run: signafAIde blocked it under "Block approve_payout when amount is above 1,000" \(rule set version 1\)\. '
        r"To allow such calls, change the rule in the console\. http://127\.0\.0\.1:\d+/r/[0-9a-f]{64}$",
        str(b),
    ), str(b)
    assert (b.tool, b.rule, b.rule_text, b.ruled_by, b.rules_version, b.check) == (
        "approve_payout",
        "approve_payout-amount",
        "Block approve_payout when amount is above 1,000",
        "witness",
        1,
        "rule",
    )
    assert b.link == f"{service.url}/r/{b.record}" and record_hash(decisions()[-1]) == b.record
    dec = decisions()[-1]["envelope"]["checks"]
    assert dec["result"] == "note"
    assert next(e for e in dec["results"] if e["check"] == "rule") == {
        "check": "rule",
        "result": "note",
        "mode": "watch",
        "enforce_result": "block",
        "set": dec["rules"][0]["set"],
        "matched": ["approve_payout-amount"],
    }
    # A Calibrating rule never blocks; the ruling names it; only the approved fields left.
    assert mod.approve_payout("Brightmoor Print", 640, "EUR").startswith("paid 640")
    last = decisions()[-1]
    assert last["receipt"]["ruling"]["would_block"] == ["approve_payout-currency"]
    assert service.disclosed[record_hash(last)][0] == {"/amount": 640, "/currency": "EUR"}

    # check: exit 1 on would-block, 0 otherwise.
    code, out = run(
        capsys,
        "check",
        "approve_payout",
        "amount=1200",
        "currency=GBP",
        "payee=Ashgrove Catering Ltd",
        "--agent",
        "payout-bot",
    )
    assert code == 1, out
    assert "would block  Block approve_payout when amount is above 1,000 (On, version 1)" in out
    assert "Dry run: nothing recorded, the tool did not run. Exit code 1." in out
    code, out = run(capsys, "check", "approve_payout", "amount=800", "currency=EUR", "--agent", "payout-bot")
    assert code == 0, out
    assert 'calibrating  would have blocked: Block approve_payout when currency is not "GBP"' in out

    # status: one line per tool.
    runtime.get().flush()
    code, out = run(capsys, "status")
    lines = out.splitlines()
    assert re.match(r"^tool\s+recorded\s+protected\s+proof$", lines[0]), out
    assert re.search(
        r"approve_payout\s+3 calls, last \d\d:\d\d\s+1 of 2 rules On, 1 Calibrating, by the code and the checks file\s+intact",
        out,
    ), out
    assert re.search(r"lookup_invoice\s+0 calls\s+Off\s+intact", out), out

    # prove: the link first, the calls, the rules in words, Before and the record.
    code, out = run(capsys, "prove", "approve_payout")
    assert code == 0, out
    assert "Proof of approve_payout (agent payout-bot), Sandbox" in out
    assert "Send this link to your auditor:" in out and re.search(r"/audit/aud_1 {3}read only, until", out)
    assert re.search(r"allowed\s+800 GBP\s+by signafAIde", out), out
    assert re.search(r"blocked\s+1,200 GBP\s+by the signafAIde witness; it did not run", out), out
    assert re.search(r"On\s+Block approve_payout when amount is above 1,000\s+blocked 1", out), out
    assert re.search(r'Calibrating\s+Block approve_payout when currency is not "GBP"\s+would have blocked 1', out), out
    assert "Before     none: approve_payout was protected before its first call" in out
    assert "Tools      payout-bot has 4 tools, all 4 recorded, 1 protected" in out
    assert service.auditor_links[0]["agent"] == "payout-bot" and service.auditor_links[0]["tool"] == "approve_payout"

    # prove --files: a pack that verifies, with the rules in words.
    code, out = run(capsys, "prove", "approve_payout", "--files", "--content")
    assert code == 0, out
    # The auditor is pointed at the standalone verifier, pinned to this release; this witness is not
    # the hosted one, so its own key list is named (the hosted witness's keys are pinned in it).
    for via in ("npx", "uvx"):
        assert (
            f"{via} signafaide-verify@{__version__} pack.json --keys {service.url}/.well-known/signafaide-keys.json"
            " --agent-keys agent-keys.json --head head.json --content content.jsonl"
        ) in out
    assert auditor_commands("https://api.signafaide.co.uk/", "agent-keys.json") == [
        f"npx signafaide-verify@{__version__} pack.json --agent-keys agent-keys.json --head head.json",
        f"uvx signafaide-verify@{__version__} pack.json --agent-keys agent-keys.json --head head.json",
    ]
    d = project / "proof" / "approve_payout"
    assert sorted(x.name for x in d.iterdir()) == ["agent-keys.json", "content.jsonl", "head.json", "pack.json"]
    r = verify(
        d / "pack.json",
        keys={"keys": [service.key_doc]},
        agent_keys=d / "agent-keys.json",
        head=d / "head.json",
        content=d / "content.jsonl",
        offline=True,
    )
    assert r.ok, str(r)
    assert (
        f"{rs['set']} version 1: rule approve_payout-amount: Block approve_payout when amount is above 1,000 (On)"
        in r.rules_lines()
    )


def test_pull_asks_before_a_new_field(flow, capsys):
    project, service = flow
    assert run(capsys, "protect", prompter=ScriptedPrompter(MOCKUP))[0] == 0
    rec = runtime.get()
    v1 = rec.checks.held_rules()
    rules = [
        {
            **r,
            "exceptions": [
                {"field": "/payee", "value": "Harbour Lane Supplies Ltd", "reason": "Quarterly rent", "since": 2}
            ],
        }
        if r["id"] == "approve_payout-amount"
        else r
        for r in v1["rules"]
    ]
    service.publish_rules(rec.api_key, rules, set_id=v1["set"])
    code, out = run(capsys, "pull", prompter=FlagPrompter(yes=True))
    assert code == 0, out
    assert "Rules      version 2 (was 1)" in out
    assert "Change     approve_payout would also send: payee" in out
    assert (
        'needed by: Block approve_payout when amount is above 1,000, except when payee is "Harbour Lane Supplies Ltd"'
        in out
    )
    assert "run signafaide pull at a terminal to approve them" in out
    assert json.loads((project / "signafaide.checks.json").read_text())["tools"]["approve_payout"]["disclose"] == [
        "/amount",
        "/currency",
    ]
    p = ScriptedPrompter([True])
    code, out = run(capsys, "pull", prompter=p)
    assert p.asked == ["Send payee to signafAIde for approve_payout? It is kept 30 days, admins only."]
    assert "approve_payout sends amount, currency, payee" in out
    assert json.loads((project / "signafaide.checks.json").read_text())["tools"]["approve_payout"]["disclose"] == [
        "/amount",
        "/currency",
        "/payee",
    ]
    rec.checks.forget()
    mod = load_tools(project)
    assert mod.approve_payout("Harbour Lane Supplies Ltd", 4800, "GBP").startswith("paid 4800")
    assert decisions()[-1]["receipt"]["ruling"]["excepted"] == ["approve_payout-amount"]


def test_without_a_person_nothing_is_on_and_no_field_approved(flow, capsys):
    project, _ = flow
    code, out = run(capsys, "protect", "approve_payout", prompter=FlagPrompter(yes=True))
    assert code == 1, out  # --yes adds the default rule, Calibrating; with no key it is not saved yet (0.5.1)
    assert "  Rule: Block approve_payout when amount is above 1,000" in out
    # No field approved without a person; watch: the kept rule blocks nothing.
    assert json.loads((project / "signafaide.checks.json").read_text())["tools"]["approve_payout"] == {
        "protect": True,
        "mode": "watch",
    }
    assert "Sandbox    not made: only a person at a terminal opts in." in out
    assert not (project / ".env").exists() and ("POST", "/v1/sandbox") not in flow[1].calls


def test_claimed_sandbox_needs_a_person(flow, capsys):
    project, service = flow
    assert run(capsys, "protect", prompter=ScriptedPrompter(MOCKUP))[0] == 0
    next(iter(service.projects.values()))["claimed"] = True
    code, out = run(capsys, "protect", "delete_payee", prompter=ScriptedPrompter([0, "20", 0, True]))
    assert code == 1, out
    assert "Rules      not saved: the sandbox is claimed, so its rules are saved by a signed-in person." in out
    lines = []
    s = login(
        service.url, "test", lines.append, sleep=lambda _s: service.answer_device("approved"), browser=lambda _u: False
    )
    assert (
        lines[0] == f"Witness     {service.url}"
        and lines[1] == f"Sign in at  {service.url}/app/device"
        and lines[2] == "Your code   BCDF-GHJK"
    )
    assert s["session"].startswith("sfa_user_")
    assert load_session(service.url)["person"]["email"] == "owner@example.test"
    assert stat.S_IMODE(session_file().stat().st_mode) == 0o600
    code, out = run(capsys, "protect", "delete_payee", prompter=ScriptedPrompter([0, "20", 1, True]))
    assert code == 0, out
    assert "Rules      saved by owner@example.test as version 2" in out
    assert service.published[-1] == {
        "project": next(iter(service.projects.values()))["project"],
        "version": 2,
        "how": "session",
        "who": "owner@example.test",
    }
    last = runtime.get().checks.held_rules()["rules"][-1]
    assert (
        last["id"] == "delete_payee-rate"
        and last["state"] == "calibrating"
        and last["limit"] == {"calls": 20, "seconds": 60, "per": "agent_tool"}
    )
    assert logout(service.url, "test") is True
    assert load_session(service.url) is None and not service.sessions


def test_refused_sign_in_saves_nothing(flow):
    _, service = flow
    from signafaide.http import SignafaideError

    with pytest.raises(SignafaideError, match="refused"):
        login(
            service.url,
            "test",
            lambda s: None,
            sleep=lambda _s: service.answer_device("denied"),
            browser=lambda _u: False,
        )
    assert not session_file().exists()


def test_local_rules_only(flow, capsys):
    project, service = flow
    code, out = run(
        capsys,
        "protect",
        "--local",
        prompter=ScriptedPrompter([[True, False, False, False], 0, "1000", 0, [False, False], True]),
    )
    assert code == 0, out
    assert "Rules      kept on this machine in signafaide.checks.json; signafAIde does not rule on them." in out
    f = json.loads((project / "signafaide.checks.json").read_text())
    assert f["tools"]["approve_payout"] == {"protect": False, "mode": "enforce"}
    assert not (project / ".env").exists()
    runtime.get().checks.forget()
    mod = load_tools(project)
    assert mod.approve_payout("x", 10, "GBP").startswith("paid")
    with pytest.raises(SignafaideBlocked) as ei:
        mod.approve_payout("x", 5000, "GBP")
    assert str(ei.value) == (
        'approve_payout did not run: the rule on this machine blocked it ("Block approve_payout when amount is above 1,000"); '
        "signafAIde did not rule on it. To allow it, change the rule in signafaide.checks.json."
    )
    assert ei.value.link is None


def test_local_without_a_person_starts_calibrating_and_is_done(flow, capsys):
    project, service = flow
    code, out = run(
        capsys,
        "protect",
        "--local",
        "--tool",
        "approve_payout",
        "--limit-field",
        "amount",
        "--above",
        "1000",
        prompter=FlagPrompter(yes=True),
    )
    assert code == 0, out
    assert "Starts Calibrating" in out
    assert "is not approved" not in out and "Sends to signafAIde" not in out and "Not finished" not in out
    f = json.loads((project / "signafaide.checks.json").read_text())
    assert f["tools"]["approve_payout"] == {"protect": False, "mode": "watch"}
    assert [r["id"] for r in f["rules"]["rules"]] == ["approve_payout-amount"]
    # --tool records one tool, and the declaration is still the agent's full tool list.
    code_text = (project / "src" / "tools.py").read_text()
    assert code_text.count("@signafaide.record(") == 1
    assert (
        'signafaide.declare_tools(["approve_payout", "delete_payee", "send_receipt", "lookup_invoice"], agent='
        in code_text
    )
    runtime.get().checks.forget()
    assert load_tools(project).approve_payout("x", 5000, "GBP").startswith("paid")


def test_local_calibrating_answer_keeps_the_tool_in_watch_mode(flow, capsys):
    project, service = flow
    code, out = run(
        capsys,
        "protect",
        "--local",
        prompter=ScriptedPrompter([[True, False, False, False], 0, "1000", 1, [False, False], True]),
    )
    assert code == 0, out
    f = json.loads((project / "signafaide.checks.json").read_text())
    assert f["tools"]["approve_payout"] == {"protect": False, "mode": "watch"}


def test_prove_before_and_start_fresh(flow, capsys):
    project, service = flow
    rec = runtime.get()
    rec.create_sandbox()

    @record(agent="payout-bot")
    def approve_payout(payee, amount, currency):
        return amount

    approve_payout("a", 10, "GBP")
    approve_payout("b", 20, "GBP")
    assert (
        run(
            capsys,
            "protect",
            prompter=ScriptedPrompter([[True, False, False, False], 0, "1000", 0, [False, False], True]),
        )[0]
        == 0
    )
    mod = load_tools(project)
    mod.approve_payout("c", 30, "GBP")
    code, out = run(capsys, "prove", "approve_payout")
    assert code == 0, out
    assert re.search(
        r"Before {5}2 calls of approve_payout \(\d\d:\d\d to \d\d:\d\d\) were recorded before it was protected\. They ran",
        out,
    ), out
    code, out = run(capsys, "start-fresh", "payout-bot")
    assert code == 0 and "The old record is kept" in out
    mod.approve_payout("d", 40, "GBP")
    code, out = run(capsys, "prove", "approve_payout")
    assert "Before     none" in out and "Calls      1," in out
    assert re.match(r"^\d{4}-", service.auditor_links[-1]["from"])
    code, out = run(capsys, "prove", "approve_payout", "--all")
    assert "Calls      4," in out


def test_no_auditor_links(flow, capsys):
    project, service = flow
    assert run(capsys, "protect", prompter=ScriptedPrompter(MOCKUP))[0] == 0
    load_tools(project).approve_payout("x", 10, "GBP")
    service.auditor_links_off = True
    code, out = run(capsys, "prove", "approve_payout")
    assert code == 0, out
    assert "No link: this witness does not make auditor links from the command line yet." in out
    assert "signafaide prove approve_payout --files" in out


def test_record_and_protect_name_arguments(project, service, monkeypatch):
    _recorder(service, monkeypatch, opt_in=False)
    try:
        fn = record(lambda *a: sum(a[:1]), name="named", args=["amount", "currency"])
        fn(5, "GBP", 1, 2)
        st = runtime.get().state
        d = next(r for r in st.read_all(st.chains()[0]) if r["envelope"]["kind"] == "decision")
        assert d["content"]["input"] == {"amount": 5, "currency": "GBP", "_rest": [1, 2]}
        with pytest.raises(TypeError, match="distinct"):
            record(lambda: 1, args=["a", "a"])
        # protect without a key: the call does not run and says how to get one.
        (project / "signafaide.checks.json").write_text(json.dumps(to_version2(None)))
        runtime.get().checks.forget()
        ran = []

        @protect(args=["amount"])
        def pay(amount):
            ran.append(amount)

        with pytest.raises(SignafaideBlocked) as ei:
            pay(5)
        assert ran == [] and ei.value.code == "no_key" and "signafaide protect" in str(ei.value)
    finally:
        _stop(runtime.get())


def test_terminal_prompter():
    from signafaide.protect_cli import TerminalPrompter

    answers = iter(["", "n", "9", "2", "1,3", "", "1500"])
    shown = []

    def read(q):
        shown.append(q)
        try:
            return next(answers)
        except StopIteration:
            raise EOFError

    p = TerminalPrompter(read=read, write=shown.append)
    assert p.person
    assert p.confirm("Write it?", True) is True
    assert p.confirm("Sandbox?", True) is False
    assert p.choose("Which?", ["a", "b"], 0) == 1  # 9 is asked again
    assert p.multi("Tick", ["x", "y", "z"], [False, False, False]) == [True, False, True]
    assert p.text("Limit:", "1000") == "1000"
    assert p.text("Limit:", "1000") == "1500"
    assert p.confirm("At the end of input:", False) is False
    assert "  > 1) a\n" in shown and "  1) [ ] x\n" in shown
