"""Setup uses the config it generates, and says what blocks (SPEC §8): ``init`` writes the checks
file, a program started afterwards in that project reads that very file, and an edit of a rule in
it changes what a call does. The output of setup says which checks are on, in which mode, which
tools are strict, which fields leave the machine and where to change it. (The Python SDK has no
``agent setup``: that command is the TypeScript SDK's.)"""

import json

import pytest

import signafaide
from signafaide import runtime
from signafaide.checks_runtime import CheckError
from signafaide.cli import main

from conftest import _stop
from helpers import records

KEY = "AKIA" + "Z3XQ7PLM2NRT5VWY"  # made up


@pytest.fixture
def cli(project, service, monkeypatch, capsys):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)

    def run(*args):
        code = main(list(args))
        return code, capsys.readouterr().out

    yield run
    runtime._default = None


def fresh_program(root):
    """A program started afresh in *root*: nothing held from the process that ran setup."""
    if runtime._default is not None:
        _stop(runtime._default)
    return runtime.configure(quiet=True, flush_interval=3600)


def make_send(ran):
    @signafaide.record(name="send_mail")
    def send(to, body):
        ran.append(to)
        return "sent"

    return send


def test_init_then_a_call_meets_the_generated_file_and_a_rule_edited_into_it_takes_effect(cli, project):
    code, _ = cli("init")
    assert code == 0
    file = project / "signafaide.checks.json"
    doc = json.loads(file.read_text())
    assert doc["mode"] == "watch"

    # Watch mode, as generated: the secret is noted and the tool runs.
    rec = fresh_program(project)
    ran = []
    assert make_send(ran)("ops@example.com", f"key {KEY}") == "sent"
    assert ran == ["ops@example.com"]
    d = next(r for r in records(rec) if r["envelope"]["kind"] == "decision")
    entry = next(e for e in d["envelope"]["checks"]["results"] if e["check"] == "secret")
    assert entry["result"] == "note" and entry["mode"] == "watch" and entry["enforce_result"] == "block" and entry["found"] == ["aws_access_key"]

    # A local rule added to the generated file, in the mode the file says: noted, runs.
    doc["rules"] = {"default": "allow", "rules": [{"id": "no-ops", "about": "Nothing to ops.", "action": "block", "tools": ["send_mail"], "agents": None,
                                                   "when": [{"field": "/to", "op": "eq", "value": "ops@example.com"}]}]}
    file.write_text(json.dumps(doc))
    rec = fresh_program(project)
    ran = []
    assert make_send(ran)("ops@example.com", "hello") == "sent"
    d = [r for r in records(rec) if r["envelope"]["kind"] == "decision"][-1]
    entry = next(e for e in d["envelope"]["checks"]["results"] if e["check"] == "rule")
    assert entry["result"] == "note" and entry["mode"] == "watch" and entry["enforce_result"] == "block"

    # The same file with the mode the owner chooses: the rule blocks, and the tool does not run.
    doc["mode"] = "enforce"
    file.write_text(json.dumps(doc))
    fresh_program(project)
    ran = []
    with pytest.raises(CheckError) as e:
        make_send(ran)("ops@example.com", "hello")
    assert e.value.rule == "no-ops" and ran == []


def test_init_says_what_is_on_the_mode_that_nothing_blocks_and_how_to_change_it(cli, project):
    _, out = cli("init")
    file = project / "signafaide.checks.json"
    assert "tool-call checks: on, Calibrating" in out
    assert "secret, address, changed_tool, fingerprint, hidden_instruction" in out
    assert "never block" in out
    assert "No tool is protected and no field of a tool's arguments leaves the machine" in out
    assert f"change it in {file}" in out
    assert '`"mode": "enforce"` is On' in out and '"strict": true' in out and '"disclose"' in out
    assert "`signafaide checks status`" in out
    # ready + claim link, why claim, time left, terms, what is sent, which checks are on, how to change them, the project note and its file
    assert len(out.splitlines()) == 10


def test_init_with_a_file_in_place_says_what_that_file_does(cli, project):
    file = project / "signafaide.checks.json"
    assert cli("init")[0] == 0
    doc = json.loads(file.read_text())
    doc["mode"] = "enforce"
    doc["tools"] = {"pay": {"strict": True, "disclose": ["/amount"]}}
    file.write_text(json.dumps(doc))
    code, out = cli("init")
    assert code == 0
    assert "tool-call checks: on, On" in out
    assert "protected tool pay: if signafAIde can't be reached: Stop; discloses /amount" in out
    assert f"change it in {file}" in out and "`signafaide checks status`" in out
    doc["tools"] = {}
    file.write_text(json.dumps(doc))
    assert "no tool is protected; only tool fingerprints leave the machine" in cli("init")[1]


def test_init_with_checks_off_says_so(cli, project, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_CHECKS", "0")
    assert "tool-call checks: off (SIGNAFAIDE_CHECKS=0)" in cli("init")[1]
