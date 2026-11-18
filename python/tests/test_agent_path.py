"""Issue #67 step 2: the path a coding agent takes. ``protect --yes --tool <name> --limit-field <f>
--above <n>`` asks nothing and adds a rule that starts Calibrating; ``protect`` and ``init`` add the
project note to AGENTS.md / CLAUDE.md after asking, never twice; a protected tool with no key or
sandbox stops with one sentence that names the one command and why."""

import json
import re
from pathlib import Path

import pytest

from signafaide import checks as C
from signafaide import cli, runtime
from signafaide.agent_note import NOTE, NOTE_FILES, SECTION_END, SECTION_START, note_files, note_section, offer_note
from signafaide.checks_runtime import SignafaideBlocked
from signafaide.decorator import protect
from signafaide.protect_cli import CALIBRATING_LINE, FlagPrompter, ScriptedPrompter, to_version2

from conftest import _recorder, _stop

TOOLS_PY = '''"""Payout tools."""


def approve_payout(payee: str, amount: float, currency: str) -> str:
    return f"paid {amount} {currency} to {payee}"


def lookup_invoice(invoice_id: str) -> str:
    return invoice_id


def refund_payout(amount: float) -> str:
    return str(amount)


tools = [approve_payout, lookup_invoice, refund_payout]
'''

AGENT_RUN = ["protect", "--yes", "--tool", "approve_payout", "--limit-field", "amount", "--above", "1000"]
REPO = Path(__file__).resolve().parents[2]
WORDS = re.compile(r"\b(flag|warn|verdict|trying|preset|egress|firewall|mediator|pipelock|bitcoin)", re.I)


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


# --- the note --------------------------------------------------------------------------------

def test_note_is_one_paragraph_and_three_lines_in_plain_words():
    heading, blank, para, blank2, *lines = NOTE.rstrip("\n").split("\n")
    assert [heading, blank, blank2] == ["## signafAIde", "", ""]
    assert "Use it when adding or changing a tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config" in para
    assert "nothing is sent and nothing is created online until a person opts in" in para
    assert len(lines) == 3
    assert lines[0].startswith("- Install: `npm install signafaide`") and "`uv add signafaide`" in lines[0]
    assert lines[1].startswith("- Wrap: `protect(") and "@signafaide.protect(" in lines[1]
    assert "`npx signafaide protect` (or `signafaide protect` in Python)" in lines[2]
    assert "protected tools stop until then" in lines[2]
    assert "npx signafaide protect --yes --tool <name> --limit-field amount --above 1000" in lines[2]
    assert not WORDS.search(NOTE) and "—" not in NOTE


def test_note_is_the_same_text_as_the_repository_and_the_typescript_sdk():
    assert (REPO / "agents" / "AGENTS.md").read_text() == NOTE
    assert (REPO / "agents" / "CLAUDE.md").read_text() == NOTE


def test_note_files_existing_ones_or_a_new_agents_md(project):
    assert NOTE_FILES == ("AGENTS.md", "CLAUDE.md")
    assert note_files(project) == [project / "AGENTS.md"]
    (project / "CLAUDE.md").write_text("# Project\n")
    assert note_files(project) == [project / "CLAUDE.md"]
    (project / "AGENTS.md").write_text("# Team\n")
    assert note_files(project) == [project / "AGENTS.md", project / "CLAUDE.md"]


def test_offer_note_asks_first_appends_and_never_twice(project):
    (project / "CLAUDE.md").write_text("# Project\n\nRun make test.\n")
    out = []
    p = ScriptedPrompter([False])
    assert offer_note(project, p, out.append) == []
    assert p.asked == ["Add the signafAIde note to CLAUDE.md?"]
    assert (project / "CLAUDE.md").read_text() == "# Project\n\nRun make test.\n"
    assert not (project / "AGENTS.md").exists()
    assert offer_note(project, ScriptedPrompter([True]), out.append) == [("CLAUDE.md", "updated")]
    assert (project / "CLAUDE.md").read_text() == "# Project\n\nRun make test.\n\n" + note_section()
    p = ScriptedPrompter([])
    assert offer_note(project, p, out.append) == [] and p.asked == []
    # An older block is replaced in place.
    (project / "CLAUDE.md").write_text(f"a\n\n{SECTION_START}\n# old skill\n{SECTION_END}\n\nb\n")
    assert offer_note(project, ScriptedPrompter([True]), out.append) == [("CLAUDE.md", "updated")]
    assert (project / "CLAUDE.md").read_text() == f"a\n\n{note_section()}\nb\n"
    # The note pasted by hand, without the markers: left as it is.
    (project / "AGENTS.md").write_text(f"# Team\n\n{NOTE}")
    assert offer_note(project, ScriptedPrompter([]), out.append) == []
    assert (project / "AGENTS.md").read_text() == f"# Team\n\n{NOTE}"


# --- protect --yes --tool --limit-field --above ----------------------------------------------

def test_agent_run_without_a_key(flow, capsys):
    project, service = flow
    code, out = run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert code == 1, out  # not finished: the rule waits for a key
    assert "  Rule: Block approve_payout when amount is above 1,000" in out
    assert CALIBRATING_LINE in out
    assert "Rules      not saved yet: there is no key. It starts Calibrating once saved." in out
    assert "To finish: signafaide protect (in a terminal)" in out
    assert "signafaide login" not in out
    assert "@signafaide.protect(" in (project / "src" / "tools.py").read_text()
    assert json.loads((project / "signafaide.checks.json").read_text())["tools"]["approve_payout"] == {"protect": True, "mode": "watch"}  # watch: the kept rule blocks nothing
    assert (project / "AGENTS.md").read_text() == note_section()
    assert (project / "CLAUDE.md").read_text() == "@AGENTS.md\n"  # Claude Code reads the same note
    assert re.search(r"AGENTS\.md +signafAIde note for coding agents", out)
    assert ("POST", "/v1/sandbox") not in service.calls
    code, again = run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert "Agents     " not in again
    assert (project / "AGENTS.md").read_text().count(SECTION_START) == 1


def test_agent_run_adds_to_an_existing_claude_md_only(flow, capsys):
    project, _ = flow
    (project / "CLAUDE.md").write_text("# Project\n")
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert (project / "CLAUDE.md").read_text() == "# Project\n\n" + note_section()
    assert not (project / "AGENTS.md").exists()


def _today():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def test_agent_rule_is_kept_as_a_local_calibrating_rule_once(flow, capsys):
    project, _ = flow
    code, out = run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert "Kept in signafaide.checks.json as a local Calibrating rule (it blocks nothing)" in out
    file = json.loads((project / "signafaide.checks.json").read_text())
    assert file["tools"]["approve_payout"] == {"protect": True, "mode": "watch"}
    assert len(file["rules"]["rules"]) == 1
    assert file["rules"]["rules"][0]["id"] == "approve_payout-amount"
    assert file["rules"]["rules"][0]["when"] == [{"field": "/amount", "op": "gt", "value": 1000}]
    assert file["proposed"] == [{"rule": "approve_payout-amount", "by": "agent", "on": _today()}]
    assert C.checks_file_errors(file) is None
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    again = json.loads((project / "signafaide.checks.json").read_text())
    assert len(again["rules"]["rules"]) == 1 and len(again["proposed"]) == 1


def test_a_person_is_offered_the_proposal_and_it_is_used_up(flow, capsys):
    project, _ = flow
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    p = ScriptedPrompter([True, 1, False, True, True])
    code, out = run(capsys, "protect", "--tool", "approve_payout", prompter=p)
    offer = next(q for q in p.asked if "proposed this rule" in q)
    assert f"An agent run on {_today()} proposed this rule for approve_payout" in offer
    assert "Block approve_payout when amount is above 1,000" in offer
    assert not any(q.startswith("What should we block on") for q in p.asked)
    assert re.search(r"Rule: Block approve_payout when amount is above 1,000 +\(proposed by an agent run on \d{4}-\d{2}-\d{2}\)", out)
    file = json.loads((project / "signafaide.checks.json").read_text())
    assert "proposed" not in file and file["rules"] is None and "mode" not in file["tools"]["approve_payout"]


def test_a_person_can_drop_the_proposal(flow, capsys):
    project, _ = flow
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    p = ScriptedPrompter([False, 0, "500", 1, [False, False], False, True])
    code, out = run(capsys, "protect", "--tool", "approve_payout", prompter=p)
    assert "is dropped; asking as usual" in out
    assert any(q.startswith("What should we block on") for q in p.asked)
    assert "proposed" not in json.loads((project / "signafaide.checks.json").read_text())


def test_a_proposal_for_a_rule_that_is_not_there_is_an_error():
    file = to_version2(None)
    file["proposed"] = [{"rule": "nope", "by": "agent", "on": "2026-11-18"}]
    assert "proposed[0].rule must be the id of a rule in rules" in C.checks_file_errors(file)


def test_claude_md_gets_the_note_once_or_imports_agents_md(flow, capsys):
    project, _ = flow
    (project / "AGENTS.md").write_text("# Team\n\n" + note_section())
    (project / "CLAUDE.md").write_text("# Project\n")
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert (project / "CLAUDE.md").read_text() == "# Project\n\n" + note_section()
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert (project / "CLAUDE.md").read_text().count(SECTION_START) == 1
    (project / "CLAUDE.md").write_text("# Project\n\n@AGENTS.md\n")
    run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert (project / "CLAUDE.md").read_text() == "# Project\n\n@AGENTS.md\n"


def test_a_person_says_no_to_the_note(flow, capsys):
    project, _ = flow
    # On, sandbox no, write the code yes, note no
    code, out = run(capsys, "protect", "--tool", "approve_payout", "--limit-field", "amount", "--above", "500",
                    prompter=ScriptedPrompter([0, False, True, False]))
    assert "Not added; run this command again to add it." in out
    assert not (project / "AGENTS.md").exists()
    assert "Rules      not saved yet: there is no key." in out
    assert "It starts Calibrating once saved" not in out  # the person chose On


def test_a_field_the_tool_does_not_have(flow, capsys):
    code, out = run(capsys, "protect", "--yes", "--tool", "approve_payout", "--limit-field", "total", "--above", "5", prompter=FlagPrompter(yes=True))
    assert code == 0, out
    assert "approve_payout has no field named total (its fields: payee, amount, currency): no rule added." in out
    assert "approve_payout has no field named total, so no rule was added" in out


@pytest.mark.parametrize("args", [
    ["--limit-field", "amount"],
    ["--above", "5", "--tool", "approve_payout"],
    ["--limit-field", "amount", "--above", "1000"],
    ["--tool", "approve_payout", "--limit-field", "amount", "--above", "-3"],
    ["--tool", "approve_payout", "--limit-field", "amount", "--above", "lots"],
    ["lookup_invoice", "--tool", "approve_payout"],
])
def test_options_that_do_not_go_together(flow, capsys, args):
    project, _ = flow
    code, out = run(capsys, "protect", "--yes", *args, prompter=FlagPrompter(yes=True))
    assert code == 2 and out.startswith("signafaide protect: "), out
    assert not (project / "signafaide.checks.json").exists()


def test_agent_run_with_an_unclaimed_sandbox_saves_it_calibrating(flow, capsys):
    project, _ = flow
    runtime.get().create_sandbox()
    code, out = run(capsys, *AGENT_RUN, prompter=FlagPrompter(yes=True))
    assert code == 0, out
    assert "Rules      saved in your sandbox as version 1" in out
    assert CALIBRATING_LINE in out
    held = runtime.get().checks.held_rules()
    rule = next(r for r in held["rules"] if r["id"] == "approve_payout-amount")
    assert rule["when"] == [{"field": "/amount", "op": "gt", "value": 1000}]
    assert C.rule_state(held, rule) == "calibrating"


# --- init ------------------------------------------------------------------------------------

def test_init_adds_the_note_once(flow, capsys):
    project, _ = flow
    code, out = run(capsys, "init", prompter=FlagPrompter())
    assert code == 0, out
    assert "agents: AGENTS.md created, with the signafAIde note for coding agents (a marked block)" in out
    assert (project / "AGENTS.md").read_text() == note_section()
    code, out = run(capsys, "init", prompter=FlagPrompter())
    assert "agents: " not in out


# --- the fail-closed first run ---------------------------------------------------------------

def test_no_key_names_the_one_command_and_why(flow):
    project, _ = flow
    (project / "signafaide.checks.json").write_text(json.dumps(to_version2(None)))
    runtime.get().checks.forget()
    ran = []

    @protect(args=["amount"])
    def approve_payout(amount):
        ran.append(amount)

    with pytest.raises(SignafaideBlocked) as ei:
        approve_payout(5)
    assert ran == [] and ei.value.code == "no_key"
    msg = str(ei.value)
    assert msg.startswith("approve_payout did not run: protected tools stop until a person runs `signafaide protect` in this project, because "
                          "there is no signafAIde key or sandbox here yet to allow the call.")
    assert ". " not in msg.split("\n")[0]  # one sentence


def test_in_a_test_runner_it_still_runs(project, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_TEST", "1")
    r = runtime.configure(quiet=True, flush_interval=3600)
    try:
        @protect(args=["amount"])
        def approve_payout(amount):
            return f"paid {amount}"

        assert approve_payout(5) == "paid 5"
    finally:
        _stop(r)


def test_several_kept_rules_are_said_in_the_plural(flow, capsys):
    code, out = run(capsys, "protect", "--yes", prompter=FlagPrompter(yes=True))
    assert "Kept in signafaide.checks.json as local Calibrating rules (they block nothing)" in out
    assert "is offered them." in out
    assert "a local Calibrating rule" not in out
