"""``signafaide check --ci`` (#67 step 3, #61): risky tools not protected fail the check, one line
each with file:line, why and the fix; protected, allowed (with a reason) and reading tools pass;
``--diff`` keeps only the tools added or changed since a git base. The fixture is the Python
repository in action/test/fixtures/py-repo, copied to a temporary folder for each test."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from signafaide.checks import checks_file_errors
from signafaide.ci_check import ci_check, risk_of
from signafaide.cli import main
from signafaide.protect_cli import tool_kind

FIXTURE = Path(__file__).resolve().parents[2] / "action" / "test" / "fixtures" / "py-repo"


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.delenv("SIGNAFAIDE_CHECKS", raising=False)
    r = tmp_path / "repo"
    shutil.copytree(FIXTURE, r)
    return r


def cli(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def edit(root, rel, old, new):
    p = root / rel
    before = p.read_text()
    assert old in before
    p.write_text(before.replace(old, new, 1))


def checks(root):
    return json.loads((root / "signafaide.checks.json").read_text())


def save_checks(root, doc):
    (root / "signafaide.checks.json").write_text(json.dumps(doc, indent=2))


def git(root, *args):
    return subprocess.run(["git", "-c", "user.email=ci@example.com", "-c", "user.name=CI", "-c", "commit.gpgsign=false", *args], cwd=root, check=True,
                          capture_output=True, text=True).stdout


def protect_all(root):
    edit(root, "agent/tools.py", "def approve_payout(", '@signafaide.protect(agent="payout-bot")\ndef approve_payout(')
    edit(root, "agent/tools.py", "@tool\ndef git_push(", '@tool\n@signafaide.protect(agent="payout-bot")\ndef git_push(')
    edit(root, "agent/server.py", "@mcp.tool()\ndef send_email(", '@mcp.tool()\n@signafaide.protect(agent="payout-bot")\ndef send_email(')


def test_fails_on_risky_tools_not_protected_one_line_each(root, capsys):
    code, text = cli(capsys, "check", "--ci", "--dir", str(root))
    assert code == 1
    lines = text.splitlines()
    assert ('agent/tools.py:7: approve_payout pays money; not protected. Fix: add @signafaide.protect(agent="payout-bot") right above def approve_payout '
            "(or: signafaide protect --tool approve_payout)") in lines
    assert ('agent/tools.py:32: git_push pushes code; not protected. Fix: add @signafaide.protect(agent="payout-bot") right above def git_push '
            "(under the framework's decorator) (or: signafaide protect --tool git_push)") in lines
    assert any(ln.startswith("agent/server.py:6: send_email sends messages; not protected.") for ln in lines)
    for t in ("delete_payee", "send_receipt", "lookup_invoice"):
        assert f"{t} " not in text
    assert "agent/tools.py:25: run_migration runs commands; allowed (checks file): runs only the migration files kept in this repository; reviewed 18 Nov 2026" in lines
    assert "signafaide check --ci: failed. 3 risky tools not protected (of 6; 2 protected, 1 allowed; Python, 7 tools found)." in lines


def test_passes_when_every_risky_tool_is_protected(root, capsys):
    protect_all(root)
    code, text = cli(capsys, "check", "--ci", "--dir", str(root))
    assert code == 0
    assert "signafaide check --ci: passed. 6 risky tools: 5 protected, 1 allowed" in text
    assert "Fix:" not in text


def test_passes_with_reviewed_exceptions(root, capsys):
    doc = checks(root)
    doc["ci"]["allow"] += [{"tool": "approve_payout", "reason": "pays only our own test ledger"}, {"tool": "git_push", "reason": "pushes to a sandbox remote"},
                           {"tool": "send_email", "reason": "sends to the team only"}]
    save_checks(root, doc)
    code, text = cli(capsys, "check", "--ci", "--dir", str(root))
    assert code == 0
    assert "approve_payout pays money; allowed (checks file): pays only our own test ledger" in text
    shutil.copy(FIXTURE / "signafaide.checks.json", root / "signafaide.checks.json")
    code, text = cli(capsys, "check", "--ci", "--dir", str(root), "--allow", "approve_payout", "--allow", "git_push", "--allow", "send_email")
    assert code == 0
    assert "git_push pushes code; allowed (--allow): allowed on the command line (--allow)" in text


def test_recorded_is_not_protected_and_the_checks_file_counts_only_through_signafaide(root):
    doc = checks(root)
    doc["tools"]["send_receipt"] = {"protect": False}
    doc["tools"]["approve_payout"] = {"protect": True}
    save_checks(root, doc)
    r = ci_check(root)
    why = {u["tool"]: u["why"] for u in r.unprotected}
    assert why["send_receipt"] == "sends messages; recorded, not protected"
    assert why["approve_payout"] == "pays money; protected in signafaide.checks.json, but its code does not go through signafaide"
    # An MCP server tool goes through signafaide when the server runs through the gateway.
    doc["tools"]["send_email"] = {"protect": True}
    save_checks(root, doc)
    assert "send_email" not in {u["tool"] for u in ci_check(root).unprotected}


def test_a_block_rule_on_this_machine_in_enforce_mode_protects_a_recorded_tool(root):
    """What ``protect --local`` writes counts: the tool's entry in enforce mode and a local block rule
    naming it. Calibrating (watch mode) blocks nothing, and an allow rule protects nothing."""
    doc = checks(root)
    doc["tools"]["send_receipt"] = {"protect": False, "mode": "enforce"}
    rule = {"id": "send_receipt-to", "about": "send_receipt: to outside the company.", "action": "block", "tools": ["send_receipt"], "agents": None,
            "when": [{"field": "/to", "op": "eq", "value": "x@example.com"}]}
    doc["rules"] = {"default": "allow", "rules": [rule]}
    save_checks(root, doc)
    assert "send_receipt" not in {u["tool"] for u in ci_check(root).unprotected}
    doc["tools"]["send_receipt"] = {"protect": False, "mode": "watch"}
    save_checks(root, doc)
    assert {u["tool"]: u["why"] for u in ci_check(root).unprotected}["send_receipt"] == "sends messages; recorded, not protected"
    doc["tools"]["send_receipt"] = {"protect": False, "mode": "enforce"}
    doc["rules"]["rules"] = [dict(rule, action="allow")]
    save_checks(root, doc)
    assert {u["tool"]: u["why"] for u in ci_check(root).unprotected}["send_receipt"] == "sends messages; recorded, not protected"


def test_diff_reports_only_tools_added_or_changed(root, capsys):
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "checkout", "-q", "-b", "feature")
    edit(root, "agent/tools.py", "return payments.invoice(invoice_id)", "return payments.invoice(invoice_id.strip())")
    git(root, "commit", "-qam", "read only")
    code, text = cli(capsys, "check", "--ci", "--dir", str(root), "--diff", "main")
    assert code == 0
    assert "signafaide check --ci: passed. 0 risky tools added or changed since main" in text

    edit(root, "agent/tools.py", "tools = [", "def refund_order(order_id: str) -> dict:\n    return payments.payout(order_id, 1, \"GBP\")\n\n\ntools = [refund_order, ")
    git(root, "commit", "-qam", "refund")
    code, text = cli(capsys, "check", "--ci", "--dir", str(root), "--diff", "main")
    assert code == 1
    assert "agent/tools.py:29: refund_order pays money; not protected." in text
    assert "approve_payout" not in text and "git_push" not in text
    assert "1 risky tool added or changed since main not protected" in text

    git(root, "checkout", "-q", "main")
    git(root, "checkout", "-q", "-b", "loosen")
    edit(root, "agent/tools.py", '@signafaide.protect(agent="payout-bot")\ndef delete_payee', "def delete_payee")
    doc = checks(root)
    del doc["tools"]["send_receipt"]
    save_checks(root, doc)
    (root / "agent" / "settings.py").write_text("from langchain_core.tools import tool\n\n\n@tool\ndef update_secret(name: str, value: str) -> str:\n    \"\"\"Set a secret.\"\"\"\n    return name + value\n")
    code, text = cli(capsys, "check", "--ci", "--dir", str(root), "--diff", "main", "--json")
    assert code == 1
    r = json.loads(text)
    assert r["format"] == "signafaide-ci/1" and r["base"] == "main"
    assert sorted(u["tool"] for u in r["unprotected"]) == ["delete_payee", "send_receipt", "update_secret"]
    assert next(u for u in r["unprotected"] if u["tool"] == "update_secret") == {
        "tool": "update_secret", "file": "agent/settings.py", "line": 4, "why": "edits secrets; not protected",
        "fix": 'add @signafaide.protect(agent="payout-bot") right above def update_secret (under the framework\'s decorator) (or: signafaide protect --tool update_secret)',
        "shape": "function", "framework": "LangChain"}


def test_errors_exit_2(root, capsys):
    code, text = cli(capsys, "check", "--ci", "--dir", str(root), "--diff", "main")
    assert code == 2 and "--diff needs a git repository" in text
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    code, text = cli(capsys, "check", "--ci", "--dir", str(root), "--diff", "no-such-branch")
    assert code == 2 and "--diff no-such-branch: no such commit in this clone" in text
    doc = checks(root)
    doc["ci"]["allow"][0]["reason"] = " "
    save_checks(root, doc)
    code, text = cli(capsys, "check", "--ci", "--dir", str(root))
    assert code == 2 and "ci.allow[0].reason must say why the tool is allowed" in text
    assert cli(capsys, "check", "--ci", "approve_payout")[0] == 2
    assert cli(capsys, "check", "approve_payout", "--diff", "main")[0] == 2


def test_says_when_there_are_javascript_files(root):
    (root / "web.ts").write_text("export const x = 1;\n")
    assert ci_check(root).other == {"language": "javascript", "files": 1, "command": "npx signafaide check --ci"}


def test_what_looks_risky():
    def why(n):
        return risk_of(n, tool_kind(n))

    assert why("approve_payout") == "pays money"
    assert why("delete_payee") == "deletes data"
    assert why("send_receipt") == "sends messages"
    assert why("run_shell") == "runs commands"
    assert why("git_push") == "pushes code"
    assert why("createCommit") == "pushes code"
    assert why("update_secret") == "edits secrets"
    assert why("set_api_key") == "edits secrets"
    assert why("write_config") == "edits config"
    assert why("get_secret") is None
    assert why("lookup_invoice") is None
    assert why("create_ticket") is None


def test_the_checks_file_ci_key():
    base = {"format": "signafaide-checks/2", "checks": {"secret": True, "address": True, "changed_tool": True, "fingerprint": True, "hidden_instruction": True},
            "tools": {}, "addresses": {"hosts": [], "cidrs": [], "resolve": False}, "rules": None}
    assert checks_file_errors({**base, "ci": {"allow": [{"tool": "run_migration", "reason": "reviewed"}]}}) is None
    assert checks_file_errors({**base, "format": "signafaide-checks/1", "mode": "watch", "ci": {"allow": []}}) is None
    assert checks_file_errors({**base, "ci": {"allow": [{"tool": "x"}]}}) == "ci.allow[0] lacks the field 'reason'"
    assert checks_file_errors({**base, "ci": {"allow": [], "deny": []}}) == "ci has the unknown field 'deny'"
    assert checks_file_errors({**base, "ci": {"allow": [{"tool": "x", "reason": "a"}, {"tool": "x", "reason": "b"}]}}) == "ci.allow lists x twice"
    assert checks_file_errors({**base, "ci": []}) == 'ci must be {"allow": [{"tool", "reason"}]}'


def test_the_python_starter_template_passes_as_shipped():
    """templates/openai-agents-python: approve_payout is protected by the rule kept on the machine."""
    r = ci_check(Path(__file__).resolve().parents[2] / "templates" / "openai-agents-python")
    assert r.ok, r.unprotected
    assert r.protected == 1
