"""The protect setup, as in the TypeScript SDK:
protected calls always ask the witness, retries within the ruling window and plain quota words,
``protect`` writing code with a diff first and keeping options, one-object tools, framework tool
discovery, one agent name in every call written, ``prove`` within the plan's limits with the agent
keys, and the words of a partial setup."""

import importlib.util
import json
import re
import time

import pytest

from signafaide import cli, runtime
from signafaide.checks_runtime import SignafaideBlocked
from signafaide.protect_cli import FlagPrompter, Prompter, ScriptedPrompter, code_changes, find_tools

from conftest import _recorder, _stop

TOOLS_PY = '''"""Payout tools."""
from __future__ import annotations

# Pays a supplier. Docs: https://example.test/payouts # not a comment to cut


async def approve_payout(payee: str, amount: float, currency: str) -> str:
    memo = "a # inside a string"
    return f"paid {amount} {currency} to {payee}"


def delete_payee(payee_id: str) -> str:
    return payee_id


def send_receipt(to: str, body: str) -> str:
    return to


def lookup_invoice(invoice_id: str) -> str:
    return invoice_id
'''

#: approve_payout only, block above 1000, On, also calibrate currency, a sandbox, write.
ANSWERS = [[True, False, False, False], 0, "1000", 0, [True, False], True, True]


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


class Recording(Prompter):
    """Answers like ScriptedPrompter and keeps every question's choices."""

    person = True

    def __init__(self, answers):
        self.inner = ScriptedPrompter(answers)
        self.choices = {}

    def confirm(self, q, d):
        return self.inner.confirm(q, d)

    def text(self, q, d=None):
        return self.inner.text(q, d)

    def choose(self, q, c, d):
        self.choices[q] = c
        return self.inner.choose(q, c, d)

    def multi(self, q, c, d):
        self.choices[q] = c
        return self.inner.multi(q, c, d)


def load(project, name="tools"):
    import sys

    modname = f"{name}_{time.monotonic_ns()}"
    spec = importlib.util.spec_from_file_location(modname, project / "src" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod  # dataclasses look their module up
    spec.loader.exec_module(mod)
    return mod


# --- protect writes the code, one-object tools, one agent ------------


def test_files_named_like_tools_diff_first_comments_kept(flow, capsys):
    project, _ = flow
    code, text = run(capsys, "protect", prompter=ScriptedPrompter(ANSWERS))
    assert code == 0, text
    assert "Change     src/tools.py" in text
    assert '  +@signafaide.protect(agent="payout-bot")' in text
    src = (project / "src" / "tools.py").read_text()
    assert "# Pays a supplier. Docs: https://example.test/payouts # not a comment to cut" in src
    assert 'memo = "a # inside a string"' in src
    assert '@signafaide.protect(agent="payout-bot")\nasync def approve_payout(' in src
    assert (
        'signafaide.declare_tools(["approve_payout", "delete_payee", "send_receipt", "lookup_invoice"], agent="payout-bot")'
        in src
    )
    assert "Done. Check a call without running it:" in text
    assert code_changes(find_tools(project), {"approve_payout"}, "payout-bot", project) == []


def test_one_object_argument_full_menu(flow, capsys):
    project, _ = flow
    (project / "src" / "tools.py").write_text("""from dataclasses import dataclass


@dataclass
class Payout:
    payee: str
    amount: float
    currency: str


def approve_payout(payout: Payout) -> str:
    return f"paid {payout.amount}"
""")
    p = Recording([[True], 0, "1000", 0, [True, False], True, True])
    code, text = run(capsys, "protect", prompter=p)
    assert code == 0, text
    assert p.choices["What should we block on approve_payout?"] == [
        "Payouts above an amount",
        "Payouts in other currencies",
        "More than a number of calls a minute",
        "Nothing yet, record only",
    ]
    rs = runtime.get().checks.held_rules()
    assert rs["rules"][0]["when"] == [{"field": "/payout/amount", "op": "gt", "value": 1000}]
    assert "Never sent to signafAIde: payee." in text
    mod = load(project)
    with pytest.raises(SignafaideBlocked):
        mod.approve_payout(mod.Payout("x", 5000, "GBP"))
    assert mod.approve_payout(mod.Payout("x", 10, "GBP")) == "paid 10"


def test_object_fields_asked(flow, capsys):
    project, _ = flow
    (project / "src" / "tools.py").write_text("def charge(req: dict) -> str:\n    return 'ok'\n")
    p = Recording([[True], "amount, currency", 0, "500", 1, [False, False], True, True])
    code, text = run(capsys, "protect", prompter=p)
    assert code == 0, text
    assert p.choices["What should we block on charge?"][0] == "Payouts above an amount"
    assert runtime.get().checks.held_rules()["rules"][0]["when"] == [{"field": "/req/amount", "op": "gt", "value": 500}]


def test_options_kept_and_the_agent_the_code_names(flow, capsys):
    project, _ = flow
    (project / "src" / "tools.py").write_text("""import signafaide


@signafaide.record(agent="billing-agent", store_content=True)
def approve_payout(payee: str, amount: float, currency: str) -> str:
    return "paid"


def lookup_invoice(invoice_id: str) -> str:
    return invoice_id


tools = [approve_payout, lookup_invoice]
""")
    (project / "src" / "main.py").write_text(
        "import signafaide\nfrom tools import tools\n\nsignafaide.declare_tools([t.__name__ for t in tools])\n"
    )
    f = find_tools(project)
    changes = {c.file.name: c.after for c in code_changes(f, {"approve_payout"}, "billing-agent", project)}
    assert '@signafaide.protect(agent="billing-agent", store_content=True)\ndef approve_payout(' in changes["tools.py"]
    assert "declare_tools(" not in changes["tools.py"]
    assert 'signafaide.declare_tools([t.__name__ for t in tools], agent="billing-agent")' in changes["main.py"]
    code, text = run(capsys, "protect", prompter=ScriptedPrompter([[True, False], 3, True, True, True]))
    assert "Agent      billing-agent (the name the code already uses)" in text


# --- discovery -----------------------------------------------------------------------


def test_framework_tools_and_not_classified(flow, capsys):
    project, _ = flow
    (project / "src" / "tools.py").unlink()
    (project / "src" / "agent.py").write_text('''from langchain_core.tools import tool, StructuredTool
from agents import function_tool
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@tool
def execute_sql(query: str) -> str:
    """Run SQL."""
    return query


@function_tool
def transfer(to: str, amount: float) -> str:
    return to


@mcp.tool()
def write_file(path: str, text: str) -> str:
    return path


def frobnicate(x: int) -> int:
    return x


def _update_account(account_id: str, email: str) -> str:
    return account_id


update = StructuredTool.from_function(func=_update_account, name="update_account")


class BillingTools:
    def refund_order(self, order_id: str, amount: float) -> str:
        return order_id

    def _helper(self):
        pass
''')
    f = find_tools(project)
    got = {t.name: (t.kind, t.framework, t.shape, [n for n, _ in t.fields]) for t in f.tools}
    assert got == {
        "execute_sql": ("runs", "LangChain", "function", ["query"]),
        "transfer": ("pays", "OpenAI Agents", "function", ["to", "amount"]),
        "write_file": ("changes", "MCP server", "function", ["path", "text"]),
        "update_account": ("changes", "LangChain", "function", ["account_id", "email"]),
        "refund_order": ("pays", None, "method", ["order_id", "amount"]),
    }
    p = Recording([[True, False, False, False, False], 1, True])
    code, text = run(capsys, "protect", "--local", prompter=p)
    assert len(p.choices[next(k for k in p.choices if k.startswith("Protect which tools?"))]) == 5
    assert not re.search(r"execute_sql\s+reads only", text)
    src = (project / "src" / "agent.py").read_text()
    # Under the framework's decorator, so the framework still reads the signature.
    assert '@tool\n@signafaide.record(agent="payout-bot")\ndef execute_sql(' in src
    assert '    @signafaide.record(agent="payout-bot")\n    def refund_order(self' in src
    (project / "src" / "more_tools.py").write_text("def frobnicate(x: int) -> int:\n    return x\n")
    f = find_tools(project, "frobnicate")
    assert [(t.name, t.kind) for t in f.tools] == [("frobnicate", "other")]
    code, text = run(capsys, "protect", "frobnicate", "--local", prompter=ScriptedPrompter([1, True]))
    assert re.search(r"frobnicate\s+not classified\s+record", text), text


# --- protected calls always ask the witness, retries --------------------------


def _protected(flow, capsys):
    project, service = flow
    assert run(capsys, "protect", prompter=ScriptedPrompter(ANSWERS))[0] == 0
    return project, service, load(project)


def test_limit_raised_after_the_version_held_here(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    rec = runtime.get()
    v1 = rec.checks.held_rules()
    rules = [
        dict(r, when=[{"field": "/amount", "op": "gt", "value": 2000}]) if r["id"] == "approve_payout-amount" else r
        for r in v1["rules"]
    ]
    service.publish_rules(rec.api_key, rules, set_id=v1["set"])
    assert rec.checks.held_rules()["version"] == 1
    assert (
        asyncio.run(mod.approve_payout("Harbour Lane Supplies Ltd", 1200, "GBP"))
        == "paid 1200 GBP to Harbour Lane Supplies Ltd"
    )


def test_local_checks_still_block_here(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    secret = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    with pytest.raises(SignafaideBlocked) as ei:
        asyncio.run(mod.approve_payout(f"pay {secret}", 10, "GBP"))
    assert ei.value.check == "secret" and ei.value.ruled_by == "client"
    assert str(ei.value).startswith("approve_payout did not run: its arguments hold a secret")


def test_unreachable_held_rules_block_else_the_setting(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    rec = runtime.get()
    v1 = rec.checks.held_rules()
    service.publish_rules(rec.api_key, v1["rules"], set_id=v1["set"], fail={"approve_payout": "open"})
    rec.checks.pull_rules()
    f = project / "signafaide.checks.json"
    f.write_text(json.dumps({**json.loads(f.read_text()), "ruling_timeout_ms": 1200}))
    rec.checks.forget()
    service.fail_always = (503, {"error": {"code": "unavailable", "message": "restarting"}})
    with pytest.raises(SignafaideBlocked) as ei:
        asyncio.run(mod.approve_payout("x", 5000, "GBP"))
    assert str(ei.value).startswith(
        "approve_payout did not run: signafAIde did not rule on it, and the signed rule set version 2 held here blocks it "
        '("Block approve_payout when amount is above 1,000"). To allow such calls, change the rule in the console.'
    )
    assert asyncio.run(mod.approve_payout("x", 10, "GBP")) == "paid 10 GBP to x"


def test_short_restart_retried(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    service.fail = (503, {"error": {"code": "unavailable", "message": "restarting"}})
    assert asyncio.run(mod.approve_payout("x", 10, "GBP")) == "paid 10 GBP to x"
    assert sum(1 for c in service.calls if c == ("POST", "/v1/records")) >= 2


def test_quota_used_up_in_plain_words(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    service.quota = 0
    t0 = time.monotonic()
    with pytest.raises(SignafaideBlocked) as ei:
        asyncio.run(mod.approve_payout("x", 10, "GBP"))
    assert time.monotonic() - t0 < 5
    assert ei.value.code == "quota_exceeded"
    assert re.match(
        r"^approve_payout did not run: signafAIde could not rule on it: the sandbox's records for this month are used up \(quota_exceeded\)\. "
        r"Keep the sandbox and choose a plan at http",
        str(ei.value),
    ), str(ei.value)
    assert "no receipt came within" not in str(ei.value)


# --- prove ---------------------------------------------------------------------------


def test_prove_plan_limit_keys_reuse_days(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    asyncio.run(mod.approve_payout("x", 10, "GBP"))
    runtime.get().flush()
    service.auditor_max_days = 7
    code, out = run(capsys, "prove", "approve_payout")
    assert code == 0, out
    assert "They can check it in their browser; nothing to install." in out
    body = service.auditor_links[0]
    assert body["days"] == 7 and body["agent"] == "payout-bot" and body["tool"] == "approve_payout"
    assert [k["agent"] for k in body["agent_keys"]["keys"]] == ["payout-bot"]
    assert "payout-bot" in next(iter(next(iter(body["head"].values())).values()))
    code, out = run(capsys, "prove", "approve_payout")
    assert "Send this link to your auditor (made earlier, still open):" in out and len(service.auditor_links) == 1
    code, out = run(capsys, "prove", "approve_payout", "--days", "3")
    assert code == 0 and service.auditor_links[-1]["days"] == 3
    code, out = run(capsys, "prove", "approve_payout", "--days", "20")
    assert "this plan's links last at most 7 days (signafaide prove --days 7)" in out


def test_prove_limit_in_words_and_no_keys_taken(flow, capsys):
    import asyncio

    project, service, mod = _protected(flow, capsys)
    asyncio.run(mod.approve_payout("x", 10, "GBP"))
    runtime.get().flush()
    service.auditor_max_days, service.auditor_max_in_body, service.auditor_links_no_keys = 7, False, True
    code, out = run(capsys, "prove", "approve_payout")
    assert code == 0, out
    assert service.auditor_links[-1]["days"] == 7 and "agent_keys" not in service.auditor_links[-1]
    assert "signafaide keys export -o agent-keys.json" in out


# --- a partial setup is never Done, the .env line -----------------------------


def test_partial_setup_not_done(flow, capsys):
    code, out = run(capsys, "protect", prompter=FlagPrompter(yes=True))
    assert not re.search(r"^Done\.", out, re.M)
    assert (
        "Not finished. Done: checks file signafaide.checks.json, code in src/tools.py, the note in AGENTS.md, the note in CLAUDE.md."
        in out
    )
    assert "  - no sandbox and no API key, so protected tools stop until there is one" in out
    assert "To finish: signafaide protect (in a terminal)" in out


def test_env_line_only_when_true(flow, capsys, monkeypatch):
    project, service = flow
    rec = runtime.get()
    rec.create_sandbox()
    key = rec.api_key
    (project / ".env").write_text("OTHER=1\n")
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", key)
    code, out = run(capsys, "protect", prompter=ScriptedPrompter([[True, False, False, False], 3, True]))
    assert "already in .gitignore" not in out
    (project / ".env").write_text(f"SIGNAFAIDE_API_KEY={key}\n")
    (project / ".gitignore").write_text(".signafaide/\n")
    code, out = run(capsys, "protect", prompter=ScriptedPrompter([[True, False, False, False], 3]))
    assert ".env is NOT in .gitignore" in out
