"""Console-made keys, claimed projects and state writes (0.5.1).

1. ``protect --yes`` with a console-made key: the console's origin is the hosted witness, and on a
   claimed project the default rules stay here as Calibrating local rules, with one console link.
2. State files are written under unique temp names: concurrent first calls never collide.
4. Under pytest a protected tool runs without a ruling, also when the recorder is made while
   pytest imports the test module (``declare_tools`` at import).
5. ``prove --days N`` says plainly when the witness gave the earlier link back.
6. Rate rules read as the console says them; an approved field is not called unapproved.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from signafaide import cli, runtime
from signafaide.decorator import record
from signafaide.http import DEFAULT_URL, witness_url
from signafaide.protect_cli import FlagPrompter, publisher
from signafaide.session import console_origin, person_witness
from signafaide.state import State, atomic_write
from signafaide.words import rule_words

from conftest import _recorder, _stop

AGENT_PY = '''"""A small support agent."""


def send_email(to: str, subject: str, body: str) -> str:
    return f"sent to {to}"


def issue_refund(order_id: str, amount: float, currency: str) -> str:
    return f"refunded {amount} {currency}"


def delete_customer_record(customer_id: str) -> str:
    return customer_id


def lookup_invoice(invoice_id: str) -> str:
    return invoice_id


tools = [send_email, issue_refund, delete_customer_record, lookup_invoice]


def main() -> None:
    raise SystemExit(0)


if __name__ == "__main__":
    main()
'''


@pytest.fixture
def flow(project, service, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    (project / "agent.py").write_text(AGENT_PY)
    (project / "pyproject.toml").write_text('[project]\nname = "support-bot"\nversion = "1.0.0"\n')
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


def the_project(service) -> dict:
    return next(iter(service.projects.values()))


# --- 1a: the hosted witness by either address ----------------------------------------------------


def test_the_consoles_origin_is_the_hosted_witness(monkeypatch):
    for u in (
        "https://signafaide.co.uk",
        "https://signafaide.co.uk/",
        " https://SIGNAFAIDE.co.uk ",
        "https://api.signafaide.co.uk/",
    ):
        assert witness_url(u) == DEFAULT_URL
    assert witness_url("http://127.0.0.1:7484/") == "http://127.0.0.1:7484"
    assert person_witness("https://signafaide.co.uk") == DEFAULT_URL
    monkeypatch.setenv("SIGNAFAIDE_URL", "https://signafaide.co.uk/")
    assert person_witness() == DEFAULT_URL
    assert console_origin("https://signafaide.co.uk") == "https://signafaide.co.uk"


def test_a_dotenv_naming_the_hosted_service_blocks_nothing(project, monkeypatch):
    monkeypatch.delenv("SIGNAFAIDE_URL", raising=False)
    (project / ".env").write_text("SIGNAFAIDE_URL=https://signafaide.co.uk\n")
    rec = runtime.configure(quiet=True, flush_interval=3600)
    try:
        assert rec.url == DEFAULT_URL
        # No key here, so nothing is asked of the network: the only reason left is the key's.
        assert publisher(rec) == "there is no API key"
    finally:
        _stop(rec)


def test_a_dotenv_naming_another_witness_still_saves_nothing_there(project, monkeypatch):
    monkeypatch.delenv("SIGNAFAIDE_URL", raising=False)
    (project / ".env").write_text("SIGNAFAIDE_URL=https://witness.example\n")
    rec = runtime.configure(quiet=True, flush_interval=3600)
    try:
        assert publisher(rec).startswith("SIGNAFAIDE_URL in the project's .env names https://witness.example")
    finally:
        _stop(rec)


# --- 1b and 6: protect --yes on a claimed project ------------------------------------------------


def add_links(out: str):
    """The add links in *out*, as a person reads them."""
    return re.findall(r"https?://\S+/tools/\S+\?add=\S+", out)


def test_claimed_keeps_the_defaults_and_prints_one_link_per_tool_from_the_witness(flow, capsys):
    project, service = flow
    runtime.get().create_sandbox()
    the_project(service)["claimed"] = True
    code, out = run(capsys, "protect", "--yes", prompter=FlagPrompter(yes=True))
    assert code == 1, out
    assert not re.search(r"Rules\s+saved", out)
    assert "Rules      kept in signafaide.checks.json as Calibrating (they block nothing). An API key" in out
    assert "cannot save rules in a project of an organisation: a person adds each one in the" in out
    tools = f"{service.url}/app/p/{the_project(service)['project']}/test/tools"
    links = add_links(out)
    assert len(links) == 3, out
    for t in ("send_email", "issue_refund", "delete_customer_record"):
        assert f"           Add {t}'s rule: {tools}/support-bot/{t}?add=" in out
    import urllib.parse

    rule = json.loads(
        urllib.parse.unquote(next(u for u in links if "/delete_customer_record?add=" in u).split("?add=")[1])
    )
    assert rule == {
        "id": "delete_customer_record-rate",
        "about": "delete_customer_record: more than 5 calls a minute.",
        "action": "block",
        "tools": ["delete_customer_record"],
        "agents": None,
        "when": [],
        "limit": {"calls": 5, "seconds": 60, "per": "agent_tool"},
    }
    assert "  - the rules are not saved for the project: a person adds each one in the console (the links above)" in out
    text = (project / "signafaide.checks.json").read_text()
    f = json.loads(text)
    assert [r["id"] for r in f["rules"]["rules"]] == ["issue_refund-amount"]
    ids = sorted(p["rule"] if isinstance(p["rule"], str) else p["rule"]["id"] for p in f["proposed"])
    assert ids == ["delete_customer_record-rate", "issue_refund-amount", "send_email-rate"]
    for t in ("send_email", "issue_refund", "delete_customer_record"):
        assert re.search(rf'"tools":\s*\[\s*"{t}"', text), t
    assert f["tools"]["issue_refund"]["protect"] is True and f["tools"]["issue_refund"]["mode"] == "watch"
    # Calibrating: a call the rule would stop still runs.
    code, out = run(capsys, "check", "issue_refund", "amount=1200", "currency=GBP")
    assert code == 0, out


def test_the_links_are_the_same_as_the_js_sdks():
    from signafaide.protect_cli import add_link

    r = {
        "id": "x-rate",
        "about": "x: more than 5 calls a minute.",
        "action": "block",
        "tools": ["x"],
        "agents": None,
        "when": [],
        "limit": {"calls": 5, "seconds": 60, "per": "agent_tool"},
        "state": "calibrating",
    }
    # encodeURIComponent(JSON.stringify(...)) in JavaScript gives exactly this.
    assert add_link("https://signafaide.co.uk/app/p/prj_X/test/tools/", "ops-bot", r) == (
        "https://signafaide.co.uk/app/p/prj_X/test/tools/ops-bot/x?add=%7B%22id%22%3A%22x-rate%22%2C%22about%22%3A%22x%3A%20more%20than%205%20calls%20a%20minute.%22%2C"
        "%22action%22%3A%22block%22%2C%22tools%22%3A%5B%22x%22%5D%2C%22agents%22%3Anull%2C%22when%22%3A%5B%5D%2C%22limit%22%3A%7B%22calls%22%3A5%2C%22seconds%22%3A60%2C%22per%22%3A%22agent_tool%22%7D%7D"
    )


def test_a_kept_rate_rule_is_offered_to_a_person_later(flow, capsys):
    project, service = flow
    runtime.get().create_sandbox()
    the_project(service)["claimed"] = True
    run(capsys, "protect", "delete_customer_record", "--yes", prompter=FlagPrompter(yes=True))
    from signafaide.protect_cli import proposal_for

    f = json.loads((project / "signafaide.checks.json").read_text())
    assert f["proposed"][0]["rule"]["limit"] == {"calls": 5, "seconds": 60, "per": "agent_tool"}
    assert proposal_for(f, "delete_customer_record")[0]["id"] == "delete_customer_record-rate"
    assert proposal_for(f, "send_email") is None


def test_a_dotenv_naming_another_witness_gives_no_link(flow, capsys, monkeypatch):
    project, service = flow
    runtime.get().create_sandbox()
    the_project(service)["claimed"] = True
    url = os.environ["SIGNAFAIDE_URL"]
    monkeypatch.delenv("SIGNAFAIDE_URL")
    with open(project / ".env", "a") as fh:
        fh.write(f"SIGNAFAIDE_URL={url}\n")
    _stop(runtime.get())
    runtime.configure(quiet=True, flush_interval=3600)
    code, out = run(capsys, "protect", "issue_refund", "--yes", prompter=FlagPrompter(yes=True))
    assert code == 1, out
    assert "Rules      not saved: SIGNAFAIDE_URL in the project's .env names" in out
    assert add_links(out) == []
    assert "Kept in signafaide.checks.json as Calibrating (they block nothing)" in out


def test_limit_field_on_a_claimed_project_does_not_call_an_approved_field_unapproved(flow, capsys):
    project, service = flow
    runtime.get().create_sandbox()
    run(capsys, "protect", "issue_refund", "--yes", prompter=FlagPrompter(yes=True))
    # A person approved sending amount at a terminal (`pull`).
    f = json.loads((project / "signafaide.checks.json").read_text())
    f["tools"]["issue_refund"] = {"protect": True, "disclose": ["/amount"]}
    (project / "signafaide.checks.json").write_text(json.dumps(f, indent=2))
    the_project(service)["claimed"] = True
    code, out = run(
        capsys,
        "protect",
        "issue_refund",
        "--limit-field",
        "amount",
        "--above",
        "5",
        "--yes",
        prompter=FlagPrompter(yes=True),
    )
    assert code == 1, out
    assert not re.search(r"Rules\s+saved", out) and len(add_links(out)) == 1, out
    assert not re.search(r"sending amount .*is not approved", out), out
    assert "Sends to signafAIde when issue_refund runs: amount (approved earlier; the fields your rule needs)" in out
    assert json.loads((project / "signafaide.checks.json").read_text())["tools"]["issue_refund"]["disclose"] == [
        "/amount"
    ]


# --- 6: rate rules in the console's words --------------------------------------------------------


def test_rate_rules_read_as_the_console_says_them():
    def rate(seconds, calls=5):
        return {
            "id": "r",
            "action": "block",
            "tools": ["delete_account"],
            "agents": None,
            "when": [],
            "limit": {"calls": calls, "seconds": seconds, "per": "agent_tool"},
        }

    tail = "by the same agent to the same tool"
    assert rule_words(rate(60)) == f"Block delete_account when more than 5 calls in 1 minute {tail}"
    assert rule_words(rate(300)) == f"Block delete_account when more than 5 calls in 5 minutes {tail}"
    assert rule_words(rate(3600)) == f"Block delete_account when more than 5 calls in 1 hour {tail}"
    assert (
        rule_words(rate(86_400, 1_000_000)) == f"Block delete_account when more than 1,000,000 calls in 24 hours {tail}"
    )
    assert rule_words(rate(90)) == f"Block delete_account when more than 5 calls in 90 seconds {tail}"
    assert rule_words(rate(1, 1)) == f"Block delete_account when more than 1 call in 1 second {tail}"


# --- 2: concurrent first calls -------------------------------------------------------------------


def test_threads_writing_the_same_state_file_all_succeed(tmp_path):
    st = State(tmp_path / ".signafaide", tmp_path)
    errors = []
    start = threading.Barrier(8)

    def writer(n):
        start.wait()
        for i in range(200):
            try:
                st.save_config(**{f"w{n}": i})
                st.save_sandbox({"n": i})
            except Exception as e:  # noqa: BLE001 - every failure is the finding
                errors.append(repr(e))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert [p.name for p in (tmp_path / ".signafaide").iterdir() if p.name.endswith(".tmp")] == []
    config = json.loads((tmp_path / ".signafaide" / "config.json").read_text())
    assert {f"w{n}" for n in range(8)} <= set(config)  # no thread's value was lost


def test_concurrent_first_calls_of_a_recorded_tool(project, service, monkeypatch):
    rec = _recorder(service, monkeypatch, opt_in=True)
    try:

        @record(agent="claims-bot")
        def lookup(n: int) -> int:
            return n

        errors, start = [], threading.Barrier(8)

        def call(n):
            start.wait()
            try:
                for i in range(20):
                    lookup(n * 100 + i)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=call, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        # The shipper may be writing a file this moment (under its lock): none is left behind.
        rec.flush()
        deadline = time.monotonic() + 5
        while list(Path(rec.state.home).rglob("*.tmp")) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not list(Path(rec.state.home).rglob("*.tmp"))
    finally:
        _stop(rec)


def test_atomic_write_uses_a_unique_name_in_the_same_folder(tmp_path, monkeypatch):
    seen = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (seen.append(str(a)), real(a, b))[1])
    p = tmp_path / "config.json"
    for i in range(20):
        atomic_write(p, f'{{"n": {i}}}\n')
    mine = [s for s in seen if Path(s).parent == tmp_path]
    assert len(mine) == 20 and len(set(mine)) == 20
    assert p.read_text() == '{"n": 19}\n'
    assert [x.name for x in tmp_path.iterdir()] == ["config.json"]


# --- 4: pytest ------------------------------------------------------------------------------------

TOOLS_PY = """import signafaide


@signafaide.protect(agent="payout-bot")
def approve_payout(payee: str, amount: float, currency: str) -> str:
    return f"paid {amount:g} {currency} to {payee}"


# At import, as protect writes it: the recorder is made while pytest collects the tests.
signafaide.declare_tools(["approve_payout"], agent="payout-bot")
"""

TEST_PY = """import tools


def test_a_large_payout_runs_in_a_unit_test():
    assert "paid 1200 GBP" in tools.approve_payout("Ashgrove Catering Ltd", 1200, "GBP")
"""


def test_under_pytest_a_protected_tool_runs_without_a_ruling(tmp_path):
    root = tmp_path / "payout"
    (root / ".git").mkdir(parents=True)
    (root / "tools.py").write_text(TOOLS_PY)
    (root / "test_tools.py").write_text(TEST_PY)
    # A key, but no witness to ask: outside test mode the call would wait for a ruling and stop.
    (root / ".env").write_text("SIGNAFAIDE_API_KEY=sfa_test_" + "0" * 32 + "\nSIGNAFAIDE_URL=http://127.0.0.1:9\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SIGNAFAIDE_", "PYTEST_"))}
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_tools.py"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (root / ".signafaide").exists()  # test mode keeps nothing in the project


def test_never_with_a_live_key(tmp_path):
    root = tmp_path / "payout"
    (root / ".git").mkdir(parents=True)
    (root / "tools.py").write_text(TOOLS_PY)
    (root / "test_tools.py").write_text(TEST_PY)
    (root / ".env").write_text("SIGNAFAIDE_API_KEY=sfa_live_" + "0" * 32 + "\nSIGNAFAIDE_URL=http://127.0.0.1:9\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SIGNAFAIDE_", "PYTEST_"))}
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_tools.py"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 1 and "approve_payout did not run" in r.stdout, r.stdout + r.stderr


def test_under_pytest_from_the_start_of_the_run(monkeypatch):
    for k in ("PYTEST_CURRENT_TEST", "PYTEST_VERSION", "PYTEST_XDIST_WORKER", "SIGNAFAIDE_TEST"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(sys, "argv", ["/venv/bin/pytest", "-q"])
    assert runtime.under_pytest() and runtime.test_mode("")
    monkeypatch.setattr(sys, "argv", ["/venv/lib/python3.12/site-packages/pytest/__main__.py", "-q"])
    assert runtime.under_pytest()
    monkeypatch.setattr(sys, "argv", ["app.py"])
    assert not runtime.under_pytest()  # pytest imported by other code turns nothing on
    monkeypatch.setenv("PYTEST_VERSION", "9.0.0")
    assert runtime.under_pytest() and runtime.test_mode("sfa_test_x") and not runtime.test_mode("sfa_live_x")
    monkeypatch.setenv("SIGNAFAIDE_TEST", "0")
    assert not runtime.test_mode("")


# --- 5: prove --days ------------------------------------------------------------------------------


def _ready(service, monkeypatch):
    rec = runtime.get()
    rec.create_sandbox()

    @record(agent="payout-bot")
    def approve_payout(amount: float) -> float:
        return amount

    approve_payout(10)
    rec.flush()


def test_prove_days_says_when_the_earlier_link_is_given_back(flow, capsys, monkeypatch):
    project, service = flow
    _ready(service, monkeypatch)
    service.auditor_reuse = True
    code, out = run(capsys, "prove", "approve_payout", "--days", "7")
    assert code == 0, out
    assert "Send this link to your auditor:" in out and "this is not a new link" not in out
    code, out = run(capsys, "prove", "approve_payout", "--days", "3")
    assert code == 0, out
    assert "Send this link to your auditor (made earlier, still open):" in out
    assert re.search(
        r"You asked for 3 days: this is not a new link\. The link made earlier is reused, open until \d+ \w+ \d{4}, "
        r"because an unclaimed sandbox's plan allows one active link\.",
        out,
    ), out
    assert "For a new link: keep the sandbox (the claim link from init), then revoke this one in the console" in out
    assert "then run signafaide prove approve_payout --days 3 again." in out
    the_project(service)["claimed"] = True
    code, out = run(capsys, "prove", "approve_payout", "--days", "3")
    assert "because the witness gives this API key its open link again for the same agent, tool and start." in out
    assert "For a new link: revoke this one in the console" in out


def test_prove_days_a_new_link_says_nothing_of_the_kind(flow, capsys, monkeypatch):
    project, service = flow
    _ready(service, monkeypatch)
    run(capsys, "prove", "approve_payout", "--days", "7")
    code, out = run(capsys, "prove", "approve_payout", "--days", "3")
    assert "Send this link to your auditor:" in out and "this is not a new link" not in out
    assert service.auditor_links[-1]["days"] == 3
