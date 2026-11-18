import json
import platform
import re

import pytest

import signafaide
from signafaide import runtime
from signafaide.cli import main
from signafaide.telemetry import client_header, detect_agent


def no_counts(line: str) -> str:
    """The result line without its check counts (§7), to compare the rest."""
    return re.sub(r": \d+ of 12 checks [^;]*; ", ": ", re.sub(r": \d+ of 12 checks [^;]*$", "", line))


@pytest.mark.parametrize(
    "env,agent",
    [
        ({"CLAUDECODE": "1"}, "claude-code"),
        ({"CLAUDE_CODE_ENTRYPOINT": "cli"}, "claude-code"),
        ({"CLAUDECODE": "1", "CODEX_COMPANION_SESSION_ID": "x", "TERM_PROGRAM": "cursor"}, "claude-code"),
        ({"CODEX_SANDBOX": "seatbelt"}, "codex"),
        ({"CODEX_COMPANION_SESSION_ID": "x"}, "unknown"),  # a Codex plugin for another agent, not Codex
        ({"CURSOR_TRACE_ID": "x"}, "cursor"),
        ({"TERM_PROGRAM": "cursor"}, "cursor"),
        ({"GEMINI_CLI": "1"}, "gemini-cli"),
        ({"COPILOT_AGENT": "1"}, "copilot"),
        ({"WINDSURF_SESSION": "1"}, "windsurf"),
        ({"TERM_PROGRAM": "vscode", "HOME": "/x"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_detect_agent(env, agent):
    assert detect_agent(env) == agent


def test_header_format_and_opt_out():
    v = re.escape(signafaide.__version__)
    py = re.escape(platform.python_version())
    h = client_header(via="cli", adapter="langchain", agent="codex", env={})
    assert re.fullmatch(rf"signafaide-python/{v} \(python {py}; adapter=langchain; agent=codex; via=cli\)", h)
    assert client_header(env={}) == f"signafaide-python/{signafaide.__version__} (python {platform.python_version()}; adapter=none; agent=unknown; via=sdk)"
    off = client_header(via="sdk", adapter="langchain", agent="codex", env={"SIGNAFAIDE_TELEMETRY": "0"})
    assert off == f"signafaide-python/{signafaide.__version__} (python {platform.python_version()}; via=sdk)"


def test_every_request_carries_the_header(recorder, service, monkeypatch):
    monkeypatch.setenv("CODEX_SANDBOX", "seatbelt")
    service.calls.clear()
    service.client_ids.clear()  # the sandbox was created before this test chose its agent
    signafaide.note("a", {})
    signafaide.flush()
    assert service.calls and len(service.client_ids) == len(service.calls)
    # Never guessed per process: a program started from a terminal inside a coding agent is not that agent.
    assert all(c and c.startswith("signafaide-python/") and c.endswith("agent=unknown; via=sdk)") for c in service.client_ids), (service.client_ids, service.calls)


def test_strict_flag_in_header(recorder, service):
    signafaide.record(lambda: 1, name="pay", strict=True)()
    assert service.client_ids[-1].endswith("via=sdk; strict=1)")
    assert client_header(strict=True, env={"SIGNAFAIDE_TELEMETRY": "0"}).endswith("(python " + platform.python_version() + "; via=sdk)")


def test_agent_stored_at_init_is_used_later(project, service, monkeypatch):
    monkeypatch.setenv("GEMINI_CLI", "1")
    rec = signafaide.init(url=service.url, quiet=True)
    assert not (rec.state.home / "config.json").exists()  # the library's init() does not guess
    rec.remember_agent()  # what `signafaide init` does
    assert json.loads((rec.state.home / "config.json").read_text())["agent"] == "gemini-cli"
    rec.create_sandbox()
    monkeypatch.delenv("GEMINI_CLI")  # later: running in production, no coding agent
    service.client_ids.clear()
    signafaide.note("a", {})
    signafaide.flush()
    assert service.client_ids and all("agent=gemini-cli" in c for c in service.client_ids)
    runtime._default = None


def test_adapter_field(recorder, service):
    lc = pytest.importorskip("langchain_core.tools")

    @lc.tool
    def echo(text: str) -> str:
        """Echo."""
        return text

    service.client_ids.clear()
    signafaide.wrap_tools([echo])[0].invoke({"text": "x"})
    signafaide.flush()
    assert service.client_ids and all("adapter=langchain;" in c for c in service.client_ids)


def test_opt_out(project, service, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_TELEMETRY", "0")
    monkeypatch.setenv("CLAUDECODE", "1")
    rec = signafaide.init(url=service.url, quiet=True)
    assert "agent" not in rec.state.config()
    rec.create_sandbox()
    signafaide.note("a", {})
    signafaide.flush()
    assert service.client_ids and all("agent=" not in c and "adapter=" not in c and c.startswith("signafaide-python/") for c in service.client_ids)
    runtime._default = None


@pytest.fixture
def cli(project, service, monkeypatch, capsys):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)

    def run(*args):
        return main(list(args)), capsys.readouterr()

    yield run
    runtime._default = None


def test_cli_reports_verify_and_export(cli, service, tmp_path):
    cli("init")
    signafaide.note("n", {})
    cli("flush")
    pack = tmp_path / "p.json"
    assert cli("export", "-o", str(pack))[0] == 0
    assert cli("verify", str(pack))[0] == 0
    assert service.events == ["export", "verify"]
    assert any("via=cli" in c for c in service.client_ids)


def test_cli_events_never_fail_the_command(cli, service, tmp_path, monkeypatch, dead_url):
    cli("init")
    signafaide.note("n", {})
    cli("flush")
    pack = tmp_path / "p.json"
    cli("export", "-o", str(pack))
    keys = tmp_path / "k.json"
    keys.write_text(json.dumps({"keys": [service.key_doc]}))
    monkeypatch.setenv("SIGNAFAIDE_URL", dead_url)  # the event cannot be delivered
    code, out = cli("verify", str(pack), "--keys", str(keys))
    # The result line, then the sandbox's claim step from sandbox.json (the witness cannot be asked).
    assert code == 0 and no_counts(out.out.strip().splitlines()[-4]).startswith("PASS: export of every agent, all records, generated ") and out.err == ""


def test_cli_opt_out_sends_no_events(cli, service, tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_TELEMETRY", "0")
    cli("init")
    signafaide.note("n", {})
    cli("flush")
    cli("export", "-o", str(tmp_path / "p.json"))
    cli("verify", str(tmp_path / "p.json"))
    assert service.events == []
