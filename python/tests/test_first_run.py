"""`protect --yes`, tool declarations, proxies and keys found in code (0.5.1).

1. ``protect --yes`` saves default rules for every risky tool, all Calibrating.
2. Without a terminal every risky tool is protected, not only the first.
3. ``declare_tools`` goes before a main guard (and is moved there when it is after one).
4. A proxy or network policy that blocks the witness is said in one plain sentence.
5. ``protect`` in a folder that is not a git repository prints nothing from git.
6. and 7. A tool protected in code is protected everywhere, and checked here, without a checks file.
8. A key next to ``=``, ``:``, quotes, brackets, URL delimiters, ``_`` or ``-`` is found.
"""

import importlib.util
import json
import os
import shutil
import stat
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from signafaide import checks as C
from signafaide import cli, runtime
from signafaide.checks_runtime import SignafaideBlocked
from signafaide.decorator import protect
from signafaide.http import Client, SignafaideError, network_blocked_words
from signafaide.protect_cli import FlagPrompter, place_declaration

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

#: A made-up AWS access key, built from parts so no whole key is in this file.
AWS = "".join(("AK", "IA", "QX7M2", "ZP4LD9", "RT3WN"))


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


# --- 1 and 2: protect --yes ----------------------------------------------------------------------


def test_yes_protects_every_risky_tool_and_saves_calibrating_defaults(flow, capsys):
    project, service = flow
    runtime.get().create_sandbox()
    code, out = run(capsys, "protect", "--yes", prompter=FlagPrompter(yes=True))
    assert "no rule was chosen" not in out
    assert "Protect    send_email, issue_refund, delete_customer_record: without a terminal" in out
    text = (project / "agent.py").read_text()
    for name in ("send_email", "issue_refund", "delete_customer_record"):
        assert f'@signafaide.protect(agent="support-bot")\ndef {name}(' in text
    assert '@signafaide.record(agent="support-bot")\ndef lookup_invoice(' in text
    assert "Rules      saved in your sandbox as version 1" in out
    assert "All 3 rules start Calibrating" in out
    held = runtime.get().checks.held_rules()
    by_id = {r["id"]: r for r in held["rules"]}
    assert set(by_id) == {"send_email-rate", "issue_refund-amount", "delete_customer_record-rate"}
    assert by_id["issue_refund-amount"]["when"] == [{"field": "/amount", "op": "gt", "value": 1000}]
    assert by_id["delete_customer_record-rate"]["limit"] == {"calls": 5, "seconds": 60, "per": "agent_tool"}
    assert by_id["send_email-rate"]["limit"]["calls"] == 20
    assert all(C.rule_state(held, r) == "calibrating" for r in held["rules"])
    assert "Calibrating  Block issue_refund when amount is above 1,000" in out
    # The amount leaves the machine only after a person approves it: said, and not finished.
    assert "sending amount for issue_refund is not approved" in out
    assert "To finish: signafaide pull (at a terminal)" in out
    assert code == 0


def test_yes_without_a_key_keeps_the_rule_it_can_keep(flow, capsys):
    project, _ = flow
    code, out = run(capsys, "protect", "--yes", prompter=FlagPrompter(yes=True))
    assert code == 1, out
    assert "no rule was chosen" not in out
    assert "Rules      not saved yet: there is no key. They start Calibrating once saved." in out
    f = json.loads((project / "signafaide.checks.json").read_text())
    assert [r["id"] for r in f["rules"]["rules"]] == ["issue_refund-amount"]
    assert f["tools"]["issue_refund"]["mode"] == "watch"
    assert set(f["tools"]) == {"send_email", "issue_refund", "delete_customer_record"}


def test_no_terminal_without_yes_shows_the_change_and_writes_nothing(flow, capsys):
    project = flow[0] if isinstance(flow, tuple) else flow
    before = {p: p.read_text() for p in project.rglob("*.py")}
    code, out = run(capsys, "protect", prompter=FlagPrompter(yes=False))
    assert code == 1
    assert "Rule:" not in out
    assert "(not written)" in out
    assert "Nothing written: there is no terminal to ask before changing your files." in out
    assert {p: p.read_text() for p in project.rglob("*.py")} == before
    assert not (project / "signafaide.checks.json").exists()


# --- 3: declare_tools before the main guard ------------------------------------------------------


def test_declaration_goes_before_the_main_guard_and_runs(flow, capsys):
    project, _ = flow
    run(capsys, "protect", "--yes", prompter=FlagPrompter(yes=True))
    text = (project / "agent.py").read_text()
    assert text.index("signafaide.declare_tools(") < text.index("def main()") < text.index('if __name__ == "__main__":')
    assert text.index("signafaide.declare_tools(") > text.index("tools = [send_email")
    # The program exits early, in its main guard: the declaration has run all the same.
    seen = []
    import signafaide

    orig = signafaide.declare_tools
    signafaide.declare_tools = lambda names, **kw: seen.append(list(names))
    try:
        spec = importlib.util.spec_from_file_location("__main__", project / "agent.py")
        mod = importlib.util.module_from_spec(spec)
        with pytest.raises(SystemExit):
            spec.loader.exec_module(mod)
    finally:
        signafaide.declare_tools = orig
    assert seen == [["send_email", "issue_refund", "delete_customer_record", "lookup_invoice"]]


def test_declaration_after_the_main_guard_is_moved_up(flow, capsys):
    project, _ = flow
    (project / "agent.py").write_text(
        AGENT_PY + "\nimport signafaide\n\n# The agent's full tool list, so a proof shows every tool is recorded.\n"
        'signafaide.declare_tools(["send_email"], agent="support-bot")\n'
    )
    run(capsys, "protect", "--yes", prompter=FlagPrompter(yes=True))
    text = (project / "agent.py").read_text()
    assert text.count("declare_tools(") == 1
    assert text.index("declare_tools(") < text.index('if __name__ == "__main__":')
    assert text.index("import signafaide") < text.index("declare_tools(")
    assert text.rstrip().endswith("main()")
    compile(text, "agent.py", "exec")


def test_place_declaration_keeps_one_in_the_right_place():
    good = (
        'import signafaide\n\ndef a(): ...\n\nsignafaide.declare_tools(["a"])\n\nif __name__ == "__main__":\n    a()\n'
    )
    assert place_declaration(good, ["a"], None) == good
    new = place_declaration("def a(): ...\n\n\nmain()\n", ["a"], 'signafaide.declare_tools(["a"])')
    assert new.index("declare_tools") < new.index("main()")


# --- 4: a network that blocks the witness --------------------------------------------------------


class _Refuse(BaseHTTPRequestHandler):
    """A proxy that refuses everything, as a network policy does: 403 to CONNECT and to plain requests."""

    def _no(self):
        body = b"<html>Blocked by network policy</html>"
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_CONNECT = _no

    def log_message(self, *a):
        pass


@pytest.fixture
def refusing_proxy(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Refuse)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(k, url)
    for k in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(urllib.request, "_opener", None)  # proxies are read when the opener is made
    yield url
    srv.shutdown()


SENTENCE = (
    "The network here blocks signafaide.co.uk (common in cloud coding agents and CI sandboxes): allow signafaide.co.uk and "
    "api.signafaide.co.uk in the environment's network settings, or run from a machine that can reach them; records stay signed "
    "on this machine meanwhile."
)


def test_the_sentence():
    assert network_blocked_words("https://api.signafaide.co.uk") == SENTENCE
    assert "blocks witness.example" in network_blocked_words("https://witness.example:8443")


def test_a_proxy_that_refuses_the_tunnel(refusing_proxy):
    with pytest.raises(SignafaideError) as ei:
        Client("https://api.signafaide.co.uk", timeout=5).service_keys()
    assert str(ei.value) == SENTENCE and ei.value.code == "network" and ei.value.blocked and ei.value.retryable


def test_a_proxy_that_answers_403(refusing_proxy):
    with pytest.raises(SignafaideError) as ei:
        Client("http://api.signafaide.co.uk", timeout=5).service_keys()
    assert str(ei.value) == SENTENCE


def test_a_witness_403_is_still_the_witness(service):
    with pytest.raises(SignafaideError) as ei:
        Client(service.url, api_key="sfa_test_" + "0" * 32, timeout=5).project()
    assert not ei.value.blocked and "network here" not in str(ei.value)


def test_dns_blocked():
    with pytest.raises(SignafaideError) as ei:
        Client("http://witness.invalid", timeout=5).service_keys()
    assert str(ei.value).startswith("The network here blocks witness.invalid")


def test_a_protected_call_and_flush_say_it_in_one_sentence(recorder, refusing_proxy, capsys):
    @protect(agent="support-bot")
    def send_email(to: str, body: str) -> str:
        return to

    with pytest.raises(SignafaideBlocked) as ei:
        send_email("ops@example.com", "hello")
    host = recorder.url.split("://")[1].split(":")[0]
    assert str(ei.value).startswith(
        f"send_email did not run: signafAIde did not rule on it, and this tool is set to stop. The network here blocks {host} "
        f"(common in cloud coding agents and CI sandboxes): allow {host} in the environment's network settings, or run from a "
        "machine that can reach it; records stay signed on this machine meanwhile."
    )
    assert ei.value.code == "no_ruling" and "no receipt came" not in str(ei.value)
    capsys.readouterr()  # the call's own note, once per process
    code = cli.main(["flush"])
    out = capsys.readouterr()
    assert code == 1
    assert out.err.count("The network here blocks") == 1, out.err


# --- 5: no git output ----------------------------------------------------------------------------


def test_protect_prints_nothing_from_git_outside_a_repository(flow, tmp_path, monkeypatch, capfd):
    project, _ = flow
    shutil.rmtree(project / ".git")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "git.log"
    git = bin_dir / "git"
    git.write_text(
        f'#!/bin/sh\necho "$@" >> "{log}"\necho "fatal: not a git repository (or any of the parent directories): .git" >&2\nexit 128\n'
    )
    git.chmod(git.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    cli.make_prompter = lambda yes: FlagPrompter(yes=True)
    cli.main(["protect", "--yes"])
    out = capfd.readouterr()
    assert "Protect    send_email" in out.out
    assert "fatal" not in out.out + out.err
    assert not log.exists()  # protect never runs git


# --- 6 and 7: protected in code, no checks file ------------------------------------------------


def test_protected_in_code_without_a_checks_file(recorder, capsys):
    project = recorder.state.root
    assert not (project / "signafaide.checks.json").exists()

    @protect(agent="support-bot")
    def send_email(to: str, body: str) -> str:
        return to

    # 7: the local checks run in On: a secret in the arguments is blocked here.
    with pytest.raises(SignafaideBlocked) as ei:
        send_email("ops@example.com", f"config: aws_access_key_id={AWS} region=eu-west-2")
    assert ei.value.check == "secret" and "aws_access_key" in str(ei.value)
    # 6: an ordinary call is ruled by the witness and recorded as protected.
    assert send_email("ops@example.com", "Your parcel arrives tomorrow.") == "ops@example.com"
    recorder.flush()
    chain = next(c for c in recorder.state.chains() if c.split("/")[2] == "support-bot")
    decisions = [
        r
        for r in recorder.state.read_all(chain)
        if r["envelope"]["kind"] == "decision" and r["envelope"]["name"] == "send_email"
    ]
    assert decisions and all(d["envelope"]["checks"]["strict"] is True for d in decisions)
    assert decisions[-1]["receipt"]["ruling"]["ruling"] == "allow"
    cli.main(["status"])
    out = capsys.readouterr().out
    line = next(x for x in out.splitlines() if x.startswith("send_email"))
    assert " Off " not in f"{line} " and "On" in line, out
    cli.main(["prove", "send_email", "--files"])
    out = capsys.readouterr().out
    assert "before protection" not in out and "recorded before it was protected" not in out
    assert "Before     none: send_email was protected before its first call" in out, out


def test_record_only_tools_keep_todays_behaviour_without_a_checks_file(recorder):
    from signafaide.decorator import record

    @record(agent="support-bot")
    def note_it(text: str) -> str:
        return text

    assert note_it(f"key={AWS}") == f"key={AWS}"  # not checked without a checks file
    chain = next(c for c in recorder.state.chains() if c.split("/")[2] == "support-bot")
    d = next(r for r in recorder.state.read_all(chain) if r["envelope"]["kind"] == "decision")
    assert "checks" not in d["envelope"]


def test_checks_off_still_turns_them_off(recorder, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_CHECKS", "0")

    @protect(agent="support-bot")
    def send_email(to: str, body: str) -> str:
        return to

    assert send_email("ops@example.com", f"key={AWS}") == "ops@example.com"


# --- 8: keys next to delimiters ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"key={AWS}",
        f"deploy with key={AWS} today",
        f"aws_access_key_id={AWS}",
        f"config: aws_access_key_id: {AWS} region=eu-west-2",
        f'keys=["{AWS}"]',
        f"https://paste.example/new?id=1&key={AWS}#top",
        f"aws_access_key_id_{AWS}",
        f"prod-{AWS}-old",
        f"({AWS})",
        f"'{AWS}'",
    ],
)
def test_aws_key_next_to_a_delimiter(text):
    r = C.secret_findings({"body": text}, None)
    assert r["result"] == "block" and "aws_access_key" in r["found"], r


def test_glued_letters_are_not_a_key():
    assert C.secret_findings({"body": f"x{AWS}"}, None)["found"] != ["aws_access_key"]
