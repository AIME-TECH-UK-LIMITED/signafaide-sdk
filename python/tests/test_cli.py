import json
import re
import subprocess
import sys

import pytest

import signafaide
from signafaide import runtime
from signafaide.cli import COMMANDS, main


def no_counts(line: str) -> str:
    """The result line without its check counts (§7), to compare the rest."""
    return re.sub(r": \d+ of 12 checks [^;]*; ", ": ", re.sub(r": \d+ of 12 checks [^;]*$", "", line))


@pytest.fixture
def cli(project, service, monkeypatch, capsys):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)

    def run(*args):
        code = main(list(args))
        out = capsys.readouterr()
        return code, out.out, out.err

    yield run
    runtime._default = None


def test_commands_registered():
    assert list(COMMANDS) == ["init", "status", "verify", "keys", "export", "replay", "compare", "claim", "flush"]


def test_init_then_claim(cli, project, service):
    code, out, _ = cli("init")
    assert code == 0 and out.count("\n") == 3 and "claim it at " + service.url in out
    assert f"By creating a sandbox you agree to the signafAIde Terms ({service.url}/legal/terms) and Privacy notice ({service.url}/legal/privacy)." in out
    assert "records written before now ship with their original times" in out
    claim = out.splitlines()[0].rsplit(" ", 1)[1]
    env = (project / ".env").read_text()
    assert "SIGNAFAIDE_API_KEY=sfa_test_" in env
    assert f"SIGNAFAIDE_URL={service.url}\n" in env  # not the default service: its URL goes with the key
    code, out, _ = cli("init")
    assert code == 0 and "key found" in out and claim in out
    assert cli("claim")[1].strip() == claim


def test_no_key_status_flush_verify_send_nothing(cli, service):
    signafaide.record(lambda x: x, name="act")(1)
    code, out, _ = cli("status")
    assert code == 0 and "records stay on this machine" in out
    code, out, _ = cli("flush")
    assert (code, out.strip()) == (0, "no API key: nothing was sent; 2 records stay local. Run `signafaide init` (or set SIGNAFAIDE_API_KEY) to send hashes")
    code, out, _ = cli("verify")
    lines = out.strip().splitlines()
    assert code == 0 and lines[-1] == "PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)"
    assert lines[-2] == "co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)"
    assert re.search(r"^ 3\. Client signatures +PASS +2 records", out, re.M)
    assert service.calls == []


def test_flush_keeps_a_chain_older_than_7_days_local(cli):
    import datetime
    from signafaide.records import make_draft

    rec = runtime.configure(quiet=True, flush_interval=3600)
    key = rec.key("claims-project")
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    rec.state.append("_pending/nokey/claims-project",
                     lambda seq, prev: make_draft(key, kind="note", agent="claims-project", seq=seq, prev=prev, name="old", content={}, time=old), lambda r: r)
    cli("init")
    code, out, err = cli("flush")
    assert code == 1 and "more than 7 days ago" in err
    assert out.strip() == "shipped 0 records, 0 left in the outbox; 1 record kept on this machine only (see above)"


def test_claim_without_sandbox(cli):
    code, _, err = cli("claim")
    assert code == 1 and "signafaide init" in err


def test_status_flush_verify_export(cli, project, service, tmp_path):
    cli("init")
    signafaide.record(lambda x: x, name="act")(1)
    code, out, _ = cli("status")
    assert code == 0
    assert "env test" in out and re.search(r"chain prj_\w+/test/claims-project: key [0-9a-f]{16}, 2 records", out)
    assert "outbox: 2 records waiting" in out and "quota: 0 of 1000" in out and "claim: " in out

    code, out, _ = cli("flush")
    assert code == 0 and out.strip() == "shipped 2 records, 0 left in the outbox"
    assert "last receipt seq 2" in cli("status")[1]

    code, out, _ = cli("verify")
    # The test service is plain http on this machine: accepted, and said not to be independent.
    assert code == 0 and no_counts(out.strip().splitlines()[-1]) == "PASS (service keys fetched over plain http, not independent)"

    pack = tmp_path / "pack.json"
    code, out, _ = cli("export", "-o", str(pack))
    assert code == 0 and "2 records" in out and f"signafaide verify {pack}" in out

    code, out, _ = cli("verify", str(pack))
    assert code == 0 and no_counts(out.strip().splitlines()[-1]).startswith("PASS (service keys fetched over plain http, not independent): export of every agent, all records, generated ")
    assert any(line.startswith("head: this project's own") for line in out.splitlines())  # the local head.json, with no flag
    assert any(line.startswith("12. Content hashes") and " PASS " in line and "2 records" in line for line in out.splitlines())

    code, out, _ = cli("verify", str(pack), "--json")
    assert code == 0 and json.loads(out)["result"] == "PASS"

    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [service.key_doc]}))
    data = json.loads(pack.read_text())
    data["records"][0]["envelope"]["name"] = "other"
    pack.write_text(json.dumps(data))
    code, out, _ = cli("verify", str(pack), "--keys", str(keys))
    assert code == 1 and no_counts(out.strip().splitlines()[-1]).startswith("FAIL: export of every agent")
    code, out, err = cli("verify", str(pack), "--keys", "http://192.0.2.1/keys.json")
    assert code == 2 and "plain http" in err


def test_export_takes_every_agent_unless_narrowed_and_empty_pack_fails(cli, tmp_path):
    cli("init")
    signafaide.note("n", {})
    signafaide.note("n", {}, agent="second-bot")
    cli("flush")
    every = tmp_path / "all.json"
    code, out, _ = cli("export", "-o", str(every))
    assert code == 0 and "(2 records)" in out
    assert "second-bot" in {r["envelope"]["agent"] for r in json.loads(every.read_text())["records"]}
    code, out, _ = cli("export", "--agent", "second-bot", "-o", str(tmp_path / "one.json"))
    assert code == 0 and "(1 record);" in out

    empty = tmp_path / "empty.json"
    code, out, err = cli("export", "--agent", "nobody", "-o", str(empty))
    assert code == 0 and "(0 records)" in out
    assert "agent 'nobody' has no records in this range; leave out --agent to export every agent" in err
    code, out, _ = cli("verify", str(empty))
    assert code == 1 and "pack: no records" in out and out.strip().splitlines()[-1].startswith("FAIL: 1 of 12 checks failed (envelope schema)") and "; export of agent nobody" in out


def test_verify_embedded_keys_warning(cli, tmp_path, service):
    cli("init")
    signafaide.note("n", {})
    cli("flush")
    pack = tmp_path / "p.json"
    cli("export", "-o", str(pack))
    code, out, _ = cli("verify", str(pack), "--trust-embedded-keys")
    assert code == 0 and "WARNING: service keys were taken from the pack itself" in out


def test_verify_unreadable_inputs_exit_2(cli, tmp_path, monkeypatch, dead_url):
    code, _, err = cli("verify", str(tmp_path / "missing.json"))
    assert code == 2 and err.count("\n") == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert cli("verify", str(bad), "--trust-embedded-keys")[0] == 2
    good = tmp_path / "p.json"
    good.write_text(json.dumps({"format": "signafaide-pack/1", "generated": "x", "project": "p", "env": "test", "service_keys": [], "agent_keys": [], "records": [], "anchors": []}))
    monkeypatch.setenv("SIGNAFAIDE_URL", dead_url)
    code, _, err = cli("verify", str(good))
    assert code == 2 and "pass --keys" in err


def test_flush_offline_is_one_line_and_exit_1(cli, project, dead_url, monkeypatch):
    (project / ".env").write_text("SIGNAFAIDE_API_KEY=sfa_test_" + "x" * 32 + "\n")
    monkeypatch.setenv("SIGNAFAIDE_URL", dead_url)
    runtime.configure(quiet=True)
    signafaide.note("n", {})
    code, out, err = cli("flush")
    assert code == 1
    assert err.count("\n") == 1 and "Cannot reach the signafAIde service" in err
    assert "1 left in the outbox" in out


def test_errors_are_one_line(cli, monkeypatch, dead_url):
    monkeypatch.setenv("SIGNAFAIDE_URL", dead_url)
    code, out, err = cli("init")
    assert code == 1 and err.count("\n") == 1 and err.startswith("signafaide: Cannot reach")


def test_module_entry_point(project):
    p = subprocess.run([sys.executable, "-m", "signafaide", "--version"], capture_output=True, text=True, cwd=project)
    assert p.returncode == 0 and p.stdout.startswith("signafaide ")


def test_keys_export_then_pack_verify_with_agent_keys_and_head(cli, project, service, tmp_path):
    import signafaide

    cli("init")
    signafaide.note("a", {})
    assert signafaide.flush()["shipped"] == 1
    code, out, _ = cli("keys", "export", "-o", str(tmp_path / "agent-keys.json"))
    assert code == 0 and "agent-keys.json" in out
    code, out, _ = cli("export", "-o", str(tmp_path / "pack.json"))
    assert code == 0
    head = project / ".signafaide" / "head.json"
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [service.key_doc]}))
    code, out, err = cli("verify", str(tmp_path / "pack.json"), "--keys", str(keys), "--agent-keys", str(tmp_path / "agent-keys.json"), "--head", str(head), "--offline")
    last = out.rstrip().splitlines()[-1]
    assert code == 0 and no_counts(last).startswith("PASS: export of every agent, all records, generated "), out + err
    code, out, err = cli("verify", str(tmp_path / "pack.json"), "--keys", str(keys), "--trust-embedded-agent-keys", "--offline")
    assert code == 0 and no_counts(out.rstrip().splitlines()[-1]).startswith("PASS (agent keys taken from the pack, not independent): export of ")
    # Keys over plain http only from this machine.
    code, out, err = cli("verify", str(tmp_path / "pack.json"), "--keys", "http://192.0.2.1/keys.json", "--offline")
    assert code == 2 and "plain http" in err


def test_hostile_sandbox_answer_writes_nothing(project, service, monkeypatch):
    import signafaide
    from signafaide import runtime

    real = service.route

    def route(method, path, query, body, auth):
        if path == "/v1/sandbox":
            return 201, {"project": "../../../escaped", "api_key": "sfa_test_" + "A" * 32 + "\nNODE_OPTIONS=--require ./pwn.js", "claim_url": "x", "free_quota": 1}
        return real(method, path, query, body, auth)

    service.route = route
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    rec = runtime.configure(quiet=True, flush_interval=3600)
    try:
        with pytest.raises(signafaide.SignafaideError, match="invalid api_key or project"):
            rec.create_sandbox()
        assert not (project / ".env").exists()
        assert not list(project.parent.rglob("escaped*"))
    finally:
        rec._stopped = True
        runtime._default = None
