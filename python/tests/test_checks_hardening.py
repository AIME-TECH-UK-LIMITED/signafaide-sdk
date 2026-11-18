"""Tool-call checks hardening (epic #58, release review): a span of the OpenTelemetry plug-in
never takes over a checked call, a renamed framework tool keeps its checks, no fail-open at a cold
start, the witness's keys pinned or kept, the checks file's stamp, test mode never with a live
key, a ruling's key active when it ruled, and rule set fingerprint exceptions. Each test failed
before its fix."""

import json
import os

import pytest

import signafaide
from signafaide import checks as C
from signafaide import runtime
from signafaide.checks_runtime import DEFAULT_SERVICE_KEYS, CheckError
from signafaide.crypto import SigningKey, b64url
from signafaide.http import DEFAULT_URL, SignafaideError

from conftest import _recorder, _stop

NEVER_PAY = [{"id": "never", "about": "Never.", "action": "block", "tools": ["pay"], "agents": None, "when": []}]


def write_checks(rec, root, **over):
    (root / "signafaide.checks.json").write_text(json.dumps({**C.default_checks_file(), **over}))
    rec.checks._looked = 0.0  # look at the file again at the next call


def lines_of(rec):
    out = []
    for chain in rec.state.chains():
        out += list(rec.state.read_all(chain))
    return out


def calls(rec):
    return [r for r in lines_of(rec) if r["envelope"]["kind"] != "note"]


@pytest.fixture
def online(project, service, monkeypatch):
    r = _recorder(service, monkeypatch, opt_in=True)
    yield r
    _stop(r)


# --- the OpenTelemetry plug-in never takes over a checked call ---------------------------

GEN_AI = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "pay", "gen_ai.tool.call.id": "call_1", "gen_ai.tool.call.arguments": '{"amount": 5000}'}


def _tracer():
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON

    from signafaide.otel import SignafaideSpanProcessor

    provider = TracerProvider(sampler=ALWAYS_ON, resource=Resource.create({"service.name": "support-bot"}))
    provider.add_span_processor(SignafaideSpanProcessor(agent="support-bot"))
    return provider.get_tracer("tests")


@pytest.mark.parametrize("how", ["file", "code"])
def test_a_strict_tool_inside_a_tool_span_is_checked_and_blocked_and_the_span_adds_no_decision(online, project, service, how):
    pytest.importorskip("opentelemetry.sdk.trace")
    service.publish_rules(online.api_key, NEVER_PAY, mode="enforce")
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True}} if how == "file" else {})
    online.checks.pull_rules()
    t = _tracer()
    ran = []

    @signafaide.record(name="pay", agent="support-bot", strict=how == "code")
    def pay(amount):
        ran.append(amount)

    with t.start_as_current_span("execute_tool pay", attributes=GEN_AI):
        with pytest.raises(CheckError) as e:
            pay(5000)
    assert e.value.code == "blocked" and ran == []
    recs = calls(online)
    assert [(r["envelope"]["kind"], r["envelope"]["name"]) for r in recs] == [("decision", "pay"), ("outcome", "pay")]
    assert recs[0]["envelope"]["checks"]["strict"] is True
    # A protected call always asks the witness, which rules with the newest rules: it blocks it.
    assert recs[1]["envelope"]["checks"] == {"ran": False, "ruling": "block", "results": [], "result": "allow"}


def test_a_tool_strict_in_code_inside_a_span_waits_for_a_ruling_not_only_a_receipt(online, project, service):
    pytest.importorskip("opentelemetry.sdk.trace")
    service.no_ruling = True
    write_checks(online, project)
    t = _tracer()
    ran = []

    @signafaide.record(name="pay", agent="support-bot", strict=True)
    def pay(amount):
        ran.append(amount)

    with t.start_as_current_span("execute_tool pay", attributes=GEN_AI):
        with pytest.raises(CheckError) as e:
            pay(5000)
    assert e.value.code == "no_ruling" and ran == []
    assert calls(online)[-1]["envelope"]["checks"] == {"ran": False, "ruling": "none", "results": [], "result": "allow"}


def test_a_span_of_a_tool_no_wrapper_records_is_still_recorded_with_checks_on(online, project):
    pytest.importorskip("opentelemetry.sdk.trace")
    write_checks(online, project)
    t = _tracer()
    signafaide.record(name="other_tool", agent="support-bot")(lambda: "x")
    with t.start_as_current_span("execute_tool pay", attributes=GEN_AI):
        pass
    assert [(r["envelope"]["kind"], r["envelope"]["name"]) for r in calls(online)] == [("decision", "pay"), ("outcome", "pay")]


# --- a renamed framework tool keeps its checks -------------------------------------------


def test_a_langchain_tool_wrapped_under_another_name_is_checked_under_that_name(online, project, service):
    tools = pytest.importorskip("langchain_core.tools")
    service.publish_rules(online.api_key, NEVER_PAY, mode="enforce", fail={"pay": "closed"})
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True}})
    online.checks.pull_rules()
    ran = []

    def payment(amount: int) -> str:
        """Pay."""
        ran.append(amount)
        return "ok"

    t = tools.StructuredTool.from_function(payment, name="payment", description="Pay.")
    pay = signafaide.wrap_tools({"pay": t})["pay"]
    with pytest.raises(CheckError) as e:
        pay.invoke({"amount": 5000})
    assert e.value.code == "blocked" and ran == []
    d = [r for r in lines_of(online) if r["envelope"]["kind"] == "decision"][-1]
    assert d["envelope"]["name"] == "pay"
    assert d["envelope"]["checks"]["strict"] is True and d["envelope"]["checks"]["fail"] == "closed"
    assert next(x for x in d["envelope"]["checks"]["results"] if x["check"] == "rule")["matched"] == ["never"]
    # The fingerprints still cover what the agent is shown: the tool's own name.
    assert d["envelope"]["checks"]["tool"] == C.tool_fingerprints("payment", "Pay.", _schema_of(t), None)


def _schema_of(t):
    from signafaide.decorator import _langchain_info

    return _langchain_info(t).input_schema


# --- no fail-open at a cold start --------------------------------------------------------


def test_with_no_rule_set_held_yet_the_rule_sets_closed_wins_over_the_checks_files_open(online, project, service):
    service.publish_rules(online.api_key, [], mode="enforce", fail={"pay": "closed"})
    service.ruling_error = "rules_unavailable"
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True, "fail": "open"}})
    ran = []

    @signafaide.record
    def pay(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        pay(1)
    assert e.value.code == "rules_unavailable" and ran == []
    assert online.checks.held_rules()["fail"] == {"pay": "closed"}


@pytest.mark.parametrize("removed", ["rule set", "keys"])
def test_a_removed_held_file_is_fetched_again_before_the_call_may_run(online, project, service, removed):
    service.publish_rules(online.api_key, [], mode="enforce", fail={"pay": "closed"})
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True, "fail": "open"}})
    online.checks.pull_rules()
    assert online.checks.held_rules() is not None
    pe = online.checks.project_env()
    target = online.checks.home / "keys.json" if removed == "keys" else online.checks.home / "rules" / pe[0] / f"{pe[1]}.json"
    target.unlink()
    assert online.checks.held_rules() is None
    service.ruling_error = "rules_unavailable"
    ran = []

    @signafaide.record
    def pay(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        pay(1)
    assert e.value.code == "rules_unavailable" and ran == []


def test_with_no_rule_set_to_be_had_a_strict_call_without_a_ruling_fails_closed(online, project, service, monkeypatch):
    write_checks(online, project, tools={"pay": {"strict": True, "fail": "open"}})
    service.no_ruling = True

    def unreachable():
        raise SignafaideError("the witness cannot be reached", code="network")

    monkeypatch.setattr(online.checks, "pull_rules", unreachable)
    ran = []

    @signafaide.record
    def pay(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        pay(1)
    assert e.value.code == "no_ruling" and ran == []


# --- the witness's keys ------------------------------------------------------------------


def _key_doc():
    k = SigningKey.generate()
    return {"key_id": k.key_id, "public_key": b64url(k.public_key), "valid_from": "2020-01-01T00:00:00.000Z", "valid_to": None}


def test_the_default_witnesss_keys_are_pinned(project):
    rec = runtime.Recorder(url=DEFAULT_URL, quiet=True)
    rec.checks.home.mkdir(parents=True, exist_ok=True)
    (rec.checks.home / "keys.json").write_text(json.dumps({"keys": [_key_doc()], "fetched": "2026-11-17T00:00:00.000Z"}))
    assert rec.checks.service_keys() == list(DEFAULT_SERVICE_KEYS)
    assert rec.checks.pull_keys() == list(DEFAULT_SERVICE_KEYS)  # no request is made


def test_a_fetched_key_set_that_drops_every_held_key_is_refused(online, service):
    held = online.checks.pull_keys()
    assert [k["key_id"] for k in held] == [service.key_doc["key_id"]]
    original, swapped = service.key_doc, _key_doc()
    service.key_doc = swapped
    assert [k["key_id"] for k in online.checks.pull_keys()] == [original["key_id"]]
    assert [k["key_id"] for k in online.checks.service_keys()] == [original["key_id"]]
    assert "drop every key held before" in online.checks.problems["keys"]
    # A rotation adds the new key first: a set that keeps a held key is taken.
    service.key_doc, service.extra_keys = original, [swapped]
    assert [k["key_id"] for k in online.checks.pull_keys()] == [original["key_id"], swapped["key_id"]]
    assert "keys" not in online.checks.problems


def test_a_witness_url_from_the_env_file_is_said_once(project, monkeypatch, capsys):
    monkeypatch.delenv("SIGNAFAIDE_URL", raising=False)
    (project / ".env").write_text("SIGNAFAIDE_URL=http://127.0.0.1:9/\n")
    rec = runtime.Recorder(quiet=False)
    assert rec.url == "http://127.0.0.1:9"
    assert rec.url == "http://127.0.0.1:9"
    err = [line for line in capsys.readouterr().err.splitlines() if line]
    assert len(err) == 1 and "SIGNAFAIDE_URL in" in err[0] and ".env" in err[0] and "warn" not in err[0].lower()
    assert runtime.Recorder(quiet=False, url="http://127.0.0.1:9").url == "http://127.0.0.1:9"
    assert capsys.readouterr().err == ""


# --- local state -------------------------------------------------------------------------


def test_the_checks_files_stamp_has_its_inode(online, project):
    p = project / "signafaide.checks.json"
    t = 1_700_000_000 * 10**9  # whole seconds: both files get exactly the same time
    write_checks(online, project, mode="enforce")
    os.utime(p, ns=(t, t))
    assert online.checks.file()["mode"] == "enforce"
    st = os.stat(p)
    swapped = json.dumps({**C.default_checks_file(), "mode": "watch"}).ljust(st.st_size)
    assert len(swapped.encode()) == st.st_size
    new = p.with_name(p.name + ".new")
    new.write_text(swapped)
    os.utime(new, ns=(t, t))
    new.replace(p)
    assert os.stat(p).st_mtime_ns == st.st_mtime_ns
    online.checks._looked = 0.0
    assert online.checks.file()["mode"] == "watch"


def test_test_mode_never_turns_on_by_itself_with_a_live_key(project, monkeypatch):
    live, sandbox = "sfa_live_" + "a" * 32, "sfa_test_" + "a" * 32
    monkeypatch.delenv("SIGNAFAIDE_TEST", raising=False)
    monkeypatch.delenv("SIGNAFAIDE_API_KEY", raising=False)
    assert "PYTEST_CURRENT_TEST" in os.environ
    assert runtime.test_mode() is True
    assert runtime.test_mode(sandbox) is True
    assert runtime.test_mode(live) is False
    monkeypatch.setenv("SIGNAFAIDE_API_KEY", live)
    assert runtime.test_mode() is False
    monkeypatch.setenv("SIGNAFAIDE_TEST", "1")  # asked for in so many words
    assert runtime.test_mode(live) is True
    monkeypatch.delenv("SIGNAFAIDE_TEST")
    monkeypatch.delenv("SIGNAFAIDE_API_KEY")
    (project / ".env").write_text(f"SIGNAFAIDE_API_KEY={live}\n")  # a live key in the project's .env counts too
    assert runtime.Recorder(quiet=True).test is False


# --- a ruling's key must be active when the witness ruled --------------------------------


def test_a_ruling_signed_by_a_key_retired_before_its_server_time_is_no_ruling(online, project, service):
    service.key_doc = {**service.key_doc, "valid_to": "2021-01-01T00:00:00.000Z"}
    write_checks(online, project, tools={"pay": {"strict": True}})
    ran = []

    @signafaide.record
    def pay(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        pay(1)
    assert e.value.code == "no_ruling" and "was not active at" in e.value.message and ran == []


# --- fingerprint exceptions of the rule set (§10.1) --------------------------------------


def test_a_shared_list_match_the_rule_set_excepts_is_no_finding_and_no_block(online, project, service):
    fp = C.tool_fingerprints("pay", "", None, None)
    service.list_update(add=[{"kind": "tool", "fingerprint": fp["tool"]}])
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True}})
    online.checks.pull_list()
    ran = []

    @signafaide.record
    def pay(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        pay(1)
    assert e.value.check == "fingerprint"
    service.publish_rules(online.api_key, [], mode="enforce", fingerprint_exceptions=[{"kind": "tool", "fingerprint": fp["tool"], "reason": "Re-approved in the console: our own tool."}])
    online.checks.pull_rules()
    pay(2)
    assert ran == [2]
    d = [r for r in lines_of(online) if r["envelope"]["kind"] == "decision"][-1]
    assert next(x for x in d["envelope"]["checks"]["results"] if x["check"] == "fingerprint") == {"check": "fingerprint", "result": "allow", "mode": "enforce", "found": []}


def test_the_rule_set_documents_fingerprint_exceptions_are_optional_and_validated(online, service):
    base = service.publish_rules(online.api_key, [])["rules"]
    assert C.rule_set_errors(base) is None
    ok = {**base, "fingerprint_exceptions": [{"kind": "description", "fingerprint": "ab" * 32, "reason": "Reviewed."}]}
    assert C.rule_set_errors(ok) is None
    assert "{kind, fingerprint, reason}" in C.rule_set_errors({**ok, "fingerprint_exceptions": [{"kind": "description", "fingerprint": "ab" * 32}]})
    assert "listed twice" in C.rule_set_errors({**ok, "fingerprint_exceptions": ok["fingerprint_exceptions"] * 2})
