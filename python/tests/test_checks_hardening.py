"""Tool-call checks hardening: a span of the OpenTelemetry plug-in
never takes over a checked call, a renamed framework tool keeps its checks, no fail-open at a cold
start, the witness's keys pinned or kept, the checks file's stamp, test mode never with a live
key, a ruling's key active when it ruled, and rule set fingerprint exceptions. Each test failed
before its fix."""

import json
import os
import time

import pytest

import signafaide
from signafaide import checks as C
from signafaide import runtime
from signafaide.checks_runtime import DEFAULT_SERVICE_KEYS, CheckError
from signafaide.crypto import SigningKey, b64url, hash_json
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

GEN_AI = {
    "gen_ai.operation.name": "execute_tool",
    "gen_ai.tool.name": "pay",
    "gen_ai.tool.call.id": "call_1",
    "gen_ai.tool.call.arguments": '{"amount": 5000}',
}


def _tracer():
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON

    from signafaide.otel import SignafaideSpanProcessor

    provider = TracerProvider(sampler=ALWAYS_ON, resource=Resource.create({"service.name": "support-bot"}))
    provider.add_span_processor(SignafaideSpanProcessor(agent="support-bot"))
    return provider.get_tracer("tests")


@pytest.mark.parametrize("how", ["file", "code"])
def test_a_strict_tool_inside_a_tool_span_is_checked_and_blocked_and_the_span_adds_no_decision(
    online, project, service, how
):
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
    assert [(r["envelope"]["kind"], r["envelope"]["name"]) for r in calls(online)] == [
        ("decision", "pay"),
        ("outcome", "pay"),
    ]


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
    target = (
        online.checks.home / "keys.json"
        if removed == "keys"
        else online.checks.home / "rules" / pe[0] / f"{pe[1]}.json"
    )
    target.unlink()
    # Keys removed: the version held is stale (its signer no longer held), enforced as held (§8).
    assert (online.checks.held_rules() is not None) == (removed == "keys")
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
    return {
        "key_id": k.key_id,
        "public_key": b64url(k.public_key),
        "valid_from": "2020-01-01T00:00:00.000Z",
        "valid_to": None,
    }


def test_the_default_witnesss_keys_are_pinned(project):
    rec = runtime.Recorder(url=DEFAULT_URL, quiet=True)
    rec.checks.home.mkdir(parents=True, exist_ok=True)
    (rec.checks.home / "keys.json").write_text(
        json.dumps({"keys": [_key_doc()], "fetched": "2026-11-17T00:00:00.000Z"})
    )
    assert rec.checks.service_keys() == list(DEFAULT_SERVICE_KEYS)
    # Online, the published list never adds a key; its revoked ids are added to the pinned ones (§5).
    from signafaide.http import Client, SignafaideError

    answers = iter(
        [
            SignafaideError("offline", "network"),
            {"keys": [_key_doc(), *DEFAULT_SERVICE_KEYS]},
            {
                "keys": list(DEFAULT_SERVICE_KEYS),
                "revoked": [{"key_id": DEFAULT_SERVICE_KEYS[0]["key_id"], "revoked_at": None}],
            },
            {"keys": list(DEFAULT_SERVICE_KEYS)},
        ]
    )

    def served(self):
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        return a

    original = Client.service_keys
    Client.service_keys = served
    try:
        assert rec.checks.pull_keys() == list(DEFAULT_SERVICE_KEYS)
        assert rec.checks.pull_keys() == list(DEFAULT_SERVICE_KEYS)
        assert rec.checks.pull_keys() == []
        assert rec.checks.pull_keys() == []  # a later list without the revocation never undoes it
        assert rec.checks.revoked_keys() == [DEFAULT_SERVICE_KEYS[0]["key_id"]]
    finally:
        Client.service_keys = original


def test_a_fetched_key_set_that_drops_every_held_key_is_refused(online, service):
    held = online.checks.pull_keys()
    assert [k["key_id"] for k in held] == [service.key_doc["key_id"]]
    original, swapped = service.key_doc, _key_doc()
    service.key_doc = swapped
    assert [k["key_id"] for k in online.checks.pull_keys()] == [original["key_id"]]
    assert [k["key_id"] for k in online.checks.service_keys()] == [original["key_id"]]
    assert "drop a key held" in online.checks.problems["keys"]
    # A rotation adds the new key first: a set that keeps a held key is taken.
    service.key_doc, service.extra_keys = original, [swapped]
    assert [k["key_id"] for k in online.checks.pull_keys()] == [original["key_id"], swapped["key_id"]]
    assert "keys" not in online.checks.problems
    # A revoked key (§5) stays listed but is never used; a malformed `revoked` keeps the held keys.
    service.revoked = [{"key_id": original["key_id"], "revoked_at": None}]
    assert [k["key_id"] for k in online.checks.pull_keys()] == [swapped["key_id"]]
    assert [k["key_id"] for k in online.checks.service_keys()] == [swapped["key_id"]]
    service.revoked = {"key_id": swapped["key_id"]}
    assert [k["key_id"] for k in online.checks.pull_keys()] == [swapped["key_id"]]
    service.revoked = None


def test_a_client_behind_a_reset_takes_the_snapshot(online, service):
    a, b = {"kind": "tool", "fingerprint": "d" * 64}, {"kind": "tool", "fingerprint": "e" * 64}
    service.list_update([a])
    online.checks.pull_list()
    service.list_update([b], [a])
    service.list_reset_seq = 2
    online.checks.pull_list()
    held = online.checks.held_list()
    assert (held["seq"], held["entries"]) == (2, [b])
    st = json.loads((online.checks.home / "fingerprints.state.json").read_text())
    assert st["held"]["seq"] == 2 and st["held"]["key_ids"] == [service.key_doc["key_id"]]
    assert st["stale"] is None and st["retry"] is None
    service.list_reset_seq = 0


def test_a_reset_with_an_older_snapshot_is_refused(online, service):
    a, b = {"kind": "tool", "fingerprint": "a3" * 32}, {"kind": "tool", "fingerprint": "b3" * 32}
    service.list_update([a])
    service.list_update([b])
    online.checks.pull_list()
    service.list_updates = service.list_updates[:1]  # the witness serves a seq 1 snapshot
    service.list_reset_seq = 3
    said = online.checks.pull_list()
    assert "refused" in said
    assert online.checks.held_list()["seq"] == 2
    st = json.loads((online.checks.home / "fingerprints.state.json").read_text())
    assert st["stale"]["since"] and st["retry"]["failures"] == 1
    asked = []
    from signafaide.http import Client

    real = Client.fingerprints
    Client.fingerprints = lambda self, *a, **k: asked.append(1) or real(self, *a, **k)
    try:
        online.checks.pull_list()  # waiting
    finally:
        Client.fingerprints = real
    assert asked == []
    service.list_reset_seq = 0


# --- the owner's policy: keep, then fail closed after REVOKED_GRACE_MS (§8) ---------------------


def _switch_and_revoke(service):
    old = service.key_doc
    nxt = SigningKey.generate()
    service.key = nxt
    service.key_doc = _doc_of(nxt)
    service.extra_keys = [old]
    service.revoked = [{"key_id": old["key_id"]}]
    return old


def _doc_of(k):
    return {
        "key_id": k.key_id,
        "public_key": b64url(k.public_key),
        "valid_from": "2020-01-01T00:00:00.000Z",
        "valid_to": None,
    }


def _resign(rec, service):
    items = service.rule_items[rec.checks.project_env()[0]]
    it = items[-1]
    items[-1] = {**it, "sig": service.key.sign("rules", hash_json(it["rules"])), "service_key_id": service.key.key_id}


def _publish_by_stranger(rec, service):
    real = service.key
    service.key = SigningKey.generate()
    service.publish_rules(rec.api_key, [], mode="enforce")
    service.key = real


def _state_path(rec, kind):
    pe = rec.checks.project_env()
    return (
        rec.checks.home / "fingerprints.state.json"
        if kind == "list"
        else rec.checks.home / "rules" / pe[0] / f"{pe[1]}.state.json"
    )


def _state(rec, kind):
    return json.loads(_state_path(rec, kind).read_text())


def _set_stale(rec, kind, **patch):
    d = _state(rec, kind)
    d["stale"] = {**d["stale"], **patch}
    _state_path(rec, kind).write_text(json.dumps(d))


def _ago(ms):
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(milliseconds=ms)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stale_line(rec):
    return next(
        (
            ln
            for ln in rec.checks.status()[0]
            if ln.startswith(("STALE rule set", "STALE shared list", "PROBLEM rule set", "PROBLEM shared list"))
        ),
        None,
    )


def _pay():
    from signafaide.checks_runtime import ToolInfo

    return ToolInfo(name="pay", description="Pays", input_schema={"type": "object"})


def _held_stale(rec, service, project):
    rec.checks.start = lambda: None  # no background fetch racing the files these tests write
    write_checks(rec, project, mode="enforce", tools={"pay": {"strict": True}})
    service.publish_rules(rec.api_key, [], mode="enforce")
    rec.checks.pull_rules()
    v1 = rec.checks.held_rules()["version"]
    _switch_and_revoke(service)
    rec.checks.fresh_keys("force")
    rec.checks.status()  # what any process does when it reads the held object
    return v1


def _notes(rec, agent="support-bot"):
    from helpers import records

    try:
        return [r for r in records(rec, agent) if r["envelope"]["name"] == "signafaide.checks_stale"]
    except (AssertionError, ValueError, KeyError, IndexError):
        return []  # no record for the agent yet


def test_a_revoked_rule_set_is_kept_noted_after_a_pull_refused_after_the_grace_and_recovered(
    online, service, project, monkeypatch, capsys
):
    from helpers import records
    from signafaide.checks_runtime import REVOKED_GRACE_MS
    from signafaide.http import Client

    v1 = _held_stale(online, service, project)
    assert online.checks.held_rules()["version"] == v1
    assert online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True).stale_blocked is None
    lines, problem = online.checks.status()
    line = next(ln for ln in lines if ln.startswith("STALE rule set"))
    assert "which the witness has revoked; waiting for the witness's re-signed copy" in line
    assert "enforced as held until 2" in line and problem is False
    assert _notes(online) == []  # not noted until the mark outlives a pull
    monkeypatch.setattr(Client, "rules", lambda self, *a, **k: None)  # an unsigned answer
    online.checks.pull_rules()
    monkeypatch.undo()
    capsys.readouterr()
    online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True)
    online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True)
    assert capsys.readouterr().err.count("revoked") == 1  # once a day
    assert len(_notes(online)) == 1
    assert _state(online, "rules")["stale"]["noted"] == ["support-bot"]
    _set_stale(online, "rules", since=_ago(REVOKED_GRACE_MS + 1000))
    ran = []

    @signafaide.record(name="pay", strict=True)
    def pay(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        pay(5)
    assert e.value.code == "rules_unavailable" and "no verified replacement arrived within 7 days" in str(e.value)
    lines, _ = online.checks.dry_run("pay", {"amount": 5}, "support-bot")
    assert f"would refuse {e.value} (rules_unavailable)" in lines  # exactly the call's reason
    assert ran == []
    mine = [r for r in records(online) if r["envelope"]["name"] == "pay"]
    assert [r["envelope"]["kind"] for r in mine] == ["decision", "outcome"]
    assert mine[1]["envelope"]["checks"]["ran"] is False
    lines, problem = online.checks.status()
    assert any(ln.startswith("PROBLEM rule set") and "protected calls are refused" in ln for ln in lines) and problem
    _resign(online, service)
    online.checks.pull_rules(force=True)  # the refused call's own fetch left a retry wait
    assert service.rules_fetches[-1][1] is None  # no If-None-Match while stale
    assert online.checks.held_rules()["version"] == v1
    assert _state(online, "rules")["stale"] is None and _stale_line(online) is None
    service.revoked = None


def test_a_refused_update_every_pull_keeps_since_and_unsigned_answers_change_nothing(
    online, service, project, monkeypatch
):
    from signafaide.http import Client

    _held_stale(online, service, project)
    since = _state(online, "rules")["stale"]["since"]
    _publish_by_stranger(online, service)
    assert "refused rule set version" in online.checks.pull_rules(force=True)
    assert "which its published key list does not name" in _stale_line(online)
    online.checks.pull_rules(force=True)
    assert _state(online, "rules")["stale"]["since"] == since
    monkeypatch.setattr(Client, "rules", lambda self, *a, **k: None)
    online.checks.pull_rules(force=True)
    monkeypatch.undo()
    assert _state(online, "rules")["stale"]["since"] == since
    service.revoked = [{"key_id": service.extra_keys[0]["key_id"]}, {"key_id": "0123456789abcdef"}]
    online.checks.fresh_keys("force")
    assert _state(online, "rules")["stale"]["since"] == since
    service.revoked = None


def test_a_one_off_refusal_then_a_healthy_pull_clears_without_a_note_and_retries_wait(
    online, service, project, monkeypatch
):
    import signafaide.checks_runtime as CR

    online.checks.start = lambda: None  # no background fetch racing this test's own
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True}})
    service.publish_rules(online.api_key, [], mode="enforce")
    online.checks.pull_rules()
    _publish_by_stranger(online, service)
    online.checks.pull_rules()
    assert _state(online, "rules")["stale"]["since"] and _state(online, "rules")["retry"]["failures"] == 1
    n = len(service.rules_fetches)
    online.checks.pull_rules()
    assert len(service.rules_fetches) == n
    online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True)
    assert _notes(online) == []
    t = [time.time()]
    monkeypatch.setattr(CR.time, "time", lambda: t[0])
    for _ in range(60):
        online.checks.pull_rules()
        t[0] += 60
    monkeypatch.undo()
    assert len(service.rules_fetches) - n <= 7
    service.rule_items[online.checks.project_env()[0]].pop()
    service.publish_rules(online.api_key, [], mode="enforce")
    online.checks.pull_rules(force=True)
    st = _state(online, "rules")
    assert st["stale"] is None and st["retry"] is None


def test_junk_revoked_ids_are_ignored_never_refused_and_the_real_one_applies(online, service, project):
    service.publish_rules(online.api_key, [], mode="enforce")
    online.checks.pull_rules()
    service.revoked = [{"key_id": format(i, "016x")} for i in range(300)]
    online.checks.fresh_keys("force")

    def held():
        return json.loads((online.checks.home / "keys.json").read_text())["witnesses"][online.url]

    assert held()["revoked"] == [] and "keys" not in online.checks.problems
    service.revoked = service.revoked + [{"key_id": service.key_doc["key_id"]}]
    online.checks.fresh_keys("force")
    assert held()["revoked"] == [service.key_doc["key_id"]]
    assert _stale_line(online).startswith("STALE rule set")
    service.revoked = None


def test_a_self_hosted_key_list_over_64_keys_has_its_key_changes_refused_and_revocations_applied(online, service):
    online.checks.fresh_keys("force")
    own = service.key_doc["key_id"]
    service.extra_keys = [_doc_of(SigningKey.generate()) for _ in range(70)]
    service.revoked = [{"key_id": own}]
    online.checks.fresh_keys("force")
    assert [k["key_id"] for k in online.checks.all_service_keys()] == [own]
    assert online.checks.revoked_keys() == [own]
    assert "name more than 64 keys" in online.checks.problems["keys"]
    service.extra_keys, service.revoked = [], None


def test_a_hostile_witness_changing_revoked_ids_reads_keys_every_10_minutes(online, service, monkeypatch, project):
    import signafaide.checks_runtime as CR
    from signafaide.http import Client

    write_checks(online, project, mode="enforce")
    service.list_update([{"kind": "tool", "fingerprint": "e4" * 32}])
    online.checks.pull_list()
    n, reads, lists = [0], [], []

    def hostile(self):
        reads.append(1)
        ids = [{"key_id": format(n[0] + i, "016x")} for i in range(70)]
        n[0] += 70
        return {"keys": [service.key_doc], "revoked": ids}

    monkeypatch.setattr(Client, "service_keys", hostile)
    real_fp = Client.fingerprints
    monkeypatch.setattr(Client, "fingerprints", lambda self, *x, **k: lists.append(1) or real_fp(self, *x, **k))
    t = [time.time()]
    monkeypatch.setattr(CR.time, "time", lambda: t[0])
    for _ in range(60):
        online.checks.refresh()
        t[0] += 60
    assert len(reads) <= 7 and len(lists) <= 61, (len(reads), len(lists))
    held = json.loads((online.checks.home / "keys.json").read_text())["witnesses"][online.url]
    assert held["revoked"] == []


def test_a_list_signed_by_a_revoked_key_or_of_an_older_release_is_fetched_from_a_snapshot(
    online, service, project, monkeypatch
):
    from signafaide.http import Client

    write_checks(online, project, mode="enforce")
    service.list_update([{"kind": "tool", "fingerprint": "c" * 64}])
    online.checks.pull_list()
    assert _state(online, "list")["held"]["key_ids"] == [service.key_doc["key_id"]]
    _switch_and_revoke(service)
    online.checks.fresh_keys("force")
    assert _stale_line(online).startswith("STALE shared list: signed by service key")
    asked = []
    real = Client.fingerprints
    monkeypatch.setattr(Client, "fingerprints", lambda self, since=None: asked.append(since) or real(self, since=since))
    online.checks.pull_list()
    assert asked[-1] is None and _state(online, "list")["stale"] is None
    assert _state(online, "list")["held"]["key_ids"] == [service.key_doc["key_id"]]
    _state_path(online, "list").unlink()  # an older release's list: its signers unknown
    online.checks.pull_list()
    assert asked[-1] is None and _state(online, "list")["held"]["key_ids"] == [service.key_doc["key_id"]]
    service.revoked = None


def test_a_crash_between_the_object_and_its_state_file_leaves_no_mark(online, service, project):
    _held_stale(online, service, project)
    assert _stale_line(online).startswith("STALE")
    _resign(online, service)
    pe = online.checks.project_env()
    item = service.rule_items[pe[0]][-1]
    before = _state_path(online, "rules").read_text()
    (online.checks.home / "rules" / pe[0] / f"{pe[1]}.json").write_text(json.dumps(item))
    _state_path(online, "rules").write_text(before)
    assert _stale_line(online) is None
    service.revoked = None


def test_a_future_since_counts_as_now_and_another_witnesss_state_never_counts(online, service, project):
    from signafaide.checks_runtime import REVOKED_GRACE_MS
    from signafaide.verifier import _epoch_ms

    _held_stale(online, service, project)
    _set_stale(online, "rules", since="2999-01-01T00:00:00.000Z")
    until = _stale_line(online).rsplit("until ", 1)[1]
    assert abs(_epoch_ms(until) - (time.time() * 1000 + REVOKED_GRACE_MS)) < 5000
    assert not _state(online, "rules")["stale"]["since"].startswith("2999")
    d = _state(online, "rules")
    d["witness"] = "https://other.example"
    _state_path(online, "rules").write_text(json.dumps(d))
    service.revoked = None
    (online.checks.home / "keys.json").unlink()
    online.checks.fresh_keys("force")
    assert _stale_line(online) is None


def test_two_processes_on_one_folder_share_one_clock(online, service, project):
    from signafaide import runtime as R

    _held_stale(online, service, project)
    since = _state(online, "rules")["stale"]["since"]
    other = R.Recorder(url=online.url, api_key=online.api_key, quiet=True)
    try:
        _publish_by_stranger(online, service)
        other.checks.pull_rules(force=True)
        assert _state(online, "rules")["stale"]["since"] == since
        assert any(ln.startswith("STALE rule set") for ln in other.checks.status()[0])
    finally:
        other.close()
    service.revoked = None


def test_no_checks_file_code_protected_expired_is_a_problem_and_a_broken_copy_expires_at_once(
    online, service, project, monkeypatch
):
    from signafaide.checks_runtime import REVOKED_GRACE_MS

    _held_stale(online, service, project)
    (project / "signafaide.checks.json").unlink()
    online.checks.forget()
    _set_stale(online, "rules", since=_ago(REVOKED_GRACE_MS + 1000))
    lines, problem = online.checks.status()
    assert any(ln.startswith("PROBLEM rule set") for ln in lines) and problem
    assert (
        "protected calls are refused"
        in online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True).stale_blocked
    )
    pe = online.checks.project_env()
    f = online.checks.home / "rules" / pe[0] / f"{pe[1]}.json"
    doc = json.loads(f.read_text())
    service.revoked = None
    (online.checks.home / "keys.json").unlink()
    online.checks.fresh_keys("force")
    # The background fetch would replace the broken copy at once: it answers "current" meanwhile.
    from signafaide.http import Client

    real_rules = Client.rules
    monkeypatch.setattr(Client, "rules", lambda self, *a, **k: None)
    doc["rules"]["default"] = "block" if doc["rules"]["default"] == "allow" else "allow"
    f.write_text(json.dumps(doc))
    assert online.checks.held_rules() is None
    assert "unreadable or fails its own signature" in _stale_line(online)
    assert online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True).stale_blocked
    assert f.exists()
    monkeypatch.setattr(Client, "rules", real_rules)
    online.checks.forced_pull()
    assert _stale_line(online) is None


def test_test_mode_never_refuses_for_stale_rules(online, service, project, monkeypatch):
    from signafaide import runtime as R
    from signafaide.checks_runtime import REVOKED_GRACE_MS

    _held_stale(online, service, project)
    _set_stale(online, "rules", since=_ago(REVOKED_GRACE_MS * 2))
    assert online.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True).stale_blocked
    monkeypatch.setenv("SIGNAFAIDE_TEST", "1")
    t = R.Recorder(url=online.url, quiet=True)
    try:
        assert t.test
        p = t.checks.plan(_pay(), "support-bot", {"amount": 5}, strict_code=True)
        assert p is None or p.stale_blocked is None
    finally:
        t.close()
    service.revoked = None


def test_key_list_reads_one_at_a_time_bounded_future_times_other_releases_every_witness(online, service, monkeypatch):
    import threading

    import signafaide.checks_runtime as CR
    from signafaide.http import Client
    from signafaide.verifier import _epoch_ms

    file = online.checks.home / "keys.json"

    def entry():
        return json.loads(file.read_text())["witnesses"][online.url]

    calls, answers = [], []
    gate = threading.Event()

    def served(self):
        calls.append(1)
        if len(calls) == 1:
            gate.wait(5)
        return answers.pop(0) if answers else {"keys": [service.key_doc]}

    monkeypatch.setattr(Client, "service_keys", served)
    th = threading.Thread(target=online.checks.fresh_keys, args=("force",))
    th.start()
    while not calls:
        time.sleep(0.01)
    second = threading.Thread(target=online.checks.fresh_keys)  # waits for the same read
    second.start()
    time.sleep(0.05)
    gate.set()
    th.join()
    second.join()
    assert len(calls) == 1 and "failed" not in entry()
    t = [time.time()]
    monkeypatch.setattr(CR.time, "time", lambda: t[0])
    t[0] += 9 * 60
    online.checks.fresh_keys()
    assert len(calls) == 1  # none for 10 minutes after a good read
    t[0] += 60
    answers.append({"keys": [{"key_id": 5}]})  # not a keys document: a failed read
    online.checks.fresh_keys()
    assert len(calls) == 2 and entry()["failed"] is True
    assert [k["key_id"] for k in online.checks.service_keys()] == [service.key_doc["key_id"]]
    t[0] += 30
    online.checks.fresh_keys()
    assert len(calls) == 2
    t[0] += 30
    online.checks.fresh_keys()
    assert len(calls) == 3  # 60 s after a failed one
    doc = json.loads(file.read_text())
    doc["witnesses"][online.url]["tried"] = "2999-01-01T00:00:00.000Z"
    doc["witnesses"]["https://other.example"] = {
        "keys": [],
        "revoked": ["0123456789abcdef"],
        "tried": "2026-01-01T00:00:00.000Z",
    }
    file.write_text(json.dumps(doc))
    online.checks.fresh_keys()
    assert len(calls) == 3 and abs(_epoch_ms(entry()["tried"]) - t[0] * 1000) < 1000  # future counts as now
    t[0] += 10 * 60
    online.checks.fresh_keys()
    assert len(calls) == 4
    d2 = json.loads(file.read_text())
    d2["witnesses"][online.url]["pinned"] = "another release"
    file.write_text(json.dumps(d2))
    online.checks.fresh_keys()
    assert len(calls) == 5  # another release's entry counts as never read
    assert json.loads(file.read_text())["witnesses"]["https://other.example"]["revoked"] == ["0123456789abcdef"]


def test_nothing_held_the_list_refused_twice_no_crash_no_clock_the_wait_doubles(online, service, project):
    write_checks(online, project, mode="enforce")
    real = service.key
    service.key = SigningKey.generate()  # every snapshot signed by a key nobody published
    try:
        service.list_update([{"kind": "tool", "fingerprint": "f1" * 32}])
        assert "refused" in online.checks.pull_list()
        assert "refused" in online.checks.pull_list(force=True)
        st = _state(online, "list")
        assert st["held"] is None and st["stale"]["since"] is None and st["retry"]["failures"] == 2
        assert online.checks.held_list() is None
    finally:
        service.key = real


def _break_held_copy(rec):
    pe = rec.checks.project_env()
    f = rec.checks.home / "rules" / pe[0] / f"{pe[1]}.json"
    doc = json.loads(f.read_text())
    doc["rules"]["protect"] = {}
    doc["rules"]["default"] = "block" if doc["rules"]["default"] == "allow" else "allow"
    f.write_text(json.dumps(doc))
    return f


def _refused(name):
    ran = []

    @signafaide.record(name=name)
    def tool(amount):
        ran.append(amount)

    with pytest.raises(CheckError) as e:
        tool(5)
    assert ran == []
    return e.value


def test_a_broken_held_copy_never_unprotects_a_console_protected_tool(online, service, project):
    online.checks.start = lambda: None
    (project / "signafaide.checks.json").unlink(missing_ok=True)
    online.checks.forget()
    service.publish_rules(online.api_key, [], mode="enforce", protect={"pay": {"fail": "closed"}})
    online.checks.pull_rules()
    f = _break_held_copy(online)
    assert online.checks.held_rules() is None
    e = _refused("pay")
    assert e.code == "rules_unavailable" and "unreadable or fails its own signature" in str(e)
    _publish_by_stranger(online, service)  # a pull refused: a key nobody published
    assert "refused" in online.checks.pull_rules(force=True)
    assert _refused("pay").code == "rules_unavailable"
    service.rule_items[online.checks.project_env()[0]] = []  # {"rules": null}: nothing changes
    online.checks.pull_rules(force=True)
    assert _refused("pay").code == "rules_unavailable"
    assert f.exists()
    lines, blocked = online.checks.dry_run("pay", {"amount": 5}, "support-bot")
    assert blocked and "would refuse pay did not run" in "\n".join(lines)


def test_a_copy_from_before_0_5_4_that_breaks_refuses_every_checked_call(online, service, project):
    online.checks.start = lambda: None
    (project / "signafaide.checks.json").unlink(missing_ok=True)
    online.checks.forget()
    service.publish_rules(online.api_key, [], mode="enforce", protect={"pay": {"fail": "closed"}})
    online.checks.pull_rules()
    pe = online.checks.project_env()
    for n in (f"{pe[1]}.state.json", f"{pe[1]}.protect.json"):
        (online.checks.home / "rules" / pe[0] / n).unlink()
    _break_held_copy(online)
    e = _refused("lookup")  # a tool nothing names
    assert e.code == "rules_unavailable" and "protection list unknown" in str(e)
    assert online.checks.dry_run("lookup", {"amount": 5}, "support-bot")[1] is True
    assert online.checks.status()[1] is True


def _rules_files(rec, service):
    pe = rec.checks.project_env()
    d = rec.checks.home / "rules" / pe[0]

    def item(v):
        return next(i for i in service.rule_items[pe[0]] if i["rules"]["version"] == v)

    return d / f"{pe[1]}.json", d / f"{pe[1]}.protect.json", item


def _no_file_protecting(rec, service, project, protect):
    rec.checks.start = lambda: None
    (project / "signafaide.checks.json").unlink(missing_ok=True)
    rec.checks.forget()
    service.publish_rules(rec.api_key, [], mode="enforce", protect=protect)
    rec.checks.pull_rules()


def test_protect_record_an_older_process_wrote_a_newer_copy(online, service, project):
    _no_file_protecting(online, service, project, {"pay": {"fail": "closed"}})
    copy, record, item = _rules_files(online, service)
    service.publish_rules(online.api_key, [], mode="enforce", protect={"refund": {"fail": "closed"}})
    copy.write_text(json.dumps(item(2)))  # what a 0.5.3 process writes: the copy only
    _break_held_copy(online)
    e = _refused("refund")
    assert e.code == "rules_unavailable" and "protection list unknown" in str(e)
    copy.write_text(json.dumps(item(2)))  # read while valid: the record follows the copy
    online.checks.status()
    assert json.loads(record.read_text())["version"] == 2
    assert json.loads(record.read_text())["protect"] == {"refund": {"fail": "closed"}}
    _break_held_copy(online)
    e = _refused("refund")
    assert e.code == "rules_unavailable" and "protection list unknown" not in str(e)


def test_protect_record_ahead_of_the_copy_keeps_the_union_until_a_newer_copy(online, service, project):
    _no_file_protecting(online, service, project, {"pay": {"fail": "closed"}})
    copy, record, _ = _rules_files(online, service)
    record.write_text(json.dumps({"witness": online.url, "version": 2, "protect": {"refund": {"fail": "closed"}}}))
    online.checks.status()
    d = json.loads(record.read_text())
    assert d["version"] == 1 and d["protect"] == {"pay": {"fail": "closed"}, "refund": {"fail": "closed"}}
    _break_held_copy(online)
    assert _refused("pay").code == "rules_unavailable"
    assert _refused("refund").code == "rules_unavailable"
    service.publish_rules(online.api_key, [], mode="enforce", protect={"lookup": {"fail": "closed"}})
    assert online.checks.pull_rules(force=True) == "rule set version 2"
    assert json.loads(record.read_text())["protect"] == {"lookup": {"fail": "closed"}}


def test_protect_record_a_crash_between_the_copy_and_its_record(online, service, project, monkeypatch):
    _no_file_protecting(online, service, project, {"pay": {"fail": "closed"}})
    copy, record, _ = _rules_files(online, service)
    service.publish_rules(online.api_key, [], mode="enforce", protect={"refund": {"fail": "closed"}})

    def died(*a, **k):
        raise RuntimeError("the process died here")

    monkeypatch.setattr(online.checks, "_save_protect", died)
    with pytest.raises(RuntimeError):
        online.checks.pull_rules(force=True)
    monkeypatch.undo()
    assert json.loads(copy.read_text())["rules"]["version"] == 2
    assert json.loads(record.read_text())["version"] == 1  # behind, never ahead
    online.checks.status()
    assert json.loads(record.read_text())["version"] == 2
    _break_held_copy(online)
    assert _refused("refund").code == "rules_unavailable"


def _refused_v2(rec, service, project, monkeypatch):
    """The witness keeps answering the refused version 2 while its rulings name newer ones."""
    write_checks(rec, project, mode="enforce", tools={"pay": {"strict": True}})
    service.publish_rules(rec.api_key, [], mode="enforce")
    rec.checks.pull_rules()
    _publish_by_stranger(rec, service)  # version 2, refused
    rec.checks.pull_rules()
    service.served_version = 2
    rec.checks.start()  # the background fetcher's own first round, before counting
    assert _until(lambda: rec.checks._rounds >= 1)
    woke = []
    real = rec.checks.wake
    monkeypatch.setattr(rec.checks, "wake", lambda: woke.append(1) or real())  # counted; the fetch is real

    @signafaide.record(name="pay", strict=True)
    def pay(amount):
        return amount

    return woke, pay, len(service.rules_fetches)


def _call(fn):
    try:
        fn(1)
    except CheckError:
        pass


def test_rulings_naming_v3_while_the_witness_answers_refused_v2_force_one_fetch(online, service, project, monkeypatch):
    woke, pay, fetches = _refused_v2(online, service, project, monkeypatch)
    _publish_by_stranger(online, service)  # version 3: the rulings name it
    for _ in range(5):
        _call(pay)
    assert woke == [1]
    assert _until(lambda: len(service.rules_fetches) - fetches == 1)  # the one forced fetch, done
    service.served_version = None


def test_rulings_naming_a_different_version_each_call_stay_bounded(online, service, project, monkeypatch):
    woke, pay, fetches = _refused_v2(online, service, project, monkeypatch)
    for _ in range(8):
        _publish_by_stranger(online, service)  # versions 3, 4, ...: each ruling names a new one
        _call(pay)
    assert len(woke) <= 3
    assert _until(lambda: len(service.rules_fetches) - fetches == len(woke))
    assert len(_state(online, "rules")["forced"]) <= 8
    service.served_version = None


def test_a_protect_record_without_a_version_never_counts(online, service, project):
    _no_file_protecting(online, service, project, {"pay": {"fail": "closed"}})
    _, record, _ = _rules_files(online, service)
    record.write_text(json.dumps({"witness": online.url, "protect": {"pay": {"fail": "closed"}}}))
    _break_held_copy(online)
    e = _refused("lookup")
    assert e.code == "rules_unavailable" and "protection list unknown" in str(e)
    lines, _ = online.checks.dry_run("lookup", {"amount": 5}, "support-bot")
    assert f"would refuse {e} (rules_unavailable)" in lines


def test_a_copy_from_before_0_5_4_read_while_valid_gets_its_protect_record(online, service):
    service.publish_rules(online.api_key, [], mode="enforce", protect={"pay": {"fail": "closed"}})
    online.checks.pull_rules()
    pe = online.checks.project_env()
    rec = online.checks.home / "rules" / pe[0] / f"{pe[1]}.protect.json"
    rec.unlink()
    f = online.checks.home / "rules" / pe[0] / f"{pe[1]}.json"
    f.write_text(f.read_text() + " ")  # as a 0.5.3 copy: read again
    online.checks.status()
    d = json.loads(rec.read_text())
    assert d["witness"] == online.url and d["protect"] == {"pay": {"fail": "closed"}}


def test_a_ruling_naming_the_refused_version_wakes_nothing_a_newer_one_is_fetched(
    online, service, project, monkeypatch
):
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True}})
    service.publish_rules(online.api_key, [], mode="enforce")
    online.checks.pull_rules()
    _publish_by_stranger(online, service)  # version 2, refused
    online.checks.pull_rules()

    @signafaide.record(name="pay", strict=True)
    def pay(amount):
        return amount

    real_wake = online.checks.wake
    woke = []
    monkeypatch.setattr(online.checks, "wake", lambda: woke.append(1) or real_wake())
    try:
        pay(1)
    except CheckError:
        pass
    assert woke == []
    service.publish_rules(online.api_key, [], mode="enforce")  # version 3, signed by the witness
    try:
        pay(1)
    except CheckError:
        pass
    assert woke == [1]
    assert _until(lambda: (online.checks.held_rules() or {}).get("version") == 3)


def _until(cond, seconds: float = 15.0) -> bool:
    deadline = time.monotonic() + seconds
    while not cond():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


def test_status_reads_and_writes_only_this_witnesss_state_files(online, service, project):
    from signafaide.checks_runtime import REVOKED_GRACE_MS

    _held_stale(online, service, project)
    pe = online.checks.project_env()
    d = online.checks.home / "rules" / "prj_other"
    d.mkdir(parents=True)
    (d / "live.json").write_text((online.checks.home / "rules" / pe[0] / f"{pe[1]}.json").read_text())
    other = json.dumps(
        {
            "witness": "https://other.example",
            "held": {"version": 1, "key_ids": ["0123456789abcdef"]},
            "sdk": "0.0.0",
            "stale": {"since": _ago(REVOKED_GRACE_MS * 3), "refused": None, "noted": [], "said": None},
            "retry": None,
        }
    )
    (d / "live.state.json").write_text(other)
    lines, _ = online.checks.status()
    assert not any("prj_other" in ln for ln in lines)
    assert any(ln.startswith(f"STALE rule set ({pe[0]}/{pe[1]})") for ln in lines)
    assert (d / "live.state.json").read_text() == other
    service.revoked = None


def test_a_retry_until_beyond_an_hour_is_clamped_and_strict_calls_never_wake_a_waiting_pull(
    online, service, project, monkeypatch
):
    online.checks.start = lambda: None
    write_checks(online, project, mode="enforce", tools={"pay": {"strict": True}})
    service.publish_rules(online.api_key, [], mode="enforce")
    online.checks.pull_rules()
    _publish_by_stranger(online, service)
    online.checks.pull_rules()
    d = _state(online, "rules")
    d["retry"]["until"] = "2999-01-01T00:00:00.000Z"
    _state_path(online, "rules").write_text(json.dumps(d))
    n = len(service.rules_fetches)
    online.checks.pull_rules()
    assert len(service.rules_fetches) == n
    from signafaide.verifier import _epoch_ms

    assert _epoch_ms(_state(online, "rules")["retry"]["until"]) - time.time() * 1000 <= 3_600_000
    woke = []
    monkeypatch.setattr(online.checks, "wake", lambda: woke.append(1))

    @signafaide.record(name="pay", strict=True)
    def pay(amount):
        return amount

    for _ in range(3):
        try:
            pay(1)
        except CheckError:
            pass
    assert woke == []


def test_a_forced_pull_reads_keys_rules_and_list_now(online, service, project, monkeypatch):
    from signafaide.http import Client

    write_checks(online, project, mode="enforce")
    service.publish_rules(online.api_key, [], mode="enforce")
    online.checks.refresh()
    calls = []
    for name in ("service_keys", "rules", "fingerprints"):
        real = getattr(Client, name)
        monkeypatch.setattr(
            Client, name, (lambda n, r: lambda self, *a, **k: calls.append(n) or r(self, *a, **k))(name, real)
        )
    online.checks.refresh()
    assert "service_keys" not in calls
    calls.clear()
    online.checks.forced_pull()
    assert calls.count("service_keys") == 1 and "rules" in calls and "fingerprints" in calls


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
    service.publish_rules(
        online.api_key,
        [],
        mode="enforce",
        fingerprint_exceptions=[
            {"kind": "tool", "fingerprint": fp["tool"], "reason": "Re-approved in the console: our own tool."}
        ],
    )
    online.checks.pull_rules()
    pay(2)
    assert ran == [2]
    d = [r for r in lines_of(online) if r["envelope"]["kind"] == "decision"][-1]
    assert next(x for x in d["envelope"]["checks"]["results"] if x["check"] == "fingerprint") == {
        "check": "fingerprint",
        "result": "allow",
        "mode": "enforce",
        "found": [],
    }


def test_the_rule_set_documents_fingerprint_exceptions_are_optional_and_validated(online, service):
    base = service.publish_rules(online.api_key, [])["rules"]
    assert C.rule_set_errors(base) is None
    ok = {**base, "fingerprint_exceptions": [{"kind": "description", "fingerprint": "ab" * 32, "reason": "Reviewed."}]}
    assert C.rule_set_errors(ok) is None
    assert "{kind, fingerprint, reason}" in C.rule_set_errors(
        {**ok, "fingerprint_exceptions": [{"kind": "description", "fingerprint": "ab" * 32}]}
    )
    assert "listed twice" in C.rule_set_errors({**ok, "fingerprint_exceptions": ok["fingerprint_exceptions"] * 2})
