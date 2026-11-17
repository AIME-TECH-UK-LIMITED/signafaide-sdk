"""Acceptance items of the tool-call checks that have no other home (SPEC §8): unknown keys of the
checks file are errors at every level, concurrent strict calls (the calls of a batch) each get
their own ruling, a call carries the id its framework gave it, a secret is matched in the whole
request target, and a credential sent to the service that issued it is no finding."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

import signafaide
from signafaide import checks as C
from signafaide.checks_runtime import CheckError
from signafaide.crypto import hash_json
from signafaide.records import record_hash

GH = ["ghp", "_A1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6Q7r8"]  # made up, in parts so no scanner stops on the file
GITHUB_TOKEN = "".join(GH)


def write_checks(root, **over):
    (root / "signafaide.checks.json").write_text(json.dumps({**C.default_checks_file(), **over}))


def decisions(rec):
    return [r for c in rec.state.chains() for r in rec.state.read_all(c) if r["envelope"]["kind"] == "decision"]


GOOD = C.default_checks_file()
RULE = {"id": "r", "about": "x", "action": "block", "tools": None, "agents": None, "when": [{"field": "/a", "op": "eq", "value": 1}]}


def with_rules(r):
    return {**GOOD, "rules": {"default": "allow", "rules": [r]}}


UNKNOWN = [
    ("a top-level key", {**GOOD, "mood": "calm"}, "mood"),
    ("a check id", {**GOOD, "checks": {**GOOD["checks"], "proxy": True}}, "proxy"),
    ("a key of a tool entry", {**GOOD, "tools": {"pay": {"strict": False, "retries": 3}}}, "retries"),
    ("a key of addresses", {**GOOD, "addresses": {"hosts": [], "cidrs": [], "resolve": False, "dns": True}}, "dns"),
    ("a key of the rules object", {**GOOD, "rules": {"default": "allow", "rules": [], "note": "x"}}, "note"),
    ("a key of a rule", with_rules({**RULE, "severity": 3}), "severity"),
    ("a key of a condition", with_rules({**RULE, "when": [{"field": "/a", "op": "eq", "value": 1, "fold": True}]}), "fold"),
    ("an operator", with_rules({**RULE, "when": [{"field": "/a", "op": "matches", "value": "x"}]}), "matches"),
    ("an action", with_rules({**RULE, "action": "deny"}), "action"),
    ("a type name", with_rules({**RULE, "when": [{"field": "/a", "op": "type", "value": "decimal"}]}), "type"),
    ("a mode", {**GOOD, "mode": "audit"}, "mode"),
    ("a fail mode", {**GOOD, "tools": {"pay": {"strict": True, "fail": "maybe"}}}, "fail"),
]


@pytest.mark.parametrize("doc,word", [(d, w) for _, d, w in UNKNOWN], ids=[n for n, _, _ in UNKNOWN])
def test_unknown_config_keys_are_errors(doc, word):
    err = C.checks_file_errors(doc)
    assert err is not None and word in err


def test_an_unknown_key_in_the_file_fails_every_checked_call_and_checks_status_reports_it(local_recorder, project):
    write_checks(project, mood="calm")
    ran = []

    @signafaide.record
    def t():
        ran.append(1)

    with pytest.raises(CheckError) as e:
        t()
    assert e.value.code == "state" and "signafaide.checks.json" in e.value.message and "mood" in e.value.message and not ran
    lines, problem = local_recorder.checks.status()
    assert problem and "mood" in "\n".join(lines)


def test_an_unknown_key_in_a_rule_set_the_witness_publishes_is_refused_and_the_held_version_stays(recorder, project, service):
    service.publish_rules(recorder.api_key, [], mode="enforce")
    write_checks(project)
    assert "version 1" in recorder.checks.pull_rules()
    item = service.publish_rules(recorder.api_key, [])
    item["rules"]["severity"] = 3  # an unknown key, signed over (the service signed what it sent)
    item["sig"] = service.key.sign("rules", hash_json(item["rules"]))
    assert "refused rule set version 2" in recorder.checks.pull_rules()
    assert recorder.checks.held_rules()["version"] == 1


def test_concurrent_strict_calls_each_wait_for_their_own_ruling(recorder, project):
    """The calls of one batch are decided at once: one shipment carries all their decisions, and every call must still get its own receipt."""
    write_checks(project, tools={"echo": {"strict": True}})

    @signafaide.record(name="echo")
    async def echo(n):
        return n

    async def go():
        return await asyncio.gather(echo(1), echo(2), echo(3))

    assert asyncio.run(go()) == [1, 2, 3]
    recorder.flush()
    ds = decisions(recorder)
    assert len(ds) == 3 and all(d["envelope"]["checks"]["strict"] for d in ds)
    assert all(d["receipt"]["ruling"]["ruling"] == "allow" for d in ds)


def test_concurrent_strict_calls_in_threads(recorder, project):
    import concurrent.futures

    write_checks(project, tools={"echo": {"strict": True}})

    @signafaide.record(name="echo")
    def echo(n):
        return n

    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        assert sorted(pool.map(echo, range(6))) == list(range(6))
    assert len(decisions(recorder)) == 6


# --- correlation ids --------------------------------------------------------------------


def call_id(rec):
    return decisions(rec)[-1]["envelope"]["checks"]["call_id"]


def test_a_plain_wrapper_has_no_call_id(local_recorder, project):
    write_checks(project)

    @signafaide.record
    def echo(n):
        return n

    echo(1)
    assert call_id(local_recorder) is None


def test_langchain_tool_call_id(local_recorder, project):
    from langchain_core.tools import tool

    write_checks(project)

    @tool
    def echo(n: int) -> str:
        """Echo."""
        return str(n)

    t = signafaide.wrap_tools([echo], declare_tools=False)[0]
    t.invoke({"name": "echo", "args": {"n": 1}, "id": "call_lc_1", "type": "tool_call"})
    assert call_id(local_recorder) == "call_lc_1"
    t.invoke({"n": 2})  # called without a tool call: no id
    assert call_id(local_recorder) is None


def test_openai_agents_tool_call_id(local_recorder, project):
    agents = pytest.importorskip("agents")
    from agents.tool_context import ToolContext

    write_checks(project)

    @agents.function_tool
    def echo(n: int) -> str:
        """Echo."""
        return str(n)

    t = signafaide.wrap_tools([echo], declare_tools=False)[0]
    args = '{"n": 1}'
    ctx = ToolContext(context=None, tool_name="echo", tool_call_id="call_oa_1", tool_arguments=args)
    asyncio.run(t.on_invoke_tool(ctx, args))
    assert call_id(local_recorder) == "call_oa_1"


def test_langchain_middleware_tool_call_id(local_recorder, project):
    pytest.importorskip("langchain")
    try:
        import langchain_signafaide  # noqa: F401
    except ImportError:  # this checkout holds the package next to the SDK
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python-langchain" / "src"))
    from langchain.agents import create_agent
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langchain_signafaide import SignafaideMiddleware

    class FakeModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    @tool
    def echo(n: int) -> str:
        """Echo."""
        return str(n)

    write_checks(project)
    msgs = [AIMessage(content="", tool_calls=[{"name": "echo", "args": {"n": 1}, "id": "call_mw_1", "type": "tool_call"}]), AIMessage(content="done")]
    agent = create_agent(FakeModel(messages=iter(msgs)), tools=[echo], middleware=[SignafaideMiddleware(agent="support-bot")])
    agent.invoke({"messages": [("user", "go")]})
    assert call_id(local_recorder) == "call_mw_1"


def test_an_id_that_is_not_1_to_128_characters_is_not_written_and_never_fails_the_call(local_recorder, project):
    write_checks(project)
    spec = signafaide.decorator._Spec("echo")
    assert spec.call({"n": 1}, lambda: 1, call_id="x" * 200) == 1
    assert call_id(local_recorder) is None
    assert spec.call({"n": 1}, lambda: 1, call_id="call_ok") == 1
    assert call_id(local_recorder) == "call_ok"


def test_an_outcome_refers_to_its_decision(local_recorder, project):
    write_checks(project)
    spec = signafaide.decorator._Spec("echo")
    spec.call({"n": 1}, lambda: 1, call_id="call_a")
    spec.call({"n": 2}, lambda: 2, call_id="call_b")
    from helpers import records

    d1, o1, d2, o2 = [r for r in records(local_recorder) if r["envelope"]["kind"] in ("decision", "outcome")]
    assert (d1["envelope"]["checks"]["call_id"], d2["envelope"]["checks"]["call_id"]) == ("call_a", "call_b")
    assert o1["envelope"]["ref"] == record_hash(d1) and o2["envelope"]["ref"] == record_hash(d2)


# --- a secret is matched in the whole request target ------------------------------------


def http_get(ran):
    @signafaide.record(name="http_get")
    def http_get(**kw):
        ran.append(kw)
        return "ok"

    return http_get


def test_the_path_and_the_query_in_two_arguments_are_joined(local_recorder, project):
    write_checks(project, mode="enforce")
    ran = []
    with pytest.raises(CheckError) as e:
        http_get(ran)(path=f"/v1/{GH[0] + GH[1]}", query=GH[2])
    assert e.value.check == "secret" and ran == []


def test_a_secret_split_across_two_arguments_is_caught(local_recorder, project):
    write_checks(project, mode="enforce")
    with pytest.raises(CheckError) as e:
        http_get([])(a=GH[0] + GH[1], b=GH[2])
    assert e.value.check == "secret"


@pytest.mark.parametrize("url", [f"https://x.example/{GITHUB_TOKEN}/y", f"https://x.example/a?k={GITHUB_TOKEN}", f"https://x.example/a#{GITHUB_TOKEN}",
                                 f"https://x.example/a?k=ghp%5F{GH[1][1:]}{GH[2]}"])
def test_in_the_path_the_query_or_the_fragment_of_one_url(local_recorder, project, url):
    write_checks(project, mode="enforce")
    with pytest.raises(CheckError) as e:
        http_get([])(url=url)
    assert e.value.check == "secret"


def test_the_address_check_reads_the_host_of_the_request_target():
    def found(url, allow=()):
        return C.address_findings({"url": url}, list(allow))["found"]

    assert found("http://allowed.example@127.0.0.1/", ["allowed.example"]) == ["loopback"]  # userinfo is not the host
    assert found("http://127.0.0.1/?h=allowed.example", ["allowed.example"]) == ["loopback"]  # a query is not the host
    assert found("http://allowed.example.evil.test/", ["allowed.example"]) == []  # a public lookalike is public, and not allowlisted by suffix
    assert found("http://localhost:8080/") == ["loopback"]  # a port does not hide the host
    assert found("http://localhost:8080/", ["localhost"]) == []  # and an allowlisted host is allowed on any port


# --- a credential going to the service that issued it is not a leak ---------------------


def post(ran):
    @signafaide.record(name="http_post")
    def http_post(**kw):
        ran.append(kw)
        return "ok"

    return http_post


def test_to_its_issuer_it_runs_in_enforce_mode_too_with_nothing_found(local_recorder, project):
    write_checks(project, mode="enforce")
    ran = []
    assert post(ran)(url="https://api.github.com/repos/o/r/issues", headers={"Authorization": f"token {GITHUB_TOKEN}"}) == "ok"
    assert len(ran) == 1
    entry = next(e for e in decisions(local_recorder)[-1]["envelope"]["checks"]["results"] if e["check"] == "secret")
    assert entry["result"] == "allow" and entry["found"] == []


def test_anywhere_else_it_is_blocked_and_with_another_host_as_well(local_recorder, project):
    write_checks(project, mode="enforce")
    ran = []
    p = post(ran)
    for kw in (dict(url="https://paste.example/new", body=GITHUB_TOKEN),
               dict(a="https://api.github.com/x", b="https://paste.example/", t=GITHUB_TOKEN),
               dict(url="https://api.github.com@paste.example/x", t=GITHUB_TOKEN)):  # the issuer in the userinfo is not the host
        with pytest.raises(CheckError) as e:
            p(**kw)
        assert e.value.check == "secret", kw
    assert ran == []


def test_no_known_destination_is_still_a_finding_and_another_services_issuer_does_not_excuse_it(local_recorder, project):
    write_checks(project, mode="enforce")
    p = post([])
    for kw in (dict(to="ops@example.com", body=GITHUB_TOKEN), dict(url="https://api.stripe.com/v1/charges", t=GITHUB_TOKEN)):
        with pytest.raises(CheckError) as e:
            p(**kw)
        assert e.value.check == "secret", kw


def test_the_key_of_this_witness_may_go_to_this_witness_and_to_no_other_host(local_recorder, project, service):
    write_checks(project, mode="enforce", addresses={"hosts": ["127.0.0.1"], "cidrs": [], "resolve": False})  # the fake witness is on loopback
    p = post([])
    key = "sfa_test_" + "a1B2" * 8
    assert p(url=f"{service.url}/v1/records", k=key) == "ok"
    with pytest.raises(CheckError) as e:
        p(url="https://other.example/", k=key)
    assert e.value.check == "secret"
