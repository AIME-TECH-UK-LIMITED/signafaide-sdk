"""The OpenTelemetry span processor (signafaide.otel), with the real OpenTelemetry SDK."""

import json
import logging
import subprocess
import time
import sys

import pytest

pytest.importorskip("opentelemetry.sdk.trace")

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF, ALWAYS_ON, ParentBased, TraceIdRatioBased
from opentelemetry.trace import Status, StatusCode

import signafaide
from helpers import records
from signafaide import runtime, telemetry
from signafaide.cli import main
from signafaide.coverage import telemetry as telemetry_of, telemetry_lines, telemetry_note, telemetry_note_name
from signafaide.otel import SignafaideSpanProcessor, tool_call
from signafaide.records import record_hash

GEN_AI = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup_order", "gen_ai.tool.call.id": "call_1", "gen_ai.tool.call.arguments": '{"order": "A1"}'}
OPENINFERENCE = {"openinference.span.kind": "TOOL", "tool.name": "lookup_order", "input.value": '{"order": "A1"}', "input.mime_type": "application/json"}
TRACELOOP = {"traceloop.span.kind": "tool", "traceloop.entity.name": "lookup_order", "traceloop.entity.input": '{"order": "A1"}'}
GEN_AI_NO_ID = {k: v for k, v in GEN_AI.items() if k != "gen_ai.tool.call.id"}
RESULT = {"gen_ai": "gen_ai.tool.call.result", "openinference": "output.value", "traceloop": "traceloop.entity.output"}
CONVENTIONS = [("gen_ai", GEN_AI), ("openinference", OPENINFERENCE), ("traceloop", TRACELOOP)]


def tracer(sampler=ALWAYS_ON, service="support-bot", **options):
    """A tracer on a provider of the application's own, with the processor added in one line."""
    provider = TracerProvider(sampler=sampler, resource=Resource.create({"service.name": service} if service else {}))
    provider.add_span_processor(SignafaideSpanProcessor(**options))
    return provider.get_tracer("tests")


def calls(recs):
    return [(r["envelope"]["kind"], r["envelope"]["name"]) for r in recs if r["envelope"]["kind"] != "note"]


def notes(recs):
    return [r["envelope"]["name"] for r in recs if r["envelope"]["kind"] == "note"]


def chains(rec):
    return {c.rsplit("/", 1)[1]: list(rec.state.read_all(c)) for c in rec.state.chains()}


# --- the three conventions, at span start and at span end -----------------------------


@pytest.mark.parametrize("convention,attributes", CONVENTIONS)
def test_span_that_says_at_its_start_that_it_is_a_tool_call(local_recorder, convention, attributes):
    t = tracer()
    with t.start_as_current_span("execute_tool lookup_order", attributes=attributes) as span:
        # The tool body: the signed decision is already in the chain, and no outcome yet.
        inside = records(local_recorder, "support-bot")
        assert calls(inside) == [("decision", "lookup_order")]
        span.set_attribute(RESULT[convention], '{"status": "shipped"}')
    recs = records(local_recorder, "support-bot")
    assert calls(recs) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    decision, outcome = [r for r in recs if r["envelope"]["kind"] != "note"]
    assert decision["content"]["input"] == {"order": "A1"}
    marker = decision["content"]["meta"]["telemetry"]
    assert marker["source"] == "opentelemetry" and marker["convention"] == convention and marker["decision_written"] == "before"
    assert len(marker["trace_id"]) == 32 and len(marker["span_id"]) == 16 and marker["span_start"].endswith("Z")
    assert decision["content"]["meta"]["sdk"] == f"signafaide-python/{signafaide.__version__}"
    assert outcome["envelope"]["ref"] == record_hash(decision)
    assert outcome["content"]["output"] == {"status": "shipped"}
    assert outcome["content"]["meta"]["telemetry"] == {"source": "opentelemetry", "convention": convention, "trace_id": marker["trace_id"], "span_id": marker["span_id"]}
    # In the envelopes, so a hash-only verifier sees it: the note right before the decision.
    names = [r["envelope"]["name"] for r in recs]
    assert names[names.index("lookup_order") - 1] == "signafaide.telemetry/start/lookup_order"
    assert "signafaide.telemetry/end/lookup_order" not in names


@pytest.mark.parametrize("convention,attributes", CONVENTIONS)
def test_span_that_says_only_at_its_end_that_it_is_a_tool_call(local_recorder, convention, attributes):
    t = tracer()
    with t.start_as_current_span("lookup_order") as span:
        span.set_attributes(attributes)  # set after the span started: the processor's start hook has run
        assert "support-bot" not in chains(local_recorder)  # the tool body runs with nothing recorded yet
        span.set_attribute(RESULT[convention], "shipped")
    recs = records(local_recorder, "support-bot")
    assert calls(recs) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    decision, outcome = [r for r in recs if r["envelope"]["kind"] != "note"]
    assert decision["content"]["input"] == {"order": "A1"} and outcome["content"]["output"] == "shipped"
    assert decision["content"]["meta"]["telemetry"]["decision_written"] == "after"
    assert decision["content"]["meta"]["telemetry"]["convention"] == convention
    assert outcome["envelope"]["ref"] == record_hash(decision)
    names = [r["envelope"]["name"] for r in recs]
    assert names[names.index("lookup_order") - 1] == "signafaide.telemetry/end/lookup_order"


def test_tool_call_reads_each_convention():
    assert tool_call("execute_tool refund", {"gen_ai.operation.name": "execute_tool"}) == {"convention": "gen_ai", "tool": "refund"}
    assert tool_call("x", {"gen_ai.operation.name": "execute_tool", "traceloop.entity.name": "refund", "traceloop.span.kind": "task"})["tool"] == "refund"
    assert tool_call("running tool", {"gen_ai.operation.name": "execute_tool"})["tool"] == "running tool"  # only the span's name names it
    assert tool_call("", {"gen_ai.operation.name": "execute_tool"}) is None  # nothing names the tool
    assert tool_call("refund", {"openinference.span.kind": "TOOL"}) == {"convention": "openinference", "tool": "refund"}
    assert tool_call("refund.tool", {"traceloop.span.kind": "tool"}) == {"convention": "traceloop", "tool": "refund"}
    assert tool_call("chat gpt", {"gen_ai.operation.name": "chat"}) is None
    assert tool_call("agent", {"openinference.span.kind": "AGENT", "traceloop.span.kind": "workflow"}) is None
    assert tool_call("x", None) is None
    got = tool_call("x", {**GEN_AI, "gen_ai.tool.call.result": "ok"})
    assert got == {"convention": "gen_ai", "tool": "lookup_order", "id": "call_1", "input": '{"order": "A1"}', "output": "ok"}


def test_spans_that_are_not_tool_calls_write_nothing(local_recorder):
    t = tracer()
    with t.start_as_current_span("chat model", attributes={"gen_ai.operation.name": "chat"}):
        with t.start_as_current_span("GET /orders", attributes={"http.request.method": "GET"}):
            pass
    assert chains(local_recorder) == {}


def test_arguments_named_only_after_the_start_go_into_the_outcome(local_recorder):
    t = tracer()
    with t.start_as_current_span("execute_tool refund", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund"}) as span:
        span.set_attribute("gen_ai.tool.call.arguments", '{"amount": 5}')
    decision, outcome = [r for r in records(local_recorder, "support-bot") if r["envelope"]["kind"] != "note"]
    assert decision["content"]["input"] is None and decision["content"]["meta"]["telemetry"]["input"] == "not in the span at its start"
    assert outcome["content"]["input"] == {"amount": 5}
    assert outcome["content"]["output"] is None and outcome["content"]["meta"]["telemetry"]["output"] == "not in the span"


def test_error_span_gives_an_error_outcome(local_recorder):
    t = tracer()
    with pytest.raises(RuntimeError):  # the application's own error is not touched
        with t.start_as_current_span("execute_tool lookup_order", attributes=GEN_AI):
            raise RuntimeError("no such order")
    with t.start_as_current_span("refund") as span:
        span.set_attributes({"openinference.span.kind": "TOOL", "tool.name": "refund"})
        span.set_status(Status(StatusCode.ERROR, "card declined"))
    outcomes = [r for r in records(local_recorder, "support-bot") if r["envelope"]["kind"] == "outcome"]
    assert outcomes[0]["content"]["error"] == {"type": "RuntimeError", "message": "no such order"}
    assert outcomes[1]["content"]["error"] == {"type": "Error", "message": "card declined"}
    assert "output" not in outcomes[0]["content"]


def test_a_tool_recorded_both_ways_gets_a_note_each_time_it_changes(local_recorder):
    t = tracer()
    for at_start in (True, True, False, False, True):
        with t.start_as_current_span("x", attributes=GEN_AI if at_start else None) as span:
            span.set_attributes(GEN_AI)
    recs = records(local_recorder, "support-bot")
    wrote = [n for n in notes(recs) if n.startswith("signafaide.telemetry/")]
    assert wrote == ["signafaide.telemetry/start/lookup_order", "signafaide.telemetry/end/lookup_order", "signafaide.telemetry/start/lookup_order"]
    # Each decision's marker is the telemetry note of its tool that comes last before it.
    last = None
    for r in recs:
        t_note = telemetry_note(r["envelope"]["kind"], r["envelope"]["name"])
        if t_note:
            last = t_note[1]
        elif r["envelope"]["kind"] == "decision":
            assert r["content"]["meta"]["telemetry"]["decision_written"] == last
    got = telemetry_of((r["envelope"]["seq"], r["envelope"]["kind"], r["envelope"]["name"]) for r in recs)
    assert got == {"tools": [{"name": "lookup_order", "decision": "both"}], "sampled": False, "parent_sampled": False}
    assert telemetry_lines("support-bot", got) == ["support-bot: 1 tool is recorded from telemetry spans: lookup_order (decisions written before and after the tool ran)"]


def test_a_long_tool_name_is_cut_as_a_declaration_cuts_it(local_recorder):
    tool = "t" * 140
    t = tracer()
    with t.start_as_current_span("x", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool}):
        pass
    recs = records(local_recorder, "support-bot")
    decision = next(r for r in recs if r["envelope"]["kind"] == "decision")
    assert len(decision["envelope"]["name"]) == 101 and decision["content"]["meta"]["tool"] == tool
    assert telemetry_note_name(tool, True) in notes(recs) and len(telemetry_note_name(tool, True)) == 128
    assert signafaide.verify().ok


# --- what a verifier sees ---------------------------------------------------------------


def test_markers_are_signed_and_every_verifier_output_carries_them(local_recorder, project):
    t = tracer(sampler=ParentBased(ALWAYS_ON))
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    with t.start_as_current_span("refund") as span:
        span.set_attributes({"openinference.span.kind": "TOOL"})
    report = signafaide.verify()
    assert report.ok and report.check("content").status == "pass" and report.check("record_sig").status == "pass"
    (chain,) = local_recorder.state.chains()
    assert report.telemetry == {chain: {"tools": [{"name": "lookup_order", "decision": "before"}, {"name": "refund", "decision": "after"}], "sampled": False, "parent_sampled": True}}
    assert report.to_dict()["telemetry"] == report.telemetry
    lines = str(report).splitlines()
    assert f"telemetry: {chain}: 2 tools are recorded from telemetry spans: lookup_order (decision written before the tool ran), refund (decision written after the tool ran)" in lines
    assert f"telemetry: {chain}: telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded" in lines
    assert f"coverage: {chain}: all 2 declared tools are recorded" in lines
    # The marker in the content is under the signature: changing it fails the content hash.
    path = local_recorder.state.chain_path(chain)
    text = path.read_text()
    assert '"decision_written":"before"' in text
    path.write_text(text.replace('"decision_written":"before"', '"decision_written":"after"', 1))
    tampered = signafaide.verify()
    assert not tampered.ok and tampered.check("content").status == "fail"


def test_no_telemetry_notes_no_telemetry_lines(local_recorder):
    signafaide.record(lambda x: x, name="act")(1)
    report = signafaide.verify()
    assert report.telemetry == {} and report.to_dict()["telemetry"] == {} and "telemetry:" not in str(report)


# --- sampling ---------------------------------------------------------------------------


def run_cli(capsys, *args):
    code = main(list(args))
    return code, capsys.readouterr().out


SAMPLED_LINE = "records come from sampled telemetry: some tool calls may not be recorded"
PARENT_SAMPLED_LINE = "telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded"


class CustomSampler(TraceIdRatioBased):
    """A sampler of the application's own: what it drops is not known."""

    def get_description(self):
        return "MySampler"


@pytest.mark.parametrize("sampler,name,line,key", [
    # Samplers that can drop traces this program starts.
    (TraceIdRatioBased(1.0), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"),
    (ParentBased(TraceIdRatioBased(1.0)), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"),
    (ParentBased(ALWAYS_ON, local_parent_sampled=TraceIdRatioBased(1.0)), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"),
    (CustomSampler(1.0), "signafaide.telemetry_sampled", SAMPLED_LINE, "sampled"),
    # OpenTelemetry's default: every trace this program starts is kept; the caller decides for its own.
    (ParentBased(ALWAYS_ON), "signafaide.telemetry_parent_sampled", PARENT_SAMPLED_LINE, "parent_sampled"),
    (None, "signafaide.telemetry_parent_sampled", PARENT_SAMPLED_LINE, "parent_sampled"),
])
def test_a_sampler_that_is_not_always_on_is_noted_once(local_recorder, capsys, sampler, name, line, key):
    if sampler is None:  # the provider's own default
        provider = TracerProvider(resource=Resource.create({"service.name": "support-bot"}))
        provider.add_span_processor(SignafaideSpanProcessor())
        t, sampler = provider.get_tracer("tests"), provider.sampler
    else:
        t = tracer(sampler=sampler)
    for _ in range(3):
        with t.start_as_current_span("x", attributes=GEN_AI):
            pass
    recs = records(local_recorder, "support-bot")
    other = ({"signafaide.telemetry_sampled", "signafaide.telemetry_parent_sampled"} - {name}).pop()
    assert other not in notes(recs)
    noted = [r for r in recs if r["envelope"]["name"] == name]
    assert len(noted) == 1 and noted[0]["envelope"]["kind"] == "note"
    assert noted[0]["content"] == {"source": "opentelemetry", "sampler": sampler.get_description()}
    assert noted[0]["envelope"]["seq"] < next(r for r in recs if r["envelope"]["kind"] == "decision")["envelope"]["seq"]
    (chain,) = local_recorder.state.chains()
    code, out = run_cli(capsys, "verify")
    assert code == 0 and [x for x in out.splitlines() if "sampled telemetry" in x or "telemetry sampling" in x] == [f"telemetry: {chain}: {line}"] and out.strip().splitlines()[-1].startswith("PASS")
    code, out = run_cli(capsys, "status")
    assert code == 0 and [x for x in out.splitlines() if "sampled telemetry" in x or "telemetry sampling" in x] == [f"note: {chain}: {line}"]
    assert f"note: {chain}: 1 tool is recorded from telemetry spans: lookup_order (decision written before the tool ran)" in out.splitlines()
    code, out = run_cli(capsys, "verify", "--json")
    got = json.loads(out)["telemetry"][chain]
    assert got[key] is True and got["sampled" if key == "parent_sampled" else "parent_sampled"] is False


@pytest.mark.parametrize("at_start", [True, False])
@pytest.mark.parametrize("sampler,name", [(ParentBased(ALWAYS_ON), "signafaide.telemetry_parent_sampled"), (TraceIdRatioBased(1.0), "signafaide.telemetry_sampled"), (ALWAYS_ON, None)])
def test_the_sampling_note_is_written_whether_the_decision_is_written_at_span_start_or_end(local_recorder, at_start, sampler, name):
    t = tracer(sampler=sampler)
    for _ in range(2):
        with t.start_as_current_span("x", attributes=GEN_AI if at_start else None) as span:
            span.set_attributes(GEN_AI)
    recs = records(local_recorder, "support-bot")
    assert [n for n in notes(recs) if "sampled" in n] == ([name] if name else [])
    assert f"signafaide.telemetry/{'start' if at_start else 'end'}/lookup_order" in notes(recs)


def test_langsmith_attribute_names_for_arguments_and_result(local_recorder):
    attributes = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund", "gen_ai.prompt": '{"order":"A1","amount":5}'}
    got = tool_call("refund", {**attributes, "gen_ai.completion": '{"output":"refunded"}'})
    assert got["input"] == '{"order":"A1","amount":5}' and got["output"] == '{"output":"refunded"}'
    # The convention's own names come first when a span has both.
    both = tool_call("refund", {**attributes, "gen_ai.tool.call.arguments": '{"order":"B2"}'})
    assert both["input"] == '{"order":"B2"}'
    # They are read on tool-call spans only.
    assert tool_call("chat", {"gen_ai.operation.name": "chat", "gen_ai.prompt": "hello"}) is None
    t = tracer()
    with t.start_as_current_span("refund") as span:
        span.set_attributes({**attributes, "gen_ai.completion": '{"output":"refunded"}'})
    decision, outcome = [r for r in records(local_recorder, "support-bot") if r["envelope"]["kind"] != "note"]
    assert decision["content"]["input"] == {"order": "A1", "amount": 5} and outcome["content"]["output"] == {"output": "refunded"}


def test_sampling_note_reads_a_sampler_description_of_either_sdk():
    from signafaide.coverage import sampling_note

    assert sampling_note("AlwaysOnSampler") is None
    assert sampling_note(ParentBased(ALWAYS_ON).get_description()) == "signafaide.telemetry_parent_sampled"
    assert sampling_note("ParentBased{root=AlwaysOnSampler, remoteParentSampled=AlwaysOnSampler, remoteParentNotSampled=AlwaysOffSampler, localParentSampled=AlwaysOnSampler, localParentNotSampled=AlwaysOffSampler}") == "signafaide.telemetry_parent_sampled"
    for other in ("AlwaysOffSampler", "TraceIdRatioBased{0.1}", "ParentBased{root=TraceIdRatioBased{0.1}, remoteParentSampled=AlwaysOnSampler, localParentSampled=AlwaysOnSampler}",
                  "ParentBased{root:AlwaysOnSampler,remoteParentSampled:AlwaysOffSampler,localParentSampled:AlwaysOnSampler}", "ParentBased{root:AlwaysOnSampler}", "MySampler", ""):
        assert sampling_note(other) == "signafaide.telemetry_sampled", other


def test_a_langchain_tool_message_in_the_result_names_the_tool():
    message = {"lc": 1, "type": "constructor", "id": ["langchain_core", "messages", "ToolMessage"], "kwargs": {"content": "ok", "name": "lookup_order"}}
    base = {"gen_ai.operation.name": "execute_tool", "traceloop.entity.name": "DynamicStructuredTool"}
    assert tool_call("execute_tool DynamicStructuredTool", base)["tool"] == "DynamicStructuredTool"
    assert tool_call("x", {**base, "traceloop.entity.output": json.dumps(message)})["tool"] == "lookup_order"
    assert tool_call("x", {**base, "gen_ai.tool.call.result": json.dumps({"output": message})})["tool"] == "lookup_order"
    # Anything else in a result is content, never a name.
    for result in ('the ToolMessage said {"name": "refund"}', json.dumps({"name": "refund", "id": ["ToolMessage"]}), json.dumps({**message, "id": ["langchain_core", "messages", "AIMessage"]}), json.dumps({**message, "kwargs": {"name": 5}})):
        assert tool_call("x", {**base, "traceloop.entity.output": result})["tool"] == "DynamicStructuredTool", result


def test_an_always_on_sampler_is_not_noted(local_recorder, capsys):
    t = tracer(sampler=ALWAYS_ON)
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    assert not [n for n in notes(records(local_recorder, "support-bot")) if "sampled" in n]
    for command in ("verify", "status"):
        out = run_cli(capsys, command)[1]
        assert "sampled telemetry" not in out and "telemetry sampling" not in out


def test_a_span_the_sampler_drops_is_not_recorded(local_recorder):
    t = tracer(sampler=ALWAYS_OFF)
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    assert chains(local_recorder) == {}


# --- one tool call, one decision and one outcome ---------------------------------------------


def lookup_order(order):
    return {"order": order, "status": "shipped"}


@pytest.mark.parametrize("at_start", [True, False])
def test_wrapped_tool_whose_span_begins_inside_the_wrapper(local_recorder, at_start):
    t = tracer()

    def traced(order):
        with t.start_as_current_span("x", attributes=GEN_AI if at_start else None) as span:
            span.set_attributes(GEN_AI)
            return lookup_order(order)

    wrapped = signafaide.wrap_tool(traced, name="lookup_order", agent="support-bot")
    assert wrapped("A1")["status"] == "shipped"
    recs = records(local_recorder, "support-bot")
    assert calls(recs) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    assert "telemetry" not in recs[-2]["content"]["meta"]  # the wrapper's own records
    assert not [n for n in notes(recs) if n.startswith("signafaide.telemetry")]
    # The next call of the same tool that is not wrapped is recorded from its span.
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    assert calls(records(local_recorder, "support-bot"))[2:] == [("decision", "lookup_order"), ("outcome", "lookup_order")]


@pytest.mark.parametrize("at_start", [True, False])
def test_wrapped_tool_called_inside_its_span(local_recorder, at_start):
    t = tracer()
    wrapped = signafaide.wrap_tool(lookup_order, agent="support-bot")
    with t.start_as_current_span("x", attributes=GEN_AI if at_start else None) as span:
        span.set_attributes(GEN_AI)
        assert wrapped("A1")["status"] == "shipped"
    recs = records(local_recorder, "support-bot")
    assert calls(recs) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    decision = next(r for r in recs if r["envelope"]["kind"] == "decision")
    # At span start the processor wrote the decision and the wrapper took it over; otherwise the
    # wrapper wrote it and the span was not recorded at its end.
    assert ("telemetry" in decision["content"]["meta"]) is at_start


@pytest.mark.parametrize("at_start", [True, False])
def test_wrapped_tool_called_while_its_span_is_open_but_not_the_current_span(local_recorder, at_start):
    t = tracer()
    wrapped = signafaide.wrap_tool(lookup_order, agent="support-bot")
    span = t.start_span("x", attributes=GEN_AI if at_start else None)  # as a callback-based instrumentation starts it
    span.set_attributes(GEN_AI)
    assert wrapped("A1")["status"] == "shipped"
    span.end()
    assert calls(records(local_recorder, "support-bot")) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    # A later call of the tool with no wrapper around it is recorded from its span.
    span = t.start_span("x")
    span.set_attributes(GEN_AI)
    span.end()
    assert len(calls(records(local_recorder, "support-bot"))) == 4


def late_span(t, attributes, start, end, *, at_start):
    """A span built after its call has ended, as a tracing tool that exports finished runs builds
    it: it carries the call's own start and end times."""
    span = t.start_span("x", start_time=start, attributes=attributes if at_start else None)
    span.set_attributes(attributes)
    span.end(end_time=end)


@pytest.mark.parametrize("at_start", [True, False])
def test_span_built_after_a_wrapped_call_has_ended_is_not_recorded_again(local_recorder, at_start):
    t = tracer()
    ran = []

    def body(order):
        ran.append(time.time_ns())
        return lookup_order(order)

    wrapped = signafaide.wrap_tool(body, name="lookup_order", agent="support-bot")
    wrapped("A1")
    # The call has ended, and only now does its span arrive, dated as the call was.
    late_span(t, GEN_AI_NO_ID, ran[0], time.time_ns(), at_start=at_start)
    recs = records(local_recorder, "support-bot")
    assert calls(recs) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    assert not [n for n in notes(recs) if n.startswith("signafaide.telemetry/")]
    # One wrapper call answers for one span: a second span of those times is another call's.
    late_span(t, GEN_AI_NO_ID, ran[0], time.time_ns(), at_start=at_start)
    assert len(calls(records(local_recorder, "support-bot"))) == 4


@pytest.mark.parametrize("at_start", [True, False])
def test_late_span_of_another_call_of_the_same_tool_is_recorded(local_recorder, at_start):
    t = tracer()
    signafaide.wrap_tool(lookup_order, agent="support-bot")("A1")
    # Same tool name, but the span's own times lie outside the wrapped call: not that call.
    before = time.time_ns() - 10_000_000_000
    late_span(t, GEN_AI_NO_ID, before, before + 1_000_000, at_start=at_start)
    assert calls(records(local_recorder, "support-bot")) == [("decision", "lookup_order"), ("outcome", "lookup_order")] * 2
    marker = records(local_recorder, "support-bot")[-2]["content"]["meta"]["telemetry"]
    assert marker["decision_written"] == ("before" if at_start else "after")


@pytest.mark.parametrize("at_start", [True, False])
def test_late_span_is_matched_by_its_tool_call_id_when_the_wrapper_has_one(local_recorder, at_start):
    from langchain_core.tools import tool

    @tool
    def lookup_order(order: str) -> str:
        """Look an order up."""
        return f"{order}: shipped"

    t = tracer()
    wrapped = signafaide.wrap_tool(lookup_order, agent="support-bot")
    started = time.time_ns()
    wrapped.invoke({"type": "tool_call", "id": "call_1", "name": "lookup_order", "args": {"order": "A1"}})
    # Another call of the tool, by its id, although its times overlap the wrapped call: recorded.
    late_span(t, {**GEN_AI, "gen_ai.tool.call.id": "call_2"}, started, time.time_ns(), at_start=at_start)
    assert len(calls(records(local_recorder, "support-bot"))) == 4
    # The wrapped call's own span, by its id, whatever its times say: not recorded again.
    long_ago = started - 3_600_000_000_000
    late_span(t, GEN_AI, long_ago, long_ago + 1000, at_start=at_start)
    assert len(calls(records(local_recorder, "support-bot"))) == 4
    # The id answered for one span only.
    late_span(t, GEN_AI, long_ago, long_ago + 1000, at_start=at_start)
    assert len(calls(records(local_recorder, "support-bot"))) == 6


def test_a_different_tool_called_inside_a_wrapped_tool_is_still_recorded(local_recorder):
    t = tracer()

    def delegate(task):
        with t.start_as_current_span("x", attributes={**GEN_AI, "gen_ai.tool.name": "search"}):
            return task

    signafaide.wrap_tool(delegate, agent="support-bot")("find it")
    assert calls(records(local_recorder, "support-bot")) == [("decision", "delegate"), ("decision", "search"), ("outcome", "search"), ("outcome", "delegate")]


def test_strict_wrapper_inside_a_recorded_span_still_waits_for_the_receipt(recorder, service):
    t = tracer()
    seen = []

    def wire(amount):
        seen.append(len(service.projects[recorder.api_key]["records"]))  # what the witness holds when the tool runs
        return amount

    wrapped = signafaide.wrap_tool(wire, name="lookup_order", agent="support-bot", strict=True)
    with t.start_as_current_span("x", attributes=GEN_AI):
        wrapped(5)
    recs = records(recorder, "support-bot")
    assert calls(recs) == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    decision = next(r for r in recs if r["envelope"]["kind"] == "decision")
    assert "receipt" in decision and seen[0] >= decision["envelope"]["seq"]


def test_a_tool_an_mcp_gateway_records_is_left_to_the_gateway(local_recorder):
    # What a gateway started with --name-prefix fs. keeps in tools/<agent>.json (SPEC §8).
    local_recorder.state.declare_tools("support-bot", "gateway:fs.", {"fs.read_file": True, "fs.write_file": True}, lambda union, expired: "")
    t = tracer()
    for tool in ("read_file", "fs.write_file", "send_email"):
        with t.start_as_current_span("x", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool}):
            pass
        with t.start_as_current_span("x") as span:
            span.set_attributes({"openinference.span.kind": "TOOL", "tool.name": tool})
    assert calls(records(local_recorder, "support-bot")) == [("decision", "send_email"), ("outcome", "send_email")] * 2


# --- it never breaks the application ---------------------------------------------------


def test_nothing_is_raised_when_the_state_folder_cannot_be_written(project, monkeypatch, caplog):
    blocker = project / "not-a-folder"
    blocker.write_text("")
    monkeypatch.setenv("SIGNAFAIDE_HOME", str(blocker / ".signafaide"))
    r = runtime.configure(quiet=True, flush_interval=3600)
    try:
        t = tracer()
        ran = []
        with caplog.at_level(logging.WARNING, logger="signafaide"):
            for _ in range(3):
                with t.start_as_current_span("x", attributes=GEN_AI):
                    ran.append("start")
                with t.start_as_current_span("x") as span:
                    span.set_attributes(OPENINFERENCE)
                    ran.append("end")
        assert ran == ["start", "end"] * 3  # every tool ran
        warnings = [m for m in caplog.messages if "could not record a tool call from its span" in m]
        assert len(warnings) == 1 and "the tool runs all the same" in warnings[0]
    finally:
        r._stopped = True
        runtime._default = None


def test_a_span_with_unusual_values_is_recorded_or_skipped_without_raising(local_recorder):
    t = tracer()
    with t.start_as_current_span("x", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "odd", "gen_ai.tool.call.arguments": "{not json", "gen_ai.tool.call.id": 7}) as span:
        span.set_attribute("gen_ai.tool.call.result", ["a", "b"])
    decision, outcome = [r for r in records(local_recorder, "support-bot") if r["envelope"]["kind"] != "note"]
    assert decision["content"]["input"] == "{not json" and outcome["content"]["output"] == ["a", "b"]
    with t.start_as_current_span("x", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": 5}):
        pass  # the attribute is not a name: the span's own name is used
    assert calls(records(local_recorder, "support-bot"))[2:] == [("decision", "x"), ("outcome", "x")]


def test_recording_turned_off_writes_nothing(local_recorder, monkeypatch):
    monkeypatch.setenv("SIGNAFAIDE_DISABLED", "1")
    t = tracer()
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    assert chains(local_recorder) == {}


def test_the_processor_exports_nothing_and_leaves_other_processors_alone(local_recorder, service):
    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_ON, resource=Resource.create({"service.name": "support-bot"}))
    provider.add_span_processor(SignafaideSpanProcessor())
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    with provider.get_tracer("tests").start_as_current_span("x", attributes=GEN_AI):
        pass
    assert provider.force_flush() is True
    provider.shutdown()
    (span,) = exporter.get_finished_spans()
    assert dict(span.attributes) == GEN_AI  # the span is as the application made it
    assert service.calls == []  # no API key: nothing left the machine


def test_core_imports_and_records_without_opentelemetry(tmp_path):
    code = """
import sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            raise ModuleNotFoundError(name)
sys.meta_path.insert(0, Block())
import signafaide
assert not any(m == "opentelemetry" or m.startswith("opentelemetry.") for m in sys.modules)
signafaide.record(lambda x: x, name="act")(1)
assert signafaide.verify().ok
try:
    import signafaide.otel
except ImportError as e:
    assert 'install "signafaide[otel]"' in str(e), e
else:
    raise SystemExit("signafaide.otel imported without OpenTelemetry")
print("ok")
"""
    out = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True, env={"SIGNAFAIDE_TEST": "1", "PATH": ""})
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr


# --- agent name, tool declaration, client header ---------------------------------------------


def test_agent_name_explicit_then_service_name_then_default(local_recorder):
    def run(**kw):
        with tracer(**kw).start_as_current_span("x", attributes=GEN_AI):
            pass

    run(agent="claims-bot", service="Support Bot")
    run(service="Support Bot")  # normalised like a folder name
    run(service=None)  # the SDK names it unknown_service: the SDK's default applies
    assert sorted(chains(local_recorder)) == ["claims-bot", "claims-project", "support-bot"]
    with pytest.raises(ValueError):
        SignafaideSpanProcessor(agent="Not A Name")


def test_tools_seen_in_spans_are_declared_as_recorded_and_no_more(local_recorder):
    t = tracer()
    for tool in ("lookup_order", "refund"):
        with t.start_as_current_span("x", attributes={**GEN_AI, "gen_ai.tool.name": tool}):
            pass
    report = signafaide.verify()
    (chain,) = local_recorder.state.chains()
    assert report.coverage[chain]["declared"] == [{"name": "lookup_order", "recorded": True}, {"name": "refund", "recorded": True}]
    assert report.coverage[chain]["undeclared_recorded"] == []
    # With the agent's full list given, a tool no span has shown is declared as not recorded.
    signafaide.declare_tools(["lookup_order", "refund", "web_search"], agent="support-bot")
    assert f"coverage: {chain}: 1 declared tool is not recorded: web_search" in str(signafaide.verify()).splitlines()


def test_declare_tools_false_declares_nothing(local_recorder):
    with tracer(declare_tools=False).start_as_current_span("x", attributes=GEN_AI):
        pass
    assert "signafaide.tools" not in notes(records(local_recorder, "support-bot"))


def test_client_header_names_the_adapter(recorder, service, monkeypatch):
    t = tracer()
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    service.client_ids.clear()
    assert recorder.flush()["left"] == 0
    assert service.client_ids and all("adapter=otel;" in c for c in service.client_ids)
    monkeypatch.setenv("SIGNAFAIDE_TELEMETRY", "0")
    service.client_ids.clear()
    with t.start_as_current_span("x", attributes=GEN_AI):
        pass
    recorder.flush()
    assert service.client_ids and all("adapter=" not in c for c in service.client_ids)
    assert "otel" in telemetry.ADAPTERS


# --- verify, locally and against the witness ---------------------------------------------------


def test_verify_passes_locally_then_co_signed_then_as_a_pack(recorder, service, capsys, tmp_path):
    t = tracer(sampler=ParentBased(ALWAYS_ON))
    with t.start_as_current_span("x", attributes=GEN_AI) as span:
        span.set_attribute("gen_ai.tool.call.result", "shipped")
    with t.start_as_current_span("refund") as span:
        span.set_attributes({"openinference.span.kind": "TOOL", "input.value": "A1"})
        span.set_status(Status(StatusCode.ERROR, "declined"))
    code, out = run_cli(capsys, "verify")
    assert code == 0 and "PASS" in out and "nothing co-signed yet" in out
    sent = recorder.flush()
    assert sent["left"] == 0 and not sent["errors"]
    # Hash-only: what the witness got holds no input, output or span data.
    stored = service.projects[recorder.api_key]["records"]
    assert stored and all("content" not in r and "salt" not in r for r in stored.values())
    code, out = run_cli(capsys, "verify")
    assert code == 0 and "PASS" in out and "nothing co-signed yet" not in out
    assert all("receipt" in r for r in records(recorder, "support-bot"))
    pack = tmp_path / "pack.json"
    assert run_cli(capsys, "export", "-o", str(pack))[0] == 0
    code, out = run_cli(capsys, "verify", str(pack))
    lines = out.splitlines()
    assert code == 0 and any(line.startswith("PASS") for line in lines)
    assert "telemetry: support-bot: 2 tools are recorded from telemetry spans: lookup_order (decision written before the tool ran), refund (decision written after the tool ran)" in lines
    assert "telemetry: support-bot: telemetry sampling follows the caller: a tool call inside a trace that arrives marked as not sampled is not recorded" in lines
    code, out = run_cli(capsys, "verify", str(pack), "--json")
    assert code == 0 and json.loads(out)["telemetry"] == {
        "support-bot": {"tools": [{"name": "lookup_order", "decision": "before"}, {"name": "refund", "decision": "after"}], "sampled": False, "parent_sampled": True}}
