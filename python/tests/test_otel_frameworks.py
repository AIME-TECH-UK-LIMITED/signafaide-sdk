"""The OpenTelemetry span processor against real instrumentation packages: a real framework runs
a real tool call, asked for by a fake model (no network, no API key). Each test looks, from
inside the tool body, at whether the signed decision is already in the chain."""

import json
import subprocess
import sys

import pytest

pytest.importorskip("opentelemetry.sdk.trace")
pytest.importorskip("langchain.agents")

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

import signafaide
from signafaide import runtime
from signafaide.otel import SignafaideSpanProcessor


class FakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def model_calling(name, args):
    """A model that asks for one tool call, then answers."""
    ask = AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": "call_1", "type": "tool_call"}])
    return FakeModel(messages=iter([ask, AIMessage(content="done")]))


def provider():
    p = TracerProvider(sampler=ALWAYS_ON, resource=Resource.create({"service.name": "support-bot"}))
    p.add_span_processor(SignafaideSpanProcessor())  # the one line
    return p


def calls():
    """(kind, name) of the tool-call records in the agent's chain, as they are on disk now."""
    rec = runtime.get()
    return [
        (r["envelope"]["kind"], r["envelope"]["name"])
        for c in rec.state.chains()
        if c.endswith("/support-bot")
        for r in rec.state.read_all(c)
        if r["envelope"]["kind"] != "note"
    ]


def decision():
    rec = runtime.get()
    return next(r for c in rec.state.chains() for r in rec.state.read_all(c) if r["envelope"]["kind"] == "decision")


#: What each tool body saw in the chain while it ran.
seen = {}


@tool
def lookup_order(order: str, lines: int) -> str:
    """Look an order up."""
    seen["lookup_order"] = calls()
    return f"{order}: {lines} lines shipped"


def run_langchain_agent(tools=(lookup_order,)):
    agent = create_agent(model_calling("lookup_order", {"order": "A1", "lines": 2}), tools=list(tools))
    out = agent.invoke({"messages": [("user", "where is order A1?")]})
    assert out["messages"][-1].content == "done"


@pytest.fixture
def openinference(local_recorder):
    pytest.importorskip("openinference.instrumentation.langchain")
    from openinference.instrumentation.langchain import LangChainInstrumentor

    seen.clear()
    instrumentor = LangChainInstrumentor()
    instrumentor.instrument(tracer_provider=provider())
    yield local_recorder
    instrumentor.uninstrument()


@pytest.fixture
def openllmetry(local_recorder):
    pytest.importorskip("opentelemetry.instrumentation.langchain")
    from opentelemetry.instrumentation.langchain import LangchainInstrumentor

    seen.clear()
    instrumentor = LangchainInstrumentor()
    instrumentor.instrument(tracer_provider=provider())
    yield local_recorder
    instrumentor.uninstrument()


def test_openinference_langchain_decision_is_written_after_the_tool_ran(openinference):
    """OpenInference's LangChain instrumentor sets a span's attributes when the span ends, so the
    span says it is a tool call only then: the decision is written after the tool body ran."""
    run_langchain_agent()
    assert seen["lookup_order"] == []  # nothing in the chain while the tool ran
    assert calls() == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    d = decision()
    assert d["content"]["meta"]["telemetry"]["convention"] == "openinference"
    assert d["content"]["meta"]["telemetry"]["decision_written"] == "after"
    assert d["content"]["input"] == {"order": "A1", "lines": 2}
    report = signafaide.verify()
    assert report.ok and "lookup_order (decision written after the tool ran)" in str(report)


def test_openllmetry_langchain_decision_is_written_after_the_tool_ran(openllmetry):
    """OpenLLMetry's LangChain instrumentation starts the span and then sets its attributes
    (gen_ai.operation.name = execute_tool, traceloop.span.kind = tool), so the span processor's
    start hook does not see them: the decision is written when the span ends."""
    run_langchain_agent()
    assert seen["lookup_order"] == []
    assert calls() == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    d = decision()
    assert d["content"]["meta"]["telemetry"]["convention"] == "gen_ai"
    assert d["content"]["meta"]["telemetry"]["decision_written"] == "after"
    assert signafaide.verify().ok


def test_pydantic_ai_decision_is_written_before_the_tool_runs(local_recorder):
    """Pydantic AI starts its execute_tool span with the GenAI attributes on it, so the decision
    is in the chain before the tool body runs."""
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.models.instrumented import InstrumentationSettings

    turns = iter(
        [
            ModelResponse(parts=[ToolCallPart("refund", {"order": "A1", "amount": 5})]),
            ModelResponse(parts=[TextPart("done")]),
        ]
    )
    agent = Agent(FunctionModel(lambda messages, info: next(turns)))
    agent.instrument = InstrumentationSettings(tracer_provider=provider())
    inside = {}

    @agent.tool_plain
    def refund(order: str, amount: float) -> str:
        """Refund an order."""
        inside["calls"] = calls()
        return f"refunded {amount} on {order}"

    assert agent.run_sync("refund order A1").output == "done"
    assert inside["calls"] == [("decision", "refund")]  # signed and chained before the tool body ran
    assert calls() == [("decision", "refund"), ("outcome", "refund")]
    d = decision()
    assert d["content"]["meta"]["telemetry"]["convention"] == "gen_ai"
    assert d["content"]["meta"]["telemetry"]["decision_written"] == "before"
    assert d["content"]["input"] == {"order": "A1", "amount": 5}
    report = signafaide.verify()
    assert report.ok and "refund (decision written before the tool ran)" in str(report)


def test_langchain_tool_wrapped_with_the_sdk_is_recorded_once(openinference):
    """A tool that is also wrapped with wrap_tools: the wrapper's decision and outcome stand (the
    decision before the tool runs), and the span of the same call is not recorded again."""
    run_langchain_agent(signafaide.wrap_tools([lookup_order], agent="support-bot"))
    assert seen["lookup_order"] == [("decision", "lookup_order")]
    assert calls() == [("decision", "lookup_order"), ("outcome", "lookup_order")]
    assert "telemetry" not in decision()["content"]["meta"]


def test_langchain_tool_wrapped_with_the_sdk_is_recorded_once_openllmetry(openllmetry):
    run_langchain_agent(signafaide.wrap_tools([lookup_order], agent="support-bot"))
    assert seen["lookup_order"] == [("decision", "lookup_order")]
    assert calls() == [("decision", "lookup_order"), ("outcome", "lookup_order")]


# --- LangSmith: spans built after the run has finished ------------------------------------------

LANGSMITH = """
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

class Sink(BaseHTTPRequestHandler):  # stands in for LangSmith's endpoint: nothing leaves this machine
    def reply(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(b"{}")
    do_GET = do_POST = do_PUT = do_PATCH = reply
    def log_message(self, *a): pass

server = HTTPServer(("127.0.0.1", 0), Sink)
threading.Thread(target=server.serve_forever, daemon=True).start()
os.environ.update(LANGSMITH_ENDPOINT=f"http://127.0.0.1:{server.server_port}", LANGSMITH_API_KEY="lsv2_test",
                  LANGSMITH_OTEL_ENABLED="true", LANGSMITH_TRACING="true", SIGNAFAIDE_TEST="1")

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
import signafaide
from signafaide import runtime
from signafaide.otel import SignafaideSpanProcessor

class FakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self

def chain():
    rec = runtime.get()
    return [r for c in rec.state.chains() for r in rec.state.read_all(c)]

provider = TracerProvider()  # OpenTelemetry's default sampler
provider.add_span_processor(SignafaideSpanProcessor(agent="support-bot"))
trace.set_tracer_provider(provider)
seen = {}

@tool
def refund(order: str, amount: float) -> str:
    \"\"\"Refund an order.\"\"\"
    seen["inside"] = len([r for r in chain() if r["envelope"]["kind"] == "decision"])
    return f"refunded {amount} on {order}"

MODE = sys.argv[1]
tools, middleware = [refund], []
if MODE == "wrapped":
    tools = signafaide.wrap_tools([refund], agent="support-bot")
elif MODE == "middleware":
    from langchain_signafaide import SignafaideMiddleware
    middleware = [SignafaideMiddleware(agent="support-bot")]
ask = AIMessage(content="", tool_calls=[{"name": "refund", "args": {"order": "A1", "amount": 5}, "id": "call_1", "type": "tool_call"}])
agent = create_agent(FakeModel(messages=iter([ask, AIMessage(content="done")])), tools=tools, middleware=middleware)
agent.invoke({"messages": [("user", "Refund order A1, 5 pounds")]})
before_flush = len(chain())
from langsmith.run_trees import get_cached_client
get_cached_client().flush()  # LangSmith builds its OpenTelemetry spans from the finished runs
print(json.dumps({"inside": seen["inside"], "before_flush": before_flush, "records": [{"kind": r["envelope"]["kind"], "name": r["envelope"]["name"], "content": r["content"]} for r in chain()]}))
"""


def run_langsmith(tmp_path, mode):
    """A LangChain agent traced by LangSmith's OpenTelemetry mode, in a process of its own
    (LangSmith reads its settings once per process)."""
    pytest.importorskip("langsmith")
    (tmp_path / ".git").mkdir()
    out = subprocess.run(
        [sys.executable, "-c", LANGSMITH, mode], cwd=tmp_path, capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr[-2000:]
    got = json.loads(out.stdout.strip().splitlines()[-1])
    got["calls"] = [(r["kind"], r["name"]) for r in got["records"] if r["kind"] != "note"]
    got["notes"] = [r["name"] for r in got["records"] if r["kind"] == "note"]
    return got


def test_langsmith_decision_is_written_after_the_tool_ran_with_arguments_result_and_sampling_note(tmp_path):
    """LangSmith builds a run's span once the run has finished, so the decision is written after
    the tool ran. The span carries the arguments as gen_ai.prompt and the result as
    gen_ai.completion, and the provider's default sampler is noted although no span said at its
    start that it was a tool call."""
    got = run_langsmith(tmp_path, "plain")
    assert got["inside"] == 0 and got["calls"] == [("decision", "refund"), ("outcome", "refund")]
    decision, outcome = [r for r in got["records"] if r["kind"] != "note"]
    marker = decision["content"]["meta"]["telemetry"]
    assert (
        marker["convention"] == "gen_ai"
        and marker["decision_written"] == "after"
        and marker["tool_call_id"] == "call_1"
    )
    assert decision["content"]["input"] == {"order": "A1", "amount": 5}
    assert outcome["content"]["output"]["output"]["content"] == "refunded 5.0 on A1"
    assert "signafaide.telemetry_parent_sampled" in got["notes"] and "signafaide.telemetry/end/refund" in got["notes"]
    assert got["notes"].index("signafaide.telemetry_parent_sampled") < got["notes"].index(
        "signafaide.telemetry/end/refund"
    )


def test_langsmith_tool_wrapped_with_the_sdk_is_recorded_once(tmp_path):
    """The wrapper's call has ended when LangSmith's span of it arrives: the span is matched to
    the call the wrapper recorded (by its tool call id) and not recorded again."""
    got = run_langsmith(tmp_path, "wrapped")
    assert got["inside"] == 1  # the wrapper's decision, before the tool ran
    assert got["calls"] == [("decision", "refund"), ("outcome", "refund")]
    assert "telemetry" not in got["records"][got["before_flush"] - 2]["content"]["meta"]
    assert not [n for n in got["notes"] if n.startswith("signafaide.telemetry")]
