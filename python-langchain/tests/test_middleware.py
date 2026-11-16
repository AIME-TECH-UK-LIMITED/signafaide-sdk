import asyncio
import atexit
import inspect
import os

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

import signafaide
from langchain_signafaide import SignafaideMiddleware
from signafaide import decorator, runtime, telemetry


class FakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def model_calling(*calls):
    """A model that asks for *calls* (name, args), one per turn, then answers."""
    msgs = [AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"call_{i}", "type": "tool_call"}]) for i, (n, a) in enumerate(calls)]
    return FakeModel(messages=iter(msgs + [AIMessage(content="done")]))


@tool
def get_weather(city: str) -> str:
    """Weather for a city."""
    if city == "Atlantis":
        raise RuntimeError("no such city")
    return f"sunny in {city}"


@tool
def refund(order: str, amount: float) -> str:
    """Refund an order."""
    return f"refunded {amount} on {order}"


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    root = tmp_path / "Claims Project"
    root.mkdir()
    (root / ".git").mkdir()
    monkeypatch.chdir(root)
    for k in list(os.environ):
        if k.startswith("SIGNAFAIDE_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("SIGNAFAIDE_TEST", "0")  # exercise the real recorder, local only
    monkeypatch.setattr(telemetry, "ADAPTERS", set())
    decorator._reset_tool_registry()
    r = runtime.configure(quiet=True, flush_interval=3600)
    yield r
    r._stopped = True
    r._wake.set()
    r._tool_stop.set()
    atexit.unregister(r.close)
    runtime._default = None


def records(rec, agent):
    (chain,) = [c for c in rec.state.chains() if c.rsplit("/", 1)[1] == agent]
    return list(rec.state.read_all(chain))


def calls(recs):
    return [(r["envelope"]["kind"], r["envelope"]["name"]) for r in recs if r["envelope"]["kind"] != "note"]


def test_agent_tool_calls_are_recorded(recorder):
    agent = create_agent(model_calling(("get_weather", {"city": "Paris"}), ("refund", {"order": "A1", "amount": 12.5})), tools=[get_weather, refund], middleware=[SignafaideMiddleware(agent="support-bot")])
    out = agent.invoke({"messages": [("user", "weather, then refund")]})
    assert out["messages"][-1].content == "done"
    recs = records(recorder, "support-bot")
    assert calls(recs) == [("decision", "get_weather"), ("outcome", "get_weather"), ("decision", "refund"), ("outcome", "refund")]
    body = [r for r in recs if r["envelope"]["kind"] != "note"]
    assert body[0]["content"]["input"] == {"city": "Paris"} and body[1]["content"]["output"] == "sunny in Paris"
    assert body[2]["content"]["input"] == {"order": "A1", "amount": 12.5} and body[3]["content"]["output"] == "refunded 12.5 on A1"
    assert signafaide.verify().ok


def test_async_agent(recorder):
    agent = create_agent(model_calling(("get_weather", {"city": "Oslo"})), tools=[get_weather], middleware=[SignafaideMiddleware(agent="support-bot")])
    asyncio.run(agent.ainvoke({"messages": [("user", "weather")]}))
    body = [r for r in records(recorder, "support-bot") if r["envelope"]["kind"] != "note"]
    assert calls(body) == [("decision", "get_weather"), ("outcome", "get_weather")]
    assert body[1]["content"]["output"] == "sunny in Oslo"


def test_tool_error_is_recorded_and_raised(recorder):
    agent = create_agent(model_calling(("get_weather", {"city": "Atlantis"})), tools=[get_weather], middleware=[SignafaideMiddleware(agent="support-bot")])
    with pytest.raises(RuntimeError, match="no such city"):
        agent.invoke({"messages": [("user", "weather")]})
    body = [r for r in records(recorder, "support-bot") if r["envelope"]["kind"] != "note"]
    assert body[1]["content"]["error"] == {"type": "RuntimeError", "message": "no such city"}


def test_declared_tools_cover_the_agent(recorder):
    mw = SignafaideMiddleware(agent="support-bot", tools=[get_weather, refund])
    agent = create_agent(model_calling(("get_weather", {"city": "Rome"})), tools=[get_weather, refund], middleware=[mw])
    agent.invoke({"messages": [("user", "weather")]})
    notes = [r["envelope"]["name"] for r in records(recorder, "support-bot") if r["envelope"]["kind"] == "note"]
    # refund was never called, and is still declared as one of the agent's recorded tools.
    assert "signafaide.tool/refund" in notes and "signafaide.tool/get_weather" in notes
    assert not [n for n in notes if n.startswith("signafaide.tool_unrecorded/")]


def test_recording_seam_has_the_shape_this_package_uses():
    spec = inspect.signature(decorator._Spec)
    assert list(spec.parameters)[:4] == ["name", "agent", "strict", "store_content"] and "listed" in spec.parameters
    for fn in (decorator._Spec.call, decorator._Spec.acall):
        assert list(inspect.signature(fn).parameters) == ["self", "args", "fn", "output"]


def test_handled_tool_error_stays_visible_in_the_record():
    from langchain_core.messages import ToolMessage

    from langchain_signafaide.middleware import _tool_output

    assert _tool_output(ToolMessage(content="ok", tool_call_id="c1")) == "ok"
    assert _tool_output(ToolMessage(content="boom", tool_call_id="c1", status="error")) == {"tool_error": "boom"}


def test_middleware_and_the_opentelemetry_processor_record_a_call_once(recorder):
    """An agent that is traced and also runs through the middleware: each tool call gives one
    decision and one outcome, the middleware's (written before the tool runs)."""
    pytest.importorskip("opentelemetry.sdk.trace")
    pytest.importorskip("openinference.instrumentation.langchain")
    from openinference.instrumentation.langchain import LangChainInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from signafaide.otel import SignafaideSpanProcessor

    provider = TracerProvider()
    provider.add_span_processor(SignafaideSpanProcessor(agent="support-bot"))
    instrumentor = LangChainInstrumentor()
    instrumentor.instrument(tracer_provider=provider)
    try:
        agent = create_agent(model_calling(("get_weather", {"city": "Paris"})), tools=[get_weather, refund], middleware=[SignafaideMiddleware(agent="support-bot")])
        agent.invoke({"messages": [("user", "weather")]})
    finally:
        instrumentor.uninstrument()
    recs = records(recorder, "support-bot")
    assert calls(recs) == [("decision", "get_weather"), ("outcome", "get_weather")]
    assert "telemetry" not in next(r for r in recs if r["envelope"]["kind"] == "decision")["content"]["meta"]
