import asyncio

import pytest

import signafaide
from helpers import records


def names(recorder, agent="claims-project"):
    return [(r["envelope"]["kind"], r["envelope"]["name"]) for r in records(recorder, agent)]


def test_wrap_tools_dict_and_list(recorder):
    def lookup(order_id):
        return {"order": order_id}

    async def refund(order_id, amount):
        return amount

    tools = signafaide.wrap_tools({"lookup_order": lookup, "refund": refund}, agent="support-bot")
    assert tools["lookup_order"]("o1") == {"order": "o1"}
    assert asyncio.run(tools["refund"]("o1", 5)) == 5
    listed = signafaide.wrap_tools([lookup], agent="support-bot")
    assert isinstance(listed, list) and listed[0]("o2") == {"order": "o2"}
    assert names(recorder, "support-bot") == [
        ("decision", "lookup_order"),
        ("outcome", "lookup_order"),
        ("decision", "refund"),
        ("outcome", "refund"),
        ("decision", "lookup"),
        ("outcome", "lookup"),
    ]


def test_wrap_tools_rejects_non_tools(recorder):
    with pytest.raises(TypeError, match="cannot record int"):
        signafaide.wrap_tools([3])


# --- LangChain -------------------------------------------------------------------------

@pytest.fixture
def lc_tools():
    return pytest.importorskip("langchain_core.tools")


def test_langchain_tool_decorator(recorder, lc_tools):
    @lc_tools.tool
    def get_weather(city: str) -> str:
        """Weather for a city."""
        return f"sunny in {city}"

    wrapped = signafaide.wrap_tools([get_weather])[0]
    assert wrapped.name == "get_weather" and wrapped.args == get_weather.args
    assert wrapped.invoke({"city": "Paris"}) == "sunny in Paris"
    msg = wrapped.invoke({"name": "get_weather", "args": {"city": "Rome"}, "id": "call_1", "type": "tool_call"})
    assert msg.content == "sunny in Rome" and msg.tool_call_id == "call_1"
    assert asyncio.run(wrapped.ainvoke({"city": "Oslo"})) == "sunny in Oslo"
    get_weather.invoke({"city": "Bern"})  # the original stays unrecorded
    recs = records(recorder)
    assert [r["envelope"]["kind"] for r in recs] == ["decision", "outcome"] * 3
    assert [r["content"]["input"] for r in recs[::2]] == [{"city": "Paris"}, {"city": "Rome"}, {"city": "Oslo"}]
    assert recs[3]["content"]["output"]["content"] == "sunny in Rome"


def test_langchain_tool_still_converts_for_models(recorder, lc_tools):
    from langchain_core.utils.function_calling import convert_to_openai_tool

    @lc_tools.tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    wrapped = signafaide.wrap_tool(add)
    assert convert_to_openai_tool(wrapped) == convert_to_openai_tool(add)


def test_langchain_basetool_subclass_and_errors(recorder, lc_tools):
    class Echo(lc_tools.BaseTool):
        name: str = "echo"
        description: str = "Echo text back."

        def _run(self, text: str) -> str:
            if text == "boom":
                raise RuntimeError("echo failed")
            return text

    wrapped = signafaide.wrap_tool(Echo())
    assert wrapped.invoke("hi") == "hi"
    with pytest.raises(RuntimeError, match="echo failed"):
        wrapped.invoke("boom")
    assert asyncio.run(wrapped.ainvoke("async")) == "async"
    recs = records(recorder)
    assert names(recorder) == [("decision", "echo"), ("outcome", "echo")] * 3
    assert recs[3]["content"]["error"] == {"type": "RuntimeError", "message": "echo failed"}


# --- OpenAI Agents SDK ------------------------------------------------------------------

@pytest.fixture
def agents():
    return pytest.importorskip("agents")


def test_openai_agents_function_tool(recorder, agents):
    from agents.tool_context import ToolContext

    @agents.function_tool
    def lookup_order(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id} shipped"

    wrapped = signafaide.wrap_tools([lookup_order], strict=False)[0]
    assert isinstance(wrapped, agents.FunctionTool)
    assert wrapped.name == "lookup_order" and wrapped.params_json_schema == lookup_order.params_json_schema
    args = '{"order_id": "42"}'
    ctx = ToolContext(context=None, tool_name="lookup_order", tool_call_id="c1", tool_arguments=args)
    assert asyncio.run(wrapped.on_invoke_tool(ctx, args)) == "order 42 shipped"
    d, o = records(recorder)
    assert d["envelope"]["name"] == "lookup_order" and d["content"]["input"] == {"order_id": "42"}
    assert o["content"] == {"output": "order 42 shipped"}


def test_openai_agents_strict_refuses(recorder, dead_url, agents):
    from agents.tool_context import ToolContext

    ran = []

    @agents.function_tool
    def pay(amount: int) -> str:
        """Pay."""
        ran.append(amount)
        return "paid"

    recorder._api_key = "sfa_test_" + "x" * 32
    recorder._url = dead_url
    wrapped = signafaide.wrap_tool(pay, strict=True)
    ctx = ToolContext(context=None, tool_name="pay", tool_call_id="c1", tool_arguments='{"amount": 1}')
    with pytest.raises(signafaide.NotRecorded):
        asyncio.run(wrapped.on_invoke_tool(ctx, '{"amount": 1}'))
    assert ran == []
