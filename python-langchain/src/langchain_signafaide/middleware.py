"""``SignafaideMiddleware``: record every tool call a LangChain agent makes."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Iterable, Optional

import signafaide
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from signafaide import telemetry

# The recording step itself (decision, run, outcome) lives in the signafaide package. It has
# no public entry point for "record this call, which I run myself" yet, so this is the one
# place that reaches into it; tests/test_middleware.py fails if it changes shape.
from signafaide.decorator import _Spec


def _tool_output(result: Any) -> Any:
    """What the outcome records for the value a tool call produced."""
    if isinstance(result, ToolMessage):
        # A tool that failed where the agent handles tool errors comes back as an error
        # message, not an exception: keep that visible in the record.
        if getattr(result, "status", None) == "error":
            return {"tool_error": result.content}
        return result.content
    update = getattr(result, "update", None)  # a langgraph Command
    return {"command": signafaide.to_jsonable(update)} if update is not None else signafaide.to_jsonable(result)


class SignafaideMiddleware(AgentMiddleware):
    """Record every tool call of the agent as signed, chained signafAIde records.

    Args:
        agent: The name of the record chain. Give one name per running agent instance in
            production. Default: the project folder's name.
        strict: A tool runs only once its decision has a receipt from the witness. When the
            witness cannot be reached the call raises ``NotRecorded`` and the tool does not run.
        store_content: Send inputs and outputs to the witness, encrypted, as well as their
            hashes. Default: the project's setting (hashes only).
        tools: The names of every tool the agent can call. They are declared in the chain as
            recorded, so a verifier can say that all of the agent's tools are covered. Without
            it, each tool is declared when it is first called.
    """

    def __init__(
        self,
        *,
        agent: Optional[str] = None,
        strict: bool = False,
        store_content: Optional[bool] = None,
        tools: Optional[Iterable[Any]] = None,
    ) -> None:
        super().__init__()
        self._agent = agent
        self._strict = strict
        self._store_content = store_content
        self._specs: dict[str, _Spec] = {}
        telemetry.ADAPTERS.add("langchain")
        for t in tools or ():
            self._spec(t if isinstance(t, str) else t.name)

    def _spec(self, name: str) -> _Spec:
        spec = self._specs.get(name)
        if spec is None:
            spec = self._specs[name] = _Spec(name, self._agent, self._strict, self._store_content, listed=True)
        return spec

    @staticmethod
    def _call(request: Any) -> tuple[str, Any, Optional[str]]:
        call = request.tool_call
        cid = call.get("id")  # the model's tool call id
        return call["name"], call.get("args", {}), cid if isinstance(cid, str) and cid else None

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        name, args, call_id = self._call(request)
        return self._spec(name).call(args, lambda: handler(request), _tool_output, call_id=call_id)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Awaitable[Any]]) -> Any:
        name, args, call_id = self._call(request)
        return await self._spec(name).acall(args, lambda: handler(request), _tool_output, call_id=call_id)
