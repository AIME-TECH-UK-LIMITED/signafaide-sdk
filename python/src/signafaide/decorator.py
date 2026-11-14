"""``record``, ``note`` and ``wrap_tools``: the decision -> run -> outcome cycle."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import contextvars
import dataclasses
import datetime
import decimal
import enum
import functools
import inspect
import json
import logging
import math
import uuid
from pathlib import PurePath
from typing import Any, Callable, Optional

from . import jcs, runtime, telemetry
from ._version import __version__
from .http import SignafaideError
from .records import record_hash

log = logging.getLogger("signafaide")

_LC_EXTRA = ("run_manager", "config", "callbacks")  # injected by LangChain, not tool input


class NotRecorded(SignafaideError):
    """Strict mode: the decision got no receipt, so the tool did not run."""


@dataclasses.dataclass(frozen=True)
class _Spec:
    name: str
    agent: Optional[str] = None
    strict: bool = False
    store_content: Optional[bool] = None
    meta: Optional[dict] = None

    def decide(self, args: Any) -> tuple:
        rec = runtime.get()
        meta = {"sdk": f"signafaide-python/{__version__}", **(self.meta or {})}
        d = rec.write("decision", self.name, {"input": to_jsonable(args), "meta": to_jsonable(meta)}, agent=self.agent, store_content=self.store_content)
        return rec, d

    def outcome(self, rec: runtime.Recorder, d: dict, content: dict) -> None:
        try:
            rec.write("outcome", self.name, content, agent=d["envelope"]["agent"], ref=record_hash(d), store_content=self.store_content)
        except Exception as e:  # the action already happened: report, never mask its result
            log.error("signafaide: could not write the outcome of %s: %s", self.name, e)

    def strict_check(self, rec: runtime.Recorder, d: dict) -> None:
        rec.strict_used = True
        if rec.test:
            return  # test mode never sends, so there is no receipt to wait for
        try:
            rec.ensure_receipt(d)
        except SignafaideError as e:
            raise NotRecorded(f"{e.message} (strict mode: {self.name} did not run)", code=e.code, status=e.status, docs=e.docs, body=e.body) from None

    def call(self, args: Any, fn: Callable[[], Any], output: Optional[Callable[[Any], Any]] = None) -> Any:
        """Run *fn* between a decision and an outcome. *output* picks the value the outcome
        records from what *fn* returned (the tool's own return value, for adapters)."""
        if runtime.recording_disabled():
            return fn()
        rec, d = self.decide(args)
        if self.strict:
            self.strict_check(rec, d)
        try:
            out = fn()
        except BaseException as e:
            self.outcome(rec, d, _error(e))
            raise
        self.outcome(rec, d, {"output": to_jsonable(output(out) if output else out)})
        return out

    async def acall(self, args: Any, fn: Callable[[], Any], output: Optional[Callable[[Any], Any]] = None) -> Any:
        if runtime.recording_disabled():
            return await fn()
        rec, d = self.decide(args)
        if self.strict:
            await asyncio.get_running_loop().run_in_executor(None, self.strict_check, rec, d)
        try:
            out = await fn()
        except BaseException as e:
            self.outcome(rec, d, _error(e))
            raise
        self.outcome(rec, d, {"output": to_jsonable(output(out) if output else out)})
        return out


def record(
    fn: Optional[Callable] = None,
    *,
    agent: Optional[str] = None,
    name: Optional[str] = None,
    strict: bool = False,
    store_content: Optional[bool] = None,
    meta: Optional[dict] = None,
) -> Any:
    """Record every call of *fn*: a ``decision`` before it runs, an ``outcome`` after.
    ``agent`` names the chain (default: the project folder's name; give one explicitly in
    production, one name per running instance).

    Use as ``@record`` or ``@record(agent=..., name=..., strict=True)``. Works on
    sync and async functions. Errors are recorded and re-raised unchanged.
    """
    if fn is None:
        return lambda f: record(f, agent=agent, name=name, strict=strict, store_content=store_content, meta=meta)
    spec = _Spec(name or fn.__name__, agent, strict, store_content, meta)
    try:
        sig: Optional[inspect.Signature] = inspect.signature(fn)
    except (TypeError, ValueError):
        sig = None

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await spec.acall(_bind(sig, args, kwargs), lambda: fn(*args, **kwargs))

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return spec.call(_bind(sig, args, kwargs), lambda: fn(*args, **kwargs))

    return wrapper


def note(name: str, content: dict, *, agent: Optional[str] = None, store_content: Optional[bool] = None) -> str:
    """Write a ``note`` record (anything worth keeping that is not a tool call). Returns its hash
    (an empty string when recording is turned off with ``SIGNAFAIDE_DISABLED=1``)."""
    if runtime.recording_disabled():
        return ""
    rec = runtime.get().write("note", name, to_jsonable(content), agent=agent, store_content=store_content)
    return record_hash(rec)


def wrap_tools(tools: Any, *, agent: Optional[str] = None, strict: bool = False, store_content: Optional[bool] = None) -> Any:
    """Record every tool in a dict (key = tool name) or a list.

    Accepts plain functions, LangChain tools (``BaseTool`` / ``@tool``) and
    OpenAI Agents SDK ``FunctionTool``s. Returns the same shape.
    """
    opts = {"agent": agent, "strict": strict, "store_content": store_content}
    if isinstance(tools, dict):
        return {k: wrap_tool(v, name=k, **opts) for k, v in tools.items()}
    if isinstance(tools, (list, tuple)):
        return type(tools)(wrap_tool(t, **opts) for t in tools)
    return wrap_tool(tools, **opts)


def wrap_tool(tool: Any, *, name: Optional[str] = None, agent: Optional[str] = None, strict: bool = False, store_content: Optional[bool] = None) -> Any:
    """Record one tool. See :func:`wrap_tools`."""
    if _is_openai_agents_tool(tool):
        return _wrap_openai_agents(tool, _Spec(name or tool.name, agent, strict, store_content))
    if _is_langchain_tool(tool):
        return _wrap_langchain(tool, _Spec(name or tool.name, agent, strict, store_content))
    if callable(tool):
        return record(tool, agent=agent, name=name, strict=strict, store_content=store_content)
    raise TypeError(f"wrap_tools cannot record {type(tool).__name__}: pass a function, a LangChain tool or an OpenAI Agents FunctionTool")


# --- adapters -------------------------------------------------------------------


def _is_openai_agents_tool(t: Any) -> bool:
    return dataclasses.is_dataclass(t) and callable(getattr(t, "on_invoke_tool", None)) and hasattr(t, "params_json_schema")


def _wrap_openai_agents(tool: Any, spec: _Spec) -> Any:
    telemetry.ADAPTERS.add("openai-agents")
    original = tool.on_invoke_tool

    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        try:
            args = json.loads(input_json) if input_json else {}
        except ValueError:
            args = input_json
        return await spec.acall(args, lambda: original(ctx, input_json))

    return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)


def _is_langchain_tool(t: Any) -> bool:
    return any(c.__name__ == "BaseTool" and c.__module__.startswith("langchain") for c in type(t).__mro__)


def _wrap_langchain(tool: Any, spec: _Spec) -> Any:
    """Copy the tool and record at ``run`` / ``arun``, which ``invoke`` /
    ``ainvoke`` call exactly once per tool call. The outcome holds the tool's own return value:
    ``run`` wraps it in a ``ToolMessage`` when called with a tool call, so the value is taken
    where the tool returns it (``_run`` / ``_arun``)."""
    telemetry.ADAPTERS.add("langchain")
    new = tool.model_copy() if hasattr(tool, "model_copy") else tool.copy()
    run, arun = new.run, new.arun
    returned: contextvars.ContextVar[Any] = contextvars.ContextVar("signafaide_lc_returned", default=_NOTHING)
    for attr in ("_run", "_arun"):
        inner = getattr(new, attr, None)
        if inner is None:
            continue
        if attr == "_run":
            def capture(*a: Any, _inner: Any = inner, **kw: Any) -> Any:
                v = _inner(*a, **kw)
                returned.set(v)
                return v
        else:
            async def capture(*a: Any, _inner: Any = inner, **kw: Any) -> Any:  # type: ignore[misc]
                v = await _inner(*a, **kw)
                returned.set(v)
                return v
        # LangChain reads _run's signature to decide what to pass it (config, run_manager):
        # the wrapper must show the same one.
        functools.update_wrapper(capture, inner)
        with contextlib.suppress(Exception):
            object.__setattr__(new, attr, capture)

    def lc_input(tool_input: Any) -> Any:
        return {k: v for k, v in tool_input.items() if k not in _LC_EXTRA} if isinstance(tool_input, dict) else tool_input

    def tool_value(out: Any) -> Any:
        v = returned.get()
        if v is not _NOTHING:
            return v
        # Not captured (a tool type that bypasses _run): a ToolMessage still yields its content.
        return getattr(out, "content", out) if type(out).__name__ == "ToolMessage" else out

    @functools.wraps(run)
    def run_recorded(tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        returned.set(_NOTHING)
        return spec.call(lc_input(tool_input), lambda: run(tool_input, *args, **kwargs), tool_value)

    @functools.wraps(arun)
    async def arun_recorded(tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        returned.set(_NOTHING)
        return await spec.acall(lc_input(tool_input), lambda: arun(tool_input, *args, **kwargs), tool_value)

    object.__setattr__(new, "run", run_recorded)
    object.__setattr__(new, "arun", arun_recorded)
    return new


_NOTHING = object()


# --- helpers --------------------------------------------------------------------


def _bind(sig: Optional[inspect.Signature], args: tuple, kwargs: dict) -> Any:
    if sig is None:
        return {"args": list(args), "kwargs": kwargs}
    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError:  # let the function itself raise the real error
        return {"args": list(args), "kwargs": kwargs}
    bound.apply_defaults()
    out = dict(bound.arguments)
    first = next(iter(sig.parameters), None)
    if first in ("self", "cls"):
        out.pop(first, None)
    for p in sig.parameters.values():  # flatten **kwargs
        if p.kind is inspect.Parameter.VAR_KEYWORD and p.name in out:
            out.update(out.pop(p.name))
    return out


def _error(e: BaseException) -> dict:
    return {"error": {"type": type(e).__name__, "message": str(e)}}


def to_jsonable(v: Any, _seen: Optional[set] = None) -> Any:
    """Turn *v* into plain JSON values that JCS can hash (deterministically)."""
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, enum.Enum):
        return to_jsonable(v.value, _seen)
    if isinstance(v, int):  # beyond +-(2^53-1) JCS rejects ints (SPEC §1): keep the digits as text
        return int(v) if abs(v) <= jcs.MAX_SAFE_INT else str(v)
    if isinstance(v, float):  # keep non-finite and integer literals beyond 2^53 as text (SPEC §1)
        return v if math.isfinite(v) and not jcs.is_unsafe_float(v) else repr(v)
    if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
        return v.isoformat()
    if isinstance(v, (decimal.Decimal, uuid.UUID, PurePath)):
        return str(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(v)).decode()
    _seen = _seen or set()
    if id(v) in _seen:
        return "[Circular]"
    _seen = _seen | {id(v)}
    if isinstance(v, dict):
        return {str(k): to_jsonable(x, _seen) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [to_jsonable(x, _seen) for x in v]
    if isinstance(v, (set, frozenset)):
        return sorted((to_jsonable(x, _seen) for x in v), key=jcs.dumps)
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return {f.name: to_jsonable(getattr(v, f.name), _seen) for f in dataclasses.fields(v)}
    dump = getattr(v, "model_dump", None)
    if callable(dump):  # pydantic v2
        try:
            return to_jsonable(dump(mode="json"), _seen)
        except Exception:
            pass
    return str(v)
