"""signafAIde for OpenTelemetry: signed records of the tool calls your traces already show.

    from signafaide.otel import SignafaideSpanProcessor

    provider.add_span_processor(SignafaideSpanProcessor())

The processor runs inside your own process. It recognises tool-call spans by three conventions
(OpenTelemetry GenAI, OpenInference, OpenLLMetry), and writes a signed ``decision`` and
``outcome`` record for each into ``.signafaide/``, exactly as the SDK does for a wrapped tool.
It exports nothing: span data is read where it is and goes nowhere else.

A decision is written when the span starts, before the tool runs, when the span says at its
start that it is a tool call. When the span only says so at its end, the decision and the
outcome are both written then, after the tool ran. Every record says which it was (SPEC §2.7).

Running a tool only once it is recorded (strict mode) is a feature of wrapping the tool with
the SDK, not of this processor: when a record cannot be written the tool still runs.

Needs ``opentelemetry-sdk``: install ``signafaide[otel]``.
"""

from __future__ import annotations

import json
import logging
import itertools
import threading
import weakref
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

try:
    from opentelemetry.sdk.trace import SpanProcessor
    from opentelemetry.trace import StatusCode
except ImportError as e:  # pragma: no cover - exercised by test_otel.py in a subprocess
    raise ImportError('signafaide.otel needs the OpenTelemetry SDK: install "signafaide[otel]" (or opentelemetry-sdk)') from e

from . import decorator, runtime, telemetry
from ._version import __version__
from .coverage import TELEMETRY_SAMPLED, declared_name, telemetry_note_name
from .decorator import to_jsonable
from .records import AGENT_RE, agent_name, record_hash

__all__ = ["SignafaideSpanProcessor", "tool_call"]

log = logging.getLogger("signafaide")

#: The most spans kept in mind at once (open tool calls, spans begun inside a wrapped tool). A
#: span that never ends leaves its entry here; the oldest go first.
_MAX_OPEN = 10_000

_INPUT_KEYS = ("gen_ai.tool.call.arguments", "input.value", "traceloop.entity.input")
_OUTPUT_KEYS = ("gen_ai.tool.call.result", "output.value", "traceloop.entity.output")
_ID_KEYS = ("gen_ai.tool.call.id", "tool_call.id")
_NAME_KEYS = {"gen_ai": "gen_ai.tool.name", "openinference": "tool.name", "traceloop": "traceloop.entity.name"}


def _text(v: Any) -> str:
    return v if isinstance(v, str) else ""


def tool_call(span_name: str, attributes: Optional[Mapping[str, Any]]) -> Optional[dict]:
    """What a span says about a tool call, or None when it is not one:
    ``{"convention", "tool", "id"?, "input"?, "output"?}``. A span is a tool call when
    ``gen_ai.operation.name`` is ``execute_tool`` (OpenTelemetry GenAI), ``openinference.span.kind``
    is ``TOOL`` (OpenInference) or ``traceloop.span.kind`` is ``tool`` (OpenLLMetry)."""
    a = attributes or {}
    if a.get("gen_ai.operation.name") == "execute_tool":
        convention = "gen_ai"
    elif _text(a.get("openinference.span.kind")).upper() == "TOOL":
        convention = "openinference"
    elif _text(a.get("traceloop.span.kind")).lower() == "tool":
        convention = "traceloop"
    else:
        return None
    # The tool's name: the convention's own attribute, then the others', then the span's name.
    tool = next((_text(a.get(k)) for k in (_NAME_KEYS[convention], *_NAME_KEYS.values()) if _text(a.get(k))), "")
    if not tool:
        tool = span_name[len("execute_tool "):] if span_name.startswith("execute_tool ") else span_name[: -len(".tool")] if span_name.endswith(".tool") else span_name
    if not tool:
        return None
    call: dict = {"convention": convention, "tool": tool}
    for field, keys in (("id", _ID_KEYS), ("input", _INPUT_KEYS), ("output", _OUTPUT_KEYS)):
        for k in keys:
            if a.get(k) is not None:
                call[field] = a[k]
                break
    return call


def _value(v: Any) -> Any:
    """A span attribute as record content: JSON text is parsed, anything else is kept as it is."""
    if isinstance(v, str) and v[:1] in ("{", "[", '"'):
        try:
            return to_jsonable(json.loads(v))
        except ValueError:
            return v
    return to_jsonable(v)


def _time(ns: Optional[int]) -> Optional[str]:
    if not ns:
        return None
    return datetime.fromtimestamp(ns // 1_000_000 / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ns // 1_000_000 % 1000:03d}Z"


def _always_on(sampler: Any) -> bool:
    try:
        return sampler.get_description() == "AlwaysOnSampler"
    except Exception:
        return False


class SignafaideSpanProcessor(SpanProcessor):
    """Write signafAIde records for the tool-call spans of a tracer provider.

    Args:
        agent: The name of the record chain. Default: the tracer resource's ``service.name``,
            else the project folder's name. Give one name per running agent instance.
        store_content: Send inputs and outputs to the witness, encrypted, as well as their
            hashes. Default: the project's setting (hashes only).
        declare_tools: Declare each tool seen in a span as one of the agent's recorded tools
            (SPEC §2.6). Default True. The declaration lists the tools seen so far, never a
            complete tool list.
    """

    def __init__(self, *, agent: Optional[str] = None, store_content: Optional[bool] = None, declare_tools: bool = True) -> None:
        if agent is not None and not (isinstance(agent, str) and AGENT_RE.match(agent)):
            raise ValueError(f"agent {agent!r} is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)")
        self._agent = agent
        self._store_content = store_content
        self._declare = declare_tools
        self._lock = threading.Lock()
        #: span id -> the decision written when the span started.
        self._open: "OrderedDict[int, dict]" = OrderedDict()
        #: span id -> the wrapped tool (runtime.RECORDING) whose call the span began inside.
        self._inside: "OrderedDict[int, str]" = OrderedDict()
        #: span id -> the tick at which the span began, for spans that did not say at their start
        #: that they are a tool call (see ``_claim``).
        self._began: "OrderedDict[int, int]" = OrderedDict()
        #: span ids left alone at their start (a wrapper or a gateway records the call).
        self._skipped: "OrderedDict[int, bool]" = OrderedDict()
        #: recorder -> (agent, tool) -> "start" | "end": the telemetry note last written for the tool.
        self._noted: "weakref.WeakKeyDictionary[runtime.Recorder, dict]" = weakref.WeakKeyDictionary()
        #: recorder -> the agents whose sampling was looked at.
        self._sampling_noted: "weakref.WeakKeyDictionary[runtime.Recorder, set]" = weakref.WeakKeyDictionary()
        self._gateway: dict = {}  # agent -> (file stamp, tools a gateway on this machine records)
        self._warned = False
        telemetry.ADAPTERS.add("otel")
        _processors.add(self)
        runtime.telemetry_adopt = _adopt
        runtime.telemetry_claim = _claim

    # --- the SpanProcessor interface: none of these ever raises -----------------------

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        try:
            self._started(span)
        except Exception as e:  # noqa: BLE001  the application must never see it
            self._warn(e)

    def on_end(self, span: Any) -> None:
        try:
            self._ended(span)
        except Exception as e:  # noqa: BLE001
            self._warn(e)

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    # --- recording ------------------------------------------------------------------

    def _warn(self, e: Exception) -> None:
        if not self._warned:
            self._warned = True
            log.warning("signafaide: could not record a tool call from its span (%s); the tool runs all the same, and later failures are not reported again", e)

    def _keep(self, held: "OrderedDict[int, Any]", span_id: int, value: Any) -> None:
        with self._lock:
            held[span_id] = value
            while len(held) > _MAX_OPEN:
                held.popitem(last=False)

    def _agent_of(self, span: Any, rec: runtime.Recorder) -> str:
        if self._agent:
            return self._agent
        service = _text((getattr(getattr(span, "resource", None), "attributes", None) or {}).get("service.name"))
        if service and not service.startswith("unknown_service"):
            return agent_name(service)
        return rec.default_agent

    def _by_gateway(self, rec: runtime.Recorder, agent: str, tool: str) -> bool:
        """An MCP gateway on this machine records this tool for the same agent (§8 ``tools/<agent>.json``)."""
        path = rec.state.tools_path(agent)
        try:
            st = path.stat()
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            return False
        held = self._gateway.get(agent)
        if held is None or held[0] != stamp:
            names = set()
            for source, entry in rec.state.tool_entries(agent).items():
                if source.startswith("gateway:"):
                    prefix = source[len("gateway:"):]
                    for name, recorded in (entry.get("tools") or {}).items():
                        if recorded:
                            names.add(name)
                            if name.startswith(prefix):
                                names.add(name[len(prefix):])
            held = self._gateway[agent] = (stamp, names)
        return tool in held[1]

    def _started(self, span: Any) -> None:
        if runtime.recording_disabled():
            return
        span_id = span.get_span_context().span_id
        wrapped = runtime.RECORDING.get()
        call = tool_call(span.name, span.attributes)
        if call is None:
            self._keep(self._began, span_id, next(_ticks))
            if wrapped:  # it may turn out to be the wrapped tool's own span when it ends
                self._keep(self._inside, span_id, wrapped)
            return
        if wrapped == call["tool"]:  # a wrapper of the SDK is recording this very call: its records stand
            _claimed(wrapped, 0)
            self._keep(self._skipped, span_id, True)
            return
        rec = runtime.get()
        agent = self._agent_of(span, rec)
        if self._by_gateway(rec, agent, call["tool"]):
            self._keep(self._skipped, span_id, True)
            return
        d = self._decide(rec, agent, span, call, at_start=True)
        self._keep(self._open, span_id, {"rec": rec, "decision": d, "tool": call["tool"], "input": "input" in call})

    def _ended(self, span: Any) -> None:
        span_id = span.get_span_context().span_id
        with self._lock:
            held = self._open.pop(span_id, None)
            wrapped = self._inside.pop(span_id, None)
            began = self._began.pop(span_id, 0)
            skipped = self._skipped.pop(span_id, False)
        if skipped or runtime.recording_disabled():
            return
        call = tool_call(span.name, span.attributes)
        if held is None:
            if call is None:
                return
            if call["tool"] == wrapped:  # the span began inside the wrapper's call
                _claimed(wrapped, began)
                return
            if _claimed(call["tool"], began):  # the wrapper ran inside the span
                return
            rec = runtime.get()
            agent = self._agent_of(span, rec)
            if self._by_gateway(rec, agent, call["tool"]):
                return
            d = self._decide(rec, agent, span, call, at_start=False)
            held = {"rec": rec, "decision": d, "tool": call["tool"], "input": True}
        call = call or {}
        meta = {"telemetry": self._marker(span, call)}
        status = getattr(span, "status", None)
        if status is not None and status.status_code is StatusCode.ERROR:
            content: dict = {"error": self._error(span, status), "meta": meta}
        else:
            content = {"output": _value(call["output"]) if "output" in call else None, "meta": meta}
            if "output" not in call:
                meta["telemetry"]["output"] = "not in the span"
        if not held["input"] and "input" in call:  # the span named its arguments only after it started
            content["input"] = _value(call["input"])
        d = held["decision"]
        held["rec"].write("outcome", d["envelope"]["name"], content, agent=d["envelope"]["agent"], ref=record_hash(d), store_content=self._store_content)

    @staticmethod
    def _marker(span: Any, call: dict) -> dict:
        ctx = span.get_span_context()
        m = {"source": "opentelemetry", "trace_id": f"{ctx.trace_id:032x}", "span_id": f"{ctx.span_id:016x}"}
        if call.get("convention"):
            m["convention"] = call["convention"]
        return m

    @staticmethod
    def _error(span: Any, status: Any) -> dict:
        kind, message = _text((span.attributes or {}).get("error.type")), _text(status.description)
        for event in getattr(span, "events", None) or ():
            if event.name == "exception":
                a = event.attributes or {}
                kind = _text(a.get("exception.type")) or kind
                message = _text(a.get("exception.message")) or message
        return {"type": kind or "Error", "message": message}

    def _decide(self, rec: runtime.Recorder, agent: str, span: Any, call: dict, *, at_start: bool) -> dict:
        """Write the decision of a tool call, behind the notes that say where it comes from
        (§2.7): that the telemetry is sampled, once per agent, and whether this tool's decisions
        are written at span start or span end, once per tool and again when that changes. The
        notes and the decision are one run, so nothing lies between them."""
        tool = call["tool"]
        decorator._remember(decorator._WRAPPED, agent, tool)
        if self._declare:
            decorator._remember(decorator._LISTED, agent, tool)
        decorator._declare_before_call(rec, agent)
        items: list = []
        sampled = self._sampling_noted.setdefault(rec, set())
        noted = self._noted.setdefault(rec, {})
        sampler = getattr(span, "_sampler", None)
        if agent not in sampled and sampler is not None and not _always_on(sampler):
            items.append(("note", TELEMETRY_SAMPLED, {"source": "opentelemetry", "sampler": _text(sampler.get_description())}, None))
        when = "start" if at_start else "end"
        if noted.get((agent, tool)) != when:
            items.append(("note", telemetry_note_name(tool, at_start), {"source": "opentelemetry", "tool": tool, "decision_written": "before" if at_start else "after"}, None))
        marker = {**self._marker(span, call), "decision_written": "before" if at_start else "after"}
        started = _time(getattr(span, "start_time", None))
        if started:
            marker["span_start"] = started
        if call.get("id") is not None:
            marker["tool_call_id"] = _text(call["id"]) or to_jsonable(call["id"])
        if "input" not in call:
            marker["input"] = "not in the span at its start" if at_start else "not in the span"
        meta: dict = {"sdk": f"signafaide-python/{__version__}", "telemetry": marker}
        name = declared_name(tool)
        if name != tool:
            meta["tool"] = tool
        items.append(("decision", name, {"input": _value(call["input"]) if "input" in call else None, "meta": meta}, None))
        d = rec.write_run(items, agent=agent, store_content=self._store_content)[-1]
        sampled.add(agent)
        noted[(agent, tool)] = when
        return d

    # --- one call, one decision (with the SDK's wrappers) --------------------------------

    def _adopt(self, name: str) -> Optional[tuple]:
        with self._lock:
            for held in reversed(self._open.values()):
                if held["tool"] == name and not held.get("adopted"):
                    held["adopted"] = True
                    return held["rec"], held["decision"]
        return None


_processors: "weakref.WeakSet[SignafaideSpanProcessor]" = weakref.WeakSet()
#: Counts span starts and wrapper calls, so their order is known without a clock.
_ticks = itertools.count(1)
#: Tool calls a wrapper of the SDK recorded, not yet matched to a span: [tool, tick].
_claims: list = []
_claims_lock = threading.Lock()


def _adopt(name: str) -> Optional[tuple]:
    """The decision this plug-in wrote at the start of a span of the tool *name* that is still
    running and that no wrapper has taken yet: the SDK wrapper running inside that span then
    writes no second decision (the plug-in writes the outcome when the span ends)."""
    try:
        for p in list(_processors):
            got = p._adopt(name)
            if got is not None:
                return got
    except Exception:  # noqa: BLE001
        pass
    return None


def _claim(name: str) -> None:
    """A wrapper of the SDK has just written the decision of a call of the tool *name*. A span
    of that tool that began before now, and says only at its end that it is a tool call, is that
    call's own span and is not recorded again."""
    with _claims_lock:
        _claims.append([name, next(_ticks)])
        del _claims[:-_MAX_OPEN]


def _claimed(tool: str, began: int) -> bool:
    """Whether a wrapper recorded a call of *tool* after the tick *began* (a span's start), and
    forget that call: one wrapper call answers for one span."""
    with _claims_lock:
        for i, (name, at) in enumerate(_claims):
            if name == tool and at > began:
                del _claims[i]
                return True
    return False
