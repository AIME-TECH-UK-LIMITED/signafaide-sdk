"""``record``, ``note``, ``wrap_tools`` and ``declare_tools``: the decision -> run -> outcome
cycle, and the agent's tool list (SPEC §2.6)."""

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
import os
import sys
import threading
import uuid
import weakref
from pathlib import PurePath

from . import notes as _notes
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import checks as checks_lib
from . import jcs, runtime, telemetry
from ._version import __version__
from .checks_runtime import CheckError, Plan, SignafaideBlocked, ToolInfo, call_link
from .coverage import declared_name
from .http import SignafaideError
from .records import record_hash

log = logging.getLogger("signafaide")

_LC_EXTRA = ("run_manager", "config", "callbacks")  # injected by LangChain, not tool input


class NotRecorded(SignafaideError):
    """The tool is protected and its decision got no receipt, so the tool did not run."""


# --- the agent's tool list (§2.6) -------------------------------------------------

#: Tool names the SDK has wrapped in this process, by agent ("" is the default agent).
_WRAPPED: Dict[str, Set[str]] = {}
#: Of those, the ones wrapped by ``wrap_tools`` / ``wrap_tool``, which declare themselves.
_LISTED: Dict[str, Set[str]] = {}
#: The full tool list given to ``declare_tools``, by agent: (names, unrecorded).
_EXPLICIT: Dict[str, Tuple[list, Set[str]]] = {}
#: Tool names a wrapper of the SDK records in this process (``record``, ``wrap_tools``,
#: ``wrap_tool``), with a framework tool's own name when the wrapper names it otherwise. With
#: tool-call checks on, the telemetry plug-in leaves a span of such a tool to the wrapper (§8):
#: the wrapper's decision carries the checks, and a span's decision written at its start would not.
_BY_WRAPPER: Set[str] = set()
#: Of those, the names a wrapper protects (strict in code): checked even without a checks file.
_STRICT_BY_WRAPPER: Set[str] = set()


def wrapper_records(name: str) -> bool:
    """Whether a wrapper of the SDK in this process records tool calls named *name*."""
    return name in _BY_WRAPPER


def wrapper_protects(name: str) -> bool:
    """Whether a wrapper of the SDK in this process protects tool calls named *name* (strict in code)."""
    return name in _STRICT_BY_WRAPPER


#: Bumped whenever one of the three changes, so a recorder looks again only then.
_tools_version = 0
#: recorder -> agent -> the ``_tools_version`` its declaration was last checked at.
_checked: "weakref.WeakKeyDictionary[runtime.Recorder, Dict[str, int]]" = weakref.WeakKeyDictionary()
_tools_lock = threading.RLock()
_told_declare = False


def auto_declare_tools() -> bool:
    """``SIGNAFAIDE_DECLARE_TOOLS=0`` turns off the declarations ``wrap_tools`` writes by itself."""
    return os.environ.get("SIGNAFAIDE_DECLARE_TOOLS", "").strip().lower() not in ("0", "false", "no", "off")


def _remember(registry: Dict[str, Set[str]], agent: Optional[str], name: str) -> None:
    global _tools_version
    with _tools_lock:
        names = registry.setdefault(agent or "", set())
        if name not in names:
            names.add(name)
            _tools_version += 1


def _names_for(registry: Dict[str, Set[str]], agent: str, is_default: bool) -> Set[str]:
    """The names in *registry* for *agent*: its own, and the default agent's when it is that one."""
    return set(registry.get(agent, ())) | (set(registry.get("", ())) if is_default else set())


def _own_tools(rec: runtime.Recorder, agent: str) -> Optional[Tuple[Dict[str, bool], str]]:
    """What this program declares for *agent*: the list given to ``declare_tools`` (a tool
    recorded when the SDK wrapped it here and it was not named unrecorded), else the tools
    ``wrap_tools`` wrapped, or None when there is nothing to declare."""
    is_default = agent == rec.default_agent
    explicit = _EXPLICIT.get(agent) or (_EXPLICIT.get("") if is_default else None)
    if explicit:
        wrapped = _names_for(_WRAPPED, agent, is_default)
        tools = {n: n in wrapped and n not in explicit[1] for n in explicit[0]}
        tools.update({n: False for n in explicit[1]})
        return tools, "declared"
    listed = _names_for(_LISTED, agent, is_default)
    if not listed or not auto_declare_tools():
        return None
    return {n: True for n in listed}, "wrap_tools"


def _declare_own(rec: runtime.Recorder, agent_opt: Optional[str]) -> str:
    """Write the agent's tool declaration when this program has one the recorder has not written
    yet. Returns the header's hash, or "" when there is nothing to declare."""
    agent = agent_opt or rec.default_agent
    own = _own_tools(rec, agent)
    if own is None:
        return ""
    return rec.declare_tools(own[0], source="sdk", origin=own[1], agent=agent)


def _declare_before_call(rec: runtime.Recorder, agent_opt: Optional[str]) -> None:
    """Before a decision: declare the tools, once per change. Never fails the tool call."""
    global _told_declare
    agent = agent_opt or rec.default_agent
    with _tools_lock:
        seen = _checked.setdefault(rec, {})
        if seen.get(agent) == _tools_version or runtime.NO_WRITES.get():
            return
        version = _tools_version
        try:
            _declare_own(rec, agent_opt)
        except Exception as e:  # tried once for this list; the tool call goes on
            if not _told_declare:
                _told_declare = True
                print(f"signafaide: could not write the tool declaration for {agent}: {e}", file=sys.stderr)
        seen[agent] = version


def declare_tools(names: Iterable[str], *, agent: Optional[str] = None, unrecorded: Iterable[str] = ()) -> str:
    """Declare the agent's full tool list (SPEC §2.6), so a verifier can say which of the agent's
    tools are recorded. A name is declared recorded when the SDK wrapped a tool of that name in
    this process (``record``, ``wrap_tools``, ``wrap_tool``), otherwise not recorded;
    ``unrecorded`` names tools that are not wrapped. The declaration is a signed note per tool in
    the agent's chain: it is evidence of what the program said its tools were, not proof that the
    list is complete. Written now, and again by itself when a tool of the list is wrapped later.
    Returns the hash of the ``signafaide.tools`` note ("" when recording is turned off)."""
    global _tools_version
    listed, skipped = list(names), list(unrecorded)
    for n in listed + skipped:
        if not isinstance(n, str) or not n:
            raise TypeError("declare_tools needs tool names: non-empty strings")
    with _tools_lock:
        _EXPLICIT[agent or ""] = (listed, set(skipped))
        _tools_version += 1
        if runtime.recording_disabled():
            return ""
        rec = runtime.get()
        h = _declare_own(rec, agent)
        _checked.setdefault(rec, {})[agent or rec.default_agent] = _tools_version
        return h


def _reset_tool_registry() -> None:
    """Forget every wrapped and declared tool (tests)."""
    global _tools_version, _told_declare
    with _tools_lock:
        _WRAPPED.clear()
        _LISTED.clear()
        _EXPLICIT.clear()
        _BY_WRAPPER.clear()
        _STRICT_BY_WRAPPER.clear()
        _tools_version += 1
        _told_declare = False


@dataclasses.dataclass(frozen=True)
class _Spec:
    name: str
    agent: Optional[str] = None
    strict: bool = False
    store_content: Optional[bool] = None
    meta: Optional[dict] = None
    #: Wrapped by ``wrap_tools`` / ``wrap_tool``: part of the tool list it declares.
    listed: bool = False
    #: What the agent is shown of the tool, for its fingerprints (§11.1): a framework tool's
    #: description and input schema; a plain function has none.
    tool: Optional[ToolInfo] = None
    #: ``protect``: strict and fail closed, whatever a version 1 checks file says.
    protect: bool = False
    #: Names of the positional arguments (spec 1.1), when given.
    args: Optional[Tuple[str, ...]] = None
    #: Called with each note of this tool's calls (§8 notes: a possible hidden instruction).
    on_note: Optional[Callable[[dict], None]] = None

    def __post_init__(self) -> None:
        _BY_WRAPPER.add(self.name)
        if self.tool is not None and self.tool.name:
            _BY_WRAPPER.add(self.tool.name)
        if self.strict:
            _STRICT_BY_WRAPPER.update(n for n in (self.name, self.tool.name if self.tool is not None else None) if n)
        _remember(_WRAPPED, self.agent, self.name)
        if self.listed:
            _remember(_LISTED, self.agent, self.name)
        # The agent is shown the tool from now on: its fingerprints are approved the first time (§8).
        if self.tool is not None and not runtime.recording_disabled():
            try:
                rec = runtime.get()
                rec.checks.seen(self.tool, self.agent or rec.default_agent, declared_name(self.name), protect=bool(self.strict))
            except Exception:  # the first call reports what is wrong
                pass

    def decide(self, args: Any, plan: Optional[Plan] = None) -> tuple:
        rec = runtime.get()
        _declare_before_call(rec, self.agent)
        meta = {"sdk": f"signafaide-python/{__version__}", **(self.meta or {})}
        # Where a strict call's protection comes from (§8, SDK 0.5.2): code, checks file, console.
        if plan is not None and plan.strict and plan.protected_by:
            meta["protected_by"] = list(plan.protected_by)
        elif plan is None and self.strict:
            meta["protected_by"] = ["code"]
        extra = {"checks": plan.checks, "disclosed": plan.disclosed, "disclosed_salt": plan.disclosed_salt} if plan is not None else {}
        d = rec.write("decision", self.name, {"input": to_jsonable(args), "meta": to_jsonable(meta)}, agent=self.agent, store_content=self.store_content, **extra)
        return rec, d

    def tool_info(self) -> ToolInfo:
        return self.tool or ToolInfo(self.name)

    def _checked_begin(self, args: Any, call_id: Optional[str]) -> Tuple[Optional[tuple], Optional[Plan]]:
        """:meth:`_begin` with the tool-call checks (§8 steps 1 and 2) when a checks file is in
        place: the plan of the call, and its decision written with ``checks``."""
        rec = runtime.get()
        decl = declared_name(self.name)
        # A tool protected in code, or from the console (the held rule set's `protect`, §8), is
        # checked even without a checks file (every check On).
        if not rec.checks.enabled(protect=bool(self.strict), tool=decl):
            held = rec.checks.held_rules()
            rec.checks.observe_console(decl, False, held["version"] if held else None)
            return self._begin(args, call_id), None
        # The checks name the tool as the envelope does (the wrapper's name, declared, §2.6); the
        # fingerprints cover what the agent is shown of it (§11.1).
        plan = rec.checks.plan(self.tool_info(), self.agent or rec.default_agent, to_jsonable(args), strict_code=self.strict, call_id=call_id,
                               declared=declared_name(self.name), protect=self.protect)
        # With checks on the wrapper never takes over a span's decision: it writes its own, with
        # the checks, and asks for the ruling of a strict call (§8).
        return self._begin(args, call_id, lambda a: self.decide(a, plan), adopt=False), plan

    def outcome_checked(self, rec: runtime.Recorder, d: dict, content: dict, *, ran: bool, ruling: str, results: Optional[list] = None) -> None:
        results = results or []
        checks = {"ran": ran, "ruling": ruling, "results": results, "result": checks_lib.combined(results)}
        try:
            rec.write("outcome", self.name, content, agent=d["envelope"]["agent"], ref=record_hash(d), store_content=self.store_content, checks=checks)
        except Exception as e:  # report, never mask the call's own result
            log.error("signafaide: could not write the outcome of %s: %s", self.name, e)

    def _refused(self, rec: runtime.Recorder, d: dict, err: CheckError, ruling: str) -> CheckError:
        """The outcome of a call that did not run (§8 steps 3 and 4), and the error to raise."""
        if isinstance(err, SignafaideBlocked):
            h = record_hash(d)
            err.attach(h, call_link(rec, h))
        e: Dict[str, Any] = {"type": "Blocked" if err.code == "blocked" else "NotRun", "message": err.message}
        if err.code != "blocked":
            e["code"] = err.code
        if err.check:
            e["check"] = err.check
        if err.rule:
            e["rule"] = err.rule
        self.outcome_checked(rec, d, {"error": e}, ran=False, ruling=ruling)
        if err.code != "blocked":
            rec.note_strict_refused(self.name, err)
        return err

    def _notify(self, rec: runtime.Recorder, found: List[dict], result: Any = None, has_result: bool = False) -> None:
        """Hand the call's notes to the caller (§8 notes); with a result, keep them for ``notes(result)``."""
        _notes.deliver(found, own=self.on_note, development=_notes.development(rec), result=result, has_result=has_result)

    def _ran(self, rec: runtime.Recorder, d: dict, ruling: str, value: Any, plan: Optional[Plan] = None, returned: Any = None) -> None:
        results = rec.checks.result_entries(value, tool=declared_name(self.name), protect=bool(self.strict))
        withheld = rec.checks.withheld(self.name, results)
        found = (plan.notes if plan is not None else []) + rec.checks.result_notes(declared_name(self.name), results)
        self._notify(rec, found, returned, has_result=withheld is None)
        if withheld is not None:
            # The result holds a secret: the agent gets this error instead, and the record keeps
            # the finding, never the result (§8 step 5).
            h = record_hash(d)
            withheld.attach(h, call_link(rec, h))
            self.outcome_checked(rec, d, {"error": {"type": "Withheld", "message": withheld.message, "check": withheld.check}}, ran=True, ruling=ruling, results=results)
            raise withheld
        self.outcome_checked(rec, d, {"output": value}, ran=True, ruling=ruling, results=results)

    def _checked_call(self, rec: runtime.Recorder, d: dict, plan: Plan, fn: Callable[[], Any], output: Optional[Callable[[Any], Any]], claimed: Any) -> Any:
        try:
            if plan.blocked is not None:
                self._notify(rec, plan.notes)
                raise self._refused(rec, d, plan.blocked, "not_asked")
            ruling = "not_asked"
            if plan.strict:
                rec.strict_used = True
                ruling, err = rec.checks.ruling(d, plan, self.name)
                if err is not None:
                    self._notify(rec, plan.notes)
                    raise self._refused(rec, d, err, ruling)
            token = runtime.RECORDING.set(self.name)
            try:
                out = fn()
            except BaseException as e:
                self.outcome_checked(rec, d, _error(e), ran=True, ruling=ruling)
                self._notify(rec, plan.notes)
                raise
            finally:
                runtime.RECORDING.reset(token)
        finally:
            self._ended(claimed)
        self._ran(rec, d, ruling, to_jsonable(output(out) if output else out), plan, out)
        return out

    async def _checked_acall(self, rec: runtime.Recorder, d: dict, plan: Plan, fn: Callable[[], Any], output: Optional[Callable[[Any], Any]], claimed: Any) -> Any:
        try:
            if plan.blocked is not None:
                self._notify(rec, plan.notes)
                raise self._refused(rec, d, plan.blocked, "not_asked")
            ruling = "not_asked"
            if plan.strict:
                rec.strict_used = True
                ruling, err = await asyncio.get_running_loop().run_in_executor(None, rec.checks.ruling, d, plan, self.name)
                if err is not None:
                    self._notify(rec, plan.notes)
                    raise self._refused(rec, d, err, ruling)
            token = runtime.RECORDING.set(self.name)
            try:
                out = await fn()
            except BaseException as e:
                self.outcome_checked(rec, d, _error(e), ran=True, ruling=ruling)
                self._notify(rec, plan.notes)
                raise
            finally:
                runtime.RECORDING.reset(token)
        finally:
            self._ended(claimed)
        self._ran(rec, d, ruling, to_jsonable(output(out) if output else out), plan, out)
        return out

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
            # Agent frameworks often swallow a tool's error (the model just sees a failed tool):
            # say once, on stderr, that a strict tool did not run and how to fix it.
            rec.note_strict_refused(self.name, e)
            raise NotRecorded(f"{e.message} ({self.name} is protected and did not run)", code=e.code, status=e.status, docs=e.docs, body=e.body) from None

    def _begin(self, args: Any, call_id: Optional[str], decide: Optional[Callable[[Any], tuple]] = None, *, adopt: bool = True) -> Optional[tuple]:
        """The decision of this call, or None when the telemetry plug-in has already written it for
        the tool span that is running now (it then writes the outcome too): one call, one decision.
        Not with *adopt* False (tool-call checks on)."""
        take = runtime.telemetry_adopt if adopt else None
        held = take(self.name, call_id) if take else None
        if held is not None:
            return None if not self.strict else (held[0], held[1], True, None)
        rec, d = (decide or self.decide)(args)
        claim = runtime.telemetry_claim
        alias = self.tool.name if self.tool is not None and self.tool.name != self.name else None
        return rec, d, False, claim(self.name, call_id, alias) if claim else None

    @staticmethod
    def _ended(claimed: Any) -> None:
        done = runtime.telemetry_done
        if claimed is not None and done:
            done(claimed)

    def call(self, args: Any, fn: Callable[[], Any], output: Optional[Callable[[Any], Any]] = None, *, call_id: Optional[str] = None) -> Any:
        """Run *fn* between a decision and an outcome. *output* picks the value the outcome
        records from what *fn* returned (the tool's own return value, for adapters). *call_id* is
        the model's tool call id, when the adapter has it: the telemetry plug-in matches the
        call's span by it."""
        if runtime.recording_disabled():
            return fn()
        # §8 (SDK 0.5.2): the rule set is fetched at start, with or without a checks file; while
        # no version is held, a call waits for the first fetch (at most RULES_START_WAIT_MS).
        runtime.get().checks.start_wait()
        begun, plan = self._checked_begin(args, call_id)
        if begun is None:
            return fn()
        rec, d, adopted, claimed = begun
        if plan is not None and not adopted:
            return self._checked_call(rec, d, plan, fn, output, claimed)
        if self.strict:
            self.strict_check(rec, d)
        if adopted:
            return fn()
        token = runtime.RECORDING.set(self.name)
        try:
            out = fn()
        except BaseException as e:
            self.outcome(rec, d, _error(e))
            raise
        finally:
            runtime.RECORDING.reset(token)
            self._ended(claimed)
        self.outcome(rec, d, {"output": to_jsonable(output(out) if output else out)})
        return out

    async def acall(self, args: Any, fn: Callable[[], Any], output: Optional[Callable[[Any], Any]] = None, *, call_id: Optional[str] = None) -> Any:
        if runtime.recording_disabled():
            return await fn()
        await asyncio.get_running_loop().run_in_executor(None, runtime.get().checks.start_wait)
        begun, plan = self._checked_begin(args, call_id)
        if begun is None:
            return await fn()
        rec, d, adopted, claimed = begun
        if plan is not None and not adopted:
            return await self._checked_acall(rec, d, plan, fn, output, claimed)
        if self.strict:
            await asyncio.get_running_loop().run_in_executor(None, self.strict_check, rec, d)
        if adopted:
            return await fn()
        token = runtime.RECORDING.set(self.name)
        try:
            out = await fn()
        except BaseException as e:
            self.outcome(rec, d, _error(e))
            raise
        finally:
            runtime.RECORDING.reset(token)
            self._ended(claimed)
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
    args: Optional[Iterable[str]] = None,
    on_note: Optional[Callable[[dict], None]] = None,
) -> Any:
    """Record every call of *fn*: a ``decision`` before it runs, an ``outcome`` after.
    ``agent`` names the chain (default: the project folder's name; give one explicitly in
    production, one name per running instance).

    Use as ``@record`` or ``@record(agent=..., name=..., strict=True)``. Works on
    sync and async functions. Errors are recorded and re-raised unchanged. *on_note* is called
    with each note of the tool's calls (a possible hidden instruction in the arguments or the
    result); :func:`signafaide.notes` gives those of a returned value.
    """
    names = _arg_names(args)
    if fn is None:
        return lambda f: record(f, agent=agent, name=name, strict=strict, store_content=store_content, meta=meta, args=names, on_note=on_note)
    return _record_with(_Spec(name or fn.__name__, agent, strict, store_content, meta, args=names, on_note=on_note), fn)


def protect(
    fn: Optional[Callable] = None,
    *,
    agent: Optional[str] = None,
    name: Optional[str] = None,
    args: Optional[Iterable[str]] = None,
    store_content: Optional[bool] = None,
    meta: Optional[dict] = None,
    on_note: Optional[Callable[[dict], None]] = None,
) -> Any:
    """Protect a tool (spec 1.1): record every call of *fn*, and run it only when signafAIde
    allows it. Each call waits for the witness's ruling under the project's rules
    and, if signafAIde can't be reached, stops (Stop, unless the rule set chooses Let it run for the tool), and sends the
    witness only the fields of the call that the rules can use and that ``signafaide.checks.json``
    lists for the tool (``signafaide pull`` asks before it adds one). A blocked call raises
    :class:`SignafaideBlocked`, whose message says why in one sentence, with the rule in words and
    a link to the call. The arguments are named by the function's signature; *args* names them
    when the signature cannot (``*args`` functions, builtins).

    Use as ``@protect`` or ``protect(fn, args=["payee", "amount", "currency"])``."""
    names = _arg_names(args)
    if fn is None:
        return lambda f: protect(f, agent=agent, name=name, args=names, store_content=store_content, meta=meta, on_note=on_note)
    return _record_with(_Spec(name or fn.__name__, agent, True, store_content, meta, protect=True, args=names, on_note=on_note), fn)


def _arg_names(args: Optional[Iterable[str]]) -> Optional[Tuple[str, ...]]:
    if args is None:
        return None
    names = tuple(args)
    if not names or not all(isinstance(n, str) and n for n in names) or len(set(names)) != len(names):
        raise TypeError('args names the positional arguments: distinct non-empty strings, for example args=["payee", "amount", "currency"]')
    return names


def _named(names: Tuple[str, ...], args: tuple, kwargs: dict) -> dict:
    """The decision's input when *names* names the positional arguments (spec 1.1); arguments past
    the names are kept, in order, under ``"_rest"``."""
    out = {n: a for n, a in zip(names, args)}
    if len(args) > len(names):
        out["_rest"] = list(args[len(names):])
    out.update(kwargs)
    return out


def _record_with(spec: _Spec, fn: Callable) -> Any:
    try:
        sig: Optional[inspect.Signature] = inspect.signature(fn)
    except (TypeError, ValueError):
        sig = None
    if spec.args is not None:
        names = spec.args

        def bind(a: tuple, kw: dict) -> Any:
            return _named(names, a, kw)
    else:
        def bind(a: tuple, kw: dict) -> Any:
            return _bind(sig, a, kw)

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await spec.acall(bind(args, kwargs), lambda: fn(*args, **kwargs))

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return spec.call(bind(args, kwargs), lambda: fn(*args, **kwargs))

    return wrapper


def note(name: str, content: dict, *, agent: Optional[str] = None, store_content: Optional[bool] = None) -> str:
    """Write a ``note`` record (anything worth keeping that is not a tool call). Returns its hash
    (an empty string when recording is turned off with ``SIGNAFAIDE_DISABLED=1``)."""
    if runtime.recording_disabled():
        return ""
    rec = runtime.get().write("note", name, to_jsonable(content), agent=agent, store_content=store_content)
    return record_hash(rec)


def wrap_tools(tools: Any, *, agent: Optional[str] = None, strict: bool = False, store_content: Optional[bool] = None, declare_tools: bool = True,
               on_note: Optional[Callable[[dict], None]] = None) -> Any:
    """Record every tool in a dict (key = tool name) or a list.

    Accepts plain functions, LangChain tools (``BaseTool`` / ``@tool``) and
    OpenAI Agents SDK ``FunctionTool``s. Returns the same shape. The wrapped tools are declared
    as the agent's recorded tools (SPEC §2.6, see :func:`declare_tools`) with the first recorded
    call, unless ``declare_tools=False``; ``SIGNAFAIDE_DECLARE_TOOLS=0`` turns it off everywhere.
    """
    opts = {"agent": agent, "strict": strict, "store_content": store_content, "declare_tools": declare_tools, "on_note": on_note}
    if isinstance(tools, dict):
        return {k: wrap_tool(v, name=k, **opts) for k, v in tools.items()}
    if isinstance(tools, (list, tuple)):
        return type(tools)(wrap_tool(t, **opts) for t in tools)
    return wrap_tool(tools, **opts)


def wrap_tool(
    tool: Any, *, name: Optional[str] = None, agent: Optional[str] = None, strict: bool = False, store_content: Optional[bool] = None, declare_tools: bool = True,
    on_note: Optional[Callable[[dict], None]] = None,
) -> Any:
    """Record one tool. See :func:`wrap_tools`."""
    if _is_openai_agents_tool(tool):
        info = ToolInfo(tool.name, getattr(tool, "description", "") or "", getattr(tool, "params_json_schema", None))
        return _wrap_openai_agents(tool, _Spec(name or tool.name, agent, strict, store_content, listed=declare_tools, tool=info, on_note=on_note))
    if _is_langchain_tool(tool):
        return _wrap_langchain(tool, _Spec(name or tool.name, agent, strict, store_content, listed=declare_tools, tool=_langchain_info(tool), on_note=on_note))
    if callable(tool):
        return _record_with(_Spec(name or tool.__name__, agent, strict, store_content, listed=declare_tools, on_note=on_note), tool)
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
        call_id = getattr(ctx, "tool_call_id", None)  # the model's tool call id
        return await spec.acall(args, lambda: original(ctx, input_json), call_id=call_id if isinstance(call_id, str) and call_id else None)

    return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)


def _langchain_info(tool: Any) -> ToolInfo:
    """A LangChain tool's name, description and input schema (§11.1), as the model is shown them."""
    schema: Any = None
    with contextlib.suppress(Exception):
        a = getattr(tool, "tool_call_schema", None) or getattr(tool, "args_schema", None)
        if isinstance(a, dict):
            schema = a
        elif a is not None and hasattr(a, "model_json_schema"):
            schema = a.model_json_schema()
        schema = json.loads(json.dumps(schema)) if schema is not None else None
    return ToolInfo(tool.name, getattr(tool, "description", "") or "", schema)


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
    returned: contextvars.ContextVar[Any] = contextvars.ContextVar("signafaide_lc_returned", default=None)
    for attr in ("_run", "_arun"):
        inner = getattr(new, attr, None)
        if inner is None:
            continue
        # LangChain runs _run in a copy of the context when it is called with a tool call, so a
        # value set there is lost on return. The context var holds a box (a list) instead: the
        # copy shares the same box, and the value put in it is seen after `run` returns.
        if attr == "_run":
            def capture(*a: Any, _inner: Any = inner, **kw: Any) -> Any:
                v = _inner(*a, **kw)
                box = returned.get()
                if isinstance(box, list):
                    box[:] = [v]
                return v
        else:
            async def capture(*a: Any, _inner: Any = inner, **kw: Any) -> Any:  # type: ignore[misc]
                v = await _inner(*a, **kw)
                box = returned.get()
                if isinstance(box, list):
                    box[:] = [v]
                return v
        # LangChain reads _run's signature to decide what to pass it (config, run_manager):
        # the wrapper must show the same one.
        functools.update_wrapper(capture, inner)
        with contextlib.suppress(Exception):
            object.__setattr__(new, attr, capture)

    def lc_input(tool_input: Any) -> Any:
        return {k: v for k, v in tool_input.items() if k not in _LC_EXTRA} if isinstance(tool_input, dict) else tool_input

    def lc_call_id(kwargs: dict) -> Optional[str]:
        """The model's tool call id: LangChain passes it to ``run`` when the tool is called with a tool call."""
        v = kwargs.get("tool_call_id")
        return v if isinstance(v, str) and v else None

    def tool_value(out: Any) -> Any:
        box = returned.get()
        if isinstance(box, list) and box:
            return box[0]
        # Not captured (a tool type that bypasses _run): a ToolMessage still yields its content.
        return getattr(out, "content", out) if type(out).__name__ == "ToolMessage" else out

    @functools.wraps(run)
    def run_recorded(tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        returned.set([])
        return spec.call(lc_input(tool_input), lambda: run(tool_input, *args, **kwargs), tool_value, call_id=lc_call_id(kwargs))

    @functools.wraps(arun)
    async def arun_recorded(tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        returned.set([])
        return await spec.acall(lc_input(tool_input), lambda: arun(tool_input, *args, **kwargs), tool_value, call_id=lc_call_id(kwargs))

    object.__setattr__(new, "run", run_recorded)
    object.__setattr__(new, "arun", arun_recorded)
    return new



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
