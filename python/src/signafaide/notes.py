"""Notes for the caller (SPEC §8 notes): a possible hidden instruction in a call's arguments or in
its result. Never a block: the call runs and its result is returned unchanged. The notes travel on
a side channel that changes nothing a caller already reads: an ``on_note`` callback (for every
call with :func:`on_note`, or one tool's ``record(fn, on_note=...)``), :func:`notes` for a result
the wrapper returned, and in development (no API key, a sandbox key or test mode) one line on
stderr.

``notes(result)`` finds a result by identity among the last ``KEPT`` results that had notes (they
are kept alive until then). Values Python shares between calls (``None``, ``True``, numbers,
strings, bytes, tuples) cannot carry notes: use ``on_note`` for them."""

from __future__ import annotations

import collections
import sys
import threading
from typing import Any, Callable, Dict, List, Optional

#: A note handler: called once for each note; an exception it raises is ignored.
NoteHandler = Callable[[Dict[str, Any]], None]

#: How many results with notes are kept for :func:`notes`.
KEPT = 256

_HANDLERS: List[NoteHandler] = []
_BY_RESULT: "collections.OrderedDict[int, tuple]" = collections.OrderedDict()
_LOCK = threading.Lock()
_SHARED = (type(None), bool, int, float, complex, str, bytes, tuple, frozenset)


def on_note(handler: NoteHandler) -> Callable[[], None]:
    """Call *handler* with every note of every recorded call in this process. Returns a function
    that stops it."""
    with _LOCK:
        _HANDLERS.append(handler)

    def stop() -> None:
        with _LOCK:
            if handler in _HANDLERS:
                _HANDLERS.remove(handler)

    return stop


def notes(result: Any) -> List[Dict[str, Any]]:
    """The notes of a call whose wrapper returned *result*; [] when there are none."""
    with _LOCK:
        got = _BY_RESULT.get(id(result))
    return [dict(n) for n in got[1]] if got is not None and got[0] is result else []


def note_line(n: Dict[str, Any]) -> str:
    """The words of a note's stderr line."""
    where = "the arguments of" if n["in"] == "arguments" else "the result of"
    return f"signafaide: note: possible hidden instruction in {where} {n['tool']} ({', '.join(n['found'])}); the call ran unchanged"


def deliver(found: List[Dict[str, Any]], *, own: Optional[NoteHandler], development: bool, result: Any = None, has_result: bool = False) -> None:
    """Hand *found* to the handlers (and *own*, a tool's own), print it in development, and keep
    it for :func:`notes` when a result is given."""
    if not found:
        return
    if has_result and not isinstance(result, _SHARED):
        with _LOCK:
            prev = _BY_RESULT.pop(id(result), None)
            kept = list(prev[1]) if prev is not None and prev[0] is result else []
            _BY_RESULT[id(result)] = (result, kept + list(found))
            while len(_BY_RESULT) > KEPT:
                _BY_RESULT.popitem(last=False)
    with _LOCK:
        handlers = ([own] if own else []) + list(_HANDLERS)
    for n in found:
        for h in handlers:
            try:
                h(dict(n))
            except Exception:  # a handler never changes the call
                pass
        if development:
            print(note_line(n), file=sys.stderr)


def development(rec: Any) -> bool:
    """Whether a recorder runs in development: no API key, a sandbox key, or test mode."""
    key = getattr(rec, "api_key", None) or ""
    return bool(getattr(rec, "test", False)) or not key.startswith("sfa_live_")
