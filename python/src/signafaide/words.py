"""Rules in words (SPEC §10.5, spec 1.1): the one English rendering of every rule, condition,
exception and default, so the verifier, ``signafaide prove``, ``check``, ``pull``, ``status`` and
the ``blocked`` error print a rule the same way the Rust core and the TypeScript SDK do. The words
never replace the document: the document and its ``rules_hash`` are what was signed."""

from __future__ import annotations

from typing import Any, List, Optional

from ._plural import plural
from .checks import rule_state
from .jcs import canonicalize


def number_words(literal: str) -> str:
    """A number literal as people read it: its integer part grouped by threes with ``,`` when it
    has no exponent (``1000`` is ``1,000``, ``-1234.5`` is ``-1,234.5``, ``1e+21`` stays)."""
    if "e" in literal or "E" in literal:
        return literal
    sign = "-" if literal.startswith("-") else ""
    rest = literal[1:] if sign else literal
    integer, _, frac = rest.partition(".")
    grouped = ""
    for i, c in enumerate(integer):
        if i > 0 and (len(integer) - i) % 3 == 0:
            grouped += ","
        grouped += c
    return f"{sign}{grouped}" + (f".{frac}" if "." in rest else "")


def value_words(v: Any) -> str:
    """A JSON value in words: a number as :func:`number_words`, a string as its JCS literal (in
    double quotes), ``true``, ``false``, ``null``, an object or array as its JCS text."""
    text = canonicalize(v).decode()
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return number_words(text)
    return text


def field_words(pointer: str) -> str:
    """A field in words: the pointer without its leading ``/``, escapes kept; ``/`` is
    ``(the empty key)``."""
    f = pointer[1:] if pointer.startswith("/") else pointer
    return f if f else "(the empty key)"


def _either(items: List[str]) -> str:
    if not items:
        return "(no values)"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " or " + items[-1]


_TYPES = {"string": "a string", "number": "a number", "integer": "an integer", "boolean": "true or false",
          "null": "null", "object": "an object", "array": "an array"}
_SIMPLE = {"eq": "is", "ne": "is not", "lt": "is below", "le": "is at most", "gt": "is above", "ge": "is at least",
           "prefix": "starts with", "suffix": "ends with", "contains": "contains"}


def condition_words(c: dict) -> str:
    """A condition in words (§10.5 table)."""
    f = field_words(c["field"])
    op = c["op"]
    if op in _SIMPLE:
        return f"{f} {_SIMPLE[op]} {value_words(c['value'])}"
    if op in ("in", "not_in"):
        items = _either([value_words(x) for x in (c["value"] if isinstance(c["value"], list) else [])])
        return f"{f} is one of {items}" if op == "in" else f"{f} is not one of {items}"
    if op == "present":
        return f"{f} is present"
    if op == "absent":
        return f"{f} is absent"
    return f"{f} is {_TYPES.get(str(c.get('value')), 'an array')}"


def exception_words(x: dict) -> str:
    """An exception in words: ``<field> is <value>``."""
    return f"{field_words(x['field'])} is {value_words(x['value'])}"


def _count(n: int, one: str, many: str) -> str:
    return f"{number_words(str(n))} {one if n == 1 else many}"


def window_words(seconds: int) -> str:
    """A limit's window as the console says it: ``1 minute`` for 60 seconds, ``2 hours``, ``90 seconds``."""
    if seconds % 3600 == 0:
        return _count(seconds // 3600, "hour", "hours")
    if seconds % 60 == 0:
        return _count(seconds // 60, "minute", "minutes")
    return _count(seconds, "second", "seconds")


_PER = {"agent": "by the same agent", "tool": "to the same tool", "agent_tool": "by the same agent to the same tool"}


def rule_words(r: dict) -> str:
    """A rule in words, without its state: ``Block approve_payout when amount is above 1,000``."""
    action = "Block" if r["action"] == "block" else "Allow"
    tools = "any tool" if r["tools"] is None else _either(list(r["tools"]))
    agents = ""
    if r["agents"] is not None:
        agents = f" for agent {r['agents'][0]}" if len(r["agents"]) == 1 else f" for agents {_either(list(r['agents']))}"
    parts = [condition_words(c) for c in r["when"]]
    lim = r.get("limit")
    if lim:
        parts.append(f"more than {_count(lim['calls'], 'call', 'calls')} in {window_words(lim['seconds'])} {_PER[lim['per']]}")
    when = f" when {' and '.join(parts)}" if parts else ""
    xs = r.get("exceptions") or []
    except_ = f", except when {' or '.join(exception_words(x) for x in xs)}" if xs else ""
    return f"{action} {tools}{agents}{when}{except_}"


def default_words(action: str) -> str:
    """The default in words."""
    return f"{'Block' if action == 'block' else 'Allow'} every call that no rule matches"


def mode_word(mode: Optional[str]) -> str:
    """A ``mode`` value in words: ``enforce`` is On, ``watch`` is Calibrating."""
    return "On" if mode == "enforce" else "Calibrating"


def fail_word(fail: Optional[str]) -> str:
    """A ``fail`` value in words, for "If signafAIde can't be reached": ``closed`` is Stop, ``open`` is Let it run."""
    return "Let it run" if fail == "open" else "Stop"


def state_word(state: Optional[str]) -> str:
    """``On`` or ``Calibrating``."""
    return "On" if state == "on" else "Calibrating"


def rule_set_words(doc: dict, hash_: str, local: bool) -> dict:
    """A valid rule set version, or local rules (*local*), in words (§7 JSON output ``rules``)."""
    def st(s: str) -> Optional[str]:
        return None if local else s

    state_doc = {"mode": "enforce"} if local else doc
    return {
        "set": "local" if local else doc["set"],
        "version": None if local else doc["version"],
        "hash": hash_,
        "issued": None if local else doc["issued"],
        "rules": [{"id": r["id"], "state": st(rule_state(state_doc, r)), "sentence": rule_words(r)} for r in doc["rules"]],
        "default": {"id": "default", "state": st("calibrating" if doc.get("mode") == "watch" else "on"), "sentence": default_words(doc["default"])},
        "exceptions": [] if local else [
            {"rule": r["id"], "since": x["since"], "sentence": exception_words(x), "reason": x["reason"]}
            for r in doc["rules"] for x in (r.get("exceptions") or [])
        ],
    }


def rule_set_lines(w: dict) -> List[str]:
    """The report lines of one rule set version or local rules (§7), without the ``rules: `` prefix."""
    label = f"{w['set']} version {w['version']}" if w["version"] is not None else f"local {w['hash'][:8]}"

    def word(s: Optional[str]) -> str:
        return "" if s is None else f" ({state_word(s)})"

    n = plural(len(w["rules"]), "rule")
    out = [f"{label}, issued {w['issued']}: {n}" if w["issued"] is not None else f"{label}: {n}"]
    for r in w["rules"]:
        out.append(f"{label}: rule {r['id']}: {r['sentence']}{word(r['state'])}")
    out.append(f"{label}: {w['default']['sentence']}{word(w['default']['state'])}")
    for x in w["exceptions"]:
        out.append(f"{label}: exception to rule {x['rule']} since version {x['since']}: {x['sentence']}, reason {canonicalize(x['reason']).decode()}")
    return out
