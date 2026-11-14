"""Tool declarations (SPEC §2.6) and the coverage they give (§7): which of an agent's tools are
recorded, read from envelopes alone (kind, name, seq), so it holds for hash-only records.
The same names, rules and wording as the Rust core and the TypeScript SDK.

Coverage is a note, never a failure, and never a claim of completeness: a declaration is the
client's own signed statement of the tools the agent has."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from ._plural import plural
from .crypto import sha256_hex

#: The name of the note that starts a new tool declaration for the agent's chain.
TOOLS = "signafaide.tools"
#: ``signafaide.tool/<tool name>``: the agent has this tool and calls to it are recorded.
TOOL_PREFIX = "signafaide.tool/"
#: ``signafaide.tool_unrecorded/<tool name>``: the agent has this tool and calls to it are not recorded.
TOOL_UNRECORDED_PREFIX = "signafaide.tool_unrecorded/"
#: The names the SDK reserves: a record named so is never a tool.
RESERVED_PREFIX = "signafaide."
#: The longest tool name a declaration holds as it is, in characters (Unicode code points): an
#: envelope name is at most 128 and the longer prefix takes 27.
MAX_DECLARED_NAME = 101
_KEPT = MAX_DECLARED_NAME - 9


def declared_name(tool: str) -> str:
    """A tool's name as a declaration holds it: the name itself when it has at most 101
    characters, else its first 92 characters, ``~``, and the first 8 hex characters of
    sha256(UTF-8 tool name). A name that is already short maps to itself."""
    if len(tool) <= MAX_DECLARED_NAME:
        return tool
    return f"{tool[:_KEPT]}~{sha256_hex(tool.encode())[:8]}"


def tool_note_name(tool: str, recorded: bool) -> str:
    """The envelope name of the note that declares *tool*."""
    return (TOOL_PREFIX if recorded else TOOL_UNRECORDED_PREFIX) + declared_name(tool)


def tool_note(kind: Any, name: Any) -> Union[None, str, Tuple[str, bool]]:
    """What a record says about the agent's tool list, from its kind and name alone:
    ``"header"``, ``(tool name, recorded)``, or None when it is not a tool-declaration note."""
    if kind != "note" or not isinstance(name, str):
        return None
    if name == TOOLS:
        return "header"
    for prefix, recorded in ((TOOL_PREFIX, True), (TOOL_UNRECORDED_PREFIX, False)):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            return (rest, recorded) if rest else None
    return None


def coverage(records: Iterable[Tuple[int, Any, Any]]) -> dict:
    """The coverage of one agent's records, given as (seq, kind, name) in seq order:
    ``{"declared": [{"name", "recorded"}], "undeclared_recorded": [names], "declared_at_seq"}``.
    The current declaration is the one started by the last ``signafaide.tools`` note; tool notes
    before the first such note belong to a declaration the records do not hold and are ignored.
    Inside a declaration a later note for the same tool replaces an earlier one. A ``decision``
    counts as a recorded tool unless its name starts with ``signafaide.``; it is compared by its
    declared name. Names are in code point order."""
    at: Optional[int] = None
    tools: Dict[str, bool] = {}
    called = set()
    for seq, kind, name in records:
        t = tool_note(kind, name)
        if t == "header":
            at, tools = seq, {}
        elif t is not None:
            if at is not None:
                tools[t[0]] = t[1]
        elif kind == "decision" and isinstance(name, str) and not name.startswith(RESERVED_PREFIX):
            called.add(declared_name(name))
    if at is None:
        return {"declared": [], "undeclared_recorded": [], "declared_at_seq": None}
    return {
        "declared": [{"name": n, "recorded": tools[n]} for n in sorted(tools)],
        "undeclared_recorded": sorted(n for n in called if n not in tools),
        "declared_at_seq": at,
    }


def _count_is(n: int, one: str) -> str:
    """``1 declared tool is``, ``2 declared tools are``."""
    return f"{plural(n, one)} {'is' if n == 1 else 'are'}"


def coverage_lines(agent: str, c: dict) -> List[str]:
    """The coverage of *agent* in words (§7), one line each: what was declared, then the recorded
    tools the declaration does not list."""
    if c["declared_at_seq"] is None:
        return [f"{agent}: no tool list was declared, so the pack cannot show which of the agent's tools are recorded"]
    unrecorded = [t["name"] for t in c["declared"] if not t["recorded"]]
    out = []
    if not c["declared"]:
        out.append(f"{agent}: the declared tool list is empty")
    elif not unrecorded:
        # One tool: "the 1 declared tool is recorded".
        out.append(f"{agent}: {'the' if len(c['declared']) == 1 else 'all'} {_count_is(len(c['declared']), 'declared tool')} recorded")
    else:
        out.append(f"{agent}: {_count_is(len(unrecorded), 'declared tool')} not recorded: {', '.join(unrecorded)}")
    if c["undeclared_recorded"]:
        out.append(f"{agent}: {_count_is(len(c['undeclared_recorded']), 'recorded tool')} not in the declared tool list: {', '.join(c['undeclared_recorded'])}")
    return out
