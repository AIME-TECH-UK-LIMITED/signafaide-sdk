"""``signafaide protect [tool]`` (spec 1.1, SPEC §8): find the agent's tools in the project, propose
which to protect, ask what to block, add ``@signafaide.protect`` and ``@signafaide.record`` to the
code, write a version 2 checks file, make the sandbox when there is no key, and publish the rules
the person chose (§6 ``POST /v1/rules``): into the project's sandbox while it is unclaimed,
otherwise with the person's session (``signafaide login``). A rule is On only when the person
answered On for it at a terminal; every other rule starts Calibrating."""

from __future__ import annotations

import ast
import copy
import datetime
import json
import re
import urllib.parse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from . import checks as C
from .agent_note import NOTE_QUESTION, note_what, offer_note
from .checks_runtime import CHECKS_FILE, checks_path
from .coverage import declared_name
from .http import Client, SignafaideError
from .jcs import canonicalize
from .records import agent_name
from .session import console_origin, load_session, on_console, person_witness
from .words import field_words, rule_words, state_word

Answer = Union[str, int, bool, List[bool]]


# --- asking a person ---------------------------------------------------------------------------


class Prompter:
    """How ``protect`` and ``pull`` ask. ``person`` is True only at a terminal: a rule is On, and
    a field is approved for sending, only when a person answered (never from flags or the
    environment)."""

    person = False
    #: ``--yes`` without a terminal: protect then saves default rules, all Calibrating.
    yes = False

    def confirm(self, question: str, default: bool) -> bool:
        raise NotImplementedError

    def choose(self, question: str, choices: List[str], default: int) -> int:
        raise NotImplementedError

    def multi(self, question: str, choices: List[str], defaults: List[bool]) -> List[bool]:
        raise NotImplementedError

    def text(self, question: str, default: Optional[str] = None) -> str:
        raise NotImplementedError


class TerminalPrompter(Prompter):
    """The prompter of a terminal: numbered choices, Enter takes the default."""

    person = True

    def __init__(self, read: Callable[[str], str] = input, write: Callable[[str], Any] = sys.stdout.write):
        self.read, self.write = read, write

    def _ask(self, q: str) -> str:
        try:
            return self.read(q)
        except EOFError:
            return ""

    def confirm(self, question: str, default: bool) -> bool:
        for _ in range(20):
            a = self._ask(f"? {question} {'(Y/n)' if default else '(y/N)'} ").strip().lower()
            if not a:
                return default
            if a in ("y", "yes"):
                return True
            if a in ("n", "no"):
                return False
        return default

    def choose(self, question: str, choices: List[str], default: int) -> int:
        self.write(f"? {question}\n")
        for i, c in enumerate(choices):
            self.write(f"  {'>' if i == default else ' '} {i + 1}) {c}\n")
        for _ in range(20):
            a = self._ask(f"  number (Enter for {default + 1}): ").strip()
            if not a:
                return default
            if a.isdigit() and 1 <= int(a) <= len(choices):
                return int(a) - 1
        return default

    def multi(self, question: str, choices: List[str], defaults: List[bool]) -> List[bool]:
        self.write(f"? {question}\n")
        for i, c in enumerate(choices):
            self.write(f"  {i + 1}) [{'x' if defaults[i] else ' '}] {c}\n")
        for _ in range(20):
            a = self._ask("  numbers to tick, comma separated, 0 for none (Enter keeps the ticks shown): ").strip()
            if not a:
                return list(defaults)
            if a == "0":
                return [False] * len(choices)
            picked = [x for x in re.split(r"[\s,]+", a) if x]
            if all(x.isdigit() and 1 <= int(x) <= len(choices) for x in picked):
                return [str(i + 1) in picked for i in range(len(choices))]
        return list(defaults)

    def text(self, question: str, default: Optional[str] = None) -> str:
        a = self._ask(f"? {question} " + (f"({default}) " if default is not None else "")).strip()
        return a or default or ""


class FlagPrompter(Prompter):
    """No person behind it (no terminal): every question takes its default, and *yes* accepts the
    code change and the sandbox. It never answers On and never approves a field."""

    person = False

    def __init__(self, yes: bool = False):
        self.yes = yes

    def confirm(self, question: str, default: bool) -> bool:
        return True if self.yes else default

    def choose(self, question: str, choices: List[str], default: int) -> int:
        return default

    def multi(self, question: str, choices: List[str], defaults: List[bool]) -> List[bool]:
        return list(defaults)

    def text(self, question: str, default: Optional[str] = None) -> str:
        return default or ""


class ScriptedPrompter(Prompter):
    """Answers from a list, in order (tests and scripted runs at a terminal)."""

    def __init__(self, answers: Sequence[Answer], person: bool = True):
        self.answers, self.person, self.asked = list(answers), person, []  # type: ignore[misc]

    def _next(self, q: str) -> Any:
        self.asked.append(q)
        # The project note's question came after most scripts were written: with no answer left it takes its default (yes).
        if not self.answers and q.startswith(NOTE_QUESTION):
            return True
        if not self.answers:
            raise AssertionError(f"no answer left for: {q}")
        return self.answers.pop(0)

    def confirm(self, question: str, default: bool) -> bool:
        return bool(self._next(question))

    def choose(self, question: str, choices: List[str], default: int) -> int:
        return int(self._next(question))

    def multi(self, question: str, choices: List[str], defaults: List[bool]) -> List[bool]:
        return list(self._next(question))

    def text(self, question: str, default: Optional[str] = None) -> str:
        return str(self._next(question))


# --- finding the tools -------------------------------------------------------------------------

KIND_WORDS = {
    "pays": "pays money",
    "deletes": "deletes data",
    "sends": "sends messages",
    "changes": "changes data",
    "runs": "runs commands",
    "reads": "reads only",
    "other": "not classified",
}
#: The kinds ``protect`` suggests protecting.
RISKY = {"pays", "deletes", "sends", "changes", "runs"}
_KIND_TOKENS = (
    (
        "pays",
        {
            "pay",
            "pays",
            "payout",
            "payouts",
            "payment",
            "payments",
            "transfer",
            "transfers",
            "refund",
            "refunds",
            "charge",
            "charges",
            "wire",
            "disburse",
            "withdraw",
        },
    ),
    (
        "deletes",
        {
            "delete",
            "deletes",
            "remove",
            "removes",
            "drop",
            "destroy",
            "purge",
            "erase",
            "wipe",
            "truncate",
            "revoke",
            "cancel",
        },
    ),
    (
        "sends",
        {
            "send",
            "sends",
            "email",
            "mail",
            "notify",
            "message",
            "sms",
            "post",
            "publish",
            "tweet",
            "reply",
            "forward",
            "invite",
        },
    ),
    (
        "runs",
        {
            "execute",
            "exec",
            "run",
            "runs",
            "command",
            "shell",
            "bash",
            "sql",
            "eval",
            "spawn",
            "script",
            "deploy",
            "invoke",
        },
    ),
    (
        "changes",
        {
            "update",
            "updates",
            "write",
            "writes",
            "set",
            "create",
            "creates",
            "insert",
            "edit",
            "modify",
            "patch",
            "upsert",
            "save",
            "put",
            "add",
            "rename",
            "move",
            "upload",
            "approve",
            "grant",
            "assign",
            "book",
            "order",
            "submit",
        },
    ),
    (
        "reads",
        {
            "get",
            "list",
            "lookup",
            "look",
            "read",
            "search",
            "find",
            "fetch",
            "query",
            "show",
            "describe",
            "view",
            "check",
            "count",
            "load",
            "browse",
            "summarize",
            "retrieve",
            "status",
        },
    ),
)
_SKIP_DIRS = {
    "node_modules",
    "dist",
    "build",
    "out",
    ".git",
    ".signafaide",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "proof",
    "site-packages",
    "tests",
    "test",
}
#: Decorators that make a function an agent's tool: LangChain ``@tool``, OpenAI Agents
#: ``@function_tool``, MCP (FastMCP) ``@mcp.tool()``, and the like.
_TOOL_DECORATORS = {
    "tool": "LangChain",
    "function_tool": "OpenAI Agents",
    "langchain.tools.tool": "LangChain",
    "langchain_core.tools.tool": "LangChain",
    "agents.function_tool": "OpenAI Agents",
}


def name_words(name: str) -> List[str]:
    return [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).lower()) if w]


def tool_kind(name: str) -> str:
    """What a tool does, from the words of its name; ``other`` (not classified) when no word says."""
    words = name_words(name)
    for kind, tokens in _KIND_TOKENS:
        if any(w in tokens for w in words):
            return kind
    return "other"


@dataclass
class FoundTool:
    name: str
    params: List[str]
    file: Path
    line: int  # the 1-based line of the ``def``
    indent: str
    kind: str
    #: Already decorated: ``protect`` or ``record``.
    wrapped: Optional[str] = None
    #: One object parameter (a dataclass, TypedDict or model, or a dict): rules read its fields.
    object_param: bool = False
    #: The fields rules can read: (name, JSON Pointer in the call's input).
    fields: List[Tuple[str, str]] = field(default_factory=list)
    #: ``function`` (a def), ``method`` (in a class), plus the framework when a decorator says so.
    shape: str = "function"
    framework: Optional[str] = None
    is_async: bool = False
    #: The agent named in its signafaide decorator already, when there is one.
    agent: Optional[str] = None


@dataclass
class Found:
    tools: List[FoundTool] = field(default_factory=list)
    #: The file and the name of the tools list or dict, when the tools come from one.
    collection: Optional[Tuple[Path, str]] = None


def _walk(root: Path) -> List[Path]:
    out: List[Path] = []
    stack = [root]
    while stack and len(out) < 2000:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.name.startswith("."):
                continue
            if e.is_dir():
                if e.name not in _SKIP_DIRS:
                    stack.append(e)
            elif e.suffix == ".py" and not e.name.startswith("test_") and not e.name.endswith("_test.py"):
                out.append(e)
    return sorted(out)


def _deco_name(d: ast.AST) -> str:
    target = d.func if isinstance(d, ast.Call) else d
    try:
        return ast.unparse(target)
    except Exception:  # noqa: BLE001 - an odd decorator is just not ours
        return ""


def _signafaide_deco(fn: ast.AST) -> Optional[ast.AST]:
    for d in getattr(fn, "decorator_list", []):
        if _deco_name(d) in ("signafaide.protect", "protect", "signafaide.record", "record"):
            return d
    return None


def _decorated_with(fn: ast.AST) -> Optional[str]:
    d = _signafaide_deco(fn)
    if d is None:
        return None
    return "protect" if _deco_name(d).endswith("protect") or _strict_kw(d) else "record"


def _strict_kw(d: ast.AST) -> bool:
    return isinstance(d, ast.Call) and any(
        k.arg == "strict" and isinstance(k.value, ast.Constant) and k.value.value is True for k in d.keywords
    )


def _deco_agent(d: Optional[ast.AST]) -> Optional[str]:
    if isinstance(d, ast.Call):
        for k in d.keywords:
            if k.arg == "agent" and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                return k.value.value
    return None


def _framework(fn: ast.AST) -> Optional[str]:
    """The framework a tool decorator names (``@tool``, ``@function_tool``, ``@mcp.tool()``)."""
    for d in getattr(fn, "decorator_list", []):
        n = _deco_name(d)
        if n in _TOOL_DECORATORS:
            return _TOOL_DECORATORS[n]
        if n.endswith(".tool") or n.endswith(".add_tool"):
            return (
                "MCP server" if isinstance(d, ast.Call) or n.split(".")[0] in ("mcp", "server", "app") else "LangChain"
            )
    return None


_PRIMITIVES = {
    "str",
    "int",
    "float",
    "bool",
    "bytes",
    "list",
    "List",
    "Sequence",
    "Any",
    "None",
    "Optional",
    "Union",
    "tuple",
    "Tuple",
    "set",
    "Set",
}
_MAPPINGS = {"dict", "Dict", "Mapping", "MutableMapping"}


def _object_classes(parsed: Dict[Path, Tuple[str, ast.Module]]) -> Dict[str, List[str]]:
    """Classes whose body annotates fields (dataclasses, TypedDicts, pydantic models): their fields."""
    out: Dict[str, List[str]] = {}
    for _text, mod in parsed.values():
        for n in ast.walk(mod):
            if isinstance(n, ast.ClassDef) and n.name not in out:
                names = [
                    x.target.id
                    for x in n.body
                    if isinstance(x, ast.AnnAssign)
                    and isinstance(x.target, ast.Name)
                    and not x.target.id.startswith("_")
                ]
                if names:
                    out[n.name] = names
    return out


def _params(fn: Any, classes: Dict[str, List[str]]) -> Tuple[List[str], bool, List[Tuple[str, str]]]:
    """The parameter names, whether the one parameter is an object, and the fields rules can read:
    each parameter (``/<param>``), or an object's fields (``/<param>/<field>``, as the decorator
    names the arguments by the signature)."""
    a = fn.args
    params = [x for x in a.posonlyargs + a.args + a.kwonlyargs if x.arg not in ("self", "cls")]
    names = [x.arg for x in params]
    if len(params) == 1 and params[0].annotation is not None:
        ann = params[0].annotation
        base = ann.value if isinstance(ann, ast.Subscript) else ann
        tname = base.attr if isinstance(base, ast.Attribute) else base.id if isinstance(base, ast.Name) else ""
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            tname = ann.value
        if tname in classes:
            return names, True, [(f, f"/{names[0]}/{f}") for f in classes[tname]]
        if tname in _MAPPINGS or (tname and tname[0].isupper() and tname not in _PRIMITIVES):
            return names, True, []
    return names, False, [(n, f"/{n}") for n in names]


def find_tools(root: Path, only: Optional[str] = None) -> Found:
    """The tools of a Python project: functions with a tool decorator (LangChain ``@tool``, OpenAI
    Agents ``@function_tool``, MCP ``@mcp.tool()``) or a signafaide one, anywhere; the functions a
    module-level ``tools`` list or dict names, or ``StructuredTool.from_function(func=...)`` and
    ``Tool(func=...)`` name; the methods of a class named like tools; else the top-level
    functions of files named like tools."""
    parsed: Dict[Path, Tuple[str, ast.Module]] = {}
    for f in _walk(root):
        try:
            text = f.read_text()
            parsed[f] = (text, ast.parse(text))
        except (OSError, SyntaxError, ValueError):
            continue
    classes = _object_classes(parsed)

    def defs(mod: ast.Module) -> Dict[str, Any]:
        return {n.name: n for n in mod.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def tool_of(f: Path, text: str, fn: Any, name: Optional[str] = None, shape: str = "function") -> FoundTool:
        params, obj, fields = _params(fn, classes)
        line = fn.lineno
        indent = re.match(r"\s*", text.splitlines()[line - 1]).group(0)  # type: ignore[union-attr]
        n = name or fn.name
        return FoundTool(
            n,
            params,
            f,
            line,
            indent,
            tool_kind(n),
            _decorated_with(fn),
            obj,
            fields,
            shape,
            _framework(fn),
            isinstance(fn, ast.AsyncFunctionDef),
            _deco_agent(_signafaide_deco(fn)),
        )

    tools: List[FoundTool] = []
    seen: Set[Tuple[Path, int]] = set()
    collection: Optional[Tuple[Path, str]] = None

    def add(t: FoundTool) -> None:
        if (t.file, t.line) in seen or any(x.name == t.name for x in tools):
            return
        seen.add((t.file, t.line))
        tools.append(t)

    for f, (text, mod) in parsed.items():
        fns = defs(mod)
        # A module-level ``tools`` list or dict.
        for node in mod.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            name = next((t.id for t in targets if isinstance(t, ast.Name) and t.id.lower().endswith("tools")), None)
            if name is None or node.value is None:
                continue
            v = node.value
            names = [
                e.id
                for e in (
                    v.elts if isinstance(v, (ast.List, ast.Tuple)) else v.values if isinstance(v, ast.Dict) else []
                )
                if isinstance(e, ast.Name)
            ]
            found = [tool_of(f, text, fns[n]) for n in names if n in fns]
            for t in found:
                add(t)
            if found and collection is None:
                collection = (f, name)
        # Functions with a tool decorator or a signafaide one, and the methods of tool classes.
        for node in ast.walk(mod):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                _framework(node) or _signafaide_deco(node) is not None
            ):
                add(tool_of(f, text, node))
            elif isinstance(node, ast.ClassDef) and re.search(r"(Tools|Toolkit|Toolset)$", node.name):
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and not m.name.startswith("_"):
                        add(tool_of(f, text, m, shape="method"))
            elif isinstance(node, ast.Call):
                # ``StructuredTool.from_function(func=fn, name="x")``, ``Tool(name="x", func=fn)``.
                callee = _deco_name(node)
                if callee.endswith("from_function") or callee in ("Tool", "StructuredTool", "FunctionTool"):
                    kw = {k.arg: k.value for k in node.keywords}
                    ref = kw.get("func") or kw.get("coroutine") or (node.args[0] if node.args else None)
                    if isinstance(ref, ast.Name) and ref.id in fns:
                        nm = kw.get("name")
                        t = tool_of(
                            f,
                            text,
                            fns[ref.id],
                            nm.value if isinstance(nm, ast.Constant) and isinstance(nm.value, str) else None,
                        )
                        t.framework = "LangChain"
                        add(t)
    if not tools or only:
        for f, (text, mod) in parsed.items():
            if "tool" not in f.name.lower() and not only:
                continue
            for n, fn in defs(mod).items():
                if n.startswith("_") or (only and n != only):
                    continue
                add(tool_of(f, text, fn))
    return Found([t for t in tools if not only or t.name == only], collection)


def agent_in_code(found: Found, root: Path) -> Optional[str]:
    """The agent the code names already (a signafaide decorator's or ``declare_tools``'s ``agent``)."""
    for t in found.tools:
        if t.agent:
            return t.agent
    for f in _walk(root):
        try:
            text = f.read_text()
            if "declare_tools(" not in text:
                continue
            mod = ast.parse(text)
        except (OSError, SyntaxError, ValueError):
            continue
        for n in ast.walk(mod):
            if isinstance(n, ast.Call) and _deco_name(n).endswith("declare_tools"):
                a = _deco_agent(n)
                if a:
                    return a
    return None


# --- what to block -----------------------------------------------------------------------------

_AMOUNT = {"amount", "total", "value", "sum", "price", "cost", "amount_cents", "amountcents", "amount_minor"}
_CURRENCY = {"currency", "ccy", "currency_code"}


@dataclass
class Choice:
    label: str
    key: str
    ask: str
    default: str
    numeric: bool
    make: Callable[[str, str, str], dict]


def choices_for(t: FoundTool) -> List[Choice]:
    out: List[Choice] = []
    amount = next((f for f in t.fields if f[0].lower() in _AMOUNT), None)
    currency = next((f for f in t.fields if f[0].lower() in _CURRENCY), None)
    noun = "Payouts" if t.kind == "pays" else "Calls"
    if amount:
        an, ap = amount
        out.append(
            Choice(
                f"{noun} above an amount",
                "amount",
                f"Block {t.name} when {an} is above:",
                "1000",
                True,
                lambda tool, v, rid: {
                    "id": rid,
                    "about": f"{tool}: {an} above {v}.",
                    "action": "block",
                    "tools": [tool],
                    "agents": None,
                    "when": [{"field": ap, "op": "gt", "value": _num(v)}],
                },
            )
        )
    if currency:
        cn, cp = currency
        out.append(
            Choice(
                f"{noun} in other currencies",
                "currency",
                f"Block {t.name} when {cn} is not:",
                "GBP",
                False,
                lambda tool, v, rid: {
                    "id": rid,
                    "about": f"{tool}: {cn} other than {v}.",
                    "action": "block",
                    "tools": [tool],
                    "agents": None,
                    "when": [_currency_condition(cp, v)],
                },
            )
        )
    out.append(
        Choice(
            "More than a number of calls a minute",
            "rate",
            f"Block {t.name} when there are more calls a minute than:",
            "20",
            True,
            lambda tool, v, rid: {
                "id": rid,
                "about": f"{tool}: more than {v} calls a minute.",
                "action": "block",
                "tools": [tool],
                "agents": None,
                "when": [],
                "limit": {"calls": int(_num(v)), "seconds": 60, "per": "agent_tool"},
            },
        )
    )
    return out


def limit_choice(t: FoundTool, field_name: str) -> Optional[Choice]:
    """The rule ``--limit-field <field> --above <n>`` gives: the tool's field of that name (any case),
    or, for a tool that takes one object whose fields the code does not show, that field of it."""
    f = next((x for x in t.fields if x[0].lower() == field_name.lower()), None)
    if f is None and t.object_param and not t.fields and re.fullmatch(r"[A-Za-z_]\w*", field_name):
        f = (field_name, f"/{t.params[0]}/{field_name}" if t.params else f"/{field_name}")
    if f is None:
        return None
    fn, fp = f
    return Choice(
        f"Calls with {fn} above a limit",
        "amount" if fn.lower() in _AMOUNT else fn,
        f"Block {t.name} when {fn} is above:",
        "1000",
        True,
        lambda tool, v, rid: {
            "id": rid,
            "about": f"{tool}: {fn} above {v}.",
            "action": "block",
            "tools": [tool],
            "agents": None,
            "when": [{"field": fp, "op": "gt", "value": _num(v)}],
        },
    )


#: The calls a minute of each default rule (``protect --yes``), by what the tool does.
DEFAULT_RATE = {
    "pays money": 5,
    "deletes data": 5,
    "sends messages": 20,
    "runs commands": 5,
    "pushes code": 5,
    "edits secrets": 5,
    "edits config": 5,
}


def risk(t: FoundTool) -> Optional[str]:
    """What makes a tool risky, in words (``check --ci`` reads tools the same way); None when it is not."""
    from .ci_check import risk_of

    return risk_of(t.name, t.kind)


def default_rule(t: FoundTool, decl: str, taken: Set[str]) -> Optional[dict]:
    """The rule ``protect --yes`` saves for a risky tool, without a person to ask: a tool that pays
    is blocked above 1000 when it has an amount, every other risky tool (and a payment without an
    amount) above a number of calls a minute. It starts Calibrating: it blocks nothing until a
    person turns it On."""
    why = risk(t)
    if why is None:
        return None
    if why == KIND_WORDS["pays"]:
        amount = next((f for f in t.fields if f[0].lower() in _AMOUNT), None)
        if amount:
            an, ap = amount
            return {
                "id": rule_id(decl, "amount", taken),
                "about": f"{decl}: {an} above 1000.",
                "action": "block",
                "tools": [decl],
                "agents": None,
                "when": [{"field": ap, "op": "gt", "value": 1000}],
            }
    n = DEFAULT_RATE.get(why, 5)
    return {
        "id": rule_id(decl, "rate", taken),
        "about": f"{decl}: more than {n} calls a minute.",
        "action": "block",
        "tools": [decl],
        "agents": None,
        "when": [],
        "limit": {"calls": n, "seconds": 60, "per": "agent_tool"},
    }


#: Said for each rule a run without a person adds.
CALIBRATING_LINE = (
    "  Starts Calibrating: it notes the calls it would have blocked and blocks none. Only a person turns it On: "
    "signafaide protect at a terminal, or the console."
)


def _currency_condition(field: str, v: str) -> dict:
    """ "not GBP" as a condition: ``ne`` for one currency (it reads ``currency is not "GBP"``), ``not_in`` for several."""
    items = [x.upper() for x in re.split(r"[\s,]+", v) if x]
    return (
        {"field": field, "op": "ne", "value": items[0]}
        if len(items) == 1
        else {"field": field, "op": "not_in", "value": items}
    )


def _num(v: str) -> Union[int, float]:
    f = float(v)
    return int(f) if f.is_integer() else f


def _limit_text(v: float) -> str:
    """1000.0 -> "1000", 12.5 -> "12.5": the limit as the person would have typed it."""
    return str(int(v)) if float(v).is_integer() else str(v)


def rule_id(tool: str, what: str, taken: Set[str]) -> str:
    base = re.sub(r"^[^a-z0-9]+", "", re.sub(r"[^a-z0-9._-]+", "-", f"{tool}-{what}".lower()))[:60] or "rule"
    rid, i = base, 2
    while rid in taken:
        rid, i = f"{base}-{i}", i + 1
    taken.add(rid)
    return rid


# --- writing the code --------------------------------------------------------------------------


def _line_offsets(text: str) -> List[int]:
    out, n = [0], 0
    for line in text.split("\n"):
        n += len(line) + 1
        out.append(n)
    return out


def _decorator_text(want: str, agent: str, old: Optional[ast.AST], text: str) -> str:
    """``@signafaide.protect(agent="...")``, keeping the keywords of the decorator already there
    (``store_content=True``...), as written; ``strict`` is dropped (protect implies it)."""
    kws: List[str] = []
    have: Set[str] = set()
    if isinstance(old, ast.Call):
        for k in old.keywords:
            if k.arg in ("strict",) or k.arg is None:
                continue
            seg = ast.get_source_segment(text, k)
            if seg:
                kws.append(seg)
                have.add(k.arg)
    if "agent" not in have:
        kws.append(f"agent={json.dumps(agent)}")
    return f"signafaide.{want}({', '.join(kws)})"


def rewrite_file(
    text: str,
    tools: List[FoundTool],
    protect_set: Set[str],
    agent: str,
    collection: Optional[str],
    declare: Optional[List[str]] = None,
) -> str:
    """Decorate each tool's function with ``@signafaide.protect`` (the chosen ones) or
    ``@signafaide.record`` (the others), right above its ``def`` (under a framework's decorator),
    at the exact place ``ast`` gives; keep a decorator already there, and its options; add
    ``import signafaide``; name the agent in a ``declare_tools`` already there, or add one when
    *declare* lists the tools (once per project)."""
    try:
        mod = ast.parse(text)
    except SyntaxError:
        return text
    offsets = _line_offsets(text)
    at = lambda line, col: offsets[line - 1] + col  # noqa: E731 - a character offset from ast's (line, col)
    by_line = {n.lineno: n for n in ast.walk(mod) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    edits: List[Tuple[int, int, str]] = []
    for t in tools:
        fn = by_line.get(t.line)
        if fn is None:
            continue
        want = "protect" if t.name in protect_set or t.wrapped == "protect" else "record"
        old = _signafaide_deco(fn)
        new = _decorator_text(want, agent, old, text)
        if old is not None:
            start, end = at(old.lineno, old.col_offset), at(old.end_lineno, old.end_col_offset)  # type: ignore[arg-type]
            if text[start:end] != new:
                edits.append((start, end, new))
        else:
            # Right above the ``def`` (or ``async def``): the innermost decorator, so a framework's
            # decorator above it still reads the function's signature.
            pos = at(fn.lineno, 0)
            indent = re.match(r"[ \t]*", text[pos:]).group(0)  # type: ignore[union-attr]
            edits.append((pos, pos, f"{indent}@{new}\n"))
    for n in ast.walk(mod):
        if (
            isinstance(n, ast.Call)
            and _deco_name(n).endswith("declare_tools")
            and not any(k.arg == "agent" for k in n.keywords)
        ):
            end = at(n.end_lineno, n.end_col_offset) - 1  # type: ignore[arg-type]
            sep = ", " if (n.args or n.keywords) else ""
            edits.append((end, end, f"{sep}agent={json.dumps(agent)}"))
    out = text
    for start, end, new in sorted(edits, key=lambda e: -e[0]):
        out = out[:start] + new + out[end:]
    if out == text and not declare:
        return place_declaration(text, [t.name for t in tools], None)
    if not re.search(r"^import signafaide\b|^from signafaide\b", out, re.M):
        body = out.split("\n")
        k = 0
        try:
            m2 = ast.parse(out)
            first = m2.body[0] if m2.body else None
            if (
                first is not None
                and isinstance(first, ast.Expr)
                and isinstance(getattr(first, "value", None), ast.Constant)
                and isinstance(first.value.value, str)
            ):
                k = first.end_lineno or 0
            for n in m2.body:
                if isinstance(n, ast.ImportFrom) and n.module == "__future__":
                    k = max(k, n.end_lineno or 0)
        except SyntaxError:
            pass
        body.insert(k, "import signafaide")
        out = "\n".join(body)
    line = f"signafaide.declare_tools({json.dumps(declare)}, agent={json.dumps(agent)})" if declare else None
    return place_declaration(out, [t.name for t in tools], line)


DECLARE_COMMENT = "# The agent's full tool list, so a proof shows every tool is recorded."


def _runs_program(n: ast.stmt) -> bool:
    """A top-level statement that runs the program: ``if __name__ == "__main__":``, or a call
    (``main()``, ``asyncio.run(main())``, ``app.run()``), never ``declare_tools`` itself."""
    if isinstance(n, ast.If):
        try:
            test = ast.unparse(n.test)
        except Exception:  # noqa: BLE001 - an odd test is not a main guard
            return False
        return "__name__" in test and "__main__" in test
    if isinstance(n, ast.Expr):
        v = n.value.value if isinstance(n.value, ast.Await) else n.value
        return isinstance(v, ast.Call) and not _deco_name(v).endswith("declare_tools")
    return False


def _is_declare(n: ast.stmt) -> bool:
    return isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and _deco_name(n.value).endswith("declare_tools")


def place_declaration(text: str, tool_names: List[str], line: Optional[str]) -> str:
    """Put the ``declare_tools`` call where it always runs: right after the imports and the tool
    definitions, before a main guard or a top-level call that runs the program (a program that
    exits early never reaches a line after it). *line* adds a new call; a top-level call already
    there after the program's run is moved up."""
    try:
        mod = ast.parse(text)
    except SyntaxError:
        return text if line is None else text.rstrip("\n") + f"\n\n{DECLARE_COMMENT}\n{line}\n"
    names = set(tool_names)

    def defines_tools(n: ast.stmt) -> bool:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return n.name in names
        if isinstance(n, ast.ClassDef):
            return any(isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in names for m in n.body)
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            return any(isinstance(t, ast.Name) and t.id.lower().endswith("tools") for t in targets)
        return False

    def is_import(n: ast.stmt) -> bool:
        return isinstance(n, (ast.Import, ast.ImportFrom))

    def signafaide_import(n: ast.stmt) -> bool:
        return (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "signafaide") or (
            isinstance(n, ast.Import) and any(x.name.split(".")[0] == "signafaide" for x in n.names)
        )

    tools_end = max((n.end_lineno or n.lineno for n in mod.body if defines_tools(n) and not is_import(n)), default=0)
    run = next((n for n in mod.body if n.lineno > tools_end and _runs_program(n)), None)
    limit = run.lineno if run is not None else float("inf")
    last = max((n.end_lineno or n.lineno for n in mod.body if defines_tools(n) and n.lineno < limit), default=0)
    lines = text.split("\n")
    if line is None:
        # One already there: moved only when it comes after the program's run.
        decl = next((n for n in mod.body if _is_declare(n)), None)
        if decl is None or run is None or decl.lineno < run.lineno:
            return text
        # The import it needs, when that comes after the program's run too, moves with it.
        moved = (
            [n for n in mod.body if signafaide_import(n) and n.lineno > run.lineno]
            if not any(signafaide_import(n) and n.lineno < run.lineno for n in mod.body)
            else []
        )
        block: List[str] = []
        for n in moved:
            block += lines[n.lineno - 1 : n.end_lineno or n.lineno]
        block += [DECLARE_COMMENT] + lines[decl.lineno - 1 : decl.end_lineno or decl.lineno]
        for n in sorted(moved + [decl], key=lambda x: -x.lineno):
            start, end = n.lineno - 1, n.end_lineno or n.lineno
            if n is decl and start > 0 and lines[start - 1].strip() == DECLARE_COMMENT:
                start -= 1
            del lines[start:end]
        while len(lines) > 1 and not lines[-1].strip() and not lines[-2].strip():
            lines.pop()
        line_block = block
    else:
        line_block = [DECLARE_COMMENT, line]
    if last:
        # Right after the imports and the tool definitions.
        lines[last:last] = ["", *line_block] if lines[last : last + 1] == [""] else ["", *line_block, ""]
        return "\n".join(lines).rstrip("\n") + "\n"
    if run is None:
        return "\n".join(lines).rstrip("\n") + "\n\n" + "\n".join(line_block) + "\n"
    at = run.lineno - 1
    # Comments right above the run statement stay with it.
    while at > 0 and lines[at - 1].lstrip().startswith("#"):
        at -= 1
    lines[at:at] = line_block + ["", ""]
    return "\n".join(lines)


@dataclass
class FileChange:
    file: Path
    before: str
    after: str
    tools: List[FoundTool]


def code_changes(
    found: Found, protect_set: Set[str], agent: str, root: Path, all_tools: Optional[Found] = None
) -> List[FileChange]:
    """The changes that record every tool and protect the ones in *protect_set*, with *agent* in
    every decorator and declaration written, and the tool list declared once in the project.
    *all_tools* is every tool of the project when *found* holds only the one ``protect --tool``
    names: the declaration is the agent's full tool list either way."""
    by_file: Dict[Path, List[FoundTool]] = {}
    for t in found.tools:
        by_file.setdefault(t.file, []).append(t)
    declared_in = []
    for f in _walk(root):
        try:
            if re.search(r"\bdeclare_tools\(", f.read_text()):
                declared_in.append(f)
        except OSError:
            continue
    order = list(by_file)
    if found.collection and found.collection[0] in order:
        order.remove(found.collection[0])
        order.insert(0, found.collection[0])
    names = [t.name for t in (all_tools or found).tools]
    declared = bool(declared_in)
    out: List[FileChange] = []
    for f in list(dict.fromkeys(order + declared_in)):
        before = f.read_text()
        tools = by_file.get(f, [])
        declare = None
        if not declared and tools:
            declare, declared = names, True
        after = rewrite_file(before, tools, protect_set, agent, None, declare)
        if after != before:
            out.append(FileChange(f, before, after, tools))
    return out


def line_diff(before: str, after: str) -> List[str]:
    """A unified diff of a file's change, for a person to read before it is written."""
    import difflib

    return [
        line.rstrip("\n") for line in difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=2)
    ][2:]


# --- rules an agent run proposed ---------------------------------------------------------------


def proposal_for(file: Optional[dict], decl: str) -> Optional[Tuple[dict, str]]:
    """The rule an agent run proposed for this tool (checks file version 2: ``proposed`` names a
    local rule, or holds a rule only the witness applies, one with a limit; and the day) as
    ``(rule, day)``, or None."""
    if not file or C.checks_file_version(file) != 2 or not isinstance(file.get("proposed"), list):
        return None
    for p in file["proposed"]:
        if isinstance(p["rule"], dict):
            if decl in (p["rule"].get("tools") or []):
                return p["rule"], p["on"]
            continue
        for r in (file.get("rules") or {}).get("rules") or []:
            if r["id"] == p["rule"] and decl in (r.get("tools") or []):
                return r, p["on"]
    return None


def proposed_id(p: dict) -> str:
    """The id a ``proposed`` entry names: its local rule's, or that of the rule it holds."""
    return p["rule"]["id"] if isinstance(p["rule"], dict) else p["rule"]


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


# --- the checks file ---------------------------------------------------------------------------


def to_version2(file: Optional[dict]) -> dict:
    """A version 2 checks file from the one in place (version 1 is rewritten: ``strict`` becomes
    ``protect``, the file's mode becomes each listed tool's mode, ``fail`` moves to the console)."""
    if file is None:
        return {
            "format": C.CHECKS_FORMAT_2,
            "checks": {k: True for k in C.FILE_CHECKS},
            "tools": {},
            "addresses": {"hosts": [], "cidrs": [], "resolve": False},
            "rules": None,
        }
    if C.checks_file_version(file) == 2:
        return copy.deepcopy(file)
    tools = {}
    for name in file["tools"]:
        s = C.tool_settings(file, name)
        if s["strict"]:
            d = list(dict.fromkeys(s["disclose"]))
            tools[name] = {"protect": True, "mode": s["mode"], **({"disclose": d} if d else {})}
        else:
            tools[name] = {"protect": False, "mode": s["mode"]}
    out = {
        "format": C.CHECKS_FORMAT_2,
        "checks": file["checks"],
        "tools": tools,
        "addresses": file["addresses"],
        "rules": file["rules"],
    }
    if "ruling_timeout_ms" in file:
        out["ruling_timeout_ms"] = file["ruling_timeout_ms"]
    if "ci" in file:
        out["ci"] = file["ci"]
    return out


def write_checks_file(path: Path, doc: dict) -> None:
    err = C.checks_file_errors(doc)
    if err:
        raise SignafaideError(
            f"signafaide would write an invalid checks file ({err}); nothing was written", code="state"
        )
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


# --- publishing --------------------------------------------------------------------------------


def publisher(rec: Any) -> Union[Tuple[Client, str, str], str]:
    """Who may publish here (§6): ``(client, how, who)`` with the person's session when one is
    held for this witness, else the project's key while it is an unclaimed sandbox; the reason
    when neither. The witness is never taken from the project's ``.env`` (§8): when that file
    names another one, nothing is saved."""
    witness = person_witness(rec._url)
    if rec.url != witness:
        return (
            f"SIGNAFAIDE_URL in the project's .env names {rec.url}, and rules are saved only at a witness named by --url or SIGNAFAIDE_URL "
            "in the environment (a project file never chooses where a person's session goes); run it again with "
            f"--url {rec.url} if you trust that witness"
        )
    s = load_session(witness)
    if s is not None and s.get("url") == witness:
        return (
            Client(witness, s["session"], 15.0, rec.client_id()),
            "session",
            (s.get("person") or {}).get("email") or "you",
        )
    key = rec.api_key
    if not key:
        return "there is no API key"
    if key.startswith("sfa_live_"):
        return "a live project's rules are saved by a signed-in person"
    try:
        p = rec.client(timeout=10).project()
    except SignafaideError as e:
        return f"the witness could not be asked whether the sandbox is claimed ({e})"
    if p.get("claimed"):
        return "the sandbox is claimed, so its rules are saved by a signed-in person"
    return rec.client(timeout=15), "sandbox_key", "this machine (unclaimed sandbox)"


def keep_proposed(doc: dict, rules: List[dict]) -> None:
    """Keep rules a run without a person could not save in the checks file as an agent run's
    proposals, all Calibrating: a rule without a limit as a local rule (the tool's mode is watch, so
    it blocks nothing), a rule with a limit held in its ``proposed`` entry (only the witness counts
    calls, so it never applies here). A person who runs protect at a terminal is offered each one."""
    if not rules:
        return
    lr = doc.get("rules") or {"default": "allow", "rules": []}
    proposals = list(doc.get("proposed") or [])
    for r in rules:
        plain = {k: v for k, v in r.items() if k != "state"}
        proposals = [p for p in proposals if proposed_id(p) != plain["id"]]
        if "limit" in plain:
            proposals.append({"rule": plain, "by": "agent", "on": _today()})
            continue
        lr["rules"] = [x for x in lr["rules"] if x["id"] != plain["id"]] + [plain]
        proposals.append({"rule": plain["id"], "by": "agent", "on": _today()})
        for d in plain.get("tools") or []:
            if (doc["tools"].get(d) or {}).get("protect"):
                doc["tools"][d]["mode"] = "watch"
    if lr["rules"]:
        doc["rules"] = lr
    doc["proposed"] = proposals


#: The longest a rule may be in an add link, once decoded.
ADD_LINK_MAX = 4000


def add_link(tools: str, agent: str, r: dict) -> Optional[str]:
    """The console link that adds one suggested rule to one tool:
    ``<add_in_console>/<agent>/<tool>?add=<rule>``, the rule with only the keys the page takes and
    never a state (a rule added from the link starts Calibrating). None when it would be too long."""
    tool = (r.get("tools") or [None])[0]
    if not isinstance(tool, str):
        return None

    def rule(about: bool) -> dict:
        return {
            "id": r["id"],
            **({"about": r["about"]} if about and r.get("about") else {}),
            "action": "block",
            "tools": [tool],
            "agents": None,
            "when": r.get("when") or [],
            **({"limit": r["limit"]} if r.get("limit") else {}),
        }

    # As JavaScript's JSON.stringify and encodeURIComponent write them, so both SDKs print one link.
    texts = [json.dumps(rule(a), separators=(",", ":"), ensure_ascii=False) for a in (True, False)]
    text = next((t for t in texts if len(t) <= ADD_LINK_MAX), None)
    if text is None:
        return None
    q = lambda x: urllib.parse.quote(x, safe="-_.!~*'()")  # noqa: E731
    return f"{tools.rstrip('/')}/{q(agent)}/{q(tool)}?add={q(text)}"


def add_in_console(rec: Any, rules: List[dict]) -> Union[str, dict, None]:
    """Where a person adds the rules of a project an API key cannot save them in: the witness says it
    (``add_in_console`` in its refusal of ``POST /v1/rules``, the project's Tools page); never built
    from SIGNAFAIDE_URL. Asked only of a witness a person chose (not one a project's ``.env`` named).
    ``{"published": item}`` when the witness saved them after all (a sandbox nobody had claimed yet)."""
    if not rec.api_key:
        return None
    try:
        if rec.url != person_witness(rec._url):
            return None
    except SignafaideError:
        return None
    try:
        return {"published": publish_rules(rec, rec.client(timeout=15), rules)}
    except SignafaideError as e:
        link = ((e.body or {}).get("error") or {}).get("add_in_console") if isinstance(e.body, dict) else None
        if not isinstance(link, str):
            return None
        u = urllib.parse.urlsplit(link)
        return link.rstrip("/") if u.scheme in ("http", "https") and u.netloc and "@" not in u.netloc else None


def next_draft(held: Optional[dict], add: List[dict]) -> dict:
    """The draft of the next version: the held version's settings and rules, plus *add*. A new
    rule set starts in enforce mode (§9); in a rule set in watch mode no rule may be On."""
    if held is None:
        return {
            "mode": "enforce",
            "default": "allow",
            "fail": {},
            "addresses": {"hosts": [], "cidrs": []},
            "approved": None,
            "rules": add,
        }
    watch = held["mode"] == "watch"
    rules = list(held["rules"]) + [{**r, "state": "calibrating"} if watch else r for r in add]
    draft = {
        "mode": held["mode"],
        "default": held["default"],
        "fail": held["fail"],
        "addresses": held["addresses"],
        "approved": held["approved"],
        "rules": rules,
    }
    if "fingerprint_exceptions" in held:
        draft["fingerprint_exceptions"] = held["fingerprint_exceptions"]
    return draft


def confirm_page(rec: Any, x: Any) -> Optional[str]:
    """§6: the console page a version waits on when a person must confirm it there (loosening a
    live project's rules from the command line): from the answer, or from a refusal's body. Only a
    page on the witness's console is given back; ``""`` when the witness asked but sent another page."""
    body = x.body if isinstance(x, SignafaideError) else x
    body = body if isinstance(body, dict) else {}
    err = body.get("error") if isinstance(body.get("error"), dict) else {}
    link = body.get("confirm_in_console", err.get("confirm_in_console"))
    if link is None and isinstance(x, SignafaideError) and x.code == "confirm_in_console":
        link = ""
    if link is None:
        return None
    return on_console(link, console_origin(rec.url)) or ""


def confirm_lines(page: str) -> List[str]:
    """The lines that say a version waits for a person in the console."""
    if page:
        return [
            "Not saved yet: loosening this project's rules is confirmed by a person in the console.",
            f"           Open {page}",
            "           and confirm there; then run signafaide rules pull.",
        ]
    return [
        "Not saved yet: loosening this project's rules is confirmed by a person in the console. Open the console and confirm there "
        "(the page the witness sent is not on its console, so it is not shown)."
    ]


def _waits(page: str) -> SignafaideError:
    return SignafaideError(
        " ".join(line.strip() for line in confirm_lines(page)),
        code="confirm_in_console",
        body={"confirm_in_console": page},
    )


def publish_rules(rec: Any, client: Client, add: List[dict]) -> dict:
    """Publish the next version with *add* (§6 ``POST /v1/rules``), and keep it as the held version."""
    key = rec.api_key
    if not key:
        raise SignafaideError("there is no API key", code="invalid_key")
    rec.resolve_project(key)
    pe = rec.checks.project_env()
    if pe is None:
        raise SignafaideError("the API key's project is not known yet", code="network")
    rec.checks.pull_rules(force=True)
    held = rec.checks.held_rules()
    try:
        item = client.publish_rules(
            {"project": pe[0], "env": pe[1], "after": held["version"] if held else None, "draft": next_draft(held, add)}
        )
    except SignafaideError as e:
        page = confirm_page(rec, e)
        if page is not None:
            raise _waits(page) from None
        raise
    page = confirm_page(rec, item)
    if page is not None:
        raise _waits(page)
    if not isinstance(item, dict) or not isinstance(item.get("rules"), dict):
        raise SignafaideError("the witness answered without the published version", code="bad_response")
    if not rec.checks.keep_rules(item):
        rec.checks.pull_rules(force=True)
    return item


#: The keys of a draft (§6 ``POST /v1/rules``); a whole rule set document's other keys are the
#: service's, and are dropped.
DRAFT_KEYS = ("mode", "default", "fail", "addresses", "approved", "rules", "fingerprint_exceptions")
SERVICE_KEYS = ("format", "project", "env", "set", "version", "prev", "issued")


def draft_from(doc: Any) -> dict:
    """A draft from a file: a draft, or a rule set document (its service keys dropped)."""
    if not isinstance(doc, dict):
        raise SignafaideError(
            "the file must hold a JSON object: a draft {mode, default, fail, addresses, approved, rules} or a rule set",
            code="bad_request",
        )
    unknown = sorted(k for k in doc if k not in DRAFT_KEYS and k not in SERVICE_KEYS)
    if unknown:
        raise SignafaideError(f"the file has the unknown key '{unknown[0]}'", code="bad_request")
    missing = [k for k in DRAFT_KEYS[:6] if k not in doc]
    if missing:
        raise SignafaideError(f"the file lacks the key '{missing[0]}'", code="bad_request")
    return {k: doc[k] for k in DRAFT_KEYS if k in doc}


def run_rules_publish(rec: Any, file: str, prompt: "Prompter", out: Callable[[str], None] = print) -> int:
    """``signafaide rules publish <file>`` (§8): publish the file's draft as the project's next rule
    set version, with the person's session (or the key of an unclaimed sandbox), once the person
    says yes at a terminal. Returns the exit code."""
    try:
        draft = draft_from(json.loads(Path(file).read_text(encoding="utf-8")))
    except (OSError, ValueError, SignafaideError) as e:
        out(f"Not published: {file}: {e}")
        return 1
    pub = publisher(rec)
    if isinstance(pub, str):
        out(f"Not published: {pub}. Sign in first: signafaide login")
        return 1
    client, how, who = pub
    key = rec.api_key
    if not key:
        out(
            "Not published: there is no API key, so the project is not known. Run signafaide init, or set SIGNAFAIDE_API_KEY"
        )
        return 1
    rec.resolve_project(key)
    pe = rec.checks.project_env()
    if pe is None:
        out("Not published: the API key's project is not known yet (the witness could not be reached)")
        return 1
    rec.checks.pull_rules(force=True)
    held = rec.checks.held_rules()
    if how == "session":
        try:
            sess = client.session()
            role = next(
                (
                    x.get("role")
                    for x in sess.get("projects") or []
                    if x.get("project") == pe[0] and x.get("env") == pe[1]
                ),
                None,
            )
            if role:
                who = f"{who} ({role})"
        except SignafaideError:
            pass  # the witness decides who may publish; the role is only shown
    nxt = held["version"] + 1 if held else 1
    out(
        f"Publish rule set version {nxt} of {pe[0]} ({pe[1]}) at {rec.url} as {who}, after version {held['version'] if held else 'none'}:"
    )
    out(f"  mode {draft['mode']}, calls no rule matches: {draft['default']}")
    before = {r["id"]: r for r in (held or {}).get("rules", [])}
    doc = {"mode": draft["mode"], "rules": draft["rules"] if isinstance(draft["rules"], list) else []}
    for r in doc["rules"]:
        if not isinstance(r, dict):
            continue
        try:
            words = rule_words(r)
        except Exception:
            words = f"rule {r.get('id')}"
        state = C.rule_state(doc, r)
        was = before.get(r.get("id"))
        if was is None:
            change = "new"
        elif C.rule_state(held, was) != state:
            change = f"was {state_word(C.rule_state(held, was))}"
        else:
            change = "unchanged" if canonicalize(was) == canonicalize(r) else "changed"
        out(f"  {state_word(state).ljust(12)} {words}  ({change})")
    for rid in before:
        if not any(isinstance(r, dict) and r.get("id") == rid for r in doc["rules"]):
            out(f"  removed      rule {rid}")
    if not prompt.person:
        out("Not published: publishing asks a person at a terminal. Run it at one.")
        return 1
    if not prompt.confirm(f"Publish this as version {nxt}?", False):
        out("Not published.")
        return 1
    try:
        item = client.publish_rules(
            {"project": pe[0], "env": pe[1], "after": held["version"] if held else None, "draft": draft}
        )
    except SignafaideError as e:
        page = confirm_page(rec, e)
        for line in confirm_lines(page) if page is not None else [f"Not published: {e}"]:
            out(line)
        return 1
    page = confirm_page(rec, item)
    if page is not None:
        for line in confirm_lines(page):
            out(line)
        return 1
    if not isinstance(item, dict) or not isinstance(item.get("rules"), dict):
        out("Not published: the witness answered without the published version")
        return 1
    if not rec.checks.keep_rules(item):
        rec.checks.pull_rules(force=True)
    out(
        f"Rules      saved {'in your sandbox' if how == 'sandbox_key' else f'by {who}'} as version {item['rules']['version']}, signed by signafAIde"
    )
    return 0


def field_uses(rs: dict, agent: str, tool: str) -> Dict[str, List[str]]:
    """The fields a tool's rules can use, and the rules that use each (for ``signafaide pull``)."""
    out: Dict[str, List[str]] = {}
    for r in rs["rules"]:
        if not C.applies(r, agent, tool):
            continue
        fields = dict.fromkeys([c["field"] for c in r["when"]] + [x["field"] for x in r.get("exceptions") or []])
        for f in fields:
            out.setdefault(f, []).append(rule_words(r))
    return out


# --- the command -------------------------------------------------------------------------------


def project_agent(root: Path, rec: Any) -> str:
    """The agent's name: from pyproject.toml's project name, else the project folder's."""
    try:
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(), re.M)
        if m:
            return agent_name(m.group(1))
    except OSError:
        pass
    return rec.default_agent


def run_protect(
    rec: Any,
    root: Path,
    prompt: Prompter,
    out: Callable[[str], None],
    tool: Optional[str] = None,
    local: bool = False,
    limit: Optional[Tuple[str, float]] = None,
) -> Tuple[int, List[dict]]:
    """The protect flow. Returns the exit code and the rules it added. *limit*: ``(field, above)``
    from ``--limit-field`` and ``--above``: block the tool when that field is above it, without
    asking what to block; without a person the rule starts Calibrating, as every rule does."""

    def rel(p: Path) -> str:
        try:
            return str(p.relative_to(root))
        except ValueError:
            return str(p)

    found = find_tools(root, tool)
    if not found.tools:
        out(
            f"No tool named {tool} was found in {root}."
            if tool
            else f"No tools were found in {root}. protect looks for functions with a tool decorator (LangChain @tool, OpenAI Agents @function_tool, "
            "MCP @mcp.tool()), a list or dict named like tools, StructuredTool.from_function(func=...), methods of a class named like tools, "
            "and the functions of files named like tools."
        )
        out('Decorate a function by hand: @signafaide.protect(agent="<agent>") from signafaide.')
        return 1, []
    named = agent_in_code(found, root)
    agent = named or project_agent(root, rec)
    out("signafAIde protect")
    out("")
    out(f"Agent      {agent}{' (the name the code already uses)' if named else ''}")
    out(
        f"Found      {'1 tool' if len(found.tools) == 1 else f'{len(found.tools)} tools'} in {', '.join(dict.fromkeys(rel(t.file) for t in found.tools))}"
    )
    out("")
    w = max([16] + [len(t.name) + 2 for t in found.tools])
    out(f"  {'tool'.ljust(w)} {'does'.ljust(16)} suggested")
    for t in found.tools:
        how = f"  ({t.framework})" if t.framework else "  (class method)" if t.shape == "method" else ""
        out(f"  {t.name.ljust(w)} {KIND_WORDS[t.kind].ljust(16)} {'protect' if t.kind in RISKY else 'record'}{how}")
    out("")
    out(
        ("It" if len(found.tools) == 1 else f"All {len(found.tools)} tools")
        + " will be recorded: each call signed here and witnessed by signafAIde."
    )
    out("A protected tool also waits for signafAIde to allow it before it runs.")
    if any(t.kind == "other" for t in found.tools):
        out(
            '"not classified": its name does not say what it does. Protect it if it pays, deletes, sends or changes anything.'
        )
    out("")
    if tool:
        chosen = [t for t in found.tools if t.name == tool]
    elif not prompt.person:
        # Nobody to ask: every risky tool is protected (and any protected in the code already).
        chosen = [t for t in found.tools if risk(t) is not None or t.wrapped == "protect"]
        if chosen:
            out(
                f"Protect    {', '.join(t.name for t in chosen)}: without a terminal, every tool that pays, deletes, sends, runs commands, "
                "pushes code or edits secrets or config is protected"
            )
    else:
        # Every tool is in the question; the first risky one, and any already protected, are ticked.
        first = next((i for i, t in enumerate(found.tools) if t.kind in RISKY), -1)
        risky = [t for t in found.tools if t.kind in RISKY]
        question = (
            "Protect which tools?"
            if len(risky) < 2
            else f"Protect which tools? Suggested: {', '.join(t.name for t in risky)}. Only {found.tools[first].name} is ticked; tick the others "
            "to protect them now (each then asks its own short questions), or leave them and run signafaide protect <tool> later."
        )
        ticks = prompt.multi(
            question,
            [f"{t.name} ({KIND_WORDS[t.kind]})" for t in found.tools],
            [i == first or t.wrapped == "protect" for i, t in enumerate(found.tools)],
        )
        chosen = [t for t, x in zip(found.tools, ticks) if x]
        later = [t for t, x in zip(found.tools, ticks) if not x and t.kind in RISKY]
        if later:
            out(f"  Protect the others later: signafaide protect {later[0].name}")
    # One object whose fields the code does not show: ask for them.
    for t in chosen:
        if not t.object_param or t.fields:
            continue
        out("")
        ans = (
            prompt.text(
                f"{t.name} takes one object, and its fields are not in the code protect read. Which fields does it hold "
                "(comma separated, e.g. payee, amount, currency; Enter for none)?",
                "",
            )
            if prompt.person
            else ""
        )
        names = list(dict.fromkeys(x for x in re.split(r"[\s,]+", ans) if re.fullmatch(r"[A-Za-z_]\w*", x)))
        t.fields = [(n, f"/{t.params[0]}/{n}" if t.params else f"/{n}") for n in names]
        if not t.fields:
            out(
                f"  {t.name}: no fields known, so only a limit on calls a minute can be set here. Annotate its argument with a dataclass, "
                "TypedDict or model, or add rules in the console."
            )
    # The sandbox first, before any rule is asked: blocking needs the witness, so a person who says no
    # knows it now, and the answers below are kept in the checks file for the next run.
    declined_sandbox = False
    if not local and chosen and not rec.api_key and prompt.person:
        out("")
        out("Blocking needs signafAIde to allow each protected call; recording works on this machine without it.")
        if prompt.confirm(
            "Make a free sandbox for these rules? No sign-up; test data only, deleted after 30 days unless you keep it.",
            True,
        ):
            rec.state.ignore_in_git()
            rec.create_sandbox(write_url=False)
            sb = rec.state.sandbox() or {}
            out("Sandbox    made for you, no sign-up. Test data only, deleted after 30 days.")
            if sb.get("claim_url"):
                out(f"           Keep it: {sb['claim_url']}")
        else:
            declined_sandbox = True
            out(
                "  No sandbox: your answers are kept in the checks file, and the next signafaide protect offers them again."
            )
    held = None if local else rec.checks.held_rules()
    taken = {r["id"] for r in (held or {}).get("rules", [])}
    try:
        file_now = rec.checks.file()
    except Exception:
        file_now = None
    new_rules: List[dict] = []
    consumed: Set[str] = set()  # ids of proposed rules offered to this person (used or dropped)
    not_chosen: List[str] = []
    sends_by: Dict[str, Set[str]] = {}
    for t in chosen:
        decl = declared_name(t.name)
        choices = choices_for(t)
        sends: Set[str] = set()
        sends_by[t.name] = sends
        out("")
        c: Optional[Choice] = None
        # A rule an agent run proposed here earlier is offered first, with the agent's value.
        proposed = None
        pr = proposal_for(file_now, decl) if (not limit and not local and prompt.person) else None
        if pr:
            consumed.add(pr[0]["id"])
            if prompt.confirm(
                f"A rule kept on {pr[1]} for {t.name}, not saved then (no key); it blocks nothing yet: {rule_words(pr[0])}\n"
                "  Use it, with that value?",
                True,
            ):
                proposed = pr
            else:
                out(f"  The rule kept on {pr[1]} is dropped; asking as usual.")
        if limit:
            # From the command line: the field and the limit are given, nothing is asked.
            lim = limit_choice(t, limit[0])
            if lim is None:
                names = ", ".join(n for n, _ in t.fields)
                out(
                    f"  {t.name} has no field named {limit[0]}{f' (its fields: {names})' if names else ''}: no rule added."
                )
                not_chosen.append(f"{t.name} has no field named {limit[0]}, so no rule was added")
                continue
            rule = lim.make(decl, _limit_text(limit[1]), rule_id(decl, lim.key, taken))
        elif proposed:
            rule = {**proposed[0], "id": rule_id(decl, proposed[0]["id"][len(decl) + 1 :] or "limit", taken)}
            out(f"  Rule: {rule_words(rule)}  (kept on {proposed[1]})")
        elif not prompt.person and prompt.yes and default_rule(t, decl, set(taken)) is not None:
            # protect --yes: a sensible default for what the tool does, Calibrating (it blocks nothing).
            rule = default_rule(t, decl, taken)  # type: ignore[assignment]
        else:
            pick = prompt.choose(
                f"What should we block on {t.name}?",
                [x.label for x in choices] + ["Nothing yet, record only"],
                0 if prompt.person else len(choices),
            )
            if pick >= len(choices):
                continue
            c = choices[pick]
            value = prompt.text(c.ask, c.default)
            try:
                ok = bool(value) and (not c.numeric or float(value) > 0)
            except ValueError:
                ok = False
            if not ok:
                out(f"  {value or '(nothing)'} is not a number above 0: no rule added for {t.name}.")
                continue
            rule = c.make(decl, value, rule_id(decl, c.key, taken))
        if not proposed:
            out(f"  Rule: {rule_words(rule)}")
        on = False
        if prompt.person:
            on = (
                prompt.choose(
                    'Turn it on now? On blocks the call. Calibrating only notes "Would have blocked".',
                    ["On", "Calibrating"],
                    0,
                )
                == 0
            )
        else:
            out(CALIBRATING_LINE)
        new_rules.append({**rule, "state": "on" if on else "calibrating"})
        sends.update(x["field"] for x in rule["when"])
        if c is None:
            continue
        extras = [x for x in choices if x is not c]
        if extras:
            out("")
            out("  Optional, each starts Calibrating and never blocks until a person turns it on:")
            extra_rules = [x.make(decl, x.default, "") for x in extras]
            ticks = prompt.multi(
                "Also calibrate", [rule_words(r).replace(f" {decl} ", " ") for r in extra_rules], [False] * len(extras)
            )
            for x, r, tick in zip(extras, extra_rules, ticks):
                if tick:
                    r = {**r, "id": rule_id(decl, x.key, taken), "state": "calibrating"}
                    new_rules.append(r)
                    sends.update(y["field"] for y in r["when"])
            out("  Rules added later in the console also start Calibrating.")
    out("")
    not_done: List[str] = list(not_chosen)
    finish: Optional[str] = None
    file_before = to_version2(file_now)
    for t in chosen:
        sends = sends_by.get(t.name, set())
        fields = sorted(sends)
        n = sum(1 for r in new_rules if declared_name(t.name) in (r.get("tools") or []))
        # Fields a person approved earlier (``pull`` or ``protect`` at a terminal) are sent already.
        was = (file_before.get("tools") or {}).get(declared_name(t.name)) or {}
        approved = list(was.get("disclose") or []) if was.get("protect") else []
        fresh = [f for f in fields if f not in approved]
        if not local and not prompt.person and fresh:
            sent = [f for f in fields if f in approved]
            now = (
                f"{', '.join(field_words(f) for f in sent)} (approved earlier); not {', '.join(field_words(f) for f in fresh)} yet"
                if sent
                else "nothing yet"
            )
            out(
                f"Sends to signafAIde when {t.name} runs: {now}. Its rules need {', '.join(field_words(f) for f in fresh)}: "
                f"run signafaide pull at a terminal to approve sending {'it' if len(fresh) == 1 else 'them'}."
            )
            not_done.append(
                f"sending {', '.join(field_words(f) for f in fresh)} for {t.name} is not approved (signafaide pull at a terminal)"
            )
            finish = finish or "signafaide pull (at a terminal)"
            for f in fresh:
                sends.discard(f)
        elif not local and not prompt.person and fields:
            out(
                f"Sends to signafAIde when {t.name} runs: {', '.join(field_words(f) for f in fields)} "
                f"(approved earlier; the fields your {'rule needs' if n == 1 else f'{n} rules need'})"
            )
        elif not local:
            what = ", ".join(field_words(f) for f in fields) or "nothing but the tool's fingerprints"
            tail = f" (the fields your {'rule needs' if n == 1 else f'{n} rules need'})" if fields else ""
            out(f"Sends to signafAIde when {t.name} runs: {what}{tail}")
        never = [name for name, ptr in t.fields if ptr not in sends]
        if never and not local:
            out(f"Never sent to signafAIde: {', '.join(never)}. Your own records on this machine keep the whole call.")
    if chosen and not local:
        out("If signafAIde can't be reached: stop (it retries for 10 s; change it in the console)")
    out("")
    # A sandbox only on a person's answer: nothing is sent without an explicit human opt-in (§8).
    if not local and chosen and not rec.api_key and not prompt.person:
        out("Sandbox    not made: only a person at a terminal opts in. Run signafaide protect (or init) in a terminal.")
        not_done.append("no sandbox and no API key, so protected tools stop until there is one")
        finish = "signafaide protect (in a terminal)"
    if declined_sandbox:
        not_done.append("no sandbox and no API key, so protected tools stop until there is one")
        finish = finish or "signafaide protect, and answer yes to the sandbox (or set SIGNAFAIDE_API_KEY)"
    changed: List[Tuple[str, str]] = []
    # With --local there is no witness to wait for: the code records, and the checks file's mode
    # for the tool (enforce when a rule is On) decides whether the local rules block.
    protect_set = set() if local else {t.name for t in chosen}
    written: List[Path] = []
    hand: List[str] = []
    changes = code_changes(found, protect_set, agent, root, find_tools(root) if tool else None)
    # No terminal and no --yes: nobody to show the change to, so it is shown here and nothing is written.
    if not prompt.person and not prompt.yes:
        for ch in changes:
            out(f"Change     {rel(ch.file)} (not written)")
            for line in line_diff(ch.before, ch.after):
                out(f"  {line}")
            out("")
        out(
            "Nothing written: there is no terminal to ask before changing your files. Run signafaide protect in a "
            "terminal, or signafaide protect --yes to apply the change above."
        )
        return 1, []
    for ch in changes:
        out(f"Change     {rel(ch.file)}")
        for line in line_diff(ch.before, ch.after):
            out(f"  {line}")
        if prompt.confirm(f"Write this change to {rel(ch.file)}?", True):
            ch.file.write_text(ch.after)
            written.append(ch.file)
            prot = [t.name for t in ch.tools if t.name in protect_set or t.wrapped == "protect"]
            what = (
                (
                    f"{'1 tool' if len(ch.tools) == 1 else f'{len(ch.tools)} tools'} recorded"
                    + (f", {', '.join(prot)} protected" if prot else "")
                )
                if ch.tools
                else f"agent {agent} named in declare_tools"
            )
            changed.append((rel(ch.file), what))
        else:
            for t in ch.tools:
                hand.append(
                    f"  @signafaide.{'protect' if t.name in protect_set or t.wrapped == 'protect' else 'record'}(agent={json.dumps(agent)})  # above def {t.name}"
                )
            not_done.append(f"{rel(ch.file)} was not changed: add the lines below by hand")
        out("")
    if hand:
        out("Add this to the code by hand:")
        out("  import signafaide")
        for line in hand:
            out(line)
        out(f"  signafaide.declare_tools({json.dumps([t.name for t in found.tools])}, agent={json.dumps(agent)})")
        out("")
    # The project note, so the next coding agent here protects such tools too (asked; never twice).
    # Only a person at a terminal is offered it: a run without one (a coding agent's --yes) never
    # writes AGENTS.md or CLAUDE.md, the instructions that shape later sessions.
    note_changes = offer_note(root, prompt, out) if prompt.person else []
    if note_changes:
        out("")
    cp = checks_path(rec.state.root) or (root / CHECKS_FILE)
    doc = to_version2(file_now)
    for t in chosen:
        decl = declared_name(t.name)
        if local:
            # On this machine a tool's rules are all On (enforce) or all Calibrating (watch): On
            # only when a person turned a rule On here, or when its local rules were On already.
            was = doc["tools"].get(decl)
            on_before = (
                bool(was)
                and was.get("protect") is not True
                and was.get("mode") == "enforce"
                and any(
                    r.get("tools") is None or decl in r["tools"] for r in ((doc.get("rules") or {}).get("rules") or [])
                )
            )
            on_now = any(r.get("state") == "on" and decl in (r.get("tools") or []) for r in new_rules)
            doc["tools"][decl] = {"protect": False, "mode": "enforce" if on_before or on_now else "watch"}
            continue
        cur = doc["tools"].get(decl) or {}
        have = list(cur.get("disclose") or []) if cur.get("protect") else []
        disclose = have + [p for p in sorted(sends_by.get(t.name, set())) if p not in have]
        doc["tools"][decl] = {"protect": True, **({"disclose": disclose} if disclose else {})}
    # Proposals a person was just offered are used up: the rule is published below or dropped.
    if consumed and doc.get("rules"):
        doc["rules"]["rules"] = [r for r in doc["rules"]["rules"] if r["id"] not in consumed]
        if not doc["rules"]["rules"]:
            doc["rules"] = None
    if isinstance(doc.get("proposed"), list):
        doc["proposed"] = [p for p in doc["proposed"] if proposed_id(p) not in consumed]
    # An agent run with no key cannot save its rule at the witness: it is kept here as a local
    # Calibrating rule (the tool's mode is watch, so it blocks nothing) that a person is offered later.
    keep_proposal = bool(not local and not rec.api_key and new_rules and (prompt.person or limit or prompt.yes))
    if keep_proposal:
        keep_proposed(doc, new_rules)
    if "proposed" in doc and not doc["proposed"]:
        del doc["proposed"]
    if local and new_rules:
        lr = doc["rules"] or {"default": "allow", "rules": []}
        ids = {r["id"] for r in lr["rules"]}
        for r in new_rules:
            if "limit" in r:
                out(f'  "{rule_words(r)}" is not kept: only the witness counts calls.')
                continue
            plain = {k: v for k, v in r.items() if k != "state"}
            on = next(
                (d for d in plain.get("tools") or [] if (doc["tools"].get(d) or {}).get("mode") == "enforce"), None
            )
            if r.get("state") == "calibrating" and on:
                out(
                    f'  "{rule_words(r)}" is not kept: on this machine a tool\'s rules are all On or all Calibrating, and {on} is On.'
                )
                continue
            if plain["id"] not in ids:
                lr["rules"].append(plain)
        doc["rules"] = lr
    write_checks_file(cp, doc)
    changed.append((rel(cp), "written by signafaide protect and pull; commit it"))
    changed.extend((f, note_what(f, what)) for f, what in note_changes)
    # The key's line only when it is so: the key is in .env, and .gitignore keeps .env out of git.
    if rec.api_key and _key_in_env_file(root):
        if env_ignored(root):
            changed.append((".env", "SIGNAFAIDE_API_KEY, already in .gitignore"))
        else:
            changed.append((".env", "SIGNAFAIDE_API_KEY; .env is NOT in .gitignore: add it before you commit"))
            not_done.append(".env is not in .gitignore (add a line .env)")
    cw = max([26] + [len(f) + 2 for f, _ in changed])
    for i, (f, what) in enumerate(changed):
        out(f"{'Changed    ' if i == 0 else '           '}{f.ljust(cw)} {what}")
    code = 0
    published = None
    if not local and new_rules and not rec.api_key:
        # No key and no sandbox: nothing can save the rules yet, and a sign-in would not help.
        calibrating = all(r.get("state") == "calibrating" for r in new_rules)
        tail = f" {'It starts' if len(new_rules) == 1 else 'They start'} Calibrating once saved." if calibrating else ""
        out(f"Rules      not saved yet: there is no key.{tail}")
        if keep_proposal:
            one = len(new_rules) == 1
            what = (
                "a local Calibrating rule (it blocks nothing)"
                if one
                else "local Calibrating rules (they block nothing)"
            )
            out(
                f"           Kept in {rel(cp)} as {what}; signafaide protect in a terminal offers {'it' if one else 'them'} again, with the free sandbox."
            )
        not_done.append("the rules are not saved (no key yet)")
        finish = finish or "signafaide protect (in a terminal)"
        code = 1
    elif not local and new_rules:
        pub = publisher(rec)
        # Without a person, on a project an API key cannot save rules in: the rules stay in the
        # checks file, Calibrating, and one console link per rule lets a person add it.
        where = add_in_console(rec, new_rules) if isinstance(pub, str) and not prompt.person else None
        if isinstance(where, dict):
            published = where["published"]["rules"]["version"]
            out(f"Rules      saved in your sandbox as version {published}, signed by signafAIde")
        elif isinstance(pub, str):
            code = 1
            if not prompt.person:
                keep_proposed(doc, new_rules)
                write_checks_file(cp, doc)
            if isinstance(where, str):
                out(f"Rules      kept in {rel(cp)} as Calibrating (they block nothing). An API key")
                out("           cannot save rules in a project of an organisation: a person adds each one in the")
                out(
                    "           console, then runs signafaide pull at a terminal to approve sending the fields it needs."
                )
                for r in new_rules:
                    tool = (r.get("tools") or [""])[0]
                    link = add_link(where, agent, r)
                    out(
                        f"           Add {tool}'s rule: {link}"
                        if link
                        else f"           Add {tool}'s rule in the console: {where}/{urllib.parse.quote(agent, safe='')}/{urllib.parse.quote(tool, safe='')} (the rule is too long for a link)"
                    )
                not_done.append(
                    "the rules are not saved for the project: a person adds each one in the console (the links above)"
                )
                finish = "a person opens each link above and adds the rule (Add as Calibrating); or signafaide login, then signafaide protect"
            else:
                out(f"Rules      not saved: {pub}.")
                out(
                    "           Saving rules needs a person's sign-in: signafaide login, then signafaide protect again (or add them in the console)."
                )
                if not prompt.person:
                    out(
                        f"           Kept in {rel(cp)} as Calibrating (they block nothing); a person who runs signafaide protect in a terminal is offered them."
                    )
                not_done.append("the rules are not saved for the project")
                finish = "signafaide login, then signafaide protect"
        else:
            client, how, who = pub
            try:
                item = publish_rules(rec, client, new_rules)
                published = item["rules"]["version"]
                out(
                    f"Rules      saved {'in your sandbox' if how == 'sandbox_key' else f'by {who}'} as version {published}, signed by signafAIde"
                )
                if not prompt.person:
                    out(
                        f"           {'The rule' if len(new_rules) == 1 else f'All {len(new_rules)} rules'} start Calibrating: "
                        f"{'it notes' if len(new_rules) == 1 else 'they note'} the calls {'it' if len(new_rules) == 1 else 'they'} would have blocked "
                        "and block none until a person turns them On:"
                    )
                    for r in new_rules:
                        out(f"             Calibrating  {rule_words(r)}")
                if how == "sandbox_key":
                    out(
                        "           This machine may save rules only while the sandbox is unclaimed. After you keep it,"
                    )
                    out("           saving rules needs a person's sign-in (signafaide login); the API key cannot.")
            except SignafaideError as e:
                if e.code == "confirm_in_console":
                    for i, line in enumerate(confirm_lines(str(e.body.get("confirm_in_console") or ""))):
                        out(f"Rules      {line}" if i == 0 else line)
                    not_done.append("the rules wait for a person to confirm them in the console")
                    finish = finish or "confirm in the console, then signafaide pull"
                else:
                    out(f"Rules      not saved: {e}")
                    not_done.append("the rules are not saved")
                    finish = finish or "signafaide protect"
                code = 1
    elif local and new_rules:
        out(f"Rules      kept on this machine in {rel(cp)}; signafAIde does not rule on them.")
    if not prompt.person and chosen and not local and not new_rules:
        not_done.append(
            f"no rule was chosen for {', '.join(t.name for t in chosen)} (a person at a terminal chooses; or add rules in the console)"
        )
    out("")
    ex = _example(chosen[0], new_rules) if chosen else None
    if not not_done:
        out("Done." + (" Check a call without running it:" if ex else ""))
        if ex:
            out(f"           signafaide check {ex}")
    else:
        done = (
            [f"checks file {rel(cp)}"]
            + [f"code in {rel(f)}" for f in written]
            + [f"the note in {f}" for f, _ in note_changes]
            + ([f"rules version {published}"] if published else [])
        )
        out(f"Not finished. Done: {', '.join(done)}.")
        out("Not done:")
        for x in not_done:
            out(f"  - {x}")
        out(
            f"To finish: {finish or ('add the lines above, then signafaide protect again' if hand else 'signafaide protect (in a terminal)')}"
        )
        if ex:
            out(f"Then check a call without running it: signafaide check {ex}")
    return code, new_rules


def env_ignored(root: Path) -> bool:
    """Whether ``.gitignore`` in *root* keeps ``.env`` out of git."""
    try:
        lines = (root / ".gitignore").read_text().splitlines()
    except OSError:
        return False
    return any(x.strip() in ("./.env", ".env", "/.env", ".env*", "*.env", ".env.*") for x in lines)


def _key_in_env_file(root: Path) -> bool:
    try:
        return re.search(r"^\s*SIGNAFAIDE_API_KEY\s*=\s*\S", (root / ".env").read_text(), re.M) is not None
    except OSError:
        return False


def _example(t: FoundTool, rules: List[dict]) -> Optional[str]:
    """``approve_payout amount=1200 currency=GBP``: a call the first new rule with a condition
    would stop, and that the tool's other rules would let through."""
    decl = declared_name(t.name)
    mine = [x for x in rules if decl in (x.get("tools") or []) and x["when"]]
    if not mine:
        return None
    parts: Dict[str, str] = {}
    for i, r in enumerate(mine):
        for c in r["when"]:
            f = field_words(c["field"])
            if f in parts:
                continue
            stop = i == 0
            if c["op"] == "gt":
                parts[f] = str(round(float(c["value"]) * 1.2)) if stop else canonicalize(c["value"]).decode()
            elif c["op"] in ("not_in", "in"):
                parts[f] = "XXX" if stop == (c["op"] == "not_in") else str(c["value"][0])
            elif c["op"] == "ne":
                parts[f] = "XXX" if stop else str(c["value"])
            else:
                parts[f] = canonicalize(c["value"]).decode()
    return f"{t.name} " + " ".join(f"{f}={v}" for f, v in parts.items())
