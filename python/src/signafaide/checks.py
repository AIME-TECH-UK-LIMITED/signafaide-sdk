"""Tool-call checks (SPEC §2.8, §3.5, §8, §10, §11): the rule language, the checks a record
carries, the client's own checks, signed rule sets, the shared fingerprint list, tool
fingerprints, and the verifier's tool-call checks report. Pure functions, no I/O (except the
optional name lookup of the ``address`` check).

Rulings are ``allow`` or ``block``, nothing between; watch mode records what enforce mode would
have done.
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import urllib.parse
from typing import Any, Callable, Iterable, List, Optional, Sequence, Tuple

from .crypto import HEX64, SALT_RE, hash_json, sha256_hex, verify_sig
from . import scan
from .jcs import canonicalize

# --- constants (§9) -----------------------------------------------------------------------

DISCLOSED_MAX_BYTES = 16_384
RULING_TIMEOUT_MS = 10_000
RULES_REFRESH_MS = 60_000
#: How long a call waits for the first rule set fetch of a process when no version is held (§8, §9, SDK 0.5.2).
RULES_START_WAIT_MS = 300
FINGERPRINTS_REFRESH_MS = 60_000
RULES_FORMAT = "signafaide-rules/1"
LIST_FORMAT = "signafaide-fingerprints/1"
CHECKS_FORMAT = "signafaide-checks/1"
#: Spec 1.1: the checks file with ``protect`` and a mode per tool (§8).
CHECKS_FORMAT_2 = "signafaide-checks/2"
MAX_RULE_SET_BYTES = 1 << 20

#: The check ids, in the order of the §2.8 table.
CHECK_IDS = ("secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction")
DECISION_CHECKS = ("secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction")
#: The checks of an outcome (§2.8): on the tool's result.
OUTCOME_CHECKS = ("secret", "hidden_instruction")
#: The checks a checks file turns on or off (``rule`` is on whenever rules are held).
FILE_CHECKS = ("secret", "address", "changed_tool", "fingerprint", "hidden_instruction")
RESULT_ORDER = {"allow": 0, "note": 1, "block": 2}
SECRET_FORMATS = (
    (
        "github_token",
        r"gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{82,244}",
        ("github.com", "api.github.com", "uploads.github.com"),
    ),
    ("aws_access_key", r"(AKIA|ASIA)[A-Z0-9]{16}", ("*.amazonaws.com",)),
    ("stripe_key", r"(sk|rk)_(live|test)_[A-Za-z0-9]{24,99}", ("api.stripe.com",)),
    ("slack_token", r"xox[abposr]-[A-Za-z0-9-]{10,200}", ("slack.com", "*.slack.com")),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,200}", ("api.anthropic.com",)),
    ("openai_key", r"sk-proj-[A-Za-z0-9_-]{20,200}", ("api.openai.com",)),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}", ("*.googleapis.com",)),
    (
        "signafaide_key",
        r"sfa_(test|live|user)_[0-9A-Za-z]{32}",
        (),
    ),  # issuer: the host of the client's witness URL; sfa_user_ is a person session (§6)
)
_SECRET_RES = tuple((fid, re.compile(pat), issuers) for fid, pat, issuers in SECRET_FORMATS)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
#: Secret formats read by a text rule, not a whole-token pattern (§8): they block like the table's.
TEXT_FORMATS = ("private_key", "wallet_private_key", "seed_phrase")
#: Secrets known by where they stand, not by a format (§8, spec 1.1): a value
#: named as a secret that looks random, a JSON Web Token, a bearer credential. Read on arguments
#: only; they block like the table's formats.
CONTEXT_FORMATS = ("bearer_token", "jwt", "named_secret")
#: What the ``secret`` check notes without blocking (§2.8): public or uncertain finds.
SECRET_NOTES = ("card_number", "high_entropy", "wallet_address")
FOUND = {
    "secret": {f[0] for f in SECRET_FORMATS} | set(TEXT_FORMATS) | set(CONTEXT_FORMATS) | set(SECRET_NOTES),
    "address": {
        "loopback",
        "private",
        "shared",
        "link_local",
        "unique_local",
        "unspecified",
        "metadata",
        "internal_name",
    },
    "changed_tool": {"description_changed", "schema_changed", "not_approved"},
    "fingerprint": {"tool", "description", "server"},
    "hidden_instruction": {
        "invisible_characters",
        "instruction_phrase",
        "encoded_content",
        "tool_shadowing",
        "look_alike_name",
        "possible_hidden_instruction",
    },
}
OPS_VALUE = {"eq", "ne", "lt", "le", "gt", "ge", "in", "not_in", "prefix", "suffix", "contains", "type"}
OPS_NO_VALUE = {"present", "absent"}
TYPES = ("string", "number", "integer", "boolean", "null", "object", "array")
RULE_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
SET_RE = re.compile(r"\Ars_[0-9A-HJKMNP-TV-Z]{26}\Z")
AGENT_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
PROJECT_RE = re.compile(r"\Aprj_[0-7][0-9A-HJKMNP-TV-Z]{25}\Z")
TIME_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")
_HOST_PATTERN = re.compile(r"\A(\*\.)?[a-z0-9._-]{1,253}\Z")


class Absent:
    """A field a pointer does not reach (§10.3)."""

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = Absent()


def is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def is_safe_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and abs(x) <= 2**53 - 1


def is_hex64(x: Any) -> bool:
    return isinstance(x, str) and bool(HEX64.match(x))


def _jcs_eq(a: Any, b: Any) -> bool:
    try:
        return canonicalize(a) == canonicalize(b)
    except (ValueError, TypeError):
        return False


def _valid_time(t: Any) -> bool:
    if not isinstance(t, str) or not TIME_RE.match(t):
        return False
    from .records import parse_time

    try:
        parse_time(t)
        return True
    except ValueError:
        return False


def _cmp_time(a: str, b: str) -> int:
    from .records import parse_time

    x, y = parse_time(a), parse_time(b)
    return (x > y) - (x < y)


# --- JSON Pointer and conditions (§10.1, §10.3) -------------------------------------------


def pointer_ok(p: Any) -> bool:
    """A JSON Pointer as §10.1 allows it: starts with ``/``, at most 256 characters, ``~`` only as ``~0`` or ``~1``."""
    return isinstance(p, str) and p.startswith("/") and len(p) <= 256 and re.search(r"~(?![01])", p) is None


def resolve(doc: Any, ptr: str) -> Any:
    """The value at *ptr* in *doc* (RFC 6901), or :data:`ABSENT`."""
    cur = doc
    for raw in ptr[1:].split("/"):
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if tok not in cur:
                return ABSENT
            cur = cur[tok]
        elif isinstance(cur, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", tok) or int(tok) >= len(cur):
                return ABSENT
            cur = cur[int(tok)]
        else:
            return ABSENT
    return cur


def _type_of(v: Any, name: str) -> bool:
    if name == "string":
        return isinstance(v, str)
    if name == "number":
        return is_num(v)
    if name == "integer":
        return is_num(v) and math.isfinite(float(v)) and float(v).is_integer()
    if name == "boolean":
        return isinstance(v, bool)
    if name == "null":
        return v is None
    if name == "object":
        return isinstance(v, dict)
    return isinstance(v, list)


def condition(cond: dict, value: Any) -> Any:
    """``True``, ``False`` or ``"error"`` for one condition against the field it names
    (*value* is :data:`ABSENT` when the field is absent)."""
    op = cond["op"]
    if value is ABSENT:
        return op == "absent"
    if op == "present":
        return True
    if op == "absent":
        return False
    want = cond["value"]
    if op == "eq":
        return _jcs_eq(value, want)
    if op == "ne":
        return not _jcs_eq(value, want)
    if op in ("lt", "le", "gt", "ge"):
        if not is_num(value):
            return "error"
        a, b = float(value), float(want)
        return {"lt": a < b, "le": a <= b, "gt": a > b, "ge": a >= b}[op]
    if op in ("in", "not_in"):
        hit = any(_jcs_eq(value, w) for w in want)
        return hit if op == "in" else not hit
    if op in ("prefix", "suffix", "contains"):
        if not isinstance(value, str):
            return "error"
        return {"prefix": value.startswith(want), "suffix": value.endswith(want), "contains": want in value}[op]
    return _type_of(value, want)


# --- rule set documents (§10.1) -----------------------------------------------------------


def _exact(o: dict, keys: Sequence[str], optional: Sequence[str], what: str) -> Optional[str]:
    extra = sorted(k for k in o if k not in keys and k not in optional)
    if extra:
        return f"{what} has the unknown field '{extra[0]}'"
    missing = [k for k in keys if k not in o]
    if missing:
        return f"{what} lacks the field '{missing[0]}'"
    return None


def _declared_name(s: Any) -> bool:
    return isinstance(s, str) and 1 <= len(s) <= 101


def _host_pattern(s: Any) -> bool:
    return isinstance(s, str) and bool(_HOST_PATTERN.match(s)) and len(s[2:] if s.startswith("*.") else s) >= 1


def _cidr(s: Any) -> bool:
    if not isinstance(s, str) or "/" not in s:
        return False
    addr, _, length = s.partition("/")
    if not length.isdigit() or length != str(int(length)):
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return int(length) <= (32 if ip.version == 4 else 128)


def condition_errors(c: Any) -> Optional[str]:
    if not isinstance(c, dict) or not isinstance(c.get("op"), str):
        return "a condition is {field, op, value}"
    op = c["op"]
    if op not in OPS_VALUE | OPS_NO_VALUE:
        return f"unknown operator '{op}'"
    err = _exact(c, ("field", "op") if op in OPS_NO_VALUE else ("field", "op", "value"), (), "a condition")
    if err:
        return err
    if not pointer_ok(c["field"]):
        return "field must be a JSON Pointer of at most 256 characters, ~ only as ~0 or ~1"
    v = c.get("value")
    ok = {
        "lt": is_num(v),
        "le": is_num(v),
        "gt": is_num(v),
        "ge": is_num(v),
        "in": isinstance(v, list) and len(v) <= 256,
        "not_in": isinstance(v, list) and len(v) <= 256,
        "prefix": isinstance(v, str),
        "suffix": isinstance(v, str),
        "contains": isinstance(v, str),
        "type": v in TYPES,
    }.get(op, True)
    return None if ok else f"the value of '{op}' has the wrong type"


def rule_errors(r: Any, allow_limit: bool = True, version: Optional[int] = None) -> Optional[str]:
    """The first problem with a rule (§10.1). *version* is the rule set document's version; None
    for the local rules of a checks file, which may use neither ``limit`` (*allow_limit* False)
    nor, from spec 1.1, ``state`` and ``exceptions`` (the checks file sets their mode per tool)."""
    if not isinstance(r, dict):
        return "each rule is an object"
    optional = (("limit",) if allow_limit else ()) + (("state", "exceptions") if version is not None else ())
    err = _exact(r, ("id", "about", "action", "tools", "agents", "when"), optional, "a rule")
    if err:
        return err
    if not isinstance(r["id"], str) or not RULE_ID_RE.match(r["id"]):
        return "a rule id matches ^[a-z0-9][a-z0-9._-]{0,63}$"
    rid = r["id"]
    if not isinstance(r["about"], str) or len(r["about"]) > 200:
        return f"rule '{rid}': about is text of at most 200 characters"
    if r["action"] not in ("allow", "block"):
        return f"rule '{rid}': action must be allow or block"
    for k, ok in (("tools", _declared_name), ("agents", lambda a: isinstance(a, str) and bool(AGENT_RE.match(a)))):
        v = r[k]
        if v is not None and not (isinstance(v, list) and 1 <= len(v) <= 256 and all(ok(x) for x in v)):
            return f"rule '{rid}': {k} is null or a list of 1 to 256 names"
    if not isinstance(r["when"], list) or len(r["when"]) > 16:
        return f"rule '{rid}': when is a list of at most 16 conditions"
    for c in r["when"]:
        e = condition_errors(c)
        if e:
            return f"rule '{rid}': {e}"
    if "limit" in r:
        lim = r["limit"]
        if r["action"] != "block":
            return f"rule '{rid}': limit is allowed only on a block rule"
        if not isinstance(lim, dict) or set(lim) != {"calls", "seconds", "per"}:
            return f"rule '{rid}': limit is {{calls, seconds, per}}"
        if not is_safe_int(lim["calls"]) or not 1 <= lim["calls"] <= 1_000_000:
            return f"rule '{rid}': limit.calls is 1 to 1,000,000"
        if not is_safe_int(lim["seconds"]) or not 1 <= lim["seconds"] <= 86_400:
            return f"rule '{rid}': limit.seconds is 1 to 86,400"
        if lim["per"] not in ("agent", "tool", "agent_tool"):
            return f"rule '{rid}': limit.per is agent, tool or agent_tool"
    if "state" in r and r["state"] not in ("calibrating", "on"):
        return f"rule '{rid}': state must be calibrating or on"
    if "exceptions" in r:
        if r["action"] != "block":
            return f"rule '{rid}': exceptions are allowed only on a block rule"
        xs = r["exceptions"]
        if not isinstance(xs, list) or not 1 <= len(xs) <= 256:
            return f"rule '{rid}': exceptions is a list of 1 to 256 exceptions"
        seen: set = set()
        for x in xs:
            if not isinstance(x, dict):
                return f"rule '{rid}': an exception is {{field, value, reason, since}}"
            e = _exact(x, ("field", "value", "reason", "since"), (), f"rule '{rid}': an exception")
            if e:
                return e
            if not pointer_ok(x["field"]):
                return f"rule '{rid}': an exception's field must be a JSON Pointer of at most 256 characters, ~ only as ~0 or ~1"
            if not isinstance(x["reason"], str) or not 1 <= len(x["reason"]) <= 200:
                return f"rule '{rid}': an exception's reason is text of 1 to 200 characters"
            if not is_safe_int(x["since"]) or not 1 <= x["since"] <= (version or 0):
                return f"rule '{rid}': an exception's since is the version that added it, 1 to this version"
            try:
                text = canonicalize(x["value"]).decode()
            except (ValueError, TypeError) as err2:
                return f"rule '{rid}': an exception's value is not canonical JSON: {err2}"
            k = (x["field"], text)
            if k in seen:
                return f"rule '{rid}': the exception {x['field']} {text} is listed twice"
            seen.add(k)
    return None


def _rules_list_errors(rules: Any, allow_limit: bool = True, version: Optional[int] = None) -> Optional[str]:
    if not isinstance(rules, list) or len(rules) > 1000:
        return "rules must be a list of at most 1,000 rules"
    seen = set()
    for r in rules:
        err = rule_errors(r, allow_limit, version)
        if err:
            return err
        if r["id"] in seen:
            return f"the rule id '{r['id']}' is used twice"
        seen.add(r["id"])
    return None


def rule_set_errors(doc: Any) -> Optional[str]:
    """The first problem with a rule set document (§10.1), or None when it is valid."""
    if not isinstance(doc, dict):
        return "a rule set is a JSON object"
    err = _exact(
        doc,
        (
            "format",
            "project",
            "env",
            "set",
            "version",
            "prev",
            "issued",
            "mode",
            "default",
            "fail",
            "addresses",
            "approved",
            "rules",
        ),
        ("fingerprint_exceptions", "protect"),
        "the rule set",
    )
    if err:
        return err
    try:
        if len(canonicalize(doc)) > MAX_RULE_SET_BYTES:
            return "the rule set's JCS form is more than 1 MiB"
    except (ValueError, TypeError) as e:
        return f"the rule set is not canonical JSON: {e}"
    if doc["format"] != RULES_FORMAT:
        return f"format must be {RULES_FORMAT}"
    if not isinstance(doc["project"], str) or not PROJECT_RE.match(doc["project"]):
        return "project must be a project id"
    if doc["env"] not in ("test", "live"):
        return "env must be test or live"
    if not isinstance(doc["set"], str) or not SET_RE.match(doc["set"]):
        return "set must be rs_ followed by 26 Crockford base32 characters"
    if not is_safe_int(doc["version"]) or doc["version"] < 1:
        return "version must be an integer of at least 1"
    if not ((doc["version"] == 1 and doc["prev"] is None) or (doc["version"] > 1 and is_hex64(doc["prev"]))):
        return "prev is the rules_hash of version - 1, and null exactly when version is 1"
    if not _valid_time(doc["issued"]):
        return "issued must be a time such as 2026-11-17T09:00:00.000Z"
    if doc["mode"] not in ("watch", "enforce"):
        return '`mode` must be "watch" (Calibrating) or "enforce" (On)'
    if doc["default"] not in ("allow", "block"):
        return "default must be allow or block"
    f = doc["fail"]
    if (
        not isinstance(f, dict)
        or len(f) > 1000
        or not all(_declared_name(k) and v in ("open", "closed") for k, v in f.items())
    ):
        return "fail maps declared tool names to open or closed"
    if "protect" in doc:
        p = doc["protect"]
        if not isinstance(p, dict) or not 1 <= len(p) <= 1000:
            return "protect must be an object of 1 to 1,000 tools (left out when no tool is protected from the console)"
        for name, e in p.items():
            if not isinstance(e, dict):
                return "protect maps declared tool names to {fail}"
            err = _exact(e, ("fail",), (), f"protect.{name}")
            if err:
                return err
            if not _declared_name(name) or e["fail"] not in ("open", "closed"):
                return 'protect maps declared tool names to {"fail": "closed" | "open"}'
            if name in f and f[name] != e["fail"]:
                return f"{name} is in fail as {f[name]} and in protect as {e['fail']}: a tool named in both has the same fail mode"
    a = doc["addresses"]
    if not isinstance(a, dict) or set(a) != {"hosts", "cidrs"}:
        return "addresses must be {hosts, cidrs}"
    if not isinstance(a["hosts"], list) or len(a["hosts"]) > 1000 or not all(_host_pattern(h) for h in a["hosts"]):
        return "addresses.hosts holds lowercase names, or *. and a suffix"
    if not isinstance(a["cidrs"], list) or len(a["cidrs"]) > 1000 or not all(_cidr(c) for c in a["cidrs"]):
        return "addresses.cidrs holds IPv4 or IPv6 networks in CIDR form"
    ap = doc["approved"]
    if ap is not None:
        if not isinstance(ap, dict) or len(ap) > 10_000:
            return "approved must be null or an object of at most 10,000 tools"
        for name, e in ap.items():
            if (
                not _declared_name(name)
                or not isinstance(e, dict)
                or set(e) != {"description", "schema"}
                or not (is_hex64(e["description"]) and is_hex64(e["schema"]))
            ):
                return "approved maps declared tool names to {description, schema} fingerprints"
    if "fingerprint_exceptions" in doc:
        xs = doc["fingerprint_exceptions"]
        if not isinstance(xs, list) or len(xs) > 1000:
            return "fingerprint_exceptions must be a list of at most 1,000 entries"
        seen: set = set()
        for x in xs:
            if not isinstance(x, dict) or set(x) != {"kind", "fingerprint", "reason"}:
                return "a fingerprint exception is {kind, fingerprint, reason}"
            if x["kind"] not in ("tool", "description", "server") or not is_hex64(x["fingerprint"]):
                return "a fingerprint exception names a kind (tool, description or server) and a 64 lowercase hex fingerprint"
            if not isinstance(x["reason"], str) or not 1 <= len(x["reason"]) <= 200:
                return "a fingerprint exception's reason is text of 1 to 200 characters"
            k = (x["kind"], x["fingerprint"])
            if k in seen:
                return f"the fingerprint exception {k[0]} {k[1]} is listed twice"
            seen.add(k)
    err = _rules_list_errors(doc["rules"], True, doc["version"])
    if err:
        return err
    if doc["mode"] == "watch":
        on = next((r for r in doc["rules"] if r.get("state") == "on"), None)
        if on is not None:
            return f"rule '{on['id']}': a rule set whose `mode` is \"watch\" (Calibrating) never blocks, so no rule in it is On"
    return None


def excepted_pairs(doc: Optional[dict]) -> set:
    """The ``(kind, fingerprint)`` pairs a rule set excepts from the shared list (§10.1
    ``fingerprint_exceptions``), for :func:`fingerprint_findings_in`; empty without a rule set."""
    xs = doc.get("fingerprint_exceptions") if isinstance(doc, dict) else None
    return {(x["kind"], x["fingerprint"]) for x in xs} if isinstance(xs, list) else set()


def local_rules_errors(rules: Any) -> Optional[str]:
    """The checks file's ``rules`` (§8): null, or ``{default, rules}`` with no ``limit``."""
    if rules is None:
        return None
    if not isinstance(rules, dict):
        return "rules must be null or {default, rules}"
    err = _exact(rules, ("default", "rules"), (), "rules")
    if err:
        return err
    if rules["default"] not in ("allow", "block"):
        return "rules.default must be allow or block"
    err = _rules_list_errors(rules["rules"], allow_limit=False, version=None)
    if err and "unknown field 'limit'" in err:
        return "rules may not use limit: only the witness counts calls"
    return err


def applies(rule: dict, agent: str, tool: str) -> bool:
    return (rule["tools"] is None or tool in rule["tools"]) and (rule["agents"] is None or agent in rule["agents"])


def rule_state(doc: dict, rule: dict) -> str:
    """A rule's state (§10.1, spec 1.1): as written, else from the document's mode (``calibrating``
    in watch mode, ``on`` in enforce mode). Local rules (no ``mode``) are always ``on``: the checks
    file sets the mode their entry is written in."""
    if rule.get("state") in ("calibrating", "on"):
        return rule["state"]
    return "calibrating" if doc.get("mode") == "watch" else "on"


def takes_part(doc: dict, rule: dict) -> bool:
    """Whether a rule takes part in the result (§10.3): every rule of a rule set in watch mode,
    and the On rules of one in enforce mode."""
    return doc.get("mode") == "watch" or rule_state(doc, rule) == "on"


def needed_fields(doc: Optional[dict], agent: str, tool: str) -> List[str]:
    """§10.4: the fields a call **needs**: the ``field`` of every condition of every rule that
    applies and takes part in the result, each once, in code point order."""
    if doc is None:
        return []
    return sorted(
        {c["field"] for r in doc["rules"] if applies(r, agent, tool) and takes_part(doc, r) for c in r["when"]}
    )


def sendable_fields(doc: Optional[dict], agent: str, tool: str) -> List[str]:
    """§10.4 (spec 1.1): the fields a call **can send**: the ``field`` of every condition of every
    rule that applies, whatever its state, and of each of their exceptions, in code point order."""
    if doc is None:
        return []
    out = set()
    for r in doc["rules"]:
        if applies(r, agent, tool):
            out.update(c["field"] for c in r["when"])
            out.update(x["field"] for x in r.get("exceptions", ()))
    return sorted(out)


def disclosure(doc: Optional[dict], agent: str, tool: str, disclose: Sequence[str]) -> dict:
    """§10.4: what a strict call sends of the fields the developer approved (*disclose*):
    ``sent``, the sendable fields it lists; ``missing``, the needed fields it does not list (a
    ruling then blocks with basis ``fields_missing``); ``unsent``, the fields only Calibrating
    rules or exceptions use that it does not list (nothing blocks for them)."""
    needed = needed_fields(doc, agent, tool)
    sendable = sendable_fields(doc, agent, tool)
    return {
        "sent": [p for p in sendable if p in disclose],
        "missing": [p for p in needed if p not in disclose],
        "unsent": [p for p in sendable if p not in disclose and p not in needed],
    }


def evaluate(
    doc: dict,
    agent: str,
    tool: str,
    lookup: Callable[[str], Any],
    count: Optional[Callable[[dict], int]] = None,
    available: Optional[Callable[[str], bool]] = None,
) -> dict:
    """§10.3: ``{result, basis, matched, would_block, not_calibrated, excepted}``, the
    enforce-mode result. *doc* has ``rules`` and ``default`` (and ``mode`` for a rule set).
    *count* is the witness's count of its earlier allow rulings for a limit rule; without it (a
    client) limit rules are skipped. *available* says whether a pointer can be read at all: a
    client holds the whole call; the witness only the pointers it was sent."""

    def avail(p: str) -> bool:
        return available is None or available(p)

    errors: List[str] = []
    blocks: List[str] = []
    allows: List[str] = []
    would_block: List[str] = []
    not_calibrated: List[str] = []
    excepted: List[str] = []
    for r in doc["rules"]:
        if not applies(r, agent, tool):
            continue
        if "limit" in r and count is None:
            continue
        part = takes_part(doc, r)
        if not part and any(not avail(c["field"]) for c in r["when"]):
            not_calibrated.append(r["id"])
            continue
        status: Any = True
        for c in r["when"]:
            status = condition(c, lookup(c["field"]))
            if status is not True:
                break
        if status == "error":
            (errors if part else would_block).append(r["id"])
            continue
        if status is not True:
            continue
        # An exception applies only to a field that is available and present (§10.1).
        hit = False
        for x in r.get("exceptions", ()):
            if avail(x["field"]):
                v = lookup(x["field"])
                if v is not ABSENT and _jcs_eq(v, x["value"]):
                    hit = True
                    break
        if hit:
            if part:
                excepted.append(r["id"])
            continue
        if "limit" in r and count is not None and count(r["limit"]) < r["limit"]["calls"]:
            continue
        if part:
            (blocks if r["action"] == "block" else allows).append(r["id"])
        elif r["action"] == "block":
            would_block.append(r["id"])
    extra = {"would_block": would_block[:16], "not_calibrated": not_calibrated[:16], "excepted": excepted[:16]}
    if errors:
        return {"result": "block", "basis": "error", "matched": errors[:16], **extra}
    if blocks:
        return {"result": "block", "basis": "rule", "matched": blocks[:16], **extra}
    if allows:
        return {"result": "allow", "basis": "rule", "matched": allows[:16], **extra}
    return {"result": doc["default"], "basis": "default", "matched": [], **extra}


def apply_mode(result: str, mode: str) -> dict:
    """A check result as an entry writes it in *mode* (§2.8): watch mode never blocks."""
    if mode == "watch":
        return {"result": "note" if result == "block" else result, "enforce_result": result}
    return {"result": result}


def entry_mode(own: str, strict: bool, local: bool) -> str:
    """The mode of a client's ``rule`` entry (§2.8, §8): the project's rule set is ruled on by the
    witness, never by the client, so its entry is always in watch mode (a call that is not strict
    is not bound by it; a strict call waits for the witness's ruling); local rules follow the
    checks file's mode (*own*) on every call. *strict* no longer changes the mode."""
    del strict
    return own if local else "watch"


def client_rule_entry(doc: dict, mode: str, set_id: str, agent: str, tool: str, args: Any) -> dict:
    """The client's ``rule`` entry for one rule set (§2.8): §10.3 as a client over the call's arguments, in *mode*."""
    res = evaluate(doc, agent, tool, lambda p: resolve(args, p))
    e = {"check": "rule", **apply_mode(res["result"], mode), "mode": mode, "set": set_id, "matched": res["matched"]}
    # Spec 1.1: present only when not empty, so an entry without them reads as before.
    if res["would_block"]:
        e["would_block"] = res["would_block"]
    if res["excepted"]:
        e["excepted"] = res["excepted"]
    return e


# --- §10.2 client acceptance of a fetched version -----------------------------------------


def key_active(k: dict, at: Any) -> bool:
    """Whether service key *k* is active at time *at*: ``valid_from <= at < valid_to`` (a None
    ``valid_to`` is open)."""
    return _key_active(k, at)


def _key_active(k: dict, at: str) -> bool:
    try:
        return _cmp_time(k["valid_from"], at) <= 0 and (k.get("valid_to") is None or _cmp_time(at, k["valid_to"]) < 0)
    except (ValueError, TypeError, KeyError):
        return False


def key_problem(
    service_keys: List[dict], revoked: Any, key_id: Any, at: Any, domain: str, h: str, sig: Any
) -> Optional[str]:
    """How one service key signature is judged (spec §5), in the order every implementation uses:
    ``unknown_key``, ``revoked``, ``not_active`` (outside valid_from..valid_to at *at*),
    ``signature``; None when it verifies. A revoked key never verifies, whatever its window."""
    key = next((k for k in service_keys if isinstance(k, dict) and k.get("key_id") == key_id), None)
    if key is None:
        return "unknown_key"
    if key.get("key_id") in (revoked or ()):
        return "revoked"
    if not _key_active(key, at):
        return "not_active"
    try:
        ok = isinstance(sig, str) and verify_sig(key.get("public_key", ""), domain, h, sig)
    except (ValueError, TypeError):
        ok = False
    return None if ok else "signature"


def ruling_key_problem(receipt: Any, service_keys: List[dict], revoked: Any = ()) -> Optional[str]:
    """A receipt's ruling signature (§3.5) as the tool-call checks runtime takes it: ``key_problem``
    for the receipt's service key at the ruling's server_time."""
    g = receipt.get("ruling") if isinstance(receipt, dict) else None
    if not isinstance(g, dict):
        return "signature"
    return key_problem(
        service_keys,
        revoked,
        receipt.get("service_key_id"),
        g.get("server_time"),
        "ruling",
        hash_json(g),
        receipt.get("ruling_sig"),
    )


def accept_rules(
    held: Optional[dict], item: Any, service_keys: List[dict], project: str, env: str, revoked: Any = ()
) -> Optional[str]:
    """The name of the first §10.2 step that refuses *item* (``{rules, sig, service_key_id}``),
    or None when the client accepts it. *held* is the document the client holds; *revoked* the
    revoked service key ids (§5): a rule set one of them signed is refused at the signature step."""
    doc = item.get("rules") if isinstance(item, dict) else None
    if rule_set_errors(doc):
        return "schema"
    if doc["project"] != project or doc["env"] != env:
        return "project"
    if key_problem(
        service_keys, revoked, item.get("service_key_id"), doc["issued"], "rules", hash_json(doc), item.get("sig")
    ):
        return "signature"
    if held is None:
        return None
    if doc["set"] != held["set"]:
        return "set"
    if doc["version"] < held["version"]:
        return "older"
    if doc["version"] == held["version"]:
        return None if hash_json(doc) == hash_json(held) else "conflict"
    if _cmp_time(doc["issued"], held["issued"]) < 0:
        return "issued"
    if doc["version"] == held["version"] + 1 and doc["prev"] != hash_json(held):
        return "prev"
    return None


# --- the shared fingerprint list (§11.2) --------------------------------------------------


def _entry_key(e: dict) -> Tuple[str, str]:
    return (e["kind"], e["fingerprint"])


def _entries_ok(entries: Any) -> bool:
    if not isinstance(entries, list) or len(entries) > 1_000_000:
        return False
    keys = []
    for e in entries:
        if (
            not isinstance(e, dict)
            or set(e) != {"kind", "fingerprint"}
            or e["kind"] not in ("tool", "description", "server")
            or not is_hex64(e["fingerprint"])
        ):
            return False
        keys.append(_entry_key(e))
    return keys == sorted(set(keys))


def state_hash(entries: List[dict]) -> str:
    return hash_json(sorted(entries, key=_entry_key))


def empty_list() -> dict:
    return {"seq": 0, "last": None, "entries": []}


def apply_list(held: dict, item: Any, service_keys: List[dict], revoked: Any = ()) -> Tuple[dict, Optional[str]]:
    """One served item ``{list, sig, service_key_id}`` applied to *held* ``{seq, last, entries}``
    (§11.2): ``(new_held, None)``, or ``(held, refusal)`` with the refusal's name
    (``signature``, ``state``, ``older``, ``gap``, ``prev``, ``invalid``)."""
    obj = item.get("list") if isinstance(item, dict) else None
    if not isinstance(obj, dict):
        return held, "invalid"
    try:
        signed = (
            key_problem(
                service_keys,
                revoked,
                item.get("service_key_id"),
                obj.get("issued"),
                "fingerprints",
                hash_json(obj),
                item.get("sig"),
            )
            is None
        )
    except (ValueError, TypeError):
        signed = False
    if not signed:
        return held, "signature"
    if obj.get("format") != LIST_FORMAT or obj.get("list") != "shared" or not is_safe_int(obj.get("seq")):
        return held, "invalid"
    if obj.get("type") == "snapshot":
        if not _entries_ok(obj.get("entries")):
            return held, "invalid"
        if state_hash(obj["entries"]) != obj.get("state_hash"):
            return held, "state"
        if obj["seq"] < held["seq"]:
            return held, "older"
        return {"seq": obj["seq"], "last": obj.get("last"), "entries": list(obj["entries"])}, None
    if obj.get("type") != "update":
        return held, "invalid"
    if obj["seq"] <= held["seq"]:
        return held, "older"
    if obj["seq"] != held["seq"] + 1:
        return held, "gap"
    if obj.get("prev") != held["last"]:
        return held, "prev"
    if not (_entries_ok(obj.get("add")) and _entries_ok(obj.get("remove"))):
        return held, "invalid"
    have = {_entry_key(e) for e in held["entries"]}
    if any(_entry_key(e) in have for e in obj["add"]) or any(_entry_key(e) not in have for e in obj["remove"]):
        return held, "invalid"
    rm = {_entry_key(e) for e in obj["remove"]}
    entries = sorted([e for e in held["entries"] if _entry_key(e) not in rm] + list(obj["add"]), key=_entry_key)
    if state_hash(entries) != obj.get("state_hash"):
        return held, "state"
    return {"seq": obj["seq"], "last": hash_json(obj), "entries": entries}, None


def held_list_errors(doc: Any) -> Optional[str]:
    """``checks/fingerprints.json`` as kept (§8): entries in order, no repeats."""
    if (
        not isinstance(doc, dict)
        or set(doc) != {"seq", "last", "entries"}
        or not is_safe_int(doc["seq"])
        or doc["seq"] < 0
    ):
        return "not {seq, last, entries}"
    if not (doc["last"] is None or is_hex64(doc["last"])) or not _entries_ok(doc["entries"]):
        return "entries out of order or repeated"
    return None


# --- tool fingerprints (§11.1) ------------------------------------------------------------

_SCHEMA_MAPS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
_SCHEMA_LISTS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_ONE = (
    "items",
    "additionalItems",
    "additionalProperties",
    "unevaluatedItems",
    "unevaluatedProperties",
    "contains",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
)


def strip_schema(s: Any) -> Any:
    """§11.1 ``strip``: without ``description`` and ``title`` members, here and in every schema inside."""
    if not isinstance(s, dict):
        return s
    out = {}
    for k, v in s.items():
        if k in ("description", "title"):
            continue
        if k in _SCHEMA_MAPS and isinstance(v, dict):
            out[k] = {name: strip_schema(x) for name, x in v.items()}
        elif k in _SCHEMA_LISTS and isinstance(v, list):
            out[k] = [strip_schema(x) for x in v]
        elif k in _SCHEMA_ONE:
            out[k] = [strip_schema(x) for x in v] if isinstance(v, list) else strip_schema(v)
        else:
            out[k] = v
    return out


def tool_fingerprints(name: str, description: str, input_schema: Any, server_info: Optional[dict]) -> dict:
    """``{tool, description, schema, server}`` (§11.1); ``server`` is null without an MCP server."""
    description = description or ""
    return {
        "tool": hash_json({"name": name, "description": description, "input_schema": input_schema}),
        "description": sha256_hex(description.encode("utf-8")),
        "schema": hash_json(strip_schema(input_schema)),
        "server": None
        if server_info is None
        else hash_json({"name": server_info.get("name"), "version": server_info.get("version")}),
    }


# --- checks in an envelope (§2.8) ---------------------------------------------------------


def combined(results: Iterable[dict]) -> str:
    return max((r["result"] for r in results), key=lambda x: RESULT_ORDER[x], default="allow")


def _entry_errors(e: Any, kind: str) -> Optional[str]:
    if not isinstance(e, dict) or e.get("check") not in CHECK_IDS:
        return "an entry names an unknown check"
    c = e["check"]
    if kind == "decision" and c not in DECISION_CHECKS:
        return f"the check '{c}' is not a check of a decision"
    if kind == "outcome" and c not in OUTCOME_CHECKS:
        return f"the check '{c}' is not a check of an outcome"
    keys = {"check", "result", "mode"}
    if e.get("mode") == "watch":
        keys.add("enforce_result")
    keys |= {"set", "matched"} if c == "rule" else {"found"}
    if c == "rule":  # spec 1.1: written only when not empty
        keys |= {k for k in ("would_block", "excepted") if k in e}
    if set(e) != keys:
        return f"the '{c}' entry has the wrong keys"
    if e["mode"] not in ("watch", "enforce") or e["result"] not in RESULT_ORDER:
        return 'an entry\'s `mode` is "watch" (Calibrating) or "enforce" (On) and its `result` allow, note or block'
    if e["mode"] == "watch":
        if e["enforce_result"] not in RESULT_ORDER or e["result"] != (
            "note" if e["enforce_result"] == "block" else e["enforce_result"]
        ):
            return 'when an entry\'s `mode` is "watch" (Calibrating), its result equals its enforce_result, except that block is written as note'
    if kind == "outcome" and c == "hidden_instruction" and "block" in (e["result"], e.get("enforce_result")):
        return "hidden_instruction never blocks on a result"
    if (
        c == "hidden_instruction"
        and isinstance(e.get("found"), list)
        and POSSIBLE in e["found"]
        and (e["result"] != "note" or (e["mode"] == "watch" and e.get("enforce_result") != "note"))
    ):
        return "a hidden_instruction entry with possible_hidden_instruction (arguments or a result) is a note, never a block"
    if c == "rule":
        if not (e["set"] == "local" or (isinstance(e["set"], str) and SET_RE.match(e["set"]))):
            return "a rule entry's set is local or the rule set's id"
        if (
            not isinstance(e["matched"], list)
            or len(e["matched"]) > 16
            or not all(isinstance(m, str) and RULE_ID_RE.match(m) for m in e["matched"])
        ):
            return "a rule entry's matched is a list of at most 16 rule ids"
        err = _id_lists_errors(e, ("would_block", "excepted"), "a rule entry")
        if err:
            return err
    else:
        f = e["found"]
        if (
            not isinstance(f, list)
            or len(f) > 8
            or len(set(map(str, f))) != len(f)
            or not all(x in FOUND[c] for x in f)
        ):
            return f"the '{c}' entry has an unknown or repeated found code"
    return None


def checks_errors(env: dict) -> Optional[str]:
    """The §2.8 rules for an envelope's ``checks``; None when valid or absent."""
    if "checks" not in env:
        return None
    ch = env["checks"]
    if (
        env.get("kind") not in ("decision", "outcome")
        or not isinstance(env.get("name"), str)
        or env["name"].startswith("signafaide.")
    ):
        return "checks is allowed only on a decision or outcome whose name does not start with 'signafaide.'"
    if not isinstance(ch, dict):
        return "checks must be an object"
    if env["kind"] == "outcome":
        if set(ch) != {"ran", "ruling", "results", "result"}:
            return "the checks of an outcome are {ran, ruling, results, result}"
        if not isinstance(ch["ran"], bool) or ch["ruling"] not in ("allow", "block", "none", "not_asked"):
            return "checks.ran is a boolean and checks.ruling allow, block, none or not_asked"
        if ch["ran"] and ch["ruling"] == "block":
            return "checks.ran is true but checks.ruling is block: a call ruled block never runs"
        if not ch["ran"] and ch["results"]:
            return "checks.results must be empty when the tool did not run"
    else:
        keys = {
            "results",
            "result",
            "rules",
            "fingerprints",
            "tool",
            "strict",
            "fail",
            "disclosed",
            "disclosed_hash",
            "call_id",
        }
        if set(ch) != keys:
            extra = sorted(set(ch) - keys)
            return (
                f"the checks of a decision have the unknown key '{extra[0]}'"
                if extra
                else "the checks of a decision lack a key"
            )
        t = ch["tool"]
        if (
            not isinstance(t, dict)
            or set(t) != {"tool", "description", "schema", "server"}
            or not all(is_hex64(t[k]) for k in ("tool", "description", "schema"))
            or not (t["server"] is None or is_hex64(t["server"]))
        ):
            return "checks.tool holds 64-hex fingerprints (server may be null)"
        rs = ch["rules"]
        if not isinstance(rs, list) or len(rs) > 2:
            return "checks.rules must be a list of at most 2 entries"
        sets = []
        for r in rs:
            if not isinstance(r, dict) or set(r) != {"set", "version", "hash"} or not is_hex64(r["hash"]):
                return "each checks.rules entry is {set, version, hash}"
            if r["set"] == "local":
                if r["version"] is not None:
                    return "the local rules' version is null"
            elif not (
                isinstance(r["set"], str) and SET_RE.match(r["set"]) and is_safe_int(r["version"]) and r["version"] >= 1
            ):
                return "checks.rules names the project's rule set (rs_..., version 1 or above) or the local rules"
            sets.append("local" if r["set"] == "local" else "project")
        if len(sets) != len(set(sets)):
            return "checks.rules holds at most one entry for the project's rule set and one for the local rules"
        if not (ch["fingerprints"] is None or (is_safe_int(ch["fingerprints"]) and ch["fingerprints"] >= 0)):
            return "checks.fingerprints must be null or the seq of the shared list"
        if not isinstance(ch["strict"], bool):
            return "checks.strict must be true (Protected) or false (Not protected)"
        if not ((ch["strict"] and ch["fail"] in ("open", "closed")) or (not ch["strict"] and ch["fail"] is None)):
            return 'checks.fail is "open" (Let it run) or "closed" (Stop) when checks.strict is true (Protected), and null otherwise'
        d = ch["disclosed"]
        if not isinstance(d, list) or len(d) > 64 or not all(pointer_ok(p) for p in d) or d != sorted(set(d)):
            return "checks.disclosed holds at most 64 JSON Pointers, in code point order, without repeats"
        if d and not ch["strict"]:
            return "checks.disclosed must be empty on a call that is not protected"
        if bool(d) != (ch["disclosed_hash"] is not None) or (d and not is_hex64(ch["disclosed_hash"])):
            return "checks.disclosed_hash is 64 hex exactly when checks.disclosed is not empty"
        cid = ch["call_id"]
        if not (cid is None or is_safe_int(cid) or (isinstance(cid, str) and 1 <= len(cid) <= 128)):
            return "checks.call_id must be null, a string of 1 to 128 characters, or an integer within ±(2^53−1)"
    res = ch["results"]
    if not isinstance(res, list) or len(res) > 32:
        return "checks.results must be a list of at most 32 entries"
    seen = set()
    for e in res:
        err = _entry_errors(e, env["kind"])
        if err:
            return err
        k = (e["check"], e.get("set"))
        if k in seen:
            return f"the '{e['check']}' check appears twice (rule appears once per rule set)"
        seen.add(k)
    if ch["result"] != combined(res):
        return f"checks.result must be the strongest result among the entries ({combined(res)})"
    return None


def asks_for_ruling(checks: Any) -> bool:
    """A decision asks the witness for a ruling: strict, and not blocked on the client (§3.5)."""
    return isinstance(checks, dict) and checks.get("strict") is True and checks.get("result") != "block"


def disclosed_hash(values: Any, salt: str) -> str:
    """``sha256(disclosed_salt || JCS(disclosed))`` (§2.3)."""
    if not isinstance(salt, str) or not SALT_RE.match(salt):
        raise ValueError("disclosed_salt must be 32 lowercase hex characters")
    return sha256_hex(bytes.fromhex(salt) + canonicalize(values))


def disclosed_errors(rec: dict, content: Any = None) -> Optional[str]:
    """Check 12 for a record's disclosed values (§2.3, §7), when it carries them: with their own
    salt, hashing to ``checks.disclosed_hash``; with *content* (matched), the call's input held them."""
    d, salt = rec.get("disclosed"), rec.get("disclosed_salt")
    if d is None and salt is None:
        return None
    if d is None or salt is None:
        return "disclosed and disclosed_salt come together"
    ch = rec["envelope"].get("checks")
    if not isinstance(ch, dict) or not isinstance(ch.get("disclosed_hash"), str):
        return "disclosed values on a record whose checks.disclosed_hash is null"
    if not isinstance(d, dict):
        return "disclosed must be an object of {pointer: value}"
    extra = sorted(k for k in d if k not in ch.get("disclosed", []))
    if extra:
        return f"disclosed holds {extra[0]}, which checks.disclosed does not list"
    try:
        h = disclosed_hash(d, salt)
    except (ValueError, TypeError) as e:
        return str(e)
    if h != ch["disclosed_hash"]:
        return f"disclosed values hash to {h}, checks.disclosed_hash says {ch['disclosed_hash']}"
    if isinstance(content, dict) and isinstance(content.get("input"), dict):
        for p in ch.get("disclosed", []):
            field = resolve(content["input"], p)
            if p in d:
                if field is ABSENT or not _jcs_eq(d[p], field):
                    return f"the disclosed value at {p} differs from the call's input"
            elif field is not ABSENT:
                return f"{p} was left out of the disclosed values as absent, but the call's input holds it"
    return None


def _id_lists_errors(o: dict, keys: Sequence[str], what: str) -> Optional[str]:
    """Spec 1.1: the optional lists of rule ids of a rule entry or a ruling: each, when present,
    1 to 16 rule ids, each once; no rule in two of them or in ``matched``."""
    lists = [("matched", o.get("matched") if isinstance(o.get("matched"), list) else [])]
    for k in keys:
        if k not in o:
            continue
        lst = o[k]
        if not isinstance(lst, list) or not 1 <= len(lst) <= 16:
            return f"{what}'s {k} is a list of 1 to 16 rule ids, written only when not empty"
        if not all(isinstance(x, str) and RULE_ID_RE.match(x) for x in lst) or len(set(lst)) != len(lst):
            return f"{what}'s {k} holds rule ids, each once"
        lists.append((k, lst))
    for i, (a, x) in enumerate(lists):
        for b, y in lists[i + 1 :]:
            both = next((rid for rid in x if rid in y), None)
            if both is not None:
                return f"the rule {both} is in both {a} and {b} of {what}"
    return None


_RULING_LISTS = ("would_block", "not_calibrated", "excepted")


def ruling_errors(r: Any) -> Optional[str]:
    """Whether a ruling object follows §3.5 field by field (check 6)."""
    if not isinstance(r, dict):
        return "a ruling is an object"
    watch = r.get("mode") == "watch"
    keys = {
        "v",
        "record_hash",
        "batch_hash",
        "server_time",
        "ruling",
        "mode",
        "basis",
        "matched",
        "missing",
        "rules",
        "fingerprints",
        "reason",
    } | ({"enforce_ruling"} if watch else set())
    if set(r) != keys | {k for k in _RULING_LISTS if k in r}:
        return (
            "the ruling's fields are "
            + ", ".join(sorted(keys))
            + " (and from spec 1.1 would_block, not_calibrated and excepted when not empty)"
        )
    if r["v"] != 1 or not is_safe_int(r["v"]):
        return "the ruling's v must be 1"
    if not (is_hex64(r["record_hash"]) and is_hex64(r["batch_hash"])) or not _valid_time(r["server_time"]):
        return "the ruling's record_hash, batch_hash or server_time is invalid"
    if r["ruling"] not in ("allow", "block") or r["mode"] not in ("watch", "enforce"):
        return 'the ruling is allow or block, and its `mode` is "watch" (Calibrating) or "enforce" (On)'
    if watch:
        if r["ruling"] != "allow":
            return 'when the ruling\'s `mode` is "watch" (Calibrating) the ruling is always allow'
        if r["enforce_ruling"] not in ("allow", "block"):
            return "enforce_ruling is allow or block"
    enforce = r["enforce_ruling"] if watch else r["ruling"]
    basis = r["basis"]
    if basis not in ("rules_version", "fields_missing", "fingerprint", "error", "rule", "default"):
        return "basis is rules_version, fields_missing, fingerprint, error, rule or default"
    if basis in ("rules_version", "fields_missing", "fingerprint", "error") and enforce != "block":
        return f'basis {basis} always blocks when On (`mode` is "enforce")'
    m = r["matched"]
    if not isinstance(m, list) or len(m) > 16 or not all(isinstance(x, str) and RULE_ID_RE.match(x) for x in m):
        return "matched is a list of at most 16 rule ids"
    if (not m) == (basis in ("error", "rule")):
        return "matched names the rules exactly for basis error and rule"
    miss = r["missing"]
    if (
        not isinstance(miss, list)
        or len(miss) > 64
        or not all(pointer_ok(p) for p in miss)
        or miss != sorted(set(miss))
    ):
        return "missing is a list of at most 64 pointers in code point order"
    if (not miss) == (basis == "fields_missing"):
        return "missing lists the pointers exactly for basis fields_missing"
    rules = r["rules"]
    if rules is None:
        if watch or basis not in ("fingerprint", "default"):
            return 'without a rule set a ruling has `mode` "enforce" (On), with basis fingerprint or default'
    elif not (
        isinstance(rules, dict)
        and set(rules) == {"set", "version", "hash"}
        and isinstance(rules["set"], str)
        and SET_RE.match(rules["set"])
        and is_safe_int(rules["version"])
        and rules["version"] >= 1
        and is_hex64(rules["hash"])
    ):
        return "the ruling's rules is null or {set, version, hash}"
    if not is_safe_int(r["fingerprints"]) or r["fingerprints"] < 0:
        return "the ruling's fingerprints is the seq of the shared list"
    if not isinstance(r["reason"], str) or not 1 <= len(r["reason"]) <= 300:
        return "the ruling's reason is 1 to 300 characters"
    for k in _RULING_LISTS:
        if k not in r:
            continue
        if basis not in ("error", "rule", "default") or rules is None:
            return f"the ruling's {k} comes only from the evaluation of a rule set (basis error, rule or default)"
        if k != "excepted" and watch:
            return f'the ruling\'s {k} is about Calibrating rules of a rule set that is On (`mode` is "enforce")'
    return _id_lists_errors(r, _RULING_LISTS, "the ruling")


# --- the client's own checks (§8) ---------------------------------------------------------


def string_leaves(value: Any) -> List[str]:
    """The strings of *value*, in the order their members appear in its JCS form."""
    return [s for s, _ in labelled_leaves(value)]


def labelled_leaves(value: Any) -> List[Tuple[str, Optional[str]]]:
    """The strings of *value* in JCS order, each with the name of the member that holds it (None
    in a list or at the top)."""
    out: List[Tuple[str, Optional[str]]] = []

    def walk(v: Any, name: Optional[str]) -> None:
        if isinstance(v, str):
            out.append((v, name))
        elif isinstance(v, list):
            for x in v:
                walk(x, None)
        elif isinstance(v, dict):
            for k in sorted(v, key=lambda s: s.encode("utf-16-be")):
                walk(v[k], k)

    walk(value, None)
    return out


def _pct_decode(s: str) -> Optional[str]:
    if not re.search(r"%[0-9A-Fa-f]{2}", s):
        return None
    try:
        return urllib.parse.unquote_to_bytes(s).decode("utf-8")
    except UnicodeDecodeError:
        return None


def host_matches(host: str, pattern: str) -> bool:
    return host.endswith(pattern[1:]) if pattern.startswith("*.") else host == pattern


_URL_RE = re.compile(r"\A(https?|wss?|ftp)://", re.I)


def url_host(s: str) -> Optional[str]:
    """The host of an absolute http(s), ws(s) or ftp URL, lowercased (an IPv6 host in brackets)."""
    if not _URL_RE.match(s):
        return None
    rest = s.split("://", 1)[1]
    auth = re.split(r"[/?#\\]", rest, maxsplit=1)[0]
    hostport = auth.rsplit("@", 1)[-1]
    if hostport.startswith("["):
        end = hostport.find("]")
        return hostport[: end + 1].lower() if end > 0 else None
    return hostport.split(":", 1)[0].lower().rstrip(".")


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


_TOKEN = re.compile(r"[A-Za-z0-9_-]+")
_TOKEN_TABLE = str.maketrans({chr(i): (chr(i) if re.match(r"[A-Za-z0-9_-]", chr(i)) else " ") for i in range(128)})
#: The shortest token any format can match (``xox?-`` and 10 more).
_MIN_TOKEN = 15
_GLUE = re.compile(r"[_-]+")


def _table_format(tok: str, hosts: List[str], witness_host: Optional[str], found: set) -> None:
    if len(tok) < _MIN_TOKEN:
        return
    for fid, pat, issuers in _SECRET_RES:
        if pat.fullmatch(tok):
            iss = (witness_host,) if fid == "signafaide_key" and witness_host else issuers
            if hosts and iss and all(any(host_matches(h, p) for p in iss) for h in hosts):
                continue
            found.add(fid)
            break


_AUTH_HEADERS = {"authorization", "proxy-authorization"}


def _context_in(text: str, name: str, single: bool, found: set) -> None:
    """The secrets known by where they stand (§8 secret, ``CONTEXT_FORMATS``) in one text of an
    argument named *name*; see the TypeScript SDK's ``contextIn``."""
    t = text[: scan.PAIRS_SCAN_MAX]
    if not (single and name.lower() in _AUTH_HEADERS):
        if any(scan.is_jwt(m.group(0)) for m in scan.JWT_RE.finditer(t)):
            found.add("jwt")
        for m in scan.BEARER_RE.finditer(t) if "bearer" in t.lower() else ():
            v = m.group(1)
            if not (v.startswith("eyJ") and scan.is_jwt(v)) and scan.looks_random(v):
                found.add("bearer_token")
                break
    dump = None
    for n, v, i in scan.pairs(t):
        if i > 0 and t[i - 1] in "?&#":
            hit = scan.secret_name(n, True) and scan.looks_random(v)
        else:
            hit = scan.secret_name(n) and (
                scan.looks_random(v)
                or (scan.dump_value(v) and (dump if dump is not None else (dump := scan.is_env_dump(t))))
            )
        if hit:
            found.add("named_secret")
            return


def _formats_in(
    text: str, label: str, hosts: List[str], witness_host: Optional[str], found: set, seeds: bool = True
) -> None:
    """The block formats *text* holds (§8 secret): the table's whole tokens (unless every known
    destination is an issuing host of the format), a private key, a wallet private key (WIF, or 64
    hex digits labelled as a private key by *label* or the text before them) and a seed phrase."""
    if text.isascii():  # split in C: every character outside the token class becomes a space
        toks = [w for w in text.translate(_TOKEN_TABLE).split() if len(w) >= _MIN_TOKEN]
    else:
        toks = [w for w in _TOKEN.findall(text) if len(w) >= _MIN_TOKEN]
        # Look-alike letters of the larger table, only in tokens that mix scripts (§8 secret).
        for tok in scan.lookalike_tokens(text):
            _table_format(tok, hosts, witness_host, found)
    for tok in toks:
        n = len(found)
        _table_format(tok, hosts, witness_host, found)
        if len(found) == n and ("_" in tok or "-" in tok):
            # A key glued to a name by "_" or "-" (aws_key_AKIA..., id-AKIA...): its parts are tokens too.
            for part in _GLUE.split(tok):
                if len(part) >= _MIN_TOKEN:
                    _table_format(part, hosts, witness_host, found)
        if len(tok) >= 51 and scan.is_wif(tok):
            found.add("wallet_private_key")
        elif len(tok) >= 64 and any(
            scan.is_hex_key(tok, label + " " + text[max(0, m.start() - 32) : m.start()])
            for m in re.finditer(r"(?<![A-Za-z0-9_-])" + re.escape(tok) + r"(?![A-Za-z0-9_-])", text)
        ):
            found.add("wallet_private_key")
    if PRIVATE_KEY_RE.search(text):
        found.add("private_key")
    if seeds and scan.has_seed_phrase(text):
        found.add("seed_phrase")


def secret_findings(args: Any, witness_host: Optional[str] = None, result: bool = False) -> dict:
    """The ``secret`` check (§8) on a call's arguments (*result* False) or on a tool's result
    (*result* True): ``{result, found}`` in enforce mode. Every string is normalised first; the
    texts read are each string, its percent-decoding, the concatenation of all and its
    percent-decoding, and what each of those decodes to (hex, base64, nested). A result has no
    destination, and is read for block formats only."""
    leaves = [(scan.normalise(s), name or "") for s, name in labelled_leaves(args)]
    hosts = [] if result else [h for h in (url_host(s) for s, _ in leaves) if h is not None]
    found: set = set()
    budget = [scan.DECODE_BUDGET]
    single = len(set(hosts)) == 1
    # Each string, its percent-decoding (twice: double encoding), and what they decode to: every
    # format; on arguments also the secrets known by where they stand, and the obfuscated tokens.
    for s, name in leaves:
        texts = [s]
        d = _pct_decode(s)
        if d is not None:
            texts.append(d)
            d2 = _pct_decode(d)
            if d2 is not None:
                texts.append(d2)
        for t in texts:
            _formats_in(t, name, hosts, witness_host, found)
            if not result:
                _context_in(t, name, single, found)
            for x in scan.decodings(t, budget):
                _formats_in(x, name, hosts, witness_host, found)
                if not result:
                    _context_in(x, name, single, found)
        if not result and scan._utf16_len(s) <= scan.OBFUSCATION_MAX:
            if scan.may_hold_reversed(s):
                _formats_in(s[::-1], "", hosts, witness_host, found, seeds=False)
            compact = scan.compact(s)
            if compact != s and scan.holds_prefix(compact):
                _formats_in(compact, "", hosts, witness_host, found, seeds=False)
        # A value named as a secret, as an argument's member: with a single destination it is how a
        # client signs in to that service, and not a finding.
        if not result and not single and scan.secret_name(name) and scan.looks_random(s):
            found.add("named_secret")
    # Short members of one object joined, in any order: a token split across members.
    if not result:
        for j in scan.member_joins(args):
            _formats_in(j, "", hosts, witness_host, found, seeds=False)
    # The concatenation of all, and its percent-decoding: a token or key split across strings.
    if len(leaves) > 1:
        joined = "".join(x for x, _ in leaves)
        d = _pct_decode(joined)
        for t in [joined] if d is None else [joined, d]:
            _formats_in(t, "", hosts, witness_host, found, seeds=False)
    if found:
        return {"result": "block", "found": sorted(found)[:8]}
    if result:
        return {"result": "allow", "found": []}
    notes: set = set()
    for s, _ in leaves:
        d = _pct_decode(s)
        for t in [s] if d is None else [s, d]:
            if scan.has_card_number(t):
                notes.add("card_number")
            for tok in _TOKEN.findall(t):
                if len(tok) >= 26 and scan.is_wallet_address(tok):
                    notes.add("wallet_address")
            for run in re.findall(r"[A-Za-z0-9_+/=-]+", t):
                if len(run) < 32 or "high_entropy" in notes or _entropy(run) < 4.5:
                    continue
                # A run that holds a whole format match or a wallet address is that, not random.
                if any(
                    (len(tok) >= _MIN_TOKEN and any(p.fullmatch(tok) for _, p, _ in _SECRET_RES))
                    or (len(tok) >= 26 and scan.is_wallet_address(tok))
                    for tok in _TOKEN.findall(run)
                ):
                    continue
                notes.add("high_entropy")
    return {"result": "note" if notes else "allow", "found": sorted(notes)}


def _whatwg_ipv4(host: str) -> Any:
    """The IPv4 address a WHATWG URL parser reads *host* as; None for a name; ``"failure"`` when invalid."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts = parts[:-1]
    last = parts[-1]
    if not (re.fullmatch(r"[0-9]+", last) or re.fullmatch(r"0[xX][0-9A-Fa-f]*", last)):
        return None
    if len(parts) > 4:
        return "failure"
    nums = []
    for p in parts:
        if re.fullmatch(r"0[xX][0-9A-Fa-f]*", p):
            nums.append(int(p[2:] or "0", 16))
        elif len(p) > 1 and p.startswith("0") and re.fullmatch(r"[0-7]+", p):
            nums.append(int(p, 8))
        elif re.fullmatch(r"[0-9]+", p):
            nums.append(int(p, 10))
        else:
            return "failure"
    if any(x > 255 for x in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return "failure"
    v = nums[-1]
    for i, x in enumerate(nums[:-1]):
        v += x * 256 ** (3 - i)
    return ipaddress.IPv4Address(v)


_METADATA = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata",
}
_V4 = [
    ("0.0.0.0/8", "unspecified"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "shared"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link_local"),
    ("172.16.0.0/12", "private"),
    ("192.168.0.0/16", "private"),
]
_V6 = [("::/128", "unspecified"), ("::1/128", "loopback"), ("fc00::/7", "unique_local"), ("fe80::/10", "link_local")]


def _classify_ip(ip: Any, allow_cidrs: Sequence[str]) -> Optional[str]:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for c in allow_cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version == ip.version and ip in net:
            return None
    if str(ip) in _METADATA:
        return "metadata"
    for net, code in _V4 if ip.version == 4 else _V6:
        if ip in ipaddress.ip_network(net):
            return code
    return None


def classify_host(
    host: str, allow_hosts: Sequence[str] = (), allow_cidrs: Sequence[str] = (), resolve_names: bool = False
) -> Optional[str]:
    """The ``address`` finding for one host, or None for a public or allowlisted host."""
    if any(host_matches(host, p) for p in allow_hosts):
        return None
    ip: Any = None
    if host.startswith("[") and host.endswith("]"):
        try:
            ip = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None
    else:
        v4 = _whatwg_ipv4(host)
        if v4 == "failure":
            return None
        ip = v4
    if ip is not None:
        return _classify_ip(ip, allow_cidrs)
    if host in _METADATA:
        return "metadata"
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    if host.endswith(".internal") or host.endswith(".local"):
        return "internal_name"
    if resolve_names and host:
        try:
            infos = socket.getaddrinfo(host, None)
        except (OSError, UnicodeError):
            return None
        for info in infos:
            try:
                code = _classify_ip(ipaddress.ip_address(info[4][0].split("%", 1)[0]), allow_cidrs)
            except ValueError:
                continue
            if code:
                return code
    return None


def _bare_address(s: str) -> Optional[str]:
    if re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", s):
        try:
            ipaddress.IPv4Address(s)
            return s
        except ValueError:
            return None
    inner = s[1:-1] if s.startswith("[") and s.endswith("]") else s
    if ":" not in inner:
        return None
    try:
        ipaddress.IPv6Address(inner)
        return "[" + inner + "]"
    except ValueError:
        return None


def address_findings(
    args: Any, allow_hosts: Sequence[str] = (), allow_cidrs: Sequence[str] = (), resolve_names: bool = False
) -> dict:
    """The ``address`` check (§8) on a call's arguments: ``{result, found}`` in enforce mode."""
    found: List[str] = []
    for raw in string_leaves(args):
        s = scan.normalise(raw)
        h = url_host(s)
        if h is None:
            h = _bare_address(s)
            if h is None:
                continue
        code = classify_host(h, allow_hosts, allow_cidrs, resolve_names)
        # A host that reads as a local or metadata name once look-alike letters are mapped (§8 address).
        if code is None:
            like = scan.host_lookalike(h)
            if like is not None and not any(host_matches(h, p) for p in allow_hosts):
                code = classify_host(like, allow_hosts, allow_cidrs)
        if code and code not in found:
            found.append(code)
    return {"result": "block" if found else "allow", "found": sorted(found)}


def _instruction_found_in(strings: Iterable[str]) -> List[str]:
    """``invisible_characters`` and ``instruction_phrase`` in *strings*; an instruction phrase is
    also looked for in what each string decodes to (hex, base64, nested; spec 1.1), within one ``DECODE_BUDGET`` for all of them."""
    found: set = set()
    budget = [scan.DECODE_BUDGET]
    for s in strings:
        if "invisible_characters" not in found and scan.has_invisible(s):
            found.add("invisible_characters")
        if "instruction_phrase" not in found and (
            scan.has_instruction(s) or any(scan.has_instruction(x) for x in scan.decodings(scan.normalise(s), budget))
        ):
            found.add("instruction_phrase")
        if len(found) == 2:
            break
    return sorted(found)


#: A short name-like string (most member names, types, enum values): no pattern, encoded run or
#: invisible character fits in it, so the definition check skips it (only the time changes).
_INERT = re.compile(r"[A-Za-z0-9_.-]{0,15}\Z")


def _instruction_found(value: Any) -> List[str]:
    return _instruction_found_in(string_leaves(value))


#: How deep a tool definition is read (nested objects and lists), and how much text (UTF-16 code
#: units of strings and member names) at most (§8 hidden_instruction, spec 1.1).
#: A definition past either cannot be read in full: ``encoded_content``.
DEFINITION_DEPTH_MAX = 64
DEFINITION_TEXT_MAX = 1 << 20


def definition_leaves(value: Any) -> Tuple[List[Tuple[str, Optional[str]]], bool]:
    """Every string of a definition and every member name, at any depth (schemas' ``properties``,
    ``$defs``, ``anyOf``, ``items``, ``default``, ``examples``, ``enum``, ...), in JCS order, each
    string with the name of the member that holds it (None for a member name, in a list or at the
    top); and whether the definition is deeper or longer than the bounds (the walk stopped there)."""
    leaves: List[Tuple[str, Optional[str]]] = []
    state = {"left": DEFINITION_TEXT_MAX, "over": False}

    def take(s: str, name: Optional[str]) -> None:
        n = scan._utf16_len(s)
        if n > state["left"]:
            state["over"] = True
            return
        state["left"] -= n
        leaves.append((s, name))

    def walk(v: Any, name: Optional[str], depth: int) -> None:
        if state["over"]:
            return
        if isinstance(v, str):
            take(v, name)
        elif isinstance(v, (list, dict)):
            if depth >= DEFINITION_DEPTH_MAX:
                state["over"] = True
                return
            if isinstance(v, list):
                for x in v:
                    walk(x, None, depth + 1)
            else:
                for k in sorted(v, key=lambda s: s.encode("utf-16-be")):
                    take(k, None)
                    walk(v[k], k, depth + 1)

    walk(value, None, 0)
    return leaves, state["over"]


#: The found code that marks a hidden instruction in what an agent writes (arguments) or a tool
#: returns (a result): always a note, beside the codes that say what was found (§2.8).
POSSIBLE = "possible_hidden_instruction"


def hidden_findings(result: Any) -> dict:
    """The ``hidden_instruction`` check (§8) on a call's result: ``{result, found}``; a note, never
    ``block``, with ``possible_hidden_instruction`` beside what was found."""
    found = _instruction_found(result)
    return {"result": "note", "found": sorted(found + [POSSIBLE])} if found else {"result": "allow", "found": []}


def argument_findings(args: Any) -> dict:
    """The ``hidden_instruction`` check (§8) on a call's arguments: a note, never ``block``."""
    return hidden_findings(args)


def call_notes(tool: str, where: str, findings: dict) -> List[dict]:
    """The notes of one ``hidden_instruction`` finding (§8 notes): none, or one
    ``{note: "possible_hidden_instruction", in: "arguments" | "result", tool, found}``."""
    if POSSIBLE not in findings["found"]:
        return []
    return [{"note": POSSIBLE, "in": where, "tool": tool, "found": [f for f in findings["found"] if f != POSSIBLE]}]


def decision_instruction_findings(definition: Optional[dict], args: dict) -> dict:
    """The decision's ``hidden_instruction`` entry (§8): the definition's findings block; without
    them, the arguments' are a note with ``possible_hidden_instruction``."""
    if definition is not None and definition["result"] == "block":
        return definition
    return args


def definition_findings(
    definition: Any, self_name: Optional[str] = None, others: Sequence[str] = (), approved: Sequence[str] = ()
) -> dict:
    """The ``hidden_instruction`` check (§8) on what the agent is shown of a tool or a server: every
    string of a tool's definition (name, title, description, schemas, annotations, ``_meta``, any
    other member), or a server's ``instructions``. Besides the instruction phrases and invisible
    characters: ``encoded_content`` and ``tool_shadowing``. ``{result, found}`` in enforce mode:
    ``block``. *self_name* and *others*: the tool's name and the other tools listed with it;
    *approved*: the tools approved earlier for the agent and the server. ``encoded_content`` also
    for a definition too deep or too long to read in full; ``look_alike_name`` for a name that
    passes for another tool's, or mixes scripts."""
    leaves, over = definition_leaves(definition)
    leaves = [(s, n) for s, n in leaves if not _INERT.match(s)]
    found = set(_instruction_found_in(s for s, _ in leaves))
    if over:
        found.add("encoded_content")
    budget = [scan.DECODE_BUDGET]
    me = (
        self_name
        if self_name is not None
        else (
            definition.get("name") if isinstance(definition, dict) and isinstance(definition.get("name"), str) else ""
        )
    )
    if scan.look_alike_name(me or "", others, approved):
        found.add("look_alike_name")
    for raw, name in leaves:
        if "encoded_content" not in found and scan.has_encoded_content(scan.normalise(raw), name, budget):
            found.add("encoded_content")
        if "tool_shadowing" not in found and scan.has_shadowing(raw, me, others):
            found.add("tool_shadowing")
        if "encoded_content" in found and "tool_shadowing" in found:
            break
    out = sorted(found)
    return {"result": "block" if out else "allow", "found": out}


def changed_tool_findings(fps: dict, approved: Optional[dict]) -> dict:
    """The ``changed_tool`` check (§8): *approved* is ``{description, schema}`` for the tool, or
    None when a rule set's ``approved`` does not list it."""
    if approved is None:
        return {"result": "block", "found": ["not_approved"]}
    if fps["schema"] != approved.get("schema"):
        found = ["schema_changed"] + (
            ["description_changed"] if fps["description"] != approved.get("description") else []
        )
        return {"result": "block", "found": sorted(found)}
    if fps["description"] != approved.get("description"):
        return {"result": "note", "found": ["description_changed"]}
    return {"result": "allow", "found": []}


def listed_pairs(entries: Iterable[dict]) -> set:
    """The ``(kind, fingerprint)`` pairs of a list, for :func:`fingerprint_findings_in`."""
    return {(e["kind"], e["fingerprint"]) for e in entries}


def fingerprint_findings(fps: dict, entries: Iterable[dict], exceptions: Iterable[dict] = ()) -> dict:
    """The ``fingerprint`` check (§8): each of the tool's fingerprints on the shared list with its
    kind, except those the held rule set excepts (§10.1 ``fingerprint_exceptions``)."""
    return fingerprint_findings_in(fps, listed_pairs(entries), listed_pairs(exceptions))


def fingerprint_findings_in(fps: dict, listed: set, excepted: Optional[set] = None) -> dict:
    found = [
        k
        for k in ("tool", "description", "server")
        if fps.get(k) and (k, fps[k]) in listed and (k, fps[k]) not in (excepted or ())
    ]
    return {"result": "block" if found else "allow", "found": sorted(found)}


def entry(check: str, findings: dict, mode: str) -> dict:
    """A results entry (§2.8) for one of the client's own checks."""
    return {"check": check, **apply_mode(findings["result"], mode), "mode": mode, "found": findings["found"]}


# --- the checks file (§8) ----------------------------------------------------------------


def checks_file_errors(doc: Any) -> Optional[str]:
    """The first problem with a checks file, naming the key; None when valid."""
    if not isinstance(doc, dict):
        return "the file is not a JSON object"
    if doc.get("format") not in (CHECKS_FORMAT, CHECKS_FORMAT_2):
        return f"format must be {CHECKS_FORMAT} or {CHECKS_FORMAT_2}"
    v2 = doc["format"] == CHECKS_FORMAT_2
    keys = (
        ("format", "checks", "tools", "addresses", "rules")
        if v2
        else ("format", "mode", "checks", "tools", "addresses", "rules")
    )
    err = _exact(doc, keys, ("ruling_timeout_ms", "ci", "proposed"), "the checks file")
    if err:
        return err
    if not v2 and doc["mode"] not in ("watch", "enforce"):
        return '`mode` must be "watch" (Calibrating) or "enforce" (On)'
    c = doc["checks"]
    if not isinstance(c, dict):
        return "checks must be an object of the five checks"
    err = _exact(c, FILE_CHECKS, (), "checks")
    if err:
        return err
    bad = [k for k in FILE_CHECKS if not isinstance(c[k], bool)]
    if bad:
        return f"checks.{bad[0]} must be true or false"
    tools = doc["tools"]
    if not isinstance(tools, dict):
        return "tools must be an object of declared tool names"
    for name, t in tools.items():
        if not _declared_name(name):
            return f"tools: '{name}' is not a declared tool name (1 to 101 characters)"
        if v2:
            if not isinstance(t, dict):
                return f'tools.{name} must be {{protect, mode?, disclose?}}: `protect` is true (Protected) or false (Not protected), `mode` is "enforce" (On) or "watch" (Calibrating)'
            err = _exact(t, ("protect",), ("mode", "disclose"), f"tools.{name}")
            if err:
                return err
            if not isinstance(t["protect"], bool):
                return f"tools.{name}.protect must be true (Protected) or false (Not protected)"
            if "mode" in t and t["mode"] not in ("watch", "enforce"):
                return f'tools.{name}.mode must be "watch" (Calibrating) or "enforce" (On)'
            if "disclose" in t:
                if not t["protect"]:
                    return f"tools.{name}.disclose is allowed only on a protected tool: only protected calls send fields (set `protect` to true to protect the tool)"
                d = t["disclose"]
                if not isinstance(d, list) or len(d) > 64 or not all(pointer_ok(p) for p in d):
                    return f"tools.{name}.disclose must be a list of at most 64 JSON Pointers"
                dup = next((p for i, p in enumerate(d) if p in d[:i]), None)
                if dup is not None:
                    return f"tools.{name}.disclose lists {dup} twice"
            continue
        if not isinstance(t, dict):
            return f'tools.{name} must be {{strict, fail?, disclose?}}: `strict` is true (Protected) or false (Not protected), `fail` is "closed" (if signafAIde can\'t be reached: Stop) or "open" (Let it run)'
        err = _exact(t, ("strict",), ("fail", "disclose"), f"tools.{name}")
        if err:
            return err
        if not isinstance(t["strict"], bool):
            return f"tools.{name}.strict must be true (Protected) or false (Not protected)"
        if "fail" in t and t["fail"] not in ("open", "closed"):
            return f'tools.{name}.fail must be "closed" (Stop) or "open" (Let it run)'
        if "disclose" in t:
            d = t["disclose"]
            if not isinstance(d, list) or len(d) > 64 or not all(pointer_ok(p) for p in d):
                return f"tools.{name}.disclose must be a list of at most 64 JSON Pointers"
    a = doc["addresses"]
    if not isinstance(a, dict):
        return "addresses must be {hosts, cidrs, resolve}"
    err = _exact(a, ("hosts", "cidrs", "resolve"), (), "addresses")
    if err:
        return err
    if not isinstance(a["hosts"], list) or not all(_host_pattern(h) for h in a["hosts"]):
        return "addresses.hosts holds lowercase names, or *. and a suffix"
    if not isinstance(a["cidrs"], list) or not all(_cidr(x) for x in a["cidrs"]):
        return "addresses.cidrs holds IPv4 or IPv6 networks in CIDR form"
    if not isinstance(a["resolve"], bool):
        return "addresses.resolve must be true or false"
    err = local_rules_errors(doc["rules"])
    if err:
        return err
    if "ruling_timeout_ms" in doc and not (
        is_safe_int(doc["ruling_timeout_ms"]) and 1 <= doc["ruling_timeout_ms"] <= 60_000
    ):
        return "ruling_timeout_ms must be an integer from 1 to 60,000"
    if "proposed" in doc:
        err = _proposed_errors(doc["proposed"], v2, doc["rules"])
        if err:
            return err
    if "ci" in doc:
        return _ci_errors(doc["ci"])
    return None


def _proposed_errors(p: Any, v2: bool, rules: Any) -> Optional[str]:
    """``proposed`` of a version 2 checks file: the rules an agent run proposed and could not save,
    each ``{rule, by: "agent", on: "YYYY-MM-DD"}``: ``rule`` is the id of a local rule, or a rule
    with a ``limit`` itself (only the witness counts calls, so it is never a local rule and never
    applies here). A person running ``protect`` is offered them."""
    if not v2:
        return "proposed is for checks file version 2"
    if not isinstance(p, list) or len(p) > 1000:
        return "proposed must be a list of at most 1,000 {rule, by, on}"
    ids = (
        {r.get("id") for r in rules["rules"]}
        if isinstance(rules, dict) and isinstance(rules.get("rules"), list)
        else set()
    )
    seen: set = set()
    for i, x in enumerate(p):
        if not isinstance(x, dict):
            return f'proposed[{i}] must be {{"rule", "by", "on"}}'
        err = _exact(x, ("rule", "by", "on"), (), f"proposed[{i}]")
        if err:
            return err
        if isinstance(x["rule"], dict):
            err = rule_errors(x["rule"], True, None)
            if err:
                return f"proposed[{i}].rule: {err}"
            if "limit" not in x["rule"]:
                return f"proposed[{i}].rule holds a rule only when it has a limit; any other rule is a local rule in rules, named by its id"
            if x["rule"]["id"] in ids:
                return f"proposed[{i}].rule has the id of a rule in rules"
            rid = x["rule"]["id"]
        elif not isinstance(x["rule"], str) or x["rule"] not in ids:
            return f"proposed[{i}].rule must be the id of a rule in rules, or a rule with a limit"
        else:
            rid = x["rule"]
        if rid in seen:
            return f"proposed lists {rid} twice"
        seen.add(rid)
        if x["by"] != "agent":
            return f'proposed[{i}].by must be "agent"'
        if not isinstance(x["on"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", x["on"]):
            return f"proposed[{i}].on must be a date, YYYY-MM-DD"
    return None


def _ci_errors(ci: Any) -> Optional[str]:
    """``ci`` of a checks file: ``{"allow": [{"tool", "reason"}]}``, the reviewed exceptions of
    ``signafaide check --ci`` (a risky tool left unprotected on purpose, with the reason)."""
    if not isinstance(ci, dict):
        return 'ci must be {"allow": [{"tool", "reason"}]}'
    err = _exact(ci, ("allow",), (), "ci")
    if err:
        return err
    allow = ci["allow"]
    if not isinstance(allow, list) or len(allow) > 1000:
        return "ci.allow must be a list of at most 1,000 {tool, reason}"
    seen: set = set()
    for i, a in enumerate(allow):
        if not isinstance(a, dict):
            return f'ci.allow[{i}] must be {{"tool", "reason"}}'
        err = _exact(a, ("tool", "reason"), (), f"ci.allow[{i}]")
        if err:
            return err
        if not _declared_name(a["tool"]):
            return f"ci.allow[{i}].tool must be a declared tool name (1 to 101 characters)"
        r = a["reason"]
        if not isinstance(r, str) or not r.strip() or len(r) > 1000:
            return f"ci.allow[{i}].reason must say why the tool is allowed (1 to 1,000 characters)"
        if a["tool"] in seen:
            return f"ci.allow lists {a['tool']} twice"
        seen.add(a["tool"])
    return None


def tool_settings(file: dict, name: str) -> dict:
    """§8: what a valid checks file says for the tool with this declared name: ``strict`` (version
    1 ``strict``, version 2 ``protect``), ``fail`` (the fail mode it gives a strict tool), ``mode``
    (of the client's own checks and local rules on its calls) and ``disclose`` (the fields the
    developer approved for sending). Version 2: a protected tool defaults to enforce mode, any
    other tool (listed or not) to watch mode."""
    tools = file.get("tools") if isinstance(file.get("tools"), dict) else {}
    t = tools.get(name)
    if file.get("format") == CHECKS_FORMAT_2:
        if not isinstance(t, dict):
            return {"strict": False, "fail": "closed", "mode": "watch", "disclose": []}
        protect = t.get("protect") is True
        return {
            "strict": protect,
            "fail": "closed",
            "mode": t.get("mode") or ("enforce" if protect else "watch"),
            "disclose": list(t.get("disclose") or []) if protect else [],
        }
    mode = "enforce" if file.get("mode") == "enforce" else "watch"
    if not isinstance(t, dict):
        return {"strict": False, "fail": "closed", "mode": mode, "disclose": []}
    strict = t.get("strict") is True
    return {
        "strict": strict,
        "fail": "open" if strict and t.get("fail") == "open" else "closed",
        "mode": mode,
        "disclose": list(t.get("disclose") or []) if strict else [],
    }


def checks_file_version(file: dict) -> int:
    """The checks file's version: 1 or 2."""
    return 2 if file.get("format") == CHECKS_FORMAT_2 else 1


def default_checks_file() -> dict:
    """The checks file ``signafaide init`` writes: every check on, in watch mode, no strict tool."""
    return {
        "format": CHECKS_FORMAT,
        "mode": "watch",
        "checks": {k: True for k in FILE_CHECKS},
        "tools": {},
        "addresses": {"hosts": [], "cidrs": [], "resolve": False},
        "rules": None,
    }


# --- the verifier's tool-call checks report (§7) ------------------------------------------


def agent_checks(items: List[dict]) -> Optional[dict]:
    """The report of one agent from its records, in chain order, each ``{seq, kind, checks,
    decision_seq, ruling}``; None when it would have no line."""
    outs = {i["decision_seq"]: i for i in items if i["kind"] == "outcome" and i.get("decision_seq") is not None}
    j: dict = {
        "checked": 0,
        "allowed": 0,
        "noted": 0,
        "blocked_here": 0,
        "blocked_by_witness": 0,
        "notes": {},
        "ruled": {
            "allow": 0,
            "block": 0,
            "watch_would_block": 0,
            "calibrating_would_block": 0,
            "by_exception": 0,
            "not_calibrated": 0,
        },
        "no_ruling": {"ran": 0, "not_run": 0, "no_outcome": 0},
        "ran_after_block": [],
        "withheld": [],
        "rule_sets": [],
    }
    sets = set()
    for d in items:
        c = d.get("checks")
        if d["kind"] != "decision" or not isinstance(c, dict):
            continue
        j["checked"] += 1
        g = d.get("ruling")
        o = outs.get(d["seq"])
        asked = c.get("strict") is True and c.get("result") != "block"
        g_ruling = g.get("ruling") if isinstance(g, dict) else None
        if c.get("result") == "block":
            j["blocked_here"] += 1
        elif g_ruling == "block":
            j["blocked_by_witness"] += 1
        elif c.get("result") == "note":
            j["noted"] += 1
        else:
            j["allowed"] += 1
        for rr in c.get("rules") or []:
            sets.add((rr["set"], rr["version"], rr["hash"]))
        if isinstance(g, dict):
            if isinstance(g.get("rules"), dict):
                sets.add((g["rules"]["set"], g["rules"]["version"], g["rules"]["hash"]))
            if g_ruling in ("allow", "block"):
                j["ruled"][g_ruling] += 1
            if g.get("mode") == "watch" and g.get("enforce_ruling") == "block":
                j["ruled"]["watch_would_block"] += 1

            def has(k: str) -> bool:
                return isinstance(g.get(k), list) and len(g[k]) > 0

            if g_ruling == "allow" and has("would_block"):
                j["ruled"]["calibrating_would_block"] += 1
            if g_ruling == "allow" and has("excepted"):
                j["ruled"]["by_exception"] += 1
            if has("not_calibrated"):
                j["ruled"]["not_calibrated"] += 1
        oc = (o.get("checks") or {}) if o is not None else {}
        o_ran = oc.get("ran", True)
        o_none = oc.get("ruling") == "none"
        if asked and (g is None or (o is not None and o_none)):
            if o is None:
                j["no_ruling"]["no_outcome"] += 1
            elif o_ran:
                j["no_ruling"]["ran"] += 1
            else:
                j["no_ruling"]["not_run"] += 1
        blocked = c.get("result") == "block" or g_ruling == "block"
        if blocked and o is not None and o_ran and not o_none:
            j["ran_after_block"].append(d["seq"])
    for i in items:
        c = i.get("checks")
        if isinstance(c, dict):
            for e in c.get("results") or []:
                if e.get("result") == "note":
                    j["notes"][e["check"]] = j["notes"].get(e["check"], 0) + 1
            if i.get("kind") == "outcome" and c.get("result") == "block":
                j["withheld"].append(i["seq"])
    j["rule_sets"] = [
        {"set": s, "version": v, "hash": h}
        for s, v, h in sorted(sets, key=lambda x: (x[0], x[1] if x[1] is not None else -1, x[2]))
    ]
    return j if checks_lines(".", j) else None


def _n(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def checks_lines(agent: str, j: dict) -> List[str]:
    """The report lines of one agent (§7), without the ``tool-call checks: `` prefix."""
    out: List[str] = []
    if j["checked"]:
        parts = [f"{j['allowed']} allowed"] + [
            f"{j[k]} {w}"
            for k, w in (
                ("noted", "with notes"),
                ("blocked_here", "blocked here without a ruling from the witness"),
                ("blocked_by_witness", "blocked by the witness"),
            )
            if j[k]
        ]
        out.append(f"{agent}: {_n(j['checked'], 'tool call', 'tool calls')} checked: " + ", ".join(parts))
    if j["notes"]:
        out.append(f"{agent}: notes: " + ", ".join(f"{k} {j['notes'][k]}" for k in CHECK_IDS if k in j["notes"]))
    r = j["ruled"]
    ruled = r["allow"] + r["block"]
    if ruled:
        p = (
            [f"{r['allow']} allowed"]
            + ([f"{r['block']} blocked"] if r["block"] else [])
            + ([f"{r['watch_would_block']} Calibrating (would have blocked if On)"] if r["watch_would_block"] else [])
            + (
                [f"{r['calibrating_would_block']} allowed that a Calibrating rule would have blocked if On"]
                if r["calibrating_would_block"]
                else []
            )
            + ([f"{r['by_exception']} allowed by exception"] if r["by_exception"] else [])
            + (
                [
                    f"{r['not_calibrated']} with a Calibrating rule that could not be checked because a field it needs was not sent"
                ]
                if r["not_calibrated"]
                else []
            )
        )
        out.append(f"{agent}: {_n(ruled, 'protected call', 'protected calls')} ruled by the witness: " + ", ".join(p))
    nr = j["no_ruling"]
    tot = nr["ran"] + nr["not_run"] + nr["no_outcome"]
    if tot:
        p = [
            f"{nr[k]} {w}"
            for k, w in (
                ("ran", "ran because the tool was set to Let it run"),
                ("not_run", "did not run"),
                ("no_outcome", "have no outcome in the pack"),
            )
            if nr[k]
        ]
        had = "had no ruling when it was decided" if tot == 1 else "had no ruling when they were decided"
        out.append(f"{agent}: {_n(tot, 'protected call', 'protected calls')} {had}: " + ", ".join(p))
    if j["ran_after_block"]:
        k = len(j["ran_after_block"])
        out.append(
            f"{agent}: {_n(k, 'call', 'calls')} ran after a block: seq "
            + ", ".join(str(s) for s in j["ran_after_block"])
        )
    if j["withheld"]:
        k = len(j["withheld"])
        out.append(
            f"{agent}: {_n(k, 'tool result', 'tool results')} withheld from the agent: seq "
            + ", ".join(str(s) for s in j["withheld"])
        )
    if j["rule_sets"]:
        out.append(
            f"{agent}: rule sets used: "
            + ", ".join(
                f"local {x['hash'][:8]}" if x["set"] == "local" else f"{x['set']} version {x['version']}"
                for x in j["rule_sets"]
            )
        )
    return out


# --- protected from the console (SDK 0.5.2, §8, §10.1) -------------------------------------------


def rule_set_fail(rs: Optional[dict], tool: Optional[str]) -> Optional[str]:
    """The fail mode the held rule set gives *tool* (its ``fail``, else its ``protect``), when it names it."""
    if not rs or tool is None:
        return None
    fail = rs.get("fail") if isinstance(rs.get("fail"), dict) else {}
    if tool in fail:
        return fail[tool]
    protect = rs.get("protect") if isinstance(rs.get("protect"), dict) else {}
    if tool in protect:
        return protect[tool]["fail"]
    return None


def console_protects(rs: Optional[dict], tool: Optional[str]) -> bool:
    """Whether the held rule set protects *tool* from the console (its ``protect`` names it)."""
    return bool(rs) and tool is not None and isinstance(rs.get("protect"), dict) and tool in rs["protect"]


def protection(rs: Optional[dict], file: Optional[dict], code: bool, tool: str) -> Optional[dict]:
    """What protects *tool* (a declared name) and how its calls are checked (§8, SDK 0.5.2):
    ``strict``, ``fail``, ``mode``, ``sources`` (``code``, ``checks_file``, ``console``, in that
    order: ``meta.protected_by``) and ``disclose``; None when its calls are not checked at all.
    ``vectors.json`` ``checks.console_protect``."""
    console = console_protects(rs, tool)
    if not file and not code and not console:
        return None
    ts = tool_settings(file, tool) if file else None
    in_file = bool(ts and ts["strict"])
    sources = [n for on, n in ((code, "code"), (in_file, "checks_file"), (console, "console")) if on]
    strict = bool(sources)
    if ts is None:
        mode = "enforce"
    elif in_file or not console:
        mode = ts["mode"]
    else:
        t = (file.get("tools") or {}).get(tool) if file.get("format") == CHECKS_FORMAT_2 else None
        mode = t["mode"] if isinstance(t, dict) and t.get("mode") in ("watch", "enforce") else "enforce"
    fail = (rule_set_fail(rs, tool) or (ts["fail"] if in_file else "closed")) if strict else None
    return {
        "strict": strict,
        "fail": fail,
        "mode": mode,
        "sources": sources,
        "disclose": list(ts["disclose"]) if ts else [],
    }


def source_words(sources: List[str], version: Optional[int] = None) -> str:
    """Where a tool's protection comes from, in words (§8): ``by the code``, ``by the checks file``,
    ``from the console (rule set version 4)``, joined with ``and`` (``by the code and the checks file``)."""
    by = ["the code" if s == "code" else "the checks file" for s in sources if s != "console"]
    parts = [f"by {' and '.join(by)}"] if by else []
    if "console" in sources:
        parts.append("from the console" + (f" (rule set version {version})" if version is not None else ""))
    return " and ".join(parts)
