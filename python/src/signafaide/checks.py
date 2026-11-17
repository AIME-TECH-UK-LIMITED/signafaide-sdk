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
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .crypto import HEX64, SALT_RE, hash_json, sha256_hex, verify_sig
from .jcs import canonicalize

# --- constants (§9) -----------------------------------------------------------------------

DISCLOSED_MAX_BYTES = 16_384
RULING_TIMEOUT_MS = 10_000
RULES_REFRESH_MS = 60_000
FINGERPRINTS_REFRESH_MS = 60_000
RULES_FORMAT = "signafaide-rules/1"
LIST_FORMAT = "signafaide-fingerprints/1"
CHECKS_FORMAT = "signafaide-checks/1"
MAX_RULE_SET_BYTES = 1 << 20

#: The check ids, in the order of the §2.8 table.
CHECK_IDS = ("secret", "address", "changed_tool", "fingerprint", "rule", "hidden_instruction")
DECISION_CHECKS = ("secret", "address", "changed_tool", "fingerprint", "rule")
#: The checks a checks file turns on or off (``rule`` is on whenever rules are held).
FILE_CHECKS = ("secret", "address", "changed_tool", "fingerprint", "hidden_instruction")
RESULT_ORDER = {"allow": 0, "note": 1, "block": 2}
SECRET_FORMATS = (
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}", ("github.com", "api.github.com", "uploads.github.com")),
    ("aws_access_key", r"(AKIA|ASIA)[A-Z0-9]{16}", ("*.amazonaws.com",)),
    ("stripe_key", r"(sk|rk)_(live|test)_[A-Za-z0-9]{24,99}", ("api.stripe.com",)),
    ("slack_token", r"xox[abposr]-[A-Za-z0-9-]{10,200}", ("slack.com", "*.slack.com")),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,200}", ("api.anthropic.com",)),
    ("openai_key", r"sk-proj-[A-Za-z0-9_-]{20,200}", ("api.openai.com",)),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}", ("*.googleapis.com",)),
    ("signafaide_key", r"sfa_(test|live)_[0-9A-Za-z]{32}", ()),  # issuer: the host of the client's witness URL
)
_SECRET_RES = tuple((fid, re.compile(pat), issuers) for fid, pat, issuers in SECRET_FORMATS)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
FOUND = {
    "secret": {f[0] for f in SECRET_FORMATS} | {"private_key", "high_entropy"},
    "address": {"loopback", "private", "shared", "link_local", "unique_local", "unspecified", "metadata", "internal_name"},
    "changed_tool": {"description_changed", "schema_changed", "not_approved"},
    "fingerprint": {"tool", "description", "server"},
    "hidden_instruction": {"invisible_characters", "instruction_phrase"},
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
        "lt": is_num(v), "le": is_num(v), "gt": is_num(v), "ge": is_num(v),
        "in": isinstance(v, list) and len(v) <= 256, "not_in": isinstance(v, list) and len(v) <= 256,
        "prefix": isinstance(v, str), "suffix": isinstance(v, str), "contains": isinstance(v, str),
        "type": v in TYPES,
    }.get(op, True)
    return None if ok else f"the value of '{op}' has the wrong type"


def rule_errors(r: Any, allow_limit: bool = True) -> Optional[str]:
    if not isinstance(r, dict):
        return "each rule is an object"
    err = _exact(r, ("id", "about", "action", "tools", "agents", "when"), ("limit",) if allow_limit else (), "a rule")
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
    return None


def _rules_list_errors(rules: Any, allow_limit: bool = True) -> Optional[str]:
    if not isinstance(rules, list) or len(rules) > 1000:
        return "rules must be a list of at most 1,000 rules"
    seen = set()
    for r in rules:
        err = rule_errors(r, allow_limit)
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
    err = _exact(doc, ("format", "project", "env", "set", "version", "prev", "issued", "mode", "default", "fail", "addresses", "approved", "rules"), ("fingerprint_exceptions",), "the rule set")
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
        return "mode must be watch or enforce"
    if doc["default"] not in ("allow", "block"):
        return "default must be allow or block"
    f = doc["fail"]
    if not isinstance(f, dict) or len(f) > 1000 or not all(_declared_name(k) and v in ("open", "closed") for k, v in f.items()):
        return "fail maps declared tool names to open or closed"
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
            if not _declared_name(name) or not isinstance(e, dict) or set(e) != {"description", "schema"} or not (is_hex64(e["description"]) and is_hex64(e["schema"])):
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
    return _rules_list_errors(doc["rules"])


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
    err = _rules_list_errors(rules["rules"], allow_limit=False)
    if err and "unknown field 'limit'" in err:
        return "rules may not use limit: only the witness counts calls"
    return err


def applies(rule: dict, agent: str, tool: str) -> bool:
    return (rule["tools"] is None or tool in rule["tools"]) and (rule["agents"] is None or agent in rule["agents"])


def needed_fields(doc: Optional[dict], agent: str, tool: str) -> List[str]:
    """§10.4: the ``field`` of every condition of every rule that applies, each once, in code point order."""
    if doc is None:
        return []
    return sorted({c["field"] for r in doc["rules"] if applies(r, agent, tool) for c in r["when"]})


def evaluate(doc: dict, agent: str, tool: str, lookup: Callable[[str], Any], count: Optional[Callable[[dict], int]] = None) -> dict:
    """§10.3: ``{result, basis, matched}``, the enforce-mode result. *doc* has ``rules`` and
    ``default``. *count* is the witness's count of its earlier allow rulings for a limit rule;
    without it (a client) limit rules are skipped."""
    errors: List[str] = []
    blocks: List[str] = []
    allows: List[str] = []
    for r in doc["rules"]:
        if not applies(r, agent, tool):
            continue
        if "limit" in r and count is None:
            continue
        status: Any = True
        for c in r["when"]:
            status = condition(c, lookup(c["field"]))
            if status is not True:
                break
        if status == "error":
            errors.append(r["id"])
            continue
        if status is not True:
            continue
        if "limit" in r and count is not None and count(r["limit"]) < r["limit"]["calls"]:
            continue
        (blocks if r["action"] == "block" else allows).append(r["id"])
    if errors:
        return {"result": "block", "basis": "error", "matched": errors[:16]}
    if blocks:
        return {"result": "block", "basis": "rule", "matched": blocks[:16]}
    if allows:
        return {"result": "allow", "basis": "rule", "matched": allows[:16]}
    return {"result": doc["default"], "basis": "default", "matched": []}


def apply_mode(result: str, mode: str) -> dict:
    """A check result as an entry writes it in *mode* (§2.8): watch mode never blocks."""
    if mode == "watch":
        return {"result": "note" if result == "block" else result, "enforce_result": result}
    return {"result": result}


def entry_mode(own: str, strict: bool, local: bool) -> str:
    """The project's rule set binds only strict calls: on a call that is not strict its entry is in watch mode (§8)."""
    return own if (strict or local) else "watch"


def client_rule_entry(doc: dict, mode: str, set_id: str, agent: str, tool: str, args: Any) -> dict:
    """The client's ``rule`` entry for one rule set (§2.8): §10.3 as a client over the call's arguments, in *mode*."""
    res = evaluate(doc, agent, tool, lambda p: resolve(args, p))
    return {"check": "rule", **apply_mode(res["result"], mode), "mode": mode, "set": set_id, "matched": res["matched"]}


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


def accept_rules(held: Optional[dict], item: Any, service_keys: List[dict], project: str, env: str) -> Optional[str]:
    """The name of the first §10.2 step that refuses *item* (``{rules, sig, service_key_id}``),
    or None when the client accepts it. *held* is the document the client holds."""
    doc = item.get("rules") if isinstance(item, dict) else None
    if rule_set_errors(doc):
        return "schema"
    if doc["project"] != project or doc["env"] != env:
        return "project"
    key = next((k for k in service_keys if k.get("key_id") == item.get("service_key_id")), None)
    if key is None or not _key_active(key, doc["issued"]) or not verify_sig(key.get("public_key", ""), "rules", hash_json(doc), item.get("sig")):
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
        if not isinstance(e, dict) or set(e) != {"kind", "fingerprint"} or e["kind"] not in ("tool", "description", "server") or not is_hex64(e["fingerprint"]):
            return False
        keys.append(_entry_key(e))
    return keys == sorted(set(keys))


def state_hash(entries: List[dict]) -> str:
    return hash_json(sorted(entries, key=_entry_key))


def empty_list() -> dict:
    return {"seq": 0, "last": None, "entries": []}


def apply_list(held: dict, item: Any, service_keys: List[dict]) -> Tuple[dict, Optional[str]]:
    """One served item ``{list, sig, service_key_id}`` applied to *held* ``{seq, last, entries}``
    (§11.2): ``(new_held, None)``, or ``(held, refusal)`` with the refusal's name
    (``signature``, ``state``, ``older``, ``gap``, ``prev``, ``invalid``)."""
    obj = item.get("list") if isinstance(item, dict) else None
    if not isinstance(obj, dict):
        return held, "invalid"
    key = next((k for k in service_keys if k.get("key_id") == item.get("service_key_id")), None)
    try:
        signed = key is not None and _key_active(key, obj.get("issued")) and verify_sig(key.get("public_key", ""), "fingerprints", hash_json(obj), item.get("sig"))
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
    if not isinstance(doc, dict) or set(doc) != {"seq", "last", "entries"} or not is_safe_int(doc["seq"]) or doc["seq"] < 0:
        return "not {seq, last, entries}"
    if not (doc["last"] is None or is_hex64(doc["last"])) or not _entries_ok(doc["entries"]):
        return "entries out of order or repeated"
    return None


# --- tool fingerprints (§11.1) ------------------------------------------------------------

_SCHEMA_MAPS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
_SCHEMA_LISTS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_ONE = ("items", "additionalItems", "additionalProperties", "unevaluatedItems", "unevaluatedProperties",
               "contains", "propertyNames", "not", "if", "then", "else")


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
        "server": None if server_info is None else hash_json({"name": server_info.get("name"), "version": server_info.get("version")}),
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
    if kind == "outcome" and c != "hidden_instruction":
        return f"the check '{c}' is not a check of an outcome"
    keys = {"check", "result", "mode"}
    if e.get("mode") == "watch":
        keys.add("enforce_result")
    keys |= {"set", "matched"} if c == "rule" else {"found"}
    if set(e) != keys:
        return f"the '{c}' entry has the wrong keys"
    if e["mode"] not in ("watch", "enforce") or e["result"] not in RESULT_ORDER:
        return "an entry's mode is watch or enforce and its result allow, note or block"
    if e["mode"] == "watch":
        if e["enforce_result"] not in RESULT_ORDER or e["result"] != ("note" if e["enforce_result"] == "block" else e["enforce_result"]):
            return "in watch mode an entry's result equals its enforce_result, except that block is written as note"
    if c == "hidden_instruction" and "block" in (e["result"], e.get("enforce_result")):
        return "hidden_instruction never blocks"
    if c == "rule":
        if not (e["set"] == "local" or (isinstance(e["set"], str) and SET_RE.match(e["set"]))):
            return "a rule entry's set is local or the rule set's id"
        if not isinstance(e["matched"], list) or len(e["matched"]) > 16 or not all(isinstance(m, str) and RULE_ID_RE.match(m) for m in e["matched"]):
            return "a rule entry's matched is a list of at most 16 rule ids"
    else:
        f = e["found"]
        if not isinstance(f, list) or len(f) > 8 or len(set(map(str, f))) != len(f) or not all(x in FOUND[c] for x in f):
            return f"the '{c}' entry has an unknown or repeated found code"
    return None


def checks_errors(env: dict) -> Optional[str]:
    """The §2.8 rules for an envelope's ``checks``; None when valid or absent."""
    if "checks" not in env:
        return None
    ch = env["checks"]
    if env.get("kind") not in ("decision", "outcome") or not isinstance(env.get("name"), str) or env["name"].startswith("signafaide."):
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
        keys = {"results", "result", "rules", "fingerprints", "tool", "strict", "fail", "disclosed", "disclosed_hash", "call_id"}
        if set(ch) != keys:
            extra = sorted(set(ch) - keys)
            return f"the checks of a decision have the unknown key '{extra[0]}'" if extra else "the checks of a decision lack a key"
        t = ch["tool"]
        if not isinstance(t, dict) or set(t) != {"tool", "description", "schema", "server"} or not all(is_hex64(t[k]) for k in ("tool", "description", "schema")) \
                or not (t["server"] is None or is_hex64(t["server"])):
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
            elif not (isinstance(r["set"], str) and SET_RE.match(r["set"]) and is_safe_int(r["version"]) and r["version"] >= 1):
                return "checks.rules names the project's rule set (rs_..., version 1 or above) or the local rules"
            sets.append("local" if r["set"] == "local" else "project")
        if len(sets) != len(set(sets)):
            return "checks.rules holds at most one entry for the project's rule set and one for the local rules"
        if not (ch["fingerprints"] is None or (is_safe_int(ch["fingerprints"]) and ch["fingerprints"] >= 0)):
            return "checks.fingerprints must be null or the seq of the shared list"
        if not isinstance(ch["strict"], bool):
            return "checks.strict must be true or false"
        if not ((ch["strict"] and ch["fail"] in ("open", "closed")) or (not ch["strict"] and ch["fail"] is None)):
            return "checks.fail is open or closed when strict is true, and null otherwise"
        d = ch["disclosed"]
        if not isinstance(d, list) or len(d) > 64 or not all(pointer_ok(p) for p in d) or d != sorted(set(d)):
            return "checks.disclosed holds at most 64 JSON Pointers, in code point order, without repeats"
        if d and not ch["strict"]:
            return "checks.disclosed must be empty on a call that is not strict"
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
    if env["kind"] == "outcome" and ch["result"] not in ("allow", "note"):
        return "checks.result of an outcome must be allow or note"
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


def ruling_errors(r: Any) -> Optional[str]:
    """Whether a ruling object follows §3.5 field by field (check 6)."""
    if not isinstance(r, dict):
        return "a ruling is an object"
    watch = r.get("mode") == "watch"
    keys = {"v", "record_hash", "batch_hash", "server_time", "ruling", "mode", "basis", "matched", "missing", "rules", "fingerprints", "reason"} | ({"enforce_ruling"} if watch else set())
    if set(r) != keys:
        return "the ruling's fields are " + ", ".join(sorted(keys))
    if r["v"] != 1 or not is_safe_int(r["v"]):
        return "the ruling's v must be 1"
    if not (is_hex64(r["record_hash"]) and is_hex64(r["batch_hash"])) or not _valid_time(r["server_time"]):
        return "the ruling's record_hash, batch_hash or server_time is invalid"
    if r["ruling"] not in ("allow", "block") or r["mode"] not in ("watch", "enforce"):
        return "the ruling is allow or block, in watch or enforce mode"
    if watch:
        if r["ruling"] != "allow":
            return "in watch mode the ruling is always allow"
        if r["enforce_ruling"] not in ("allow", "block"):
            return "enforce_ruling is allow or block"
    enforce = r["enforce_ruling"] if watch else r["ruling"]
    basis = r["basis"]
    if basis not in ("rules_version", "fields_missing", "fingerprint", "error", "rule", "default"):
        return "basis is rules_version, fields_missing, fingerprint, error, rule or default"
    if basis in ("rules_version", "fields_missing", "fingerprint", "error") and enforce != "block":
        return f"basis {basis} always blocks in enforce mode"
    m = r["matched"]
    if not isinstance(m, list) or len(m) > 16 or not all(isinstance(x, str) and RULE_ID_RE.match(x) for x in m):
        return "matched is a list of at most 16 rule ids"
    if (not m) == (basis in ("error", "rule")):
        return "matched names the rules exactly for basis error and rule"
    miss = r["missing"]
    if not isinstance(miss, list) or len(miss) > 64 or not all(pointer_ok(p) for p in miss) or miss != sorted(set(miss)):
        return "missing is a list of at most 64 pointers in code point order"
    if (not miss) == (basis == "fields_missing"):
        return "missing lists the pointers exactly for basis fields_missing"
    rules = r["rules"]
    if rules is None:
        if watch or basis not in ("fingerprint", "default"):
            return "without a rule set a ruling is in enforce mode, with basis fingerprint or default"
    elif not (isinstance(rules, dict) and set(rules) == {"set", "version", "hash"} and isinstance(rules["set"], str) and SET_RE.match(rules["set"])
              and is_safe_int(rules["version"]) and rules["version"] >= 1 and is_hex64(rules["hash"])):
        return "the ruling's rules is null or {set, version, hash}"
    if not is_safe_int(r["fingerprints"]) or r["fingerprints"] < 0:
        return "the ruling's fingerprints is the seq of the shared list"
    if not isinstance(r["reason"], str) or not 1 <= len(r["reason"]) <= 300:
        return "the ruling's reason is 1 to 300 characters"
    return None


# --- the client's own checks (§8) ---------------------------------------------------------


def string_leaves(value: Any) -> List[str]:
    """The strings of *value*, in the order their members appear in its JCS form."""
    out: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for k in sorted(v, key=lambda s: s.encode("utf-16-be")):
                walk(v[k])

    walk(value)
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
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def secret_findings(args: Any, witness_host: Optional[str] = None) -> dict:
    """The ``secret`` check (§8) on a call's arguments: ``{result, found}`` in enforce mode."""
    leaves = string_leaves(args)
    texts: List[str] = []
    for s in leaves + ["".join(leaves)]:
        texts.append(s)
        d = _pct_decode(s)
        if d is not None:
            texts.append(d)
    hosts = [h for h in (url_host(s) for s in leaves) if h is not None]
    found: List[str] = []
    for t in texts:
        for tok in re.findall(r"[A-Za-z0-9_-]+", t):
            for fid, pat, issuers in _SECRET_RES:
                if pat.fullmatch(tok):
                    iss = (witness_host,) if fid == "signafaide_key" and witness_host else issuers
                    if hosts and iss and all(any(host_matches(h, p) for p in iss) for h in hosts):
                        continue
                    if fid not in found:
                        found.append(fid)
                    break
        if PRIVATE_KEY_RE.search(t) and "private_key" not in found:
            found.append("private_key")
    if found:
        return {"result": "block", "found": sorted(found)[:8]}
    for s in leaves:
        cands = [s] + [d for d in [_pct_decode(s)] if d is not None]
        for t in cands:
            for tok in re.findall(r"[A-Za-z0-9_+/=-]+", t):
                if any(p.fullmatch(tok) for _, p, _ in _SECRET_RES):
                    continue
                if len(tok) >= 32 and _entropy(tok) >= 4.5:
                    return {"result": "note", "found": ["high_entropy"]}
    return {"result": "allow", "found": []}


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


_METADATA = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal", "metadata"}
_V4 = [("0.0.0.0/8", "unspecified"), ("10.0.0.0/8", "private"), ("100.64.0.0/10", "shared"), ("127.0.0.0/8", "loopback"),
       ("169.254.0.0/16", "link_local"), ("172.16.0.0/12", "private"), ("192.168.0.0/16", "private")]
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
    for net, code in (_V4 if ip.version == 4 else _V6):
        if ip in ipaddress.ip_network(net):
            return code
    return None


def classify_host(host: str, allow_hosts: Sequence[str] = (), allow_cidrs: Sequence[str] = (), resolve_names: bool = False) -> Optional[str]:
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


def address_findings(args: Any, allow_hosts: Sequence[str] = (), allow_cidrs: Sequence[str] = (), resolve_names: bool = False) -> dict:
    """The ``address`` check (§8) on a call's arguments: ``{result, found}`` in enforce mode."""
    found: List[str] = []
    for s in string_leaves(args):
        h = url_host(s)
        if h is None:
            h = _bare_address(s)
            if h is None:
                continue
        code = classify_host(h, allow_hosts, allow_cidrs, resolve_names)
        if code and code not in found:
            found.append(code)
    return {"result": "block" if found else "allow", "found": sorted(found)}


_INVISIBLE = ((0xE0000, 0xE007F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069))
_PHRASES = ("ignore previous instructions", "ignore all previous instructions", "ignore the previous instructions",
            "disregard previous instructions", "disregard all previous instructions", "forget your instructions", "do not tell the user")


def hidden_findings(result: Any) -> dict:
    """The ``hidden_instruction`` check (§8) on a call's result: ``{result, found}``; never ``block``."""
    found: List[str] = []
    for s in string_leaves(result):
        if any(lo <= ord(ch) <= hi for ch in s for lo, hi in _INVISIBLE) or "﻿" in s[1:]:
            if "invisible_characters" not in found:
                found.append("invisible_characters")
        low = re.sub(r"\s+", " ", "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in s))
        if any(p in low for p in _PHRASES) and "instruction_phrase" not in found:
            found.append("instruction_phrase")
    return {"result": "note" if found else "allow", "found": sorted(found)}


def changed_tool_findings(fps: dict, approved: Optional[dict]) -> dict:
    """The ``changed_tool`` check (§8): *approved* is ``{description, schema}`` for the tool, or
    None when a rule set's ``approved`` does not list it."""
    if approved is None:
        return {"result": "block", "found": ["not_approved"]}
    if fps["schema"] != approved.get("schema"):
        found = ["schema_changed"] + (["description_changed"] if fps["description"] != approved.get("description") else [])
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
    found = [k for k in ("tool", "description", "server") if fps.get(k) and (k, fps[k]) in listed and (k, fps[k]) not in (excepted or ())]
    return {"result": "block" if found else "allow", "found": sorted(found)}


def entry(check: str, findings: dict, mode: str) -> dict:
    """A results entry (§2.8) for one of the client's own checks."""
    return {"check": check, **apply_mode(findings["result"], mode), "mode": mode, "found": findings["found"]}


# --- the checks file (§8) ----------------------------------------------------------------


def checks_file_errors(doc: Any) -> Optional[str]:
    """The first problem with a checks file, naming the key; None when valid."""
    if not isinstance(doc, dict):
        return "the file is not a JSON object"
    err = _exact(doc, ("format", "mode", "checks", "tools", "addresses", "rules"), ("ruling_timeout_ms",), "the checks file")
    if err:
        return err
    if doc["format"] != CHECKS_FORMAT:
        return f"format must be {CHECKS_FORMAT}"
    if doc["mode"] not in ("watch", "enforce"):
        return "mode must be watch or enforce"
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
        if not isinstance(t, dict):
            return f"tools.{name} must be {{strict, fail?, disclose?}}"
        err = _exact(t, ("strict",), ("fail", "disclose"), f"tools.{name}")
        if err:
            return err
        if not isinstance(t["strict"], bool):
            return f"tools.{name}.strict must be true or false"
        if "fail" in t and t["fail"] not in ("open", "closed"):
            return f"tools.{name}.fail must be open or closed"
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
    if "ruling_timeout_ms" in doc and not (is_safe_int(doc["ruling_timeout_ms"]) and 1 <= doc["ruling_timeout_ms"] <= 60_000):
        return "ruling_timeout_ms must be an integer from 1 to 60,000"
    return None


def default_checks_file() -> dict:
    """The checks file ``signafaide init`` writes: every check on, in watch mode, no strict tool."""
    return {"format": CHECKS_FORMAT, "mode": "watch", "checks": {k: True for k in FILE_CHECKS}, "tools": {},
            "addresses": {"hosts": [], "cidrs": [], "resolve": False}, "rules": None}


# --- the verifier's tool-call checks report (§7) ------------------------------------------


def agent_checks(items: List[dict]) -> Optional[dict]:
    """The report of one agent from its records, in chain order, each ``{seq, kind, checks,
    decision_seq, ruling}``; None when it would have no line."""
    outs = {i["decision_seq"]: i for i in items if i["kind"] == "outcome" and i.get("decision_seq") is not None}
    j: dict = {"checked": 0, "allowed": 0, "noted": 0, "blocked_here": 0, "blocked_by_witness": 0, "notes": {},
               "ruled": {"allow": 0, "block": 0, "watch_would_block": 0}, "no_ruling": {"ran": 0, "not_run": 0, "no_outcome": 0},
               "ran_after_block": [], "rule_sets": []}
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
    j["rule_sets"] = [{"set": s, "version": v, "hash": h} for s, v, h in sorted(sets, key=lambda x: (x[0], x[1] if x[1] is not None else -1, x[2]))]
    return j if checks_lines(".", j) else None


def _n(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def checks_lines(agent: str, j: dict) -> List[str]:
    """The report lines of one agent (§7), without the ``tool-call checks: `` prefix."""
    out: List[str] = []
    if j["checked"]:
        parts = [f"{j['allowed']} allowed"] + [f"{j[k]} {w}" for k, w in (("noted", "with notes"), ("blocked_here", "blocked here"), ("blocked_by_witness", "blocked by the witness")) if j[k]]
        out.append(f"{agent}: {_n(j['checked'], 'tool call', 'tool calls')} checked: " + ", ".join(parts))
    if j["notes"]:
        out.append(f"{agent}: notes: " + ", ".join(f"{k} {j['notes'][k]}" for k in CHECK_IDS if k in j["notes"]))
    r = j["ruled"]
    ruled = r["allow"] + r["block"]
    if ruled:
        p = [f"{r['allow']} allowed"] + ([f"{r['block']} blocked"] if r["block"] else []) + \
            ([f"{r['watch_would_block']} in watch mode that enforce mode would have blocked"] if r["watch_would_block"] else [])
        out.append(f"{agent}: {_n(ruled, 'strict call', 'strict calls')} ruled by the witness: " + ", ".join(p))
    nr = j["no_ruling"]
    tot = nr["ran"] + nr["not_run"] + nr["no_outcome"]
    if tot:
        p = [f"{nr[k]} {w}" for k, w in (("ran", "ran (fail open)"), ("not_run", "did not run"), ("no_outcome", "have no outcome in the pack")) if nr[k]]
        had = "had no ruling when it was decided" if tot == 1 else "had no ruling when they were decided"
        out.append(f"{agent}: {_n(tot, 'strict call', 'strict calls')} {had}: " + ", ".join(p))
    if j["ran_after_block"]:
        k = len(j["ran_after_block"])
        out.append(f"{agent}: {_n(k, 'call', 'calls')} ran after a block: seq " + ", ".join(str(s) for s in j["ran_after_block"]))
    if j["rule_sets"]:
        out.append(f"{agent}: rule sets used: " + ", ".join(f"local {x['hash'][:8]}" if x["set"] == "local" else f"{x['set']} version {x['version']}" for x in j["rule_sets"]))
    return out
