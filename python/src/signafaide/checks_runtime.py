"""Tool-call checks in a running program (SPEC §8): the checks file and its live reload, the
held rule set and shared fingerprint list (fetched every 60 s, kept offline), local tool
approvals, the decision checks of a call, and the witness's ruling on a strict call."""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import checks as C
from . import scan
from .coverage import declared_name
from .crypto import hash_json, new_salt
from .http import DEFAULT_URL, SignafaideError
from .jcs import canonicalize, dumps
from .state import atomic_write
from .records import now, parse_time
from .notes import development
from .verifier import _epoch_ms, _fmt as _fmt_ms, load_service_key_set
from ._version import __version__
from .words import fail_word, mode_word, rule_words

log = logging.getLogger("signafaide")

CHECKS_FILE = "signafaide.checks.json"


def _pinned_document() -> dict:
    """The package's own service-keys.json (spec/service-keys.json): the default witness's keys."""
    from importlib import resources

    return json.loads(resources.files("signafaide").joinpath("service-keys.json").read_text())


#: The public keys of the default witness (``DEFAULT_URL``), shipped with the SDK and pinned: read
#: from the package's service-keys.json. With the default URL, rule sets, the shared list and
#: rulings verify with these keys only; a key set fetched from the network never adds a key (§8).
DEFAULT_SERVICE_KEYS: Tuple[dict, ...] = tuple(load_service_key_set(_pinned_document())[0])

#: The revoked ids pinned with them (§5): never used. Online, the published list's revoked ids are
#: added (the union), as every verifier does.
DEFAULT_REVOKED: Tuple[str, ...] = tuple(load_service_key_set(_pinned_document())[1])

#: The pinned keys and revoked ids of this release, as a hash: a keys.json entry read with other
#: ones counts as never fetched.
_PINNED_HASH = hash_json({"keys": list(DEFAULT_SERVICE_KEYS), "revoked": list(DEFAULT_REVOKED)})

#: How long a fetched key list (its revoked ids) is used before it is fetched again: 10 minutes.
KEYS_REFRESH_MS = 10 * 60_000

#: Forced fetches of the rule set a ruling may cause (§8): per ``RULES_REFRESH_MS`` in all, and how
#: many versions' last forced fetch the state file keeps.
MAX_FORCED_PER_INTERVAL = 3
MAX_FORCED_KEPT = 8

#: What a broken held rule set with no protect record means (§8): never fail open.
PROTECTION_UNKNOWN = (
    "protection list unknown: every checked call is refused until the rule set verifies; run `signafaide pull`"
)

#: How long a held rule set or shared list that is stale (§8: signed by a key now revoked or no
#: longer held, or its replacement refused) is still enforced as it is: 7 days from when the client
#: first learned it. After that every protected call is refused until a verified copy arrives.
REVOKED_GRACE_MS = 7 * 86_400_000

#: The first wait after a refused signed rule set or list item, doubling up to the longest (§8).
STALE_RETRY_FIRST_MS = 60_000
STALE_RETRY_MAX_MS = 3_600_000

#: How long after a failed key list read the next one waits (after a good one: KEYS_REFRESH_MS).
KEYS_RETRY_MS = 60_000

#: The most keys held for a self-hosted witness, and the most revoked ids kept for the default
#: witness that name keys this release does not pin yet (so a release that pins one applies it).
MAX_WITNESS_KEYS = 64
MAX_UNPINNED_REVOKED = 64


def _now_ms() -> int:
    return int(time.time() * 1000)


def _iso(ms: int) -> str:
    return _fmt_ms(int(ms))


def stale_transition(s: dict, ev: dict, now_: str, held: bool) -> dict:
    """The one transition of the stale state of a held rule set or list (§8, ``vectors.json``
    ``key_lifecycle.stale_transitions``): ``{since, refused, retry, confirmed when true}``. *held*: an
    object is held (nothing held never starts the clock: a code-protected call still needs a verified
    ruling). A ``since`` in the future counts as now; a retry wait is never longer than the longest
    from now. Only ``verified`` clears."""
    t = _epoch_ms(now_)

    def clamp(x: Any) -> Optional[str]:
        m = _epoch_ms(x) if isinstance(x, str) else None
        return None if m is None else (now_ if m > t else x)

    since = clamp(s.get("since"))
    retry = s.get("retry")
    if retry and (_epoch_ms(retry.get("until")) or 0) > t + STALE_RETRY_MAX_MS:
        retry = {**retry, "until": _iso(t + STALE_RETRY_MAX_MS)}
    out: dict = {"since": since, "refused": s.get("refused"), "retry": retry or None}
    if s.get("confirmed") and since:
        out["confirmed"] = True
    kind = ev.get("type")
    if kind == "verified":
        return {"since": None, "refused": None, "retry": None}
    if kind == "signer_bad":
        if held and not since:
            out["since"] = now_
    elif kind == "refused":
        if held and not since:
            out["since"] = now_
        out["refused"] = ev.get("refused")
        n = ((retry or {}).get("failures") or 0) + 1
        out["retry"] = {
            "failures": n,
            "until": _iso(t + min(STALE_RETRY_FIRST_MS * 2 ** min(n - 1, 30), STALE_RETRY_MAX_MS)),
        }
    elif kind == "pull_done":
        if ev.get("stale_before") and since:
            out["confirmed"] = True
    elif kind == "merge":
        other = clamp(ev.get("since"))
        if held and other:
            out["since"] = since if since and _epoch_ms(since) <= _epoch_ms(other) else other
    # unsigned answers, network errors, key list changes, re-saves: nothing changes
    if not out["since"]:
        out.pop("confirmed", None)
    return out


#: Why a protected tool stops with no key or sandbox, and the one command that fixes it (one sentence).
NO_KEY_WHY = (
    "protected tools stop until a person runs `signafaide protect` in this project, because there is no signafAIde key or sandbox "
    "here yet to allow the call."
)


class CheckError(SignafaideError):
    """A tool call that did not run: ``blocked`` (a check or the witness's ruling), ``no_ruling``,
    ``rules_unavailable``, ``no_key`` (strict without a key) or ``state`` (the checks file is
    invalid). ``check``, ``rule``, ``rules_version`` and ``missing`` say what to change."""

    def __init__(
        self,
        message: str,
        code: str,
        *,
        check: Optional[str] = None,
        rule: Optional[str] = None,
        rules_version: Optional[int] = None,
        missing: Optional[List[str]] = None,
    ):
        super().__init__(message, code=code)
        self.check, self.rule, self.rules_version, self.missing = check, rule, rules_version, list(missing or [])


class SignafaideBlocked(CheckError):
    """A protected or checked tool call that did not run (spec 1.1): one sentence that says what
    did not run and why, the rule in words (§10.5) and its rule set version, and a console link.
    A :class:`CheckError` with the same fields (``code``, ``check``, ``rule`` (the rule's id),
    ``rules_version``, ``missing``), plus ``tool``, ``rule_text`` (the rule in words),
    ``ruled_by`` (``witness``: the witness's ruling; ``client``: a check or the local rules on
    this machine), ``record`` (the decision's record hash) and ``link`` (the call in the console;
    None without an API key)."""

    def __init__(
        self,
        message: str,
        code: str,
        *,
        tool: str,
        ruled_by: str,
        rule_text: Optional[str] = None,
        check: Optional[str] = None,
        rule: Optional[str] = None,
        rules_version: Optional[int] = None,
        missing: Optional[List[str]] = None,
    ):
        super().__init__(message, code, check=check, rule=rule, rules_version=rules_version, missing=missing)
        self.tool, self.ruled_by, self.rule_text = tool, ruled_by, rule_text
        self.record: Optional[str] = None
        self.link: Optional[str] = None

    def attach(self, record: str, link: Optional[str]) -> "SignafaideBlocked":
        """Name the decision this error refused, and the console link to it (when there is one)."""
        self.record = record
        if link:
            self.link = link
            self.message = f"{self.message} {link}"
            self.args = (self.message,)
        return self


def site_of(url: str) -> str:
    """The website of a witness: https://api.signafaide.co.uk -> https://signafaide.co.uk."""
    import urllib.parse

    u = urllib.parse.urlsplit(url)
    host = u.netloc[4:] if u.netloc.startswith("api.") else u.netloc
    return f"{u.scheme}://{host}" if u.scheme else url


def call_link(rec: Any, record_hash: str) -> Optional[str]:
    """The console link to a call, by its decision's record hash (spec 1.1
    ``SignafaideBlocked.link``): none in test mode or without an API key."""
    if rec.test or not rec.api_key:
        return None
    return f"{site_of(rec.url)}/r/{record_hash}"


@dataclasses.dataclass(frozen=True)
class ToolInfo:
    """What the agent is shown of a tool (§11.1): its whole name, description, input schema and
    the MCP server's ``serverInfo`` (None for a tool that does not come from one)."""

    name: str
    description: str = ""
    input_schema: Any = None
    server_info: Optional[dict] = None
    #: Which MCP server the tool comes from, when the caller knows better than ``serverInfo.name``.
    #: Keys the tool's local approval, so two servers that offer one tool name never share it.
    server: Optional[str] = None
    #: The whole definition the agent is shown (an MCP ``tools/list`` entry), for the
    #: ``hidden_instruction`` check; by default its name, description and input schema.
    definition: Any = None
    #: The names of the other tools listed with it, for instructions about other tools (§8 ``tool_shadowing``).
    others: Tuple[str, ...] = ()


def server_identity(tool: ToolInfo) -> str:
    """The server a tool comes from, for its local approval: ``server``, else ``serverInfo.name``,
    else "" (a plain function)."""
    if isinstance(tool.server, str) and tool.server:
        return tool.server
    n = (tool.server_info or {}).get("name")
    return n if isinstance(n, str) else ""


def approval_key(server: str, name: str) -> str:
    """The key of a local approval: the declared name alone for a tool with no server, else the
    pair ``["<server>","<name>"]`` as compact JSON (the TypeScript SDK writes the same text)."""
    return json.dumps([server, name], separators=(",", ":"), ensure_ascii=False) if server else name


def _is_approval(v: Any) -> bool:
    return isinstance(v, dict) and "description" in v and "schema" in v


def _keyed_pair(key: str) -> Optional[Tuple[str, str]]:
    """The server and tool name of a ``["<server>","<name>"]`` approval key, else None."""
    if not key.startswith('["'):
        return None
    try:
        v = json.loads(key)
    except ValueError:
        return None
    return (
        (v[0], v[1])
        if isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], str)
        else None
    )


def _keyed_tool(key: str) -> Optional[str]:
    """The tool name of a ``["<server>","<name>"]`` approval key, else None."""
    pair = _keyed_pair(key)
    return pair[1] if pair is not None else None


def shown_why(found: List[str]) -> str:
    """What a definition finding holds, in words (§8 hidden_instruction)."""
    parts = []
    hidden = [x for x in found if x in ("instruction_phrase", "invisible_characters")]
    if hidden:
        parts.append(f"holds hidden instructions ({', '.join(hidden)})")
    if "encoded_content" in found:
        parts.append("holds content it cannot read (encoded_content)")
    if "tool_shadowing" in found:
        parts.append("instructs about other tools (tool_shadowing)")
    if "look_alike_name" in found:
        parts.append("has a name that passes for another tool's (look_alike_name)")
    return " and ".join(parts) or f"holds hidden instructions ({', '.join(found)})"


def shown_definition(tool: ToolInfo) -> Any:
    """What the agent is shown of a tool, as the ``hidden_instruction`` check reads it: None when
    the client knows nothing of it but its name (a plain function)."""
    if tool.definition is not None:
        return tool.definition
    if not tool.description and tool.input_schema is None:
        return None
    return {"name": tool.name, "description": tool.description or "", "inputSchema": tool.input_schema}


@dataclasses.dataclass
class Plan:
    """The decision checks of one call (§8 steps 1 and 2)."""

    checks: dict
    strict: bool
    fail: Optional[str]
    timeout_ms: int
    disclosed: Optional[dict] = None
    disclosed_salt: Optional[str] = None
    #: The first entry that blocks the call, with the words of its error.
    blocked: Optional[CheckError] = None
    rules_version: Optional[int] = None
    #: Fields the held rule set needs for this call that the tool's ``disclose`` does not list.
    not_disclosed: List[str] = dataclasses.field(default_factory=list)
    #: The tool's declared name (§2.6), as the checks name it.
    declared: Optional[str] = None
    #: The checks file's ``fail`` for the tool, when it sets one.
    file_fail: Optional[str] = None
    #: A strict call the held rule set (in enforce mode) would block: the witness rules on it all
    #: the same; this applies only when there is no ruling (§8).
    held_block: Optional[CheckError] = None
    #: Notes for the caller (§8 notes): a possible hidden instruction in the call's arguments.
    notes: List[dict] = dataclasses.field(default_factory=list)
    #: The stale rules or list's grace period is over (§8): the call is refused (``rules_unavailable``)
    #: after its decision is written, as a strict call without a ruling.
    stale_blocked: Optional[str] = None
    #: What protects a strict call (``meta.protected_by``, §8, SDK 0.5.2): ``code``,
    #: ``checks_file``, ``console``, in that order; empty when the call is not strict.
    protected_by: List[str] = dataclasses.field(default_factory=list)


#: A protected call retries a failed request within its ruling timeout: first after this many ms,
#: doubling, at most ``RETRY_MAX_MS`` apart (§8).
RETRY_FIRST_MS = 250
RETRY_MAX_MS = 2_000


def quota_words(rec: Any, e: SignafaideError) -> str:
    """Why a protected call had no ruling when the witness refused its record for the project's
    allowance (``quota_exceeded``, ``plan_required``), and the fix, in one sentence."""
    sandbox = (rec.api_key or "").startswith("sfa_test_")
    claim = (rec.state.sandbox() or {}).get("claim_url") if sandbox else None
    site = site_of(rec.url)
    if e.code == "plan_required":
        return f"signafAIde could not rule on it: the project's plan does not include this ({e.message}). Upgrade the plan in the console ({site}/pricing)."
    if sandbox:
        where = f" at {claim}" if claim else " in the console"
        return (
            f"signafAIde could not rule on it: the sandbox's records for this month are used up (quota_exceeded). Keep the sandbox and choose a "
            f"plan{where}, or wait for next month; until then protected tools stop."
        )
    return (
        f"signafAIde could not rule on it: the project's records for this month are used up (quota_exceeded). Upgrade the plan in the console "
        f"({site}/pricing), or wait for next month; until then protected tools stop."
    )


def checks_path(root: Path) -> Optional[Path]:
    """The checks file: ``SIGNAFAIDE_CHECKS`` names another, ``SIGNAFAIDE_CHECKS=0`` turns checks off."""
    v = os.environ.get("SIGNAFAIDE_CHECKS", "").strip()
    if v in ("0", "false", "off", "no"):
        return None
    return Path(v) if v else root / CHECKS_FILE


def _write_pretty(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _write_jcs(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, dumps(value))


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _age(at: Optional[str]) -> str:
    if not at:
        return "unknown age"
    try:
        s = int(time.time() - parse_time(at).timestamp())
    except ValueError:
        return "unknown age"
    return f"{s} s old" if s < 120 else f"{s // 60} min old" if s < 7200 else f"{s // 3600} h old"


class ChecksState:
    """One recorder's tool-call checks."""

    def __init__(self, recorder: Any):
        self.rec = recorder
        self._lock = threading.RLock()
        self._file: Optional[Tuple[Path, Tuple[int, int, int], dict]] = (
            None  # path, (inode, size, mtime_ns), the version in force
        )
        self._file_error: Optional[str] = None  # the file is invalid and no good version is in force
        self._told: Optional[str] = None
        self._looked = 0.0
        #: What went wrong with the file, a fetched rule set or list update: name -> message.
        self.problems: Dict[str, str] = {}
        self._cache: Dict[str, Tuple[tuple, Any]] = {}  # path -> (stamp, what was made of the file)
        self._listed: Optional[Tuple[dict, set]] = None  # the held list and its (kind, fingerprint) pairs
        self._hashes: Dict[int, Tuple[dict, str]] = {}  # id(doc) -> (doc, hash_json(doc))
        self._thread: Optional[threading.Thread] = None
        #: The last fetch said the project has no rule set (§8, a strict call's fail mode).
        self._no_rule_set = False
        #: Fetch rounds the background fetcher has finished, to wait for the next one.
        self._rounds = 0
        self._round_done = threading.Condition()
        self._wake = threading.Event()
        self._stop = threading.Event()
        #: A call was checked: the shared list is fetched from then on (§8, SDK 0.5.2).
        self._planned = False
        #: Per tool, whether the held version protected it at its last call (the stderr line, §8).
        self._console_seen: Dict[str, bool] = {}

    # --- the checks file ----------------------------------------------------------------

    @property
    def home(self) -> Path:
        return self.rec.state.home / "checks"

    def path(self) -> Optional[Path]:
        return checks_path(self.rec.state.root)

    def file(self) -> Optional[dict]:
        """The checks file in force, or None when checks are off. Looked at at most once a
        second; a broken edit keeps the previous version in force and prints one error line. A
        file that is invalid with no earlier version in force raises ``state``."""
        with self._lock:
            path = self.path()
            if path is None:
                return None
            t = time.monotonic()
            if self._file is not None and self._file[0] == path and t - self._looked < 1.0:
                return self._file[2]
            if self._file is None and self._file_error is not None and t - self._looked < 1.0:
                raise CheckError(self._file_error, "state")
            self._looked = t
            try:
                st = path.stat()
            except OSError:
                self._file, self._file_error = None, None
                self.problems.pop("file", None)
                return None
            # inode, size and modification time, as the other held files: a file replaced within
            # one clock tick by another of the same size is still seen as changed.
            stamp = (st.st_ino, st.st_size, st.st_mtime_ns)
            if self._file is not None and self._file[0] == path and self._file[1] == stamp:
                return self._file[2]
            try:
                doc = json.loads(path.read_text())
                err = C.checks_file_errors(doc)
            except (OSError, ValueError) as e:
                doc, err = None, f"not valid JSON ({e})"
            if err is None:
                self._file, self._file_error = (path, stamp, doc), None
                self.problems.pop("file", None)
                self._told = None
                return doc
            msg = f"the checks file {path} is invalid: {err}"
            self.problems["file"] = msg
            if self._file is not None and self._file[0] == path:
                if self._told != msg:
                    self._told = msg
                    print(f"signafaide: {msg}; the previous version stays in force until it is fixed", file=sys.stderr)
                return self._file[2]
            self._file_error = msg + " (spec §8); fix it, or set SIGNAFAIDE_CHECKS=0 to turn checks off"
            raise CheckError(self._file_error, "state")

    def enabled(self, protect: bool = False, tool: Optional[str] = None) -> bool:
        """Whether checks are on: a checks file exists (valid or not). With *protect* (a tool
        protected in code) they are on unless ``SIGNAFAIDE_CHECKS=0`` turns them off: without a
        checks file such a tool runs every check in On, as ``init`` would write them (§8). The
        same holds for *tool* when the held rule set protects it from the console (SDK 0.5.2)."""
        p = self.path()
        return p is not None and (protect or p.exists() or (tool is not None and self.console_protects(tool)))

    def console_protects(self, tool: str) -> bool:
        """Whether the held rule set protects *tool* (a declared name) from the console (§8, SDK
        0.5.2). Never while checks are off."""
        if self.path() is None:
            return False
        # A held copy that is broken still protects what it protected when last verified (§8).
        rs = self.held_rules()
        return self._protects(rs if rs is not None else self._broken_protect(), tool)

    def console_protects_any(self) -> bool:
        """Whether the held rule set protects any tool from the console."""
        if self.path() is None:
            return False
        rs = self.held_rules()
        if rs is None:
            rs = self._broken_protect()
        return bool(rs) and ((isinstance(rs.get("protect"), dict) and bool(rs["protect"])) or rs.get("unknown") is True)

    def observe_console(
        self, tool: str, protected_now: bool, version: Optional[int], others: Optional[List[str]] = None
    ) -> None:
        """The stderr line of §8 (development only): the first call of a tool after the held
        version starts or stops protecting it from the console. *others*: what else protects it."""
        with self._lock:
            before = self._console_seen.get(tool)
            self._console_seen[tool] = protected_now
        if not development(self.rec):
            return
        if protected_now and before is not True:
            print(f"signafaide: {tool} is now protected from the console (rule set version {version})", file=sys.stderr)
        elif not protected_now and before is True:
            stays = f"; it stays protected {C.source_words(others)}" if others else ""
            v = version if version is not None else "none"
            print(
                f"signafaide: {tool} is no longer protected from the console (rule set version {v}){stays}",
                file=sys.stderr,
            )

    def start_wait(self) -> None:
        """A call that starts while no rule set version is held and the first fetch of this
        process is running waits for that fetch, at most ``RULES_START_WAIT_MS`` (§8, SDK 0.5.2)."""
        if self.rec.test or not self.rec.api_key or self.path() is None:
            return
        self.start()
        with self._round_done:
            if self._rounds > 0 or self.held_rules_item() is not None:
                return
            self._round_done.wait_for(lambda: self._rounds > 0, timeout=C.RULES_START_WAIT_MS / 1000)

    def wrapped_state(self, tool: str) -> str:
        """Whether this program has shown *tool* to signafAIde (§8, SDK 0.5.2): ``wrapped`` (a
        declaration lists it as recorded, or a call of it was seen in this process),
        ``unrecorded`` (declared as not recorded), or ``unseen``."""
        if tool in self._console_seen:
            return "wrapped"
        unrecorded = False
        try:
            for agent in self.rec.state.agents():
                for tools in self.rec.state.tool_sources(agent).values():
                    for n, r in tools.items():
                        if declared_name(n) != tool:
                            continue
                        if r:
                            return "wrapped"
                        unrecorded = True
        except Exception:  # noqa: BLE001 - no tool list held
            pass
        return "unrecorded" if unrecorded else "unseen"

    def file_for(self, protect: bool, tool: Optional[str] = None) -> Optional[dict]:
        """The checks file in force; for a tool protected in code (or from the console, *tool*)
        with no checks file, the one ``init`` writes with every check On (enforce): its calls are
        checked here and ruled by the witness all the same (§8)."""
        f = self.file()
        if f is None and (protect or (tool is not None and self.console_protects(tool))) and self.path() is not None:
            f = C.default_checks_file()
            f["mode"] = "enforce"
            f["_default"] = True
        return f

    def _other_sources(self, f: Optional[dict], tool: str, by_code: bool) -> List[str]:
        out = ["code"] if by_code else []
        if f is not None and not f.get("_default") and C.tool_settings(f, tool)["strict"]:
            out.append("checks_file")
        return out

    # --- held state ---------------------------------------------------------------------

    def project_env(self) -> Optional[Tuple[str, str]]:
        api_key = self.rec.api_key
        if not api_key:
            return None
        bucket = self.rec.state.bucket(api_key)
        if bucket.startswith("_pending/"):
            return None
        p, e = bucket.split("/")
        return p, e

    def _stamped(self, path: Path, load: Callable[[], Any], extra: tuple = ()) -> Any:
        """``load()`` for the file at *path*, kept until the file changes (its inode, size or
        modification time): a call costs one ``stat``, not a read, a parse and a check of
        everything the file holds. Not kept when ``load`` returns None."""
        key = str(path)
        try:
            st = os.stat(path)
        except OSError:
            self._cache.pop(key, None)
            return load()
        stamp = (st.st_ino, st.st_size, st.st_mtime_ns) + extra
        hit = self._cache.get(key)
        if hit is not None and hit[0] == stamp:
            return hit[1]
        value = load()
        if value is None:
            self._cache.pop(key, None)
        else:
            self._cache[key] = (stamp, value)
        return value

    def _hash(self, doc: dict) -> str:
        """``hash_json(doc)``, made once for each parsed copy of a rule set or of the local rules."""
        hit = self._hashes.get(id(doc))
        if hit is None or hit[0] is not doc:
            if len(self._hashes) > 64:
                self._hashes.clear()
            hit = self._hashes[id(doc)] = (doc, hash_json(doc))
        return hit[1]

    def _pinned(self) -> bool:
        """Whether the witness is the default one, whose keys are pinned (``DEFAULT_SERVICE_KEYS``)."""
        return self.rec.url == DEFAULT_URL

    def _keys_file(self) -> Dict[str, dict]:
        """``checks/keys.json``: per witness URL, the keys, the revoked ids, when the key list was last
        tried (``tried``, ``failed`` when that try failed) and the hash of the pinned keys it was read
        with (``pinned``: another release's entry counts as never fetched). A file from before it held
        one witness (``{keys, revoked?, fetched, url?}``) is read as that witness's entry."""
        doc = _read(self.home / "keys.json")
        if not isinstance(doc, dict):
            return {}

        def entry(e: dict) -> dict:
            out: dict = {
                "keys": e["keys"] if isinstance(e.get("keys"), list) else [],
                "revoked": [x for x in e.get("revoked") or [] if isinstance(x, str)]
                if isinstance(e.get("revoked"), list)
                else [],
            }
            if isinstance(e.get("tried"), str):
                out["tried"] = e["tried"]
            if e.get("failed") is True:
                out["failed"] = True
            if isinstance(e.get("pinned"), str):
                out["pinned"] = e["pinned"]
            return out

        if isinstance(doc.get("witnesses"), dict):
            return {u: entry(e) for u, e in doc["witnesses"].items() if isinstance(e, dict)}
        if not isinstance(doc.get("keys"), list):
            return {}
        return {doc["url"] if isinstance(doc.get("url"), str) else self.rec.url: entry(doc)}

    def _edit_keys_entry(self, fn: Callable[[dict], dict]) -> None:
        """Change this witness's entry under the keys file's lock, keeping every other witness's."""
        path = self.home / "keys.json"
        with self._lock, self.rec.state._lock_at(path.with_suffix(".lock")):
            all_ = self._keys_file()
            all_[self.rec.url] = fn(all_.get(self.rec.url) or {"keys": [], "revoked": []})
            _write_pretty(path, {"witnesses": all_})

    def _held_keys(self) -> dict:
        """This witness's entry in ``checks/keys.json``: the keys and the revoked ids last fetched."""
        url = self.rec.url

        def load() -> Optional[dict]:
            e = self._keys_file().get(url)
            return {"keys": e["keys"], "revoked": e["revoked"]} if e else None

        return self._stamped(self.home / "keys.json", load, (url,)) or {"keys": [], "revoked": []}

    def revoked_keys(self) -> List[str]:
        """The revoked service key ids held for the witness (§5): the pinned ones for the default
        witness, and those its published list named when it was last fetched."""
        out = list(DEFAULT_REVOKED) if self._pinned() else []
        return out + [x for x in self._held_keys()["revoked"] if x not in out]

    def all_service_keys(self) -> List[dict]:
        """Every service key held for the witness, revoked ones too (key_problem names them revoked):
        the pinned ones for the default witness (a fetched list never adds a key to them)."""
        if self._pinned():
            return [dict(k) for k in DEFAULT_SERVICE_KEYS]
        return [dict(k) for k in self._held_keys()["keys"]]

    def service_keys(self) -> List[dict]:
        """The witness's service keys (§5) that may verify: ``all_service_keys`` without the revoked ones."""
        revoked = self.revoked_keys()
        return [k for k in self.all_service_keys() if k.get("key_id") not in revoked]

    def _rules_path(self, pe: Tuple[str, str]) -> Path:
        return self.home / "rules" / pe[0] / f"{pe[1]}.json"

    def _rules_held(self, pe: Tuple[str, str]) -> Optional[Tuple[Optional[dict], str]]:
        """The held rule set file of *pe* judged with the keys held now (cached until it or the keys
        change): ``ok``; ``revoked`` or ``not_held`` (its signer is revoked or no longer among the keys
        held: enforced as it is during the grace period, §8); ``broken`` (unreadable or failing its
        own signature: never enforced, never dropped, protected calls are refused until a pull
        verifies). None when none is held."""
        path = self._rules_path(pe)
        if not path.exists():
            return None
        try:
            ks = os.stat(self.home / "keys.json")
            extra: tuple = (ks.st_ino, ks.st_size, ks.st_mtime_ns)
        except OSError:
            extra = ()

        def load() -> Tuple[Optional[dict], str]:
            doc = _read(path)
            if not isinstance(doc, dict):
                return None, "broken"
            if C.accept_rules(None, doc, self.service_keys(), pe[0], pe[1]) is None:
                return doc, "ok"
            kid = str(doc.get("service_key_id"))
            if (
                kid in self.revoked_keys()
                and C.accept_rules(None, doc, self.all_service_keys(), pe[0], pe[1], ()) is None
            ):
                return doc, "revoked"
            if not any(k.get("key_id") == kid for k in self.all_service_keys()) and (
                C.accept_rules(None, doc, [], pe[0], pe[1]) == "signature"
            ):
                return doc, "not_held"
            return None, "broken"

        h = self._stamped(path, load, extra + (self.rec.url, ",".join(self.revoked_keys())))
        # The protect record follows every verified copy read (a revoked signer's too), §8.
        if h and h[1] in ("ok", "revoked"):
            self._sync_protect(pe, h[0])
        return h

    def held_rules_item(self) -> Optional[dict]:
        """The held rule set version ``{rules, sig, service_key_id}`` (§8): verified, or stale and in
        its grace period's keeping; None when none is held or it is broken."""
        pe = self.project_env()
        h = self._rules_held(pe) if pe else None
        return h[0] if h else None

    def _listed_pairs(self, held: dict) -> set:
        """The pairs of a held list as a set, made once for each version of the list read."""
        if self._listed is None or self._listed[0] is not held:
            self._listed = (held, C.listed_pairs(held["entries"]))
        return self._listed[1]

    def held_rules(self) -> Optional[dict]:
        item = self.held_rules_item()
        return item["rules"] if item else None

    def _list_held(self) -> Optional[Tuple[Optional[dict]]]:
        """The held shared list file: ``(list,)``, or ``(None,)`` when broken (unreadable or invalid:
        never used, never dropped; protected calls are refused until a pull verifies one, §8)."""
        path = self.home / "fingerprints.json"
        if not path.exists():
            return None

        def load() -> Tuple[Optional[dict]]:
            doc = _read(path)
            return (doc,) if doc is not None and not C.held_list_errors(doc) else (None,)

        return self._stamped(path, load)

    def held_list(self) -> Optional[dict]:
        """The held shared list ``{seq, last, entries}``; None when none is held or it is broken."""
        h = self._list_held()
        return h[0] if h else None

    def _approved_path(self, agent: str) -> Path:
        return self.home / "approved" / f"{agent}.json"

    def approvals(self, agent: str) -> Dict[str, dict]:
        path = self._approved_path(agent)
        doc = self._stamped(path, lambda: (lambda d: d if isinstance(d, dict) else None)(_read(path)))
        return dict(doc) if doc else {}  # a copy: callers edit it, and the file is what changes the cache

    def approved_names(self, agent: str, tool: ToolInfo, declared: str) -> List[str]:
        """The names of the tools approved earlier for *agent* and the server *tool* comes from
        (local approvals), as the tool's own name is written (without the part of *declared*
        before it, a gateway's prefix), for ``look_alike_name`` (§8 hidden_instruction)."""
        if not tool.name or not declared.endswith(tool.name):
            return []
        prefix = declared[: len(declared) - len(tool.name)]
        server = server_identity(tool)
        out: List[str] = []
        for key in self.approvals(agent):
            pair = _keyed_pair(key)
            n = key if pair is None else (pair[1] if pair[0] == server else None)
            if n is not None and n.startswith(prefix):
                out.append(n[len(prefix) :])
        return out

    def _look_alike_of(self, on: dict, agent: str, tool: ToolInfo, declared: str) -> Tuple[List[str], bool]:
        """The tool's look-alike context (§8 ``look_alike_name``): the tools approved earlier, and
        whether its name passes for one of them or of the tools listed with it."""
        if not on["hidden_instruction"] or not tool.name:
            return [], False
        approved = self.approved_names(agent, tool, declared)
        return approved, scan.look_alike_name(tool.name, tool.others, approved)

    def _approval_for(
        self, rs: Optional[dict], agent: str, tool: ToolInfo, declared: str, fps: dict, look_alike: bool
    ) -> Optional[dict]:
        """What ``changed_tool`` compares a tool with: the held rule set's approval, else its local
        approval, written the first time, except for a tool whose name passes for another's, which
        is never approved (its own ``look_alike_name`` finding says why)."""
        if rs is not None and rs.get("approved") is not None:
            return rs["approved"].get(declared)
        if not look_alike:
            return self.local_approval(agent, server_identity(tool), declared, fps)
        have = self.approvals(agent).get(approval_key(server_identity(tool), declared))
        return have if _is_approval(have) else {"description": fps["description"], "schema": fps["schema"]}

    def local_approval(self, agent: str, server: str, name: str, fps: dict) -> dict:
        """A tool's local approval (§8): its fingerprints the first time the client sees it, kept
        per agent, server and tool name. An approval written before servers were part of the key
        (the bare tool name) belongs to the first server that asks for that name."""
        key = approval_key(server, name)
        have = self.approvals(agent).get(key)
        if _is_approval(have):
            return have
        path = self._approved_path(agent)
        with self.rec.state._lock_at(path.with_suffix(".lock")):
            doc = self.approvals(agent)
            if key not in doc:
                if key != name and _is_approval(doc.get(name)):
                    doc[key] = doc.pop(name)  # migrated: the old key is this server's
                else:
                    doc[key] = {"description": fps["description"], "schema": fps["schema"], "at": now()}
                _write_pretty(path, doc)
            return doc[key]

    def approve(self, name: str, agent: Optional[str] = None) -> List[str]:
        """``signafaide checks approve <tool>``: drop the tool's local approvals (every server's),
        so its next call approves the description and schema it has then. Returns the agents it
        was dropped for."""
        root = self.home / "approved"
        agents = [agent] if agent else [p.stem for p in sorted(root.glob("*.json"))] if root.is_dir() else []
        done = []
        for a in agents:
            path = self._approved_path(a)
            with self.rec.state._lock_at(path.with_suffix(".lock")):
                doc = self.approvals(a)
                keys = [k for k in doc if k == name or _keyed_tool(k) == name]
                if keys:
                    for k in keys:
                        del doc[k]
                    _write_pretty(path, doc)
                    done.append(a)
        return done

    # --- fetching (§8, §10.2, §11.2) ----------------------------------------------------

    def stop(self) -> None:
        """Stop the background fetcher: it ends at once (a fetch in flight finishes first)."""
        self._stop.set()
        self._wake.set()

    def start(self) -> None:
        """Fetch the rule set and the list now and every 60 s in the background (with an API key)."""
        if self.rec.test or not self.rec.api_key or self.path() is None:
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive() and not self._stop.is_set():
                return
            if self._thread is not None and self._thread.is_alive():
                return  # a stopped fetcher still finishing: never two
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="signafaide-checks", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        # A stopped recorder's fetcher stops too, so it never fetches for a program that ended.
        while not self._stop.is_set() and not getattr(self.rec, "_stopped", False):
            try:
                self.refresh()
            except Exception as e:  # noqa: BLE001 - the refresher never stops a program
                log.debug("signafaide: checks refresh failed: %s", e)
            with self._round_done:
                self._rounds += 1
                self._round_done.notify_all()
            self._wake.wait(C.RULES_REFRESH_MS / 1000)
            self._wake.clear()

    def wake(self) -> None:
        self._wake.set()

    def refresh(self) -> None:
        if not self.rec.api_key:
            return
        self.fresh_keys()
        force_rules, self._force_rules = self._force_rules, False

        def rules() -> str:
            return self.pull_rules(force=force_rules)

        for name, fn in (("rules", rules), ("fingerprints", self.pull_list)):
            # Without a checks file the rule set is fetched for `protect` (§8); the shared list
            # only once a call is checked (a checks file, a tool protected in code or from the console).
            if name == "fingerprints" and not self._planned and not self.enabled() and not self.console_protects_any():
                continue
            try:
                fn()
            except SignafaideError as e:
                if e.code not in ("network", "rate_limited") and e.status < 500:
                    self.problems[name] = (
                        f"could not fetch the {'rule set' if name == 'rules' else 'shared fingerprint list'}: {e.message}"
                    )

    def forced_pull(self) -> str:
        """``signafaide pull`` and ``signafaide rules pull``: the key list, the rule set and the shared
        list, all fetched now whatever any wait says (§8). Returns the rule set's words."""
        self.fresh_keys("force")
        said = self.pull_rules(force=True)
        try:
            self.pull_list(force=True)
        except SignafaideError as e:
            if e.code not in ("network", "rate_limited") and e.status < 500:
                self.problems["fingerprints"] = f"could not fetch the shared fingerprint list: {e.message}"
        return said

    def fresh_keys(self, mode: str = "normal") -> None:
        """The published key list (its revoked ids above all), for every witness, the default one
        too: read again ``KEYS_REFRESH_MS`` after a good read and ``KEYS_RETRY_MS`` after a failed one
        (one on-disk ``tried``, shared by every process; an entry read with other pinned keys counts as
        never read). ``soon``: a signature that does not verify reads it again after ``KEYS_RETRY_MS``;
        ``force``: now. One read at a time in a process."""
        with self._keys_fetch:
            if mode != "force":
                e = self._keys_file().get(self.rec.url) or {}
                at = _epoch_ms(e.get("tried")) if e.get("pinned") == _PINNED_HASH else None
                now_ms = _now_ms()
                if at is not None and at > now_ms:
                    # A time in the future counts as now (written back), never as a wait without end.
                    at = now_ms
                    self._edit_keys_entry(lambda x: {**x, "tried": _iso(now_ms)})
                wait = KEYS_RETRY_MS if mode == "soon" or e.get("failed") else KEYS_REFRESH_MS
                if at is not None and now_ms - at < wait:
                    return
            try:
                self.pull_keys()
            except (SignafaideError, ValueError, OSError):
                pass  # the keys and revoked ids held stay

    _keys_fetch = threading.Lock()

    def pull_keys(self) -> List[dict]:
        """Read the witness's key list (§5) once. Revocations are never refused: from any valid keys
        document the client keeps exactly the revoked ids that name a key it holds for that witness
        (for the default witness also up to ``MAX_UNPINNED_REVOKED`` naming keys not pinned yet), never
        drops one, and ignores the rest. Keys: the default witness's stay the pinned ones; a
        self-hosted witness's are merged, never dropped, up to ``MAX_WITNESS_KEYS``; a document that
        drops or changes a key held, or would pass the limit, has its key changes refused (its
        revocations still apply)."""
        failed = lambda x: {**x, "tried": _iso(_now_ms()), "failed": True, "pinned": _PINNED_HASH}  # noqa: E731
        try:
            doc = self.rec.client(timeout=10.0).service_keys()
        except SignafaideError:
            self._edit_keys_entry(failed)
            if self._pinned():
                return self.service_keys()
            raise
        try:
            if not (isinstance(doc, dict) and isinstance(doc.get("keys"), list)):
                raise ValueError("not a keys document")
            new_keys, new_revoked = load_service_key_set(doc)
        except ValueError:
            self.problems["keys"] = (
                f"bad_response: the service keys of {self.rec.url} are not a valid keys document (spec §5); kept the keys held"
            )
            self._edit_keys_entry(failed)
            return self.service_keys()
        refused: List[str] = []

        def edit(x: dict) -> dict:
            keys = [dict(k) for k in DEFAULT_SERVICE_KEYS] if self._pinned() else list(x["keys"])
            if not self._pinned():
                ids = {k["key_id"]: k for k in new_keys}
                merged = [
                    ids[k["key_id"]]
                    if k.get("key_id") in ids and ids[k["key_id"]]["public_key"] == k.get("public_key")
                    else k
                    for k in keys
                ]
                merged += [n for n in new_keys if not any(k.get("key_id") == n["key_id"] for k in merged)]
                if any(k.get("key_id") not in ids for k in keys):
                    refused.append("drop a key held")
                elif any(
                    k.get("key_id") in ids and ids[k["key_id"]]["public_key"] != k.get("public_key") for k in keys
                ):
                    refused.append("change a key held")
                elif len(merged) > MAX_WITNESS_KEYS:
                    refused.append(f"name more than {MAX_WITNESS_KEYS} keys")
                if not refused:
                    keys = merged
            held = {k.get("key_id") for k in keys}
            revoked = list(x["revoked"])
            unpinned = sum(1 for r in revoked if r not in held)
            for r in new_revoked:
                if r in revoked:
                    continue
                if r in held:
                    revoked.append(r)
                elif self._pinned() and unpinned < MAX_UNPINNED_REVOKED:
                    revoked.append(r)
                    unpinned += 1
            return {"keys": keys, "revoked": revoked, "tried": _iso(_now_ms()), "pinned": _PINNED_HASH}

        self._edit_keys_entry(edit)
        if refused:
            self.problems["keys"] = (
                f"bad_response: refused the key changes of {self.rec.url}: they {refused[0]} (spec §8); kept the keys held, applied its revocations"
            )
        else:
            self.problems.pop("keys", None)
        return self.service_keys()

    def _refused_item(self, kind: str, pe: Optional[Tuple[str, str]], step: str, item: Any, offered: Any) -> str:
        """A refused signed item (§8): the clock starts if something is held, the refusal is kept for
        the words, the next fetch waits."""
        kid = str(item["service_key_id"]) if isinstance(item, dict) and item.get("service_key_id") is not None else None
        unknown = (
            step == "signature" and kid is not None and not any(k.get("key_id") == kid for k in self.all_service_keys())
        )
        refused = {"cause": "unknown_key" if unknown else "step", "step": step, "key_id": kid, "offered": offered}
        self._edit_state(kind, {"type": "refused", "refused": refused}, pe)
        info = self.stale_info(kind, pe)
        held = f": {info['words']}" if info else ""
        if kind == "rules":
            msg = f"bad_response: refused rule set version {offered if offered is not None else '?'} at step {step} (spec §10.2); kept the version held{held}"
            self.problems["rules"] = msg
        else:
            msg = f"bad_response: refused a shared list item at step {step} (spec §11.2); kept the list held{held}"
            self.problems["fingerprints"] = msg
        return msg

    def pull_rules(self, force: bool = False) -> str:
        """Fetch the rule set now (§10.2). *force*: a person asked (no retry wait). Returns what
        happened, in words."""
        api_key = self.rec.api_key
        if not api_key:
            return "no API key: rule sets need one"
        self.rec.resolve_project(api_key)
        pe = self.project_env()
        if pe is None:
            return "the API key's project is not known yet"
        if not force and self._retrying("rules"):
            return self.problems.get("rules") or "the rule set is not fetched again yet"
        stale_before = self.stale_info("rules", pe) is not None
        held = self.held_rules_item()
        # While stale, fetched whole: a refused copy of the version held (a glitch) clears when its verified copy comes again.
        item = self.rec.client(timeout=10.0).rules(etag=hash_json(held["rules"]) if held and not stale_before else None)

        def done(said: str) -> str:
            if stale_before:
                self._edit_state("rules", {"type": "pull_done", "stale_before": True}, pe)
            return said

        if item is None or not isinstance(item, dict) or item.get("rules") is None:
            # An unsigned answer (current, or no rule set): nothing starts or clears a clock.
            self.problems.pop("rules", None)
            self._no_rule_set = held is None
            if item is None:
                return done(f"rule set version {held['rules']['version']} is current" if held else "no rule set")
            return done(f"kept rule set version {held['rules']['version']}" if held else "the project has no rule set")
        self._no_rule_set = False
        self.fresh_keys()

        def verdict() -> Optional[str]:
            h = self._rules_held(pe)
            base = None if h is None or h[1] == "broken" or held is None else held["rules"]
            return C.accept_rules(base, item, self.service_keys(), pe[0], pe[1])

        err = verdict()
        if err == "signature":
            self.fresh_keys("soon")
            err = verdict()
        if err is not None:
            v = item["rules"].get("version") if isinstance(item.get("rules"), dict) else "?"
            return done(self._refused_item("rules", pe, err, item, v))
        self._commit_verified("rules", pe, item, [str(item.get("service_key_id"))])
        self.problems.pop("rules", None)
        return f"rule set version {item['rules']['version']}"

    def keep_rules(self, item: dict) -> bool:
        """Keep a version the client was handed (a publish's answer) as the held version, when §10.2
        accepts it over the version held, through the one function that clears (§8)."""
        self.fresh_keys()
        pe = self.project_env()
        if pe is None or not isinstance(item, dict):
            return False
        held = self.held_rules()
        if C.accept_rules(held, item, self.service_keys(), pe[0], pe[1]) is not None:
            return False
        self._commit_verified("rules", pe, item, [str(item.get("service_key_id"))])
        self._no_rule_set = False
        self.problems.pop("rules", None)
        return True

    def forget(self) -> None:
        """Look at the checks file again at the next call."""
        self._looked = float("-inf")

    def pull_list(self, force: bool = False) -> str:
        """Fetch the shared fingerprint list now (§11.2). The list is written once, at the end of a
        clean pull whose signers are not revoked; a held list that is stale, broken or of unknown
        signers (an older release's) is fetched again from a snapshot and stays until one verifies."""
        if not self.rec.api_key:
            return "no API key: the shared list needs one"
        if not force and self._retrying("list"):
            return self.problems.get("fingerprints") or "the shared list is not fetched again yet"
        client = self.rec.client(timeout=10.0)
        self.fresh_keys()
        if not self.service_keys():
            self.fresh_keys("soon")
        keys = self.service_keys()
        stale_before = self.stale_info("list", None) is not None
        held = self.held_list()
        live = self._live_state("list", None)
        known = live["held"].get("key_ids") if live and isinstance(live["held"].get("key_ids"), list) else None
        base = held if held and known is not None and not stale_before else None

        def done(said: str) -> str:
            if stale_before:
                self._edit_state("list", {"type": "pull_done", "stale_before": True}, None)
            return said

        cur = base or C.empty_list()
        since = base["seq"] if base else None
        signers = set(known or []) if base else set()
        fresh, snapshot_ok, keys_again, complete = base is None, False, False, False
        rounds = 0
        while rounds < 100 and not complete:
            rounds += 1
            resp = client.fingerprints(since=since)
            if isinstance(resp, dict) and resp.get("reset") is True:
                if not resp.get("snapshot"):
                    return done(self._refused_item("list", None, "reset", None, None))  # a reset without its snapshot
                cur, fresh, snapshot_ok = {**C.empty_list(), "seq": base["seq"] if base else 0}, True, False
                signers.clear()
            updates = list((resp or {}).get("updates") or []) if isinstance(resp, dict) else []
            items = ([resp["snapshot"]] if isinstance(resp, dict) and resp.get("snapshot") else []) + updates
            gap = False
            for it in items:
                nxt, err = C.apply_list(cur, it, keys)
                if err == "signature" and not keys_again:
                    keys_again = True
                    self.fresh_keys("soon")
                    keys = self.service_keys()
                    nxt, err = C.apply_list(cur, it, keys)
                if err == "gap":
                    gap = True
                    break
                if err is not None:
                    seq = it["list"].get("seq") if isinstance(it, dict) and isinstance(it.get("list"), dict) else None
                    return done(self._refused_item("list", None, err, it, seq))
                if (
                    fresh
                    and isinstance(it, dict)
                    and isinstance(it.get("list"), dict)
                    and it["list"].get("type") == "snapshot"
                ):
                    snapshot_ok = True
                if isinstance(it, dict) and it.get("service_key_id") is not None:
                    signers.add(str(it["service_key_id"]))
                cur = nxt
            if gap or len(updates) >= 1000:
                since = cur["seq"]
            else:
                complete = True
        if not complete:
            return done(self._refused_item("list", None, "rounds", None, cur["seq"]))  # never a success
        if fresh and not snapshot_ok:
            self.problems.pop("fingerprints", None)
            return done(f"kept shared list seq {held['seq']}" if held else "no shared list")
        if base is not None and cur is base:
            self.problems.pop("fingerprints", None)
            return done(f"shared list seq {cur['seq']} is current")
        revoked = self.revoked_keys()
        bad = next((k for k in sorted(signers) if k in revoked), None)
        if bad:
            return done(self._refused_item("list", None, "revoked", {"service_key_id": bad}, cur["seq"]))
        self._commit_verified("list", None, cur, sorted(signers))
        self.problems.pop("fingerprints", None)
        return f"shared list seq {cur['seq']}"

    # --- stale rules and list (§8): one state file per held object ------------------------------

    def _state_path(self, kind: str, pe: Optional[Tuple[str, str]]) -> Optional[Path]:
        """``checks/rules/<project>/<env>.state.json`` or ``checks/fingerprints.state.json``."""
        if kind == "list":
            return self.home / "fingerprints.state.json"
        return self.home / "rules" / pe[0] / f"{pe[1]}.state.json" if pe else None

    def _held_id(self, kind: str, pe: Optional[Tuple[str, str]]) -> Optional[dict]:
        """What identifies the held object on disk: a rule set's version and signer, a list's seq and
        last; None when none is held or it is broken."""
        if kind == "rules":
            h = self._rules_held(pe) if pe else None
            if not h or h[0] is None:
                return None
            return {"version": h[0]["rules"]["version"], "key_ids": [str(h[0].get("service_key_id"))]}
        lst = self.held_list()
        return {"seq": lst["seq"], "last": lst["last"]} if lst else None

    def _live_state(self, kind: str, pe: Optional[Tuple[str, str]]) -> Optional[dict]:
        """The state file, when it belongs to this witness and the object held now (a state file left
        by a crash before it was rewritten, or another witness's, counts as none)."""
        p = self._state_path(kind, pe)
        doc = _read(p) if p else None
        hid = self._held_id(kind, pe)
        if (
            not isinstance(doc, dict)
            or doc.get("witness") != self.rec.url
            or not isinstance(doc.get("held"), dict)
            or not hid
        ):
            return None
        h = doc["held"]
        if kind == "rules":
            same = h.get("version") == hid["version"] and h.get("key_ids") == hid["key_ids"]
        else:
            same = h.get("seq") == hid["seq"] and h.get("last") == hid["last"]
        return doc if same else None

    def _edit_state(
        self, kind: str, ev: dict, pe: Optional[Tuple[str, str]], extra: Optional[Callable[[dict], None]] = None
    ) -> None:
        """Apply one event to the state file under its lock (a state file that is not live starts
        fresh, naming the object held now)."""
        p = self._state_path(kind, pe)
        if p is None:
            return
        with self._lock, self.rec.state._lock_at(p.with_suffix(".lock")):
            hid = self._held_id(kind, pe)
            raw = _read(p)
            live = self._live_state(kind, pe)
            if (
                live is None
                and hid is None
                and isinstance(raw, dict)
                and raw.get("witness") == self.rec.url
                and raw.get("held") is None
            ):
                live = raw  # nothing held: the retry wait still counts on
            list_keys = (
                live["held"].get("key_ids") if kind == "list" and live and isinstance(live.get("held"), dict) else None
            )
            d = live or {"witness": self.rec.url, "held": hid, "sdk": __version__, "stale": None, "retry": None}
            if kind == "list" and hid:
                d["held"] = {**hid, "key_ids": list_keys if isinstance(list_keys, list) else None}
            st = d.get("stale") if isinstance(d.get("stale"), dict) else {}
            nxt = stale_transition(
                {
                    "since": st.get("since"),
                    "refused": st.get("refused"),
                    "retry": d.get("retry"),
                    "confirmed": st.get("confirmed") is True,
                },
                ev,
                _iso(_now_ms()),
                hid is not None,
            )
            same = nxt["since"] == st.get("since")
            if nxt["since"]:
                d["stale"] = {
                    "since": nxt["since"],
                    "refused": nxt["refused"],
                    "noted": st.get("noted") if same and isinstance(st.get("noted"), list) else [],
                    "said": st.get("said") if same else None,
                }
                if nxt.get("confirmed"):
                    d["stale"]["confirmed"] = True
            elif nxt["refused"]:
                d["stale"] = {"since": None, "refused": nxt["refused"], "noted": [], "said": None}
            else:
                d["stale"] = None
            d["retry"] = nxt["retry"]
            if ev.get("type") == "refused":
                d["sdk"] = __version__
            if extra:
                extra(d)
            _write_pretty(p, d)

    def _commit_verified(self, kind: str, pe: Optional[Tuple[str, str]], obj: dict, key_ids: List[str]) -> None:
        """The one function that clears: write a verified object, then a fresh state file naming it."""
        p = self._state_path(kind, pe)
        if p is None:
            return
        with self._lock, self.rec.state._lock_at(p.with_suffix(".lock")):
            if kind == "rules":
                assert pe is not None
                # The copy first, then its protect record: a crash between leaves the record behind
                # the copy (refreshed from it at the next read), never ahead.
                _write_jcs(self._rules_path(pe), {k: obj[k] for k in ("rules", "sig", "service_key_id")})
                with self.rec.state._lock_at(self._protect_path(pe).with_suffix(".lock")):
                    self._save_protect(pe, obj)
                _write_pretty(self.home / "rules" / pe[0] / f"{pe[1]}.at.json", {"fetched": now()})
                held: dict = {"version": obj["rules"]["version"], "key_ids": key_ids}
            else:
                _write_pretty(
                    self.home / "fingerprints.json", {"seq": obj["seq"], "last": obj["last"], "entries": obj["entries"]}
                )
                _write_pretty(self.home / "fingerprints.at.json", {"fetched": now()})
                held = {"seq": obj["seq"], "last": obj["last"], "key_ids": sorted(set(key_ids))}
            _write_pretty(p, {"witness": self.rec.url, "held": held, "sdk": __version__, "stale": None, "retry": None})

    _force_rules = False

    def _may_force(self, version: Any) -> bool:
        """Whether a ruling naming *version* may force a fetch now (§8): at most one per version per
        ``RULES_REFRESH_MS``, and at most ``MAX_FORCED_PER_INTERVAL`` in all in that time, counted in
        the rule set's state file (``forced``: the last forced fetch per version, the latest few
        kept)."""
        ok = [False]

        def edit(d: dict) -> None:
            now_ms = _now_ms()
            f: Dict[str, str] = {}
            for k, v in (d.get("forced") or {}).items() if isinstance(d.get("forced"), dict) else ():
                t = _epoch_ms(v) if isinstance(v, str) else None
                if t is not None:
                    f[k] = _iso(min(t, now_ms))  # a time in the future counts as now

            def within(t: str) -> bool:
                return now_ms - (_epoch_ms(t) or 0) < C.RULES_REFRESH_MS

            key = str(version)
            if not (key in f and within(f[key])) and sum(1 for t in f.values() if within(t)) < MAX_FORCED_PER_INTERVAL:
                f[key] = _iso(now_ms)
                ok[0] = True
            d["forced"] = dict(sorted(f.items(), key=lambda kv: -(_epoch_ms(kv[1]) or 0))[:MAX_FORCED_KEPT])

        self._edit_state("rules", {"type": "resaved"}, self.project_env(), edit)
        return ok[0]

    def protection_unknown(self, pe: Any = "current") -> bool:
        """Whether the held rule set is broken and nobody knows which tools it protected (§8):
        every checked call is refused."""
        b = self._broken_protect(pe)
        return bool(b and b.get("unknown"))

    def _protection_rs(self, tool: str) -> Optional[dict]:
        """The rule set ``C.protection`` judges a tool with: the held one, or while it is broken the
        protect set it leaves (every tool when that is unknown), so mode and result agree with
        ``plan``."""
        rs = self.held_rules()
        prs = rs if rs is not None else self._broken_protect()
        if prs and prs.get("unknown"):
            return {**prs, "protect": {**prs["protect"], tool: {"fail": "closed"}}}
        return prs

    def _refused_offered(self) -> Any:
        """The version the last refused rule set offered (kept in its state file), if any."""
        p = self._state_path("rules", self.project_env())
        d = _read(p) if p else None
        st = d.get("stale") if isinstance(d, dict) and d.get("witness") == self.rec.url else None
        return st["refused"].get("offered") if isinstance(st, dict) and isinstance(st.get("refused"), dict) else None

    def _retrying(self, kind: str) -> bool:
        """Whether a refused rule set or list waits before the next fetch: never after a forced pull
        or under another SDK version; an ``until`` more than the longest wait ahead counts as the
        longest wait from now (written back)."""
        p = self._state_path(kind, self.project_env())
        d = _read(p) if p else None
        if not isinstance(d, dict) or d.get("witness") != self.rec.url or d.get("sdk") != __version__:
            return False
        until = _epoch_ms((d.get("retry") or {}).get("until")) if isinstance(d.get("retry"), dict) else None
        if until is None:
            return False
        left = until - _now_ms()
        if left <= 0:
            return False
        if left > STALE_RETRY_MAX_MS:
            self._edit_state(kind, {"type": "resaved"}, self.project_env())
        return True

    def _protect_path(self, pe: Tuple[str, str]) -> Path:
        """``rules/<project>/<env>.protect.json``: the tools the console protects in the held rule
        set, as last verified, for this witness. Its own file: no state edit ever erases it. Written
        with every verified version, and backfilled the first time a still-valid copy (one from
        before 0.5.4 too) is read."""
        return self.home / "rules" / pe[0] / f"{pe[1]}.protect.json"

    def _save_protect(self, pe: Tuple[str, str], item: dict) -> None:
        protect = item["rules"].get("protect")
        _write_pretty(
            self._protect_path(pe),
            {
                "witness": self.rec.url,
                "version": item["rules"]["version"],
                "protect": protect if isinstance(protect, dict) else {},
            },
        )

    def _protect_record(self, pe: Tuple[str, str]) -> Optional[dict]:
        path = self._protect_path(pe)

        def load() -> Optional[dict]:
            d = _read(path)
            ok = isinstance(d, dict) and d.get("witness") == self.rec.url and isinstance(d.get("protect"), dict)
            return d if ok else None

        return self._stamped(path, load, (self.rec.url,))

    def _sync_protect(self, pe: Tuple[str, str], doc: dict) -> None:
        """Keep the protect record in step with the verified copy held (under its lock): written when
        missing or of another version. A union-only safety net: a record of a newer version than the
        copy (another process held one) keeps every tool it named, joined with the copy's, until a
        verified newer copy replaces it. A copy that changed meanwhile is left to the next read."""
        v = doc["rules"]["version"]
        rec = self._protect_record(pe)
        if rec is not None and rec.get("version") == v:
            return
        with self._lock, self.rec.state._lock_at(self._protect_path(pe).with_suffix(".lock")):
            cur = _read(self._rules_path(pe))
            if not isinstance(cur, dict) or not isinstance(cur.get("rules"), dict) or cur["rules"].get("version") != v:
                return
            r = self._protect_record(pe)
            if r is not None and r.get("version") == v:
                return
            own = doc["rules"].get("protect") if isinstance(doc["rules"].get("protect"), dict) else {}
            ahead = r is not None and isinstance(r.get("version"), int) and r["version"] > v
            _write_pretty(
                self._protect_path(pe),
                {"witness": self.rec.url, "version": v, "protect": {**own, **r["protect"]} if ahead else own},
            )

    def _broken_protect(self, pe: Any = "current") -> Optional[dict]:
        """What protects tools from the console while the held rule set is broken: the tools of its
        last verified version (its protect record) joined with those the broken file still names.
        With no protect record nobody knows which tools it protected: ``unknown``, and every tool
        counts as protected, so every checked call is refused until a pull verifies (never fail
        open). None when the held rule set is not broken."""
        if pe == "current":
            pe = self.project_env()
        h = self._rules_held(pe) if pe else None
        if not h or h[1] != "broken":
            return None
        raw = _read(self._rules_path(pe))
        rules = raw.get("rules") if isinstance(raw, dict) else None
        named = rules.get("protect") if isinstance(rules, dict) and isinstance(rules.get("protect"), dict) else {}
        # The record counts only for the version the broken copy still says it is: a copy another
        # process (an older release) wrote over it, or one that no longer parses, may protect others.
        v = rules.get("version") if isinstance(rules, dict) else None
        r = self._protect_record(pe)
        rec = r if r is not None and isinstance(r.get("version"), int) and r.get("version") == v else None
        return {
            "protect": {**named, **(r["protect"] if r else {})},
            "version": rec.get("version") if rec else None,
            "unknown": rec is None,
        }

    @staticmethod
    def _protects(rs: Optional[dict], tool: Optional[str]) -> bool:
        """Whether *rs* (a held rule set, or ``_broken_protect``) protects *tool* from the console."""
        return C.console_protects(rs, tool) or (isinstance(rs, dict) and rs.get("unknown") is True and tool is not None)

    def _signer_problem(
        self, kind: str, pe: Optional[Tuple[str, str]], live: Optional[dict]
    ) -> Optional[Tuple[str, str]]:
        """The held object's signer problem, from the keys held now: revoked, or no longer held."""
        if kind == "rules":
            h = self._rules_held(pe) if pe else None
            if h and h[1] in ("revoked", "not_held"):
                return h[1], str(h[0].get("service_key_id"))  # type: ignore[union-attr]
            return None
        ids = live["held"]["key_ids"] if live and isinstance(live["held"].get("key_ids"), list) else []
        revoked = self.revoked_keys()
        r = next((k for k in ids if k in revoked), None)
        if r:
            return "revoked", r
        held = {k.get("key_id") for k in self.all_service_keys()}
        gone = next((k for k in ids if k not in held), None)
        return ("not_held", gone) if gone else None

    def stale_info(self, kind: str, pe: Any = "current") -> Optional[dict]:
        """What is stale about the held rule set of *pe* or the held list, from the disk (any
        process): None when nothing is. Marks the clock when the held object's signer is revoked or
        no longer held. A broken object counts as expired at once."""
        if pe == "current":
            pe = self.project_env()
        what = (
            f"rule set ({pe[0]}/{pe[1]})"
            if kind == "rules" and pe
            else "rule set"
            if kind == "rules"
            else "shared list"
        )
        h = (self._rules_held(pe) if pe else None) if kind == "rules" else self._list_held()
        if not h:
            return None
        unknown = kind == "rules" and self.protection_unknown(pe)
        if h[0] is None:
            return {
                "what": what,
                "since": None,
                "expired": True,
                "broken": True,
                "confirmed": True,
                "unknown": unknown,
                "words": f"the copy held is unreadable or fails its own signature; {PROTECTION_UNKNOWN}"
                if unknown
                else "the copy held is unreadable or fails its own signature",
                "deadline": None,
                "noted": [],
                "said": None,
            }
        live = self._live_state(kind, pe)
        signer = self._signer_problem(kind, pe, live)
        if signer and not (live and isinstance(live.get("stale"), dict) and live["stale"].get("since")):
            self._edit_state(kind, {"type": "signer_bad"}, pe)
            live = self._live_state(kind, pe)
        st = live.get("stale") if live and isinstance(live.get("stale"), dict) else None
        since = _epoch_ms(st.get("since")) if st and isinstance(st.get("since"), str) else None
        if since is None:
            return None
        if since > _now_ms():
            self._edit_state(kind, {"type": "resaved"}, pe)  # the transition clamps it to now
            since = _now_ms()
        ref = st.get("refused") if isinstance(st.get("refused"), dict) else None
        if ref and ref.get("cause") == "unknown_key":
            words = (
                "the witness now signs with a key this release does not know (update signafaide)"
                if self._pinned()
                else f"the witness signs with key {ref.get('key_id')}, which its published key list does not name (ask the witness's operator)"
            )
        elif signer and signer[0] == "revoked":
            words = f"signed by service key {signer[1]}, which the witness has revoked; waiting for the witness's re-signed copy (run `signafaide pull`)"
        elif signer:
            words = "the key that signed it is no longer in the keys held (run `signafaide pull`)"
        elif ref:
            words = f"version {ref.get('offered')} from the witness failed check {ref.get('step')} (run `signafaide pull`; report it with the output of `signafaide checks status`)"
        else:
            words = "waiting for a verified copy from the witness (run `signafaide pull`)"
        expired = _now_ms() - since >= REVOKED_GRACE_MS
        return {
            "what": what,
            "since": since,
            "expired": expired,
            "broken": False,
            "confirmed": st.get("confirmed") is True,
            "words": f"{words}; no verified replacement arrived within 7 days" if expired else words,
            "deadline": _iso(since + REVOKED_GRACE_MS),
            "noted": st.get("noted") if isinstance(st.get("noted"), list) else [],
            "said": st.get("said") if isinstance(st.get("said"), str) else None,
        }

    def _stale_lines(self) -> List[Tuple[str, bool]]:
        """The status lines of every state file of this witness (every project's rule set, the list)."""
        pes = []
        try:
            for prj in sorted((self.home / "rules").iterdir()):
                for f in sorted(prj.iterdir()):
                    n = f.name
                    if n.endswith(".json") and not n.endswith((".state.json", ".at.json", ".protect.json")):
                        pes.append((prj.name, n[:-5]))
        except OSError:
            pass
        # Only this witness's: another project's rule set counts when its state file names this
        # witness (the current project's always does); another witness's state is never read or written.
        cur = self.project_env()

        def mine(pe: Tuple[str, str]) -> bool:
            if cur and tuple(pe) == tuple(cur):
                return True
            st = _read(self._state_path("rules", pe))
            return isinstance(st, dict) and st.get("witness") == self.rec.url

        out = []
        for info in [self.stale_info("rules", pe) for pe in pes if mine(pe)] + [self.stale_info("list", None)]:
            if not info:
                continue
            if info["broken"]:
                tail = (
                    "" if info.get("unknown") else "; protected calls are refused until `signafaide pull` verifies one"
                )
                out.append((f"PROBLEM {info['what']}: {info['words']}{tail}", True))
            elif info["expired"]:
                out.append((f"PROBLEM {info['what']}: {info['words']}; protected calls are refused", True))
            else:
                out.append((f"STALE {info['what']}: {info['words']}; enforced as held until {info['deadline']}", False))
        return out

    def _stale_gate(self, agent: str, strict: bool) -> Optional[str]:
        """Before a call is checked (§8): a stale rule set or list is enforced as it is for
        REVOKED_GRACE_MS. Once the mark has outlived a pull it is said once a day per object on stderr
        and noted in a ``signafaide.checks_stale`` record once per agent (both kept in the state file).
        After the grace period, or at once for a broken copy, a protected call is refused: its decision
        is written, the tool does not run. Never in test mode."""
        if self.rec.test:
            return None
        pe = self.project_env()
        for kind in ("rules", "list"):
            info = self.stale_info(kind, pe)
            if not info:
                continue
            if info["broken"] or not info["confirmed"]:
                continue
            today = _iso(_now_ms())[:10]
            say = info["said"] != today
            note = agent not in info["noted"]
            if not say and not note:
                continue
            if say:
                print(f"signafaide: {info['what']}: {info['words']}", file=sys.stderr)
            noted = False
            if note:
                try:
                    rs = self.held_rules_item() if kind == "rules" else None
                    self.rec.write(
                        "note",
                        "signafaide.checks_stale",
                        {
                            "stale": kind,
                            "since": _iso(info["since"]),
                            "words": info["words"],
                            "rule_set": {
                                "set": rs["rules"]["set"],
                                "version": rs["rules"]["version"],
                                "service_key_id": rs["service_key_id"],
                            }
                            if rs
                            else None,
                            "grace_days": REVOKED_GRACE_MS // 86_400_000,
                        },
                        agent=agent,
                    )
                    noted = True
                except Exception:  # noqa: BLE001 - a record that cannot be written never stops the call here
                    pass

            def mark(d: dict, say: bool = say, noted: bool = noted) -> None:
                if not isinstance(d.get("stale"), dict):
                    return
                if say:
                    d["stale"]["said"] = today
                if noted and agent not in d["stale"]["noted"]:
                    d["stale"]["noted"] = d["stale"]["noted"] + [agent]

            self._edit_state(kind, {"type": "resaved"}, pe, mark)
        return self.stale_refusal(pe) if strict else None

    def stale_refusal(self, pe: Any = "current") -> Optional[str]:
        """Why a protected call is refused now (§8), or None: the one reason the call, ``check`` and
        ``rules test`` all give (the stale grace period over, a broken copy)."""
        if self.rec.test:
            return None
        if pe == "current":
            pe = self.project_env()
        blocks = []
        for kind in ("rules", "list"):
            info = self.stale_info(kind, pe)
            if info and info["expired"]:
                tail = "" if info.get("unknown") else "; protected calls are refused"
                blocks.append(f"{info['what']}: {info['words']}{tail}")
        return f"{'; '.join(blocks)} (spec §8)" if blocks else None

    def witness_host(self) -> Optional[str]:
        return C.url_host(self.rec.url)

    def plan(
        self,
        tool: ToolInfo,
        agent: str,
        args: Any,
        *,
        strict_code: bool,
        call_id: Any = None,
        telemetry: bool = False,
        declared: Optional[str] = None,
        protect: bool = False,
    ) -> Optional[Plan]:
        """Steps 1 and 2 of a call (§8): the decision checks on *args*, the `checks` the decision
        carries, and the values a strict call discloses. None when checks are off. *telemetry*:
        the OpenTelemetry plug-in, which never blocks (every entry in watch mode, not strict).
        *declared*: the declared name (§2.6) the checks use, when it is not the tool's own name
        cut (a wrapper's name for a framework tool named otherwise)."""
        decl = declared if declared is not None else declared_name(tool.name)
        rs = self.held_rules()
        # §8 (SDK 0.5.2): the held rule set's `protect` protects a tool the client wraps, as the
        # checks file's `protect: true` would; never a telemetry span (it never blocks).
        # A held copy that is broken still protects what it protected when last verified (refused).
        prs = rs if rs is not None else self._broken_protect()
        from_console = not telemetry and self.path() is not None and self._protects(prs, decl)
        by_code = bool(strict_code or protect)
        f = self.file_for((by_code or from_console) and not telemetry)
        if not telemetry:
            self.observe_console(
                decl,
                from_console,
                rs["version"] if rs else None,
                self._other_sources(f, decl, by_code) if f is not None else (["code"] if by_code else []),
            )
        if f is None:
            return None
        self._planned = True
        self.start()
        ts = C.tool_settings(f, decl)
        mode = "watch" if telemetry else ts["mode"]
        if from_console and not ts["strict"]:
            mode = C.protection(self._protection_rs(decl), f, False, decl)["mode"]
        file_fail = (f["tools"].get(decl) or {}).get("fail") if C.checks_file_version(f) == 1 and not protect else None
        cfg = {"strict": ts["strict"], "disclose": ts["disclose"], "fail": file_fail}
        strict = False if telemetry else bool(strict_code or cfg.get("strict") or from_console)
        stale_blocked = None if telemetry else self._stale_gate(agent, strict)
        protected_by = (
            []
            if not strict
            else (["code"] if by_code else [])
            + (["checks_file"] if ts["strict"] and not f.get("_default") else [])
            + (["console"] if from_console else [])
        )
        held = self.held_list()
        fps = C.tool_fingerprints(tool.name, tool.description or "", tool.input_schema, tool.server_info)
        on = f["checks"]
        results: List[dict] = []
        if on["secret"]:
            results.append(C.entry("secret", C.secret_findings(args, self.witness_host()), mode))
        if on["address"]:
            hosts = list(f["addresses"]["hosts"]) + (list(rs["addresses"]["hosts"]) if rs else [])
            cidrs = list(f["addresses"]["cidrs"]) + (list(rs["addresses"]["cidrs"]) if rs else [])
            results.append(C.entry("address", C.address_findings(args, hosts, cidrs, f["addresses"]["resolve"]), mode))
        like_approved, look_alike = self._look_alike_of(on, agent, tool, decl)
        if on["changed_tool"]:
            approved = self._approval_for(rs, agent, tool, decl, fps, look_alike)
            results.append(C.entry("changed_tool", C.changed_tool_findings(fps, approved), mode))
        if on["fingerprint"] and held is not None:
            excepted = C.excepted_pairs(rs) if rs is not None else None
            results.append(
                C.entry("fingerprint", C.fingerprint_findings_in(fps, self._listed_pairs(held), excepted), mode)
            )
        rules_used: List[dict] = []
        held_entry: Optional[dict] = None
        if rs is not None:
            # The project's rule set is ruled on by the witness (§8): its entry never blocks here.
            m = "watch" if telemetry else C.entry_mode(rs["mode"], strict, False)
            held_entry = C.client_rule_entry(rs, m, rs["set"], agent, decl, args)
            results.append(held_entry)
            rules_used.append({"set": rs["set"], "version": rs["version"], "hash": self._hash(rs)})
        if f["rules"] is not None:
            results.append(C.client_rule_entry(f["rules"], mode, "local", agent, decl, args))
            rules_used.append({"set": "local", "version": None, "hash": self._hash(f["rules"])})
        # hidden_instruction: what the agent is shown of the tool blocks; without a finding there, the
        # arguments are read too, a note only (a possible hidden instruction, handed to the caller).
        notes: List[dict] = []
        if on["hidden_instruction"]:
            shown = shown_definition(tool)
            definition = (
                C.definition_findings(shown, tool.name, tool.others, like_approved) if shown is not None else None
            )
            arg_f = C.argument_findings(args)
            fnd = C.decision_instruction_findings(definition, arg_f)
            if shown is not None or fnd["found"]:
                results.append(C.entry("hidden_instruction", fnd, mode))
            if fnd is arg_f:
                notes = C.call_notes(decl, "arguments", arg_f)
        result = C.combined(results)
        fail = None
        if strict:
            fail = C.rule_set_fail(rs, decl) or cfg.get("fail") or "closed"
        disclose = cfg.get("disclose") or []
        # §10.4: a strict call sends the fields the held rule set can use for it that `disclose`
        # lists; a needed field it does not list makes the ruling fields_missing.
        dsc = C.disclosure(rs, agent, decl, disclose)
        not_disclosed = dsc["missing"]
        pointers: List[str] = []
        values: Optional[dict] = None
        salt: Optional[str] = None
        if strict and result != "block":
            pointers = dsc["sent"]
            values = {p: v for p in pointers for v in [C.resolve(args, p)] if v is not C.ABSENT}
            try:
                too_big = len(canonicalize(values)) > C.DISCLOSED_MAX_BYTES
            except (ValueError, TypeError):
                too_big = True
            if too_big or not pointers:
                pointers, values = [], None
            else:
                salt = new_salt()
        cid = call_id if (isinstance(call_id, str) and 1 <= len(call_id) <= 128) or C.is_safe_int(call_id) else None
        checks = {
            "results": results,
            "result": result,
            "rules": rules_used,
            "fingerprints": held["seq"] if held else None,
            "tool": fps,
            "strict": strict,
            "fail": fail,
            "disclosed": pointers,
            "disclosed_hash": C.disclosed_hash(values, salt) if pointers else None,
            "call_id": cid,
        }
        timeout = f.get("ruling_timeout_ms", C.RULING_TIMEOUT_MS)
        plan = Plan(
            checks,
            strict,
            fail,
            timeout,
            values if pointers else None,
            salt,
            None,
            rs["version"] if rs else None,
            not_disclosed,
            decl,
            cfg.get("fail"),
            notes=notes,
            protected_by=protected_by,
            stale_blocked=stale_blocked,
        )
        if result == "block":
            plan.blocked = self._block_error(decl, next(e for e in results if e["result"] == "block"), rs, f["rules"])
        elif (
            strict
            and rs is not None
            and rs["mode"] == "enforce"
            and held_entry is not None
            and held_entry.get("enforce_result") == "block"
        ):
            plan.held_block = self._held_block_error(decl, held_entry, rs)
        return plan

    def _held_block_error(self, tool: str, e: dict, rs: dict) -> SignafaideBlocked:
        """A strict call with no ruling that the held version would block (§8): the client decides
        alone, with the rules it holds, and says the witness did not rule."""
        rid = e["matched"][0] if e["matched"] else None
        rule = next((r for r in rs["rules"] if r["id"] == rid), None) if rid else None
        text = (
            rule_words(rule)
            if rule is not None
            else (f"rule {rid}" if rid else "Block every call that no rule matches")
        )
        return SignafaideBlocked(
            f"{tool} did not run: signafAIde did not rule on it, and the signed rule set version {rs['version']} held here blocks it "
            f'("{text}"). To allow such calls, change the rule in the console.',
            "blocked",
            check="rule",
            rule=rid,
            rules_version=rs["version"],
            tool=tool,
            rule_text=text,
            ruled_by="client",
        )

    def _block_error(self, tool: str, e: dict, rs: Optional[dict], local_rules: Optional[dict]) -> SignafaideBlocked:
        """The words of a block on this machine (spec 1.1): what did not run, the rule in words,
        and how to allow the call, in one sentence."""
        c = e["check"]
        v = rs["version"] if rs else None
        file = (self.path() or Path(CHECKS_FILE)).name
        if c == "rule":
            rid = e["matched"][0] if e["matched"] else None
            local = e["set"] == "local"
            doc = local_rules if local else rs
            rule = next((r for r in doc["rules"] if r["id"] == rid), None) if (rid and doc) else None
            if rule is not None:
                text = rule_words(rule)
            elif rid:
                text = f"rule {rid}"
            else:
                text = (
                    f"{'Block' if (doc or {}).get('default') == 'block' else 'Allow'} every call that no rule matches"
                )
            if local:
                msg = f'{tool} did not run: the rule on this machine blocked it ("{text}"); signafAIde did not rule on it. To allow it, change the rule in {file}.'
            else:
                msg = f'{tool} did not run: blocked here under signed rule set version {v} ("{text}"); the witness did not rule on it. To allow such calls, change the rule in the console.'
            return SignafaideBlocked(
                msg,
                "blocked",
                check="rule",
                rule=rid,
                rules_version=None if local else v,
                tool=tool,
                rule_text=text,
                ruled_by="client",
            )
        found = ", ".join(e["found"])
        why = {
            "secret": f"its arguments hold a secret ({found}). To allow it, remove the secret, or send it only to the service that issued it.",
            "address": f"it goes to an address that is not public ({found}). If that address is meant, add the host to addresses in {file}, or to the rule set's allowlist in the console.",
            "changed_tool": f"the tool changed since it was approved ({found}). To allow it, re-approve the tool: `npx signafaide checks approve {tool}`, or in the console when the rule set approves tools.",
            "fingerprint": f"it is on the list of known bad tools ({found}). Remove or replace the tool.",
            "hidden_instruction": f"what the agent is shown of the tool {shown_why(e['found'])}. Review the tool's description and schema; if it is meant, set the tool's `mode` to `\"watch\"` in {file} (Calibrating: it is shown and noted, nothing is blocked).",
        }
        return SignafaideBlocked(
            f"{tool} did not run: {why[c]}", "blocked", check=c, rules_version=v, tool=tool, ruled_by="client"
        )

    def ruling(self, d: dict, plan: Plan, tool: str) -> Tuple[str, Optional[CheckError]]:
        """Step 4 of a strict call (§8): ship the decision, wait for its receipt up to the ruling
        timeout, and read the ruling. Returns the outcome's ``ruling`` (``allow``, ``block``,
        ``none``) and the error to raise when the tool must not run."""
        rec = self.rec
        if rec.test:
            return "none", None  # test mode sends nothing: strict calls run without a ruling
        # The grace period of stale rules or a stale list is over (§8): refused, never asked or run.
        if plan.stale_blocked:
            return "none", CheckError(f"{tool} did not run: {plan.stale_blocked}", "rules_unavailable")
        closed = plan.fail != "open"
        if not rec.api_key:
            err = SignafaideBlocked(f"{tool} did not run: {NO_KEY_WHY}", "no_key", tool=tool, ruled_by="client")
            return "none", (err if closed else None)
        why = "no receipt came"
        code = "no_ruling"
        deadline = time.monotonic() + plan.timeout_ms / 1000
        # No rule set held (a cold start, or its file or the keys file was removed): fetch it now,
        # within the same ruling timeout, so its fail mode is known before the call may run.
        # Never while a refused version's retry wait runs: a call does not wake a pull per call.
        fetching = self.held_rules() is None and not self._no_rule_set and not self._retrying("rules")
        if fetching:
            with self._round_done:
                rounds = self._rounds
            self.start()
            self.wake()
        # A short restart of the witness must not stop the call: a request that failed for a reason
        # a new attempt can fix is sent again, with backoff, until the ruling timeout.
        receipt = None
        refused: Optional[SignafaideError] = None
        blocked: Optional[SignafaideError] = None  # the network here blocks the witness
        pause = RETRY_FIRST_MS / 1000
        attempt = 0
        while True:
            attempt += 1
            left = deadline - time.monotonic()
            try:
                receipt = rec.ensure_receipt(d, timeout=max(0.001, left))
                break
            except SignafaideError as e:
                if not e.retryable and e.code != "network":
                    if e.code in ("quota_exceeded", "plan_required"):
                        refused = e
                    why = f"no receipt came ({e.message})"
                    break
                blocked = e if e.blocked else None
                why = f"no receipt came within {plan.timeout_ms} ms, {'1 attempt' if attempt == 1 else f'{attempt} attempts'} ({e.message})"
                left = deadline - time.monotonic()
                if left <= pause or blocked is not None:  # a network that blocks the witness does not open by waiting
                    break
                time.sleep(pause)
                pause = min(pause * 2, RETRY_MAX_MS / 1000)
        if fetching:
            with self._round_done:
                self._round_done.wait_for(lambda: self._rounds > rounds, timeout=max(0.0, deadline - time.monotonic()))
        closed = self._fail_closed(plan)
        if refused is not None:
            # The project's allowance is used up: no new attempt can fix it, so say so plainly.
            if plan.held_block is not None:
                return "none", plan.held_block
            q = SignafaideBlocked(
                f"{tool} did not run: {quota_words(rec, refused)}", refused.code, tool=tool, ruled_by="client"
            )
            return "none", (q if closed else None)
        if receipt is not None:
            g = receipt.get("ruling")
            if g is None:
                if receipt.get("ruling_error") == "rules_unavailable":
                    code, why = "rules_unavailable", "the witness could not load or sign the project's rule set"
                else:
                    why = "the receipt has no ruling (a witness that does not rule)"
            else:
                bad = self._ruling_problem(receipt, d)
                if bad:
                    why = bad
                else:
                    held = self.held_rules()
                    # A newer version than the one held: fetch it at once (§8). The version refused
                    # while its retry wait runs wakes nothing (no pull per strict call); any other
                    # version does, and its fetch does not wait.
                    if isinstance(g.get("rules"), dict) and (held is None or g["rules"]["version"] > held["version"]):
                        waiting = self._retrying("rules")
                        if not waiting:
                            self.wake()
                        elif g["rules"]["version"] != self._refused_offered() and self._may_force(
                            g["rules"]["version"]
                        ):
                            # Bounded (``_may_force``): a witness naming other versions in its
                            # rulings never makes a fetch per call.
                            self._force_rules = True
                            self.wake()
                    if g["ruling"] == "allow":
                        return "allow", None
                    return "block", self._ruling_error(tool, g)
        # No ruling: the client decides alone. The rules it holds still block what they block; else
        # the tool's If unreachable setting (Stop by default) decides.
        if plan.held_block is not None:
            return "none", plan.held_block
        if blocked is not None and receipt is None:
            err = SignafaideBlocked(
                f"{tool} did not run: signafAIde did not rule on it, and this tool is set to stop. {blocked.message}",
                code,
                tool=tool,
                ruled_by="client",
            )
            return "none", (err if closed else None)
        err = SignafaideBlocked(
            f"{tool} did not run: signafAIde did not rule on it ({why}), and this tool is set to stop. Check the network and "
            "`signafaide checks status`; the console sets whether it stops or runs.",
            code,
            tool=tool,
            ruled_by="client",
        )
        return "none", (err if closed else None)

    def _fail_closed(self, plan: Plan) -> bool:
        """The fail mode of a strict call that has no ruling (§8): the held rule set's for the
        tool, else the checks file's when the witness said the project has no rule set, else
        closed. With an API key and no rule set held, nothing local can open it: the rule set the
        witness holds may say closed."""
        rs = self.held_rules()
        if rs is not None:
            return (C.rule_set_fail(rs, plan.declared) or plan.file_fail or plan.fail or "closed") != "open"
        if self._no_rule_set:
            return plan.fail != "open"
        return True

    def _ruling_problem(self, receipt: dict, d: dict) -> Optional[str]:
        g = receipt.get("ruling")
        err = C.ruling_errors(g)
        if err:
            return f"the ruling is malformed ({err})"
        if (
            g["record_hash"] != receipt.get("record_hash")
            or g["batch_hash"] != receipt.get("batch_hash")
            or g["server_time"] != (receipt.get("batch") or {}).get("server_time")
        ):
            return "the ruling names another record than its receipt"
        # The same judgement as every verifier (key_problem): unknown key, revoked, not active, signature,
        # with the published revoked ids read at most KEYS_REFRESH_MS ago.
        self.fresh_keys()
        kid = receipt.get("service_key_id")
        if not any(k.get("key_id") == kid for k in self.all_service_keys()):
            self.fresh_keys("soon")  # the keys held stay when it fails
        bad = C.ruling_key_problem(receipt, self.all_service_keys(), self.revoked_keys())
        if bad == "revoked":
            return f"the ruling's service key {kid} is revoked"
        # The key must be active when the witness ruled: a retired key never signs a new ruling.
        if bad == "not_active":
            return f"the ruling's service key {kid} was not active at {g['server_time']}"
        if bad:
            return "the ruling's signature does not verify with the witness's keys"
        return None

    def _ruling_error(self, tool: str, g: dict) -> SignafaideBlocked:
        """The words of the witness's block (spec 1.1): the rule in words when the held version is
        the one it ruled under, the version, and how to allow the call."""
        v = g["rules"]["version"] if isinstance(g.get("rules"), dict) else None
        rule = g["matched"][0] if g["matched"] else None
        rs = self.held_rules()
        doc = rs if (rs is not None and v is not None and rs["version"] == v) else None
        found = next((r for r in doc["rules"] if r["id"] == rule), None) if (rule and doc) else None
        text = rule_words(found) if found is not None else None
        if text is None and g["basis"] == "default" and doc is not None:
            text = "Block every call that no rule matches"
        at = f" (rule set version {v})" if v is not None else ""
        basis = g["basis"]
        if basis == "fields_missing":
            fields = ", ".join(p[1:] or "(the empty key)" for p in g["missing"])
            msg = (
                f"{tool} did not run: a rule needs {fields}, which this machine does not send yet{at}; run npx signafaide pull "
                f"(it adds {', '.join(g['missing'])} to the disclose list of {tool} in the checks file)."
            )
        elif basis == "fingerprint":
            msg = f"{tool} did not run: it is on the list of known bad tools{at}. Remove or replace the tool."
        elif basis == "rules_version":
            msg = f"{tool} did not run: {g['reason']}"
        elif basis == "error":
            msg = (
                f'{tool} did not run: signafAIde blocked it under "{text or f"rule {rule}"}"{at}, because a field had the wrong type for the rule. '
                "To allow it, send the field with the type the rule expects, or change the rule in the console."
            )
        else:
            shown = text or (f"rule {rule}" if rule else "Block every call that no rule matches")
            msg = f'{tool} did not run: signafAIde blocked it under "{shown}"{at}. To allow such calls, change the rule in the console.'
        return SignafaideBlocked(
            msg,
            "blocked",
            check="rule" if basis in ("rule", "error", "default") else basis,
            rule=rule,
            rules_version=v,
            missing=g["missing"],
            tool=tool,
            rule_text=text,
            ruled_by="witness",
        )

    def result_entries(
        self, output: Any, telemetry: bool = False, tool: Optional[str] = None, protect: bool = False
    ) -> List[dict]:
        """Step 5 (§8): the result checks of a call that ran (``secret``, ``hidden_instruction``),
        in the mode the checks file sets for *tool* (its declared name); *protect*: a tool
        protected in code, checked in On without a checks file."""
        f = self.file_for(protect and not telemetry, None if telemetry else tool)
        if f is None:
            return []
        if telemetry:
            mode = "watch"
        elif tool is not None:
            mode = C.tool_settings(f, tool)["mode"]
            # A tool protected from the console (§8): its checks are On unless the file names its mode.
            if self.console_protects(tool) and not C.tool_settings(f, tool)["strict"]:
                mode = C.protection(self._protection_rs(tool), f, False, tool)["mode"]
        else:
            mode = f.get("mode", "watch")
        out: List[dict] = []
        if f["checks"]["secret"]:
            out.append(C.entry("secret", C.secret_findings(output, self.witness_host(), result=True), mode))
        if f["checks"]["hidden_instruction"]:
            out.append(C.entry("hidden_instruction", C.hidden_findings(output), mode))
        return out

    def result_notes(self, tool: str, results: List[dict]) -> List[dict]:
        """The notes of a call's result entries (§8 notes): a possible hidden instruction in the result."""
        e = next((x for x in results if x["check"] == "hidden_instruction"), None)
        return (
            C.call_notes(tool, "result", {"result": e.get("enforce_result", e["result"]), "found": e["found"]})
            if e
            else []
        )

    def withheld(self, tool: str, results: List[dict]) -> Optional[SignafaideBlocked]:
        """The error that replaces a result the client withheld (§8 step 5): the tool ran, and its
        result held a secret, so the agent is not given it. None when no entry blocks."""
        e = next((x for x in results if x["result"] == "block"), None)
        if e is None:
            return None
        file = (self.path() or Path(CHECKS_FILE)).name
        return SignafaideBlocked(
            f"{tool} ran, but its result was withheld from the agent: it holds a secret ({', '.join(e['found'])}). What the tool did stands. "
            f'If the agent should see such results, set the tool\'s `mode` to `"watch"` in {file} (Calibrating: the result goes through and the finding is noted).',
            "withheld",
            check=e["check"],
            tool=tool,
            ruled_by="client",
        )

    def seen(self, tool: ToolInfo, agent: str, declared: str, protect: bool = False) -> None:
        """A wrapper is shown a tool's definition (§8 changed_tool): approve its fingerprints the
        first time, so a change before its first call is still a change."""
        try:
            f = self.file_for(protect, declared)
            if f is None or not f["checks"]["changed_tool"] or not tool.name:
                return
            rs = self.held_rules()
            if rs is not None and rs.get("approved") is not None:
                return
            if self._look_alike_of(f["checks"], agent, tool, declared)[1]:
                return  # never approved
            self.local_approval(
                agent,
                server_identity(tool),
                declared,
                C.tool_fingerprints(tool.name, tool.description or "", tool.input_schema, tool.server_info),
            )
        except Exception:  # the call's own checks report a broken checks file
            return

    # --- status (signafaide checks status) ----------------------------------------------

    def strict_tools(self, f: dict) -> List[str]:
        """The tools the checks file makes strict (version 1 ``strict``, version 2 ``protect``)."""
        return sorted(n for n in f["tools"] if C.tool_settings(f, n)["strict"])

    def status(self) -> Tuple[List[str], bool]:
        """``signafaide checks status``: (lines, problem). Every state file of this witness is said on
        every path (§8): ``STALE ...; enforced as held until <UTC>`` in the grace period (exit 0),
        ``PROBLEM ...; protected calls are refused`` after it (exit 1)."""
        lines, problem = self._status_lines()
        for line, p in self._stale_lines():
            lines.append(line)
            problem = problem or p
        return lines, problem

    def _status_lines(self) -> Tuple[List[str], bool]:
        """The lines of ``signafaide checks status``, and whether there is a problem."""
        lines: List[str] = []
        path = self.path()
        if path is None:
            return ["checks: off (SIGNAFAIDE_CHECKS=0)"], False
        try:
            f = self.file()
        except CheckError as e:
            return [f"checks: PROBLEM {e.message}"], True
        real = f
        if f is None:
            if not self.console_protects_any():
                return [
                    f"checks: off for tools not protected in code or from the console (no {path}; `signafaide protect` or `signafaide init` writes one); "
                    "a tool protected in code or from the console runs every check in On"
                ], False
            f = self.file_for(True)
        on = [k for k in C.FILE_CHECKS if f["checks"][k]]
        v2 = C.checks_file_version(f) == 2
        if real is None:
            lines.append(
                f"checks: no {path}: only tools protected in code or from the console are checked, every check On ({', '.join(on)})"
            )
        elif v2:
            lines.append(
                f"checks: on, On or Calibrating per tool ({path}, version 2): protected tools are On, others Calibrating unless the file sets a tool's `mode`; checks on: {', '.join(on) or 'none'}"
            )
        else:
            lines.append(
                f'checks: on, {mode_word(f["mode"])} ({path}, version 1: `mode` is "{f["mode"]}"); checks on: {", ".join(on) or "none"}'
            )
        rs = self.held_rules()
        item = self.held_rules_item()
        pe = self.project_env()
        if rs:
            at = (_read(self._rules_path(pe).with_name(f"{pe[1]}.at.json")) or {}).get("fetched") if pe else None
            lines.append(
                f"rule set: {rs['set']} version {rs['version']}, {mode_word(rs['mode'])}, default {rs['default']}, issued {rs['issued']} (fetched copy {_age(at)})"
            )
            for r in rs["rules"]:
                lines.append(
                    f"rule {r['id']}: {rule_words(r)} ({'On' if C.rule_state(rs, r) == 'on' else 'Calibrating'})"
                )
        elif item is None:
            lines.append("rule set: none held" + ("" if self.rec.api_key else " (no API key)"))
        held = self.held_list()
        at = (_read(self.home / "fingerprints.at.json") or {}).get("fetched")
        lines.append(
            f"shared fingerprint list: seq {held['seq']}, {len(held['entries'])} entries ({_age(at)})"
            if held
            else "shared fingerprint list: none held"
        )
        lines.append(f"ruling timeout: {f.get('ruling_timeout_ms', C.RULING_TIMEOUT_MS)} ms")
        from_console = sorted(rs["protect"]) if rs and isinstance(rs.get("protect"), dict) else []
        strict = sorted(set((self.strict_tools(real) if real is not None else []) + from_console))
        word = "protected tool"
        for n in strict:
            t = C.tool_settings(f, n)
            pr = C.protection(rs, real, False, n)
            fail = C.rule_set_fail(rs, n) or (
                ("closed" if v2 else (f["tools"][n].get("fail") or "closed")) if t["strict"] else "closed"
            )
            show_mode = v2 or real is None or not t["strict"]
            lines.append(
                f"{word} {n}: if signafAIde can't be reached: {fail_word(fail)}{', local checks ' + mode_word(pr['mode']) if show_mode else ''}; "
                f"discloses {', '.join(t['disclose']) or 'no field'}; protected {C.source_words(pr['sources'], rs['version'] if rs else None)}"
            )
        # §8 (SDK 0.5.2): a tool the console protects that this program has not shown to signafAIde.
        for n in from_console:
            where = self.wrapped_state(n)
            if where == "wrapped":
                continue
            if where == "unrecorded":
                lines.append(
                    f"{word} {n}: protected from the console (rule set version {rs['version']}), but the program declares it as not recorded: signafAIde never sees "
                    "its calls, so it cannot protect them. Wrap it with record, protect or wrap_tools, or run it through the gateway"
                )
            else:
                lines.append(
                    f"{word} {n}: protected from the console (rule set version {rs['version']}), but no record or declaration of this program names it yet: if the "
                    "program does not wrap it, signafAIde never sees its calls and cannot protect them (wrap it with record, protect or wrap_tools, or run it through the gateway)"
                )
        if rs:
            for n in strict:
                d = C.disclosure(rs, self.rec.default_agent, n, C.tool_settings(f, n)["disclose"])
                if d["missing"]:
                    m = ", ".join(d["missing"])
                    lines.append(
                        f"{word} {n}: rule set version {rs['version']} needs {m}: run `signafaide pull` to approve sending {m} (it adds them to its disclose list), "
                        "or its protected calls are ruled block (fields_missing)"
                    )
                if d["unsent"]:
                    lines.append(
                        f"{word} {n}: Calibrating rules or exceptions of rule set version {rs['version']} can use {', '.join(d['unsent'])}, which it does not send: "
                        "they are not calibrated until `signafaide pull` adds them"
                    )
        if not strict:
            lines.append(
                "protected tools: none (`signafaide protect <tool>` protects one)"
                if v2
                else 'protected tools: none (a tool is protected by code, the gateway\'s --strict, or `"strict": true` in the checks file)'
            )
        problem = False
        # Stale rules or list (§8), from the disk: a new process sees it too.
        for name, msg in sorted(self.problems.items()):
            lines.append(f"PROBLEM {name}: {msg}")
            problem = True
        return lines, problem

    def dry_run(self, tool: str, args: Any, agent: str) -> Tuple[List[str], bool]:
        """``signafaide check`` and ``signafaide rules test``: a call evaluated as a client does,
        nothing recorded and nothing run. Returns the lines and whether the call would not run."""
        f = self.file() or C.default_checks_file()
        rs = self.held_rules()
        decl = declared_name(tool)
        ts = C.tool_settings(f, decl)
        out: List[str] = []
        blocked = False

        def words(doc: dict, ids: List[str]) -> str:
            return "; ".join(rule_words(next(r for r in doc["rules"] if r["id"] == i)) for i in ids)

        if rs is None and f["rules"] is None:
            out.append("no rule set held and no local rules: nothing to evaluate")
        if rs is not None:
            res = C.evaluate(rs, agent, decl, lambda p: C.resolve(args, p))
            d = C.disclosure(rs, agent, decl, ts["disclose"])
            at = f"version {rs['version']}"
            text = "Block every call that no rule matches" if res["basis"] == "default" else words(rs, res["matched"])
            if res["result"] == "block" and ts["strict"] and rs["mode"] == "enforce":
                blocked = True
                out.append(f"would block  {text} (On, {at})")
            elif res["result"] == "block":
                out.append(f"would note   {text} ({mode_word(rs['mode'])}, {at})")
                if not ts["strict"]:
                    out.append(
                        f"             {decl} is not protected: the rule set binds only protected calls, so this call runs and the rule is noted"
                    )
            elif res["basis"] == "rule":
                out.append(f"allowed      {text} ({at})")
            else:
                out.append(
                    f"allowed      no rule matched; {'Allow' if rs['default'] == 'allow' else 'Block'} every call that no rule matches ({at})"
                )
            if res["would_block"]:
                out.append(f"calibrating  would have blocked: {words(rs, res['would_block'])}")
            if res["excepted"]:
                out.append(f"excepted     allowed by an exception to: {words(rs, res['excepted'])}")
            if ts["strict"]:
                out.append(f"sends        {', '.join(p[1:] or '(the empty key)' for p in d['sent']) or 'no field'}")
                if d["missing"]:
                    blocked = True
                    out.append(
                        f"would block  a rule needs {', '.join(d['missing'])}, which this machine does not send yet; run npx signafaide pull"
                    )
        if f["rules"] is not None:
            res = C.evaluate(f["rules"], agent, decl, lambda p: C.resolve(args, p))
            text = (
                f"{'Block' if f['rules']['default'] == 'block' else 'Allow'} every call that no rule matches"
                if res["basis"] == "default"
                else words(f["rules"], res["matched"])
            )
            if res["result"] == "block" and ts["mode"] == "enforce":
                blocked = True
                out.append(
                    f"would block  {text} (the rules on this machine, {(self.path() or Path(CHECKS_FILE)).name})"
                )
            else:
                out.append(
                    f"{'would note  ' if res['result'] == 'block' else 'allowed     '} {text} (the rules on this machine, {mode_word(ts['mode'])})"
                )
        # The stale gate (§8), as the real call meets it: a protected call is refused, with the same reason.
        prs = rs if rs is not None else self._broken_protect()
        if ts["strict"] or self._protects(prs, decl):
            why = self.stale_refusal()
            if why:
                blocked = True
                out.append(f"would refuse {decl} did not run: {why} (rules_unavailable)")
        out.append(f"             Dry run: nothing recorded, the tool did not run. Exit code {1 if blocked else 0}.")
        return out, blocked

    def test_call(self, tool: str, args: Any, agent: str) -> List[str]:
        """``signafaide rules test``: a call evaluated as a client does, against the held rule set and local rules."""
        f = self.file() or C.default_checks_file()
        rs = self.held_rules()
        decl = declared_name(tool)
        ts = C.tool_settings(f, decl)
        out: List[str] = []

        def matched(m: List[str]) -> str:
            return ": " + ", ".join(m) if m else ""

        if rs is None and f["rules"] is None:
            out.append("no rule set held and no local rules: nothing to evaluate")
        if rs is not None:
            res = C.evaluate(rs, agent, decl, lambda p: C.resolve(args, p))
            out.append(
                f"rule set {rs['set']} version {rs['version']} ({mode_word(rs['mode'])}): {res['result']} ({res['basis']}{matched(res['matched'])})"
            )
            for rid in res["matched"]:
                r = next((x for x in rs["rules"] if x["id"] == rid), None)
                if r is not None:
                    out.append(
                        f"  rule {rid}: {rule_words(r)} ({'On' if C.rule_state(rs, r) == 'on' else 'Calibrating'})"
                    )
            if res["would_block"]:
                out.append(f"  Calibrating rules that would have blocked it: {', '.join(res['would_block'])}")
            if res["excepted"]:
                out.append(f"  allowed by an exception to: {', '.join(res['excepted'])}")
            if not ts["strict"]:
                out.append(
                    f"  {decl} is not protected: the rule set binds only protected calls, so this call runs and the entry is a note"
                )
            d = C.disclosure(rs, agent, decl, ts["disclose"])
            out.append(f"  a protected call discloses: {', '.join(d['sent']) or 'no field'}")
            if d["missing"]:
                out.append(
                    f"  needed fields not in its disclose list: {', '.join(d['missing'])} (a protected call is ruled block, fields_missing)"
                )
        if f["rules"] is not None:
            res = C.evaluate(f["rules"], agent, decl, lambda p: C.resolve(args, p))
            out.append(
                f"local rules ({mode_word(ts['mode'])}): {res['result']} ({res['basis']}{matched(res['matched'])})"
            )
        return out
