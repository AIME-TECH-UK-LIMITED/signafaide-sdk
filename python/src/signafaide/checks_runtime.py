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
from .crypto import hash_json, new_salt, verify_sig
from .http import DEFAULT_URL, SignafaideError
from .jcs import canonicalize, dumps
from .records import now, parse_time
from .words import fail_word, mode_word, rule_words

log = logging.getLogger("signafaide")

CHECKS_FILE = "signafaide.checks.json"

#: The public keys of the default witness (``DEFAULT_URL``), shipped with the SDK and pinned: with
#: the default URL, rule sets, the shared list and rulings verify with these keys only, and a key
#: set fetched from the network is never used (§8). A new key reaches clients with an SDK release.
DEFAULT_SERVICE_KEYS: Tuple[dict, ...] = (
    {"key_id": "7eb0111937aeef44", "public_key": "Z0rlIr0TTqeoJM36r51U3qMO_5fsp2Jk8sMfkeNQAl8", "valid_from": "2026-11-14T17:36:24.017Z", "valid_to": None},
)

#: Why a protected tool stops with no key or sandbox, and the one command that fixes it (one sentence).
NO_KEY_WHY = ("protected tools stop until a person runs `signafaide protect` in this project, because there is no signafAIde key or sandbox "
              "here yet to allow the call.")


class CheckError(SignafaideError):
    """A tool call that did not run: ``blocked`` (a check or the witness's ruling), ``no_ruling``,
    ``rules_unavailable``, ``no_key`` (strict without a key) or ``state`` (the checks file is
    invalid). ``check``, ``rule``, ``rules_version`` and ``missing`` say what to change."""

    def __init__(self, message: str, code: str, *, check: Optional[str] = None, rule: Optional[str] = None,
                 rules_version: Optional[int] = None, missing: Optional[List[str]] = None):
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

    def __init__(self, message: str, code: str, *, tool: str, ruled_by: str, rule_text: Optional[str] = None, check: Optional[str] = None,
                 rule: Optional[str] = None, rules_version: Optional[int] = None, missing: Optional[List[str]] = None):
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
    return (v[0], v[1]) if isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], str) else None


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
        return (f"signafAIde could not rule on it: the sandbox's records for this month are used up (quota_exceeded). Keep the sandbox and choose a "
                f"plan{where}, or wait for next month; until then protected tools stop.")
    return (f"signafAIde could not rule on it: the project's records for this month are used up (quota_exceeded). Upgrade the plan in the console "
            f"({site}/pricing), or wait for next month; until then protected tools stop.")


def checks_path(root: Path) -> Optional[Path]:
    """The checks file: ``SIGNAFAIDE_CHECKS`` names another, ``SIGNAFAIDE_CHECKS=0`` turns checks off."""
    v = os.environ.get("SIGNAFAIDE_CHECKS", "").strip()
    if v in ("0", "false", "off", "no"):
        return None
    return Path(v) if v else root / CHECKS_FILE


def _write_pretty(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)


def _write_jcs(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(dumps(value))
    tmp.replace(path)


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
        self._file: Optional[Tuple[Path, Tuple[int, int, int], dict]] = None  # path, (inode, size, mtime_ns), the version in force
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

    def enabled(self, protect: bool = False) -> bool:
        """Whether checks are on: a checks file exists (valid or not). With *protect* (a tool
        protected in code) they are on unless ``SIGNAFAIDE_CHECKS=0`` turns them off: without a
        checks file such a tool runs every check in On, as ``init`` would write them (§8)."""
        p = self.path()
        return p is not None and (protect or p.exists())

    def file_for(self, protect: bool) -> Optional[dict]:
        """The checks file in force; for a tool protected in code with no checks file, the one
        ``init`` writes with every check On (enforce): its calls are checked here and ruled by the
        witness all the same (§8)."""
        f = self.file()
        if f is None and protect and self.path() is not None:
            f = C.default_checks_file()
            f["mode"] = "enforce"
        return f

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

    def service_keys(self) -> List[dict]:
        """The witness's service keys (§5): the pinned ones for the default witness, else the ones
        held in ``checks/keys.json`` for the witness's URL (none when they were fetched from another)."""
        if self._pinned():
            return [dict(k) for k in DEFAULT_SERVICE_KEYS]
        url = self.rec.url

        def load() -> Optional[List[dict]]:
            doc = _read(self.home / "keys.json")
            if not (isinstance(doc, dict) and isinstance(doc.get("keys"), list)):
                return None
            # A file from before the URL was kept holds the keys of the witness in use then.
            return doc["keys"] if doc.get("url") in (None, url) else []

        return self._stamped(self.home / "keys.json", load, (url,)) or []

    def _rules_path(self, pe: Tuple[str, str]) -> Path:
        return self.home / "rules" / pe[0] / f"{pe[1]}.json"

    def held_rules_item(self) -> Optional[dict]:
        """The held rule set version ``{rules, sig, service_key_id}`` (§8), checked again by §10.2
        steps 1 to 3; None when none is held or it fails (it is then fetched again)."""
        pe = self.project_env()
        if pe is None:
            return None
        path = self._rules_path(pe)
        try:
            ks = os.stat(self.home / "keys.json")
            extra: tuple = (ks.st_ino, ks.st_size, ks.st_mtime_ns)
        except OSError:
            extra = ()

        # The signature check runs again only when the rule set file or the service keys change.
        def load() -> Optional[dict]:
            doc = _read(path)
            return doc if doc is not None and C.accept_rules(None, doc, self.service_keys(), pe[0], pe[1]) is None else None

        item = self._stamped(path, load, extra)
        if item is None and _read(path) is not None:
            self._wake.set()
        return item

    def _listed_pairs(self, held: dict) -> set:
        """The pairs of a held list as a set, made once for each version of the list read."""
        if self._listed is None or self._listed[0] is not held:
            self._listed = (held, C.listed_pairs(held["entries"]))
        return self._listed[1]

    def held_rules(self) -> Optional[dict]:
        item = self.held_rules_item()
        return item["rules"] if item else None

    def held_list(self) -> Optional[dict]:
        """The held shared list ``{seq, last, entries}``; None when none is held (or it was dropped)."""
        path = self.home / "fingerprints.json"

        def load() -> Optional[dict]:
            doc = _read(path)
            if doc is None:
                return None
            if C.held_list_errors(doc):
                try:
                    path.unlink()
                except OSError:
                    pass
                return None
            return doc

        return self._stamped(path, load)

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
                out.append(n[len(prefix):])
        return out

    def _look_alike_of(self, on: dict, agent: str, tool: ToolInfo, declared: str) -> Tuple[List[str], bool]:
        """The tool's look-alike context (§8 ``look_alike_name``): the tools approved earlier, and
        whether its name passes for one of them or of the tools listed with it."""
        if not on["hidden_instruction"] or not tool.name:
            return [], False
        approved = self.approved_names(agent, tool, declared)
        return approved, scan.look_alike_name(tool.name, tool.others, approved)

    def _approval_for(self, rs: Optional[dict], agent: str, tool: ToolInfo, declared: str, fps: dict, look_alike: bool) -> Optional[dict]:
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

    def start(self) -> None:
        """Fetch the rule set and the list now and every 60 s in the background (with an API key)."""
        if self.rec.test or not self.rec.api_key:
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="signafaide-checks", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
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
        for name, fn in (("rules", self.pull_rules), ("fingerprints", self.pull_list)):
            try:
                fn()
            except SignafaideError as e:
                if e.code not in ("network", "rate_limited") and e.status < 500:
                    self.problems[name] = f"could not fetch the {'rule set' if name == 'rules' else 'shared fingerprint list'}: {e.message}"

    def pull_keys(self) -> List[dict]:
        """Fetch the witness's service keys (§5). Never for the default witness: its keys are
        pinned. A fetched set that drops every key held before for the same witness is refused (a
        witness rotates by adding a key first), and the keys held stay in force."""
        if self._pinned():
            return [dict(k) for k in DEFAULT_SERVICE_KEYS]
        doc = self.rec.client(timeout=10.0).service_keys()
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(keys, list) or not all(isinstance(k, dict) and isinstance(k.get("key_id"), str) and isinstance(k.get("public_key"), str) for k in keys):
            return self.service_keys()
        before = self.service_keys()
        if before and not any(k["key_id"] == b.get("key_id") and k["public_key"] == b.get("public_key") for b in before for k in keys):
            self.problems["keys"] = f"bad_response: refused the service keys of {self.rec.url}: they drop every key held before (spec §8); kept the keys held"
            return before
        self.problems.pop("keys", None)
        _write_pretty(self.home / "keys.json", {"keys": keys, "fetched": now(), "url": self.rec.url})
        return keys

    def pull_rules(self) -> str:
        """Fetch the rule set now (§10.2). Returns what happened, in words."""
        api_key = self.rec.api_key
        if not api_key:
            return "no API key: rule sets need one"
        self.rec.resolve_project(api_key)
        pe = self.project_env()
        if pe is None:
            return "the API key's project is not known yet"
        held = self.held_rules_item()
        client = self.rec.client(timeout=10.0)
        item = client.rules(etag=hash_json(held["rules"]) if held else None)
        if item is None:
            self.problems.pop("rules", None)
            self._no_rule_set = held is None
            return f"rule set version {held['rules']['version']} is current" if held else "no rule set"
        if not isinstance(item, dict) or item.get("rules") is None:
            self.problems.pop("rules", None)
            self._no_rule_set = held is None
            return "the project has no rule set" if not held else f"kept rule set version {held['rules']['version']}"
        self._no_rule_set = False
        keys = self.service_keys()
        err = C.accept_rules(held["rules"] if held else None, item, keys, pe[0], pe[1])
        if err == "signature":
            keys = self.pull_keys()
            err = C.accept_rules(held["rules"] if held else None, item, keys, pe[0], pe[1])
        if err is not None:
            v = item["rules"].get("version") if isinstance(item.get("rules"), dict) else "?"
            self.problems["rules"] = f"bad_response: refused rule set version {v} at step {err} (spec §10.2); kept the version held"
            return self.problems["rules"]
        with self._lock:
            _write_jcs(self._rules_path(pe), {k: item[k] for k in ("rules", "sig", "service_key_id")})
            _write_pretty(self.home / "rules" / pe[0] / f"{pe[1]}.at.json", {"fetched": now()})
        self.problems.pop("rules", None)
        return f"rule set version {item['rules']['version']}"

    def keep_rules(self, item: dict) -> bool:
        """Keep a version the client was handed (a publish's answer) as the held version, when
        §10.2 accepts it over the version held. Returns whether it was kept."""
        pe = self.project_env()
        if pe is None or not isinstance(item, dict):
            return False
        held = self.held_rules()
        if C.accept_rules(held, item, self.service_keys(), pe[0], pe[1]) is not None:
            return False
        with self._lock:
            _write_jcs(self._rules_path(pe), {k: item[k] for k in ("rules", "sig", "service_key_id")})
            _write_pretty(self.home / "rules" / pe[0] / f"{pe[1]}.at.json", {"fetched": now()})
        self._no_rule_set = False
        self.problems.pop("rules", None)
        return True

    def forget(self) -> None:
        """Look at the checks file again at the next call."""
        self._looked = float("-inf")

    def pull_list(self) -> str:
        """Fetch the shared fingerprint list now (§11.2)."""
        if not self.rec.api_key:
            return "no API key: the shared list needs one"
        held = self.held_list()
        cur = held or C.empty_list()
        client = self.rec.client(timeout=10.0)
        keys = self.service_keys() or self.pull_keys()
        since = held["seq"] if held else None
        for _ in range(100):
            resp = client.fingerprints(since=since)
            items = ([resp["snapshot"]] if isinstance(resp, dict) and resp.get("snapshot") else []) + list((resp or {}).get("updates") or [])
            gap = False
            for it in items:
                nxt, err = C.apply_list(cur, it, keys)
                if err == "signature" and keys is not None:
                    keys = self.pull_keys()
                    nxt, err = C.apply_list(cur, it, keys)
                if err == "gap":
                    gap = True
                    break
                if err is not None:
                    self.problems["fingerprints"] = f"bad_response: refused a shared list item at step {err} (spec §11.2); kept the list held"
                    self._save_list(cur)
                    return self.problems["fingerprints"]
                cur = nxt
            self._save_list(cur)
            if gap or len((resp or {}).get("updates") or []) >= 1000:
                since = cur["seq"]
                continue
            break
        self.problems.pop("fingerprints", None)
        return f"shared list seq {cur['seq']}"

    def _save_list(self, cur: dict) -> None:
        with self._lock:
            _write_pretty(self.home / "fingerprints.json", {"seq": cur["seq"], "last": cur["last"], "entries": cur["entries"]})
            _write_pretty(self.home / "fingerprints.at.json", {"fetched": now()})

    # --- a call (§8) --------------------------------------------------------------------

    def witness_host(self) -> Optional[str]:
        return C.url_host(self.rec.url)

    def plan(self, tool: ToolInfo, agent: str, args: Any, *, strict_code: bool, call_id: Any = None, telemetry: bool = False,
             declared: Optional[str] = None, protect: bool = False) -> Optional[Plan]:
        """Steps 1 and 2 of a call (§8): the decision checks on *args*, the `checks` the decision
        carries, and the values a strict call discloses. None when checks are off. *telemetry*:
        the OpenTelemetry plug-in, which never blocks (every entry in watch mode, not strict).
        *declared*: the declared name (§2.6) the checks use, when it is not the tool's own name
        cut (a wrapper's name for a framework tool named otherwise)."""
        f = self.file_for(bool(strict_code or protect) and not telemetry)
        if f is None:
            return None
        self.start()
        decl = declared if declared is not None else declared_name(tool.name)
        ts = C.tool_settings(f, decl)
        mode = "watch" if telemetry else ts["mode"]
        file_fail = (f["tools"].get(decl) or {}).get("fail") if C.checks_file_version(f) == 1 and not protect else None
        cfg = {"strict": ts["strict"], "disclose": ts["disclose"], "fail": file_fail}
        strict = False if telemetry else bool(strict_code or cfg.get("strict"))
        rs = self.held_rules()
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
            results.append(C.entry("fingerprint", C.fingerprint_findings_in(fps, self._listed_pairs(held), excepted), mode))
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
            definition = C.definition_findings(shown, tool.name, tool.others, like_approved) if shown is not None else None
            arg_f = C.argument_findings(args)
            fnd = C.decision_instruction_findings(definition, arg_f)
            if shown is not None or fnd["found"]:
                results.append(C.entry("hidden_instruction", fnd, mode))
            if fnd is arg_f:
                notes = C.call_notes(decl, "arguments", arg_f)
        result = C.combined(results)
        fail = None
        if strict:
            fail = (rs["fail"].get(decl) if rs else None) or cfg.get("fail") or "closed"
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
        checks = {"results": results, "result": result, "rules": rules_used, "fingerprints": held["seq"] if held else None, "tool": fps,
                  "strict": strict, "fail": fail, "disclosed": pointers, "disclosed_hash": C.disclosed_hash(values, salt) if pointers else None,
                  "call_id": cid}
        timeout = f.get("ruling_timeout_ms", C.RULING_TIMEOUT_MS)
        plan = Plan(checks, strict, fail, timeout, values if pointers else None, salt, None, rs["version"] if rs else None, not_disclosed, decl, cfg.get("fail"), notes=notes)
        if result == "block":
            plan.blocked = self._block_error(decl, next(e for e in results if e["result"] == "block"), rs, f["rules"])
        elif strict and rs is not None and rs["mode"] == "enforce" and held_entry is not None and held_entry.get("enforce_result") == "block":
            plan.held_block = self._held_block_error(decl, held_entry, rs)
        return plan

    def _held_block_error(self, tool: str, e: dict, rs: dict) -> SignafaideBlocked:
        """A strict call with no ruling that the held version would block (§8): the client decides
        alone, with the rules it holds, and says the witness did not rule."""
        rid = e["matched"][0] if e["matched"] else None
        rule = next((r for r in rs["rules"] if r["id"] == rid), None) if rid else None
        text = rule_words(rule) if rule is not None else (f"rule {rid}" if rid else "Block every call that no rule matches")
        return SignafaideBlocked(f"{tool} did not run: signafAIde did not rule on it, and the signed rule set version {rs['version']} held here blocks it "
                                 f"(\"{text}\"). To allow such calls, change the rule in the console.", "blocked", check="rule", rule=rid,
                                 rules_version=rs["version"], tool=tool, rule_text=text, ruled_by="client")

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
                text = f"{'Block' if (doc or {}).get('default') == 'block' else 'Allow'} every call that no rule matches"
            if local:
                msg = f"{tool} did not run: the rule on this machine blocked it (\"{text}\"); signafAIde did not rule on it. To allow it, change the rule in {file}."
            else:
                msg = f"{tool} did not run: blocked here under signed rule set version {v} (\"{text}\"); the witness did not rule on it. To allow such calls, change the rule in the console."
            return SignafaideBlocked(msg, "blocked", check="rule", rule=rid, rules_version=None if local else v, tool=tool, rule_text=text, ruled_by="client")
        found = ", ".join(e["found"])
        why = {
            "secret": f"its arguments hold a secret ({found}). To allow it, remove the secret, or send it only to the service that issued it.",
            "address": f"it goes to an address that is not public ({found}). If that address is meant, add the host to addresses in {file}, or to the rule set's allowlist in the console.",
            "changed_tool": f"the tool changed since it was approved ({found}). To allow it, re-approve the tool: `npx signafaide checks approve {tool}`, or in the console when the rule set approves tools.",
            "fingerprint": f"it is on the list of known bad tools ({found}). Remove or replace the tool.",
            "hidden_instruction": f"what the agent is shown of the tool {shown_why(e['found'])}. Review the tool's description and schema; if it is meant, set the tool's `mode` to `\"watch\"` in {file} (Calibrating: it is shown and noted, nothing is blocked).",
        }
        return SignafaideBlocked(f"{tool} did not run: {why[c]}", "blocked", check=c, rules_version=v, tool=tool, ruled_by="client")

    def ruling(self, d: dict, plan: Plan, tool: str) -> Tuple[str, Optional[CheckError]]:
        """Step 4 of a strict call (§8): ship the decision, wait for its receipt up to the ruling
        timeout, and read the ruling. Returns the outcome's ``ruling`` (``allow``, ``block``,
        ``none``) and the error to raise when the tool must not run."""
        rec = self.rec
        if rec.test:
            return "none", None  # test mode sends nothing: strict calls run without a ruling
        closed = plan.fail != "open"
        if not rec.api_key:
            err = SignafaideBlocked(f"{tool} did not run: {NO_KEY_WHY}", "no_key", tool=tool, ruled_by="client")
            return "none", (err if closed else None)
        why = "no receipt came"
        code = "no_ruling"
        deadline = time.monotonic() + plan.timeout_ms / 1000
        # No rule set held (a cold start, or its file or the keys file was removed): fetch it now,
        # within the same ruling timeout, so its fail mode is known before the call may run.
        fetching = self.held_rules() is None and not self._no_rule_set
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
            q = SignafaideBlocked(f"{tool} did not run: {quota_words(rec, refused)}", refused.code, tool=tool, ruled_by="client")
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
                    if isinstance(g.get("rules"), dict) and (held is None or g["rules"]["version"] > held["version"]):
                        self.wake()  # a newer version than the one held: fetch it at once (§8)
                    if g["ruling"] == "allow":
                        return "allow", None
                    return "block", self._ruling_error(tool, g)
        # No ruling: the client decides alone. The rules it holds still block what they block; else
        # the tool's If unreachable setting (Stop by default) decides.
        if plan.held_block is not None:
            return "none", plan.held_block
        if blocked is not None and receipt is None:
            err = SignafaideBlocked(f"{tool} did not run: signafAIde did not rule on it, and this tool is set to stop. {blocked.message}", code, tool=tool, ruled_by="client")
            return "none", (err if closed else None)
        err = SignafaideBlocked(f"{tool} did not run: signafAIde did not rule on it ({why}), and this tool is set to stop. Check the network and "
                                "`signafaide checks status`; the console sets whether it stops or runs.", code, tool=tool, ruled_by="client")
        return "none", (err if closed else None)

    def _fail_closed(self, plan: Plan) -> bool:
        """The fail mode of a strict call that has no ruling (§8): the held rule set's for the
        tool, else the checks file's when the witness said the project has no rule set, else
        closed. With an API key and no rule set held, nothing local can open it: the rule set the
        witness holds may say closed."""
        rs = self.held_rules()
        if rs is not None:
            return ((rs["fail"].get(plan.declared) if plan.declared is not None else None) or plan.file_fail or plan.fail or "closed") != "open"
        if self._no_rule_set:
            return plan.fail != "open"
        return True

    def _ruling_problem(self, receipt: dict, d: dict) -> Optional[str]:
        g, sig = receipt.get("ruling"), receipt.get("ruling_sig")
        err = C.ruling_errors(g)
        if err:
            return f"the ruling is malformed ({err})"
        if g["record_hash"] != receipt.get("record_hash") or g["batch_hash"] != receipt.get("batch_hash") or g["server_time"] != (receipt.get("batch") or {}).get("server_time"):
            return "the ruling names another record than its receipt"
        keys = self.service_keys()
        k = next((k for k in keys if k.get("key_id") == receipt.get("service_key_id")), None)
        if k is None:
            try:
                keys = self.pull_keys()
            except SignafaideError:
                keys = []
            k = next((k for k in keys if k.get("key_id") == receipt.get("service_key_id")), None)
        if k is None or not isinstance(sig, str) or not verify_sig(k["public_key"], "ruling", hash_json(g), sig):
            return "the ruling's signature does not verify with the witness's keys"
        # The key must be active when the witness ruled: a retired key never signs a new ruling.
        if not C.key_active(k, g["server_time"]):
            return f"the ruling's service key {k['key_id']} was not active at {g['server_time']}"
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
            msg = (f"{tool} did not run: a rule needs {fields}, which this machine does not send yet{at}; run npx signafaide pull "
                   f"(it adds {', '.join(g['missing'])} to the disclose list of {tool} in the checks file).")
        elif basis == "fingerprint":
            msg = f"{tool} did not run: it is on the list of known bad tools{at}. Remove or replace the tool."
        elif basis == "rules_version":
            msg = f"{tool} did not run: {g['reason']}"
        elif basis == "error":
            msg = (f"{tool} did not run: signafAIde blocked it under \"{text or f'rule {rule}'}\"{at}, because a field had the wrong type for the rule. "
                   "To allow it, send the field with the type the rule expects, or change the rule in the console.")
        else:
            shown = text or (f"rule {rule}" if rule else "Block every call that no rule matches")
            msg = f"{tool} did not run: signafAIde blocked it under \"{shown}\"{at}. To allow such calls, change the rule in the console."
        return SignafaideBlocked(msg, "blocked", check="rule" if basis in ("rule", "error", "default") else basis, rule=rule, rules_version=v,
                                 missing=g["missing"], tool=tool, rule_text=text, ruled_by="witness")

    def result_entries(self, output: Any, telemetry: bool = False, tool: Optional[str] = None, protect: bool = False) -> List[dict]:
        """Step 5 (§8): the result checks of a call that ran (``secret``, ``hidden_instruction``),
        in the mode the checks file sets for *tool* (its declared name); *protect*: a tool
        protected in code, checked in On without a checks file."""
        f = self.file_for(protect and not telemetry)
        if f is None:
            return []
        if telemetry:
            mode = "watch"
        elif tool is not None:
            mode = C.tool_settings(f, tool)["mode"]
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
        return C.call_notes(tool, "result", {"result": e.get("enforce_result", e["result"]), "found": e["found"]}) if e else []

    def withheld(self, tool: str, results: List[dict]) -> Optional[SignafaideBlocked]:
        """The error that replaces a result the client withheld (§8 step 5): the tool ran, and its
        result held a secret, so the agent is not given it. None when no entry blocks."""
        e = next((x for x in results if x["result"] == "block"), None)
        if e is None:
            return None
        file = (self.path() or Path(CHECKS_FILE)).name
        return SignafaideBlocked(
            f"{tool} ran, but its result was withheld from the agent: it holds a secret ({', '.join(e['found'])}). What the tool did stands. "
            f"If the agent should see such results, set the tool's `mode` to `\"watch\"` in {file} (Calibrating: the result goes through and the finding is noted).",
            "withheld", check=e["check"], tool=tool, ruled_by="client")

    def seen(self, tool: ToolInfo, agent: str, declared: str, protect: bool = False) -> None:
        """A wrapper is shown a tool's definition (§8 changed_tool): approve its fingerprints the
        first time, so a change before its first call is still a change."""
        try:
            f = self.file_for(protect)
            if f is None or not f["checks"]["changed_tool"] or not tool.name:
                return
            rs = self.held_rules()
            if rs is not None and rs.get("approved") is not None:
                return
            if self._look_alike_of(f["checks"], agent, tool, declared)[1]:
                return  # never approved
            self.local_approval(agent, server_identity(tool), declared, C.tool_fingerprints(tool.name, tool.description or "", tool.input_schema, tool.server_info))
        except Exception:  # the call's own checks report a broken checks file
            return

    # --- status (signafaide checks status) ----------------------------------------------

    def strict_tools(self, f: dict) -> List[str]:
        """The tools the checks file makes strict (version 1 ``strict``, version 2 ``protect``)."""
        return sorted(n for n in f["tools"] if C.tool_settings(f, n)["strict"])

    def status(self) -> Tuple[List[str], bool]:
        """The lines of ``signafaide checks status``, and whether there is a problem."""
        lines: List[str] = []
        path = self.path()
        if path is None:
            return ["checks: off (SIGNAFAIDE_CHECKS=0)"], False
        try:
            f = self.file()
        except CheckError as e:
            return [f"checks: PROBLEM {e.message}"], True
        if f is None:
            return [f"checks: off for tools not protected in code (no {path}; `signafaide protect` or `signafaide init` writes one); a tool protected in code runs every check in On"], False
        on = [k for k in C.FILE_CHECKS if f["checks"][k]]
        v2 = C.checks_file_version(f) == 2
        if v2:
            lines.append(f"checks: on, On or Calibrating per tool ({path}, version 2): protected tools are On, others Calibrating unless the file sets a tool's `mode`; checks on: {', '.join(on) or 'none'}")
        else:
            lines.append(f"checks: on, {mode_word(f['mode'])} ({path}, version 1: `mode` is \"{f['mode']}\"); checks on: {', '.join(on) or 'none'}")
        rs = self.held_rules()
        item = self.held_rules_item()
        pe = self.project_env()
        if rs:
            at = (_read(self._rules_path(pe).with_name(f"{pe[1]}.at.json")) or {}).get("fetched") if pe else None
            lines.append(f"rule set: {rs['set']} version {rs['version']}, {mode_word(rs['mode'])}, default {rs['default']}, issued {rs['issued']} (fetched copy {_age(at)})")
            for r in rs["rules"]:
                lines.append(f"rule {r['id']}: {rule_words(r)} ({'On' if C.rule_state(rs, r) == 'on' else 'Calibrating'})")
        elif item is None:
            lines.append("rule set: none held" + ("" if self.rec.api_key else " (no API key)"))
        held = self.held_list()
        at = (_read(self.home / "fingerprints.at.json") or {}).get("fetched")
        lines.append(f"shared fingerprint list: seq {held['seq']}, {len(held['entries'])} entries ({_age(at)})" if held else "shared fingerprint list: none held")
        lines.append(f"ruling timeout: {f.get('ruling_timeout_ms', C.RULING_TIMEOUT_MS)} ms")
        strict = self.strict_tools(f)
        word = "protected tool"
        for n in strict:
            t = C.tool_settings(f, n)
            fail = (rs["fail"].get(n) if rs else None) or ("closed" if v2 else (f["tools"][n].get("fail") or "closed"))
            lines.append(f"{word} {n}: if signafAIde can't be reached: {fail_word(fail)}{', local checks ' + mode_word(t['mode']) if v2 else ''}; discloses {', '.join(t['disclose']) or 'no field'}")
        if rs:
            for n in strict:
                d = C.disclosure(rs, self.rec.default_agent, n, C.tool_settings(f, n)["disclose"])
                if d["missing"]:
                    lines.append(f"{word} {n}: rule set version {rs['version']} needs {', '.join(d['missing'])}: add them to its disclose list (`signafaide pull`), "
                                 "or its protected calls are ruled block (fields_missing)")
                if d["unsent"]:
                    lines.append(f"{word} {n}: Calibrating rules or exceptions of rule set version {rs['version']} can use {', '.join(d['unsent'])}, which it does not send: "
                                 "they are not calibrated until `signafaide pull` adds them")
        if not strict:
            lines.append("protected tools: none (`signafaide protect <tool>` protects one)" if v2 else
                         "protected tools: none (a tool is protected by code, the gateway's --strict, or `\"strict\": true` in the checks file)")
        problem = False
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
                    out.append(f"             {decl} is not protected: the rule set binds only protected calls, so this call runs and the rule is noted")
            elif res["basis"] == "rule":
                out.append(f"allowed      {text} ({at})")
            else:
                out.append(f"allowed      no rule matched; {'Allow' if rs['default'] == 'allow' else 'Block'} every call that no rule matches ({at})")
            if res["would_block"]:
                out.append(f"calibrating  would have blocked: {words(rs, res['would_block'])}")
            if res["excepted"]:
                out.append(f"excepted     allowed by an exception to: {words(rs, res['excepted'])}")
            if ts["strict"]:
                out.append(f"sends        {', '.join(p[1:] or '(the empty key)' for p in d['sent']) or 'no field'}")
                if d["missing"]:
                    blocked = True
                    out.append(f"would block  a rule needs {', '.join(d['missing'])}, which this machine does not send yet; run npx signafaide pull")
        if f["rules"] is not None:
            res = C.evaluate(f["rules"], agent, decl, lambda p: C.resolve(args, p))
            text = f"{'Block' if f['rules']['default'] == 'block' else 'Allow'} every call that no rule matches" if res["basis"] == "default" else words(f["rules"], res["matched"])
            if res["result"] == "block" and ts["mode"] == "enforce":
                blocked = True
                out.append(f"would block  {text} (the rules on this machine, {(self.path() or Path(CHECKS_FILE)).name})")
            else:
                out.append(f"{'would note  ' if res['result'] == 'block' else 'allowed     '} {text} (the rules on this machine, {mode_word(ts['mode'])})")
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
            out.append(f"rule set {rs['set']} version {rs['version']} ({mode_word(rs['mode'])}): {res['result']} ({res['basis']}{matched(res['matched'])})")
            for rid in res["matched"]:
                r = next((x for x in rs["rules"] if x["id"] == rid), None)
                if r is not None:
                    out.append(f"  rule {rid}: {rule_words(r)} ({'On' if C.rule_state(rs, r) == 'on' else 'Calibrating'})")
            if res["would_block"]:
                out.append(f"  Calibrating rules that would have blocked it: {', '.join(res['would_block'])}")
            if res["excepted"]:
                out.append(f"  allowed by an exception to: {', '.join(res['excepted'])}")
            if not ts["strict"]:
                out.append(f"  {decl} is not protected: the rule set binds only protected calls, so this call runs and the entry is a note")
            d = C.disclosure(rs, agent, decl, ts["disclose"])
            out.append(f"  a protected call discloses: {', '.join(d['sent']) or 'no field'}")
            if d["missing"]:
                out.append(f"  needed fields not in its disclose list: {', '.join(d['missing'])} (a protected call is ruled block, fields_missing)")
        if f["rules"] is not None:
            res = C.evaluate(f["rules"], agent, decl, lambda p: C.resolve(args, p))
            out.append(f"local rules ({mode_word(ts['mode'])}): {res['result']} ({res['basis']}{matched(res['matched'])})")
        return out
