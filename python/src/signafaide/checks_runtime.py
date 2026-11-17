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
from .coverage import declared_name
from .crypto import hash_json, new_salt, verify_sig
from .http import DEFAULT_URL, SignafaideError
from .jcs import canonicalize, dumps
from .records import now, parse_time

log = logging.getLogger("signafaide")

CHECKS_FILE = "signafaide.checks.json"

#: The public keys of the default witness (``DEFAULT_URL``), shipped with the SDK and pinned: with
#: the default URL, rule sets, the shared list and rulings verify with these keys only, and a key
#: set fetched from the network is never used (§8). A new key reaches clients with an SDK release.
DEFAULT_SERVICE_KEYS: Tuple[dict, ...] = (
    {"key_id": "7eb0111937aeef44", "public_key": "Z0rlIr0TTqeoJM36r51U3qMO_5fsp2Jk8sMfkeNQAl8", "valid_from": "2026-11-14T17:36:24.017Z", "valid_to": None},
)


class CheckError(SignafaideError):
    """A tool call that did not run: ``blocked`` (a check or the witness's ruling), ``no_ruling``,
    ``rules_unavailable``, ``no_key`` (strict without a key) or ``state`` (the checks file is
    invalid). ``check``, ``rule``, ``rules_version`` and ``missing`` say what to change."""

    def __init__(self, message: str, code: str, *, check: Optional[str] = None, rule: Optional[str] = None,
                 rules_version: Optional[int] = None, missing: Optional[List[str]] = None):
        super().__init__(message, code=code)
        self.check, self.rule, self.rules_version, self.missing = check, rule, rules_version, list(missing or [])


@dataclasses.dataclass(frozen=True)
class ToolInfo:
    """What the agent is shown of a tool (§11.1): its whole name, description, input schema and
    the MCP server's ``serverInfo`` (None for a tool that does not come from one)."""

    name: str
    description: str = ""
    input_schema: Any = None
    server_info: Optional[dict] = None


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

    def enabled(self) -> bool:
        """Whether checks are on: a checks file exists (valid or not)."""
        p = self.path()
        return p is not None and p.exists()

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

    def local_approval(self, agent: str, name: str, fps: dict) -> dict:
        """A tool's local approval (§8): its fingerprints the first time the client sees it."""
        have = self.approvals(agent).get(name)
        if isinstance(have, dict) and "description" in have and "schema" in have:
            return have
        path = self._approved_path(agent)
        with self.rec.state._lock_at(path.with_suffix(".lock")):
            doc = self.approvals(agent)
            if name not in doc:
                doc[name] = {"description": fps["description"], "schema": fps["schema"], "at": now()}
                _write_pretty(path, doc)
            return doc[name]

    def approve(self, name: str, agent: Optional[str] = None) -> List[str]:
        """``signafaide checks approve <tool>``: drop the tool's local approval, so its next call
        approves the description and schema it has then. Returns the agents it was dropped for."""
        root = self.home / "approved"
        agents = [agent] if agent else [p.stem for p in sorted(root.glob("*.json"))] if root.is_dir() else []
        done = []
        for a in agents:
            path = self._approved_path(a)
            with self.rec.state._lock_at(path.with_suffix(".lock")):
                doc = self.approvals(a)
                if name in doc:
                    del doc[name]
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
             declared: Optional[str] = None) -> Optional[Plan]:
        """Steps 1 and 2 of a call (§8): the decision checks on *args*, the `checks` the decision
        carries, and the values a strict call discloses. None when checks are off. *telemetry*:
        the OpenTelemetry plug-in, which never blocks (every entry in watch mode, not strict).
        *declared*: the declared name (§2.6) the checks use, when it is not the tool's own name
        cut (a wrapper's name for a framework tool named otherwise)."""
        f = self.file()
        if f is None:
            return None
        self.start()
        decl = declared if declared is not None else declared_name(tool.name)
        mode = "watch" if telemetry else f["mode"]
        cfg = f["tools"].get(decl) or {}
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
        if on["changed_tool"]:
            if rs is not None and rs["approved"] is not None:
                approved = rs["approved"].get(decl)
            else:
                approved = self.local_approval(agent, decl, fps)
            results.append(C.entry("changed_tool", C.changed_tool_findings(fps, approved), mode))
        if on["fingerprint"] and held is not None:
            excepted = C.excepted_pairs(rs) if rs is not None else None
            results.append(C.entry("fingerprint", C.fingerprint_findings_in(fps, self._listed_pairs(held), excepted), mode))
        rules_used: List[dict] = []
        if rs is not None:
            m = "watch" if telemetry else C.entry_mode(rs["mode"], strict, False)
            results.append(C.client_rule_entry(rs, m, rs["set"], agent, decl, args))
            rules_used.append({"set": rs["set"], "version": rs["version"], "hash": self._hash(rs)})
        if f["rules"] is not None:
            results.append(C.client_rule_entry(f["rules"], mode, "local", agent, decl, args))
            rules_used.append({"set": "local", "version": None, "hash": self._hash(f["rules"])})
        result = C.combined(results)
        fail = None
        if strict:
            fail = (rs["fail"].get(decl) if rs else None) or cfg.get("fail") or "closed"
        need = C.needed_fields(rs, agent, decl)
        disclose = cfg.get("disclose") or []
        not_disclosed = [p for p in need if p not in disclose]
        pointers: List[str] = []
        values: Optional[dict] = None
        salt: Optional[str] = None
        if strict and result != "block":
            pointers = [p for p in need if p in disclose]
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
        plan = Plan(checks, strict, fail, timeout, values if pointers else None, salt, None, rs["version"] if rs else None, not_disclosed, decl, cfg.get("fail"))
        if result == "block":
            plan.blocked = self._block_error(decl, next(e for e in results if e["result"] == "block"), rs)
        return plan

    def _block_error(self, tool: str, e: dict, rs: Optional[dict]) -> CheckError:
        c = e["check"]
        v = rs["version"] if rs else None
        if c == "rule":
            rid = e["matched"][0] if e["matched"] else None
            local = e["set"] == "local"
            where = "the local rules (checks file)" if local else f"rule set version {v}"
            what = f"rule {rid} of {where} blocked it" if rid else f"no rule of {where} allows it, and its default is block"
            fix = "change the rule in the checks file" if local else "change the rule in the console"
            return CheckError(f"{tool} did not run: {what}. To allow it: {fix}.", "blocked", check="rule", rule=rid, rules_version=None if local else v)
        found = ", ".join(e["found"])
        fixes = {
            "secret": "remove the secret from the call's arguments, or send it only to the service that issued it",
            "address": "if the address is meant, add the host to addresses.hosts or addresses.cidrs in the checks file, or to the rule set's allowlist in the console",
            "changed_tool": f"re-approve the tool: `signafaide checks approve {tool}`, or in the console when the rule set approves tools",
            "fingerprint": "remove or replace the tool: its fingerprint was reported as malicious and accepted after review",
        }
        return CheckError(f"{tool} did not run: the {c} check found {found}. To allow it: {fixes[c]}.", "blocked", check=c, rules_version=v)

    def ruling(self, d: dict, plan: Plan, tool: str) -> Tuple[str, Optional[CheckError]]:
        """Step 4 of a strict call (§8): ship the decision, wait for its receipt up to the ruling
        timeout, and read the ruling. Returns the outcome's ``ruling`` (``allow``, ``block``,
        ``none``) and the error to raise when the tool must not run."""
        rec = self.rec
        if rec.test:
            return "none", None  # test mode sends nothing: strict calls run without a ruling
        closed = plan.fail != "open"
        if not rec.api_key:
            err = CheckError(f"{tool} did not run: strict mode needs the witness's ruling, and there is no API key. Run `signafaide init` (a free sandbox) "
                             "or set SIGNAFAIDE_API_KEY, or drop strict for this tool.", "no_key")
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
        try:
            receipt = rec.ensure_receipt(d, timeout=plan.timeout_ms / 1000)
        except SignafaideError as e:
            receipt, why = None, f"no receipt came within {plan.timeout_ms} ms ({e.message})"
        if fetching:
            with self._round_done:
                self._round_done.wait_for(lambda: self._rounds > rounds, timeout=max(0.0, deadline - time.monotonic()))
        closed = self._fail_closed(plan)
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
        err = CheckError(f"{tool} did not run: {why}, and its fail mode is closed. Check the network and `signafaide checks status`, or set "
                         f"\"fail\": \"open\" for {tool} in the checks file (unless the rule set sets it).", code)
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

    def _ruling_error(self, tool: str, g: dict) -> CheckError:
        v = g["rules"]["version"] if isinstance(g.get("rules"), dict) else None
        rule = g["matched"][0] if g["matched"] else None
        msg = f"{tool} did not run: the witness ruled block ({g['basis']}): {g['reason']}"
        if g["basis"] == "fields_missing":
            msg += f" Add {', '.join(g['missing'])} to the disclose list of {tool} in the checks file."
        return CheckError(msg, "blocked", check="rule" if g["basis"] in ("rule", "error", "default") else g["basis"], rule=rule, rules_version=v, missing=g["missing"])

    def result_entries(self, output: Any, telemetry: bool = False) -> List[dict]:
        """Step 5 (§8): the result checks of a call that ran (``hidden_instruction``)."""
        f = self.file()
        if f is None or not f["checks"]["hidden_instruction"]:
            return []
        return [C.entry("hidden_instruction", C.hidden_findings(output), "watch" if telemetry else f["mode"])]

    # --- status (signafaide checks status) ----------------------------------------------

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
            return [f"checks: off (no {path}; `signafaide init` writes one in watch mode)"], False
        on = [k for k in C.FILE_CHECKS if f["checks"][k]]
        lines.append(f"checks: on, {f['mode']} mode ({path}); checks on: {', '.join(on) or 'none'}")
        rs = self.held_rules()
        item = self.held_rules_item()
        pe = self.project_env()
        if rs:
            at = (_read(self._rules_path(pe).with_name(f"{pe[1]}.at.json")) or {}).get("fetched") if pe else None
            lines.append(f"rule set: {rs['set']} version {rs['version']}, {rs['mode']} mode, default {rs['default']}, issued {rs['issued']} (fetched copy {_age(at)})")
        elif item is None:
            lines.append("rule set: none held" + ("" if self.rec.api_key else " (no API key)"))
        held = self.held_list()
        at = (_read(self.home / "fingerprints.at.json") or {}).get("fetched")
        lines.append(f"shared fingerprint list: seq {held['seq']}, {len(held['entries'])} entries ({_age(at)})" if held else "shared fingerprint list: none held")
        lines.append(f"ruling timeout: {f.get('ruling_timeout_ms', C.RULING_TIMEOUT_MS)} ms")
        strict = sorted(n for n, t in f["tools"].items() if t.get("strict"))
        for n in strict:
            t = f["tools"][n]
            fail = (rs["fail"].get(n) if rs else None) or t.get("fail") or "closed"
            disclose = t.get("disclose") or []
            lines.append(f"strict tool {n}: fail {fail}; discloses {', '.join(disclose) or 'no field'}")
        if rs:
            for n in strict:
                need = sorted({c["field"] for r in rs["rules"] if r["tools"] is None or n in r["tools"] for c in r["when"]})
                missing = [p for p in need if p not in (f["tools"][n].get("disclose") or [])]
                if missing:
                    lines.append(f"strict tool {n}: rule set version {rs['version']} needs {', '.join(missing)}: add them to its disclose list, or its strict calls are ruled block (fields_missing)")
        if not strict:
            lines.append("strict tools: none (a tool is strict by code, the gateway's --strict, or \"strict\": true in the checks file)")
        problem = False
        for name, msg in sorted(self.problems.items()):
            lines.append(f"PROBLEM {name}: {msg}")
            problem = True
        return lines, problem

    def test_call(self, tool: str, args: Any, agent: str) -> List[str]:
        """``signafaide rules test``: a call evaluated as a client does, against the held rule set and local rules."""
        f = self.file() or C.default_checks_file()
        rs = self.held_rules()
        decl = declared_name(tool)
        cfg = f["tools"].get(decl) or {}
        out: List[str] = []
        if rs is None and f["rules"] is None:
            out.append("no rule set held and no local rules: nothing to evaluate")
        if rs is not None:
            res = C.evaluate(rs, agent, decl, lambda p: C.resolve(args, p))
            out.append(f"rule set {rs['set']} version {rs['version']} ({rs['mode']} mode): {res['result']} ({res['basis']}{': ' + ', '.join(res['matched']) if res['matched'] else ''})")
            if not cfg.get("strict"):
                out.append(f"  {decl} is not strict: the rule set binds only strict calls, so this call runs and the entry is a note in watch mode")
            need = C.needed_fields(rs, agent, decl)
            disclose = cfg.get("disclose") or []
            out.append(f"  a strict call discloses: {', '.join(p for p in need if p in disclose) or 'no field'}")
            missing = [p for p in need if p not in disclose]
            if missing:
                out.append(f"  needed fields not in its disclose list: {', '.join(missing)} (a strict call is ruled block, fields_missing)")
        if f["rules"] is not None:
            res = C.evaluate(f["rules"], agent, decl, lambda p: C.resolve(args, p))
            out.append(f"local rules ({f['mode']} mode): {res['result']} ({res['basis']}{': ' + ', '.join(res['matched']) if res['matched'] else ''})")
        return out
