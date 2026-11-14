"""Local state in ``.signafaide/`` (SPEC §8).

A chain is identified by ``<project>/<env>/<agent>`` (the service chains per
project, env and agent). Records written before the project of the API key is
known go to ``_pending/<key fingerprint>/<agent>`` (or ``_pending/nokey/<agent>``
when there is no key yet) and the whole chain is moved under its project once a
sandbox response or a receipt names it.

- ``agents/<agent>.key``                 private key (JSON with its ``created`` time, mode 0600);
                                         live chains use their own key, ``agents/live/<agent>.key``
- ``agents/retired/<agent>.<key_id>.key`` keys replaced by ``signafaide keys rotate`` (``agents/live/retired/`` for live)
- ``held/<chain>/<from>-<to>.jsonl``     records ``signafaide repair`` set aside (kept, verifiable)
- ``blocked.json``                       chains the witness refused, with why (status, verify, replay)
- ``chain/<chain>.jsonl``                one JCS line per record ``{envelope, key_id, sig, content, receipt?}``;
                                         in a ``_pending`` chain, unsigned drafts ``{draft, envelope, content, store_content}``
- ``chain/<chain>.drafts.json``          draft hash -> signed record hash, once a pending chain was signed
- ``outbox/<chain>/<seq>.json``          signed records not yet accepted by the service
- ``head.json``                          newest signed head, ``{project: {env: {agent: {head, head_sig}}}}``
- ``config.json``                        coding agent; API key fingerprint -> {project, env}
- ``sandbox.json``                       the sandbox project and claim link

Writers take a per-chain lock file, so several processes can record for the same
agent without forking its chain. The chain file is append-only, except that
receipts are filled into the trailing lines that do not have one yet; that
rewrite goes through a journal (``<agent>.jsonl.tail``) so a crash never loses a line.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import jcs
from .crypto import SigningKey, b64url, b64url_decode
from .records import AGENT_KEYS_FORMAT, AGENT_RE, ENVS, _valid_time, manifest_entry, now, parse_time, record_hash, sign_draft, valid_project_id

_MARKERS = (".git", "pyproject.toml", "package.json")
LOCK_STALE_S = 10.0
LOCK_WAIT_S = 15.0
PENDING = "_pending"
SCOPES = ("", "live")
#: A provider of agent keys from a secret store: ``(agent, scope) -> key file dict or JSON text, or None``.
KeyProvider = Callable[[str, str], Any]


def segment_bytes() -> int:
    """A shipped chain file larger than this rolls into a sealed segment (SIGNAFAIDE_SEGMENT_BYTES)."""
    try:
        return int(os.environ.get("SIGNAFAIDE_SEGMENT_BYTES") or 0) or 64 * 1024 * 1024
    except ValueError:
        return 64 * 1024 * 1024


def scope_of(bucket: str) -> str:
    """Which agent key a chain uses: live chains have their own key (§8), everything else the default."""
    return "live" if bucket.endswith("/live") else ""


def agent_key_env_name(agent: str, scope: str = "") -> str:
    """``SIGNAFAIDE_AGENT_KEY_<NAME>``: an agent's key file content from the environment or a secret store."""
    return "SIGNAFAIDE_AGENT_KEY_" + ("LIVE_" if scope else "") + "".join(c if c.isalnum() else "_" for c in agent.upper())


class StateError(Exception):
    """Local state is unusable; the message says how to fix it."""


def fs_error(e: OSError, home: Path) -> Exception:
    """A file-system error, said plainly: what could not be written, and how to fix it."""
    import errno

    if e.errno in (errno.EACCES, errno.EROFS, errno.EPERM):
        why = "read-only file system" if e.errno == errno.EROFS else "permission denied"
        return StateError(
            f"cannot write signafAIde's local state in {home} ({why}). Set SIGNAFAIDE_HOME to a writable folder (for example a mounted "
            "volume, or /tmp/signafaide on serverless) or SIGNAFAIDE_DISABLED=1 to turn recording off; see https://signafaide.com/docs/production"
        )
    return e


def find_root(start: Optional[Path] = None) -> Path:
    """Project root: nearest folder with ``.signafaide``, else with .git /
    pyproject.toml / package.json (below the home folder), else the cwd."""
    start = (start or Path.cwd()).resolve()
    home = Path.home().resolve()
    chain = [start, *start.parents]
    for d in chain:
        if (d / ".signafaide").is_dir():
            return d
    for d in chain:
        if d == home or d == d.parent:
            break
        if any((d / m).exists() for m in _MARKERS):
            return d
    return start


class State:
    def __init__(self, home: Path, root: Path):
        self.home = Path(home)
        self.root = Path(root)
        #: Agent keys from a secret store, before the key files (``Recorder(key_provider=...)``).
        self.key_provider: Optional[KeyProvider] = None

    @classmethod
    def discover(cls, home: Optional[str] = None) -> "State":
        root = find_root()
        home = home or os.environ.get("SIGNAFAIDE_HOME")
        return cls(Path(home).resolve() if home else root / ".signafaide", root)

    # --- layout -------------------------------------------------------------

    def ensure(self) -> None:
        """Create the folders. ``.gitignore`` is never edited here: only ``signafaide init`` and
        ``agent setup`` do that, so a CI checkout stays clean (§8)."""
        try:
            for sub in ("agents", "chain", "outbox"):
                (self.home / sub).mkdir(parents=True, exist_ok=True)
            # Inside the folder itself: nothing in it (agent keys above all) is ever committed,
            # even before `signafaide init` adds the folder to the project's .gitignore (§8).
            gi = self.home / ".gitignore"
            if not gi.exists():
                gi.write_text("*\n")
        except OSError as e:
            raise fs_error(e, self.home) from None

    def ignore_in_git(self, *extra: str) -> None:
        """Add ``.signafaide/`` (and *extra*) to the project's .gitignore (init and agent setup only)."""
        gi = self.root / ".gitignore"
        if self.home == self.root / ".signafaide":
            ensure_gitignore(gi, ".signafaide/")
        for e in extra:
            ensure_gitignore(gi, e)

    def key_dir(self, scope: str = "") -> Path:
        return self.home / "agents" / scope if scope else self.home / "agents"

    def key_path(self, agent: str, scope: str = "") -> Path:
        return self.key_dir(scope) / f"{agent}.key"

    def provided_key(self, agent: str, scope: str = "") -> Optional[dict]:
        """The key handed in for this agent (provider, then ``SIGNAFAIDE_AGENT_KEY_<NAME>``; a live
        chain tries ``SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>`` first), as ``{private_key, created}``, or None."""
        v = self.key_provider(agent, scope) if self.key_provider else None
        if v is None:
            v = os.environ.get(agent_key_env_name(agent, scope)) or (os.environ.get(agent_key_env_name(agent)) if scope else None)
        if not v:
            return None
        doc = v
        if isinstance(v, str):
            try:
                doc = json.loads(v)
            except ValueError:
                raise StateError(f"{agent_key_env_name(agent, scope)} must hold the agent's key file (JSON with private_key and created), "
                                 f"as `cat .signafaide/agents/{agent}.key` shows it") from None
        if not isinstance(doc, dict) or not isinstance(doc.get("private_key"), str) or not _valid_time(doc.get("created")) or doc.get("agent", agent) != agent:
            raise StateError(f'the key given for agent {agent} must be the agent\'s key file: {{"agent", "private_key", "created", ...}}')
        return {"private_key": doc["private_key"], "created": doc["created"]}

    def chain_path(self, chain: str) -> Path:
        return self.home / "chain" / f"{chain}.jsonl"

    def outbox_dir(self, chain: str) -> Path:
        return self.home / "outbox" / chain

    def chains(self) -> List[str]:
        """Every local chain id (``<project>/<env>/<agent>`` or ``_pending/<fp>/<agent>``)."""
        root = self.home / "chain"
        return sorted(str(p.relative_to(root).with_suffix("")) for p in root.glob("*/*/*.jsonl")) if root.is_dir() else []

    def agents(self) -> List[str]:
        names = {c.rsplit("/", 1)[1] for c in self.chains()}
        for scope in SCOPES:
            names |= {p.stem for p in self.key_dir(scope).glob("*.key")} if self.key_dir(scope).is_dir() else set()
            names |= {p.name.split(".")[0] for p in self.retired_dir(scope).glob("*.key")} if self.retired_dir(scope).is_dir() else set()
        for k, v in os.environ.items():
            if k.startswith("SIGNAFAIDE_AGENT_KEY_") and v:
                with contextlib.suppress(ValueError, AttributeError):
                    a = json.loads(v).get("agent")
                    if isinstance(a, str):
                        names.add(a)
        return sorted(n for n in names if AGENT_RE.match(n))

    # --- blocked chains, held segments ------------------------------------------

    def blocked(self) -> Dict[str, dict]:
        """Chains the witness refused, with why: ``{chain: {code, message, at, seq}}`` (blocked.json)."""
        return _read_json(self.home / "blocked.json") or {}

    def set_blocked(self, chain: str, info: Optional[dict]) -> None:
        """Record (or, with None, clear) why the witness refuses a chain. Never raises (read-only disks)."""
        try:
            data = self.blocked()
            if info is None:
                if chain not in data:
                    return
                del data[chain]
            else:
                old = data.get(chain)
                if old and all(old.get(k) == info.get(k) for k in ("code", "message", "seq")):
                    return
                data[chain] = {**info, "at": now()}
            _write_json(self.home / "blocked.json", data)
        except (OSError, StateError):
            pass

    def held_dir(self, chain: str) -> Path:
        return self.home / "held" / chain

    def held_segments(self) -> List[Tuple[str, Path, List[dict]]]:
        """Every held segment: (chain, file, records)."""
        root = self.home / "held"
        out = []
        for p in sorted(root.glob("*/*/*/*.jsonl")) if root.is_dir() else []:
            chain = str(p.parent.relative_to(root))
            out.append((chain, p, [_parse_line(p, ln) for ln in p.read_bytes().splitlines() if ln.strip()]))
        return out

    def hold_tail(self, chain: str, from_seq: int) -> Tuple[Path, List[dict]]:
        """``signafaide repair``: move the chain's records from *from_seq* to the end (none of them
        co-signed) into ``held/<chain>/<from>-<to>.jsonl``, and drop them from the outbox. The held
        file is written and flushed before the chain file is cut, so a crash never loses a line."""
        path = self.chain_path(chain)
        with self.lock(chain):
            cut: List[Tuple[int, dict]] = []
            with open(path, "rb") as f:
                for off, line in _reverse_lines(f):
                    rec = _parse_line(path, line)
                    if rec["envelope"]["seq"] < from_seq:
                        break
                    if "receipt" in rec:
                        raise StateError(f"{chain} seq {rec['envelope']['seq']} has a receipt: co-signed records are never set aside")
                    cut.append((off, rec))
            cut.reverse()
            if not cut:
                raise StateError(f"{chain} has no records from seq {from_seq}")
            recs = [r for _, r in cut]
            d = self.held_dir(chain)
            d.mkdir(parents=True, exist_ok=True)
            out = d / f"{recs[0]['envelope']['seq']:012d}-{recs[-1]['envelope']['seq']:012d}.jsonl"
            tmp = out.with_name(out.name + ".tmp")
            with open(tmp, "wb") as f:
                f.write("".join(jcs.dumps(r) + "\n" for r in recs).encode())
                f.flush()
                os.fsync(f.fileno())
            tmp.replace(out)
            with open(path, "r+b") as f:
                f.truncate(cut[0][0])
                f.flush()
                os.fsync(f.fileno())
            self.drop_outbox(chain, [r["envelope"]["seq"] for r in recs])
        return out, recs

    # --- projects -------------------------------------------------------------

    def bucket(self, api_key: Optional[str]) -> str:
        """``<project>/<env>`` for this API key, or ``_pending/<fp>`` while its project is unknown."""
        if not api_key:
            return f"{PENDING}/nokey"
        fp = key_fingerprint(api_key)
        p = self.config().get("projects", {}).get(fp)
        if p and valid_project_id(p.get("project")) and p.get("env") in ENVS:
            return f"{p['project']}/{p['env']}"
        return f"{PENDING}/{fp}"

    def learn_project(self, api_key: str, project: str, env: str) -> None:
        """Remember an API key's project. The values come from the service, so they are
        checked before they can name a folder (§8)."""
        if not valid_project_id(project) or env not in ENVS:
            raise StateError(f"the service named project {project!r} env {env!r}, which is not a valid project id and env; check SIGNAFAIDE_URL")
        projects = dict(self.config().get("projects", {}))
        projects[key_fingerprint(api_key)] = {"project": project, "env": env}
        self.save_config(projects=projects)

    def adopt(self, src: str, dst: str, key: Callable[..., SigningKey], wire: Callable[[dict], dict],
              not_before: Optional[str] = None, bases: Optional[Dict[str, dict]] = None) -> List[Tuple[str, str]]:
        """Sign every draft chain of bucket *src* into *dst* (``<project>/<env>``) with its
        outbox (§8), keeping each record's time. Returns the chains left pending, with why:
        ``exists`` (that agent already has a chain under *dst*) or the first draft's time when
        it is before *not_before* (the service would refuse it, §2.4)."""
        project, env = dst.split("/")
        conflicts: List[Tuple[str, str]] = []
        root = self.home / "chain" / src
        for path in sorted(root.glob("*.jsonl")) if root.is_dir() else []:
            agent = path.stem
            with self.lock(f"{src}/{agent}"), self.lock(f"{dst}/{agent}"):
                lines = list(self._lines(f"{src}/{agent}"))
                target = self.chain_path(f"{dst}/{agent}")
                mapping = self._draft_map(f"{dst}/{agent}")
                first = lines[0]["envelope"]["time"] if lines else None
                too_old = bool(not_before and first and parse_time(first) < parse_time(not_before))
                if target.exists():
                    if lines and all(record_hash(d) in mapping for d in lines):
                        path.unlink()  # an earlier adoption finished but did not clean up
                        continue
                    conflicts.append((f"{src}/{agent}", first if too_old else "exists"))
                    continue
                if too_old:
                    conflicts.append((f"{src}/{agent}", first))
                    continue
                # The service already holds a chain for this agent that is not on this disk (an
                # ephemeral disk lost it): the drafts continue after the service's head (§8).
                base = (bases or {}).get(agent)
                prev: Optional[str] = base["record_hash"] if base else None
                offset = base["seq"] if base else 0
                out = []
                for d in lines:
                    if not d.get("draft"):
                        raise StateError(f"{path} holds a signed record; pending chains hold drafts only. Move it aside and run `signafaide verify`")
                    ref = d["envelope"]["ref"]
                    rec = sign_draft(key(agent, first), d, project=project, env=env, prev=prev, ref=mapping.get(ref, ref) if ref else None,
                                     seq=d["envelope"]["seq"] + offset)
                    mapping[record_hash(d)] = prev = record_hash(rec)
                    out.append((rec, d.get("store_content")))
                target.parent.mkdir(parents=True, exist_ok=True)
                _write_json(self._map_path(f"{dst}/{agent}"), mapping)
                if base and isinstance(base.get("signed"), dict):
                    # The witness's signed head this chain continues after: the local verify
                    # reports the chain as continuing after it instead of missing seq 1..N.
                    _write_json(self._base_path(f"{dst}/{agent}"), base["signed"])
                tmp = target.with_name(target.name + ".tmp")
                with open(tmp, "wb") as f:
                    f.write("".join(jcs.dumps(r) + "\n" for r, _ in out).encode())
                    f.flush()
                    os.fsync(f.fileno())
                for rec, store in out:
                    self._write_outbox(f"{dst}/{agent}", wire(rec) if store is None else _wire(rec, store))
                tmp.replace(target)
                path.unlink()
        return conflicts

    def _base_path(self, chain: str) -> Path:
        return self.home / "chain" / f"{chain}.base.json"

    def chain_base(self, chain: str) -> Optional[dict]:
        """The witness's signed head ``{head, head_sig}`` that *chain* continues after, when
        this machine started it on an empty disk (§8), else None."""
        return _read_json(self._base_path(chain))

    def _map_path(self, chain: str) -> Path:
        return self.home / "chain" / f"{chain}.drafts.json"

    def _draft_map(self, chain: str) -> Dict[str, str]:
        return _read_json(self._map_path(chain)) or {}

    def translate_ref(self, chain: str, ref: Optional[str]) -> Optional[str]:
        """A ref to a draft that has since been signed points at the signed record."""
        if not ref:
            return ref
        return self._draft_map(chain).get(ref, ref)

    def has_drafts(self) -> bool:
        """Any chain still waiting for its project (§8)."""
        return any(c.startswith(PENDING + "/") for c in self.chains())

    def draft_count(self, chain: str) -> int:
        return sum(1 for r in self._lines(chain) if r.get("draft"))

    # --- keys ---------------------------------------------------------------

    def key_created(self, agent: str, scope: str = "") -> Optional[str]:
        """When the key was generated: the ``valid_from`` sent at registration, so
        records signed offline before registering still verify (§2.4)."""
        given = self.provided_key(agent, scope)
        if given:
            return given["created"]
        try:
            return json.loads(self.key_path(agent, scope).read_text()).get("created")
        except (OSError, ValueError):
            return None

    def retired_dir(self, scope: str = "") -> Path:
        return self.key_dir(scope) / "retired"

    def retired_keys(self, agent: str, scope: str = "") -> List[Tuple[SigningKey, str]]:
        """(key, created) of the agent's retired keys, newest first."""
        out = []
        for p in self.retired_dir(scope).glob(f"{agent}.*.key") if self.retired_dir(scope).is_dir() else []:
            if p.name.count(".") != 2:
                continue
            try:
                doc = json.loads(p.read_text())
                if doc.get("agent") == agent:
                    out.append((SigningKey(b64url_decode(doc["private_key"])), doc["created"]))
            except (OSError, ValueError, KeyError, TypeError):
                raise StateError(f"{p} is not a valid signafaide key file; restore it from backup") from None
        return sorted(out, key=lambda x: x[1], reverse=True)

    def retired_at(self, agent: str, key_id: str, scope: str = "") -> Optional[str]:
        """When the service retired this key (§2.4 rotation), once it said so; None before."""
        try:
            v = json.loads((self.retired_dir(scope) / f"{agent}.{key_id}.key").read_text()).get("retired")
        except (OSError, ValueError):
            return None
        return v if isinstance(v, str) and _valid_time(v) else None

    def mark_retired(self, agent: str, key_id: str, valid_to: str, scope: str = "") -> bool:
        """Record the service's retirement time in a retired key's file (kept for keys export)."""
        p = self.retired_dir(scope) / f"{agent}.{key_id}.key"
        if not AGENT_RE.match(agent) or not _valid_time(valid_to) or not p.is_file():
            return False
        doc = json.loads(p.read_text())
        if doc.get("retired") == valid_to:
            return False
        doc["retired"] = valid_to
        tmp = p.with_name(p.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(jcs.dumps(doc) + "\n")
        os.replace(tmp, p)
        return True

    def rotate_key(self, agent: str, scope: str = "") -> Tuple[SigningKey, SigningKey]:
        """Retire the agent's key and make a new one: (old, new). The next registration is
        signed by the old key (§2.4 rotation)."""
        if not AGENT_RE.match(agent):
            raise StateError(f"agent {agent!r} is invalid")
        if self.provided_key(agent, scope):
            raise StateError(f"agent {agent}'s key comes from {agent_key_env_name(agent, scope)} (or a key provider): make a new key with "
                             "`signafaide keys rotate` on a machine with the key file, store the new file in your secret store, and keep the old one "
                             f"as {agent}.<key id>.key in .signafaide/agents/{scope + '/' if scope else ''}retired/")
        old = self.load_key(agent, create=False, scope=scope)
        if old is None:
            raise StateError(f"agent {agent} has no key to rotate; it gets one with its first record")
        self.retired_dir(scope).mkdir(parents=True, exist_ok=True)
        self.key_path(agent, scope).replace(self.retired_dir(scope) / f"{agent}.{old.key_id}.key")
        new = self.load_key(agent, scope=scope)
        assert new is not None
        return old, new

    def agent_public_keys(self) -> List[dict]:
        """Every current and retired agent key: ``{agent, key_id, public_key, created, retired}``
        (``retired``: when the service retired it, or None)."""
        out, seen = [], set()
        for agent in self.agents():
            for scope in SCOPES:
                k = self.load_key(agent, create=False, scope=scope)
                if k is not None and k.key_id not in seen:
                    seen.add(k.key_id)
                    out.append({"agent": agent, "key_id": k.key_id, "public_key": b64url(k.public_key), "created": self.key_created(agent, scope), "retired": None})
                for rk, created in self.retired_keys(agent, scope):
                    if rk.key_id in seen:
                        continue
                    seen.add(rk.key_id)
                    out.append({"agent": agent, "key_id": rk.key_id, "public_key": b64url(rk.public_key), "created": created,
                                "retired": self.retired_at(agent, rk.key_id, scope)})
        return out

    def export_agent_keys(self) -> dict:
        """The §2.5 manifest of every current and retired key, each entry self-signed."""
        keys, seen = [], set()
        for agent in self.agents():
            for scope in SCOPES:
                k = self.load_key(agent, create=False, scope=scope)
                if k is not None and k.key_id not in seen:
                    seen.add(k.key_id)
                    keys.append(manifest_entry(agent, k, self.key_created(agent, scope)))
                # A retired key carries the time the service retired it, signed by that key (§2.5).
                for rk, created in self.retired_keys(agent, scope):
                    if rk.key_id not in seen:
                        seen.add(rk.key_id)
                        keys.append(manifest_entry(agent, rk, created, self.retired_at(agent, rk.key_id, scope)))
        return {"format": AGENT_KEYS_FORMAT, "keys": keys}

    def load_key(self, agent: str, create: bool = True, scope: str = "", created_at: Optional[str] = None) -> Optional[SigningKey]:
        """*created_at*: for a key made now to sign records written earlier (drafts signed into a
        live chain), its creation time, so it is valid from the first of them (§2.4)."""
        given = self.provided_key(agent, scope)
        if given:
            try:
                return SigningKey(b64url_decode(given["private_key"]))
            except (ValueError, TypeError) as e:
                raise StateError(f"the key given for agent {agent} ({agent_key_env_name(agent, scope)}) is not a valid key ({e})") from None
        path = self.key_path(agent, scope)
        if not path.exists():
            if not create:
                return None
            self.ensure()
            key = SigningKey.generate()
            t = now()
            created = created_at if created_at and _valid_time(created_at) and created_at < t else t
            doc = {"agent": agent, "key_id": key.key_id, "public_key": b64url(key.public_key), "private_key": b64url(key.seed()), "created": created}
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:  # another process won the race; use its key
                return self.load_key(agent, create=False, scope=scope)
            except OSError as e:
                raise fs_error(e, self.home) from None
            with os.fdopen(fd, "w") as f:
                f.write(jcs.dumps(doc) + "\n")
            return key
        try:
            doc = json.loads(path.read_text())
            return SigningKey(b64url_decode(doc["private_key"]))
        except (ValueError, KeyError, TypeError) as e:
            raise StateError(f"{path} is not a valid signafaide key file ({e}); restore it from backup") from None

    # --- locking ------------------------------------------------------------

    @contextlib.contextmanager
    def lock(self, chain: str) -> Iterator[None]:
        path = self.home / "chain" / f"{chain}.lock"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise fs_error(e, self.home) from None
        deadline = time.monotonic() + LOCK_WAIT_S
        while True:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, lock_stamp().encode())
                os.close(fd)
                break
            except OSError as e:
                if not isinstance(e, FileExistsError):
                    raise fs_error(e, self.home) from None
                try:
                    if lock_age(path) > LOCK_STALE_S:
                        path.unlink()
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise StateError(f"{path} is held by another process; delete it if no signafaide process is running") from None
                time.sleep(0.002)
        try:
            self._recover(chain)
            yield
        finally:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

    def _recover(self, chain: str) -> None:
        """Finish an interrupted receipt rewrite (journal ``.tail``)."""
        path = self.chain_path(chain)
        journal = path.with_name(path.name + ".tail")
        if not journal.exists():
            return
        with open(journal, "rb") as f:
            offset = int(f.readline())
            data = f.read()
        with open(path, "r+b") as f:
            f.truncate(offset)
            f.seek(offset)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        journal.unlink()

    # --- chain --------------------------------------------------------------

    def tail(self, chain: str) -> Tuple[int, Optional[str], Optional[str]]:
        """(seq, record_hash, time) of the last record in the local chain (the last sealed
        segment's when the chain file was just rolled), (0, None, None) if empty."""
        for path in [self.chain_path(chain), *reversed(self.segments(chain))]:
            if not path.exists():
                continue
            with open(path, "rb") as f:
                for _, line in _reverse_lines(f):
                    rec = _parse_line(path, line)
                    return rec["envelope"]["seq"], record_hash(rec), rec["envelope"]["time"]
        return 0, None, None

    def segment_dir(self, chain: str) -> Path:
        return self.home / "chain" / f"{chain}.segments"

    def segments(self, chain: str) -> List[Path]:
        """Sealed segments of a chain, oldest first."""
        d = self.segment_dir(chain)
        return sorted(d.glob("*.jsonl")) if d.is_dir() else []

    def _maybe_roll(self, chain: str) -> None:
        """Roll a large chain file into a sealed segment, under the chain lock. Only a fully
        shipped file rolls (its last line has a receipt), so receipts never go into a segment."""
        path = self.chain_path(chain)
        try:
            if path.stat().st_size < segment_bytes():
                return
        except OSError:
            return
        with open(path, "rb") as f:
            last = next((_parse_line(path, ln) for _, ln in _reverse_lines(f)), None)
            if not last or "receipt" not in last:
                return
            f.seek(0)
            first = _parse_line(path, f.readline())
        d = self.segment_dir(chain)
        d.mkdir(parents=True, exist_ok=True)
        path.replace(d / f"{first['envelope']['seq']:012d}-{last['envelope']['seq']:012d}.jsonl")
        path.write_bytes(b"")

    def append(
        self,
        chain: str,
        build: Callable[[int, Optional[str], Optional[str]], dict],
        wire: Callable[[dict], dict],
        still_valid: Callable[[], bool] = lambda: True,
    ) -> Optional[dict]:
        """Under the chain lock: build the next record from (seq, prev), append it
        to the chain and put ``wire(record)`` in the outbox. Returns the record, or
        None when ``still_valid()`` is false once the lock is held (the chain was
        just moved under its project; the caller resolves the chain again)."""
        self.ensure()
        with self.lock(chain):
            if not still_valid():
                return None
            seq, prev, prev_time = self.tail(chain)
            rec = build(seq + 1, prev, prev_time)
            try:
                with open(self.chain_path(chain), "ab") as f:
                    f.write((jcs.dumps(rec) + "\n").encode())
            except OSError as e:
                raise fs_error(e, self.home) from None
            if not rec.get("draft"):  # a draft ships once it is signed (adopt)
                self._write_outbox(chain, wire(rec))
        return rec

    def _write_outbox(self, chain: str, rec: dict) -> None:
        d = self.outbox_dir(chain)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{rec['envelope']['seq']:012d}.tmp"
        tmp.write_text(jcs.dumps(rec))
        tmp.replace(d / f"{rec['envelope']['seq']:012d}.json")

    def _lines(self, chain: str) -> Iterator[dict]:
        for path in [*self.segments(chain), self.chain_path(chain)]:
            if not path.exists():
                continue
            with open(path, "rb") as f:
                for line in f:
                    if line.strip():
                        yield _parse_line(path, line)

    def read_chain(self, chain: str) -> Iterator[dict]:
        """The records of a chain that name their project (drafts are skipped)."""
        return (r for r in self._lines(chain) if not r.get("draft"))

    def read_all(self, chain: str) -> Iterator[dict]:
        """Every line of a chain, drafts included (§8)."""
        return self._lines(chain)

    def apply_receipts(self, chain: str, receipts: Dict[str, dict]) -> int:
        """Fill receipts into the trailing chain lines that lack one.
        Returns how many lines were filled."""
        path = self.chain_path(chain)
        filled_seqs: List[int] = []
        with self.lock(chain):
            if not path.exists():
                return 0
            with open(path, "rb") as f:
                suffix: List[Tuple[int, dict]] = []
                for off, line in _reverse_lines(f):
                    rec = _parse_line(path, line)
                    if "receipt" in rec:
                        break
                    suffix.append((off, rec))
            suffix.reverse()
            if suffix:
                out = []
                for _, rec in suffix:
                    r = receipts.get(record_hash(rec))
                    if r is not None:
                        rec["receipt"] = r
                        filled_seqs.append(rec["envelope"]["seq"])
                    out.append(jcs.dumps(rec) + "\n")
                if filled_seqs:
                    journal = path.with_name(path.name + ".tail")
                    tmp = path.with_name(path.name + ".tail.tmp")
                    with open(tmp, "wb") as f:
                        f.write(f"{suffix[0][0]}\n".encode() + "".join(out).encode())
                        f.flush()
                        os.fsync(f.fileno())
                    tmp.replace(journal)
                    self._recover(chain)
                    self._maybe_roll(chain)
        return len(filled_seqs)

    def reconcile_outbox(self, chain: str, wire: Callable[[dict], dict]) -> int:
        """Re-queue chain records that have neither a receipt nor an outbox file
        (a crash between the chain write and the outbox write)."""
        path = self.chain_path(chain)
        if not path.exists():
            return 0
        n = 0
        with self.lock(chain), open(path, "rb") as f:
            for _, line in _reverse_lines(f):
                rec = _parse_line(path, line)
                if "receipt" in rec or rec.get("draft"):
                    break
                if not (self.outbox_dir(chain) / f"{rec['envelope']['seq']:012d}.json").exists():
                    self._write_outbox(chain, wire(rec))
                    n += 1
        return n

    # --- outbox -------------------------------------------------------------

    def drop_outbox(self, chain: str, seqs: List[int]) -> None:
        for seq in seqs:
            with contextlib.suppress(FileNotFoundError):
                (self.outbox_dir(chain) / f"{seq:012d}.json").unlink()

    def outbox(self, chain: str, limit: int = 1000) -> List[dict]:
        d = self.outbox_dir(chain)
        if not d.is_dir():
            return []
        out = []
        for p in sorted(d.glob("*.json"))[:limit]:
            with contextlib.suppress(FileNotFoundError):
                out.append(json.loads(p.read_text()))
        return out

    def outbox_chains(self, bucket: Optional[str] = None) -> List[str]:
        """Chains with records waiting, optionally only those in *bucket*."""
        d = self.home / "outbox"
        if not d.is_dir():
            return []
        found = {str(p.parent.relative_to(d)) for p in d.glob("*/*/*/*.json")}
        return sorted(c for c in found if bucket is None or c.startswith(bucket + "/"))

    def outbox_size(self, bucket: Optional[str] = None) -> int:
        """Records waiting, in everything, a bucket (``<project>/<env>``) or one chain."""
        d = self.home / "outbox"
        if not d.is_dir():
            return 0
        return sum(1 for p in d.glob("*/*/*/*.json") if bucket is None or str(p.relative_to(d)).startswith(bucket + "/"))


    # --- heads, sandbox -----------------------------------------------------

    def heads(self) -> Dict[str, dict]:
        """``{project: {env: {agent: {head, head_sig}}}}``."""
        return _read_json(self.home / "head.json") or {}

    def chain_heads(self) -> Dict[str, dict]:
        """The newest signed head per chain id ``<project>/<env>/<agent>``."""
        return {f"{p}/{e}/{a}": sh for p, envs in self.heads().items() for e, agents in envs.items() for a, sh in agents.items()}

    def update_heads(self, signed_heads: List[dict]) -> List[str]:
        """Keep the newest head per (project, env, agent). Returns warnings for heads
        that go backwards (the service showing a shorter chain = truncation)."""
        warnings = []
        heads = self.heads()
        for sh in signed_heads:
            head = sh.get("head") or {}
            slot = heads.setdefault(head.get("project"), {}).setdefault(head.get("env"), {})
            old = (slot.get(head.get("agent")) or {}).get("head")
            if old and head.get("seq", 0) < old.get("seq", 0):
                warnings.append(
                    f"service head for {head.get('agent')} went back from seq {old['seq']} to {head.get('seq')}: "
                    "keep .signafaide/head.json, it proves truncation"
                )
                continue
            slot[head.get("agent")] = sh
        _write_json(self.home / "head.json", heads)
        return warnings

    def config(self) -> dict:
        """``config.json``: settings kept with the project (the coding agent that set it up)."""
        return _read_json(self.home / "config.json") or {}

    def save_config(self, **values: Any) -> None:
        self.ensure()
        try:
            _write_json(self.home / "config.json", {**self.config(), **values})
        except OSError as e:
            raise fs_error(e, self.home) from None

    def sandbox(self) -> Optional[dict]:
        return _read_json(self.home / "sandbox.json")

    def save_sandbox(self, info: dict) -> None:
        self.ensure()
        _write_json(self.home / "sandbox.json", info)


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def lock_stamp() -> str:
    """A lock file's content: ``<pid> <boot id> <monotonic seconds>``. The monotonic clock is the
    machine's (CLOCK_MONOTONIC, shared by every process since boot), so a step of the wall clock
    never makes a held lock look stale or a stale one look fresh."""
    return f"{os.getpid()} {_boot_id() or '-'} {time.monotonic():.3f}"


def lock_age(path: Path) -> float:
    """Seconds since the lock at *path* was taken: by the monotonic clock when it was written on
    this machine since its last boot, else by the file's modification time."""
    try:
        parts = path.read_text().split()
    except OSError:
        parts = []
    boot = _boot_id()
    if len(parts) == 3 and boot and parts[1] == boot:
        try:
            return time.monotonic() - float(parts[2])
        except ValueError:
            pass
    return time.time() - path.stat().st_mtime


def key_fingerprint(api_key: str) -> str:
    """Names an API key in config.json without storing it: sha256, first 16 hex."""
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


def wire_record(rec: dict, store_content: bool) -> dict:
    """The record as sent to the service: content and its salt only when stored there (§2.3)."""
    out = {k: rec[k] for k in ("envelope", "key_id", "sig")}
    if store_content and "content" in rec:
        out["content"] = rec["content"]
        if "salt" in rec:
            out["salt"] = rec["salt"]
    return out


_wire = wire_record


def _parse_line(path: Path, line: bytes) -> dict:
    try:
        rec = json.loads(line)
        rec["envelope"]["seq"]
        return rec
    except (ValueError, KeyError, TypeError):
        raise StateError(f"{path} has a damaged line; move that line aside and run `signafaide verify`") from None


def _reverse_lines(f) -> Iterator[Tuple[int, bytes]]:
    """(offset, line) pairs from the end of a binary file, skipping blank lines."""
    f.seek(0, 2)
    pos = f.tell()
    buf = b""
    while pos > 0:
        n = min(65536, pos)
        pos -= n
        f.seek(pos)
        buf = f.read(n) + buf
        parts = buf.split(b"\n")
        buf = parts[0]
        off = pos + len(buf) + 1
        complete = []
        for ln in parts[1:]:
            complete.append((off, ln))
            off += len(ln) + 1
        for off_ln in reversed(complete):
            if off_ln[1].strip():
                yield off_ln
    if buf.strip():
        yield 0, buf


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except ValueError:
        raise StateError(f"{path} is not valid JSON; fix or delete it") from None


def _write_json(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def ensure_gitignore(path: Path, entry: str) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    bare = entry.strip("/")
    if any(ln.strip().strip("/") == bare for ln in lines):
        return
    text = path.read_text() if path.exists() else ""
    if text and not text.endswith("\n"):
        text += "\n"
    path.write_text(text + entry + "\n")


def read_env_file(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k.startswith("export "):
            k = k[7:].strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out[k] = v
    return out


def append_env_file(path: Path, key: str, value: str) -> None:
    """Append ``key=value``; never touches other lines. The file holds a secret, so it is
    created (and kept) with mode 0600, and a value can never add a line of its own."""
    if any(c in value for c in "\r\n\0") or not key.isidentifier():
        raise StateError(f"refusing to write {key} to {path}: the value is not a single line")
    if path.is_symlink():
        raise StateError(f"refusing to write {path}: it is a symbolic link")
    text = path.read_text() if path.exists() else ""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        if text and not text.endswith("\n"):
            f.write("\n")
        f.write(f"{key}={value}\n")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
