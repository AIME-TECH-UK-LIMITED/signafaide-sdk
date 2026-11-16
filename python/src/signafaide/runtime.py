"""The recorder: writes signed records locally and ships them in the background."""

from __future__ import annotations

import atexit
import contextvars
import json
import logging
import os
import re
import shutil
import sys
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from datetime import datetime, timedelta, timezone

from ._plural import plural
from .coverage import TOOLS, declared_name, telemetry as tool_telemetry, telemetry_lines, tool_note_name
from .crypto import SigningKey, b64url, hash_json
from .http import DEFAULT_URL, Client, SignafaideError
from .records import (API_KEY_RE, AGENT_RE, INSTANCE_STOP, MAX_CLOCK_SKEW_MS, instance_stop_content, is_stop_note, agent_name, clamp_time, make_draft, make_record, now, parse_time, record_hash,
                      registration, valid_project_id, with_wall_time)
from .state import TOOL_SOURCE_REFRESH_MS, PENDING, KeyProvider, State, StateError, agent_key_env_name, append_env_file, key_fingerprint, read_env_file, scope_of, wire_record
from . import telemetry

log = logging.getLogger("signafaide")

BATCH_MAX = 1000  # §6: at most 1000 records per POST /v1/records
#: §2.4: a registration's valid_from is at most 7 days old; keep an hour of margin.
KEY_MAX_AGE = timedelta(days=7) - timedelta(hours=1)

# Set while a compare runs a candidate function: any record written in that context is refused,
# so a candidate can never add to a chain (and a recorded tool it calls never runs).
NO_WRITES: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("signafaide_no_writes", default=None)

# Set while a tool wrapped with the SDK runs: the tool's name. The telemetry plug-in
# (signafaide.otel) leaves a span of that tool begun inside the call alone, so one tool call is
# recorded once (the wrapper's records stand, the span's are not written).
RECORDING: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("signafaide_recording", default=None)

#: Set by the telemetry plug-in. ``adopt(name, call_id)`` returns ``(recorder, decision)`` when
#: the plug-in has already written the decision of a span of that tool that is running now, so a
#: wrapper inside that span writes no second one. ``claim(name, call_id)`` tells it that a wrapper
#: has written the decision of a call of the tool, and returns what ``done`` takes when the call
#: has ended, so the call's own span is not recorded again whenever it arrives. *call_id* is the
#: model's tool call id when the wrapper knows it. None of them ever raises.
telemetry_adopt: Optional[Callable[[str, Optional[str]], Optional[tuple]]] = None
telemetry_claim: Optional[Callable[[str, Optional[str]], object]] = None
telemetry_done: Optional[Callable[[object], None]] = None


def recording_disabled() -> bool:
    """``SIGNAFAIDE_DISABLED=1``: ``record`` and ``wrap_tools`` call the function and write nothing."""
    return os.environ.get("SIGNAFAIDE_DISABLED", "").strip().lower() in ("1", "true", "yes")


def test_mode() -> bool:
    """Test mode: records are written to a temporary folder and never sent, so unit tests never ship
    records under a production agent name. On with ``SIGNAFAIDE_TEST=1``, and by itself under pytest
    unless ``SIGNAFAIDE_TEST=0``."""
    v = os.environ.get("SIGNAFAIDE_TEST", "").strip().lower()
    if v:
        return v in ("1", "true", "yes")
    return "PYTEST_CURRENT_TEST" in os.environ


#: Problems found on this machine, not refusals by the witness: they never slow shipping down.
LOCAL_CODES = ("too_old", "chain_exists")
#: Refusals that apply to every chain: nothing is sent until the configuration changes.
PROJECT_WIDE = ("invalid_key", "quota_exceeded", "plan_required")


class Recorder:
    """One project's recorder. The module-level API uses a default instance."""

    def __init__(
        self,
        *,
        home: Optional[str] = None,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        store_content: bool = False,
        flush_interval: float = 2.0,
        flush_size: int = 100,
        quiet: bool = False,
        via: str = "sdk",
        key_provider: Optional[KeyProvider] = None,
        exit_flush: Optional[float] = None,
        head_file: Optional[str] = None,
        on_head: Optional[Callable[[List[dict]], None]] = None,
        instance_stop: Optional[bool] = None,
    ):
        self.test = test_mode()
        if home is None and self.test and not os.environ.get("SIGNAFAIDE_HOME"):
            import tempfile

            home = tempfile.mkdtemp(prefix="signafaide-test-")
            # Test mode sends nothing and keeps nothing: the folder goes when the process ends.
            # Registered before the shipper's own exit hook, so it runs after it.
            atexit.register(shutil.rmtree, home, True)
        self.state = State.discover(home)
        self.state.key_provider = key_provider
        #: Also keep the newest signed heads in this file (default ``SIGNAFAIDE_HEAD_FILE``): a path
        #: on a persistent volume or mounted bucket, so an ephemeral container's heads outlive it.
        self.state.head_file = head_file or os.environ.get("SIGNAFAIDE_HEAD_FILE") or None
        #: Called with the newest signed heads after every accepted batch, to keep them anywhere
        #: (an object store, a database). An exception it raises is logged and never stops recording.
        self.on_head = on_head
        #: Write a signed stop note when the program ends with nothing left to send (§8), so the
        #: next instance's start is a clean restart. Default: on when a head file is set (an
        #: ephemeral container) or ``SIGNAFAIDE_INSTANCE_STOP=1``; ``SIGNAFAIDE_INSTANCE_STOP=0``
        #: turns it off. ``stop()`` always writes one.
        env_stop = os.environ.get("SIGNAFAIDE_INSTANCE_STOP")
        self.instance_stop = False if env_stop == "0" else (instance_stop if instance_stop is not None else (env_stop == "1" or bool(self.state.head_file)))
        self._wrote: Set[str] = set()  # agents this process wrote records for since its last stop note
        self._told_strict = False
        #: (agent, source) -> the tool set this recorder last declared for it (§2.6), and the header's hash.
        self._declared: Dict[Tuple[str, str], tuple] = {}
        self._tool_thread: Optional[threading.Thread] = None  # refreshes tools/<agent>.json once an hour (§8)
        self._tool_stop = threading.Event()
        self._url = url
        self._api_key = api_key
        self.store_content = store_content
        self.flush_interval = flush_interval
        self.flush_size = flush_size
        self.quiet = quiet
        self.via = via
        if exit_flush is None:
            try:
                exit_flush = float(os.environ["SIGNAFAIDE_EXIT_FLUSH_MS"]) / 1000 if "SIGNAFAIDE_EXIT_FLUSH_MS" in os.environ else 3.0
            except ValueError:
                exit_flush = 3.0
        #: The longest a finished program is kept open to ship the outbox (seconds; 0: never).
        self.exit_flush = max(0.0, exit_flush)
        self.strict_used = False  # a strict-mode tool ran in this process (client header)
        self._keys: Dict[Tuple[str, str], Tuple[SigningKey, Optional[tuple]]] = {}
        self._registered: Set[tuple] = set()
        self._reconciled: Set[str] = set()
        self._blocked: Dict[str, Tuple[str, SignafaideError]] = {}
        self._halted: Optional[Tuple[str, SignafaideError]] = None
        self._ship_lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pending = 0
        self._next_attempt = 0.0  # monotonic time before which the background shipper waits
        self._deadline: Optional[float] = None  # monotonic: requests made now must end by then (exit)
        self._deadline_limit = 0.0  # the exit limit that deadline came from, in seconds
        self._failing: Optional[str] = None
        self._atexit = False
        self._stopped = False
        self._told_local = False
        self._told_bad_key = False
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    # --- configuration --------------------------------------------------------

    def _setting(self, name: str) -> Optional[str]:
        return os.environ.get(name) or read_env_file(self.state.root / ".env").get(name) or None

    @property
    def url(self) -> str:
        return (self._url or self._setting("SIGNAFAIDE_URL") or DEFAULT_URL).rstrip("/")

    @property
    def raw_api_key(self) -> Optional[str]:
        """SIGNAFAIDE_API_KEY as set, even when it is not a valid key."""
        return self._api_key or self._setting("SIGNAFAIDE_API_KEY")

    @property
    def api_key(self) -> Optional[str]:
        """The API key, or None: none set, test mode, or not a signafAIde key (checked here, so a
        wrong value is never sent anywhere)."""
        if self.test:
            return None
        k = self.raw_api_key
        if not k:
            return None
        if not API_KEY_RE.match(k):
            if not self._told_bad_key and not self.quiet:
                self._told_bad_key = True
                log.warning("signafaide: SIGNAFAIDE_API_KEY (%s...) is not a signafAIde key (sfa_test_ or sfa_live_ and 32 letters or digits); "
                            "nothing is sent and records stay on this machine. Fix it or remove it.", k[:8])
            return None
        return k

    def _config_fp(self) -> str:
        """What shipping depends on: when it changes, refused chains are tried again."""
        def stamp(d) -> str:
            try:
                return str(os.stat(d).st_mtime_ns)
            except OSError:
                return "0"
        dirs = [self.state.key_dir(""), self.state.retired_dir(""), self.state.key_dir("live"), self.state.retired_dir("live")]
        return "\n".join([self.url, self.api_key or "", *map(stamp, dirs)])

    def client(self, timeout: float = 10.0, api_key: Optional[str] = None) -> Client:
        label = None
        if self._deadline is not None:
            import time

            # At exit every request shares one limit: a timeout names that limit, not what was left of it.
            label = f"no answer within the {self._deadline_limit:g} s allowed at exit (SIGNAFAIDE_EXIT_FLUSH_MS)"
            timeout = min(timeout, self._deadline - time.monotonic())
            if timeout <= 0:
                raise SignafaideError(f"Cannot reach the signafAIde service at {self.url} ({label}); records stay in the outbox.", code="network")
        c = Client(self.url, api_key or self.api_key, timeout=timeout, client_id=self.client_id())
        c.timeout_label = label
        return c

    def agent(self) -> str:
        """The coding agent stored when the project was set up (``init``, ``agent setup``). Never
        guessed per process: a program started from a terminal inside a coding agent is not that agent."""
        return self.state.config().get("agent", "unknown")

    def client_id(self) -> str:
        return telemetry.client_header(via=self.via, adapter=telemetry.adapter_field(), agent=self.agent(), strict=self.strict_used)

    def remember_agent(self) -> None:
        """Store the detected coding agent in config.json (not when telemetry is off). Only
        ``init`` and ``agent setup`` call it."""
        agent = telemetry.detect_agent()
        if telemetry.enabled() and agent != "unknown" and self.state.config().get("agent") != agent:
            self.state.save_config(agent=agent)

    def event(self, name: str) -> None:
        """Fire-and-forget usage event; never raises, skipped when telemetry is off and when
        there is no API key (nothing is sent before a human opts in)."""
        if not telemetry.enabled() or not self.api_key:
            return
        try:
            self.client(timeout=2.0).event(name)
        except Exception:
            pass

    def only_agent(self) -> Optional[str]:
        """The one agent with records here, when there is exactly one (replay and compare
        without ``--agent``), else None."""
        names = {c.rsplit("/", 1)[1] for c in self.state.chains()}
        return names.pop() if len(names) == 1 else None

    @property
    def default_agent(self) -> str:
        """The agent name used when none is given: the project folder's name. Give agents explicit
        names in production (one per running instance); see the production guide."""
        return agent_name(self.state.root.name)

    def create_sandbox(self) -> str:
        """Return the API key; create a sandbox project if there is none. Only an explicit
        human opt-in calls this (``signafaide init``): records never create a sandbox by
        themselves."""
        raw = self.raw_api_key
        if raw and not API_KEY_RE.match(raw):
            raise SignafaideError(f"SIGNAFAIDE_API_KEY ({raw[:8]}...) is not a signafAIde key (sfa_test_ or sfa_live_ and 32 letters or digits): "
                                  "fix it, or remove it to create a sandbox.", code="invalid_key")
        key = self.api_key
        if key:
            try:
                self.resolve_project(key)
            except SignafaideError as e:
                if e.code != "network":
                    raise
            return key
        self.state.ensure()
        self.remember_agent()
        with self.state.lock("~init"):
            key = self.api_key  # another process may have just created it
            if key:
                return key
            resp = self.client().sandbox()
            key = resp.get("api_key") if isinstance(resp, dict) else None
            # The service's answer names a file line and folders: check it before using it (§8).
            if not isinstance(key, str) or not API_KEY_RE.match(key) or not key.startswith("sfa_test_") or not valid_project_id(resp.get("project")):
                raise SignafaideError(
                    f"The service at {self.url} answered POST /v1/sandbox with an invalid api_key or project; check SIGNAFAIDE_URL.", code="bad_response"
                )
            env_file = self.state.root / ".env"
            append_env_file(env_file, "SIGNAFAIDE_API_KEY", key)
            # A sandbox key only works on the service that issued it: keep that service with the key.
            if self.url != DEFAULT_URL and not read_env_file(env_file).get("SIGNAFAIDE_URL"):
                append_env_file(env_file, "SIGNAFAIDE_URL", self.url)
            self.state.ignore_in_git(".env")  # the key must not be committed
            self.state.learn_project(key, resp["project"], "test")
            legal = legal_links(resp, self.url)
            from . import _claim

            # When the witness deletes the sandbox unless it is claimed; a witness that does not say is not guessed.
            expires = _claim.parse_expiry(resp.get("expires_at"))
            self.state.save_sandbox(
                {k: resp.get(k) for k in ("project", "claim_url", "free_quota")} | {"url": self.url, "created": now()}
                | ({"expires_at": expires} if expires else {}) | legal
            )
            self._api_key = key
            if not self.quiet:
                print(f"signafaide: sandbox ready, key saved to .env; claim it at {resp.get('claim_url')}. {terms_notice(legal)}", file=sys.stderr)
                view = {"claim_url": resp.get("claim_url"), "claimed": False, "expires_at": expires,
                        "days_left": _claim.days_left(expires) if expires else None, "refused": False, "unconfirmed": False}
                for line in _claim.claim_notes(view):
                    print(f"signafaide: {line}", file=sys.stderr)
        return key

    def resolve_project(self, api_key: str) -> None:
        """Learn the API key's project (``GET /v1/project``) if it is not known yet, so
        envelopes can name it (§2.2). Raises SignafaideError when the service cannot say.
        Never called while a record is written: until the project is known, records are
        signed drafts (§8), and the background shipper learns it."""
        if not self.state.bucket(api_key).startswith(PENDING + "/"):
            return
        resp = self.client(api_key=api_key).project()
        project, env = (resp.get("project"), resp.get("env")) if isinstance(resp, dict) else (None, None)
        if env != _env_of(api_key) or not valid_project_id(project):
            raise SignafaideError(f"The service at {self.url} answered GET /v1/project with an invalid project or env; check SIGNAFAIDE_URL.", code="bad_response")
        self.state.learn_project(api_key, project, env)

    # --- writing ------------------------------------------------------------

    def key(self, agent: str, scope: str = "", first_time: Optional[str] = None) -> SigningKey:
        """The agent's key, reloaded when its file changes: `signafaide keys rotate` in another
        process takes effect at this process's next record (§2.4)."""

        def stamp() -> Optional[tuple]:
            if self.state.provided_key(agent, scope):
                return ("provided",)
            try:
                st = os.stat(self.state.key_path(agent, scope))
                return (st.st_ino, st.st_mtime_ns, st.st_size)
            except OSError:
                return None

        held = self._keys.get((agent, scope))
        now_ = stamp()
        if held is not None and now_ is not None and held[1] == now_:
            return held[0]
        k = self.state.load_key(agent, scope=scope, created_at=first_time)
        assert k is not None
        self._keys[(agent, scope)] = (k, stamp())
        return k

    def _timed(self, content: dict, prev_time: Optional[str], agent: str, scope: str) -> Tuple[str, dict]:
        """The record's time (§2.2): never earlier than the previous record's or the key's
        valid_from. When the clock read earlier, its reading is kept in ``meta.wall_time``."""
        wall = now()
        t, raised = clamp_time(wall, prev_time, self.state.key_created(agent, scope))
        return (t, with_wall_time(content, wall)) if raised else (t, content)

    def write(
        self,
        kind: str,
        name: str,
        content: dict,
        *,
        agent: Optional[str] = None,
        ref: Optional[str] = None,
        store_content: Optional[bool] = None,
    ) -> dict:
        """Sign and chain one record locally (synchronous, no network) and queue it for
        shipping. The chain is this API key's ``<project>/<env>/<agent>`` (§8); while the key's
        project is not known yet, the record is a signed draft."""
        return self.write_run([(kind, name, content, ref)], agent=agent, store_content=store_content)[0]

    def write_run(self, items: List[Tuple[str, str, dict, Optional[str]]], *, agent: Optional[str] = None, store_content: Optional[bool] = None) -> List[dict]:
        """:meth:`write` for records that must follow each other with nothing between them (a
        tool declaration, §2.6): ``(kind, name, content, ref)`` each, signed and appended under
        one hold of the chain lock."""
        why = NO_WRITES.get()
        if why:
            raise SignafaideError(f"{why} must not write records: candidate functions must be side-effect free (it tried to record {items[0][1]!r})", code="no_writes")
        agent = agent or self.default_agent
        if not AGENT_RE.match(agent):
            raise ValueError(f"agent {agent!r} is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)")
        sc = self.store_content if store_content is None else store_content
        api_key = self.api_key
        while True:
            bucket = self._write_bucket(api_key, agent)
            scope = scope_of(bucket)
            key = self.key(agent, scope)
            chain = f"{bucket}/{agent}"
            if not self.state.chain_path(chain).exists():
                for e in self._adopt_into(bucket, api_key).values():
                    self._report(f"signafaide: {e}")
            builds = []
            for kind, name, content, ref in items:
                if bucket.startswith(PENDING + "/"):
                    # The project is not known yet, and an envelope names it: keep a draft, signed later (§8).
                    def build(seq, prev, prev_time, scope=scope, key=key, kind=kind, name=name, content=content, ref=ref):
                        t, c = self._timed(content, prev_time, agent, scope)
                        return make_draft(key, kind=kind, agent=agent, seq=seq, prev=prev, name=name, content=c, ref=ref, store_content=sc, time=t)
                else:
                    project, env = bucket.split("/")

                    def build(seq, prev, prev_time, chain=chain, project=project, env=env, scope=scope, key=key, kind=kind, name=name, content=content, ref=ref):
                        r = self.state.translate_ref(chain, ref)
                        t, c = self._timed(content, prev_time, agent, scope)
                        return make_record(key, kind=kind, project=project, env=env, agent=agent, seq=seq, prev=prev, name=name, content=c, ref=r, time=t)

                builds.append(build)
            recs = self.state.append_run(chain, builds, lambda r: wire_record(r, sc), still_valid=lambda b=bucket: self._write_bucket(api_key, agent) == b)
            if recs is not None:
                break
        self._pending += len(recs)
        if any(name != INSTANCE_STOP for _, name, _, _ in items):
            self._wrote.add(agent)
        if not api_key and not self._told_local and not self.quiet and not self.test:
            self._told_local = True
            print(
                f"signafaide: recording locally in {self.state.home} (signed and chained; no API key, so nothing is sent). "
                "Run `signafaide init` to send hashes for co-signature and public timestamps, or set SIGNAFAIDE_API_KEY.",
                file=sys.stderr,
            )
        self._start()
        if self._pending >= self.flush_size:
            self._wake.set()  # the shipper still honours its backoff
        return recs

    def declare_tools(self, tools: Dict[str, bool], *, source: str, origin: str, agent: Optional[str] = None, store_content: Optional[bool] = None) -> str:
        """Declare the tools one source knows for an agent (§2.6): a ``signafaide.tools`` note
        followed by one note per tool, written as one run. *source* names who declares (``sdk``:
        the SDK in this program); *origin* is ``wrap_tools`` or ``declared``. The notes list the
        agent's whole tool list, the union over every source that declared on this machine (§8
        ``tools/<agent>.json``), a tool recorded when any source records it. Written at most once
        per recorder for the same set: the first time, and again when the set changes. Returns the
        header's record hash."""
        agent = agent or self.default_agent
        if not AGENT_RE.match(agent):
            raise ValueError(f"agent {agent!r} is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)")
        names = sorted(tools)
        for n in names:
            if not isinstance(n, str) or not n or any(ord(c) < 0x20 or ord(c) == 0x7F for c in n):
                raise TypeError(f"a tool name must be a non-empty string without control characters (got {n!r})")
        sig = json.dumps([[n, bool(tools[n])] for n in names])
        held = self._declared.get((agent, source))

        def write(union: Dict[str, bool], expired: bool) -> str:
            # The same list as last time: only the entry's time is refreshed, unless a stopped
            # source's tools just dropped out of the agent's list (§8), which is declared anew.
            if held and held[0] == sig and not expired:
                return held[1]
            # By declared name (a long name is cut, §2.6); two names cut to the same one keep the recorded form.
            by_name: Dict[str, Tuple[str, bool]] = {}
            for tool, recorded in union.items():
                d = declared_name(tool)
                if d not in by_name or (recorded and not by_name[d][1]):
                    by_name[d] = (tool, recorded)
            listed = [by_name[d] for d in sorted(by_name)]
            n_recorded = sum(1 for _, r in listed if r)
            items: List[Tuple[str, str, dict, Optional[str]]] = [
                ("note", TOOLS, {"source": origin, "tools": len(listed), "recorded": n_recorded, "unrecorded": len(listed) - n_recorded}, None)
            ]
            items += [("note", tool_note_name(tool, recorded), {"tool": tool, "recorded": recorded}, None) for tool, recorded in listed]
            return record_hash(self.write_run(items, agent=agent, store_content=store_content)[0])

        own = {n: bool(tools[n]) for n in names}
        h = self.state.declare_tools(agent, source, own, write)
        self._declared[(agent, source)] = (sig, h, origin, own, store_content)
        if self._tool_thread is None and not self._stopped:
            self._tool_stop.clear()
            self._tool_thread = threading.Thread(target=self._tool_loop, name="signafaide-tools", daemon=True)  # never keeps a finished program alive
            self._tool_thread.start()
        return h

    def _tool_loop(self) -> None:
        while not self._tool_stop.wait(TOOL_SOURCE_REFRESH_MS / 1000):
            self.refresh_tool_sources()

    def refresh_tool_sources(self) -> None:
        """Refresh this recorder's entries in ``tools/<agent>.json`` (§8): each gets the current
        time, so other sources keep counting its tools, and entries of sources that stopped more
        than 24 hours ago drop out. Nothing is written to the chain unless that changed the
        agent's tool list. Runs by itself once an hour while the process lives. Never raises."""
        for (agent, source), (_, _, origin, tools, store_content) in list(self._declared.items()):
            try:
                self.declare_tools(tools, source=source, origin=origin, agent=agent, store_content=store_content)
            except Exception as e:  # noqa: BLE001
                self._report(f"signafaide: could not refresh the tool list of {agent}: {e}")

    def release_tool_sources(self) -> None:
        """A clean end of this source (§8): its entries leave ``tools/<agent>.json``, so the next
        declaration by any source no longer counts its tools. Nothing is written to the chain.
        Never raises."""
        self._tool_stop.set()
        self._tool_thread = None
        for agent, source in list(self._declared):
            try:
                self.state.release_tool_source(agent, source)
            except Exception:  # noqa: BLE001  the 24-hour rule covers an entry that could not be removed
                pass
        self._declared.clear()

    def _write_bucket(self, api_key: Optional[str], agent: str) -> str:
        """Where *agent*'s next record goes. A known project whose chain for *agent* is not on
        this disk (an empty ``SIGNAFAIDE_HOME`` on Lambda or Cloud Run) may already have that
        chain on the witness, so the record is a draft until the shipper has asked for the
        witness's head and continues after it (§8). Writing never waits for the network."""
        bucket = self.state.bucket(api_key)
        if not api_key or bucket.startswith(PENDING + "/") or self.state.chain_path(f"{bucket}/{agent}").exists():
            return bucket
        # Drafts already written for this agent before the key was set continue in place.
        nokey = f"{PENDING}/nokey"
        return nokey if self.state.chain_path(f"{nokey}/{agent}").exists() else f"{PENDING}/{key_fingerprint(api_key)}"

    def _adopt_into(self, bucket: str, api_key: Optional[str], bases: Optional[Dict[str, dict]] = None) -> Dict[str, SignafaideError]:
        """Sign the draft chains written before the project was known into *bucket* (§8).
        Returns the chains that stay pending, with why (chain id -> error). *bases*: agent ->
        the service's head, for a chain whose local file is gone (an ephemeral disk)."""
        out: Dict[str, SignafaideError] = {}
        if bucket.startswith(PENDING + "/"):
            return out
        sources = [f"{PENDING}/nokey"]
        if api_key:
            sources.append(f"{PENDING}/{key_fingerprint(api_key)}")
        # §2.4: a key's valid_from is at most 7 days before its registration, so the service
        # accepts records written up to 7 days (less an hour of margin) before they are sent.
        not_before = (datetime.now(timezone.utc) - KEY_MAX_AGE).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
        scope = scope_of(bucket)
        for src in sources:
            for chain, why in self.state.adopt(src, bucket, lambda a, first=None: self.key(a, scope, first), lambda r: wire_record(r, self.store_content), not_before, bases):
                if why == "exists":
                    msg = (f"{chain} cannot join {bucket}, which already has that agent's chain; it stays pending (local only) "
                           "and still verifies with `signafaide verify`")
                else:
                    msg = (f"{chain} starts at {why}, more than 7 days ago: the service accepts records up to 7 days old (§2.4), "
                           f"so this chain stays local; it still verifies with `signafaide verify`. New records of that agent start a new chain under {bucket}")
                out[chain] = SignafaideError(msg, code="chain_exists" if why == "exists" else "too_old")
        return out

    def _remote_bases(self, bucket: str, api_key: str) -> Dict[str, dict]:
        """The service's heads for pending agents with no local chain under *bucket* (an ephemeral
        disk lost it): their drafts continue the service's chain instead of conflicting."""
        out: Dict[str, dict] = {}
        fp = key_fingerprint(api_key)
        agents = {c.rsplit("/", 1)[1] for c in self.state.chains() if c.startswith(f"{PENDING}/nokey/") or c.startswith(f"{PENDING}/{fp}/")}
        agents = {a for a in agents if not self.state.chain_path(f"{bucket}/{a}").exists()}
        client = self.client(api_key=api_key)
        for a in sorted(agents):
            try:
                sh = client.head(a) or {}
            except SignafaideError as e:
                # No head (no records yet) or no agent at all (not registered yet): the chain
                # starts at seq 1; the shipper registers the key first (§2.4).
                if e.code in ("not_found", "unknown_agent"):
                    continue
                raise
            h = sh.get("head") or {}
            seq, rh = h.get("seq"), h.get("record_hash")
            if isinstance(seq, int) and seq > 0 and isinstance(rh, str) and re.fullmatch(r"[0-9a-f]{64}", rh) and f"{h.get('project')}/{h.get('env')}" == bucket and h.get("agent") == a:
                out[a] = {"seq": seq, "record_hash": rh, "signed": {"head": h, "head_sig": sh.get("head_sig")}}
                # Is the head's record the earlier instance's stop note (a clean restart, §8)? When
                # the witness cannot say, the start note says "unknown" and counts as one with no stop.
                try:
                    got = (client.record(rh) or {}).get("record")
                except SignafaideError:
                    got = None
                if is_stop_note(got, a, rh):
                    out[a]["stop"] = {"envelope": got["envelope"], "key_id": got.get("key_id"), "sig": got.get("sig")}
        return out

    def _waiting(self) -> int:
        """Records waiting to ship, drafts included."""
        return self.state.outbox_size() + sum(self.state.draft_count(c) for c in self.state.chains() if c.startswith(PENDING + "/"))

    # --- shipping -----------------------------------------------------------

    def _key_label(self, api_key: str) -> str:
        return f"API key {api_key[:13]}..."

    def flush(self, timeout: float = 10.0, *, background: bool = False) -> dict:
        """Ship the outbox of this API key's project now. Returns ``{shipped, left, errors}``;
        ``errors`` maps chain id (or the API key, for errors about the key) to the one-sentence
        fix. Records of other projects (an earlier key) wait until that key is used again. An
        explicit flush always tries, even after a refusal."""
        if not background:
            self._halted = None
            self._blocked.clear()
        shipped, errors = 0, {}
        # Local-first: with no API key nothing is sent and no sandbox is created. A human opts
        # in with `signafaide init` or by setting SIGNAFAIDE_API_KEY.
        api_key = self.api_key
        if api_key and (self.state.outbox_size() or self.state.has_drafts()):
            bases: Dict[str, dict] = {}
            try:
                self.resolve_project(api_key)
                if self.state.has_drafts():
                    bases = self._remote_bases(self.state.bucket(api_key), api_key)
            except (SignafaideError, StateError) as e:
                err = e if isinstance(e, SignafaideError) else SignafaideError(str(e), code="state")
                return {"shipped": 0, "left": self._waiting(), "errors": {self._key_label(api_key): err}}
            done: Set[str] = set()
            while True:
                bucket = self.state.bucket(api_key)
                errors.update(self._adopt_into(bucket, api_key, bases))
                bases = {}
                todo = [c for c in self.state.outbox_chains(bucket) if c not in done]
                if not todo:
                    break
                done.add(todo[0])
                try:
                    shipped += len(self._ship_chain(todo[0], api_key, timeout))
                except SignafaideError as e:
                    errors[self._key_label(api_key) if e.code == "invalid_key" else todo[0]] = e
                    if e.retryable or e.code in PROJECT_WIDE:
                        break  # the same error applies to every chain
        return {"shipped": shipped, "left": self._waiting(), "errors": errors}

    def stop(self, timeout: float = 10.0, *, background: bool = False) -> dict:
        """A clean stop (§8): ship everything, then write and ship a signed stop note for each
        agent this process wrote records for. The next instance's start right after it is a clean
        restart, with no "earlier unsent records are not known" warning. Nothing is written while
        any record is still unsent (the next start then carries the warning, as it should). Call
        it in the shutdown handler of an ephemeral container (SIGTERM); a program that ends by
        itself with a head file set does it at exit. Returns ``{shipped, left, errors, stopped}``;
        ``stopped`` lists the chains whose stop note the witness co-signed."""
        first = self.flush(timeout, background=background)
        api_key = self.api_key
        stopped: List[str] = []
        if self.test or not api_key or first["left"] or first["errors"]:
            return {**first, "stopped": stopped}
        bucket = self.state.bucket(api_key)
        if bucket.startswith(PENDING + "/"):
            return {**first, "stopped": stopped}
        for agent in sorted(self._wrote):
            chain = f"{bucket}/{agent}"
            last = self.state.last_record(chain) if self.state.chain_path(chain).exists() else None
            if not last or "receipt" not in last or (last["envelope"]["kind"] == "note" and last["envelope"]["name"] == INSTANCE_STOP):
                continue
            self.write("note", INSTANCE_STOP, instance_stop_content(last["envelope"]["seq"], record_hash(last)), agent=agent)
            stopped.append(chain)
        self._wrote.clear()
        if not stopped:
            return {**first, "stopped": stopped}
        second = self.flush(timeout, background=background)
        return {"shipped": first["shipped"] + second["shipped"], "left": second["left"], "errors": second["errors"], "stopped": [] if second["left"] else stopped}

    def warn_strict_refused(self, tool: str, err: SignafaideError) -> None:
        """One stderr line, the first time a strict tool is refused in this process (frameworks
        often swallow the tool's error): the tool, why, and the fix."""
        if self._told_strict:
            return
        self._told_strict = True
        fix = ("there is no API key, and strict mode needs the witness's receipt. Fix: run `signafaide init` (a free sandbox) or set "
               "SIGNAFAIDE_API_KEY, or drop strict for this tool") if err.code == "no_key" else err.message
        print(f"signafaide: WARNING strict tool \"{tool}\" was refused and did not run ({err.code}): {fix}. Later strict refusals in this process are not printed again.",
              file=sys.stderr)

    def ensure_receipt(self, rec: dict, timeout: float = 10.0) -> dict:
        """Strict mode: ship *rec*'s chain now and return its receipt, or raise."""
        agent, h = rec["envelope"]["agent"], record_hash(rec)
        api_key = self.api_key
        if not api_key:
            raise SignafaideError(
                "Strict mode needs the service's receipt, and there is no API key: run `signafaide init` (a free sandbox) or set SIGNAFAIDE_API_KEY.",
                code="no_key",
            )
        self.resolve_project(api_key)
        bucket = self.state.bucket(api_key)
        self._adopt_into(bucket, api_key, self._remote_bases(bucket, api_key) if self.state.has_drafts() else None)
        h = self.state.translate_ref(f"{bucket}/{agent}", h)  # a draft is signed by now
        received = self._ship_chain(f"{bucket}/{agent}", api_key, timeout)
        if h not in received:
            raise SignafaideError(f"The service did not return a receipt for record {h[:12]}; check `signafaide status`.", code="not_recorded")
        self._adopt_into(self.state.bucket(api_key), api_key)
        return received[h]

    def _explain(self, e: SignafaideError, chain: str, key_id: str, current: str) -> SignafaideError:
        """The witness's refusal, in words that say what happened and what to do."""
        agent = chain.rsplit("/", 1)[1]
        msg = f"{e.message} (chain {chain})"
        if e.code == "bad_signature" and re.search(r"revoked|retired", e.message):
            if key_id == current:
                scope = scope_of(chain.rsplit("/", 1)[0])
                if self.state.provided_key(agent, scope):
                    msg = (f"{chain}: agent key {key_id} was revoked, so the witness refuses every record it signs. Put a new key for {agent} in "
                           f"{agent_key_env_name(agent, scope)} (or your key provider), then run `signafaide repair --agent {agent}`: it sets aside the "
                           "records the revoked key signed after it ended, kept on this machine and still verifiable.")
                else:
                    msg = (f"{chain}: agent key {key_id} was revoked, so the witness refuses every record it signs. Run `signafaide repair --agent {agent}`: "
                           "it sets aside the records the revoked key signed after it ended, kept on this machine and still verifiable, and gives the "
                           "agent a new key.")
            else:
                msg = (f"{chain}: records signed by agent key {key_id} after it was revoked or retired cannot be co-signed, and new records wait "
                       f"behind them. Run `signafaide repair --agent {agent}`: it sets them aside (kept on this machine, still verifiable) so the "
                       "new key's records ship.")
        elif "signafaide repair" in e.message:
            msg = f"{e.message} (chain {chain})"  # the witness already said what to do
        elif re.search(r"ahead of the service clock|must not be in the future", e.message):
            msg = (f"{e.message} (chain {chain}). This machine's clock is ahead of the witness's. Fix the clock (NTP); records already written "
                   f"with future times ship once the witness's clock reaches them, or run `signafaide repair --agent {agent}` to set them aside "
                   "with a fresh key now.")
        elif re.search(r"not active at|earlier than the time of", e.message):
            msg = (f"{e.message} (chain {chain}). Run `signafaide repair --agent {agent}`: it sets the records the witness cannot take aside "
                   "(kept, still verifiable) and starts a new segment with a fresh key.")
        return SignafaideError(msg, code=e.code, status=e.status, docs=e.docs, body=e.body)

    def _ship_chain(self, chain: str, api_key: str, timeout: float) -> Dict[str, dict]:
        """Ship one chain's outbox in order. Returns {record_hash: receipt}."""
        agent = chain.rsplit("/", 1)[1]
        scope = scope_of(chain.rsplit("/", 1)[0])
        received: Dict[str, dict] = {}
        wait = None if self._deadline is None else max(0.0, self._deadline - __import__("time").monotonic())
        if not self._ship_lock.acquire(timeout=-1 if wait is None else wait):
            raise SignafaideError("another send is still waiting for the service; records stay in the outbox.", code="network")
        try:
            fp = self._config_fp()
            b = self._blocked.get(chain)
            if b and b[0] == fp:
                raise b[1]
            self._blocked.pop(chain, None)
            wire = lambda r: wire_record(r, self.store_content)  # noqa: E731
            if chain not in self._reconciled:
                self.state.reconcile_outbox(chain, wire)
                self._reconciled.add(chain)
            client = self.client(timeout, api_key=api_key)
            while True:
                batch = self.state.outbox(chain, BATCH_MAX)
                if not batch:
                    return received
                current = self.key(agent, scope).key_id
                if batch[0]["key_id"] != current:
                    # Records signed before `keys rotate` go first, under the old key: registering
                    # the new key retires the old one on the service (§2.4).
                    batch = [r for r in batch[: next((i for i, r in enumerate(batch) if r["key_id"] == current), len(batch))]]
                else:
                    self._register(client, agent, scope)
                try:
                    try:
                        resp = client.submit(batch)
                    except SignafaideError as e:
                        if e.code != "unknown_agent":
                            raise
                        self._registered.discard((client.api_key, agent, self.key(agent, scope).key_id))
                        self._register(client, agent, scope)
                        resp = client.submit(batch)
                except SignafaideError as e:
                    if e.code == "chain_conflict":
                        head = (e.body.get("error") or {}).get("head") or {}
                        err = SignafaideError(
                            f"{e.message} (chain {chain}: service head is seq {head.get('seq')} "
                            f"{head.get('record_hash')}; local outbox starts at seq {batch[0]['envelope']['seq']}; "
                            "nothing was rewritten, run `signafaide verify` and `signafaide status`)",
                            code=e.code, status=e.status, docs=e.docs, body=e.body,
                        )
                    else:
                        err = self._explain(e, chain, batch[0]["key_id"], current) if e.permanent else e
                    if err.permanent and err.code not in PROJECT_WIDE:
                        self._blocked[chain] = (fp, err)
                        self.state.set_blocked(chain, {"code": err.code, "message": err.message, "seq": batch[0]["envelope"]["seq"]})
                    raise err from None
                got = {r["record_hash"]: r for r in resp.get("receipts", [])}
                bucket = chain.rsplit("/", 1)[0]
                if any(f"{r['batch']['project']}/{r['batch']['env']}" != bucket for r in got.values()):
                    raise SignafaideError(f"The service returned receipts for another project than {bucket}; nothing was written. Check SIGNAFAIDE_URL and the API key.", code="bad_response")
                self.state.apply_receipts(chain, got)
                self.state.drop_outbox(chain, [r["envelope"]["seq"] for r in batch if record_hash(r) in got])
                for w in self.state.update_heads(resp.get("heads", [])):
                    log.warning("signafaide: %s", w)
                if self.on_head is not None and resp.get("heads"):
                    try:
                        self.on_head(resp["heads"])
                    except Exception as e:  # noqa: BLE001 - a hook never stops recording
                        log.warning("signafaide: on_head failed (the heads are still in head.json): %s", e)
                received.update(got)
                self._pending = 0
                if not got:
                    raise SignafaideError("The service accepted the batch but returned no matching receipts.", code="no_receipts")
                self.state.set_blocked(chain, None)
        finally:
            self._ship_lock.release()

    def create_key(self, agent: str, env: str, print_only: bool) -> dict:
        """``signafaide keys create``: a new key for *agent* in *env*, registered with the witness
        under the API key (which must be of that env), writing no record. With *print_only*,
        nothing is written here: the key file is returned for a secret store
        (``SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>`` for live). Otherwise it becomes the agent's key
        file. Refused when the agent already has a key here or from the environment; the witness
        refuses it when the agent already has an active key there."""
        api_key = self.api_key
        if not api_key:
            raise SignafaideError("keys create registers the new key with the witness: set SIGNAFAIDE_API_KEY to a key of that env first "
                                  "(a live key from the console for --env live).", code="no_key")
        if _env_of(api_key) != env:
            raise SignafaideError(f"SIGNAFAIDE_API_KEY is a {_env_of(api_key)} key; --env {env} needs a {env} key.", code="invalid_key")
        scope = "live" if env == "live" else ""
        if self.state.provided_key(agent, scope):
            raise StateError(f"agent {agent} already has a key from {agent_key_env_name(agent, scope)} (or a key provider); unset it to make a new one, "
                             "or use `signafaide keys rotate`")
        if not print_only and self.state.key_path(agent, scope).exists():
            raise StateError(f"agent {agent} already has a key file ({self.state.key_path(agent, scope)}); use `signafaide keys rotate` to replace it")
        # The key's project, asked of the witness: with --print nothing is written here, not even
        # the project mapping in config.json.
        known = self.state.bucket(api_key)
        if not known.startswith(PENDING + "/"):
            project, key_env = known.split("/")
        else:
            resp = self.client(api_key=api_key).project()
            project, key_env = (resp.get("project"), resp.get("env")) if isinstance(resp, dict) else (None, None)
            if key_env != env or not valid_project_id(project):
                raise SignafaideError(f"The service at {self.url} answered GET /v1/project with an invalid project or env; check SIGNAFAIDE_URL.", code="bad_response")
            if not print_only:
                self.state.learn_project(api_key, project, key_env)
        key, doc = self.state.new_key_file(agent)
        reg = registration(project, key_env, agent, doc["public_key"], doc["created"])
        try:
            resp = self.client(api_key=api_key).register_agent(agent, doc["public_key"], doc["created"], key.sign("register", hash_json(reg)), None)
        except SignafaideError as e:
            if e.code == "bad_signature":
                raise SignafaideError(
                    f"agent {agent} already has an active key on the witness, so a new one needs the old key's rotation signature: run "
                    f"`signafaide keys rotate --agent {agent} --env {env}` where that key is, or have an admin revoke it in the console, then run keys create again.",
                    code="bad_signature") from None
            raise
        if resp.get("key_id") not in (None, key.key_id):
            raise SignafaideError(f"The service registered key {resp.get('key_id')} for {agent}, expected {key.key_id}.", code="key_mismatch")
        self._registered.add((api_key, agent, key.key_id))
        out = {"doc": doc, "env_name": agent_key_env_name(agent, scope), "project": project}
        if not print_only:
            out["file"] = str(self.state.save_key_file(doc, scope))
        return out

    def _register(self, client: Client, agent: str, scope: str) -> None:
        """§2.4: register the agent's key with its proof of possession, and a rotation
        signature by the newest retired key when there is one. valid_from is the key's creation
        time, kept within the 7 days the service allows, and never after this machine's clock now
        (a key made while the clock was ahead registers once the clock is right)."""
        k = self.key(agent, scope)
        # Per key: a key rotated while this process runs (`signafaide keys rotate`) is registered too.
        if (client.api_key, agent, k.key_id) in self._registered:
            return
        project, env = self.state.bucket(client.api_key).split("/")
        now_ = now()
        floor = (datetime.now(timezone.utc) - KEY_MAX_AGE).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        valid_from = min(max(self.state.key_created(agent, scope) or now_, floor), now_)
        reg = registration(project, env, agent, b64url(k.public_key), valid_from)
        h = hash_json(reg)
        retired = self.state.retired_keys(agent, scope)
        rotation = {"key_id": retired[0][0].key_id, "sig": retired[0][0].sign("rotate", h)} if retired else None
        try:
            resp = client.register_agent(agent, reg["public_key"], valid_from, k.sign("register", h), rotation)
        except SignafaideError as e:
            if e.permanent:
                raise self._explain(e, f"{project}/{env}/{agent}", k.key_id, k.key_id) from None
            raise
        if resp.get("key_id") not in (None, k.key_id):
            raise SignafaideError(f"The service registered key {resp.get('key_id')} for {agent}, expected {k.key_id}.", code="key_mismatch")
        # The service says when it retired the agent's earlier keys: kept for `keys export` (§2.5).
        for r in resp.get("retired") or []:
            if isinstance(r, dict) and isinstance(r.get("key_id"), str) and isinstance(r.get("valid_to"), str):
                self.state.mark_retired(agent, r["key_id"], r["valid_to"], scope)
        self._registered.add((client.api_key, agent, k.key_id))

    # --- background thread --------------------------------------------------

    def _start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopped = False
        self._thread = threading.Thread(target=self._loop, name="signafaide-shipper", daemon=True)
        self._thread.start()
        if not self._atexit:
            atexit.register(self.close)
            self._atexit = True

    def _loop(self) -> None:
        """One attempt at a time (a single thread), never inside the backoff (a wake-up from
        ``write`` only shortens the wait when the backoff is over), and never after a refusal
        retrying cannot fix until the configuration (API key, URL, agent keys) changes."""
        import random
        import time

        failures = 0
        while not self._stopped:
            delay = max(self.flush_interval if not self._next_attempt else self._next_attempt - time.monotonic(), 0.05)
            self._wake.wait(delay)
            self._wake.clear()
            if self._stopped:
                return
            if time.monotonic() < self._next_attempt:
                continue  # woken inside the backoff: wait out the rest
            if not self.api_key or not self._waiting():
                self._next_attempt = 0.0
                continue  # no key: local only, nothing is sent
            fp = self._config_fp()
            if self._halted is not None:
                if self._halted[0] == fp:
                    self._next_attempt = time.monotonic() + self.flush_interval
                    continue
                self._halted = None
            result = self._flush_logged(background=True)
            errs = [e for e in (result or {}).get("errors", {}).values() if e.code not in LOCAL_CODES] if result else []
            if result is not None and not errs:
                failures, self._next_attempt = 0, 0.0
                continue
            wide = next((e for e in errs if e.permanent and e.code in PROJECT_WIDE), None)
            if wide is not None:
                self._halted = (fp, wide)
                self._report(f"signafaide: sending stopped until the API key or SIGNAFAIDE_URL changes (`signafaide flush` tries again now): {wide}")
                self._next_attempt = time.monotonic() + self.flush_interval
                continue
            failures += 1
            self._next_attempt = time.monotonic() + min(60.0, self.flush_interval * 2**failures) * random.uniform(0.8, 1.2)

    def _flush_logged(self, timeout: float = 10.0, background: bool = False) -> Optional[dict]:
        try:
            result = self.flush(timeout, background=background)
        except Exception as e:  # never let the shipper die
            self._report(f"signafaide: {e}")
            return None
        if result["errors"]:
            self._report("signafaide: " + "; ".join(str(e) if a in str(e) else f"{a}: {e}" for a, e in result["errors"].items()))
        elif self._failing and result["shipped"]:
            log.warning("signafaide: service reachable again, shipped %s", plural(result["shipped"], "record"))
            self._failing = None
        return result

    def _report(self, msg: str) -> None:
        if msg != self._failing:  # one line per distinct problem, not per retry
            log.warning(msg)
            self._failing = msg

    def close(self, timeout: Optional[float] = None) -> None:
        """Stop the shipper and make one last attempt to ship (process exit), holding the
        process at most ``exit_flush`` seconds (or *timeout*) in all."""
        import time

        self._stopped = True
        self._wake.set()
        self.release_tool_sources()  # a clean end: this program's tools leave the agent's tool list (§8)
        limit = self.exit_flush if timeout is None else timeout
        stop = self.instance_stop and bool(self._wrote) and not self.test
        if not limit or not self.api_key or not (self._waiting() or stop):
            return
        if self._halted is not None and self._halted[0] == self._config_fp():
            return
        self._deadline = time.monotonic() + limit
        self._deadline_limit = limit
        try:
            if stop:
                # A clean exit of an ephemeral instance: the stop note, when everything else was sent.
                try:
                    result = self.stop(limit, background=True)
                    if result["errors"]:
                        self._report("signafaide: " + "; ".join(str(e) if a in str(e) else f"{a}: {e}" for a, e in result["errors"].items()))
                except Exception as e:  # noqa: BLE001  never fail the program's exit
                    self._report(f"signafaide: {e}")
            else:
                self._flush_logged(limit, background=True)
        finally:
            self._deadline = None
        left = self._waiting()
        if left and not self.quiet:
            print(f"signafaide: {plural(left, 'record')} kept in {self.state.home / 'outbox'}; they ship on the next run or with `signafaide flush`", file=sys.stderr)

    def _after_fork(self) -> None:
        self._ship_lock = threading.Lock()
        self._wake = threading.Event()
        self._thread = None
        self._tool_thread = None
        self._tool_stop = threading.Event()

    # --- blocked chains and repair -------------------------------------------

    def diagnose(self) -> List[dict]:
        """Why each chain cannot ship, found on this machine (time going back, a clock ahead, a
        key used after it ended) or said by the witness (blocked.json): ``{chain, seq, code,
        reason, records, next}``. Reads only the records without a receipt."""
        out: List[dict] = []
        saved = self.state.blocked()
        now_ms = datetime.now(timezone.utc).timestamp() * 1000
        for chain in self.state.chains():
            if chain.startswith(PENDING + "/"):
                continue
            agent = chain.rsplit("/", 1)[1]
            scope = scope_of(chain.rsplit("/", 1)[0])
            tail: List[dict] = []
            prev_time: Optional[str] = None
            path = self.state.chain_path(chain)
            if path.exists():
                from .state import _parse_line, _reverse_lines

                with open(path, "rb") as f:
                    for _, line in _reverse_lines(f):
                        r = _parse_line(path, line)
                        if "receipt" in r:
                            prev_time = r["envelope"]["time"]
                            break
                        tail.append(r)
            tail.reverse()
            if not tail:
                continue
            ended = {rk.key_id: t for rk, _ in self.state.retired_keys(agent, scope) if (t := self.state.retired_at(agent, rk.key_id, scope))}
            created: Dict[str, str] = {rk.key_id: c for rk, c in self.state.retired_keys(agent, scope)}
            cur = self.state.load_key(agent, create=False, scope=scope)
            c0 = self.state.key_created(agent, scope)
            if cur is not None and c0:
                created[cur.key_id] = c0
            nxt = f"run `signafaide repair --agent {agent}` (sets these records aside, kept and verifiable, and starts a new segment with a fresh key)"
            wait = (f"fix the clock (NTP) and wait until it catches up with these records, which then ship, or run `signafaide repair --agent {agent}` "
                    "(sets them aside, kept and verifiable, and starts a new segment with a fresh key)")
            found = None
            for i, r in enumerate(tail):
                t, seq, kid = r["envelope"]["time"], r["envelope"]["seq"], r["key_id"]

                def at(code: str, reason: str) -> dict:
                    return {"chain": chain, "seq": seq, "code": code, "reason": reason, "records": len(tail) - i, "next": nxt}

                if prev_time and t < prev_time:
                    found = at("time_back", f"seq {seq} has time {t}, earlier than the record before it ({prev_time}): the clock went back while an older SDK was writing")
                elif kid in created and t < created[kid]:
                    found = at("before_key", f"seq {seq} has time {t}, before its key {kid} was made ({created[kid]})")
                elif kid in ended and t >= ended[kid]:
                    found = at("key_ended", f"seq {seq} is signed by key {kid} after it ended at {ended[kid]}")
                elif parse_time(t).timestamp() * 1000 > now_ms + MAX_CLOCK_SKEW_MS:
                    found = at("clock_ahead", f"seq {seq} has time {t}, ahead of this machine's clock now: the clock was ahead when it was written")
                    found["next"] = wait
                if found:
                    break
                prev_time = t
            w = saved.get(chain)
            if not found and w:
                i, first = next(((i, r) for i, r in enumerate(tail) if w.get("seq") is None or r["envelope"]["seq"] >= w["seq"]), (0, tail[0]))
                msg = str(w.get("message") or "")
                msg = msg[len(chain) + 2:] if msg.startswith(f"{chain}: ") else msg
                msg = msg.rstrip(" .")  # the line goes on with "; <n> records cannot ship"
                ahead = bool(re.search(r"ahead of the service clock|must not be in the future", msg))
                found = {"chain": chain, "seq": first["envelope"]["seq"], "code": w.get("code"), "reason": f"refused by the witness: {msg}",
                         "records": len(tail) - i, "next": wait if ahead else nxt}
            if found:
                out.append(found)
        return out

    def repair(self, agent: Optional[str] = None, dry_run: bool = False) -> List[dict]:
        """``signafaide repair``: for each blocked chain (of *agent*, or every agent), set the
        records from the first one that cannot ship aside into ``held/`` (kept, still verifiable
        locally), give the agent a new key (rotation, §2.4), and write a ``note`` named
        ``signafaide.repair`` that commits to the held records' hashes, so the new segment's first
        co-signed record fixes them in time. Co-signed records are never touched."""
        out = []
        for b in self.diagnose():
            name = b["chain"].rsplit("/", 1)[1]
            if agent and name != agent:
                continue
            if dry_run:
                out.append({"chain": b["chain"], "blocked": b})
                continue
            bucket = b["chain"].rsplit("/", 1)[0]
            scope = scope_of(bucket)
            path, recs = self.state.hold_tail(b["chain"], b["seq"])
            new_key = None
            if not self.state.provided_key(name, scope):
                new_key = self.state.rotate_key(name, scope)[1].key_id
            self._keys.pop((name, scope), None)
            content = {
                "held": str(path.relative_to(self.state.home)),
                "from_seq": recs[0]["envelope"]["seq"],
                "to_seq": recs[-1]["envelope"]["seq"],
                "records": len(recs),
                "records_hash": hash_json([record_hash(r) for r in recs]),
                "code": b["code"],
                "reason": b["reason"],
            }
            project, env = bucket.split("/")
            key = self.key(name, scope)

            def build(seq, prev, prev_time):
                t, c = self._timed(content, prev_time, name, scope)
                return make_record(key, kind="note", project=project, env=env, agent=name, seq=seq, prev=prev, name="signafaide.repair", content=c, ref=None, time=t)

            note = self.state.append(b["chain"], build, lambda r: wire_record(r, self.store_content))
            self.state.set_blocked(b["chain"], None)
            self._blocked.pop(b["chain"], None)
            self._halted = None
            out.append({"chain": b["chain"], "blocked": b, "held": str(path), "records": len(recs), "new_key": new_key, "note": record_hash(note)})
        return out

    # --- status -------------------------------------------------------------

    def telemetry_notes(self, chain: str) -> List[str]:
        """What the chain's telemetry notes say (§2.7), in the verifier's words: the tools
        recorded from telemetry spans, and that the telemetry is sampled. Only the lines that
        name such a note are parsed, so a long chain is read quickly. Never raises."""
        found = []
        for path in [*self.state.segments(chain), self.state.chain_path(chain)]:
            try:
                with open(path, "rb") as f:
                    for line in f:
                        if b'"signafaide.telemetry' in line:
                            e = json.loads(line)["envelope"]
                            found.append((e["seq"], e["kind"], e["name"]))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        t = tool_telemetry(found)
        return telemetry_lines(chain, t) if t else []

    def status(self) -> dict:
        heads = self.state.chain_heads()
        bucket = self.state.bucket(self.api_key)
        blocked = {b["chain"]: b for b in self.diagnose()}
        chains = []
        for c in self.state.chains():
            agent = c.rsplit("/", 1)[1]
            k = self.state.load_key(agent, create=False, scope=scope_of(c.rsplit("/", 1)[0]))
            h = (heads.get(c) or {}).get("head") or {}
            chains.append(
                {
                    "chain": c,
                    "agent": agent,
                    "current": c.startswith(bucket + "/"),
                    "key_id": k.key_id if k else None,
                    "records": self.state.tail(c)[0],
                    "waiting": self.state.outbox_size(c),
                    "receipt_seq": h.get("seq"),
                    "receipt_time": h.get("server_time"),
                    "blocked": blocked.get(c),
                    "telemetry": self.telemetry_notes(c),
                }
            )
        return {
            "url": self.url,
            "home": str(self.state.home),
            "api_key": self.api_key,
            "api_key_invalid": not self.api_key and bool(self.raw_api_key) and not self.test,
            "test_mode": self.test,
            "env": _env_of(self.api_key),
            "bucket": bucket,
            "sandbox": self.state.sandbox(),
            "chains": chains,
            "held": [{"chain": c, "file": str(p), "records": len(r)} for c, p, r in self.state.held_segments()],
            # Drafts wait too: for the project, or for the witness's head of a chain new to this disk.
            "outbox": self._waiting(),
        }


def _env_of(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    return "test" if key.startswith("sfa_test_") else "live" if key.startswith("sfa_live_") else "unknown"


# --- default instance ---------------------------------------------------------

_default: Optional[Recorder] = None
_default_lock = threading.Lock()


def get() -> Recorder:
    global _default
    with _default_lock:
        if _default is None:
            _default = Recorder()
        return _default


def configure(**kwargs) -> Recorder:
    """Replace the default recorder (used by ``init`` and tests)."""
    global _default
    with _default_lock:
        if _default is not None:
            _default._stopped = True
            _default._wake.set()
            _default._tool_stop.set()
            atexit.unregister(_default.close)
        _default = Recorder(**kwargs)
        return _default



def legal_links(resp: dict, url: str) -> dict:
    """The Terms and Privacy notice links from a ``POST /v1/sandbox`` answer (or ``sandbox.json``);
    a service that sends none (or anything but an http(s) URL) gets ``<url>/legal/terms`` and ``/legal/privacy``."""

    def ok(v: object) -> bool:
        return isinstance(v, str) and len(v) <= 300 and re.fullmatch(r"https?://\S+", v) is not None

    base = url.rstrip("/")
    return {
        "terms_url": resp.get("terms_url") if ok(resp.get("terms_url")) else f"{base}/legal/terms",
        "privacy_url": resp.get("privacy_url") if ok(resp.get("privacy_url")) else f"{base}/legal/privacy",
    }


def terms_notice(links: dict) -> str:
    """The one line shown when a sandbox is created."""
    return f"By creating a sandbox you agree to the signafAIde Terms ({links['terms_url']}) and Privacy notice ({links['privacy_url']})."
