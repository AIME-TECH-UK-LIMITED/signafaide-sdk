"""The recorder: writes signed records locally and ships them in the background."""

from __future__ import annotations

import atexit
import contextvars
import logging
import os
import sys
import threading
from typing import Dict, Optional, Set, Tuple

from datetime import datetime, timedelta, timezone

from ._plural import plural
from .crypto import SigningKey, b64url, hash_json
from .http import DEFAULT_URL, Client, SignafaideError
from .records import API_KEY_RE, AGENT_RE, agent_name, make_draft, make_record, now, record_hash, registration, valid_project_id
from .state import PENDING, State, StateError, append_env_file, ensure_gitignore, key_fingerprint, read_env_file, wire_record
from . import telemetry

log = logging.getLogger("signafaide")

BATCH_MAX = 1000  # §6: at most 1000 records per POST /v1/records
#: §2.4: a registration's valid_from is at most 7 days old; keep an hour of margin.
KEY_MAX_AGE = timedelta(days=7) - timedelta(hours=1)

# Set while a compare runs a candidate function: any record written in that context is refused,
# so a candidate can never add to a chain (and a recorded tool it calls never runs).
NO_WRITES: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("signafaide_no_writes", default=None)


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
    ):
        self.state = State.discover(home)
        self._url = url
        self._api_key = api_key
        self.store_content = store_content
        self.flush_interval = flush_interval
        self.flush_size = flush_size
        self.quiet = quiet
        self.via = via
        self.strict_used = False  # a strict-mode tool ran in this process (client header)
        self._keys: Dict[str, Tuple[SigningKey, Optional[tuple]]] = {}
        self._registered: Set[tuple] = set()
        self._reconciled: Set[str] = set()
        self._blocked: Dict[str, SignafaideError] = {}
        self._ship_lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pending = 0
        self._resolve_after = 0.0  # monotonic time before which an offline project lookup is not retried
        self._failing: Optional[str] = None
        self._atexit = False
        self._stopped = False
        self._told_local = False
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    # --- configuration --------------------------------------------------------

    def _setting(self, name: str) -> Optional[str]:
        return os.environ.get(name) or read_env_file(self.state.root / ".env").get(name) or None

    @property
    def url(self) -> str:
        return (self._url or self._setting("SIGNAFAIDE_URL") or DEFAULT_URL).rstrip("/")

    @property
    def api_key(self) -> Optional[str]:
        return self._api_key or self._setting("SIGNAFAIDE_API_KEY")

    def client(self, timeout: float = 10.0, api_key: Optional[str] = None) -> Client:
        return Client(self.url, api_key or self.api_key, timeout=timeout, client_id=self.client_id())

    def agent(self) -> str:
        """The coding agent running now, else the one stored when the project was set up."""
        now_ = telemetry.detect_agent()
        return now_ if now_ != "unknown" else self.state.config().get("agent", "unknown")

    def client_id(self) -> str:
        return telemetry.client_header(via=self.via, adapter=telemetry.adapter_field(), agent=self.agent(), strict=self.strict_used)

    def remember_agent(self) -> None:
        """Store the detected coding agent in config.json (not when telemetry is off)."""
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

    @property
    def default_agent(self) -> str:
        return agent_name(self.state.root.name)

    def create_sandbox(self) -> str:
        """Return the API key; create a sandbox project if there is none. Only an explicit
        human opt-in calls this (``signafaide init``): records never create a sandbox by
        themselves."""
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
            ensure_gitignore(self.state.root / ".gitignore", ".env")  # the key must not be committed
            self.state.learn_project(key, resp["project"], "test")
            self.state.save_sandbox(
                {k: resp.get(k) for k in ("project", "claim_url", "free_quota")} | {"url": self.url, "created": now()}
            )
            self._api_key = key
            if not self.quiet:
                print(f"signafaide: sandbox ready, key saved to .env; claim it at {resp.get('claim_url')}", file=sys.stderr)
        return key

    def _resolve_now(self) -> None:
        """Before a record is signed, learn the API key's project so the record can name it.
        With no key nothing is asked (local-first: the record is a signed draft). Offline, the
        record becomes a draft too and the lookup waits 60 s before it is tried again."""
        import time

        key = self.api_key
        if not key or time.monotonic() < self._resolve_after:
            return
        try:
            self.resolve_project(key)
        except SignafaideError as e:
            if e.code != "network":
                raise
            self._resolve_after = time.monotonic() + 60.0

    def resolve_project(self, api_key: str) -> None:
        """Learn the API key's project (``GET /v1/project``) if it is not known yet, so
        envelopes can name it (§2.2). Raises SignafaideError when the service cannot say."""
        if not self.state.bucket(api_key).startswith(PENDING + "/"):
            return
        resp = self.client(api_key=api_key).project()
        project, env = (resp.get("project"), resp.get("env")) if isinstance(resp, dict) else (None, None)
        if env != _env_of(api_key) or not valid_project_id(project):
            raise SignafaideError(f"The service at {self.url} answered GET /v1/project with an invalid project or env; check SIGNAFAIDE_URL.", code="bad_response")
        self.state.learn_project(api_key, project, env)

    # --- writing ------------------------------------------------------------

    def key(self, agent: str) -> SigningKey:
        """The agent's key, reloaded when its file changes: `signafaide keys rotate` in another
        process takes effect at this process's next record (§2.4)."""

        def stamp() -> Optional[tuple]:
            try:
                st = os.stat(self.state.key_path(agent))
                return (st.st_ino, st.st_mtime_ns, st.st_size)
            except OSError:
                return None

        held = self._keys.get(agent)
        now = stamp()
        if held is not None and now is not None and held[1] == now:
            return held[0]
        k = self.state.load_key(agent)
        self._keys[agent] = (k, stamp())
        return k

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
        """Sign and chain one record locally (synchronous) and queue it for shipping.
        The chain is this API key's ``<project>/<env>/<agent>`` (§8)."""
        why = NO_WRITES.get()
        if why:
            raise SignafaideError(f"{why} must not write records: candidate functions must be side-effect free (it tried to record {name!r})", code="no_writes")
        agent = agent or self.default_agent
        if not AGENT_RE.match(agent):
            raise ValueError(f"agent {agent!r} is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)")
        key = self.key(agent)
        sc = self.store_content if store_content is None else store_content
        if self.state.bucket(self.api_key).startswith(PENDING + "/"):
            self._resolve_now()
        api_key = self.api_key
        while True:
            bucket = self.state.bucket(api_key)
            chain = f"{bucket}/{agent}"
            if not self.state.chain_path(chain).exists():
                for e in self._adopt_into(bucket, api_key).values():
                    self._report(f"signafaide: {e}")
            if bucket.startswith(PENDING + "/"):
                # The project is not known yet, and an envelope names it: keep a draft, signed later (§8).
                def build(seq, prev):
                    return make_draft(key, kind=kind, agent=agent, seq=seq, prev=prev, name=name, content=content, ref=ref, store_content=sc)
            else:
                project, env = bucket.split("/")

                def build(seq, prev, chain=chain, project=project, env=env):
                    r = self.state.translate_ref(chain, ref)
                    return make_record(key, kind=kind, project=project, env=env, agent=agent, seq=seq, prev=prev, name=name, content=content, ref=r)

            rec = self.state.append(chain, build, lambda r: wire_record(r, sc), still_valid=lambda b=bucket: self.state.bucket(api_key) == b)
            if rec is not None:
                break
        self._pending += 1
        if not api_key and not self._told_local and not self.quiet:
            self._told_local = True
            print(
                f"signafaide: recording locally in {self.state.home} (signed and chained; no API key, so nothing is sent). "
                "Run `signafaide init` to send hashes for co-signature and public timestamps, or set SIGNAFAIDE_API_KEY.",
                file=sys.stderr,
            )
        self._start()
        if self._pending >= self.flush_size:
            self._wake.set()
        return rec

    def _adopt_into(self, bucket: str, api_key: Optional[str]) -> Dict[str, SignafaideError]:
        """Sign the draft chains written before the project was known into *bucket* (§8).
        Returns the chains that stay pending, with why (chain id -> error)."""
        out: Dict[str, SignafaideError] = {}
        if bucket.startswith(PENDING + "/"):
            return out
        sources = [f"{PENDING}/nokey"]
        if api_key:
            sources.append(f"{PENDING}/{key_fingerprint(api_key)}")
        # §2.4: a key's valid_from is at most 7 days before its registration, so the service
        # accepts records written up to 7 days (less an hour of margin) before they are sent.
        not_before = (datetime.now(timezone.utc) - KEY_MAX_AGE).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
        for src in sources:
            for chain, why in self.state.adopt(src, bucket, self.key, lambda r: wire_record(r, self.store_content), not_before):
                if why == "exists":
                    msg = (f"{chain} cannot join {bucket}, which already has that agent's chain; it stays pending (local only) "
                           "and still verifies with `signafaide verify`")
                else:
                    msg = (f"{chain} starts at {why}, more than 7 days ago: the service accepts records up to 7 days old (§2.4), "
                           f"so this chain stays local; it still verifies with `signafaide verify`. New records of that agent start a new chain under {bucket}")
                out[chain] = SignafaideError(msg, code="chain_exists" if why == "exists" else "too_old")
        return out

    def _waiting(self) -> int:
        """Records waiting to ship, drafts included."""
        return self.state.outbox_size() + sum(self.state.draft_count(c) for c in self.state.chains() if c.startswith(PENDING + "/"))

    # --- shipping -----------------------------------------------------------

    def flush(self, timeout: float = 10.0) -> dict:
        """Ship the outbox of this API key's project now. Returns ``{shipped, left,
        errors}``; ``errors`` maps chain id to the one-sentence fix. Records of other
        projects (an earlier key) wait until that key is used again."""
        shipped, errors = 0, {}
        # Local-first: with no API key nothing is sent and no sandbox is created. A human opts
        # in with `signafaide init` or by setting SIGNAFAIDE_API_KEY.
        api_key = self.api_key
        if api_key and (self.state.outbox_size() or self.state.has_drafts()):
            try:
                self.resolve_project(api_key)
            except (SignafaideError, StateError) as e:
                err = e if isinstance(e, SignafaideError) else SignafaideError(str(e), code="state")
                waiting = self.state.outbox_chains() or [c for c in self.state.chains() if c.startswith(PENDING + "/")]
                return {"shipped": 0, "left": self._waiting(), "errors": {c: err for c in waiting}}
            done: Set[str] = set()
            while True:
                bucket = self.state.bucket(api_key)
                errors.update(self._adopt_into(bucket, api_key))
                todo = [c for c in self.state.outbox_chains(bucket) if c not in done]
                if not todo:
                    break
                done.add(todo[0])
                try:
                    shipped += len(self._ship_chain(todo[0], api_key, timeout))
                except SignafaideError as e:
                    errors[todo[0]] = e
                    if e.retryable or e.code in ("invalid_key", "quota_exceeded"):
                        break  # the same error applies to every chain
        return {"shipped": shipped, "left": self._waiting(), "errors": errors}

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
        self._adopt_into(bucket, api_key)
        h = self.state.translate_ref(f"{bucket}/{agent}", h)  # a draft is signed by now
        received = self._ship_chain(f"{bucket}/{agent}", api_key, timeout)
        if h not in received:
            raise SignafaideError(f"The service did not return a receipt for record {h[:12]}; check `signafaide status`.", code="not_recorded")
        self._adopt_into(self.state.bucket(api_key), api_key)
        return received[h]

    def _ship_chain(self, chain: str, api_key: str, timeout: float) -> Dict[str, dict]:
        """Ship one chain's outbox in order. Returns {record_hash: receipt}."""
        agent = chain.rsplit("/", 1)[1]
        received: Dict[str, dict] = {}
        with self._ship_lock:
            if chain in self._blocked:
                raise self._blocked[chain]
            wire = lambda r: wire_record(r, self.store_content)  # noqa: E731
            if chain not in self._reconciled:
                self.state.reconcile_outbox(chain, wire)
                self._reconciled.add(chain)
            client = self.client(timeout, api_key=api_key)
            while True:
                batch = self.state.outbox(chain, BATCH_MAX)
                if not batch:
                    return received
                current = self.key(agent).key_id
                if batch[0]["key_id"] != current:
                    # Records signed before `keys rotate` go first, under the old key: registering
                    # the new key retires the old one on the service (§2.4).
                    batch = [r for r in batch[: next((i for i, r in enumerate(batch) if r["key_id"] == current), len(batch))]]
                else:
                    self._register(client, agent)
                try:
                    resp = client.submit(batch)
                except SignafaideError as e:
                    if e.code == "unknown_agent":
                        self._registered.discard((client.api_key, agent))
                        self._register(client, agent)
                        resp = client.submit(batch)
                    elif e.code == "chain_conflict":
                        head = (e.body.get("error") or {}).get("head") or {}
                        e.message = (
                            f"{e.message} (chain {chain}: service head is seq {head.get('seq')} "
                            f"{head.get('record_hash')}; local outbox starts at seq {batch[0]['envelope']['seq']}; "
                            "nothing was rewritten, run `signafaide verify` and `signafaide status`)"
                        )
                        e.args = (e.message,)
                        self._blocked[chain] = e
                        raise
                    else:
                        if not e.retryable and e.code not in ("invalid_key", "quota_exceeded"):
                            self._blocked[chain] = e
                        raise
                got = {r["record_hash"]: r for r in resp.get("receipts", [])}
                bucket = chain.rsplit("/", 1)[0]
                if any(f"{r['batch']['project']}/{r['batch']['env']}" != bucket for r in got.values()):
                    raise SignafaideError(f"The service returned receipts for another project than {bucket}; nothing was written. Check SIGNAFAIDE_URL and the API key.", code="bad_response")
                self.state.apply_receipts(chain, got)
                self.state.drop_outbox(chain, [r["envelope"]["seq"] for r in batch if record_hash(r) in got])
                for w in self.state.update_heads(resp.get("heads", [])):
                    log.warning("signafaide: %s", w)
                received.update(got)
                self._pending = 0
                if not got:
                    raise SignafaideError("The service accepted the batch but returned no matching receipts.", code="no_receipts")

    def _register(self, client: Client, agent: str) -> None:
        """§2.4: register the agent's key with its proof of possession, and a rotation
        signature by the newest retired key when there is one."""
        k = self.key(agent)
        if (client.api_key, agent) in self._registered:
            return
        project, env = self.state.bucket(client.api_key).split("/")
        floor = (datetime.now(timezone.utc) - KEY_MAX_AGE).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        valid_from = max(self.state.key_created(agent) or now(), floor)
        reg = registration(project, env, agent, b64url(k.public_key), valid_from)
        h = hash_json(reg)
        retired = self.state.retired_keys(agent)
        rotation = {"key_id": retired[0][0].key_id, "sig": retired[0][0].sign("rotate", h)} if retired else None
        resp = client.register_agent(agent, reg["public_key"], valid_from, k.sign("register", h), rotation)
        if resp.get("key_id") not in (None, k.key_id):
            raise SignafaideError(f"The service registered key {resp.get('key_id')} for {agent}, expected {k.key_id}.", code="key_mismatch")
        # The service says when it retired the agent's earlier keys: kept for `keys export` (§2.5).
        for r in resp.get("retired") or []:
            if isinstance(r, dict) and isinstance(r.get("key_id"), str) and isinstance(r.get("valid_to"), str):
                self.state.mark_retired(agent, r["key_id"], r["valid_to"])
        self._registered.add((client.api_key, agent))

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
        delay = self.flush_interval
        failures = 0
        while not self._stopped:
            self._wake.wait(delay)
            self._wake.clear()
            if self._stopped:
                return
            if not self.api_key:
                continue  # no key: local only, nothing is sent
            result = self._flush_logged()
            if result is None or result["errors"]:
                failures += 1
                delay = min(60.0, self.flush_interval * 2**failures)
            else:
                failures, delay = 0, self.flush_interval

    def _flush_logged(self, timeout: float = 10.0) -> Optional[dict]:
        try:
            result = self.flush(timeout)
        except Exception as e:  # never let the shipper die
            self._report(f"signafaide: {e}")
            return None
        if result["errors"]:
            self._report("signafaide: " + "; ".join(f"{a}: {e}" for a, e in result["errors"].items()))
        elif self._failing and result["shipped"]:
            log.warning("signafaide: service reachable again, shipped %s", plural(result["shipped"], "record"))
            self._failing = None
        return result

    def _report(self, msg: str) -> None:
        if msg != self._failing:  # one line per distinct problem, not per retry
            log.warning(msg)
            self._failing = msg

    def close(self, timeout: float = 3.0) -> None:
        """Stop the shipper and make one last attempt to ship (process exit)."""
        self._stopped = True
        self._wake.set()
        if not self.api_key or not self._waiting():
            return
        self._flush_logged(timeout)
        left = self._waiting()
        if left and not self.quiet:
            print(f"signafaide: {plural(left, 'record')} kept in {self.state.home / 'outbox'}; they ship on the next run or with `signafaide flush`", file=sys.stderr)

    def _after_fork(self) -> None:
        self._ship_lock = threading.Lock()
        self._wake = threading.Event()
        self._thread = None

    # --- status -------------------------------------------------------------

    def status(self) -> dict:
        heads = self.state.chain_heads()
        bucket = self.state.bucket(self.api_key)
        chains = []
        for c in self.state.chains():
            agent = c.rsplit("/", 1)[1]
            k = self.state.load_key(agent, create=False)
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
                }
            )
        return {
            "url": self.url,
            "home": str(self.state.home),
            "api_key": self.api_key,
            "env": _env_of(self.api_key),
            "bucket": bucket,
            "sandbox": self.state.sandbox(),
            "chains": chains,
            "outbox": self.state.outbox_size(),
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
            atexit.unregister(_default.close)
        _default = Recorder(**kwargs)
        return _default

