"""Minimal JSON client for the signafAIde HTTP API (SPEC §6). Standard library only."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from ._version import __version__
from .telemetry import HEADER, client_header

#: The hosted witness. Configurable with SIGNAFAIDE_URL (a self-hosted witness, or a local dev
#: server such as http://127.0.0.1:7474); a release test fails if this is ever a loopback address.
DEFAULT_URL = "https://api.signafaide.co.uk"

#: The hosted console's origin. The console's prompt gives it as ``SIGNAFAIDE_URL``, and it answers
#: as the hosted witness too: it and ``DEFAULT_URL`` are one service.
HOSTED_CONSOLE = "https://signafaide.co.uk"


def witness_url(u: str) -> str:
    """A witness URL as the SDK uses it: trimmed, without a trailing slash, and the hosted
    console's origin read as the hosted witness (``DEFAULT_URL``), so either address names the
    same witness."""
    t = u.strip().rstrip("/")
    return DEFAULT_URL if t.lower() in (HOSTED_CONSOLE, DEFAULT_URL) else t


#: Errors the SDK cannot fix by retrying: shipping stops until the configuration changes.
NON_RETRYABLE = frozenset(
    {
        "quota_exceeded",
        "invalid_key",
        "plan_required",
        "bad_signature",
        "invalid_record",
        "content_mismatch",
        "chain_conflict",
        "unknown_agent",
        "key_mismatch",
        "bad_response",
    }
)


def network_blocked_words(url: str) -> str:
    """The one sentence said when the network here does not let the witness be reached (a proxy
    or network policy refused it, or its name does not resolve): common in cloud coding agents
    and CI sandboxes."""
    host = (urllib.parse.urlsplit(url).hostname or url).lower()
    if host == "signafaide.co.uk" or host.endswith(".signafaide.co.uk"):
        return (
            "The network here blocks signafaide.co.uk (common in cloud coding agents and CI sandboxes): allow signafaide.co.uk and "
            "api.signafaide.co.uk in the environment's network settings, or run from a machine that can reach them; "
            "records stay signed on this machine meanwhile."
        )
    return (
        f"The network here blocks {host} (common in cloud coding agents and CI sandboxes): allow {host} in the environment's "
        "network settings, or run from a machine that can reach it; records stay signed on this machine meanwhile."
    )


def _uses_proxy(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
        proxies = urllib.request.getproxies()
        return bool(proxies.get(parts.scheme)) and not urllib.request.proxy_bypass(parts.hostname or "")
    except Exception:  # noqa: BLE001 - no proxy settings to read
        return False


def blocked_by_network(url: str, reason: BaseException) -> bool:
    """Whether a failed request was stopped by the network here rather than by the witness: a
    proxy refused the tunnel (HTTP 403 or 407 to CONNECT), or, with no proxy in the way, the name
    does not resolve (DNS blocked). A proxy that cannot be reached, or does not answer, has
    refused nothing: that is said as it is."""
    text = str(reason)
    if "Tunnel connection failed" in text or ("407" in text and "roxy" in text):
        return True
    if _uses_proxy(url):
        return False  # the witness's name is looked up by the proxy, not here
    return (
        isinstance(reason, socket.gaierror)
        or "Name or service not known" in text
        or "Temporary failure in name resolution" in text
        or "nodename nor servname" in text
        or "getaddrinfo failed" in text
    )


class SignafaideError(Exception):
    """An error from the service or the SDK. ``str(e)`` is the one-sentence fix.

    ``code`` is the service error code (``chain_conflict``, ``invalid_key``...),
    or ``network`` when the service could not be reached.
    """

    def __init__(
        self,
        message: str,
        code: str = "error",
        status: int = 0,
        docs: Optional[str] = None,
        body: Optional[dict] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.docs = docs
        self.body = body or {}

    @property
    def blocked(self) -> bool:
        """The network here blocks the witness (a proxy or network policy): the message says so."""
        return self.code == "network" and bool(self.body.get("blocked"))

    @property
    def retryable(self) -> bool:
        return self.code in ("network", "rate_limited") or self.status >= 500

    @property
    def permanent(self) -> bool:
        """The service refused for a reason retrying cannot change (quota, key, revoked agent key...)."""
        return not self.retryable and self.code in NON_RETRYABLE


class Client:
    def __init__(
        self,
        url: str = DEFAULT_URL,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        client_id: Optional[str] = None,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        #: Said instead of "no answer within <timeout> s" when the timeout is a share of a larger limit.
        self.timeout_label: Optional[str] = None
        # The coding agent is detected only at set-up time (init, agent setup), never per request.
        self.client_id = client_id or client_header()

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        auth: bool = True,
        query: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> Any:
        """One request. Returns the JSON answer, or None for 304 Not Modified (a request with
        ``If-None-Match``)."""
        return self._request(method, path, body, auth, query, headers or {})

    def _request(self, method: str, path: str, body: Any, auth: bool, query: Optional[dict], extra: dict) -> Any:
        url = self.url + path
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q)
        headers = {
            "Accept": "application/json",
            "User-Agent": f"signafaide-python/{__version__}",
            HEADER: self.client_id,
            **extra,
        }
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            if not self.api_key:
                raise SignafaideError(
                    "No API key: run `signafaide init` or set SIGNAFAIDE_API_KEY.", code="invalid_key"
                )
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None
            err = _service_error(e.code, e.read())
            # A proxy's refusal, not the witness's: 407, or a 403 that is not the witness's JSON error.
            if e.code == 407 or (e.code == 403 and err.code == "http_error"):
                raise SignafaideError(
                    network_blocked_words(self.url), code="network", status=0, body={"blocked": True}
                ) from None
            raise err from None
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, BaseException) and blocked_by_network(url, reason):
                raise SignafaideError(network_blocked_words(self.url), code="network", body={"blocked": True}) from None
            if "timed out" in str(reason):
                reason = self.timeout_label or f"no answer within {self.timeout:g} s"
            raise SignafaideError(
                f"Cannot reach the signafAIde service at {self.url} ({reason}); check the network or SIGNAFAIDE_URL.",
                code="network",
            ) from None
        if "json" in ctype or raw[:1] in (b"{", b"["):
            return json.loads(raw)
        return raw.decode()

    # --- endpoints ----------------------------------------------------------

    def sandbox(self) -> dict:
        return self.request("POST", "/v1/sandbox", {}, auth=False)

    def register_agent(
        self, name: str, public_key: str, valid_from: str, proof: str, rotation: Optional[dict] = None
    ) -> dict:
        """§2.4: the registration with its proof of possession (and rotation signature)."""
        body: dict = {"name": name, "public_key": public_key, "valid_from": valid_from, "proof": proof}
        if rotation:
            body["rotation"] = rotation
        return self.request("POST", "/v1/agents", body)

    def project(self) -> dict:
        """``{project, env}`` of this API key (§6)."""
        return self.request("GET", "/v1/project")

    def submit(self, records: list) -> dict:
        return self.request("POST", "/v1/records", {"records": records})

    def head(self, agent: str) -> dict:
        return self.request("GET", f"/v1/heads/{urllib.parse.quote(agent)}")

    def record(self, record_hash: str) -> dict:
        """``{record, receipt, anchor}`` of one record of the key's project."""
        return self.request("GET", f"/v1/records/{urllib.parse.quote(record_hash)}")

    def export(self, agent: Optional[str] = None, from_: Optional[str] = None, to: Optional[str] = None) -> dict:
        """A verification pack (§7) of the whole project, or of one agent."""
        return self.request("GET", "/v1/export", query={"agent": agent, "from": from_, "to": to})

    def usage(self) -> dict:
        return self.request("GET", "/v1/usage")

    def event(self, name: str) -> None:
        """Usage event (``verify``, ``export``). Not part of SPEC §6 yet."""
        self.request("POST", "/v1/events", {"name": name}, auth=bool(self.api_key))

    def service_keys(self) -> dict:
        return self.request("GET", "/.well-known/signafaide-keys.json", auth=False)

    def rules(self, etag: Optional[str] = None, version: Optional[int] = None) -> Optional[dict]:
        """The project's signed rule set (§6, §10.2): ``{rules, sig, service_key_id}``,
        ``{"rules": null}`` without one, or None when *etag* (its ``rules_hash``) is still current."""
        return self.request(
            "GET", "/v1/rules", query={"version": version}, headers={"If-None-Match": f'"{etag}"'} if etag else None
        )

    def device_code(self, client: str, host: str) -> dict:
        """§6 (1.1): start a device sign-in. No auth."""
        return self.request("POST", "/v1/device/code", {"client": client, "host": host}, auth=False)

    def device_token(self, device_code: str) -> dict:
        """§6 (1.1): poll a device sign-in. Always 200 with ``{status}``. No auth."""
        return self.request("POST", "/v1/device/token", {"device_code": device_code}, auth=False)

    def session(self) -> dict:
        """§6 (1.1): who a person session is (the client's key is the session): ``{person, organisation,
        expires_at, projects: [{project, name, env, role}]}``, ``role`` being ``owner``, ``admin`` or
        ``developer``."""
        return self.request("GET", "/v1/session")

    def end_session(self) -> Any:
        """§6 (1.1): end a person session (``signafaide logout``)."""
        return self.request("DELETE", "/v1/session")

    def publish_rules(self, body: dict) -> dict:
        """§6 (1.1): publish the next version of a project's rule set, with a person session or
        the key of an unclaimed sandbox. Returns ``{rules, sig, service_key_id}``."""
        return self.request("POST", "/v1/rules", body)

    def auditor_link(self, body: dict) -> dict:
        """§6 (1.1) ``POST /v1/auditor-links``: a read-only auditor link (``signafaide prove``), body
        ``{agent, tool?, from?, days, agent_keys?, head?}``, answer ``{url, expires_at, agent_keys?}``
        (``agent_keys: true`` when the witness keeps the manifest for the auditor's browser check). A
        witness without it answers ``not_found``, and prove points at files."""
        return self.request("POST", "/v1/auditor-links", body)

    def fingerprints(self, since: Optional[int] = None) -> dict:
        """The shared fingerprint list (§6, §11.2): ``{snapshot, updates}``."""
        return self.request("GET", "/v1/fingerprints", query={"since": since})


def _service_error(status: int, raw: bytes) -> SignafaideError:
    try:
        body = json.loads(raw)
        err = body["error"]
        return SignafaideError(
            err["message"], code=err.get("code", "error"), status=status, docs=err.get("docs"), body=body
        )
    except (ValueError, KeyError, TypeError):
        text = raw.decode(errors="replace").strip()[:200]
        return SignafaideError(
            f"The service answered HTTP {status}: {text or 'no body'}.", code="http_error", status=status
        )


def fetch_json(url: str, timeout: float = 10.0, client_id: Optional[str] = None) -> Any:
    """GET a JSON document (used for ``--keys <url>``)."""
    host, _, path = url.partition("://")[2].partition("/")
    # a --keys URL may be anyone's: send only the SDK name and version there
    client_id = client_id or f"signafaide-python/{__version__}"
    return Client(url.split("://")[0] + "://" + host, timeout=timeout, client_id=client_id).request(
        "GET", "/" + path, auth=False
    )
