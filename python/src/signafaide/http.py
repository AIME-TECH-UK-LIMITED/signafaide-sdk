"""Minimal JSON client for the signafAIde HTTP API (SPEC §6). Standard library only."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from ._version import __version__
from .telemetry import HEADER, client_header, detect_agent

DEFAULT_URL = "http://127.0.0.1:7474"


class SignafaideError(Exception):
    """An error from the service or the SDK. ``str(e)`` is the one-sentence fix.

    ``code`` is the service error code (``chain_conflict``, ``invalid_key``...),
    or ``network`` when the service could not be reached.
    """

    def __init__(self, message: str, code: str = "error", status: int = 0, docs: Optional[str] = None, body: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.docs = docs
        self.body = body or {}

    @property
    def retryable(self) -> bool:
        return self.code in ("network", "rate_limited") or self.status >= 500


class Client:
    def __init__(self, url: str = DEFAULT_URL, api_key: Optional[str] = None, timeout: float = 10.0, client_id: Optional[str] = None):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.client_id = client_id or client_header(agent=detect_agent())

    def request(self, method: str, path: str, body: Any = None, auth: bool = True, query: Optional[dict] = None) -> Any:
        url = self.url + path
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q)
        headers = {"Accept": "application/json", "User-Agent": f"signafaide-python/{__version__}", HEADER: self.client_id}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            if not self.api_key:
                raise SignafaideError("No API key: run `signafaide init` or set SIGNAFAIDE_API_KEY.", code="invalid_key")
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            raise _service_error(e.code, e.read()) from None
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise SignafaideError(
                f"Cannot reach the signafAIde service at {self.url} ({reason}); start it or set SIGNAFAIDE_URL.",
                code="network",
            ) from None
        if "json" in ctype or raw[:1] in (b"{", b"["):
            return json.loads(raw)
        return raw.decode()

    # --- endpoints ----------------------------------------------------------

    def sandbox(self) -> dict:
        return self.request("POST", "/v1/sandbox", {}, auth=False)

    def register_agent(self, name: str, public_key: str, valid_from: str, proof: str, rotation: Optional[dict] = None) -> dict:
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


def _service_error(status: int, raw: bytes) -> SignafaideError:
    try:
        body = json.loads(raw)
        err = body["error"]
        return SignafaideError(err["message"], code=err.get("code", "error"), status=status, docs=err.get("docs"), body=body)
    except (ValueError, KeyError, TypeError):
        text = raw.decode(errors="replace").strip()[:200]
        return SignafaideError(f"The service answered HTTP {status}: {text or 'no body'}.", code="http_error", status=status)


def fetch_json(url: str, timeout: float = 10.0, client_id: Optional[str] = None) -> Any:
    """GET a JSON document (used for ``--keys <url>``)."""
    host, _, path = url.partition("://")[2].partition("/")
    # a --keys URL may be anyone's: send only the SDK name and version there
    client_id = client_id or f"signafaide-python/{__version__}"
    return Client(url.split("://")[0] + "://" + host, timeout=timeout, client_id=client_id).request("GET", "/" + path, auth=False)
