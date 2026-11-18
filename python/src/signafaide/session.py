"""Signing in from the command line (SPEC §6 and §8, spec 1.1): ``signafaide login`` runs the device
sign-in, ``signafaide logout`` ends it. The person session is kept in the operating system's
credential store through ``keyring`` when it is installed and works, else in
``signafaide/session.json`` under the user's configuration directory with file mode 0600: never in
the project, its ``.signafaide/`` folder or its ``.env``, and never in an environment variable the
agent's process reads. ``session.json`` always says which witness each session is for and where its
secret is. Only the CLI uses it, and only to publish rules.

Where a person signs in is never chosen by a file in the project: the witness is ``--url``, else
``SIGNAFAIDE_URL`` in the process environment, else the hosted service (``person_witness``). The
sign-in page the witness sends is shown and opened only when it is on that witness's console
(``console_origin``), and a session is only ever sent to the witness it was made for."""

from __future__ import annotations

import json
import os
import re
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from ._version import __version__
from .http import DEFAULT_URL, Client, SignafaideError

SESSION_RE = re.compile(r"\Asfa_user_[0-9A-Za-z]{32}\Z")
#: The console of the hosted witness (``DEFAULT_URL``): its sign-in page is on this origin.
DEFAULT_CONSOLE = "https://signafaide.co.uk"
#: Characters a URL the CLI shows, opens or keys a session by may hold (RFC 3986, without quotes).
_URL_CHARS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]+\Z")
_SERVICE = "signafaide"


def _origin(url: str) -> Optional[str]:
    """``scheme://host[:port]`` of an http(s) URL without user info, the default port left out; else None."""
    if not isinstance(url, str) or not _URL_CHARS.match(url):
        return None
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return None
    scheme = u.scheme.lower()
    if scheme not in ("http", "https") or not u.hostname or "@" in u.netloc:
        return None
    host = u.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + (f":{port}" if port is not None and port != default else "")


def person_witness(given: Optional[str] = None) -> str:
    """The witness a person signs in to and publishes rules with (§8): *given* (``--url``), else
    ``SIGNAFAIDE_URL`` in the process environment, else the hosted service. Never the project's
    ``.env``: a file in a project must not choose where a person's sign-in or session goes."""
    u = (given or os.environ.get("SIGNAFAIDE_URL") or DEFAULT_URL).strip().rstrip("/")
    if _origin(u) is None:
        raise SignafaideError(f"{u} is not a witness URL (https://host, or http://127.0.0.1:port for a local one).", code="bad_request")
    return u


def console_origin(witness: str, given: Optional[str] = None) -> str:
    """The origin the sign-in page of the witness at *witness* must be on (§8): *given*
    (``--console``) when given, the hosted console for the hosted witness, else the witness's own origin."""
    if given:
        o = _origin(given.strip())
        if o is None:
            raise SignafaideError(f"--console {given} is not an http(s) origin.", code="bad_request")
        return o
    if witness.rstrip("/") == DEFAULT_URL:
        return DEFAULT_CONSOLE
    o = _origin(witness)
    if o is None:
        raise SignafaideError(f"{witness} is not a witness URL.", code="bad_request")
    return o


def on_console(link, origin: str) -> Optional[str]:
    """*link* when it is an http(s) URL on *origin*; else None."""
    return link if isinstance(link, str) and _origin(link) == origin else None


def config_dir() -> Path:
    """``$XDG_CONFIG_HOME``, else ``%APPDATA%`` on Windows, else ``~/.config``."""
    if os.environ.get("XDG_CONFIG_HOME"):
        return Path(os.environ["XDG_CONFIG_HOME"])
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"])
    return Path.home() / ".config"


def session_file() -> Path:
    return config_dir() / "signafaide" / "session.json"


# --- the operating system's credential store ----------------------------------------------------

def credential_store():
    """``(name, keyring module)`` when ``keyring`` is installed and has a working backend, else
    None (also with ``SIGNAFAIDE_CREDENTIAL_STORE=file``). The name is the store's: ``keychain``
    and ``secret-service`` are the ones the TypeScript CLI also reads."""
    if os.environ.get("SIGNAFAIDE_CREDENTIAL_STORE", "").strip().lower() == "file":
        return None
    try:
        import keyring
        from keyring.backends import fail

        kr = keyring.get_keyring()
        if isinstance(kr, fail.Keyring):
            return None
        mod = type(kr).__module__
        name = "keychain" if mod.endswith(".macOS") else "secret-service" if mod.endswith(".SecretService") else "keyring"
        return name, keyring
    except Exception:
        return None


def _all() -> dict:
    try:
        doc = json.loads(session_file().read_text())
        return doc["sessions"] if isinstance(doc, dict) and isinstance(doc.get("sessions"), dict) else {}
    except (OSError, ValueError):
        return {}


def _write(sessions: dict) -> None:
    f = session_file()
    f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = f.with_name(f"session.json.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps({"sessions": sessions}, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, f)


def load_session(url: str) -> Optional[dict]:
    """The held session for the witness at *url*, or None (none, another witness's, malformed,
    expired, or its secret gone from the credential store)."""
    s = _all().get(url)
    if not isinstance(s, dict) or s.get("url") != url:
        return None
    try:
        if datetime.fromisoformat(str(s.get("expires_at")).replace("Z", "+00:00")) <= datetime.now(timezone.utc):
            return None
    except ValueError:
        pass
    secret = s.get("session")
    if s.get("store") not in (None, "file"):
        store = credential_store()
        secret = None
        if store is not None and store[0] == s["store"]:
            try:
                secret = store[1].get_password(_SERVICE, url)
            except Exception:
                secret = None
    if not isinstance(secret, str) or not SESSION_RE.match(secret):
        return None
    return {**s, "session": secret}


def save_session(s: dict) -> str:
    """Keep *s*: its secret in the credential store when there is one, else in session.json (0600).
    Returns where the secret went."""
    meta = dict(s)
    store = credential_store()
    meta["store"] = "file"
    if store is not None:
        try:
            store[1].set_password(_SERVICE, s["url"], s["session"])
            meta["store"] = store[0]
            del meta["session"]
        except Exception:
            pass
    _write({**_all(), s["url"]: meta})
    return meta["store"]


def forget_session(url: str) -> bool:
    sessions = _all()
    if url not in sessions:
        return False
    was = sessions[url]
    if isinstance(was, dict) and was.get("store") not in (None, "file"):
        store = credential_store()
        if store is not None and store[0] == was["store"]:
            try:
                store[1].delete_password(_SERVICE, url)
            except Exception:
                pass
    del sessions[url]
    _write(sessions)
    return True


def open_browser(url: str) -> bool:
    """Open an http(s) URL in the person's browser when this machine has one; never fails. Only a
    URL that parses as http(s) without quotes or spaces is opened, through ``webbrowser`` (no shell)."""
    if os.environ.get("SIGNAFAIDE_NO_BROWSER") or os.environ.get("CI") or not sys.stdout.isatty():
        return False
    if _origin(url) is None:
        return False
    try:
        import webbrowser

        return bool(webbrowser.open(url))
    except Exception:
        return False


def login(url: str, client_id: str, out: Callable[[str], None], *, sleep: Callable[[float], None] = time.sleep,
          browser: Callable[[str], bool] = open_browser, console: Optional[str] = None) -> dict:
    """``signafaide login``: the device sign-in of §6. Says which witness it signs in to, checks
    that the page the witness sends is on that witness's console (else stops: a relay could send
    the real console's page and keep the session the person approves), prints the code and the
    page, opens the browser when it can, polls until the person approves or refuses, and keeps the
    session for that witness only."""
    url = url.strip().rstrip("/")
    origin = console_origin(url, console)
    client = Client(url, None, 10.0, client_id)
    host = (socket.gethostname() or "this machine")[:100]
    out(f"Witness     {url}")
    code = client.device_code(f"signafaide-python/{__version__}", host)
    if not isinstance(code, dict) or not all(isinstance(code.get(k), str) for k in ("device_code", "user_code", "verification_uri")):
        raise SignafaideError(f"The service at {url} answered POST /v1/device/code without a code; check the witness URL.", code="bad_response")
    page = on_console(code["verification_uri"], origin)
    full = page if code.get("verification_uri_complete") is None else on_console(code.get("verification_uri_complete"), origin)
    if not page or not full:
        shown = str(code.get("verification_uri_complete") or code["verification_uri"])[:200]
        raise SignafaideError(
            f"Not signed in: the witness at {url} sent a sign-in page ({shown}) that is not on its console ({origin}). Nothing was opened or saved. "
            f"If this witness's console is elsewhere, run signafaide login --url {url} --console <console origin>.", code="bad_response")
    if not re.fullmatch(r"[A-Z0-9-]{1,20}", code["user_code"]):
        raise SignafaideError(f"The service at {url} answered POST /v1/device/code with a malformed code; nothing was saved.", code="bad_response")
    out(f"Sign in at  {page}")
    out(f"Your code   {code['user_code']}")
    out(f"            The page shows this machine ({host}); approve it only if you started this sign-in, for {url}.")
    if browser(full):
        out("            Opened your browser.")
    interval = max(1, int(code.get("interval") or 5))
    until = time.monotonic() + max(1, int(code.get("expires_in") or 600))
    while time.monotonic() < until:
        sleep(interval)
        t = client.device_token(code["device_code"]) or {}
        status = t.get("status")
        if status == "pending":
            continue
        if status == "slow_down":
            interval += 5
            continue
        if status == "denied":
            raise SignafaideError("The sign-in was refused on the console page; nothing was saved.", code="denied")
        if status == "expired":
            raise SignafaideError("The code expired before anyone approved it; run `signafaide login` again.", code="expired")
        if status == "approved" and isinstance(t.get("session"), str) and SESSION_RE.match(t["session"]):
            expires = t.get("expires_at") or (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
            s = {"session": t["session"], "expires_at": expires, "url": url, "person": t.get("person"), "organisation": t.get("organisation")}
            s["store"] = save_session(s)
            if s["store"] == "file":
                out(f"            note: no credential store on this machine (install keyring for one); the session is in {session_file()} (readable by you only).")
            return s
        raise SignafaideError(f"The service at {url} answered the sign-in with an unexpected status; run `signafaide login` again.", code="bad_response")
    raise SignafaideError("The code expired before anyone approved it; run `signafaide login` again.", code="expired")


def logout(url: str, client_id: str) -> bool:
    """``signafaide logout``: end the session at the witness it was made for and forget it here."""
    url = url.strip().rstrip("/")
    s = load_session(url)
    if s is not None:
        try:
            Client(s["url"], s["session"], 10.0, client_id).end_session()
        except SignafaideError as e:
            if e.code != "invalid_key":
                forget_session(url)
                raise
    return forget_session(url) or s is not None
