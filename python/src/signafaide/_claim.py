"""The claim step: what ``init``, ``status``, ``claim`` and a passing ``verify`` say about a
sandbox. Why to claim it, and how long an unclaimed one has left. The TypeScript SDK
(``claim.ts``) says the same, word for word.

The time left comes from the witness (``expires_at`` of ``POST /v1/sandbox`` and
``GET /v1/project``, SPEC §6). A witness that does not send it gets no line about days: the SDK
never assumes a number.
"""

from __future__ import annotations

import math
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from ._plural import plural
from .http import SignafaideError
from .state import StateError

_EXPIRY_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
_MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]
_UNSET = object()


def _when(v: object) -> Optional[datetime]:
    m = _EXPIRY_RE.match(v) if isinstance(v, str) else None
    if not m:
        return None
    try:
        t = datetime(*(int(x) for x in m.groups()[:6]), tzinfo=timezone.utc)
    except ValueError:
        return None
    t += timedelta(seconds=float(m.group(7) or 0))
    if m.group(8) != "Z":
        sign = 1 if m.group(8)[0] == "+" else -1
        t -= sign * timedelta(hours=int(m.group(8)[1:3]), minutes=int(m.group(8)[4:6]))
    return t


def parse_expiry(v: object) -> Optional[str]:
    """The witness's ``expires_at`` when it is an RFC 3339 time (SPEC §1 writes UTC with milliseconds), else None."""
    return v if _when(v) is not None else None  # type: ignore[return-value]


def days_left(expires_at: str, now: Optional[float] = None) -> int:
    """Whole days from *now* (Unix seconds) to *expires_at*, rounded up; 0 once it has passed."""
    t = _when(expires_at)
    assert t is not None
    return max(0, math.ceil((t.timestamp() - (time.time() if now is None else now)) / 86_400))


def long_date(when: str) -> str:
    """``15 December 2026``, the UTC date."""
    t = _when(when)
    assert t is not None
    return f"{t.day} {_MONTHS[t.month - 1]} {t.year}"


def sandbox_view(
    rec, answer=_UNSET, refused: bool = False, refresh: bool = True, timeout: float = 3, now: Optional[float] = None
) -> Optional[dict]:
    """The sandbox of this project when its test key is in use, else None:
    ``{claim_url, claimed, expires_at, days_left, refused, unconfirmed}``. Unless it is known to be
    claimed, the witness is asked once (``GET /v1/project``, or *answer* when the caller already
    has it; ``refresh=False`` asks nothing) and what it says is saved in ``sandbox.json``.

    ``refused``: the witness refused the sandbox's key (``invalid_key``), so it deleted the sandbox.
    ``unconfirmed``: ``expires_at`` has passed and the witness could not be asked whether the
    sandbox was claimed first."""
    s = rec.state.sandbox() or {}
    key = rec.api_key or ""
    if not s.get("claim_url") or not key.startswith("sfa_test_"):
        return None
    claimed = bool(s.get("claimed"))
    expires = parse_expiry(s.get("expires_at"))
    asked = False
    was_refused = False
    # A test key of another project (pasted from the console) says nothing about this sandbox.
    bucket = rec.state.bucket(key)
    own = not s.get("project") or bucket.startswith("_pending/") or bucket == f"{s['project']}/test"
    if not claimed and own:
        was_refused = bool(refused)
        if answer is _UNSET and not was_refused and refresh:
            try:
                answer = rec.client(timeout=timeout).project()
            except SignafaideError as e:
                was_refused = e.code == "invalid_key"
                answer = None
        if isinstance(answer, dict) and answer and (not s.get("project") or answer.get("project") == s.get("project")):
            asked = True
            nxt = dict(s)
            if answer.get("claimed") is True:
                claimed, expires = True, None
                nxt["claimed"] = True
                nxt.pop("expires_at", None)
            else:
                told = parse_expiry(answer.get("expires_at"))
                if told:
                    nxt["expires_at"] = expires = told
            if nxt != s:
                try:
                    rec.state.save_sandbox(nxt)
                except (StateError, OSError):
                    pass  # shown from the answer all the same
    days = days_left(expires, now) if expires else None
    return {
        "claim_url": s["claim_url"],
        "claimed": claimed,
        "expires_at": None if claimed else expires,
        "days_left": None if claimed else days,
        "refused": was_refused,
        "unconfirmed": not claimed and days == 0 and not asked and not was_refused,
    }


def sandbox_json(v: dict) -> dict:
    """The sandbox as data, for ``--json`` output."""
    return {k: v[k] for k in ("claim_url", "claimed", "expires_at", "days_left")}


CLAIM_DONE = "claim: done (this sandbox belongs to an organisation now)"
CLAIM_WHY = (
    "claiming is free and needs no card: the sandbox moves into your own organisation and stops expiring, "
    "and you get the console, live keys and auditor links"
)
_KEPT = "Records on this machine are kept and still verify"


def _start_again(env_file: Path) -> str:
    """How to carry on once the witness has deleted the sandbox."""
    return (
        f"{_KEPT}. To carry on with the service: remove SIGNAFAIDE_API_KEY from {env_file} (or from the environment), "
        "run `signafaide init` for a new sandbox and claim it"
    )


def claim_notes(v: dict) -> List[str]:
    """The lines after the claim link: why to claim, and the time left when the witness gave it."""
    lines = [CLAIM_WHY]
    if v["expires_at"] and v["days_left"]:
        lines.append(
            f"{plural(v['days_left'], 'day')} left: an unclaimed sandbox and its records on the service are deleted on "
            f"{long_date(v['expires_at'])}. {_KEPT}"
        )
    return lines


def claim_lines(v: dict, root: Path) -> List[str]:
    """Everything about the claim step, one plain line each; the first starts with ``claim: ``."""
    env_file = Path(root) / ".env"
    if v["claimed"]:
        return [CLAIM_DONE]
    if v["unconfirmed"]:
        return [
            f"claim: {v['claim_url']}",
            f"this sandbox was due to be deleted on {long_date(v['expires_at'])} unless it was claimed first, and the service could not be "
            f"asked just now; run `signafaide status` when it can be reached. {_KEPT}",
        ]
    if v["expires_at"] and v["days_left"] == 0:
        return [
            f"claim: this sandbox expired on {long_date(v['expires_at'])} without being claimed, so its claim link no longer works. "
            "The service deletes an expired sandbox and its records there within a day, and from then on refuses its key (invalid_key)",
            _start_again(env_file),
        ]
    if v["refused"]:
        return [
            "claim: the service refuses this sandbox's key (invalid_key). The service deletes an unclaimed sandbox and its records there "
            "when it expires, and this one had not been claimed when this machine last asked",
            _start_again(env_file),
        ]
    return [f"claim: {v['claim_url']}", *claim_notes(v)]


def sandbox_gone(v: dict) -> bool:
    """Whether the sandbox can no longer be claimed (expired, or its key refused)."""
    return (
        not v["claimed"] and not v["unconfirmed"] and ((bool(v["expires_at"]) and v["days_left"] == 0) or v["refused"])
    )
