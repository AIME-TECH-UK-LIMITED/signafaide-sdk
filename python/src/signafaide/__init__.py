"""signafAIde: signed, chained records of what your AI agents decided.

    import signafaide

    @signafaide.record
    def approve_payout(claim_id: str, amount: float): ...

Every call writes a ``decision`` record before the function runs and an
``outcome`` record after it. Records are signed with the agent's own key and
chained locally in ``.signafaide/``. Nothing is sent until a human opts in
(``signafaide init``, or SIGNAFAIDE_API_KEY); then records ship to the service
in the background. Only hashes leave the machine unless ``store_content=True``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Union

from . import runtime
from ._version import __version__
from .drand import load_verifier as load_drand_verifier
from .decorator import NotRecorded, note, record, to_jsonable, wrap_tool, wrap_tools
from .experiments import ExperimentReport, VerificationFailed, compare
from .http import SignafaideError
from .replay import Replay, replay
from .runtime import Recorder
from .bitcoin import DEFAULT_URL as DEFAULT_TIMESTAMP_URL, lookup as lookup_timestamps
from .verifier import (
    DRAND_NOT_CHECKED, KeysRequired, Report, bitcoin_heights, is_loopback_url, load_agent_keys, load_content, load_heads, load_service_keys,
    loads as _loads, plain_http, verify_local, verify_pack,
)

__all__ = [
    "init",
    "record",
    "wrap_tools",
    "wrap_tool",
    "note",
    "flush",
    "verify",
    "status",
    "replay",
    "compare",
    "Replay",
    "ExperimentReport",
    "VerificationFailed",
    "Recorder",
    "Report",
    "SignafaideError",
    "NotRecorded",
    "KeysRequired",
    "to_jsonable",
    "__version__",
]


def not_yet(unsent: int, total: int, has_key: bool) -> list:
    """What the local verify could not check because the records have not reached a witness yet."""
    if not unsent:
        return []
    what = f"all {total}" if unsent == total else f"{unsent} of {total}"
    return [
        f"checked here: signatures, chain links and content hashes of {what} record{'' if total == 1 else 's'}, using this machine's keys",
        f"co-signature, public timestamp: not yet for {what} (`signafaide flush` sends them now, or says why it cannot)"
        if has_key
        else "co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)",
    ]


def init(
    *,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    home: Optional[str] = None,
    store_content: bool = False,
    quiet: bool = False,
) -> Recorder:
    """Configure signafAIde (optional). Finds SIGNAFAIDE_API_KEY (env or .env).
    Without one, records stay local (signed, chained, verifiable in ``.signafaide/``)
    and nothing is sent: it never creates a sandbox. A human opts in with
    ``signafaide init`` or by setting the key. Never raises when the service is
    offline: records are kept in the outbox."""
    rec = runtime.configure(url=url, api_key=api_key, home=home, store_content=store_content, quiet=quiet)
    rec.remember_agent()
    key = rec.api_key
    if not key:
        return rec
    try:
        rec.resolve_project(key)
    except SignafaideError as e:
        if e.code != "network":
            raise
        if not quiet:
            import sys

            print(f"signafaide: {e} Records are kept locally until then.", file=sys.stderr)
    return rec


def flush(timeout: float = 10.0) -> dict:
    """Ship the outbox now. Returns ``{shipped, left, errors}``."""
    return runtime.get().flush(timeout)


def status() -> dict:
    """Key, env, agents, last receipts and outbox size."""
    return runtime.get().status()


def verify(
    pack: Union[str, Path, dict, None] = None,
    *,
    keys: Any = None,
    trust_embedded_keys: bool = False,
    agent_keys: Any = None,
    trust_embedded_agent_keys: bool = False,
    head: Any = None,
    timestamp_check: str = DEFAULT_TIMESTAMP_URL,
    offline: bool = False,
    content: Union[str, Path, None] = None,
) -> Report:
    """Run the §7 verifier on a pack (path or dict) or, with no pack, on the
    local ``.signafaide`` state. ``print(report)`` shows one line per check and
    the result line; ``report.ok`` is the result.

    ``keys`` is a file, URL or dict of service keys. Without it the keys are
    fetched from the service (``SIGNAFAIDE_URL``), which is independent of the
    pack. ``agent_keys`` is the customer's manifest (``signafaide keys export``);
    for a pack it defaults to this project's own agent keys in ``.signafaide/agents``.
    ``head`` is a client's ``head.json``; for a pack it defaults to this project's own
    ``.signafaide/head.json``. Public timestamps are checked online against
    ``timestamp_check`` unless ``offline``. Keys over plain http are accepted only from this
    machine and never count as independent. Raises :class:`KeysRequired` when no service
    keys can be had, and OSError or ValueError when an input cannot be read.
    """
    rec = runtime.get()
    notes = []
    service_keys = None
    keys_plain = False
    if keys is not None:
        service_keys = load_service_keys(keys)
        keys_plain = plain_http(keys)
        notes.append(f"service keys: {keys if isinstance(keys, (str, Path)) else 'given'}")
    elif pack is None and not rec.state.chain_heads():
        service_keys = []  # nothing has been shipped, so nothing needs a service key: no request is made
    elif pack is None or not trust_embedded_keys:
        url = f"{rec.url}/.well-known/signafaide-keys.json"
        if url.startswith("http://") and not is_loopback_url(url):
            raise KeysRequired(f"will not fetch service keys over plain http from {url}: anyone on the network path can alter them; pass --keys <file|https url>")
        keys_plain = url.startswith("http://")
        try:
            service_keys = load_service_keys(rec.client().request("GET", "/.well-known/signafaide-keys.json", auth=False))
            notes.append(f"service keys: {url}" + (" (plain http on this machine: not independent)" if keys_plain else ""))
        except (SignafaideError, ValueError) as e:
            if pack is not None or rec.state.chain_heads():
                raise KeysRequired(f"could not load service keys from {url} ({e}); pass --keys <file|url>") from None
            service_keys = []  # nothing has been shipped, so nothing needs a service key
    drand = load_drand_verifier()
    if pack is None:
        report = verify_local(rec.state, service_keys, drand=drand, service_keys_plain_http=keys_plain)
        notes.insert(0, f"local state: {rec.state.home}")
        records = [r for c in rec.state.chains() for r in rec.state.read_all(c)]
        report.after += not_yet(sum(1 for r in records if "receipt" not in r), len(records), bool(rec.api_key))
    else:
        if isinstance(pack, (str, Path)):
            pack = _loads(Path(pack).read_text())
        if content is None and (rec.state.home / "chain").is_dir():
            content = rec.state.home / "chain"
        contents = load_content(content) if content is not None else None
        independent_agents = None
        if agent_keys is not None:
            independent_agents = load_agent_keys(agent_keys)
            notes.append(f"agent keys: {agent_keys if isinstance(agent_keys, (str, Path)) else 'given'}")
        elif not trust_embedded_agent_keys:
            local = [{"agent": k["agent"], "key_id": k["key_id"], "public_key": k["public_key"], "valid_from": k["created"], "valid_to": k["retired"]}
                     for k in rec.state.agent_public_keys() if k.get("created")]
            if local:
                independent_agents = local
                notes.append(f"agent keys: this project's own ({rec.state.home / 'agents'})")
        if head is not None:
            heads = load_heads(head)
        else:
            # This project's own newest signed heads: a pack cut off before them fails.
            heads = load_heads(rec.state.heads()) or None
            if heads:
                notes.append(f"head: this project's own ({rec.state.home / 'head.json'})")
        heights = bitcoin_heights(pack)
        stamps = None if offline or not heights else lookup_timestamps(timestamp_check, heights)
        report = verify_pack(pack, service_keys, trust_embedded_keys=trust_embedded_keys, agent_keys=independent_agents,
                             trust_embedded_agent_keys=trust_embedded_agent_keys, heads=heads, bitcoin=stamps, contents=contents, drand=drand,
                             service_keys_plain_http=keys_plain, agent_keys_plain_http=plain_http(agent_keys))
        if independent_agents is None and not trust_embedded_agent_keys:
            notes.append("no agent keys: ask the customer for `signafaide keys export -o agent-keys.json` and pass --agent-keys agent-keys.json")
    if drand is None and report.check("drand").checked:
        notes.append(DRAND_NOT_CHECKED)
    report.notes[:0] = notes
    return report
