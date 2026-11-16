"""The §7 verifier, in pure Python.

``verify_pack(pack, service_keys)`` checks a verification pack and
``verify_local(state, service_keys)`` the local ``.signafaide`` state. Both
return a :class:`Report` with the same check ids, statuses, text and JSON as
the reference verifier (``signafaide-verify``).

The drand BLS12-381 signature (check 9) is checked with ``py_ecc`` (a dependency, as
``@noble/curves`` is for the TypeScript SDK), so both SDKs count the same checks; if it cannot be
imported the check says ``DRAND_NOT_CHECKED``, never pass.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import ots
from ._plural import plural
from .coverage import coverage as tool_coverage, coverage_lines, telemetry as tool_telemetry, telemetry_lines
from .bitcoin import check_header
from .crypto import HEX64, b64url, b64url_decode, check_content, hash_json, key_id, sha256_hex, verify_inclusion, verify_sig
from .records import AGENT_RE, CLEAN_RESTART_NOTE, INSTANCE_NOTE, INSTANCE_START, INSTANCE_STOP, is_stop_note, MAX_CLOCK_SKEW_MS, draft_errors, key_entry_errors, manifest_errors, parse_time, receipt_errors, record_errors, valid_project_id

CHECKS = [
    ("schema", "Envelope schema"),
    ("record_hash", "Record hashes"),
    ("record_sig", "Client signatures"),
    ("chain", "Agent chains"),
    ("merkle", "Merkle proofs"),
    ("batch_sig", "Batch hashes and signatures"),
    ("batch_chain", "Batch chain"),
    ("head_sig", "Signed heads"),
    ("drand", "drand rounds"),
    ("anchor", "Anchors"),
    ("ots", "OpenTimestamps"),
    ("content", "Content hashes"),
]
UNITS = [("record",), ("record",), ("record",), ("record",), ("record",), ("batch", "batches"), ("batch", "batches"), ("head",), ("round",), ("anchor",), ("proof",), ("record",)]
QUICKNET_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
#: PENDING: ran, found nothing wrong, and waits for an anchor or public timestamp not confirmed yet (§7); never counted as passed.
PASS, FAIL, NOT_CHECKED, PENDING = "pass", "fail", "not_checked", "pending"
#: Why a pack without records fails (§7): an empty pack proves nothing.
NO_RECORDS = "no records: an empty pack proves nothing"
NO_LOCAL_RECORDS = "no records: nothing has been recorded here yet"
#: Check 3 without independent agent keys (§7).
NOT_INDEPENDENT = (
    "NOT INDEPENDENT: agent keys came from the pack; pass --agent-keys <file|url> (the customer's `signafaide keys export`), or --trust-embedded-agent-keys"
)
QUICKNET_GENESIS = 1692803367
MAX_ROUND_AGE_MS = 120_000
#: The highest drand round whose publication time is a protocol time (year 9999 at most).
MAX_ROUND = (253_402_300_799 - QUICKNET_GENESIS) // 3 + 1
#: A batch is anchored within this time of its server_time (§4); an older batch no anchor covers is "not timestamped".
ANCHOR_WINDOW_MS = 7_200_000
#: Where keys came from, when not from an independent source (§7 result line).
INDEPENDENT, FROM_PACK, PLAIN_HTTP = "independent", "taken from the pack", "fetched over plain http"
#: py_ecc is a dependency (about 23 MB with its own); if it cannot be imported, say so plainly.
DRAND_NOT_CHECKED = "drand: not checked (BLS library not installed; pip install py_ecc)"


class KeysRequired(ValueError):
    """No independent service keys and ``trust_embedded_keys`` not set."""


@dataclass
class Check:
    n: int
    id: str
    title: str
    status: str
    checked: int
    detail: str
    value: Optional[str] = None
    failures: List[dict] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.status == FAIL:
            return "FAIL"
        if self.status == NOT_CHECKED:
            return "NOT CHECKED"
        if self.status == PENDING:
            return "PENDING"
        return "CONFIRMED" if (self.value or "").startswith("confirmed@") else (self.value or "pass").upper()


def _key_reasons(service: str, agent: str) -> Optional[str]:
    a = None if service == INDEPENDENT else service
    b = None if agent == INDEPENDENT else agent
    if a and b:
        return f"service keys and agent keys {a}" if a == b else f"service keys {a} and agent keys {b}"
    if a:
        return f"service keys {a}"
    if b:
        return f"agent keys {b}"
    return None


def scope_text(filter: dict, generated: str) -> str:
    """What a pack covers (§7 result line): ``export of every agent, all records, generated <t>``."""
    agents = filter.get("agents")
    who = "every agent" if agents is None else f"agent {agents[0]}" if len(agents) == 1 else "agents " + ", ".join(agents)
    f, t = filter.get("from"), filter.get("to")
    window = "all records" if f is None and t is None else f"records from {f}" if t is None else f"records before {t}" if f is None else f"records from {f} before {t}"
    return f"export of {who}, {window}, generated {generated}"


#: The short name of each check in the result line (§7).
SHORT_NAMES = {
    "schema": "envelope schema", "record_hash": "record hashes", "record_sig": "client signatures", "chain": "agent chains",
    "merkle": "Merkle proofs", "batch_sig": "batch signatures", "batch_chain": "batch chain", "head_sig": "signed heads",
    "drand": "drand rounds", "anchor": "anchors", "ots": "public timestamp", "content": "content hashes",
}
#: The checks of the witness's part: locally, while nothing is co-signed, they are named together (§7).
WITNESS_CHECKS = ("record_hash", "merkle", "batch_sig", "batch_chain", "head_sig", "drand", "anchor", "ots")
NOTHING_COSIGNED = "nothing co-signed yet"
#: The one definition of "pending" (§7), printed under the checks whenever one is pending.
PENDING_MEANS = ("pending: co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms "
                 "within a few hours); never counted as passed")


def counts_text(checks: List[Tuple[str, str]], nothing_cosigned: bool = False) -> str:
    """How many checks passed, failed, are pending and were not checked (§7 result line)."""
    total = len(checks)
    failed = [SHORT_NAMES[i] for i, st in checks if st == FAIL]
    pending = [SHORT_NAMES[i] for i, st in checks if st == PENDING]
    unchecked_ids = [i for i, st in checks if st == NOT_CHECKED]
    passed = total - len(failed) - len(pending) - len(unchecked_ids)
    if failed:
        out = f"{len(failed)} of {total} checks failed ({', '.join(failed)})"
        if passed:
            out += f", {passed} passed"
        if pending:
            out += f", {len(pending)} pending"
        if unchecked_ids:
            out += f", {len(unchecked_ids)} not checked"
        return out
    out = f"{passed} of {total} checks passed"
    if pending:
        out += f", {len(pending)} pending ({', '.join(pending)})"
    if unchecked_ids:
        names = [SHORT_NAMES[i] for i in unchecked_ids]
        if nothing_cosigned and any(i in WITNESS_CHECKS for i in unchecked_ids):
            names = [NOTHING_COSIGNED] + [SHORT_NAMES[i] for i in unchecked_ids if i not in WITNESS_CHECKS]
        out += f", {len(unchecked_ids)} not checked ({', '.join(names)})"
    return out


def result_line(result: str, service: str = INDEPENDENT, agent: str = INDEPENDENT, by_service: bool = False, scope: Optional[str] = None,
                counts: str = "") -> str:
    """`PASS` or `FAIL`; on PASS, why keys were not independent; then how many checks ran and
    what the pack covers (§7)."""
    out = result
    if result == "PASS":
        if by_service:
            out += " (checked by the service with its own key registry; not independent)"
        else:
            r = _key_reasons(service, agent)
            if r:
                out += f" ({r}, not independent)"
    if counts:
        out += f": {counts}"
    if scope:
        out += f"; {scope}" if counts else f": {scope}"
    return out


@dataclass
class Report:
    checks: List[Check]
    project: Optional[str] = None
    env: Optional[str] = None
    records: int = 0
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    independent: Dict[str, bool] = field(default_factory=lambda: {"service_keys": True, "agent_keys": True})
    generated: Optional[str] = None
    filter: Optional[dict] = None
    sources: Tuple[str, str] = (INDEPENDENT, INDEPENDENT)
    by_service: bool = False
    #: Lines shown after the checks, before the result line: for local state, what still needs
    #: the witness (co-signature, public timestamp).
    after: List[str] = field(default_factory=list)
    #: Local state with no record co-signed yet: the result line says so (§7).
    nothing_cosigned: bool = False
    #: The project's name from the signed export statement, when the pack has one.
    project_name: Optional[str] = None
    #: Local state: chains that cannot ship (refused by the witness, or wedged here), as
    #: ``<chain>: <reason>``. Any makes the result BLOCKED, which always fails (§7).
    blocked: List[str] = field(default_factory=list)
    #: Local state with --fail-on-pending-send: records not co-signed yet, which then fail.
    not_sent: int = 0
    #: Tool coverage per agent (§7; per chain for local state): the agent's current tool
    #: declaration and the recorded tools it does not list. A note, never a failure.
    coverage: Dict[str, dict] = field(default_factory=dict)
    #: Telemetry notes per agent (§7; per chain for local state), for agents that have any: the
    #: tools recorded from telemetry spans, when their decisions were written, and whether the
    #: telemetry is sampled. A note, never a failure.
    telemetry: Dict[str, dict] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.blocked and not self.not_sent and all(c.status != FAIL for c in self.checks)

    @property
    def result(self) -> str:
        if any(c.status == FAIL for c in self.checks) or (self.not_sent and not self.blocked):
            return "FAIL"
        return "BLOCKED" if self.blocked else "PASS"

    def check(self, id: str) -> Check:
        return next(c for c in self.checks if c.id == id)

    def first_failed(self) -> Optional[str]:
        return next((c.id for c in self.checks if c.status == FAIL), None)

    def coverage_lines(self) -> List[str]:
        """Tool coverage in words (§7), agent by agent: what each agent declared, then the
        recorded tools its declaration does not list."""
        return [line for agent, c in self.coverage.items() for line in coverage_lines(agent, c)]

    def telemetry_lines(self) -> List[str]:
        """The telemetry notes in words (§7), agent by agent."""
        return [line for agent, t in self.telemetry.items() for line in telemetry_lines(agent, t)]

    def lines(self) -> List[str]:
        out = list(self.notes)
        if self.project and self.env:
            if self.project_name:
                out.append(f"signafAIde pack of project {self.project_name} ({self.project}, {self.env}), {plural(self.records, 'record')}")
            else:
                out.append(f"signafAIde pack {self.project} ({self.env}), {plural(self.records, 'record')}")
        out += [f"WARNING: {w}" for w in self.warnings]
        for c in self.checks:
            out.append(f"{c.n:>2}. {c.title:<28} {c.label:<12} {c.detail}")
            out += [f"      - {f['item']}: {f['message']}" for f in c.failures[:20]]
            if len(c.failures) > 20:
                out.append(f"      ... and {len(c.failures) - 20} more")
        if any(c.status == PENDING for c in self.checks):
            out.append(PENDING_MEANS)
        out += [f"coverage: {line}" for line in self.coverage_lines()]
        out += [f"telemetry: {line}" for line in self.telemetry_lines()]
        out += self.after
        out += [f"BLOCKED {b}" for b in self.blocked]
        out.append(self.result_line)
        return out

    @property
    def result_line(self) -> str:
        scope = scope_text(self.filter, self.generated) if self.filter is not None and self.generated else None
        counts = counts_text([(c.id, c.status) for c in self.checks], self.nothing_cosigned)
        if self.blocked:
            counts = f"{plural(len(self.blocked), 'chain')} cannot ship ({', '.join(b.split(':')[0] for b in self.blocked)}); {counts}"
        elif self.not_sent:
            counts = f"{plural(self.not_sent, 'record')} not sent yet (--fail-on-pending-send); {counts}"
        return result_line(self.result, self.sources[0], self.sources[1], self.by_service, scope, counts)

    def __str__(self) -> str:
        return "\n".join(self.lines())

    def to_dict(self) -> dict:
        checks = []
        for c in self.checks:
            d = {"n": c.n, "id": c.id, "title": c.title, "status": c.status, "checked": c.checked, "detail": c.detail, "failures": c.failures}
            if c.value is not None:
                d["value"] = c.value
            checks.append(d)
        return {
            "result": self.result, "result_line": self.result_line, "project": self.project,
            **({"project_name": self.project_name} if self.project_name else {}), "env": self.env, "records": self.records,
            "generated": self.generated, "filter": self.filter, "warnings": self.warnings, "independent": self.independent, "notes": self.notes,
            "checks": checks,
            "coverage": self.coverage,
            "telemetry": self.telemetry,
            **({"not_yet": self.after} if self.after else {}),
            **({"blocked": self.blocked} if self.blocked else {}),
        }


# --- inputs ---------------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def loads(text: str) -> Any:
    """JSON as every verifier reads it: NaN and Infinity are not JSON."""
    return json.loads(text, parse_constant=_reject_constant)


def is_loopback_url(url: str) -> bool:
    """True for ``http://localhost`` and loopback addresses: the only hosts plain http is accepted from."""
    import ipaddress

    if not url.startswith("http://"):
        return False
    authority = re.split(r"[/?#]", url[len("http://"):], maxsplit=1)[0]
    if "@" in authority:
        return False
    if authority.startswith("["):
        host = authority[1:].split("]", 1)[0]
    else:
        host = authority.rsplit(":", 1)[0] if ":" in authority else authority
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def plain_http(src: Any) -> bool:
    """``src`` is an http:// URL (accepted only from this machine, and never independent)."""
    return isinstance(src, (str, Path)) and str(src).startswith("http://")


def _read(src: Any, flag: str) -> Any:
    if isinstance(src, (str, Path)) and str(src).startswith(("http://", "https://")):
        if str(src).startswith("http://"):
            if not is_loopback_url(str(src)):
                raise ValueError(f"{flag} {src} uses plain http://, which anyone on the network path can alter; use https:// "
                                 "(plain http is accepted only from this machine, e.g. http://127.0.0.1)")
            import sys

            print(f"WARNING: {flag} {src} uses plain http:// on this machine; the keys do not count as independent", file=sys.stderr)
        from .http import fetch_json

        return fetch_json(str(src))
    if isinstance(src, (str, Path)):
        return loads(Path(src).read_text())
    return src


def load_service_keys(src: Any) -> List[dict]:
    """Service keys from a dict/list, a file path or an http(s) URL."""
    src = _read(src, "--keys")
    keys = src.get("keys") if isinstance(src, dict) else src
    if not isinstance(keys, list):
        raise ValueError('service keys must be {"keys": [...]} as served at /.well-known/signafaide-keys.json')
    for k in keys:
        errs = key_entry_errors(k)
        if errs:
            raise ValueError("keys: " + "; ".join(errs))
    return keys


def load_agent_keys(src: Any) -> List[dict]:
    """The customer's agent-key manifest (§2.5) from a dict, a file path or an http(s) URL;
    every entry's self-signature is checked."""
    doc = _read(src, "--agent-keys")
    errs = manifest_errors(doc)
    if errs:
        raise ValueError("agent keys: " + "; ".join(errs))
    return doc["keys"]


def load_heads(src: Any) -> List[dict]:
    """The client's head file (§8 ``head.json``) as a list of ``{head, head_sig}``."""
    doc = _read(src, "--head")
    out = []
    if not isinstance(doc, dict):
        raise ValueError("head file: the file must be an object")
    for envs in doc.values():
        if not isinstance(envs, dict):
            raise ValueError("head file: each project must be an object")
        for agents in envs.values():
            if not isinstance(agents, dict):
                raise ValueError("head file: each env must be an object")
            for sh in agents.values():
                if _signed_head_errors(sh):
                    raise ValueError("head file: " + _signed_head_errors(sh))
                out.append(sh)
    return out


def load_content(src: Any) -> Dict[str, dict]:
    """record_hash -> ``{content, salt}`` from JSON lines or a JSON array of ``{envelope, content,
    salt}`` objects (a chain .jsonl file), or from every ``*.jsonl`` below a directory (§7)."""
    p = Path(src)
    files = sorted(p.rglob("*.jsonl")) if p.is_dir() else [p]
    out: Dict[str, dict] = {}
    for f in files:
        text = f.read_text()
        try:
            doc = loads(text)
            items = doc if isinstance(doc, list) else [doc]
        except ValueError:
            items = [loads(line) for line in text.splitlines() if line.strip()]
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("envelope"), dict) and isinstance(item.get("content"), dict) and "draft" not in item:
                salt = item.get("salt") if isinstance(item.get("salt"), str) else None
                out[hash_json(item["envelope"])] = {"content": item["content"], "salt": salt}
    return out


def bitcoin_heights(pack: Any) -> List[int]:  # noqa: D401
    """The Bitcoin block heights the pack's OTS proofs claim, for :mod:`signafaide.bitcoin`."""
    out = set()
    for a in (pack.get("anchors") if isinstance(pack, dict) and isinstance(pack.get("anchors"), list) else []):
        try:
            out.update(h for h, _ in ots.bitcoin_attestations(base64.b64decode(a["anchor"]["ots"], validate=True)))
        except (KeyError, TypeError, ValueError, binascii.Error):
            continue
    return sorted(out)


# --- entry points ---------------------------------------------------------------


def verify_pack(
    pack: Any,
    service_keys: Optional[List[dict]] = None,
    *,
    trust_embedded_keys: bool = False,
    agent_keys: Optional[List[dict]] = None,
    trust_embedded_agent_keys: bool = False,
    heads: Optional[List[dict]] = None,
    bitcoin: Optional[Dict[int, Tuple[bool, Any]]] = None,
    contents: Optional[Dict[str, dict]] = None,
    drand: Optional[Callable[[dict], bool]] = None,
    service_keys_plain_http: bool = False,
    agent_keys_plain_http: bool = False,
    by_service: bool = False,
) -> Report:
    """Verify a pack (dict or path). Raises :class:`KeysRequired` when no service
    keys are given and ``trust_embedded_keys`` is False. ``agent_keys`` is the customer's
    manifest (:func:`load_agent_keys`); ``heads`` the client's head file (:func:`load_heads`);
    ``bitcoin`` height -> (True, {hash, header}) or (False, why not) from
    :func:`signafaide.bitcoin.lookup`, or None for offline. ``*_plain_http``: those keys came over
    plain http from this machine (not independent). ``by_service``: the service checks its own
    pack with its own key registry (never independent)."""
    if isinstance(pack, (str, Path)):
        pack = loads(Path(pack).read_text())
    service_src = FROM_PACK if service_keys is None else PLAIN_HTTP if service_keys_plain_http else INDEPENDENT
    agent_src = FROM_PACK if agent_keys is None else PLAIN_HTTP if agent_keys_plain_http else INDEPENDENT
    if by_service:
        service_src = agent_src = FROM_PACK
    independent = {"service_keys": service_src == INDEPENDENT, "agent_keys": agent_src == INDEPENDENT}
    why = _pack_errors(pack)
    if why:
        return _malformed(why, independent)
    warnings = []
    if service_keys is None:
        if not trust_embedded_keys or by_service:
            raise KeysRequired("service keys are required: pass --keys <file|url>, or --trust-embedded-keys to use the keys inside the pack")
        warnings.append("service keys were taken from the pack itself (--trust-embedded-keys); this does not prove the service signed it")
        service_keys = pack["service_keys"]
    for src, what in ((service_src, "service"), (agent_src, "agent")):
        if src == PLAIN_HTTP:
            warnings.append(f"{what} keys were fetched over plain http, which anyone on the network path can alter: not independent")
    not_independent = False
    if agent_keys is not None and not by_service:
        keys = []
        for e in agent_keys:
            # A retirement or revocation can only narrow the window: the earlier of the customer's
            # signed retirement (§2.5) and the service's record (§7) wins.
            held = next((k for k in pack["agent_keys"] if (k["agent"], k["key_id"], k["public_key"]) == (e["agent"], e["key_id"], e["public_key"])), None)
            keys.append({"agent": e["agent"], "key_id": e["key_id"], "public_key": e["public_key"], "valid_from": e["valid_from"],
                         "valid_to": _earliest(e.get("valid_to"), held["valid_to"] if held else None)})
    else:
        if by_service:
            pass
        elif trust_embedded_agent_keys:
            warnings.append("agent keys were taken from the pack itself (--trust-embedded-agent-keys); this does not prove the customer's agents signed it")
        else:
            not_independent = True
        keys = pack["agent_keys"]
    v = _Verifier(service_keys, keys, contents or {}, project=pack["project"], env=pack["env"], local=False, drand=drand,
                  filter=pack["filter"], export_heads=pack["heads"], client_heads=heads, bitcoin=bitcoin, not_independent=not_independent,
                  generated=pack["generated"], export_sig=pack["export_sig"])
    v.project_name = pack.get("project_name")
    checks = v.run(pack["records"], pack["anchors"])
    return Report(checks, pack["project"], pack["env"], len(pack["records"]), warnings, independent=independent, generated=pack["generated"],
                  filter=pack["filter"], sources=(service_src, agent_src), by_service=by_service,
                  project_name=pack.get("project_name") if isinstance(pack.get("project_name"), str) else None, coverage=v.coverage, telemetry=v.telemetry)


def _earliest(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None or b is None:
        return a if b is None else b
    return b if _epoch_ms(b) < _epoch_ms(a) else a


def records_hash(records: list) -> str:
    """``records_hash`` (§7): sha256(JCS(list)) of every record's ``receipt.record_hash``, in pack order."""
    out = []
    for r in records:
        h = r.get("receipt", {}).get("record_hash") if isinstance(r, dict) and isinstance(r.get("receipt"), dict) else None
        if not isinstance(h, str):
            raise ValueError("a record has no receipt.record_hash")
        out.append(h)
    return hash_json(out)


def export_statement(pack: dict) -> dict:
    """The export statement the service signs (§7, domain ``export``)."""
    return {"project": pack["project"], **({"project_name": pack["project_name"]} if "project_name" in pack else {}),
            "env": pack["env"], "generated": pack["generated"], "filter": pack["filter"],
            "heads": [sh["head"] for sh in pack["heads"]], "records_hash": records_hash(pack["records"])}


def verify_local(
    state: Any, service_keys: Optional[List[dict]], *, drand: Optional[Callable[[dict], bool]] = None, chains: Optional[List[str]] = None,
    service_keys_plain_http: bool = False,
) -> Report:
    """Verify everything in a ``.signafaide`` folder (a :class:`~signafaide.state.State`),
    chain by chain (``<project>/<env>/<agent>``), or only ``chains``. Unshipped records are
    fine; a chain must be complete from seq 1 and reach the newest signed head in ``head.json``.
    Drafts (records written before the project was known, §8) are signed locally too and are
    verified like every other record."""
    records: List[dict] = []
    chain_ids: List[str] = []
    for chain in state.chains() if chains is None else chains:
        for rec in state.read_all(chain):
            records.append(rec)
            chain_ids.append(chain)
    agent_keys = [{"agent": k["agent"], "key_id": k["key_id"], "public_key": k["public_key"], "valid_from": None, "valid_to": k.get("retired")}
                  for k in state.agent_public_keys()]
    heads = {c: h for c, h in state.chain_heads().items() if chains is None or c in chains}
    bases = {c: b for c in set(chain_ids) for b in [state.chain_base(c)] if b is not None} if hasattr(state, "chain_base") else {}
    v = _Verifier(service_keys, agent_keys, {}, project=None, env=None, local=True, local_heads=heads, drand=drand, local_bases=bases)
    checks = v.run(records, [], chain_ids)
    return Report(checks, records=len(records), independent={"service_keys": not service_keys_plain_http, "agent_keys": True},
                  sources=(PLAIN_HTTP if service_keys_plain_http else INDEPENDENT, INDEPENDENT), nothing_cosigned=v.nothing_cosigned,
                  coverage=v.coverage, telemetry=v.telemetry)


def _signed_head_errors(sh: Any) -> str:
    if not isinstance(sh, dict) or set(sh) != {"head", "head_sig"} or not isinstance(sh["head_sig"], str):
        return "a signed head is {head, head_sig}"
    h = sh["head"]
    if not isinstance(h, dict) or set(h) != {"project", "env", "agent", "seq", "record_hash", "server_time"}:
        return "head fields are agent, env, project, record_hash, seq, server_time"
    if not (isinstance(h["project"], str) and h["env"] in ("test", "live") and isinstance(h["agent"], str) and AGENT_RE.match(h["agent"])
            and _is_u64(h["seq"]) and isinstance(h["record_hash"], str) and HEX64.match(h["record_hash"]) and _ms(h["server_time"]) is not None):
        return "a head has an invalid value"
    return ""


def _is_u64(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 2**64


def _pack_errors(pack: Any) -> Optional[str]:
    if not isinstance(pack, dict):
        return "the pack is not a JSON object"
    if pack.get("format") != "signafaide-pack/1":
        return f"format is '{pack.get('format')}', expected 'signafaide-pack/1'"
    fields = ("format", "generated", "project", "env", "service_keys", "agent_keys", "filter", "heads", "records", "anchors", "export_sig")
    for k in fields:
        if k not in pack:
            return f"missing field `{k}`"
    extra = sorted(set(pack) - set(fields) - {"project_name"})
    if extra:
        return f"unknown field `{extra[0]}`"
    if "project_name" in pack:
        n = pack["project_name"]
        if not isinstance(n, str) or not n or len(n) > 200 or any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in n):
            return "project_name must be 1 to 200 characters, without control characters"
    for k in ("service_keys", "agent_keys", "heads", "records", "anchors"):
        if not isinstance(pack[k], list):
            return f"`{k}` must be a list"
    if not isinstance(pack["export_sig"], str):
        return "`export_sig` must be a string"
    if pack["env"] not in ("test", "live"):
        return "env must be test or live"
    if not valid_project_id(pack["project"]):
        return "project is not a valid project id"
    if _ms(pack["generated"]) is None:
        return "generated is not a time"
    for k in pack["service_keys"]:
        errs = key_entry_errors(k)
        if errs:
            return errs[0]
    for k in pack["agent_keys"]:
        errs = key_entry_errors(k, agent=True)
        if errs:
            return errs[0]
    f = pack["filter"]
    if not isinstance(f, dict) or set(f) != {"agents", "from", "to"}:
        return "filter is {agents, from, to}"
    for name in ("from", "to"):
        if f[name] is not None and _ms(f[name]) is None:
            return f"filter.{name} is not a time"
    if f["agents"] is not None and not (isinstance(f["agents"], list) and all(isinstance(a, str) and AGENT_RE.match(a) for a in f["agents"])):
        return "filter.agents holds an invalid agent name"
    for sh in pack["heads"]:
        if _signed_head_errors(sh):
            return "heads holds an invalid head"
    return None


def _malformed(why: str, independent: Dict[str, bool]) -> Report:
    checks = [
        Check(i + 1, cid, title, FAIL if i == 0 else NOT_CHECKED, 0, "the pack itself is malformed" if i == 0 else "pack unreadable", failures=[{"item": "pack", "message": why}] if i == 0 else [])
        for i, (cid, title) in enumerate(CHECKS)
    ]
    return Report(checks, independent=independent)


# --- the checks -----------------------------------------------------------------


def _ms(s: Any) -> Optional[datetime]:
    try:
        return parse_time(s)
    except ValueError:
        return None


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _epoch_ms(s: Any) -> Optional[int]:
    t = _ms(s)
    return None if t is None else (t - _EPOCH) // timedelta(milliseconds=1)


def _fmt(ms: int) -> str:
    t = _EPOCH + timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _active(key: dict, at: Optional[datetime]) -> bool:
    """valid_from <= at < valid_to; a null bound is open."""
    start, end = key.get("valid_from"), key.get("valid_to")
    s, e = _ms(start), _ms(end)
    if at is None or (start is not None and s is None) or (end is not None and e is None):
        return False
    return (s is None or s <= at) and (e is None or at < e)


def service_keys_hash(keys: List[dict], created_ms: int) -> str:
    """``keys_hash`` (§4): the service keys with ``valid_from <= created``, as
    ``{key_id, public_key, valid_from}``, ordered by ``valid_from`` then ``key_id``."""
    lst = [
        {"key_id": k["key_id"], "public_key": k["public_key"], "valid_from": k["valid_from"]}
        for k in keys
        if _epoch_ms(k.get("valid_from")) is not None and _epoch_ms(k["valid_from"]) <= created_ms
    ]
    return hash_json(sorted(lst, key=lambda k: (k["valid_from"], k["key_id"])))


def check_round_time(server_ms: int, rnd: int) -> Optional[str]:
    """§3.1: why ``server_ms`` does not fit drand round ``rnd``, or None."""
    if not 1 <= rnd <= MAX_ROUND:
        return f"drand round {rnd} is out of range (1 to {MAX_ROUND})"
    published = (QUICKNET_GENESIS + (rnd - 1) * 3) * 1000
    if server_ms < published:
        return f"server_time {_fmt(server_ms)} is before drand round {rnd} was published at {_fmt(published)}"
    if server_ms - published > MAX_ROUND_AGE_MS:
        return f"drand round {rnd} is {(server_ms - published) // 1000} s older than server_time; at most {MAX_ROUND_AGE_MS // 1000} s is allowed"
    return None


class _Acc:
    def __init__(self) -> None:
        self.checked = 0
        self.failures: List[dict] = []
        self.notes: List[str] = []
        self.not_checked = False
        self.pending = False
        self.value: Optional[str] = None

    def fail(self, item: str, message: str) -> None:
        self.failures.append({"item": item, "message": message})


class _Verifier:
    project_name: Optional[str] = None

    def __init__(self, service_keys, agent_keys, contents, *, project, env, local, local_heads=None, drand=None,
                 filter=None, export_heads=None, client_heads=None, bitcoin=None, not_independent=False, generated=None, export_sig=None,
                 local_bases=None):
        self.service_keys = service_keys
        self.agent_keys = agent_keys
        self.contents = contents
        self.project, self.env, self.local = project, env, local
        self.local_heads = local_heads or {}
        # Local state: chain id -> the witness's signed head a chain continues after (§8, a
        # chain this machine started on an empty disk).
        self.local_bases = local_bases or {}
        self.drand_verifier = drand
        self.filter = filter or {"agents": None, "from": None, "to": None}
        self.export_heads = export_heads or []
        self.client_heads = client_heads
        self.bitcoin = bitcoin
        self.not_independent = not_independent
        self.generated, self.export_sig = generated, export_sig
        self.generated_ms = _epoch_ms(generated) if generated else None
        self.from_ms = _epoch_ms(self.filter["from"]) if self.filter["from"] is not None else None
        self.to_ms = _epoch_ms(self.filter["to"]) if self.filter["to"] is not None else None
        # The earliest any key of each agent was valid: no record of that agent is older.
        self.first_key: Dict[str, int] = {}
        for k in agent_keys or []:
            f = _epoch_ms(k.get("valid_from"))
            if f is not None and isinstance(k.get("agent"), str):
                self.first_key[k["agent"]] = min(self.first_key.get(k["agent"], f), f)
        self.nothing_cosigned = False
        self.coverage: Dict[str, dict] = {}  # tool coverage per chain (§7), filled by run
        self.telemetry: Dict[str, dict] = {}  # telemetry notes per chain (§7), filled by run
        self.drafts = 0  # local drafts waiting for the project (§8): not a reason for "no records"
        self.chain_of: Dict[int, str] = {}  # id(record) -> chain id (local state)
        self.acc = [_Acc() for _ in CHECKS]

    def service_key(self, key_id: Any, at: Any) -> dict:
        k = next((k for k in self.service_keys or [] if k.get("key_id") == key_id), None)
        if k is None:
            raise ValueError(f"unknown service key {key_id}")
        if not _active(k, _ms(at)):
            raise ValueError(f"service key {key_id} was not active at {at}")
        return k

    def from_cuts(self, agent: str) -> bool:
        """A chain may start after seq 1 only when the export's from is after the agent's first key."""
        return self.from_ms is not None and agent in self.first_key and self.from_ms > self.first_key[agent]

    def to_may_cut(self, h: dict) -> bool:
        """A head's record may be cut off by to only when it could be at or after to (its time is at
        most 300 s after the head's server_time)."""
        s = _epoch_ms(h.get("server_time"))
        return self.to_ms is not None and (s is None or s + MAX_CLOCK_SKEW_MS >= self.to_ms)

    def any_key(self, domain: str, h: str, sig: Any, at: Any) -> bool:
        t = _ms(at)
        return any(_active(k, t) and verify_sig(k.get("public_key", ""), domain, h, sig) for k in self.service_keys or [])

    def run(self, raw_records: list, anchors: list, chain_ids: Optional[List[str]] = None) -> List[Check]:
        a = self.acc
        if self.not_independent:
            a[2].fail("agent keys", NOT_INDEPENDENT)
        if not raw_records and not self.drafts:
            a[0].fail("local state" if self.local else "pack", NO_LOCAL_RECORDS if self.local else NO_RECORDS)
        if chain_ids:
            self.chain_of = {id(r): c for r, c in zip(raw_records, chain_ids)}
        recs = self.schema(raw_records)
        self.recs, self.raw_records = recs, raw_records
        shipped = [x for x in recs if "receipt" in x[1]]

        # 2. record_hash
        for label, r, h in shipped:
            a[1].checked += 1
            if h != r["receipt"]["record_hash"]:
                a[1].fail(label, f"envelope hashes to {h}, receipt says {r['receipt']['record_hash']}")
        if len(shipped) < len(recs):
            a[1].notes.append(f"{len(recs) - len(shipped)} not yet shipped (no receipt)")

        # 3. client signatures
        for label, r, h in recs:
            a[2].checked += 1
            err = self.client_sig(r, h)
            if err:
                a[2].fail(label, err)

        chains = self.chains(recs)
        self.merkle(shipped)
        batches = self.batch_sigs(shipped)
        self.batch_chain(batches)
        self.heads(shipped, chains)
        self.drand(batches)
        self.anchors(anchors, batches)
        self.content(recs)
        if self.local and not shipped and recs:
            self.nothing_cosigned = True
            # Local records no witness has co-signed yet: the checks of the witness's part are not passes.
            for i in (1, 4, 5, 6, 7):
                if a[i].checked or a[i].failures:
                    continue
                a[i].not_checked = True
                a[i].notes.append("nothing co-signed yet")

        checks = []
        for i, acc in enumerate(a):
            status = FAIL if acc.failures else NOT_CHECKED if acc.not_checked else PENDING if acc.pending else PASS
            detail = plural(acc.checked, *UNITS[i]) + "".join(f"; {n}" for n in acc.notes)
            checks.append(Check(i + 1, CHECKS[i][0], CHECKS[i][1], status, acc.checked, detail, acc.value, acc.failures))
        return checks

    # 1
    def schema(self, raw: list) -> List[Tuple[str, dict, str]]:
        recs = []
        for i, r in enumerate(raw):
            self.acc[0].checked += 1
            # A local draft (§8): no project or env yet, signed over domain `draft`.
            draft = self.local and isinstance(r, dict) and r.get("draft") is True
            errs = draft_errors(r) if draft else record_errors(r)
            if draft:
                if not errs and not self.chain_id(r).startswith("_pending/"):
                    errs = [f"a draft belongs in a pending chain, not {self.chain_id(r)}"]
            elif not errs and "receipt" in r:
                errs = receipt_errors(r["receipt"]) or self.consistent(r)
            elif not errs and not self.local:
                errs = ["missing receipt"]
            elif not errs:
                errs = self.envelope_bucket(r)
            if errs:
                self.acc[0].fail(f"record[{i}]", "; ".join(errs))
                continue
            env = r["envelope"]
            recs.append((f"{self.chain_id(r)}#{env['seq']}", r, hash_json(env)))
        return recs

    def chain_id(self, r: dict) -> str:
        """The chain a record belongs to: its agent in a pack, ``<project>/<env>/<agent>`` locally."""
        return self.chain_of.get(id(r), r["envelope"]["agent"])

    def head_chain(self, head: dict) -> str:
        return f"{head.get('project')}/{head.get('env')}/{head.get('agent')}" if self.local else str(head.get("agent"))

    def envelope_bucket(self, r: dict) -> List[str]:
        """Locally, a record's envelope names the project and env of its chain."""
        e = r["envelope"]
        bucket = self.chain_id(r).rsplit("/", 1)[0]
        if self.local and not bucket.startswith("_pending/") and bucket != f"{e['project']}/{e['env']}":
            return [f"envelope is for {e['project']}/{e['env']}, but the record is in chain {self.chain_id(r)}"]
        return []

    def consistent(self, r: dict) -> List[str]:
        e, b, h = r["envelope"], r["receipt"]["batch"], r["receipt"]["head"]
        if not self.local and (e["project"], e["env"]) != (self.project, self.env):
            return ["envelope belongs to another project or env"]
        if not self.local and (b["project"], b["env"]) != (self.project, self.env):
            return ["receipt batch belongs to another project or env"]
        if self.local and (e["project"], e["env"]) != (b["project"], b["env"]):
            return ["envelope and receipt batch name different projects or envs"]
        errs = self.envelope_bucket(r)
        if errs:
            return errs
        if (h["project"], h["env"]) != (b["project"], b["env"]) or h["agent"] != e["agent"]:
            return ["receipt head belongs to another project, env or agent"]
        return []

    def client_sig(self, r: dict, h: str) -> Optional[str]:
        env = r["envelope"]
        k = next((k for k in self.agent_keys if k.get("agent") == env["agent"] and k.get("key_id") == r["key_id"]), None)
        if k is None:
            return f"no key {r['key_id']} for agent {env['agent']} in the agent keys"
        try:
            if key_id(b64url_decode(k["public_key"])) != k["key_id"]:
                return "agent key_id does not match its public key"
        except (ValueError, KeyError, TypeError):
            return "agent public key is not base64url"
        if not _active(k, _ms(env["time"])):
            return f"key {k['key_id']} was not active at {env['time']}"
        if k.get("valid_to") is not None and "receipt" in r:
            server = r["receipt"]["batch"]["server_time"]
            if _ms(server) >= _ms(k["valid_to"]):
                return f"key {k['key_id']} was revoked at {k['valid_to']}, before the service received this record at {server}"
        if not verify_sig(k["public_key"], "draft" if self.local and r.get("draft") is True else "record", h, r["sig"]):
            return "signature does not verify"
        return None

    # 4
    def chains(self, recs: list) -> Dict[str, Dict[int, Tuple[str, dict, str]]]:
        acc = self.acc[3]
        chains: Dict[str, Dict[int, Tuple[str, dict, str]]] = {}
        for x in recs:
            chain = chains.setdefault(self.chain_id(x[1]), {})
            seq = x[1]["envelope"]["seq"]
            if seq in chain and chain[seq][2] != x[2]:
                acc.fail(x[0], "two different records with the same seq (fork)")
                continue
            chain.setdefault(seq, x)
        edge = 0
        based: List[str] = []
        starts: List[str] = []
        clean: List[str] = []
        for agent, chain in sorted(chains.items()):
            acc.checked += len(chain)
            prev = None
            for seq in sorted(chain):
                label, r, _ = chain[seq]
                e = r["envelope"]
                if prev is not None and prev[1]["envelope"]["seq"] + 1 == seq:
                    if e["prev"] != prev[2]:
                        acc.fail(label, f"prev does not equal the record_hash of seq {seq - 1}")
                    if _ms(e["time"]) < _ms(prev[1]["envelope"]["time"]):
                        acc.fail(label, f"time {e['time']} is earlier than the time of seq {seq - 1} ({prev[1]['envelope']['time']})")
                elif prev is not None:
                    if self.local:
                        acc.fail(label, f"the local chain is missing seq {prev[1]['envelope']['seq'] + 1}..{seq - 1}")
                    else:
                        acc.fail(label, f"the pack is missing seq {prev[1]['envelope']['seq'] + 1}..{seq - 1} of agent {agent} (a gap inside the chain)")
                elif seq > 1:
                    base = ((self.local_bases.get(agent) or {}).get("head") or {}) if self.local else {}
                    if self.local and base.get("seq") == seq - 1 and base.get("record_hash") == e["prev"]:
                        based.append(f"{agent} after seq {seq - 1}")
                    elif self.local:
                        acc.fail(label, f"the local chain is missing seq 1..{seq - 1}")
                    elif self.from_cuts(agent):
                        edge += 1
                    elif self.filter["from"] is not None:
                        acc.fail(label, f"the pack is missing seq 1..{seq - 1} of agent {agent}; its export's from filter is not after the agent's first key, so they belong in it")
                    else:
                        acc.fail(label, f"the pack is missing seq 1..{seq - 1} of agent {agent} and its export declares no from filter")
                if e["kind"] == "note" and e["name"] == INSTANCE_START:
                    # Clean only when the record right before it is a stop note: in the pack, or
                    # (local state) kept with the witness's head this chain continues after.
                    if prev is not None and prev[1]["envelope"]["seq"] + 1 == seq:
                        pe = prev[1]["envelope"]
                        after_stop = pe["kind"] == "note" and pe["name"] == INSTANCE_STOP
                    else:
                        b = (self.local_bases.get(agent) or {}) if self.local and prev is None else {}
                        bh = b.get("head") or {}
                        after_stop = bool(b.get("stop")) and bh.get("seq") == seq - 1 and e["prev"] == bh.get("record_hash") and is_stop_note(b["stop"], e["agent"], bh.get("record_hash"))
                    (clean if after_stop else starts).append(f"{agent} after seq {seq - 1}")
                if "receipt" in r:
                    server = r["receipt"]["batch"]["server_time"]
                    if _epoch_ms(e["time"]) > _epoch_ms(server) + MAX_CLOCK_SKEW_MS:
                        acc.fail(label, f"time {e['time']} is more than 300 s after its batch's server_time {server}")
                prev = chain[seq]
        if edge:
            acc.notes.append(f"{plural(edge, 'chain')} start after seq 1, as the export's from filter allows")
        if starts:
            acc.notes.append(f"{INSTANCE_NOTE}: {', '.join(starts)}")
        if clean:
            acc.notes.append(f"{CLEAN_RESTART_NOTE}: {', '.join(clean)}")
        if based:
            acc.notes.append(f"continues after a co-signed record this machine does not hold: {', '.join(based)} (the witness's signed head, see signed heads)")
        # Tool coverage (§7): a note per agent, read from the envelopes of its chain in seq order.
        self.coverage = {
            agent: tool_coverage((seq, chain[seq][1]["envelope"]["kind"], chain[seq][1]["envelope"]["name"]) for seq in sorted(chain))
            for agent, chain in sorted(chains.items())
        }
        self.telemetry = {
            agent: t for agent, chain in sorted(chains.items())
            for t in [tool_telemetry((seq, chain[seq][1]["envelope"]["kind"], chain[seq][1]["envelope"]["name"]) for seq in sorted(chain))] if t is not None
        }
        return chains

    # 5
    def merkle(self, shipped: list) -> None:
        for label, r, h in shipped:
            self.acc[4].checked += 1
            rc = r["receipt"]
            if not verify_inclusion(h, rc["index"], rc["batch"]["size"], rc["proof"], rc["batch"]["root"]):
                self.acc[4].fail(label, f"proof does not lead to the root of batch {rc['batch']['seq']}")

    # 6
    def batch_sigs(self, shipped: list) -> Dict[Tuple[int, str], dict]:
        acc = self.acc[5]
        batches: Dict[Tuple[int, str], dict] = {}
        seen = set()
        for _, r, _ in shipped:
            rc = r["receipt"]
            computed = hash_json(rc["batch"])
            key = (computed, rc["batch_hash"], rc["batch_sig"], rc["service_key_id"])
            if key in seen:
                continue
            seen.add(key)
            acc.checked += 1
            item = f"batch {rc['batch']['seq']}"
            if computed != rc["batch_hash"]:
                acc.fail(item, f"batch hashes to {computed}, receipt says {rc['batch_hash']}")
            try:
                k = self.service_key(rc["service_key_id"], rc["batch"]["server_time"])
                if not verify_sig(k["public_key"], "batch", computed, rc["batch_sig"]):
                    raise ValueError("signature does not verify")
            except ValueError as e:
                acc.fail(item, f"batch_sig: {e}")
            batches[(rc["batch"]["seq"], computed)] = rc
        return batches

    # 7
    def batch_chain(self, batches: Dict[Tuple[int, str], dict]) -> None:
        acc = self.acc[6]
        by_seq: Dict[Tuple[Any, Any, int], Tuple[str, dict]] = {}
        for (seq, h), rc in sorted(batches.items()):
            acc.checked += 1
            b = rc["batch"]
            k = (b["project"], b["env"], seq)
            if k in by_seq:
                if by_seq[k][0] != h:
                    acc.fail(f"batch {seq}", "two different batches with the same seq (fork)")
                continue
            by_seq[k] = (h, b)
        gaps = 0
        prev: Optional[Tuple[Any, Any, int, str, dict]] = None
        for (p, e, seq), (h, b) in sorted(by_seq.items()):
            if (seq == 1) != (b["prev"] is None):
                acc.fail(f"batch {seq}", "prev must be null exactly when seq is 1")
            if prev and prev[:2] == (p, e):
                if prev[2] + 1 == seq and b["prev"] != prev[3]:
                    acc.fail(f"batch {seq}", f"prev does not equal the batch_hash of batch {prev[2]}")
                elif prev[2] + 1 != seq:
                    gaps += 1
                if _ms(b["server_time"]) < _ms(prev[4]["server_time"]):
                    acc.fail(f"batch {seq}", f"server_time {b['server_time']} is earlier than the server_time of batch {prev[2]} ({prev[4]['server_time']})")
            prev = (p, e, seq, h, b)
        if gaps:
            acc.notes.append(f"{plural(gaps, 'gap')} between batches held in the pack")

    # 8
    def heads(self, shipped: list, chains: dict) -> None:
        acc = self.acc[7]
        seen = set()

        def held(chain: str, seq: Any) -> Optional[str]:
            x = chains.get(chain, {}).get(seq)
            return x[2] if x else None

        def last_held(chain: str) -> int:
            return max(chains.get(chain, {}) or [0])

        for _, r, _ in shipped:
            rc = r["receipt"]
            item = f"head {rc['head']['agent']}#{rc['head']['seq']}"
            hh = hash_json(rc["head"])
            if (hh, rc["head_sig"]) not in seen:
                seen.add((hh, rc["head_sig"]))
                try:
                    k = self.service_key(rc["service_key_id"], rc["head"]["server_time"])
                    if not verify_sig(k["public_key"], "head", hh, rc["head_sig"]):
                        raise ValueError("signature does not verify")
                except ValueError as e:
                    acc.fail(item, f"head_sig: {e}")
                h = held(self.head_chain(rc["head"]), rc["head"]["seq"])
                if h and h != rc["head"]["record_hash"]:
                    acc.fail(item, "head names a different record than the pack holds at that seq")
            if rc["head"]["seq"] < r["envelope"]["seq"]:
                acc.fail(item, f"head is older than record seq {r['envelope']['seq']} it was issued with")

        if not self.local:
            try:
                stmt = {"project": self.project, "env": self.env, "generated": self.generated, "filter": self.filter, "heads": self.export_heads,
                        "records": self.raw_records, **({"project_name": self.project_name} if self.project_name is not None else {})}
                ok = self.any_key("export", hash_json(export_statement(stmt)),
                                  self.export_sig, self.generated)
                if not ok:
                    acc.fail("export statement", "export_sig does not verify with any service key active at generated: the pack's filter, heads, "
                             "generated time or records were changed after the service signed it")
            except ValueError as e:
                acc.fail("export statement", str(e))
            agents = self.filter["agents"]
            in_filter = (lambda a: agents is None or a in agents)
            for label, r, _ in self.recs:
                e = r["envelope"]
                t = _epoch_ms(e["time"])
                if not in_filter(e["agent"]):
                    acc.fail(label, "the record's agent is not in the export's filter")
                elif self.from_ms is not None and t < self.from_ms:
                    acc.fail(label, f"time {e['time']} is before the export's from filter")
                elif self.to_ms is not None and t >= self.to_ms:
                    acc.fail(label, f"time {e['time']} is not before the export's to filter")
        else:
            in_filter = (lambda a: True)

        export: Dict[str, dict] = {}
        for sh in self.export_heads:
            h = sh["head"]
            item = f"export head {h['agent']}#{h['seq']}"
            if (h["project"], h["env"]) != (self.project, self.env):
                acc.fail(item, "the export head belongs to another project or env")
                continue
            hh = hash_json(h)
            if (hh, sh["head_sig"]) not in seen:
                seen.add((hh, sh["head_sig"]))
                if not self.any_key("head", hh, sh["head_sig"], h["server_time"]):
                    acc.fail(item, "head_sig does not verify with any service key active at its server_time")
            s_ms = _epoch_ms(h["server_time"])
            if s_ms is None or self.generated_ms is None or s_ms > self.generated_ms:
                acc.fail(item, f"the export head's server_time {h['server_time']} is after the pack was generated ({self.generated})")
            if not in_filter(h["agent"]):
                acc.fail(item, "the export head is for an agent outside the export's filter")
            x = held(h["agent"], h["seq"])
            if x and x != h["record_hash"]:
                acc.fail(item, "the export head names a different record than the pack holds at that seq")
            if h["agent"] in export:
                acc.fail(item, "two export heads for the same agent")
            else:
                export[h["agent"]] = h
        if not self.local:
            for agent in sorted(chains):
                have, h = last_held(agent), export.get(agent)
                if h is None:
                    acc.fail(f"agent {agent}", "the pack has no export head for this agent, so records cut off at the end cannot be detected")
                elif have > h["seq"]:
                    acc.fail(f"export head {agent}#{h['seq']}", f"the pack holds seq {have}, beyond the export head seq {h['seq']}")
                elif have < h["seq"] and not self.to_may_cut(h):
                    acc.fail(f"export head {agent}#{h['seq']}", f"the pack ends at seq {have} but the service's head at export was seq {h['seq']} (records missing at the end)")
            for agent, h in sorted(export.items()):
                if agent not in chains:
                    acc.fail(f"export head {agent}#{h['seq']}", "the pack holds none of this agent's records, but the export names its head")

        newer = 0
        for sh in self.client_heads or []:
            h = sh["head"]
            if (h["project"], h["env"]) != (self.project, self.env):
                continue
            if not in_filter(h["agent"]):
                continue
            item = f"head file {h['agent']}#{h['seq']}"
            hh = hash_json(h)
            if (hh, sh["head_sig"]) not in seen:
                seen.add((hh, sh["head_sig"]))
                if not self.any_key("head", hh, sh["head_sig"], h["server_time"]):
                    acc.fail(item, "head_sig does not verify with any service key active at its server_time")
            x = held(h["agent"], h["seq"])
            if x and x != h["record_hash"]:
                acc.fail(item, "the client's head names a different record than the pack holds at that seq")
            s_ms = _epoch_ms(h["server_time"])
            if s_ms is None or self.generated_ms is None or s_ms > self.generated_ms:
                newer += 1
                continue
            have = last_held(h["agent"])
            # Records must reach the client's head when the agent has records in the pack (time never
            # goes back along a chain), or when the window holds all its records.
            applies = (have > 0 or not self.from_cuts(h["agent"])) and not self.to_may_cut(h)
            if applies and have < h["seq"]:
                acc.fail(item, f"the client's head is seq {h['seq']} but the pack ends at seq {have} (records missing at the end)")
        if newer:
            acc.notes.append(f"{plural(newer, 'client head')} newer than the export, not applied")

        for chain, sh in sorted(self.local_bases.items()):
            head = (sh or {}).get("head") or {}
            hh = hash_json(head)
            sig = (sh or {}).get("head_sig", "")
            if self.service_keys and (hh, sig) not in seen:
                seen.add((hh, sig))
                if not self.any_key("head", hh, sig, head.get("server_time")):
                    acc.fail(f"base {chain}#{head.get('seq')}", "head_sig: signature does not verify")

        for chain, sh in sorted(self.local_heads.items()):
            head = (sh or {}).get("head") or {}
            item = f"head.json {chain}#{head.get('seq')}"
            hh = hash_json(head)
            sig = (sh or {}).get("head_sig", "")
            if (hh, sig) not in seen:
                seen.add((hh, sig))
                if not self.any_key("head", hh, sig, head.get("server_time")):
                    acc.fail(item, "head_sig: signature does not verify")
                x = held(chain, head.get("seq"))
                if x and x != head.get("record_hash"):
                    acc.fail(item, "head names a different record than the pack holds at that seq")
            have = last_held(chain)
            if have < (head.get("seq") or 0):
                acc.fail(item, f"the service holds seq {head.get('seq')} but the local chain ends at seq {have} (truncated)")
        acc.checked = len(seen)

    # 9
    def drand(self, batches: Dict[Tuple[int, str], dict]) -> None:
        acc = self.acc[8]
        nulls = 0
        rounds = set()
        to_check: list = []
        for rc in batches.values():
            d = rc["batch"]["drand"]
            if d is None:
                nulls += 1
                continue
            item = f"batch {rc['batch']['seq']} round {d['round']}"
            why = check_round_time(_epoch_ms(rc["batch"]["server_time"]) or 0, d["round"])
            if why:
                acc.fail(item, why)
            if (d["round"], d["signature"]) in rounds:
                continue
            rounds.add((d["round"], d["signature"]))
            if d["chain"] != QUICKNET_CHAIN:
                acc.fail(item, f"unknown drand chain {d['chain']}")
            elif not re.fullmatch(r"(?:[0-9a-f]{2})+", d["signature"]):
                acc.fail(item, "signature is not hex")
            elif sha256_hex(bytes.fromhex(d["signature"])) != d["randomness"]:
                acc.fail(item, "randomness is not sha256(signature)")
            else:
                to_check.append((item, d))
        if self.drand_verifier and to_check:
            many = getattr(self.drand_verifier, "many", None)
            results = many([d for _, d in to_check]) if many else [self.drand_verifier(d) for _, d in to_check]
            for (item, d), ok in zip(to_check, results):
                if not ok:
                    acc.fail(item, f"BLS signature does not verify for round {d['round']}")
        acc.checked = len(rounds)
        if nulls:
            acc.notes.append(f"{plural(nulls, 'batch', 'batches')} without a drand round (beacon unreachable when written)")
        if not rounds or not self.drand_verifier:
            acc.not_checked = True
            if rounds:
                acc.notes.append(DRAND_NOT_CHECKED.split(": ", 1)[1])

    # 10, 11
    def anchors(self, anchors: list, batches: Dict[Tuple[int, str], dict]) -> None:
        a10, a11 = self.acc[9], self.acc[10]
        batch_times = {h: (seq, rc["batch"]["server_time"]) for (seq, h), rc in batches.items()}
        anchored = set()
        by_seq: Dict[int, Tuple[str, dict]] = {}
        proofs: List[tuple] = []
        for i, entry in enumerate(anchors):
            a10.checked += 1
            errs = _anchor_errors(entry)
            if errs:
                a10.fail(f"anchors[{i}]", errs)
                continue
            a = entry["anchor"]
            item = f"anchor {a['seq']}"
            ah = hash_json({k: v for k, v in a.items() if k not in ("ots", "status", "bitcoin_block")})
            created = _epoch_ms(a["created"])
            if not self.any_key("anchor", ah, entry["anchor_sig"], a["created"]):
                a10.fail(item, "anchor_sig does not verify with any service key active at its creation")
            if service_keys_hash(self.service_keys or [], created) != a["keys_hash"]:
                a10.fail(item, "keys_hash does not match the service keys supplied: the key list was changed after this anchor was signed")
            for bh, p in entry["paths"].items():
                if verify_inclusion(bh, p.get("index"), a["size"], p.get("path"), a["root"]):
                    anchored.add(bh)
                    if bh in batch_times and created < _epoch_ms(batch_times[bh][1]):
                        a10.fail(item, f"created {a['created']} is before the server_time of batch {batch_times[bh][0]} ({batch_times[bh][1]}) it covers")
                else:
                    a10.fail(item, f"path for batch {bh} does not lead to the anchor root")
            if a["seq"] in by_seq:
                if by_seq[a["seq"]][0] != ah:  # noqa: SIM102
                    a10.fail(item, "two different signed anchors with the same seq")
            else:
                by_seq[a["seq"]] = (ah, a)
            a11.checked += 1
            try:
                proofs.append(_ots_check(a, ah, self.bitcoin))
            except ValueError as e:
                a11.fail(item, str(e))
        prev = None
        for seq in sorted(by_seq):
            ah, a = by_seq[seq]
            if prev and prev[0] + 1 == seq and a["prev"] != prev[1]:
                a10.fail(f"anchor {seq}", f"prev does not equal the anchor_hash of anchor {prev[0]}")
            prev = (seq, ah)
        stale = young = 0
        # Local state holds no anchors: a batch younger than the anchor window is pending (the
        # same rule as a pack, judged at the time of the check); an older one is not checked here.
        ref_ms = int(time.time() * 1000) if self.local else self.generated_ms
        for (_, h), rc in batches.items():
            if h in anchored:
                continue
            t = _epoch_ms(rc["batch"]["server_time"])
            if t is None or ref_ms is None or t + ANCHOR_WINDOW_MS < ref_ms:
                stale += 1
            else:
                young += 1
        if stale:
            a10.not_checked = True
            a10.notes.append(f"{plural(stale, 'batch', 'batches')} older than the 2-hour anchor window: local state holds no anchors, so verify an export (`signafaide export`) to check them"
                             if self.local else
                             f"{plural(stale, 'batch', 'batches')} not timestamped: older than the 2-hour anchor window, and no anchor in the pack covers them")
        if not anchors and not stale and not (self.local and young):
            if self.local:
                a10.not_checked = True
            else:
                a10.pending = True
            a10.notes.append("local state holds no anchors" if self.local else "no anchors in the pack yet (an anchor is made every hour)")
        elif young:
            a10.pending = True
            a10.notes.append(f"{plural(young, 'batch', 'batches')} not yet anchored")
        unchecked = [p for p in proofs if p[0] == "unchecked"]
        if not proofs:
            # No proof yet because the batches wait for their anchor: pending, not unchecked.
            if a10.pending and not a10.not_checked:
                a11.pending = True
                a11.notes.append("waiting for the anchor")
            else:
                a11.not_checked = True
        elif unchecked:
            a11.not_checked = True
            a11.notes.append(f"public timestamp not checked ({unchecked[0][2]}); claims block {', '.join(str(p[1]) for p in unchecked)}")
        elif all(p[0] == "confirmed" for p in proofs):
            a11.value = f"confirmed@{max(p[1] for p in proofs)}"
            a11.notes.append(f"each public timestamp checked against its public record (block {max(p[1] for p in proofs)})")
        else:
            a11.value = "pending"
            a11.pending = True
            a11.notes.append(f"waiting for the public timestamp to confirm (usually within a few hours): {sum(1 for p in proofs if p[0] == 'pending')} of {len(proofs)}")

    # 12
    def content(self, recs: list) -> None:
        acc = self.acc[11]
        for label, r, h in recs:
            c, salt = r.get("content"), r.get("salt")
            local = self.contents.get(h)
            if c is None and salt is None and local is not None:
                c, salt = local["content"], local["salt"]
            if c is None and salt is None:
                continue
            acc.checked += 1
            try:
                ch = check_content(c, salt, r["envelope"]["content_hash"])
            except (ValueError, TypeError) as e:
                acc.fail(label, str(e))
                continue
            if ch is not None:
                acc.fail(label, f"content hashes to {ch}, envelope says {r['envelope']['content_hash']}")
        if not acc.checked:
            acc.not_checked = True
            acc.notes.append("no content supplied (hash-only records)")


def _is_hex(x: Any) -> bool:
    return isinstance(x, str) and bool(HEX64.match(x))


def _anchor_errors(entry: Any) -> str:
    if not isinstance(entry, dict) or set(entry) != {"anchor", "anchor_sig", "paths"}:
        return "an anchor entry has exactly anchor, anchor_sig and paths"
    a = entry["anchor"]
    if not isinstance(a, dict) or set(a) != {"v", "seq", "prev", "root", "size", "created", "keys_hash", "ots", "status", "bitcoin_block"}:
        return "anchor fields are v, seq, prev, root, size, created, keys_hash, ots, status, bitcoin_block"
    if a["v"] != 1 or not _is_u64(a["v"]) or not _is_u64(a["seq"]) or not _is_u64(a["size"]) or _ms(a["created"]) is None:
        return "anchor v, seq, size or created is invalid"
    if not (_is_hex(a["root"]) and _is_hex(a["keys_hash"]) and (a["prev"] is None or _is_hex(a["prev"]))):
        return "anchor root, keys_hash or prev is not a hash"
    if not isinstance(a["ots"], str) or not isinstance(entry["anchor_sig"], str) or not (a["bitcoin_block"] is None or _is_u64(a["bitcoin_block"])):
        return "anchor ots, anchor_sig or bitcoin_block is invalid"
    if a["status"] not in ("pending", "confirmed") or not isinstance(entry["paths"], dict):
        return "anchor status or paths is invalid"
    if not all(_is_hex(k) and isinstance(p, dict) and set(p) == {"index", "path"} and _is_u64(p["index"]) and isinstance(p["path"], list) and all(_is_hex(x) for x in p["path"])
               for k, p in entry["paths"].items()):
        return 'each anchor path is {"index": n, "path": [...]}'
    return ""


def _ots_check(a: dict, anchor_hash: str, bitcoin: Optional[Dict[int, Tuple[bool, Any]]]) -> tuple:
    """("pending",), ("confirmed", h) or ("unchecked", h, why); ValueError on a bad proof."""
    try:
        data = base64.b64decode(a["ots"], validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise ValueError("ots is not standard base64") from None
    digest, height = ots.status(data)
    if digest.hex() != anchor_hash:
        raise ValueError("OTS proof is for a different digest than the anchor hash")
    if a["status"] == "confirmed" and height is None:
        raise ValueError("anchor says confirmed but the proof is still pending")
    if a["status"] == "confirmed" and a["bitcoin_block"] is not None and height != a["bitcoin_block"]:
        raise ValueError(f"anchor says block {a['bitcoin_block']} but the proof attests block {height}")
    if height is None:
        return ("pending",)
    attested = ots.bitcoin_attestations(data)
    if bitcoin is None:
        return ("unchecked", height, "offline")
    # A header is trusted only when it hashes to its block and meets its own proof of work.
    roots: Dict[int, Tuple[bool, Any]] = {}
    for h, (ok, got) in bitcoin.items():
        if not ok:
            roots[h] = (False, got)
            continue
        try:
            roots[h] = (True, check_header(got["hash"], got["header"]))
        except (ValueError, KeyError, TypeError) as e:
            roots[h] = (False, str(e))
    for h, msg in attested:
        got = roots.get(h)
        if got and got[0] and got[1] != msg:
            raise ValueError(f"the timestamp claims block {h}, but its Merkle root does not match that block's header")
    for h, _ in attested:
        got = roots.get(h)
        if got is None:
            return ("unchecked", height, f"block {h} was not looked up")
        if not got[0]:
            return ("unchecked", height, got[1])
    return ("confirmed", height)
