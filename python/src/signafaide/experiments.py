"""Experiments: A/B on past decisions.

``compare(candidate_fn, agent=..., name=...)`` takes recorded decisions from the local chain
(verified first), calls ``candidate_fn`` with each recorded input on this machine, with your
own models and keys, and compares its result with the recorded outcome.

Candidate functions must be side-effect free: they get inputs only, nothing is recorded while
they run (a recorded tool called from a candidate raises instead of running), and compare never
writes to the chain. ``report.upload()`` sends the result to the service, hash-only by default.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from . import jcs, runtime
from ._plural import plural
from .crypto import hash_json
from .decorator import to_jsonable
from .replay import agent_chain, time_arg, verify_chain
from .verifier import Report


class VerificationFailed(ValueError):
    """The local chain did not verify, so its decisions are not compared."""


def recorded_value(outcome_content: dict) -> Any:
    """What a candidate is compared with: the outcome's ``output``, else the whole outcome
    content (an ``error``)."""
    return outcome_content["output"] if "output" in outcome_content else outcome_content


@dataclass
class Row:
    record_hash: str
    outcome_hash: str
    time: str
    name: str
    input: Any
    recorded: Any
    candidate: Any
    same: Optional[bool]  # None when the candidate raised
    error: Optional[str] = None

    @property
    def result(self) -> str:
        return "error" if self.same is None else "agreed" if self.same else "changed"

    def to_dict(self) -> dict:
        return {
            "record_hash": self.record_hash,
            "outcome_hash": self.outcome_hash,
            "time": self.time,
            "name": self.name,
            "input": self.input,
            "recorded": self.recorded,
            "candidate": self.candidate,
            "same": self.same,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class ExperimentReport:
    agent: str
    chain: str
    name: Optional[str]
    candidate_name: str
    rows: List[Row]
    skipped: int
    verification: Report
    since: Optional[str] = None
    until: Optional[str] = None
    label: Optional[str] = None
    uploaded: Optional[dict] = field(default=None, repr=False)

    @property
    def n(self) -> int:
        return len(self.rows)

    @property
    def agreed(self) -> int:
        return sum(r.result == "agreed" for r in self.rows)

    @property
    def changed(self) -> int:
        return sum(r.result == "changed" for r in self.rows)

    @property
    def errors(self) -> int:
        return sum(r.result == "error" for r in self.rows)

    @property
    def agreement(self) -> Optional[float]:
        return self.agreed / self.n if self.n else None

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "chain": self.chain,
            "name": self.name,
            "candidate": self.candidate_name,
            "since": self.since,
            "until": self.until,
            "n": self.n,
            "agreed": self.agreed,
            "changed": self.changed,
            "errors": self.errors,
            "skipped": self.skipped,
            "rows": [r.to_dict() for r in self.rows],
        }

    def __str__(self) -> str:
        pct = f" ({self.agreement:.1%} agreement)" if self.n else ""
        out = [
            f"compare {self.candidate_name} on {self.agent}"
            + (f" / {self.name}" if self.name else "")
            + f" ({self.chain})",
            f"n {self.n}: agreed {self.agreed}, changed {self.changed}, errors {self.errors}{pct}",
        ]
        if self.skipped:
            out.append(f"skipped {plural(self.skipped, 'decision')} without a co-signed outcome yet")
        for r in [r for r in self.rows if r.result != "agreed"][:20]:
            what = (
                f"error {r.error}"
                if r.result == "error"
                else f"recorded {jcs.dumps(r.recorded)[:80]}  candidate {jcs.dumps(r.candidate)[:80]}"
            )
            out.append(f"  {r.result:<7} {r.record_hash[:16]}  {r.time}  {what}")
        if self.changed + self.errors > 20:
            out.append(f"  ... and {self.changed + self.errors - 20} more")
        if self.uploaded:
            out.append(f"uploaded: {self.uploaded.get('url')}")
        return "\n".join(out)

    def payload(self, values: bool = False) -> dict:
        """The ``POST /v1/experiments`` body. Hash-only unless *values*: record hashes, the
        result and the hash of each candidate output; with *values*, the recorded and candidate
        values too (accepted only for decisions whose content is stored with the service)."""
        rows = []
        for r in self.rows:
            row = {
                "record_hash": r.record_hash,
                "outcome_hash": r.outcome_hash,
                "result": r.result,
                "candidate_hash": hash_json(r.candidate),
            }
            if values:
                row["recorded"], row["candidate"] = r.recorded, r.candidate
            rows.append(row)
        body = {
            "agent": self.agent,
            "name": self.name,
            "label": self.label,
            "candidate": self.candidate_name,
            "since": self.since,
            "until": self.until,
            "rows": rows,
        }
        return {k: v for k, v in body.items() if v is not None}

    def upload(self, values: Optional[bool] = None) -> dict:
        """Send the report to the service. *values* defaults to the recorder's ``store_content``.
        Returns the stored summary with its console ``url``."""
        rec = runtime.get()
        self.uploaded = rec.client(timeout=60).request(
            "POST", "/v1/experiments", self.payload(rec.store_content if values is None else values)
        )
        return self.uploaded


def _call(fn: Callable[..., Any], inp: Any) -> Any:
    out = fn(**inp) if isinstance(inp, dict) else fn(inp)
    if inspect.isawaitable(out):

        async def wait() -> Any:
            return await out

        out = asyncio.run(wait())
    return out


def compare(
    candidate_fn: Callable[..., Any],
    *,
    agent: Optional[str] = None,
    name: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: Optional[int] = None,
    same: Optional[Callable[[Any, Any], bool]] = None,
    chain: Optional[str] = None,
    keys: Any = None,
    label: Optional[str] = None,
    upload: bool = False,
) -> ExperimentReport:
    """Re-run recorded decisions with *candidate_fn* and compare with what happened.

    The agent's local chain is verified first (raises :class:`VerificationFailed` on FAIL).
    Decisions of *name* (all names when None) between *since* and *until* that have a co-signed
    outcome are taken, the newest *limit* of them when set. A recorded input that is an object
    is passed as keyword arguments, anything else as the one argument. The candidate's result is
    compared with the outcome's ``output`` by exact equality (canonical JSON), or by
    ``same(recorded, candidate)``. A candidate that raises counts as an error.

    Never writes records and never calls recorded tools: candidates must be side-effect free.
    """
    rec = runtime.get()
    agent = agent or rec.only_agent() or rec.default_agent
    chain = chain or agent_chain(rec, agent)
    lo, hi = time_arg(since, "since"), time_arg(until, "until", end=True)
    report = verify_chain(rec, chain, keys)
    if not report.ok:
        raise VerificationFailed(f"the local chain {chain} does not verify, so it is not compared:\n{report}")
    records = list(rec.state.read_chain(chain))
    outcomes = {r["envelope"]["ref"]: r for r in records if r["envelope"]["kind"] == "outcome" and "receipt" in r}
    picked, skipped = [], 0
    for r in records:
        e = r["envelope"]
        if (
            e["kind"] != "decision"
            or (name and e["name"] != name)
            or (lo and e["time"] < lo)
            or (hi and e["time"] >= hi)
        ):
            continue
        h = hash_json(e)
        o = outcomes.get(h)
        if (
            "receipt" not in r
            or o is None
            or not isinstance(r.get("content"), dict)
            or not isinstance(o.get("content"), dict)
        ):
            skipped += 1
            continue
        picked.append((h, r, o))
    if limit is not None:
        picked = picked[-limit:] if limit > 0 else []
    equal = same or (lambda a, b: jcs.dumps(a) == jcs.dumps(b))
    fname = getattr(candidate_fn, "__qualname__", None) or repr(candidate_fn)
    rows = []
    token = runtime.NO_WRITES.set(f"compare candidate {fname}")
    try:
        for h, d, o in picked:
            inp, recorded = d["content"].get("input"), recorded_value(o["content"])
            row = Row(
                h, hash_json(o["envelope"]), d["envelope"]["time"], d["envelope"]["name"], inp, recorded, None, None
            )
            try:
                row.candidate = to_jsonable(_call(candidate_fn, inp))
                row.same = bool(equal(recorded, row.candidate))
            except Exception as ex:  # the candidate's failure is a result, not a crash
                row.candidate = {"error": {"type": type(ex).__name__, "message": str(ex)}}
                row.error = f"{type(ex).__name__}: {ex}"
            rows.append(row)
    finally:
        runtime.NO_WRITES.reset(token)
    out = ExperimentReport(agent, chain, name, fname, rows, skipped, report, lo, hi, label)
    if upload:
        out.upload()
    return out
