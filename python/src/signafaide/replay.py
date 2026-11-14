"""Replay: what an agent saw and did, from the local chain, proven.

``replay(agent="claims-bot")`` reads the agent's chain in ``.signafaide/chain``, runs the §7
verifier over it (signatures, chain links, receipts, and each record's content against its
``content_hash``), and returns the timeline of decisions and outcomes with their inputs and
outputs. ``str(r)`` is the terminal view; ``r.to_html()`` a self-contained page.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import runtime
from ._plural import plural
from .crypto import hash_json
from .drand import load_verifier as load_drand_verifier
from .http import SignafaideError
from .records import TIME_RE
from .verifier import KeysRequired, Report, load_service_keys, verify_local

DATE_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


def time_arg(value: Optional[str], name: str, end: bool = False) -> Optional[str]:
    """``YYYY-MM-DD`` or a protocol time (``2026-11-13T10:00:00.000Z``) as a protocol time.
    A bare date as an end bound means the end of that day."""
    if value is None or value == "":
        return None
    if DATE_RE.match(value):
        if end:
            from datetime import date, timedelta

            value = (date.fromisoformat(value) + timedelta(days=1)).isoformat()
        return f"{value}T00:00:00.000Z"
    if not TIME_RE.match(value):
        raise ValueError(f"{name} must be YYYY-MM-DD or a time like 2026-11-13T10:00:00.000Z")
    return value


def agent_chain(rec: runtime.Recorder, agent: str) -> str:
    """The chain to read for *agent*: the current API key's, else the only one there is."""
    current = f"{rec.state.bucket(rec.api_key)}/{agent}"
    if rec.state.chain_path(current).exists():
        return current
    found = [c for c in rec.state.chains() if c.rsplit("/", 1)[1] == agent]
    if len(found) == 1:
        return found[0]
    if not found:
        raise ValueError(f"no local chain for agent {agent!r} in {rec.state.home}; agents here: {', '.join(rec.state.agents()) or 'none'}")
    raise ValueError(f"agent {agent!r} has several chains ({', '.join(found)}); pass chain= (--chain) to pick one")


def verify_chain(rec: runtime.Recorder, chain: str, keys: Any = None) -> Report:
    """Run the §7 verifier over one local chain. Service keys come from *keys* (file, URL or
    dict) or from the service; with no receipts in the chain none are needed."""
    note = None
    if keys is not None:
        service_keys = load_service_keys(keys)
        note = f"service keys: {keys if isinstance(keys, (str, Path)) else 'given'}"
    elif not any("receipt" in r for r in rec.state.read_all(chain)):
        service_keys = []  # no request: nothing has been co-signed
        note = "service keys: none needed (nothing co-signed yet)"
    else:
        try:
            service_keys = load_service_keys(rec.client().request("GET", "/.well-known/signafaide-keys.json", auth=False))
            note = f"service keys: {rec.url}/.well-known/signafaide-keys.json"
        except (SignafaideError, ValueError) as e:
            if any("receipt" in r for r in rec.state.read_chain(chain)):
                raise KeysRequired(f"could not load service keys from {rec.url} ({e}); pass keys= (--keys <file|url>)") from None
            service_keys = []
    report = verify_local(rec.state, service_keys, drand=load_drand_verifier(), chains=[chain])
    report.notes[:0] = [f"chain: {chain}"] + ([note] if note else [])
    return report


@dataclass
class Entry:
    """One record of the timeline."""

    record: dict
    hash: str
    problems: List[str] = field(default_factory=list)
    pair: Optional["Entry"] = None  # the outcome of a decision, or the decision of an outcome
    blocked: Optional[str] = None  # why the witness can never take this record (the chain is BLOCKED from here)

    @property
    def envelope(self) -> dict:
        return self.record["envelope"]

    @property
    def content(self) -> Optional[dict]:
        c = self.record.get("content")
        return c if isinstance(c, dict) else None

    @property
    def receipt(self) -> Optional[dict]:
        return self.record.get("receipt")

    @property
    def status(self) -> str:
        """``verified``, ``signed`` (not co-signed by the service yet), ``BLOCKED`` (can never be
        co-signed as it is) or ``FAIL``."""
        if self.problems:
            return "FAIL"
        return "verified" if self.receipt else "BLOCKED" if self.blocked else "signed"

    def to_dict(self) -> dict:
        e, rc = self.envelope, self.receipt or {}
        b = rc.get("batch") or {}
        return {
            "seq": e["seq"], "kind": e["kind"], "name": e["name"], "time": e["time"], "record_hash": self.hash,
            "ref": e["ref"], "content_hash": e["content_hash"], "content": self.content, "status": self.status,
            "problems": self.problems, "batch_seq": b.get("seq"), "server_time": b.get("server_time"),
            "drand_round": (b.get("drand") or {}).get("round"), "pair": self.pair.hash if self.pair else None,
            **({"blocked": self.blocked} if self.blocked else {}),
        }


@dataclass
class Replay:
    agent: str
    chain: str
    entries: List[Entry]
    report: Report
    since: Optional[str] = None
    until: Optional[str] = None
    total: int = 0
    #: Why the chain cannot ship from some record on (`signafaide repair` fixes it), or None.
    blocked: Optional[dict] = None

    @property
    def ok(self) -> bool:
        return self.report.ok and not self.blocked

    @property
    def result(self) -> str:
        """PASS, FAIL or BLOCKED (a chain the witness refuses never passes)."""
        return "BLOCKED" if self.report.result == "PASS" and self.blocked else self.report.result

    def to_dict(self) -> dict:
        return {
            "agent": self.agent, "chain": self.chain, "since": self.since, "until": self.until, "total": self.total,
            "shown": len(self.entries), "result": self.result, **({"blocked": self.blocked} if self.blocked else {}),
            "verification": self.report.to_dict(), "entries": [e.to_dict() for e in self.entries],
        }

    def __str__(self) -> str:
        return "\n".join(self.lines())

    def lines(self) -> List[str]:
        window = f"{self.since or 'start'} to {self.until or 'now'}"
        out = [f"signafAIde replay: {self.agent}  ({self.chain})", f"window: {window}; {len(self.entries)} of {plural(self.total, 'record')} shown"]
        out.append(f"verification: {self.report.result_line}" + ("" if self.report.ok else f" (first failed check: {self.report.first_failed()})"))
        if self.blocked:
            out.append(f"BLOCKED from seq {self.blocked['seq']}: {self.blocked['reason']}. Next: {self.blocked['next']}")
        out += [f"  {n}" for n in self.report.notes]
        out.append("")
        for e in self.entries:
            env = e.envelope
            link = ""
            if e.pair is not None:
                link = f"  -> outcome #{e.pair.envelope['seq']}" if env["kind"] == "decision" else f"  <- decision #{e.pair.envelope['seq']}"
            rc = e.receipt
            where = (f"batch {rc['batch']['seq']}" + (f", drand {rc['batch']['drand']['round']}" if rc["batch"].get("drand") else "") if rc
                     else "the witness cannot take it" if e.blocked else "not co-signed yet")
            out.append(f"#{env['seq']:<5} {env['time']}  {env['kind']:<8} {env['name']}{link}")
            out.append(f"       {e.hash[:16]}  {e.status.upper()} ({where})")
            for p in e.problems:
                out.append(f"       ! {p}")
            for k, v in (e.content or {}).items():
                text = json.dumps(v, ensure_ascii=False, separators=(", ", ": "))
                if len(text) > 100:
                    text = "\n".join("         " + ln for ln in json.dumps(v, ensure_ascii=False, indent=2).splitlines()).lstrip()
                out.append(f"       {k:<7} {text}")
            if e.content is None:
                out.append("       (no local content for this record)")
            out.append("")
        failed = sum(1 for e in self.entries if e.problems)
        signed = sum(1 for e in self.entries if not e.receipt and not e.problems)
        blocked_n = sum(1 for e in self.entries if e.status == "BLOCKED")
        if failed:
            what = f"{failed} failed"
        elif signed:
            what = (f"each checked against its content_hash and signature; {signed} not co-signed yet"
                    + (f" ({blocked_n} BLOCKED)" if blocked_n else "") + ", so their receipts could not be checked")
        else:
            what = "each checked against its content_hash, its signature and its receipt"
        out.append(f"{self.result}: {plural(len(self.entries), 'record')} shown, {what}")
        return out

    def to_html(self) -> str:
        """One self-contained page: inline CSS, no scripts, no external assets."""
        esc = html.escape
        rows = []
        for e in self.entries:
            env, rc = e.envelope, e.receipt
            link = ""
            if e.pair is not None:
                link = f'<span class="muted">{"outcome" if env["kind"] == "decision" else "decision"} <a href="#r{e.pair.envelope["seq"]}">#{e.pair.envelope["seq"]}</a></span>'
            cls = {"verified": "ok", "signed": "warn", "BLOCKED": "bad", "FAIL": "bad"}[e.status]
            body = "".join(
                f'<div class="kv"><span>{esc(k)}</span><pre>{esc(json.dumps(v, ensure_ascii=False, indent=2))}</pre></div>' for k, v in (e.content or {}).items()
            ) or '<p class="muted">No local content for this record.</p>'
            probs = "".join(f'<li>{esc(p)}</li>' for p in e.problems)
            receipt = (
                f'batch {rc["batch"]["seq"]} · {esc(rc["batch"]["server_time"])}' + (f' · drand {rc["batch"]["drand"]["round"]}' if rc["batch"].get("drand") else "")
                if rc else f"BLOCKED: {esc(e.blocked)}" if e.blocked else "not co-signed by the service yet"
            )
            rows.append(
                f'<article id="r{env["seq"]}" class="{esc(env["kind"])}"><header><span class="seq">#{env["seq"]}</span>'
                f'<span class="kind">{esc(env["kind"])}</span><b>{esc(env["name"])}</b>{link}<span class="st {cls}">{esc(e.status)}</span></header>'
                f'<div class="meta"><code title="record_hash">{esc(e.hash)}</code> · {esc(env["time"])} · {receipt}</div>'
                + (f'<ul class="probs">{probs}</ul>' if probs else "") + f"{body}</article>"
            )
        checks = "".join(
            f'<tr><td>{c.n}</td><td>{esc(c.title)}</td><td><span class="st {"ok" if c.status == "pass" else "bad" if c.status == "fail" else ""}">{esc(c.label)}</span></td><td>{esc(c.detail)}</td></tr>'
            for c in self.report.checks
        )
        notes = "".join(f"<li>{esc(n)}</li>" for n in self.report.notes)
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Replay: {esc(self.agent)}</title><style>{_CSS}</style></head><body><main>
<p class="muted small">signafAIde replay</p><h1>{esc(self.agent)}</h1>
<p class="muted">{esc(self.chain)} · {esc(self.since or "start")} to {esc(self.until or "now")} · {len(self.entries)} of {plural(self.total, 'record')}</p>
<p class="result">Verification: <span class="st {"ok" if self.ok else "bad"}">{self.result}</span> <span class="muted small">{esc(self.report.result_line)}</span></p>
{f'<p class="probs">BLOCKED from seq {self.blocked["seq"]}: {esc(self.blocked["reason"])}. Next: {esc(self.blocked["next"])}</p>' if self.blocked else ""}
<details><summary>Checks</summary><ul class="small muted">{notes}</ul><table>{checks}</table></details>
{"".join(rows)}
<footer>Each record was checked against its content_hash, its signature and the service's receipt. Generated by signafAIde from the local chain.</footer>
</main></body></html>"""


_CSS = """
*{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#1a1d23;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 24px 64px}h1{margin:0;font-size:22px}a{color:#2456c4}
.muted{color:#5d6472}.small{font-size:12px}.result{font-weight:600}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}td{padding:4px 8px;border-bottom:1px solid #e3e6ec;vertical-align:top}
article{background:#fff;border:1px solid #e3e6ec;border-radius:8px;padding:12px 14px;margin:10px 0}
article.outcome{margin-left:28px}article header{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.seq{color:#5d6472;font-variant-numeric:tabular-nums}.kind{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5d6472}
.meta{font-size:12px;color:#5d6472;margin:4px 0 8px;word-break:break-all}code,pre{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{margin:2px 0 6px;padding:8px 10px;background:#f6f7f9;border-radius:6px;white-space:pre-wrap;word-break:break-word}
.kv>span{font-size:11.5px;font-weight:600;color:#4a5160}
.st{margin-left:auto;padding:1px 8px;border-radius:4px;font-size:11.5px;font-weight:700;background:#eceef2;color:#4a5160}
.st.ok{background:#e3f4ea;color:#1d6b3f}.st.warn{background:#fdf2dc;color:#7a5200}.st.bad{background:#fbe5e5;color:#9b1c1c}
.probs{color:#9b1c1c;font-size:12.5px;margin:4px 0}footer{margin-top:24px;font-size:12px;color:#5d6472}
@media print{body{background:#fff}article{break-inside:avoid}}
"""


def replay(
    agent: Optional[str] = None,
    *,
    since: Optional[str] = None,
    until: Optional[str] = None,
    record: Optional[str] = None,
    chain: Optional[str] = None,
    keys: Any = None,
) -> Replay:
    """The agent's decisions and outcomes from the local chain, each checked against its
    ``content_hash``, its signature and its receipt. ``since``/``until`` are ``YYYY-MM-DD`` or
    protocol times (``until`` exclusive); ``record`` (a record hash or a prefix of at least 8
    characters) shows that record and its decision or outcome. Never writes anything."""
    rec = runtime.get()
    agent = agent or rec.only_agent() or rec.default_agent
    chain = chain or agent_chain(rec, agent)
    lo, hi = time_arg(since, "since"), time_arg(until, "until", end=True)
    report = verify_chain(rec, chain, keys)
    entries = [Entry(r, hash_json(r["envelope"])) for r in rec.state.read_all(chain)]
    by_label: Dict[str, List[str]] = {}
    for c in report.checks:
        for f in c.failures:
            by_label.setdefault(f["item"], []).append(f"{c.title}: {f['message']}")
    by_hash = {e.hash: e for e in entries}
    for e in entries:
        env, rc = e.envelope, e.receipt
        e.problems = list(by_label.get(f"{chain}#{env['seq']}", []))
        if rc:
            e.problems += by_label.get(f"batch {rc['batch']['seq']}", []) + by_label.get(f"head {rc['head']['agent']}#{rc['head']['seq']}", [])
        if env["kind"] == "outcome" and env["ref"] in by_hash:
            e.pair, by_hash[env["ref"]].pair = by_hash[env["ref"]], e
    total = len(entries)
    if record:
        r = record.lower()
        if len(r) < 8:
            raise ValueError("record must be a record hash or a prefix of at least 8 characters")
        hit = [e for e in entries if e.hash.startswith(r)]
        if len(hit) != 1:
            raise ValueError(f"{'no' if not hit else len(hit)} records match {record} in {chain}")
        entries = sorted({id(x): x for x in [hit[0], hit[0].pair] if x}.values(), key=lambda x: x.envelope["seq"])
    b = next((x for x in rec.diagnose() if x["chain"] == chain), None)
    if b:
        for e in entries:
            if not e.receipt and e.envelope["seq"] >= b["seq"]:
                e.blocked = b["reason"]
    entries = [e for e in entries if (lo is None or e.envelope["time"] >= lo) and (hi is None or e.envelope["time"] < hi)]
    return Replay(agent, chain, entries, report, lo, hi, total, {"seq": b["seq"], "reason": b["reason"], "next": b["next"]} if b else None)

