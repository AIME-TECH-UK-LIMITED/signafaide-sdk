"""The per-tool commands of spec 1.1: ``status`` (one line per tool: recorded, protected, proof),
``check`` (a dry run that exits 1 when the call would be blocked), ``pull`` (fetch the rules and ask
before any new field leaves the machine), ``prove [tool]`` (what an auditor gets, with the rules in
words) and ``start-fresh <agent>`` (proofs of the agent start from now; the old record is kept)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from . import checks as C
from ._plural import plural
from ._version import __version__
from .checks_runtime import site_of
from .coverage import coverage, declared_name
from .crypto import hash_json
from .http import SignafaideError
from .protect_cli import Prompter, field_uses, find_tools, to_version2, write_checks_file
from .records import record_hash
from .words import field_words, number_words, rule_words, state_word

Out = Callable[[str], None]
# How auditors install the standalone verifier (§7).
AUDITOR_DOCS_URL = "https://signafaide.co.uk/docs/verify"
# The hosted witness, whose service keys are pinned in signafaide-verify.
_HOSTED = ("https://api.signafaide.co.uk", "https://signafaide.co.uk")


def auditor_commands(witness: str, agent_keys: str, extra: str = "") -> List[str]:
    """The one command an auditor runs, as npx and uvx lines, pinned to this release. For the hosted
    witness it passes no --keys: signafaide-verify uses the keys pinned in it and checks them against
    the published list. A self-hosted witness's keys come from that witness."""
    base = witness.rstrip("/")
    keys = "" if base in _HOSTED else f" --keys {base}/.well-known/signafaide-keys.json"
    args = f"pack.json{keys} --agent-keys {agent_keys} --head head.json{extra}"
    return [f"npx signafaide-verify@{__version__} {args}", f"uvx signafaide-verify@{__version__} {args}"]


_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _hhmm(t: str) -> str:
    return t[11:16]


def _when(t: str, year: bool = True) -> str:
    return f"{int(t[8:10])} {_MONTHS[int(t[5:7]) - 1]}" + (f" {t[:4]}" if year else "") + f" {_hhmm(t)}"


def _file(rec: Any) -> Optional[dict]:
    try:
        return rec.checks.file()
    except Exception:
        return None


def chains_by_agent(rec: Any) -> Dict[str, Tuple[str, List[dict]]]:
    """The records of this project's chains (the current key's project and env, or every chain
    without a key), by agent."""
    key = rec.api_key
    bucket = rec.state.bucket(key) if key else None
    out: Dict[str, Tuple[str, List[dict]]] = {}
    for chain in rec.state.chains():
        agent = chain.split("/")[2]
        if bucket and not (chain.startswith(f"{bucket}/") or chain.startswith("_pending/")):
            continue
        records = list(rec.state.read_all(chain))
        if agent not in out or len(records) > len(out[agent][1]):
            out[agent] = (chain, records)
    return out


def protected_in_code(rec: Any) -> Set[str]:
    """The declared names of the tools the project's code protects (``@signafaide.protect``, or
    ``record(strict=True)``): protected whatever the checks file says (§8)."""
    try:
        return {declared_name(t.name) for t in find_tools(Path(rec.state.root)).tools if t.wrapped == "protect"}
    except Exception:  # noqa: BLE001 - code that cannot be read protects nothing here
        return set()


def protected_names(rec: Any, f: Optional[dict], records: List[dict]) -> Set[str]:
    """The tools that are protected: by the checks file, by the code, or whose last call was strict."""
    out = {n for n in (f or {}).get("tools", {}) if C.tool_settings(f, n)["strict"]} if f else set()
    last: Dict[str, bool] = {}
    for r in records:
        e = r["envelope"]
        if e["kind"] == "decision" and isinstance(e.get("checks"), dict):
            last[e["name"]] = e["checks"].get("strict") is True
    # §8 (SDK 0.5.2): the tools the held rule set protects from the console, that the program wraps.
    rs = rec.checks.held_rules() if rec.checks.path() is not None else None
    if rs and isinstance(rs.get("protect"), dict):
        named = {r["envelope"]["name"] for r in records}
        out |= {n for n in rs["protect"] if rec.checks.wrapped_state(n) == "wrapped" or n in named}
    return out | protected_in_code(rec) | {n for n, x in last.items() if x}


def protection_words(
    rec: Any, f: Optional[dict], agent: str, tool: str, in_code: bool = False, seen: bool = True
) -> str:
    """What ``status`` says of a tool's protection: ``1 of 3 rules On, 2 Calibrating``, ``Off``...
    *in_code*: the code protects it (its decorator, or its last call was strict). *seen*: the
    program has shown the tool to signafAIde (a tool it never wraps cannot be protected, §8)."""
    decl = declared_name(tool)
    ts = C.tool_settings(f, decl) if f else None
    rs = rec.checks.held_rules()
    console = rec.checks.path() is not None and C.console_protects(rs, decl)
    if console and not seen:
        return f"Off: protected from the console (rule set version {rs['version']}), but not wrapped, so signafAIde never sees its calls"
    sources = (
        (["code"] if in_code else [])
        + (["checks_file"] if ts and ts["strict"] else [])
        + (["console"] if console else [])
    )
    if in_code or console:
        ts = {**(ts or {"mode": "enforce", "disclose": []}), "strict": True}
    frm = f", {C.source_words(sources, rs['version'] if rs else None)}" if sources else ""
    if ts and not ts["strict"] and ts["mode"] == "enforce" and f.get("rules"):
        n = sum(1 for r in f["rules"]["rules"] if C.applies(r, agent, decl))
        return f"this machine only, {plural(n, 'rule')}"
    if not ts or not ts["strict"]:
        return "Off"
    rules = [r for r in rs["rules"] if C.applies(r, agent, decl)] if rs else []
    if not rs or not rules:
        return ("On, no rule for it yet" if rs else "On, rules not fetched yet") + frm
    on = sum(1 for r in rules if C.rule_state(rs, r) == "on") if rs["mode"] == "enforce" else 0
    cal = len(rules) - on
    return f"{on} of {plural(len(rules), 'rule')} On" + (f", {cal} Calibrating" if cal else "") + frm


def proof_by_agent(rec: Any) -> Callable[[str], str]:
    """The proof column of each agent, from the local verify."""
    from . import verify

    try:
        report = verify(None, offline=True)
    except Exception:
        report = None
    chains = chains_by_agent(rec)

    def of(agent: str) -> str:
        if report is None:
            return "unknown (run signafaide verify)"
        if not report.ok:
            return "NOT intact (run signafaide verify)"
        recs = chains.get(agent, ("", []))[1]
        if not recs:
            return "intact"
        if any(not r.get("receipt") for r in recs):
            return "intact, not co-signed yet" if rec.api_key else "intact, kept on this machine"
        return "intact, timestamp pending" if any(c.status == "pending" for c in report.checks) else "intact"

    return of


def status_table(rec: Any) -> List[str]:
    """The tool lines of ``status``: one line per tool."""
    f = _file(rec)
    chains = chains_by_agent(rec)
    agents = set(chains) | set(rec.state.agents())
    proof = proof_by_agent(rec)
    code = protected_in_code(rec)
    held = rec.checks.held_rules() if rec.checks.path() is not None else None
    rows: List[Tuple[str, str, int, Optional[str], str, str]] = []
    for agent in sorted(agents):
        names = set()
        for tools in rec.state.tool_sources(agent).values():
            names.update(declared_name(t) for t in tools)
        calls: Dict[str, List[Any]] = {}
        strict: Dict[str, bool] = {}  # the last call of each tool: strict (protected in code) or not
        for r in chains.get(agent, ("", []))[1]:
            e = r["envelope"]
            if e["kind"] != "decision" or e["name"].startswith("signafaide."):
                continue
            names.add(e["name"])
            if isinstance(e.get("checks"), dict):
                strict[e["name"]] = e["checks"].get("strict") is True
            c = calls.setdefault(e["name"], [0, e["time"]])
            c[0] += 1
            c[1] = e["time"]
        if f and len(agents) == 1:
            names.update(f["tools"])
        # The tools the console protects (§8, SDK 0.5.2): listed, so one the program never wraps shows.
        if held and isinstance(held.get("protect"), dict) and len(agents) == 1:
            names.update(held["protect"])
        if not names:
            continue
        p = proof(agent)
        for tool in sorted(names):
            n, last = calls.get(tool, [0, None])
            seen = n > 0 or rec.checks.wrapped_state(tool) == "wrapped"
            in_code = tool in code or (
                strict.get(tool, False)
                and not C.console_protects(held, tool)
                and not (f and C.tool_settings(f, tool)["strict"])
            )
            rows.append((agent, tool, n, last, protection_words(rec, f, agent, tool, in_code, seen), p))
    if not rows:
        return []
    many = len({r[0] for r in rows}) > 1
    cells = [
        [f"{a}/{t}" if many else t, f"{plural(n, 'call')}, last {_hhmm(last)}" if n else "0 calls", prot, pr]
        for a, t, n, last, prot, pr in rows
    ]
    head = ["tool", "recorded", "protected", "proof"]
    w = [max([len(head[i])] + [len(c[i]) for c in cells]) + 2 for i in range(4)]

    def fmt(r: List[str]) -> str:
        return " ".join(c.ljust(w[i]) if i < 3 else c for i, c in enumerate(r)).rstrip()

    return [fmt(head)] + [fmt(c) for c in cells]


# --- check -------------------------------------------------------------------------------------


def parse_field_args(pairs: List[str]) -> dict:
    """``amount=1200 currency=GBP payee/name=Ashgrove`` as arguments: a value is JSON when it reads
    as JSON, else text; ``a/b=v`` sets a field inside an object."""
    out: dict = {}
    for p in pairs:
        if "=" not in p or p.index("=") == 0:
            raise ValueError(f"{p}: give each field as name=value, for example amount=1200")
        k, raw = p.split("=", 1)
        keys = k.lstrip("/").split("/")
        try:
            value = json.loads(raw)
        except ValueError:
            value = raw
        cur = out
        for key in keys[:-1]:
            if not isinstance(cur.get(key), dict):
                cur[key] = {}
            cur = cur[key]
        cur[keys[-1]] = value
    return out


def run_check(rec: Any, tool: str, pairs: List[str], agent: Optional[str] = None) -> Tuple[List[str], int]:
    """``signafaide check <tool> <field>=<value>...``: lines and the exit code (1: would be blocked)."""
    args = json.loads(pairs[0]) if len(pairs) == 1 and pairs[0].strip().startswith("{") else parse_field_args(pairs)
    if rec.api_key and rec.checks.held_rules() is None:
        try:
            rec.checks.pull_rules()
        except SignafaideError:
            pass
    lines, blocked = rec.checks.dry_run(tool, args, agent or rec.default_agent)
    return lines, 1 if blocked else 0


# --- pull --------------------------------------------------------------------------------------


def run_pull(rec: Any, prompt: Prompter, out: Out) -> int:
    """``signafaide pull``: fetch the rule set, rewrite the checks file as version 2, and for each
    protected tool ask before adding a field the held version can use. Never removes an approved
    field; never adds one without a person at a terminal."""
    held = rec.checks.held_rules()
    before = held["version"] if held else None
    code = 0
    if rec.api_key:
        said = rec.checks.forced_pull()  # a person asked: key list, rule set and list, never waiting
        if "rules" in rec.checks.problems:
            out(f"Rules      {said}")
            code = 1
    else:
        out("Rules      no API key: only the rules in the checks file apply (signafaide protect makes a sandbox)")
    rs = rec.checks.held_rules()
    if rs:
        was = (
            f" (was {before})"
            if before is not None and before != rs["version"]
            else " (no change)"
            if before == rs["version"]
            else ""
        )
        out(f"Rules      version {rs['version']}{was}")
    elif rec.api_key:
        out("Rules      the project has no rule set yet (signafaide protect adds one)")
    from .checks_runtime import checks_path

    p = checks_path(rec.state.root)
    if p is None:
        out("Checks     off (SIGNAFAIDE_CHECKS=0): nothing to write")
        return code
    try:
        f = rec.checks.file()
    except Exception as e:
        out(f"Checks     {e}")
        return 1
    # §8 (SDK 0.5.2): the tools the held version protects from the console have fields to approve too.
    from_console = list(rs["protect"]) if rs and isinstance(rs.get("protect"), dict) else []
    if f is None and not from_console:
        out(f"Checks     no {p.name} here: signafaide protect writes one")
        return code
    doc = to_version2(f if f is not None else C.default_checks_file())
    agent = rec.default_agent
    changes: List[str] = []
    wait: List[str] = []
    now_file: List[str] = []
    for name in sorted(set(doc["tools"]) | set(from_console)):
        only_console = not (doc["tools"].get(name) or {}).get("protect") and name in from_console
        t = doc["tools"].get(name) or {"protect": False}
        if (not t.get("protect") and not only_console) or not rs:
            continue
        have = list(t.get("disclose") or [])
        uses = field_uses(rs, agent, name)
        for fld in [x for x in C.sendable_fields(rs, agent, name) if x not in have]:
            out(f"Change     {name} would also send: {field_words(fld)}")
            out(f"           needed by: {'; '.join(uses.get(fld, []))}")
            if not prompt.person:
                wait.append(f"{name}: {field_words(fld)}")
                continue
            if prompt.confirm(
                f"Send {field_words(fld)} to signafAIde for {name}? It is kept 30 days, admins only.", False
            ):
                have.append(fld)
                changes.append(name)
            else:
                wait.append(f"{name}: {field_words(fld)}")
        if have:
            t["disclose"] = have
            if only_console:
                # A version 2 file lists fields only on a protected tool, so a client before 0.5.2
                # still reads it: the checks file now protects the tool too.
                t["protect"] = True
                doc["tools"][name] = t
                now_file.append(name)
    v1 = f is not None and C.checks_file_version(f) == 1
    if changes or v1:
        write_checks_file(p, doc)
        rec.checks.forget()
        what = [
            f"{n} sends {', '.join(field_words(x) for x in doc['tools'][n]['disclose'])}"
            for n in dict.fromkeys(changes)
        ]
        out(
            f"Changed    {p.name}     "
            + "; ".join(
                (["now version 2 (each tool Protected or Not protected, On or Calibrating)"] if v1 else []) + what
            )
        )
        for n in now_file:
            out(
                f"           {n} was protected from the console only; {p.name} now protects it too (a checks file lists the fields to send only for a protected "
                "tool), so Unprotect in the console no longer unprotects it"
            )
        out(
            "Commit it. Until then, a call a rule needs one of these fields for is blocked and the error says to run pull."
        )
    else:
        out(f"Checks     {p.name} is up to date")
    if wait:
        out(
            f"Not sent   {', '.join(wait)}"
            + (" (you said no)" if prompt.person else ": run signafaide pull at a terminal to approve them")
        )
    return code


# --- start-fresh -------------------------------------------------------------------------------


def fresh_from(rec: Any, agent: str) -> Optional[str]:
    try:
        v = json.loads((rec.state.home / "fresh.json").read_text()).get(agent)
        return v if isinstance(v, str) else None
    except (OSError, ValueError, AttributeError):
        return None


def start_fresh(rec: Any, agent: str) -> str:
    rec.state.ensure()
    p = rec.state.home / "fresh.json"
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError):
        doc = {}
    t = (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
    )
    doc[agent] = t
    p.write_text(json.dumps(doc, indent=2) + "\n")
    return t


# --- prove -------------------------------------------------------------------------------------


def _call_words(inp: Any) -> str:
    if not isinstance(inp, dict):
        return "" if inp is None else json.dumps(inp)[:30]
    vals = [(k, v) for k, v in inp.items() if isinstance(v, (int, float, str)) and not isinstance(v, bool)]
    amount = next(
        ((k, v) for k, v in vals if any(x in k.lower() for x in ("amount", "total", "value", "price", "sum", "cost"))),
        None,
    )
    ccy = next(((k, v) for k, v in vals if "currency" in k.lower() or "ccy" in k.lower()), None)
    if amount:
        a = number_words(json.dumps(amount[1])) if not isinstance(amount[1], str) else amount[1]
        return f"{a}{' ' + str(ccy[1]) if ccy else ''}"
    return " ".join(f"{k}={str(v)[:20]}" for k, v in vals[:2])


def _fate(d: dict, o: Optional[dict]) -> Tuple[str, str]:
    ch = d["envelope"].get("checks")
    g = (d.get("receipt") or {}).get("ruling")
    oc = (o or {}).get("envelope", {}).get("checks")
    ran = (oc.get("ran") is not False) if isinstance(oc, dict) else o is not None
    if isinstance(ch, dict) and ch.get("result") == "block":
        e = next((x for x in ch["results"] if x["result"] == "block"), {})
        if e.get("check") == "rule" and e.get("set") != "local":
            # The client held the signed rule set and blocked the call itself: the witness never ruled on it.
            v = next((x.get("version") for x in ch.get("rules") or [] if x.get("set") == e.get("set")), None)
            return "blocked", f"here under signed rule set version {v if v is not None else '?'}; it did not run"
        if e.get("check") == "rule":
            return "blocked", "here by the rules on this machine; it did not run"
        return "blocked", f"here by the {e.get('check', 'local')} check; it did not run"
    if isinstance(g, dict) and g.get("ruling") == "block":
        return "blocked", "by the signafAIde witness" + (", but it ran" if ran else "; it did not run")
    if isinstance(g, dict) and g.get("ruling") == "allow":
        if g.get("excepted"):
            return "allowed", "by signafAIde, by exception"
        if g.get("would_block"):
            return "allowed", "by signafAIde; a Calibrating rule would have blocked it"
        return "allowed", "by signafAIde"
    if isinstance(ch, dict) and ch.get("strict"):
        return ("ran", "no ruling yet (Let it run)") if ran else ("stopped", "no ruling, it did not run")
    return "recorded", "not protected" if ch else "before protection"


def _links_file(rec: Any) -> Path:
    """Links ``prove`` made, kept so a second ``prove`` reuses an active one."""
    return Path(rec.state.home) / "auditor-links.json"


def _kept_links(rec: Any) -> List[dict]:
    try:
        doc = json.loads(_links_file(rec).read_text())
        return (
            [x for x in doc if isinstance(x, dict) and isinstance(x.get("url"), str)] if isinstance(doc, list) else []
        )
    except (OSError, ValueError):
        return []


def _proof_inputs(rec: Any, agent: str) -> Tuple[dict, Optional[dict]]:
    """The agent's §2.5 manifest (its keys only) and its newest signed head: both public, and
    already on this machine, so the auditor's browser check is complete."""
    allk = rec.state.export_agent_keys()
    keys = {"format": allk["format"], "keys": [k for k in allk["keys"] if k["agent"] == agent]}
    head = None
    for p, envs in (rec.state.heads() or {}).items():
        for e, agents in envs.items():
            if agent in agents:
                head = {p: {e: {agent: agents[agent]}}}
    return keys, head


def auditor_link_for(
    rec: Any, agent: str, tool: Optional[str], start: Optional[str], days: Optional[int] = None
) -> Union[Tuple[dict, bool], str]:
    """§6 ``POST /v1/auditor-links`` as ``prove`` asks it: reuse an active link for the same agent,
    tool and start; else ask for *days* (default 30, then the longest the plan allows), with the
    agent's keys and head. Returns (link, reused), or why there is none."""
    import datetime as _dt

    soon = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    kept = _kept_links(rec)
    same = lambda x: (
        x.get("agent") == agent and x.get("tool") == tool and x.get("from") == start and x.get("witness") == rec.url
    )  # noqa: E731
    hit = next((x for x in kept if same(x) and (not x.get("expires_at") or x["expires_at"] > soon)), None)
    if hit is not None and days is None:
        return hit, True
    keys, head = _proof_inputs(rec, agent)
    with_keys = bool(keys["keys"])
    want = days or 30
    link = None
    client = rec.client(timeout=15)
    for _ in range(3):
        body = {"agent": agent, **({"tool": tool} if tool else {}), "from": start, "days": want}
        if with_keys:
            body["agent_keys"] = keys
            if head:
                body["head"] = head
        try:
            link = client.auditor_link(body)
            break
        except SignafaideError as e:
            if e.code == "not_found" and re.search(r"route|endpoint", str(e), re.I):
                return "this witness does not make auditor links from the command line yet"
            if e.code == "not_found":
                return f"the witness did not make the link ({e})"
            err = (e.body or {}).get("error") or {}
            m = re.search(r"within (\d+) days?", str(e))
            mx = err.get("max_days") if isinstance(err.get("max_days"), int) else (int(m.group(1)) if m else None)
            if e.code == "plan_required" and days is None and mx and 1 <= mx < want:
                want = mx
                continue
            if e.code == "bad_request" and with_keys and re.search(r"agent_keys|head", str(e)):
                with_keys = False  # a witness that does not take them yet: the link without them
                continue
            if e.code == "plan_required" and days is not None and mx:
                return f"the witness did not make the link: this plan's links last at most {mx} days (signafaide prove --days {mx})"
            return f"the witness did not make the link ({e})"
    if not isinstance(link, dict) or not link.get("url"):
        return "the witness answered without a link"
    if not with_keys:
        link = {**link, "agent_keys": False}
    try:
        rest = [x for x in kept if not same(x) and (not x.get("expires_at") or x["expires_at"] > soon)]
        _links_file(rec).parent.mkdir(parents=True, exist_ok=True)
        _links_file(rec).write_text(
            json.dumps(rest + [{**link, "agent": agent, "tool": tool, "from": start, "witness": rec.url}], indent=2)
            + "\n"
        )
    except OSError:
        pass  # not kept: the next prove asks again
    return link, link.get("reused") is True


def _reused_link_lines(rec: Any, link: dict, days: int, tool: Optional[str]) -> List[str]:
    """Said when ``prove --days N`` got the link made earlier back instead of a new one: plainly
    that it is the earlier link and until when, why, and how to get a new one."""
    sandbox = False
    try:
        sandbox = (rec.client(timeout=10).project() or {}).get("claimed") is False
    except Exception:  # unknown: said without the plan
        pass
    until = f", open until {_when(link['expires_at'])[:-6]}" if link.get("expires_at") else ""
    why = (
        "an unclaimed sandbox's plan allows one active link"
        if sandbox
        else "the witness gives this API key its open link again for the same agent, tool and start"
    )
    return [
        f"           You asked for {days} {'day' if days == 1 else 'days'}: this is not a new link. The link made earlier is reused{until}, because {why}.",
        f"           For a new link: {'keep the sandbox (the claim link from init), then ' if sandbox else ''}revoke this one in the console "
        f"({site_of(rec.url)}, Share with an auditor), then run signafaide prove{' ' + tool if tool else ''} --days {days} again.",
    ]


def run_prove(
    rec: Any,
    prompt: Prompter,
    out: Out,
    tool: Optional[str] = None,
    agent: Optional[str] = None,
    files: bool = False,
    content: Optional[bool] = None,
    all_: bool = False,
    dir_: Optional[Path] = None,
    days: Optional[int] = None,
) -> int:
    """``signafaide prove [tool]``: the link (or files) for an auditor, and what they show."""
    chains = chains_by_agent(rec)
    decl = declared_name(tool) if tool else None
    if agent is None:
        if decl:
            agent = next((a for a, (_, rs) in chains.items() if any(r["envelope"]["name"] == decl for r in rs)), None)
        if agent is None:
            agent = next(iter(chains)) if len(chains) == 1 else rec.default_agent
    if agent not in chains:
        out(f"No records of agent {agent} here yet: run the agent first (`signafaide status` lists the agents).")
        return 1
    start = None if all_ else fresh_from(rec, agent)
    recs = [r for r in chains[agent][1] if not start or r["envelope"]["time"] >= start]
    calls: List[List[Any]] = []
    by_hash: Dict[str, List[Any]] = {}
    for r in recs:
        e = r["envelope"]
        if e["kind"] == "decision" and not e["name"].startswith("signafaide.") and (not decl or e["name"] == decl):
            c = [r, None]
            calls.append(c)
            if not r.get("draft"):
                by_hash[record_hash(r)] = c
        elif e["kind"] == "outcome" and e.get("ref") in by_hash:
            by_hash[e["ref"]][1] = r
    what = f"{tool} (agent {agent})" if tool else f"agent {agent}"
    env = "Live" if (rec.api_key or "").startswith("sfa_live_") else "Sandbox" if rec.api_key else "this machine only"
    t0 = calls[0][0]["envelope"]["time"] if calls else (recs[0]["envelope"]["time"] if recs else None)
    t1 = calls[-1][0]["envelope"]["time"] if calls else (recs[-1]["envelope"]["time"] if recs else None)
    span = f", {_when(t0)} to {_hhmm(t1) if t1[:10] == t0[:10] else _when(t1)} UTC" if t0 and t1 else ""
    out(f"Proof of {what}, {env}{span}")
    out("")
    if not files:
        link, why, reused = None, "", False
        if not rec.api_key:
            why = "these records are on this machine only (no API key), so there is no link"
        else:
            got = auditor_link_for(rec, agent, decl, start, days)
            if isinstance(got, str):
                why = got
            else:
                link, reused = got
        if isinstance(link, dict) and link.get("url"):
            out(
                "Send this link to your auditor (made earlier, still open):"
                if reused
                else "Send this link to your auditor:"
            )
            until = f", until {_when(link['expires_at'])[:-6]}" if link.get("expires_at") else ""
            out(f"           {link['url']}   read only{until}")
            if reused and days is not None:
                for line in _reused_link_lines(rec, link, days, tool):
                    out(line)
            if link.get("agent_keys") is True:
                out("           They can check it in their browser; nothing to install.")
            else:
                out("           The witness did not keep this agent's public keys with the link, so the browser check")
                out("           cannot check the agent's signatures on its own. Give your auditor the keys too:")
                out(
                    "           signafaide keys export -o agent-keys.json   (attach it in the console, Share with an auditor)"
                )
        else:
            out(f"No link: {why}.")
            out(
                f"           Make one in the console ({site_of(rec.url)}, Share with an auditor), or give files: signafaide prove{' ' + tool if tool else ''} --files"
            )
        out("")
    out("What it shows")
    out(f"  Calls      {len(calls)}, each signed by {agent}" + (" and witnessed by signafAIde" if rec.api_key else ""))
    for d, o in calls[-10:]:
        fate, by = _fate(d, o)
        out(
            f"               {d['envelope']['time'][11:19]}  {fate.ljust(9)} {_call_words((d.get('content') or {}).get('input')).ljust(12)} {by}"
        )
    if len(calls) > 10:
        out(f"               (the last 10 of {len(calls)})")
    rs = rec.checks.held_rules()
    if rs:
        rules = [
            r
            for r in rs["rules"]
            if (C.applies(r, agent, decl) if decl else (r["agents"] is None or agent in r["agents"]))
        ]
        out(f"  Rules      version {rs['version']}, {_when(rs['issued'], False)}, signed by signafAIde")
        rulings = [(d.get("receipt") or {}).get("ruling") for d, _ in calls]
        rulings = [g for g in rulings if isinstance(g, dict)]
        for r in rules:
            state = C.rule_state(rs, r) if rs["mode"] == "enforce" else "calibrating"
            here = sum(
                1
                for d, _ in calls
                if any(
                    e.get("check") == "rule"
                    and e.get("set") == rs["set"]
                    and e.get("result") == "block"
                    and r["id"] in e.get("matched", [])
                    for e in ((d["envelope"].get("checks") or {}).get("results") or [])
                )
            )
            blocked = here + sum(1 for g in rulings if g["ruling"] == "block" and r["id"] in g["matched"])
            would = sum(
                1
                for g in rulings
                if r["id"] in (g.get("would_block") or [])
                or (g["mode"] == "watch" and g.get("enforce_ruling") == "block" and r["id"] in g["matched"])
            )
            counts = f"blocked {blocked}" if state == "on" else f"would have blocked {would}"
            out(f"               {state_word(state).ljust(12)} {rule_words(r)}    {counts}")
            for x in r.get("exceptions") or []:
                out(
                    f'               {"".ljust(12)} Allowed by exception: {field_words(x["field"])} is {json.dumps(x["value"])}, "{x["reason"]}", since version {x["since"]}'
                )
    else:
        out(
            "  Rules      none held from signafAIde"
            + ("; the rules on this machine are in the checks file" if (_file(rec) or {}).get("rules") else "")
        )
    first = next((i for i, (d, _) in enumerate(calls) if (d["envelope"].get("checks") or {}).get("strict") is True), -1)
    before = (calls if rs else []) if first < 0 else calls[:first]
    subject = tool or agent
    if before:
        span = _hhmm(before[0][0]["envelope"]["time"]) + (
            f" to {_hhmm(before[-1][0]['envelope']['time'])}" if len(before) > 1 else ""
        )
        was = "was" if len(before) == 1 else "were"
        out(
            f"  Before     {plural(len(before), f'call of {subject}', f'calls of {subject}')} ({span}) {was} recorded before "
            f"{'any rule applied' if first < 0 else 'it was protected'}. {'It' if len(before) == 1 else 'They'} ran"
        )
        out("             with no rules, and your auditor will see them. That is honest, not an error.")
        out(f"             To start a fresh record from now: signafaide start-fresh {agent}")
        out("             (the old record is kept and can still be proved)")
    else:
        out(f"  Before     none: {subject} was protected before its first call")
    # The declaration in the chain, read as ``verify`` reads it (§7 coverage); else this machine's tool list.
    cov = coverage([(r["envelope"]["seq"], r["envelope"]["kind"], r["envelope"]["name"]) for r in chains[agent][1]])
    declared: Dict[str, bool] = {t["name"]: t["recorded"] for t in cov["declared"]}
    if not declared:
        for tools in rec.state.tool_sources(agent).values():
            for n, r in tools.items():
                declared[declared_name(n)] = declared.get(declared_name(n), False) or bool(r)
    f = _file(rec)
    prot = len(protected_names(rec, f, chains[agent][1]))
    if declared:
        rcd = sum(1 for x in declared.values() if x)
        out(
            f"  Tools      {agent} has {plural(len(declared), 'tool')}, {'all ' + str(rcd) if rcd == len(declared) else rcd} recorded, {prot} protected"
        )
    else:
        out(
            f"  Tools      {agent} has not declared its tool list (declare_tools), so the proof cannot show every tool is recorded"
        )
    # Where each protected tool's protection comes from (§8, SDK 0.5.2): never a surprise.
    now_protected = sorted(n for n in protected_names(rec, f, chains[agent][1]) if not decl or n == decl)
    if now_protected:
        in_code = protected_in_code(rec)
        held = rec.checks.held_rules()

        def src(n: str) -> List[str]:
            got = (
                (["code"] if n in in_code else [])
                + (["checks_file"] if f and C.tool_settings(f, n)["strict"] else [])
                + (["console"] if C.console_protects(held, n) else [])
            )
            return got or ["code"]

        out(
            "  Protected  "
            + "; ".join(f"{n} {C.source_words(src(n), held['version'] if held else None)}" for n in now_protected)
        )
    from . import verify

    try:
        report = verify(None, offline=True)
    except Exception as e:
        report = None
        out(f"  Record     could not be checked here: {e}")
    if report is not None:
        unsent = sum(1 for r in recs if not r.get("receipt"))
        if not report.ok:
            out(f"  Record     NOT intact: {report.result_line} (run signafaide verify for the details)")
        elif not rec.api_key:
            out(
                "  Record     Every record is present and unaltered on this machine; none is witnessed yet (no API key)."
            )
        elif unsent:
            out(
                f"  Record     Every record is present and unaltered. {plural(unsent, 'record is', 'records are')} not co-signed yet: run signafaide flush."
            )
        elif any(c.status == "pending" for c in report.checks):
            out("  Record     Every record is present and unaltered. Some records are waiting for their")
            out("             public timestamp, normal for the last hour; the link updates by itself.")
        else:
            out("  Record     Every record is present and unaltered.")
    out("")
    if not files:
        out(f"Want files instead of a link? signafaide prove{' ' + tool if tool else ''} --files")
        out(f"  writes proof/{tool or agent}/ and the command an auditor runs to check them offline")
        return 1 if report is not None and not report.ok else 0
    if not rec.api_key:
        out("Files need the witness's pack (an API key): run signafaide protect or signafaide init first.")
        return 1
    d = dir_ or (Path(rec.state.root) / "proof" / (tool or agent))
    d.mkdir(parents=True, exist_ok=True)
    rec.flush()
    pack = rec.client(timeout=60).export(agent, start)
    f = _file(rec)
    named = {
        x["hash"]
        for r in pack.get("records", [])
        for x in ((r.get("envelope") or {}).get("checks") or {}).get("rules") or []
        if x.get("set") == "local"
    }
    if f and f.get("rules") and C.local_rules_errors(f["rules"]) is None:
        h = hash_json(f["rules"])
        if h in named:
            pack["local_rules"] = [{"hash": h, "rules": f["rules"]}]
    written = ["pack.json", "agent-keys.json", "head.json"]
    (d / "pack.json").write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n")
    (d / "agent-keys.json").write_text(json.dumps(rec.state.export_agent_keys(), indent=2) + "\n")
    (d / "head.json").write_text(json.dumps(rec.state.heads(), indent=2) + "\n")
    if content is None and prompt.person:
        content = prompt.confirm(
            "Your auditor can also see what the calls said, from this machine's own copy. "
            "signafAIde still only receives the fields it was sent. Include it?",
            False,
        )
    if content:
        lines = [
            json.dumps(
                {"envelope": r["envelope"], "content": r.get("content"), "salt": r.get("salt")}, ensure_ascii=False
            )
            for r in recs
            if "content" in r and not r.get("draft")
        ]
        (d / "content.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""))
        written.append("content.jsonl")
    try:
        rel = d.relative_to(rec.state.root)
    except ValueError:
        rel = d
    out(f"Wrote {rel}/  {' '.join(written)}")
    out("Your auditor checks them with the standalone verifier (no account, no SDK), one of:")
    for line in auditor_commands(rec.url, "agent-keys.json", " --content content.jsonl" if content else ""):
        out(f"  {line}")
    out(f"or with the signafaide-verify binary and the same arguments: {AUDITOR_DOCS_URL}")
    return 0
