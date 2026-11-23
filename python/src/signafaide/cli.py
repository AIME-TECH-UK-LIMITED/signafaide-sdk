"""``signafaide`` command line. Add a command with ``@command``."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import _claim, runtime
from . import KeysRequired
from . import verify as run_verify
from ._version import __version__
from ._plural import plural
from .http import SignafaideError
from .state import StateError

Handler = Callable[[argparse.Namespace], int]

#: How ``protect``, ``pull`` and ``prove`` ask: a person at a terminal, else nobody (defaults only,
#: never On, never a new field). Tests set their own.
make_prompter: Optional[Callable[[bool], "Any"]] = None


def _prompter(yes: bool = False) -> Any:
    from .protect_cli import FlagPrompter, TerminalPrompter

    if make_prompter is not None:
        return make_prompter(yes)
    return TerminalPrompter() if sys.stdin.isatty() else FlagPrompter(yes)


COMMANDS: Dict[str, Tuple[str, Callable[[argparse.ArgumentParser], None], Handler]] = {}


def command(name: str, help: str, args: Callable[[argparse.ArgumentParser], None] = lambda p: None):
    def register(fn: Handler) -> Handler:
        COMMANDS[name] = (help, args, fn)
        return fn

    return register


def _recorder() -> runtime.Recorder:
    return runtime.configure(quiet=True, via="cli")


def _mask(key: Optional[str]) -> str:
    return f"{key[:13]}..." if key else "none"


def _site(url: str) -> str:
    """The website of a witness: https://api.signafaide.co.uk -> https://signafaide.co.uk."""
    import urllib.parse

    u = urllib.parse.urlsplit(url)
    host = u.netloc[4:] if u.netloc.startswith("api.") else u.netloc
    return f"{u.scheme}://{host}"


#: One plain line each, never in --json output. The verify one shows at most once a week.
UPGRADE_LIMIT = "upgrade: paid plans take more live records a month and keep recording past them: {site}/pricing"
UPGRADE_VERIFY = "upgrade: paid plans add a verification report for a period and longer auditor links: {site}/pricing"
HINT_EVERY_S = 7 * 86_400


def _upgrade_after_verify(rec: runtime.Recorder) -> None:
    """After a passing verify on a live key of a Free organisation: one line, once a week."""
    from datetime import datetime, timezone

    if not (rec.api_key or "").startswith("sfa_live_"):
        return
    cfg = rec.state.config()
    last = cfg.get("upgrade_hint")
    now = datetime.now(timezone.utc)
    try:
        if last and (now - datetime.fromisoformat(str(last).replace("Z", "+00:00"))).total_seconds() < HINT_EVERY_S:
            return
    except ValueError:
        pass
    try:
        if (rec.client(timeout=3).usage() or {}).get("plan") != "free":
            return
        rec.state.save_config(upgrade_hint=now.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    except (SignafaideError, StateError):
        return
    print(UPGRADE_VERIFY.format(site=_site(rec.url)))


def _upgrade_at_limit(rec: runtime.Recorder, errors) -> None:
    """When a live key hit the Free plan's monthly allowance: one line."""
    if (rec.api_key or "").startswith("sfa_live_") and any(
        getattr(e, "code", None) == "quota_exceeded" for e in errors
    ):
        print(UPGRADE_LIMIT.format(site=_site(rec.url)))


@command(
    "init",
    "opt in to the witness: create a free sandbox if there is no API key (no account, email or card), print the claim link "
    "and how long an unclaimed sandbox is kept. "
    "The witness is https://api.signafaide.co.uk unless SIGNAFAIDE_URL names another (a self-hosted witness, or http://127.0.0.1:7474 "
    "for a local one); an existing key is read from SIGNAFAIDE_API_KEY. Adds .signafaide/ and .env to .gitignore",
)
def cmd_init(a: argparse.Namespace) -> int:
    rec = _recorder()
    rec.remember_agent()
    rec.state.ignore_in_git()
    had = rec.api_key
    key = rec.create_sandbox()
    sandbox = rec.state.sandbox() or {}
    # A sandbox made just now is described from the witness's own answer; an existing one is asked about.
    view = _claim.sandbox_view(rec, refresh=bool(had))
    if not had:
        print(
            f"sandbox ready at {rec.url}, key saved to {rec.state.root / '.env'}; claim it at {sandbox.get('claim_url')}"
        )
        for line in _claim.claim_notes(view) if view else []:
            print(line)
        print(runtime.terms_notice(runtime.legal_links(sandbox, sandbox.get("url") or rec.url)))
        print(
            "from now on record hashes (never content) are sent for co-signature and public timestamps; "
            "records written before now ship with their original times on the next run or with `signafaide flush`"
        )
    elif view:
        first, *rest = _claim.claim_lines(view, rec.state.root)
        print(
            f"key found ({_mask(key)}); {first}"
            if view["claimed"] or _claim.sandbox_gone(view)
            else f"key found ({_mask(key)}); claim the sandbox at {view['claim_url']}"
        )
        for line in rest:
            print(line)
    else:
        print(f"key found ({_mask(key)}, env {runtime._env_of(key)}); nothing to create")
    _init_checks(rec)
    from .agent_note import note_what, offer_note

    for f, what in offer_note(Path(rec.state.root), _prompter(), print):
        print(f"agents: {f} {what}, with {note_what(f, what, True)}")
    return 0


def _init_checks(rec: runtime.Recorder) -> None:
    """Turn tool-call checks on in watch mode (§8): write the checks file when there is none, and
    say which checks are on, in which mode, which tools are strict and which fields leave the machine."""
    from .checks import FILE_CHECKS, default_checks_file
    from .checks_runtime import checks_path

    path = checks_path(rec.state.root)
    if path is None:
        print("tool-call checks: off (SIGNAFAIDE_CHECKS=0)")
        return
    how = (
        f'tool-call checks: change it in {path}: `"mode": "enforce"` is On (it blocks) and `"watch"` is Calibrating (it only notes), `"strict": true` on a tool protects it (it asks the witness for a ruling; `false` is Not protected), `"fail": "closed"` is Stop and `"open"` is Let it run if signafAIde can\'t be reached, `"disclose"` lists the fields of its '
        "arguments that may leave the machine; `signafaide checks status` shows what is on, which tools are protected and which fields leave"
    )
    if not path.exists():
        path.write_text(json.dumps(default_checks_file(), indent=2) + "\n")
        print(
            f"tool-call checks: on, Calibrating ({path.name}, commit it with the code): {', '.join(FILE_CHECKS)} and your rules note what they find and never block. "
            "No tool is protected and no field of a tool's arguments leaves the machine; only tool fingerprints do."
        )
    else:
        lines, _ = rec.checks.status()
        print("tool-call checks: " + lines[0].removeprefix("checks: "))
        # Which tools are strict and which fields leave the machine, as the file says.
        for line in lines[1:]:
            if line.startswith(("protected tool ", "PROBLEM")):
                print("tool-call checks: " + line)
        if not any(line.startswith("protected tool ") for line in lines):
            print(
                "tool-call checks: no tool is protected; only tool fingerprints leave the machine unless a tool lists fields in disclose"
            )
    print(how)


@command(
    "status",
    "one line per tool (recorded, protected, proof), then key and env, agents, last receipt, outbox size, quota; BLOCKED chains (exit 1 when any)",
)
def cmd_status(a: argparse.Namespace) -> int:
    from .tool_commands import status_table

    rec = _recorder()
    table = status_table(rec)
    for line in table:
        print(line)
    if table:
        print()
    s = rec.status()
    if s["test_mode"]:
        print(
            "test mode: records go to a temporary folder and nothing is sent (SIGNAFAIDE_TEST, or pytest); SIGNAFAIDE_TEST=0 turns it off"
        )
    if s["api_key_invalid"]:
        print(
            "key: SIGNAFAIDE_API_KEY is set but is not a signafAIde key (sfa_test_ or sfa_live_ and 32 letters or digits); nothing is sent until it is fixed"
        )
    else:
        print(
            f"key: {_mask(s['api_key'])}"
            + (
                f" (env {s['env']})"
                if s["env"]
                else "; records stay on this machine (signed and chained, nothing is sent). `signafaide init` creates a free sandbox and sends hashes; or set SIGNAFAIDE_API_KEY"
            )
        )
    print(f"service: {s['url']}")
    project: dict = {}
    answered = refused = False
    if s["api_key"]:
        try:
            project = rec.client(timeout=5).project() or {}
            answered = True
        except SignafaideError as e:
            project = {}
            refused = e.code == "invalid_key"
    name = project.get("name") if isinstance(project.get("name"), str) and project.get("name") else None
    if project.get("project"):
        print(
            f"project: {name} ({project['project']}, {project.get('env')})"
            if name
            else f"project: {project['project']} ({project.get('env')})"
        )
    print(f"home: {s['home']}")
    if not s["chains"]:
        print("chains: none yet; decorate a function with @signafaide.record")
    blocked = []
    for c in s["chains"]:
        last = (
            f"last receipt seq {c['receipt_seq']} at {c['receipt_time']}"
            if c["receipt_seq"]
            else "drafts, signed for the project when they ship"
            if c["chain"].startswith("_pending/")
            else "no receipt yet"
        )
        other = "" if c["current"] or not c["waiting"] else f"; {c['waiting']} waiting for the key of that project"
        shown = c["chain"]
        if name and shown.startswith(f"{project['project']}/"):
            shown = f"{name}/{shown[len(project['project']) + 1 :]}"
        print(
            f"chain {shown}: key {c['key_id']}, {plural(c['records'], 'record')}, {last}{other}"
            + ("; BLOCKED" if c["blocked"] else "")
        )
        if c["blocked"]:
            b = c["blocked"]
            blocked.append(
                f"BLOCKED {c['chain']}: {b['reason']}; {plural(b['records'], 'record')} cannot ship. Next: {b['next']}"
            )
    for c in s["chains"]:
        for line in c["telemetry"]:
            print(f"note: {line}")
    if any(c["agent"] == rec.default_agent for c in s["chains"]):
        print(
            f'note: agent "{rec.default_agent}" is named after the project folder; give agents explicit names in production '
            '(@signafaide.record(agent="claims-bot"))'
        )
    for h in s["held"]:
        print(
            f"held: {h['chain']}: {plural(h['records'], 'record')} set aside by `signafaide repair` in {h['file']} (kept, verifiable locally, not co-signed)"
        )
    print(
        f"outbox: {plural(s['outbox'], 'record')} waiting"
        + ("; run `signafaide flush`" if s["outbox"] and not blocked else "")
    )
    for line in blocked:
        print(line)
    # One agent name = one key: say so when the witness holds another key for an agent here.
    if answered and project.get("project"):
        from .tool_commands import key_mismatch

        for agent in dict.fromkeys(c["agent"] for c in s["chains"] if c.get("current")):
            why = key_mismatch(rec, agent)
            if why:
                print(f"KEY {why}")
    if s["api_key"]:
        try:
            u = rec.client(timeout=5).usage()
            print(f"quota: {u.get('used')} of {u.get('quota')} used in {u.get('period')}")
            q, used = u.get("quota"), u.get("used")
            if (
                u.get("plan") == "free"
                and isinstance(q, int)
                and isinstance(used, int)
                and used >= q
                and s["api_key"].startswith("sfa_live_")
            ):
                print(UPGRADE_LIMIT.format(site=_site(rec.url)))
        except SignafaideError as e:
            print(f"quota: unknown ({e})")
    # The claim step, from the answer above: the link and why to claim, the time left when the
    # witness gave it, "done" once claimed, and how to carry on when the sandbox is gone.
    view = _claim.sandbox_view(rec, answer=project if answered else None, refused=refused)
    for line in _claim.claim_lines(view, rec.state.root) if view else []:
        print(line)
    return 1 if blocked else 0


def _repair_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--agent", help="only this agent (default: every blocked chain)")
    p.add_argument("--dry-run", action="store_true", help="say what would be done, change nothing")


@command(
    "repair",
    "set aside records the witness can never take (clock went back, revoked key, clock ahead), rotate the agent's key and "
    "start a new segment; history is kept and verifiable",
    _repair_args,
)
def cmd_repair(a: argparse.Namespace) -> int:
    rec = _recorder()
    done = rec.repair(agent=a.agent, dry_run=a.dry_run)
    if not done:
        print(
            f"nothing to repair{f' for agent {a.agent}' if a.agent else ''}: every chain can ship (`signafaide status` shows them)"
        )
        return 0
    for r in done:
        b = r["blocked"]
        print(f"{r['chain']}: {b['reason']}")
        if a.dry_run:
            print(
                f"  would set aside seq {b['seq']} onwards ({plural(b['records'], 'record')}), give the agent a new key and write a signafaide.repair note"
            )
            continue
        print(
            f"  set aside {plural(r['records'], 'record')} in {r['held']} (kept; `signafaide verify` still checks their signatures and content hashes)"
        )
        print(
            f"  new key {r['new_key']} signs from now on; the old key is retired on the witness at the next send"
            if r["new_key"]
            else "  the key comes from a secret store: rotate it there if it was revoked"
        )
        print(
            f"  note {r['note'][:12]} (signafaide.repair) commits to the held records' hashes and ships with the next send"
        )
    if not a.dry_run:
        print(
            "next: `signafaide flush` sends the new segment, then `signafaide keys export` for your auditors (it lists the old and new keys)"
        )
    return 0


def _verify_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("pack", nargs="?", help="pack.json (default: the local .signafaide state)")
    p.add_argument("--keys", help="service keys file or URL (default: fetched from SIGNAFAIDE_URL)")
    p.add_argument("--trust-embedded-keys", action="store_true", help="use the service keys inside the pack")
    p.add_argument(
        "--agent-keys",
        help="the customer's agent keys from `signafaide keys export` (default: this project's own keys)",
    )
    p.add_argument(
        "--trust-embedded-agent-keys", action="store_true", help="use the agent keys inside the pack (not independent)"
    )
    p.add_argument(
        "--head",
        help="the customer's .signafaide/head.json (their newest receipt per agent, sent with the pack): proves no record was "
        "cut from the end of the pack (default: this project's own)",
    )
    p.add_argument(
        "--timestamp-check",
        "--bitcoin",
        dest="timestamp_check",
        default=None,
        help="explorer API that confirms public timestamps (default https://mempool.space/api)",
    )
    p.add_argument("--offline", action="store_true", help="do not look up public timestamps (they show NOT CHECKED)")
    p.add_argument("--content", help="chain .jsonl file or folder with the content (default: local .signafaide/chain)")
    p.add_argument(
        "--fail-on-pending-send",
        action="store_true",
        help="local state: also fail while records wait to be co-signed (for CI); a BLOCKED chain always fails",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")


@command("verify", "verify a pack or the local state; exit 0 PASS, 1 FAIL, 2 unreadable input", _verify_args)
def cmd_verify(a: argparse.Namespace) -> int:
    rec = _recorder()
    try:
        kw = {"timestamp_check": a.timestamp_check} if a.timestamp_check else {}
        report = run_verify(
            a.pack,
            keys=a.keys,
            trust_embedded_keys=a.trust_embedded_keys,
            agent_keys=a.agent_keys,
            trust_embedded_agent_keys=a.trust_embedded_agent_keys,
            head=a.head,
            offline=a.offline,
            content=a.content,
            fail_on_pending_send=a.fail_on_pending_send,
            **kw,
        )
    except (KeysRequired, SignafaideError, StateError, OSError, ValueError) as e:
        print(f"signafaide: {e}", file=sys.stderr)
        rec.event("verify")
        return 2
    # The sandbox's claim step goes with the result: as data in --json, as plain lines after a pass.
    view = _claim.sandbox_view(rec, refresh=not a.offline)
    print(
        json.dumps(report.to_dict() | ({"sandbox": _claim.sandbox_json(view)} if view else {}), indent=2)
        if a.json
        else str(report),
        flush=True,
    )
    rec.event("verify")
    if report.ok and not a.json:
        if view and not view["claimed"]:
            for line in _claim.claim_lines(view, rec.state.root):
                print(line)
        _upgrade_after_verify(rec)
    return 0 if report.ok else 1


def _keys_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "action",
        choices=["export", "create", "rotate"],
        help="export: write the agent-key manifest for auditors; create: make and register a key for a secret store, writing no record; "
        "rotate: give an agent a new key",
    )
    p.add_argument("--agent", help="create, rotate: the agent (default: this project's folder name)")
    p.add_argument(
        "--env", choices=["test", "live"], help="create, rotate: the key of this env (default: the API key's env)"
    )
    p.add_argument(
        "--print",
        dest="print_key",
        action="store_true",
        help="create: print the key file for a secret store and save nothing here",
    )
    p.add_argument("-o", "--output", help="export: output file (default agent-keys.json)")


@command(
    "keys",
    "export the agent public keys for auditors, make a key for a secret store, or rotate an agent's key",
    _keys_args,
)
def cmd_keys(a: argparse.Namespace) -> int:
    rec = _recorder()
    if a.action == "export":
        doc = rec.state.export_agent_keys()
        if not doc["keys"]:
            print("signafaide: no agent keys here yet; they are made with the first record", file=sys.stderr)
            return 1
        from .tool_commands import auditor_commands

        out = Path(a.output or "agent-keys.json")
        out.write_text(json.dumps(doc, indent=2) + "\n")
        print(
            f"wrote {out} ({plural(len(doc['keys']), 'key')}); give it to your auditors with pack.json and head.json: "
            + auditor_commands(rec.url, str(out))[0]
        )
        return 0
    agent = a.agent or rec.default_agent
    env = a.env or runtime._env_of(rec.api_key)
    if a.action == "create":
        if env not in ("test", "live"):
            print("signafaide keys create: --env must be test or live (or set SIGNAFAIDE_API_KEY)", file=sys.stderr)
            return 2
        r = rec.create_key(agent, env, a.print_key)
        if a.print_key:
            print(json.dumps(r["doc"], separators=(",", ":")), flush=True)
            print(
                f"signafaide: registered key {r['doc']['key_id']} for {agent} ({r['project']}, {env}); no record was written and nothing was saved here. "
                f"Store the line above in your secret store as {r['env_name']} and keep a backup: it is the only copy of the private key.",
                file=sys.stderr,
            )
        else:
            print(
                f"{agent}: registered key {r['doc']['key_id']} ({r['project']}, {env}) and saved it as {r['file']}; no record was written. "
                f"For a secret store, store that file's content as {r['env_name']}."
            )
        return 0
    old, new = rec.state.rotate_key(agent, "live" if env == "live" else "")
    print(
        f"{agent}: new key {new.key_id} signs from now on. Records the old key {old.key_id} signed earlier ship first; the next record then "
        "registers the new key, signed by the old one, and the service retires the old key at that moment"
    )
    return 0


def _export_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--agent", help="only this agent (default: every agent in the project)")
    p.add_argument("--from", dest="from_", help="RFC 3339 start time")
    p.add_argument("--to", help="RFC 3339 end time")
    p.add_argument(
        "-o", "--output", help="output file (default: <project>-pack.json, or <agent>-pack.json with --agent)"
    )


@command(
    "export",
    "download a verification pack of the whole project (every agent), or of one agent with --agent",
    _export_args,
)
def cmd_export(a: argparse.Namespace) -> int:
    rec = _recorder()
    agent = a.agent
    try:
        pack = rec.client(timeout=60).export(agent, a.from_, a.to)
    except SignafaideError:
        rec.event("export")
        raise
    n = len(pack.get("records") or [])
    out = Path(a.output or f"{agent or pack.get('project')}-pack.json")
    out.write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out} ({plural(n, 'record')}); check it with `signafaide verify {out}`", flush=True)
    if not n:
        print(
            f"signafaide export: agent '{agent}' has no records in this range; leave out --agent to export every agent (`signafaide status` lists them)"
            if agent
            else "signafaide export: this project has no records in this range, so the pack proves nothing",
            file=sys.stderr,
        )
    rec.event("export")
    return 0


def _replay_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--agent", help="agent name (default: the only agent with records here, else this project's folder name)"
    )
    p.add_argument("--from", dest="from_", help="YYYY-MM-DD or RFC 3339 start time")
    p.add_argument("--to", help="YYYY-MM-DD (inclusive) or RFC 3339 end time (exclusive)")
    p.add_argument("--record", help="one record hash (or a prefix of 8+ characters) and its decision or outcome")
    p.add_argument("--chain", help="chain id when the agent has several (<project>/<env>/<agent>)")
    p.add_argument("--keys", help="service keys file or URL (default: fetched from SIGNAFAIDE_URL)")
    p.add_argument("--html", help="also write a self-contained HTML page to this file")
    p.add_argument("--json", action="store_true", help="machine-readable output")


@command(
    "replay", "show what an agent saw and did, from the local chain, each record verified; exit 1 on FAIL", _replay_args
)
def cmd_replay(a: argparse.Namespace) -> int:
    from .replay import replay

    _recorder()
    r = replay(a.agent, since=a.from_, until=a.to, record=a.record, chain=a.chain, keys=a.keys)
    print(json.dumps(r.to_dict(), indent=2, ensure_ascii=False) if a.json else str(r), flush=True)
    if a.html:
        Path(a.html).write_text(r.to_html(), encoding="utf-8")
        print(f"wrote {a.html}", file=sys.stderr)
    return 0 if r.ok else 1


def _compare_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--module", required=True, help="the candidate: path/to/file.py:function or package.module:function")
    p.add_argument(
        "--agent", help="agent name (default: the only agent with records here, else this project's folder name)"
    )
    p.add_argument("--name", help="only decisions of this action or tool name")
    p.add_argument("--from", dest="from_", help="YYYY-MM-DD or RFC 3339 start time")
    p.add_argument("--to", help="YYYY-MM-DD (inclusive) or RFC 3339 end time (exclusive)")
    p.add_argument("--limit", type=int, help="only the newest N decisions")
    p.add_argument("--label", help="a name for this experiment in the console")
    p.add_argument("--chain", help="chain id when the agent has several")
    p.add_argument("--keys", help="service keys file or URL")
    p.add_argument("--upload", action="store_true", help="send the report to the service, hash-only")
    p.add_argument(
        "--values",
        action="store_true",
        help="with --upload: include recorded and candidate values (decisions stored with the service only)",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")


def load_candidate(spec: str) -> Callable:
    """``path/to/file.py:function`` or ``package.module:function``."""
    import importlib
    import importlib.util

    target, sep, fn = spec.rpartition(":")
    if not sep or not target or not fn:
        raise ValueError("--module must be path/to/file.py:function or package.module:function")
    try:
        if target.endswith(".py") or "/" in target:
            path = Path(target).resolve()
            spec_ = importlib.util.spec_from_file_location(path.stem, path)
            if spec_ is None or spec_.loader is None:
                raise ImportError(f"{target} is not a Python file")
            mod = importlib.util.module_from_spec(spec_)
            sys.path.insert(0, str(path.parent))
            spec_.loader.exec_module(mod)
        else:
            sys.path.insert(0, str(Path.cwd()))
            mod = importlib.import_module(target)
    except (ImportError, OSError, SyntaxError) as e:
        raise ValueError(f"cannot load the candidate {target}: {e}") from None
    out = getattr(mod, fn, None)
    if not callable(out):
        raise ValueError(f"{spec}: no function {fn!r} in {target}")
    return out


@command("compare", "re-run recorded decisions with a candidate function and compare the results", _compare_args)
def cmd_compare(a: argparse.Namespace) -> int:
    from .experiments import compare

    _recorder()
    r = compare(
        load_candidate(a.module),
        agent=a.agent,
        name=a.name,
        since=a.from_,
        until=a.to,
        limit=a.limit,
        chain=a.chain,
        keys=a.keys,
        label=a.label,
    )
    if a.upload:
        r.upload(values=True if a.values else None)
    print(
        json.dumps(r.to_dict() | ({"uploaded": r.uploaded} if r.uploaded else {}), indent=2, ensure_ascii=False)
        if a.json
        else str(r),
        flush=True,
    )
    return 0


@command("claim", "print the sandbox claim link again, why to claim it and how long an unclaimed sandbox has left")
def cmd_claim(a: argparse.Namespace) -> int:
    rec = _recorder()
    if (rec.api_key or "").startswith("sfa_live_"):
        print("this project uses a live key; there is nothing to claim")
        return 0
    view = _claim.sandbox_view(rec)
    if not view:
        print("no sandbox here; run `signafaide init` first", file=sys.stderr)
        return 1
    if view["claimed"]:
        print(_claim.CLAIM_DONE)
        return 0
    lines = _claim.claim_lines(view, rec.state.root)
    if _claim.sandbox_gone(view):
        for line in lines:
            print(line, file=sys.stderr)
        return 1
    # The link alone on the first line, for scripts; then why to claim and the time left.
    print(view["claim_url"])
    for line in lines[1:]:
        print(line)
    return 0


@command("flush", "ship the outbox now")
def cmd_flush(a: argparse.Namespace) -> int:
    rec = _recorder()
    r = rec.flush()
    blocked = next((e for e in r["errors"].values() if getattr(e, "blocked", False)), None)
    if blocked is not None:
        # The network here blocks the witness: one sentence for every chain, not one line each.
        print(str(blocked), file=sys.stderr)
    for agent, e in r["errors"].items():
        if blocked is None or not getattr(e, "blocked", False):
            print(f"{agent}: {e}", file=sys.stderr)
    if not rec.api_key:
        print(
            f"no API key: nothing was sent; {plural(r['left'], 'record')} stay local. Run `signafaide init` (or set SIGNAFAIDE_API_KEY) to send hashes"
        )
        return 0
    # Chains the service cannot take (too_old, chain_exists) stay on this machine: not "left to ship".
    local = sum(rec.state.draft_count(c) for c, e in r["errors"].items() if e.code in ("too_old", "chain_exists"))
    print(
        f"shipped {plural(r['shipped'], 'record')}, {r['left'] - local} left in the outbox"
        + (f"; {plural(local, 'record')} kept on this machine only (see above)" if local else "")
    )
    for b in rec.diagnose():
        print(f"BLOCKED {b['chain']}: {plural(b['records'], 'record')} cannot ship as they are. Next: {b['next']}")
    _upgrade_at_limit(rec, r["errors"].values())
    return 1 if r["errors"] else 0


def _checks_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "action",
        choices=["status", "approve"],
        help="status: what is on and whether each tool is On or Calibrating, the protected tools, the held rule set and list, any problem; "
        "approve <tool>: re-approve a changed tool (local approvals)",
    )
    p.add_argument("tool", nargs="?", help="approve: the tool's declared name")
    p.add_argument("--agent", help="approve: only this agent's approvals (default: every agent's)")


@command("checks", "tool-call checks: `checks status` (exit 1 on a problem), `checks approve <tool>`", _checks_args)
def cmd_checks(a: argparse.Namespace) -> int:
    rec = _recorder()
    if a.action == "approve":
        if not a.tool:
            print("signafaide checks approve: name the tool", file=sys.stderr)
            return 2
        agents = rec.checks.approve(a.tool, a.agent)
        held = rec.checks.held_rules()
        if held is not None and held["approved"] is not None:
            print(
                f"{a.tool}: the rule set approves tools (version {held['version']}); re-approve it in the console, which publishes a new version"
            )
            return 1
        if not agents:
            print(f"{a.tool}: no local approval held; its next call approves the description and schema it has then")
        else:
            print(
                f"{a.tool}: approval dropped for {', '.join(agents)}; its next call approves the description and schema it has then"
            )
        return 0
    lines, problem = rec.checks.status()
    for line in lines:
        print(line)
    return 1 if problem else 0


def _rules_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "action",
        choices=["pull", "show", "test", "publish"],
        help="pull: fetch the project's rule set now; show: print the held one; "
        "test <tool> <arguments JSON>: evaluate a call as the client does; publish <file>: save the file's rules as the next version, "
        "signed in (signafaide login), after you say yes at this terminal",
    )
    p.add_argument("tool", nargs="?", help="test: the tool's name; publish: the file")
    p.add_argument("arguments", nargs="?", help="test: the call's arguments, as JSON")
    p.add_argument("--agent", help="test: the agent (default: the project's default agent)")
    _url_arg(p)


@command(
    "rules",
    "the project's rule set: `rules pull`, `rules show`, `rules test <tool> <arguments JSON>`, `rules publish <file>`",
    _rules_args,
)
def cmd_rules(a: argparse.Namespace) -> int:
    from .session import person_witness

    rec = runtime.configure(quiet=True, via="cli", url=person_witness(a.url)) if a.url else _recorder()
    if a.action == "publish":
        if not a.tool:
            print("usage: signafaide rules publish <file>", file=sys.stderr)
            return 2
        from .protect_cli import run_rules_publish

        return run_rules_publish(rec, a.tool, _prompter(False))
    if a.action == "pull":
        print(rec.checks.forced_pull())
        return 1 if "rules" in rec.checks.problems else 0
    if a.action == "show":
        item = rec.checks.held_rules_item()
        if item is None:
            print(
                "no rule set held" + ("" if rec.api_key else " (no API key)") + "; `signafaide rules pull` fetches it"
            )
            return 1
        print(json.dumps(item["rules"], indent=2, ensure_ascii=False))
        return 0
    if not a.tool or a.arguments is None:
        print("signafaide rules test: give the tool and its arguments as JSON", file=sys.stderr)
        return 2
    args = json.loads(a.arguments)
    for line in rec.checks.test_call(a.tool, args, a.agent or rec.default_agent):
        print(line)
    return 0


def _protect_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "tool", nargs="?", help="protect this one tool (default: proposes the tools that pay, delete or send)"
    )
    p.add_argument("--tool", dest="tool_opt", metavar="NAME", help="the same as the tool argument")
    p.add_argument(
        "--limit-field",
        metavar="FIELD",
        help="with --above: block the tool when this field is above the number, without asking what to block",
    )
    p.add_argument("--above", metavar="NUMBER", help="with --limit-field: the limit")
    p.add_argument(
        "--local",
        action="store_true",
        help="rules only on this machine (the checks file); no account, signafAIde does not rule",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="without a terminal, accept the code change and the project note; rules then start Calibrating, "
        "no field is sent until `signafaide pull` at a terminal, and no sandbox is made",
    )
    p.add_argument("--dir", help="the project folder (default: this one)")
    _url_arg(p)


@command(
    "protect",
    "find your agent's tools, ask what to block, add @signafaide.protect to the code, make a free sandbox and save the rules; "
    "a rule is On only when you answer On at the terminal, every other rule starts Calibrating",
    _protect_args,
)
def cmd_protect(a: argparse.Namespace) -> int:
    from .protect_cli import run_protect

    tool = a.tool_opt or a.tool
    if a.tool_opt and a.tool and a.tool_opt != a.tool:
        print(f"signafaide protect: two tools named ({a.tool} and --tool {a.tool_opt}); name one", file=sys.stderr)
        return 2
    limit = None
    if a.limit_field is not None or a.above is not None:
        try:
            above = float(a.above) if a.above is not None else 0.0
        except ValueError:
            above = 0.0
        if not a.limit_field or not (above > 0 and math.isfinite(above)) or not tool:
            print(
                "signafaide protect: --limit-field <field> and --above <number above 0> go together, with the tool: "
                "protect --tool <name> --limit-field amount --above 1000",
                file=sys.stderr,
            )
            return 2
        limit = (a.limit_field, above)
    root = Path(a.dir).resolve() if a.dir else None
    from .session import person_witness

    rec = runtime.configure(
        quiet=True, via="cli", **({"root": root} if root else {}), **({"url": person_witness(a.url)} if a.url else {})
    )
    code, _ = run_protect(rec, Path(rec.state.root), _prompter(a.yes), print, tool=tool, local=a.local, limit=limit)
    return code


def _check_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("tool", nargs="?")
    p.add_argument(
        "fields",
        nargs="*",
        help="name=value (a value is JSON when it reads as JSON, else text; a/b=v sets a field inside an object)",
    )
    p.add_argument("--agent")
    p.add_argument(
        "--ci",
        action="store_true",
        help="list the tools that pay, delete, send, run commands, push code or edit secrets or config and are "
        "not protected, one line each with the fix; exit 1 when there is one, 0 when none. Reads the code and the checks file only: "
        "no account, no key, nothing sent",
    )
    p.add_argument(
        "--diff",
        metavar="BASE_REF",
        help="with --ci: only the tools added or changed since this git base (a pull request's base commit)",
    )
    p.add_argument(
        "--allow",
        action="append",
        metavar="TOOL",
        help="with --ci: a reviewed exception (or list it with its reason in "
        'signafaide.checks.json: "ci": {"allow": [{"tool", "reason"}]})',
    )
    p.add_argument("--dir", help="with --ci: the folder to check (default: this one)")
    p.add_argument("--json", action="store_true", help="with --ci: the result as JSON")


@command(
    "check",
    "a dry run of a tool call against the rules: records nothing, runs nothing; exit 1 when the call would be blocked. "
    "check --ci: exit 1 when a risky tool is not protected (for CI)",
    _check_args,
)
def cmd_check(a: argparse.Namespace) -> int:
    from .tool_commands import run_check

    if a.ci:
        from .ci_check import CiError, ci_check, ci_lines

        if a.tool is not None:
            print(
                "signafaide check --ci takes no tool; usage: signafaide check --ci [--diff BASE_REF] [--allow TOOL]... [--json]",
                file=sys.stderr,
            )
            return 2
        try:
            r = ci_check(Path(a.dir) if a.dir else Path.cwd(), base=a.diff, allow=a.allow or ())
        except CiError as e:
            print(f"signafaide check --ci: {e}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(r.to_json(), indent=2))
        else:
            for line in ci_lines(r):
                print(line)
        return 0 if r.ok else 1
    if a.diff is not None or a.allow or a.json or a.dir is not None:
        print("signafaide check: --diff, --allow, --dir and --json go with --ci", file=sys.stderr)
        return 2
    if a.tool is None:
        print(
            "usage: signafaide check <tool> <field>=<value>... [--agent X], or signafaide check --ci", file=sys.stderr
        )
        return 2
    lines, code = run_check(_recorder(), a.tool, a.fields, a.agent)
    for line in lines:
        print(line)
    return code


@command(
    "pull",
    "fetch the project's rules and update the checks file; asks before any new field of a protected tool is sent to signafAIde",
)
def cmd_pull(a: argparse.Namespace) -> int:
    from .tool_commands import run_pull

    return run_pull(_recorder(), _prompter(), print)


def _prove_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("tool", nargs="?")
    p.add_argument("--agent")
    p.add_argument(
        "--files",
        action="store_true",
        help="write proof/<tool>/ (pack, agent keys, head, and the content when you say so)",
    )
    p.add_argument("--content", action="store_true", default=None, help="with --files: include what the calls said")
    p.add_argument(
        "--all", action="store_true", help="from the agent's first record, not from `signafaide start-fresh`"
    )
    p.add_argument(
        "--days",
        type=int,
        help="how long the link works (default 30, or the longest your plan allows); an active link for the same "
        "tool is reused unless --days is given",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="make it even when this machine's agent key is not the one the witness holds",
    )


@command(
    "prove",
    "what to give your auditor: a read-only link (or files with --files), with the calls, the rules in words, "
    "what ran before protection and the tool coverage",
    _prove_args,
)
def cmd_prove(a: argparse.Namespace) -> int:
    from .tool_commands import run_prove

    if a.days is not None and not 1 <= a.days <= 3650:
        print("signafaide prove: --days takes a whole number of days from 1, e.g. --days 7", file=sys.stderr)
        return 2
    return run_prove(
        _recorder(),
        _prompter(),
        print,
        tool=a.tool,
        agent=a.agent,
        files=a.files,
        content=a.content,
        all_=a.all,
        days=a.days,
        force=a.force,
    )


@command(
    "start-fresh",
    "start the agent's proofs from now (the calls before stay recorded and can still be proved with prove --all)",
    lambda p: p.add_argument("agent"),
)
def cmd_start_fresh(a: argparse.Namespace) -> int:
    from .tool_commands import start_fresh

    t = start_fresh(_recorder(), a.agent)
    print(
        f"{a.agent}: proofs start at {t} from now on. The old record is kept and can still be proved: signafaide prove --agent {a.agent} --all"
    )
    return 0


def _url_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--url",
        help="the witness (else SIGNAFAIDE_URL in the environment, else the hosted service; never the project's .env)",
    )


def _login_args(p: argparse.ArgumentParser) -> None:
    _url_arg(p)
    p.add_argument(
        "--console", help="where a self-hosted witness's sign-in page is, when not on the witness's own origin"
    )


@command(
    "login",
    "sign in to the console from this terminal (device code), so you can save rules; the session is kept outside the project",
    _login_args,
)
def cmd_login(a: argparse.Namespace) -> int:
    from .session import login, person_witness

    rec = _recorder()
    url = person_witness(a.url)
    if rec.url != url:
        print(
            f"note: SIGNAFAIDE_URL in the project's .env names {rec.url}; signing in and saving rules use {url} "
            "(--url, or SIGNAFAIDE_URL in the environment), never a project file.",
            file=sys.stderr,
        )
    s = login(url, rec.client_id(), print, console=a.console)
    org = (s.get("organisation") or {}).get("name")
    print(
        f"Signed in as {(s.get('person') or {}).get('email') or 'you'}{f' ({org})' if org else ''} at {url} until {s['expires_at']}. Rules you save from this terminal name you."
    )
    return 0


@command("logout", "end the console session this terminal holds", _url_arg)
def cmd_logout(a: argparse.Namespace) -> int:
    from .session import logout, person_witness

    url = person_witness(a.url)
    print(f"Signed out of {url}." if logout(url, _recorder().client_id()) else f"No session was held here for {url}.")
    return 0


@command("whoami", "who is signed in on this terminal (signafaide login), and until when", _url_arg)
def cmd_whoami(a: argparse.Namespace) -> int:
    from .session import load_session, person_witness

    s = load_session(person_witness(a.url))
    if s is None:
        print("not signed in (signafaide login)")
        return 1
    org = (s.get("organisation") or {}).get("name")
    print(f"{(s.get('person') or {}).get('email') or 'signed in'}{f' ({org})' if org else ''} until {s['expires_at']}")
    return 0


# The spec 1.1 commands first in the help, as in the TypeScript CLI: protect is where a project starts.
_FIRST = ("protect", "check", "pull", "prove", "start-fresh", "login", "logout", "whoami")
COMMANDS = {**{k: COMMANDS[k] for k in _FIRST}, **{k: v for k, v in COMMANDS.items() if k not in _FIRST}}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="signafaide", description="Signed records of AI agent decisions.")
    p.add_argument("--version", action="version", version=f"signafaide {__version__}")
    sub = p.add_subparsers(dest="command", metavar="command")
    for name, (help, args, fn) in COMMANDS.items():
        sp = sub.add_parser(name, help=help, description=help)
        args(sp)
        sp.set_defaults(handler=fn)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    p = parser()
    a = p.parse_args(argv)
    if not getattr(a, "handler", None):
        p.print_help()
        return 1
    try:
        return a.handler(a)
    except (SignafaideError, StateError, OSError, ValueError) as e:
        print(f"signafaide: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
