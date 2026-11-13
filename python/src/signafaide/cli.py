"""``signafaide`` command line. Add a command with ``@command``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import runtime
from . import KeysRequired
from . import verify as run_verify
from ._version import __version__
from ._plural import plural
from .http import SignafaideError
from .state import StateError

Handler = Callable[[argparse.Namespace], int]
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


@command("init", "opt in to the witness: create a free sandbox if there is no API key (no account, email or card), print the claim link")
def cmd_init(a: argparse.Namespace) -> int:
    rec = _recorder()
    rec.remember_agent()
    had = rec.api_key
    key = rec.create_sandbox()
    sandbox = rec.state.sandbox() or {}
    claim = sandbox.get("claim_url")
    if not had:
        print(f"sandbox ready at {rec.url}, key saved to {rec.state.root / '.env'}; claim it at {claim}")
        print("from now on record hashes (never content) are sent for co-signature and public timestamps; "
              "records written before now ship with their original times on the next run or with `signafaide flush`")
    elif key.startswith("sfa_test_") and claim:
        print(f"key found ({_mask(key)}); claim the sandbox at {claim}")
    else:
        print(f"key found ({_mask(key)}, env {runtime._env_of(key)}); nothing to create")
    return 0


@command("status", "key and env, agents, last receipt, outbox size, quota")
def cmd_status(a: argparse.Namespace) -> int:
    rec = _recorder()
    s = rec.status()
    print(f"key: {_mask(s['api_key'])}" + (f" (env {s['env']})" if s["env"] else
          "; records stay on this machine (signed and chained, nothing is sent). `signafaide init` creates a free sandbox and sends hashes; or set SIGNAFAIDE_API_KEY"))
    print(f"service: {s['url']}")
    print(f"home: {s['home']}")
    if not s["chains"]:
        print("chains: none yet; decorate a function with @signafaide.record")
    for c in s["chains"]:
        last = f"last receipt seq {c['receipt_seq']} at {c['receipt_time']}" if c["receipt_seq"] else "no receipt yet"
        other = "" if c["current"] or not c["waiting"] else f"; {c['waiting']} waiting for the key of that project"
        print(f"chain {c['chain']}: key {c['key_id']}, {plural(c['records'], 'record')}, {last}{other}")
    print(f"outbox: {plural(s['outbox'], 'record')} waiting" + ("; run `signafaide flush`" if s["outbox"] else ""))
    if s["api_key"]:
        try:
            u = rec.client(timeout=5).usage()
            print(f"quota: {u.get('used')} of {u.get('quota')} used in {u.get('period')}")
        except SignafaideError as e:
            print(f"quota: unknown ({e})")
    claim = (s["sandbox"] or {}).get("claim_url")
    if claim and (s["api_key"] or "").startswith("sfa_test_"):
        print(f"claim: {claim}")
    return 0


def _verify_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("pack", nargs="?", help="pack.json (default: the local .signafaide state)")
    p.add_argument("--keys", help="service keys file or URL (default: fetched from SIGNAFAIDE_URL)")
    p.add_argument("--trust-embedded-keys", action="store_true", help="use the service keys inside the pack")
    p.add_argument("--agent-keys", help="the customer's agent keys from `signafaide keys export` (default: this project's own keys)")
    p.add_argument("--trust-embedded-agent-keys", action="store_true", help="use the agent keys inside the pack (not independent)")
    p.add_argument("--head", help="the client's .signafaide/head.json: fails if the pack ends before it (default: this project's own)")
    p.add_argument("--timestamp-check", "--bitcoin", dest="timestamp_check", default=None, help="explorer API that confirms public timestamps (default https://mempool.space/api)")
    p.add_argument("--offline", action="store_true", help="do not look up public timestamps (they show NOT CHECKED)")
    p.add_argument("--content", help="chain .jsonl file or folder with the content (default: local .signafaide/chain)")
    p.add_argument("--json", action="store_true", help="machine-readable output")


@command("verify", "verify a pack or the local state; exit 0 PASS, 1 FAIL, 2 unreadable input", _verify_args)
def cmd_verify(a: argparse.Namespace) -> int:
    rec = _recorder()
    try:
        kw = {"timestamp_check": a.timestamp_check} if a.timestamp_check else {}
        report = run_verify(a.pack, keys=a.keys, trust_embedded_keys=a.trust_embedded_keys, agent_keys=a.agent_keys,
                            trust_embedded_agent_keys=a.trust_embedded_agent_keys, head=a.head, offline=a.offline, content=a.content, **kw)
    except (KeysRequired, SignafaideError, StateError, OSError, ValueError) as e:
        print(f"signafaide: {e}", file=sys.stderr)
        rec.event("verify")
        return 2
    print(json.dumps(report.to_dict(), indent=2) if a.json else str(report), flush=True)
    rec.event("verify")
    return 0 if report.ok else 1


def _keys_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("action", choices=["export", "rotate"], help="export: write the agent-key manifest for auditors; rotate: give an agent a new key")
    p.add_argument("--agent", help="rotate: the agent (default: this project's folder name)")
    p.add_argument("-o", "--output", help="export: output file (default agent-keys.json)")


@command("keys", "export the agent public keys for auditors, or rotate an agent's key", _keys_args)
def cmd_keys(a: argparse.Namespace) -> int:
    rec = _recorder()
    if a.action == "export":
        doc = rec.state.export_agent_keys()
        if not doc["keys"]:
            print("signafaide: no agent keys here yet; they are made with the first record", file=sys.stderr)
            return 1
        out = Path(a.output or "agent-keys.json")
        out.write_text(json.dumps(doc, indent=2) + "\n")
        print(f"wrote {out} ({plural(len(doc['keys']), 'key')}); give it to your auditors: signafaide verify pack.json --agent-keys {out}")
        return 0
    agent = a.agent or rec.default_agent
    old, new = rec.state.rotate_key(agent)
    print(f"{agent}: new key {new.key_id} signs from now on. Records the old key {old.key_id} signed earlier ship first; the next record then "
          "registers the new key, signed by the old one, and the service retires the old key at that moment")
    return 0


def _export_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--agent", help="only this agent (default: every agent in the project)")
    p.add_argument("--from", dest="from_", help="RFC 3339 start time")
    p.add_argument("--to", help="RFC 3339 end time")
    p.add_argument("-o", "--output", help="output file (default: <project>-pack.json, or <agent>-pack.json with --agent)")


@command("export", "download a verification pack of the whole project (every agent), or of one agent with --agent", _export_args)
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
    p.add_argument("--agent", help="agent name (default: this project's folder name)")
    p.add_argument("--from", dest="from_", help="YYYY-MM-DD or RFC 3339 start time")
    p.add_argument("--to", help="YYYY-MM-DD (inclusive) or RFC 3339 end time (exclusive)")
    p.add_argument("--record", help="one record hash (or a prefix of 8+ characters) and its decision or outcome")
    p.add_argument("--chain", help="chain id when the agent has several (<project>/<env>/<agent>)")
    p.add_argument("--keys", help="service keys file or URL (default: fetched from SIGNAFAIDE_URL)")
    p.add_argument("--html", help="also write a self-contained HTML page to this file")
    p.add_argument("--json", action="store_true", help="machine-readable output")


@command("replay", "show what an agent saw and did, from the local chain, each record verified; exit 1 on FAIL", _replay_args)
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
    p.add_argument("--agent", help="agent name (default: this project's folder name)")
    p.add_argument("--name", help="only decisions of this action or tool name")
    p.add_argument("--from", dest="from_", help="YYYY-MM-DD or RFC 3339 start time")
    p.add_argument("--to", help="YYYY-MM-DD (inclusive) or RFC 3339 end time (exclusive)")
    p.add_argument("--limit", type=int, help="only the newest N decisions")
    p.add_argument("--label", help="a name for this experiment in the console")
    p.add_argument("--chain", help="chain id when the agent has several")
    p.add_argument("--keys", help="service keys file or URL")
    p.add_argument("--upload", action="store_true", help="send the report to the service, hash-only")
    p.add_argument("--values", action="store_true", help="with --upload: include recorded and candidate values (decisions stored with the service only)")
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
    r = compare(load_candidate(a.module), agent=a.agent, name=a.name, since=a.from_, until=a.to, limit=a.limit, chain=a.chain, keys=a.keys, label=a.label)
    if a.upload:
        r.upload(values=True if a.values else None)
    print(json.dumps(r.to_dict() | ({"uploaded": r.uploaded} if r.uploaded else {}), indent=2, ensure_ascii=False) if a.json else str(r), flush=True)
    return 0


@command("claim", "print the sandbox claim link again")
def cmd_claim(a: argparse.Namespace) -> int:
    rec = _recorder()
    claim = (rec.state.sandbox() or {}).get("claim_url")
    if (rec.api_key or "").startswith("sfa_live_"):
        print("this project uses a live key; there is nothing to claim")
        return 0
    if not claim:
        print("no sandbox here; run `signafaide init` first", file=sys.stderr)
        return 1
    print(claim)
    return 0


@command("flush", "ship the outbox now")
def cmd_flush(a: argparse.Namespace) -> int:
    rec = _recorder()
    r = rec.flush()
    for agent, e in r["errors"].items():
        print(f"{agent}: {e}", file=sys.stderr)
    if not rec.api_key:
        print(f"no API key: nothing was sent; {plural(r['left'], 'record')} stay local. Run `signafaide init` (or set SIGNAFAIDE_API_KEY) to send hashes")
        return 0
    # Chains the service cannot take (too_old, chain_exists) stay on this machine: not "left to ship".
    local = sum(rec.state.draft_count(c) for c, e in r["errors"].items() if e.code in ("too_old", "chain_exists"))
    print(f"shipped {plural(r['shipped'], 'record')}, {r['left'] - local} left in the outbox"
          + (f"; {plural(local, 'record')} kept on this machine only (see above)" if local else ""))
    return 1 if r["errors"] else 0


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
