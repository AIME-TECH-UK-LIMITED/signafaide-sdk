"""Cost of the local tool-call checks of one call (spec §8), Python SDK.

    cd python && .venv/bin/python ../bench/checks_bench.py            # prints a table
    cd python && .venv/bin/python ../bench/checks_bench.py --json     # one JSON line

Measured: ``ChecksState.plan()``, which runs the decision checks (secret, address, changed_tool,
fingerprint, rule, and from spec 1.1 hidden_instruction on the tool's definition) of a call and
builds the ``checks`` of its decision, and ``result_entries()``, the result checks (secret and
hidden_instruction) on the result. The last row's call also carries a 3 KB base64 attachment,
which the secret check decodes (spec 1.1). The checks file is on,
with a 50-rule local rule set. The "connected" case adds a held project rule set of 50 rules and
a shared fingerprint list. Nothing is sent: the fake service of the tests only signs the rule set
and the list once, before timing. Run under ``systemd-run --user --scope -p MemoryMax=8G``.
"""
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "python" / "tests"), str(HERE.parent / "python" / "src")]

from fake_service import FakeService  # noqa: E402
from signafaide import runtime  # noqa: E402
from signafaide.checks import default_checks_file  # noqa: E402
from signafaide.checks_runtime import ToolInfo  # noqa: E402

N = int(os.environ.get("BENCH_N", "20000"))
WARM = min(2000, N)


def rules(n):
    tools = ["pay", "delete_account", "send_email", "refund", "export_data"]
    out = []
    for i in range(n):
        when = [{"field": "/amount", "op": "gt" if i % 2 else "lt", "value": 1000 + i}]
        if i % 3 == 0:
            when.append({"field": "/to", "op": "suffix", "value": f"@blocked{i}.example"})
        if i % 4 == 0:
            when.append({"field": "/currency", "op": "not_in", "value": ["GBP", "EUR", "USD"]})
        out.append({"id": f"rule-{i + 1:02d}", "about": f"Rule {i + 1}.", "action": "allow" if i % 5 == 0 else "block",
                    "tools": None if i % 7 == 0 else [tools[i % len(tools)]], "agents": ["other-bot"] if i % 11 == 0 else None, "when": when})
    return out


TOOL = ToolInfo("send_email", "Send an email to a customer on behalf of the claims team. Returns the message id.",
                {"type": "object", "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"},
                                                  "amount": {"type": "number"}, "currency": {"type": "string"}, "callback": {"type": "string"}},
                 "required": ["to", "body"]})
ARGS = {"to": "customer@example.org", "subject": "Your claim 48213 has been approved",
        "body": "Hello, your claim has been approved and the payment of 120.00 GBP will reach your account within three working days. Reply to this message if anything looks wrong. Regards, the claims team.",
        "amount": 120, "currency": "GBP", "callback": "https://api.example.com/v1/claims/48213/status"}
#: A call with a 3 KB base64 attachment and a hex digest: the secret check decodes both (spec 1.1).
ENCODED_ARGS = {**ARGS, "attachment": __import__("base64").b64encode(("Quarterly claims summary. " * 118).encode()).decode(),
                "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
OUTPUT = {"id": "msg_93f1", "status": "queued", "detail": "The message was accepted for delivery and will be sent within a minute."}


def timed(fn):
    for _ in range(WARM):
        fn()
    us = []
    clock = time.perf_counter_ns
    for _ in range(N):
        t = clock()
        fn()
        us.append((clock() - t) / 1000)
    us.sort()
    pick = lambda p: us[min(len(us) - 1, int(p / 100 * len(us)))]
    return {"p50": pick(50), "p95": pick(95), "p99": pick(99), "mean": sum(us) / len(us)}


def scenario(name, connected, list_size, args=ARGS):
    root = Path(tempfile.mkdtemp(prefix="sfa-bench-")) / "bench-project"
    (root / ".git").mkdir(parents=True)
    cwd = os.getcwd()
    os.chdir(root)
    service = FakeService()
    os.environ["SIGNAFAIDE_URL"] = service.url
    os.environ["SIGNAFAIDE_TEST"] = "0"
    rec = runtime.configure(quiet=True, flush_interval=3600)
    try:
        doc = default_checks_file()
        doc["rules"] = {"default": "allow", "rules": rules(50)}
        (root / "signafaide.checks.json").write_text(json.dumps(doc))
        rec.create_sandbox()
        if connected:
            service.publish_rules(rec.api_key, rules(50), mode="watch")
        service.list_update([{"kind": "tool", "fingerprint": format(i + 1, "064x")} for i in range(list_size)])
        rec.checks.pull_list()
        if connected:
            rec.checks.pull_rules()
        plan = rec.checks.plan(TOOL, "claims-bot", args, strict_code=False)
        kinds = ",".join(r["check"] for r in plan.checks["results"])
        decision = timed(lambda: rec.checks.plan(TOOL, "claims-bot", args, strict_code=False))
        result = timed(lambda: rec.checks.result_entries(OUTPUT))
        return {"name": name, "listSize": list_size, "checks": kinds, "decision": decision, "result": result}
    finally:
        rec._stopped = True
        rec._wake.set()
        runtime._default = None
        service.close()
        os.chdir(cwd)
        shutil.rmtree(root.parent, ignore_errors=True)


out = [scenario("local rules only (50 local rules, list of 1,000)", False, 1000),
       scenario("connected (50 local + 50 held rules, list of 1,000)", True, 1000),
       scenario("connected, list of 20,000", True, 20000),
       scenario("local rules, list of 1,000, a 3 KB base64 attachment", False, 1000, ENCODED_ARGS)]
if "--json" in sys.argv:
    print(json.dumps({"sdk": "python", "python": platform.python_version(), "iterations": N, "scenarios": out}))
else:
    print(f"python {platform.python_version()}, {N} calls per row, microseconds")
    for s in out:
        print(f"{s['name']}  [{s['checks']}]")
        for k in ("decision", "result"):
            print(f"  {k:<9} p50 {s[k]['p50']:.1f}  p95 {s[k]['p95']:.1f}  p99 {s[k]['p99']:.1f}  mean {s[k]['mean']:.1f}")
