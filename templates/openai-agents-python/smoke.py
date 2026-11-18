"""The smoke test, with no account, no key and no network: the agent pays 800, and 1,200 is
blocked by the rule on this machine before approve_payout runs. Exit 1 when either is not so."""

import sys

import signafaide
from payout_agent.agent import run_agent

failed = 0
for prompt, want in [
    ("Pay Ashgrove Catering Ltd 800 GBP.", "paid 800 GBP to Ashgrove Catering Ltd"),
    ("Pay Ashgrove Catering Ltd 1200 GBP.", 'approve_payout did not run: the rule on this machine blocked it ("Block approve_payout when amount is above 1,000")'),
]:
    text = run_agent(prompt)
    ok = want in text
    failed += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {prompt}\n     {text}")
signafaide.flush()
sys.exit(1 if failed else 0)
