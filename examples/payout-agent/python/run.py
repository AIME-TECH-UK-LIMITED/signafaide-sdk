"""Pays 800, then tries 1,200: with the quickstart's rule (block above 1,000, On) the second call
does not run, and its error says why in one sentence with a link."""

import signafaide
from payout_agent.tools import approve_payout

print(approve_payout("Ashgrove Catering Ltd", 800, "GBP"))
try:
    print(approve_payout("Ashgrove Catering Ltd", 1200, "GBP"))
except signafaide.SignafaideBlocked as e:
    print(e)
signafaide.flush()
