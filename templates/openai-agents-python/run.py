"""Runs the agent once. With OPENAI_API_KEY and AGENT_MODEL set (a model name), a real model
decides; without them a scripted model does, so this runs with no account."""

import os
import sys

import signafaide
from payout_agent.agent import run_agent

prompt = " ".join(sys.argv[1:]) or "Pay Ashgrove Catering Ltd 1200 GBP for invoice INV-1042."
model = os.environ.get("AGENT_MODEL") if os.environ.get("OPENAI_API_KEY") else None
print(run_agent(prompt, model))
signafaide.flush()
