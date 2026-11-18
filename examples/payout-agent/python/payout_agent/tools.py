"""The quickstart's payout agent: four tools, approve_payout protected.

What ``signafaide protect`` writes: every tool recorded, approve_payout protected, the same agent
name in every decorator, so the project is one agent in the console and in its proofs."""

import signafaide


def _payout(payee: str, amount: float, currency: str) -> str:
    """A stand-in for a real payments client: it only says what it would do."""
    return f"paid {amount:g} {currency} to {payee}"


@signafaide.protect(agent="payout-bot")
def approve_payout(payee: str, amount: float, currency: str) -> str:
    return _payout(payee, amount, currency)


@signafaide.record(agent="payout-bot")
def delete_payee(payee_id: str) -> str:
    return f"deleted payee {payee_id}"


@signafaide.record(agent="payout-bot")
def send_receipt(to: str, body: str) -> str:
    return f"receipt sent to {to} ({len(body)} characters)"


@signafaide.record(agent="payout-bot")
def lookup_invoice(invoice_id: str) -> str:
    return f"invoice {invoice_id}: 1 line item, status open"


tools = [approve_payout, delete_payee, send_receipt, lookup_invoice]

# The agent's full tool list, so a proof shows every tool is recorded.
signafaide.declare_tools(["approve_payout", "delete_payee", "send_receipt", "lookup_invoice"], agent="payout-bot")
