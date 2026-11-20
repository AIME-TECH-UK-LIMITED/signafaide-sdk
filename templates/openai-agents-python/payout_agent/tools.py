"""The agent's tools. approve_payout pays money, so it is protected ("protect": true in
signafaide.checks.json): every call runs the local checks in On, the rule on this machine blocks it
when the amount is above 1,000, and a call the rule lets through runs only when signafAIde rules
allow (a key or sandbox: signafaide init). lookup_invoice only reads, so it is recorded. Every call
is signed and recorded in .signafaide/."""

import signafaide
from agents import RunContextWrapper, function_tool
from agents.tool import default_tool_error_function


def say_why(ctx: RunContextWrapper, error: Exception) -> str:
    """What the model is told when a tool fails: a blocked call's reason, in signafAIde's words, so
    the agent can tell the person; any other error as the Agents SDK says it."""
    if isinstance(error, signafaide.SignafaideBlocked):
        return str(error)
    return default_tool_error_function(ctx, error)


def _pay(payee: str, amount: float, currency: str) -> str:
    """A stand-in for a real payments client: it only says what it would do."""
    return f"paid {amount:g} {currency} to {payee}"


@function_tool(failure_error_function=say_why)
@signafaide.record(agent="payout-agent")
def approve_payout(payee: str, amount: float, currency: str) -> str:
    """Pay a supplier an amount in a currency."""
    return _pay(payee, amount, currency)


@function_tool(failure_error_function=say_why)
@signafaide.record(agent="payout-agent")
def lookup_invoice(invoice_id: str) -> str:
    """Look up an invoice by its id."""
    return f"invoice {invoice_id}: 1 line item, status open"


tools = [approve_payout, lookup_invoice]

# The agent's full tool list, so a proof shows every tool is recorded.
signafaide.declare_tools(["approve_payout", "lookup_invoice"], agent="payout-agent")
