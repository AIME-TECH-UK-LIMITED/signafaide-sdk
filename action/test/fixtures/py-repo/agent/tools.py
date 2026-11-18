import signafaide
from langchain_core.tools import tool

from .payments import payments


def approve_payout(payee: str, amount: float, currency: str) -> dict:
    return payments.payout(payee, amount, currency)


@signafaide.protect(agent="payout-bot")
def delete_payee(payee_id: str) -> str:
    return payments.remove_payee(payee_id)


@signafaide.record(agent="payout-bot")
def send_receipt(to: str, body: str) -> str:
    return payments.mail(to, body)


def lookup_invoice(invoice_id: str) -> dict:
    return payments.invoice(invoice_id)


def run_migration(name: str) -> str:
    return payments.migrate(name)


tools = [approve_payout, delete_payee, send_receipt, lookup_invoice, run_migration]


@tool
def git_push(branch: str) -> str:
    """Push the current branch to the remote."""
    return f"pushed {branch}"
