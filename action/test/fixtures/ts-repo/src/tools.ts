import { protect, record } from "signafaide";
import { payments } from "./payments";

export async function approve_payout(payee: string, amount: number, currency: string) {
  return payments.payout({ payee, amount, currency });
}

async function delete_payee(payeeId: string) {
  return payments.removePayee(payeeId);
}

async function send_receipt(to: string, body: string) {
  return payments.mail(to, body);
}

async function lookup_invoice(invoiceId: string) {
  return payments.invoice(invoiceId);
}

async function run_migration(name: string) {
  return payments.migrate(name);
}

export const tools = {
  approve_payout,
  delete_payee: protect(delete_payee, { args: ["payeeId"], agent: "payout-bot" }),
  send_receipt: record(send_receipt, { args: ["to", "body"], agent: "payout-bot" }),
  lookup_invoice,
  run_migration,
};
