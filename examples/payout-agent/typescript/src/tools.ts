import { payments } from "./payments.js";
import { protect, record, declareTools } from "signafaide";

async function approve_payout(payee: string, amount: number, currency: string): Promise<string> {
  return payments.payout({ payee, amount, currency });
}

async function delete_payee(payeeId: string): Promise<string> {
  return `deleted payee ${payeeId}`;
}

async function send_receipt(to: string, body: string): Promise<string> {
  return `receipt sent to ${to} (${body.length} characters)`;
}

async function lookup_invoice(id: string): Promise<string> {
  return `invoice ${id}: 1 line item, status open`;
}

// What `npx signafaide protect` writes: every tool recorded, approve_payout protected, the same
// agent name in every call, so the project is one agent in the console and in its proofs.
export const tools = {
  approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }),
  delete_payee: record(delete_payee, { args: ["payeeId"], agent: "payout-bot" }),
  send_receipt: record(send_receipt, { args: ["to", "body"], agent: "payout-bot" }),
  lookup_invoice: record(lookup_invoice, { args: ["id"], agent: "payout-bot" }),
};

// The agent's full tool list, so a proof shows every tool is recorded.
declareTools(Object.keys(tools), { agent: "payout-bot" });
