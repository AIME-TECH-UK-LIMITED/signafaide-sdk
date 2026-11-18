import { tool } from "ai";
import { z } from "zod";
import { declareTools, wrapTool } from "signafaide";

/** A stand-in for a real payments client: it only says what it would do. */
async function pay(payee: string, amount: number, currency: string): Promise<string> {
  return `paid ${amount} ${currency} to ${payee}`;
}

// approve_payout pays money, so it is protected (`"protect": true` in signafaide.checks.json): every
// call runs the local checks in On, the rule on this machine blocks it when the amount is above
// 1,000, and a call the rule lets through runs only when signafAIde rules allow (a key or sandbox:
// `npx signafaide init`). lookup_invoice only reads, so it is recorded. Every call is signed and
// recorded in .signafaide/.
export const tools = {
  approve_payout: wrapTool(
    tool({
      description: "Pay a supplier an amount in a currency.",
      inputSchema: z.object({ payee: z.string(), amount: z.number(), currency: z.string() }),
      execute: async ({ payee, amount, currency }) => pay(payee, amount, currency),
    }),
    { name: "approve_payout", agent: "payout-agent" },
  ),
  lookup_invoice: wrapTool(
    tool({
      description: "Look up an invoice by its id.",
      inputSchema: z.object({ id: z.string() }),
      execute: async ({ id }) => `invoice ${id}: 1 line item, status open`,
    }),
    { name: "lookup_invoice", agent: "payout-agent" },
  ),
};

// The agent's full tool list, so a proof shows every tool is recorded.
declareTools(Object.keys(tools), { agent: "payout-agent" });
