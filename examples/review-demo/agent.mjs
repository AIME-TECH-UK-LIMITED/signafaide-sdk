import { declareTools, record, stop } from "signafaide";
const agent = "claims-bot";
const lookupClaim = record(async (claim) => ({ claim, status: "open", amount: 240 }), { name: "lookup_claim", agent });
const approvePayout = record(async (claim, amount) => ({ claim, approved: amount <= 500 }), { name: "approve_payout", agent });
const sendLetter = record(async (claim, template) => ({ claim, template, sent: true }), { name: "send_letter", agent });
declareTools(["lookup_claim", "approve_payout", "send_letter"], { agent });
for (const c of ["CLM-1001", "CLM-1002", "CLM-1003"]) {
  const info = await lookupClaim(c);
  const ok = await approvePayout(c, info.amount);
  if (ok.approved) await sendLetter(c, "payout-approved");
}
const r = await stop();
console.log("stop:", JSON.stringify(r).slice(0, 200));
