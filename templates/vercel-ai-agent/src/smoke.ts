/** The smoke test, with no account, no key and no network: the agent pays 800, and 1,200 is
 * blocked by the rule on this machine before approve_payout runs. Exit 1 when either is not so.
 * It runs in test mode (./test-mode.ts, first import): a protected tool asks signafAIde for a
 * ruling, and with no key or sandbox here only test mode lets it run without one. */
import "./test-mode.js";
import { flush } from "signafaide";
import { runAgent } from "./agent.js";
import { scriptedModel } from "./scripted-model.js";

let failed = 0;
async function expectAnswer(prompt: string, want: string): Promise<void> {
  const { text } = await runAgent(scriptedModel(), prompt);
  const ok = text.includes(want);
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${prompt}\n     ${text}`);
}

await expectAnswer("Pay Ashgrove Catering Ltd 800 GBP.", "paid 800 GBP to Ashgrove Catering Ltd");
await expectAnswer("Pay Ashgrove Catering Ltd 1200 GBP.", 'approve_payout did not run: the rule on this machine blocked it ("Block approve_payout when amount is above 1,000")');
await flush();
process.exit(failed ? 1 : 0);
