/** Test mode for the smoke test, imported before the tools: records go to a temporary folder and
 * nothing is sent, so the protected approve_payout runs without a ruling (as under Vitest, Jest and
 * `node --test`) and the rule on this machine still blocks 1,200. Never set with a live key. */
process.env.SIGNAFAIDE_TEST ??= "1";
