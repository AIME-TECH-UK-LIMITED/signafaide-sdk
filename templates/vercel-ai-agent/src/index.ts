/** Runs the agent once. With AI_MODEL set (a Vercel AI Gateway model id, with AI_GATEWAY_API_KEY),
 * a real model decides; without it a scripted model does, so this runs with no account. */
import { flush } from "signafaide";
import { runAgent } from "./agent.js";
import { scriptedModel } from "./scripted-model.js";

const prompt = process.argv.slice(2).join(" ") || "Pay Ashgrove Catering Ltd 1200 GBP for invoice INV-1042.";
const model = process.env.AI_MODEL || scriptedModel();
const result = await runAgent(model, prompt);
console.log(result.text);
await flush();
