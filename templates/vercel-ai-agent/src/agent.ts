import { generateText, stepCountIs, type LanguageModel } from "ai";
import { tools } from "./tools.js";

/** One agent run: the model may call the tools, up to five steps. A tool the rules block does not
 * run; the model gets the reason as the tool's error and answers with it. */
export async function runAgent(model: LanguageModel, prompt: string) {
  return generateText({
    model,
    tools,
    stopWhen: stepCountIs(5),
    system: "You pay suppliers with approve_payout and look up invoices with lookup_invoice. Say what happened in one sentence.",
    prompt,
  });
}
