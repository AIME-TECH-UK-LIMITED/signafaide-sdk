import { MockLanguageModelV4 } from "ai/test";

const usage = {
  inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 0, text: 0, reasoning: 0 },
};

/** A stand-in for a model, so the agent runs with no account and no key. It calls approve_payout
 * once with the amount in the prompt, then says what the tool answered. */
export function scriptedModel() {
  return new MockLanguageModelV4({
    doGenerate: async ({ prompt }) => {
      const last = prompt[prompt.length - 1];
      if (last.role === "tool") {
        const part = last.content.find((p) => p.type === "tool-result");
        const out = part?.type === "tool-result" ? part.output : undefined;
        const text = out && "value" in out ? (typeof out.value === "string" ? out.value : JSON.stringify(out.value)) : "no answer";
        return { content: [{ type: "text", text }], finishReason: { unified: "stop", raw: undefined }, usage, warnings: [] };
      }
      const words = last.role === "user" ? last.content.map((p) => (p.type === "text" ? p.text : "")).join(" ") : "";
      const amount = Number((/(\d[\d,]*(?:\.\d+)?)/.exec(words)?.[1] ?? "0").replace(/,/g, ""));
      const input = JSON.stringify({ payee: "Ashgrove Catering Ltd", amount, currency: "GBP" });
      return {
        content: [{ type: "tool-call", toolCallId: `call-${amount}`, toolName: "approve_payout", input }],
        finishReason: { unified: "tool-calls", raw: undefined },
        usage,
        warnings: [],
      };
    },
  });
}
