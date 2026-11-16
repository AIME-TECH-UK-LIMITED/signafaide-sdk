/** The OpenTelemetry span processor against real instrumentation packages: a real framework runs
 * a real tool call, asked for by a fake model (no network, no API key). Each test looks, from
 * inside the tool body, at whether the signed decision is already in the chain. */

import { OpenTelemetry } from "@ai-sdk/otel";
import { LangChainInstrumentation as OpenInferenceLangChain } from "@arizeai/openinference-instrumentation-langchain";
import * as CallbackManagerModule from "@langchain/core/callbacks/manager";
import { generateText, registerTelemetry, stepCountIs, tool as aiTool } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { verify, wrapTools } from "../src/index.js";
import { useProject } from "./helpers.js";
import { calls, decision, lookupOrder, marker, provider, runLangChainAgent, seen, toolRecords, unregister } from "./otel-helpers.js";

describe("signafaide/otel with real instrumentation", () => {
  useProject();
  afterEach(unregister);

  it("Vercel AI SDK (@ai-sdk/otel, GenAI convention): the decision is written before the tool runs", async () => {
    // The AI SDK starts its execute_tool span with the GenAI attributes on it, so the decision
    // is in the chain before the tool body runs.
    registerTelemetry(new OpenTelemetry({ tracer: provider().getTracer("ai") }));
    const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
    const model = new MockLanguageModelV4({
      doGenerate: [
        { content: [{ type: "tool-call", toolCallId: "call_1", toolName: "refund", input: JSON.stringify({ order: "A1", amount: 5 }) }], finishReason: { unified: "tool-calls", raw: "tool_calls" }, usage, warnings: [] },
        { content: [{ type: "text", text: "done" }], finishReason: { unified: "stop", raw: "stop" }, usage, warnings: [] },
      ] as any,
    });
    let inside: string[] | undefined;
    const result = await generateText({
      model,
      prompt: "refund order A1",
      stopWhen: stepCountIs(3),
      tools: {
        refund: aiTool({
          description: "Refund an order.",
          inputSchema: z.object({ order: z.string(), amount: z.number() }),
          execute: async ({ order, amount }) => {
            inside = calls();
            return `refunded ${amount} on ${order}`;
          },
        }),
      },
    });
    expect(result.text).toBe("done");
    expect(inside).toEqual(["decision refund"]); // signed and chained before the tool body ran
    expect(calls()).toEqual(["decision refund", "outcome refund"]);
    expect(marker()).toMatchObject({ convention: "gen_ai", decision_written: "before", tool_call_id: "call_1" });
    expect((decision().content as any).input).toEqual({ order: "A1", amount: 5 });
    expect((toolRecords()[1].content as any).output).toBe("refunded 5 on A1");
    const report = await verify();
    expect(report.ok).toBe(true);
    expect(String(report)).toContain("refund (decision written before the tool ran)");
  });

  it("OpenInference LangChain: the decision is written after the tool ran", async () => {
    // OpenInference's LangChain instrumentation sets a span's attributes when the span ends, so
    // the span says it is a tool call only then.
    new OpenInferenceLangChain({ tracerProvider: provider() }).manuallyInstrument(CallbackManagerModule);
    await runLangChainAgent();
    expect(seen.calls).toEqual([]); // nothing in the chain while the tool ran
    expect(calls()).toEqual(["decision lookup_order", "outcome lookup_order"]);
    expect(marker()).toMatchObject({ convention: "openinference", decision_written: "after" });
    expect((decision().content as any).input).toEqual({ order: "A1", lines: 2 });
    const report = await verify();
    expect(report.ok).toBe(true);
    expect(String(report)).toContain("lookup_order (decision written after the tool ran)");
  });

  it("OpenInference LangChain: a tool also wrapped with the SDK is recorded once", async () => {
    new OpenInferenceLangChain({ tracerProvider: provider() }).manuallyInstrument(CallbackManagerModule);
    await runLangChainAgent(wrapTools([lookupOrder], { agent: "support-bot" }));
    expect(seen.calls).toEqual(["decision lookup_order"]); // the wrapper's decision, before the tool ran
    expect(calls()).toEqual(["decision lookup_order", "outcome lookup_order"]);
    expect((decision().content as any).meta).not.toHaveProperty("telemetry");
  });
});
