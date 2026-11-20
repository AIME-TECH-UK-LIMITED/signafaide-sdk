/** Shared by the tests that run the span processor against real instrumentation packages: a
 * tracer provider with the processor added, a LangChain agent with a fake model, and a look at
 * the chain from inside the tool body. */

import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { AIMessage } from "@langchain/core/messages";
import { context, propagation, trace } from "@opentelemetry/api";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { AlwaysOnSampler } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { createAgent, tool } from "langchain";
import { expect } from "vitest";
import { z } from "zod";
import { SignafaideSpanProcessor } from "../src/otel.js";
import type { SignedRecord } from "../src/records.js";
import { getRecorder } from "../src/runtime.js";

export function provider(): NodeTracerProvider {
  const p = new NodeTracerProvider({
    sampler: new AlwaysOnSampler(),
    resource: resourceFromAttributes({ "service.name": "support-bot" }),
    spanProcessors: [new SignafaideSpanProcessor()], // the one line
  });
  p.register();
  return p;
}

/** The tool-call records in the agent's chain, as they are on disk now. */
export function toolRecords(): SignedRecord[] {
  const rec = getRecorder();
  return rec.state
    .chains()
    .filter((c) => c.endsWith("/support-bot"))
    .flatMap((c) => rec.state.readAll(c))
    .filter((r) => r.envelope.kind !== "note");
}
export const calls = () => toolRecords().map((r) => `${r.envelope.kind} ${r.envelope.name}`);
export const decision = () => toolRecords().find((r) => r.envelope.kind === "decision")!;
export const marker = () => (decision().content as any).meta.telemetry;

/** A chat model that asks for one tool call, then answers. */
class FakeModel extends BaseChatModel {
  turns = [
    new AIMessage({
      content: "",
      tool_calls: [{ name: "lookup_order", args: { order: "A1", lines: 2 }, id: "call_1", type: "tool_call" }],
    }),
    new AIMessage("done"),
  ];
  _llmType() {
    return "fake";
  }
  override bindTools() {
    return this;
  }
  async _generate() {
    return { generations: [{ message: this.turns.shift()!, text: "" }] };
  }
}

/** What the tool body saw in the chain while it ran. */
export const seen: { calls?: string[] } = {};
export const lookupOrder = tool(
  async ({ order, lines }: { order: string; lines: number }) => {
    seen.calls = calls();
    return `${order}: ${lines} lines shipped`;
  },
  {
    name: "lookup_order",
    description: "Look an order up.",
    schema: z.object({ order: z.string(), lines: z.number() }),
  },
);

export async function runLangChainAgent(tools: unknown[] = [lookupOrder]): Promise<void> {
  const agent = createAgent({ model: new FakeModel({}), tools: tools as any });
  const out = await agent.invoke({ messages: [{ role: "user", content: "where is order A1?" }] });
  expect(out.messages.at(-1)!.content).toBe("done");
}

/** Undo the application's tracing set-up after a test. */
export function unregister(): void {
  delete seen.calls;
  trace.disable();
  context.disable();
  propagation.disable();
}
