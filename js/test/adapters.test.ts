import { tool as openaiTool } from "@openai/agents-core";
import { tool as lcTool, StructuredTool } from "@langchain/core/tools";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { NotRecorded, wrapTool, wrapTools } from "../src/index.js";
import { getRecorder } from "../src/runtime.js";
import { toolNote } from "../src/coverage.js";
import { deadUrl, records, useProject } from "./helpers.js";

useProject();
const names = (agent = "claims-project") => records(agent).map((r) => `${r.envelope.kind}:${r.envelope.name}`);
/** The agent's chain without its tool-declaration notes (SPEC §2.6): `wrapTools` writes them before the first call; tools.test.ts covers them. */
const chain = (agent = "claims-project") => records(agent).filter((r) => !toolNote(r.envelope.kind, r.envelope.name));

describe("wrapTools", () => {
  it("wraps an object of functions (key = name) and an array", async () => {
    const tools = wrapTools({ lookupOrder: (id: string) => ({ id }), refund: async (_id: string, amount: number) => amount }, { agent: "support-bot" });
    expect(tools.lookupOrder("o1")).toEqual({ id: "o1" });
    expect(await tools.refund("o1", 5)).toBe(5);
    function escalate(reason: string) {
      return reason;
    }
    const [wrapped] = wrapTools([escalate], { agent: "support-bot" });
    expect(wrapped("late")).toBe("late");
    // The wrapped tools declare themselves with the first call, and again when the list grows (SPEC §2.6).
    expect(names("support-bot")).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/lookupOrder",
      "note:signafaide.tool/refund",
      "decision:lookupOrder",
      "outcome:lookupOrder",
      "decision:refund",
      "outcome:refund",
      "note:signafaide.tools",
      "note:signafaide.tool/escalate",
      "note:signafaide.tool/lookupOrder",
      "note:signafaide.tool/refund",
      "decision:escalate",
      "outcome:escalate",
    ]);
  });

  it("rejects things that are not tools", () => {
    expect(() => wrapTools([3])).toThrow(/cannot record number/);
  });
});

describe("Vercel AI SDK tools (objects with execute)", () => {
  // `tool()` from "ai" returns its argument unchanged, so a plain object is the real shape.
  const weather = {
    description: "Weather for a city",
    inputSchema: z.object({ city: z.string() }),
    execute: async ({ city }: { city: string }, _opts: { toolCallId: string }) => `sunny in ${city}`,
  };

  it("records input and output, keeps the schema", async () => {
    const tools = wrapTools({ weather });
    expect(tools.weather.inputSchema).toBe(weather.inputSchema);
    expect(await tools.weather.execute({ city: "Paris" }, { toolCallId: "c1" })).toBe("sunny in Paris");
    const [d, o] = chain();
    expect(d.envelope.name).toBe("weather");
    expect(d.content!.input).toEqual({ city: "Paris" }); // not the options (messages, abort signal)
    expect(o.content).toEqual({ output: "sunny in Paris" });
  });
});

describe("OpenAI Agents JS", () => {
  const lookup = openaiTool({
    name: "lookup_order",
    description: "Look up an order",
    parameters: z.object({ orderId: z.string() }),
    execute: async ({ orderId }) => `order ${orderId} shipped`,
  });

  it("records invoke(runContext, input)", async () => {
    const [wrapped] = wrapTools([lookup]);
    expect(wrapped.name).toBe("lookup_order");
    expect(wrapped.parameters).toBe(lookup.parameters);
    expect(await wrapped.invoke(undefined as any, '{"orderId":"42"}')).toBe("order 42 shipped");
    const [d, o] = chain();
    expect(d.envelope.name).toBe("lookup_order");
    expect(d.content!.input).toEqual({ orderId: "42" });
    expect(o.content).toEqual({ output: "order 42 shipped" });
  });

  it("strict mode refuses to run", async () => {
    let ran = false;
    const pay = openaiTool({ name: "pay", description: "Pay", parameters: z.object({ amount: z.number() }), execute: async () => ((ran = true), "paid") });
    const rec = getRecorder();
    rec._apiKey = "sfa_test_" + "x".repeat(32);
    rec._url = await deadUrl();
    await expect(wrapTool(pay, { strict: true }).invoke(undefined as any, '{"amount":1}')).rejects.toThrow(NotRecorded);
    expect(ran).toBe(false);
  });
});

describe("LangChain.js", () => {
  const weather = lcTool(async ({ city }: { city: string }) => `sunny in ${city}`, {
    name: "get_weather",
    description: "Weather for a city",
    schema: z.object({ city: z.string() }),
  });

  it("records tool() tools through invoke, including tool calls", async () => {
    const [wrapped] = wrapTools([weather]);
    expect(wrapped.name).toBe("get_weather");
    expect(wrapped).toBeInstanceOf(StructuredTool);
    expect(await wrapped.invoke({ city: "Paris" })).toBe("sunny in Paris");
    const msg: any = await wrapped.invoke({ name: "get_weather", args: { city: "Rome" }, id: "call_1", type: "tool_call" });
    expect(msg.content).toBe("sunny in Rome");
    expect(msg.tool_call_id).toBe("call_1");
    await weather.invoke({ city: "Bern" }); // the original stays unrecorded
    expect(chain().map((r) => r.content!.input ?? r.content!.output)).toEqual([{ city: "Paris" }, "sunny in Paris", { city: "Rome" }, "sunny in Rome"]);
  });

  it("records StructuredTool subclasses and errors", async () => {
    class Echo extends StructuredTool {
      name = "echo";
      description = "Echo text back";
      schema = z.object({ text: z.string() });
      async _call({ text }: { text: string }) {
        if (text === "boom") throw new Error("echo failed");
        return text;
      }
    }
    const wrapped = wrapTool(new Echo());
    expect(await wrapped.invoke({ text: "hi" })).toBe("hi");
    await expect(wrapped.invoke({ text: "boom" })).rejects.toThrow("echo failed");
    expect(names()).toEqual(["note:signafaide.tools", "note:signafaide.tool/echo", "decision:echo", "outcome:echo", "decision:echo", "outcome:echo"]);
    expect(chain()[3].content).toEqual({ error: { type: "Error", message: "echo failed" } });
  });
});
