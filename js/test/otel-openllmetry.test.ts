/** The OpenTelemetry span processor against OpenLLMetry's LangChain instrumentation: a real
 * LangChain agent runs a real tool call, asked for by a fake model (no network, no API key). */

import * as CallbackManagerModule from "@langchain/core/callbacks/manager";
import { LangChainInstrumentation as OpenLLMetryLangChain } from "@traceloop/instrumentation-langchain";
import { afterEach, describe, expect, it } from "vitest";
import { verify } from "../src/index.js";
import { useProject } from "./helpers.js";
import { marker, provider, runLangChainAgent, seen, toolRecords, unregister } from "./otel-helpers.js";

describe("signafaide/otel with OpenLLMetry's LangChain instrumentation", () => {
  useProject();
  afterEach(unregister);

  it("OpenLLMetry LangChain: the decision is written after the tool ran", async () => {
    // OpenLLMetry's LangChain instrumentation starts the span and then sets its attributes
    // (gen_ai.operation.name = execute_tool), so the processor's start hook does not see them.
    const instrumentation = new OpenLLMetryLangChain();
    instrumentation.setTracerProvider(provider());
    instrumentation.manuallyInstrument({ callbackManagerModule: CallbackManagerModule });
    try {
      await runLangChainAgent();
    } finally {
      instrumentation.disable();
    }
    expect(seen.calls).toEqual([]);
    const recs = toolRecords();
    // The instrumentation names the span after the tool's class (DynamicStructuredTool); the
    // tool's own name is in the LangChain tool message the span carries as its result.
    expect(recs.map((r) => `${r.envelope.kind} ${r.envelope.name}`)).toEqual(["decision lookup_order", "outcome lookup_order"]);
    expect(marker()).toMatchObject({ convention: "gen_ai", decision_written: "after" });
    expect((await verify()).ok).toBe(true);
  });
});
