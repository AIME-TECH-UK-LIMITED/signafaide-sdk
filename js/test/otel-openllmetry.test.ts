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
    expect(recs.map((r) => r.envelope.kind)).toEqual(["decision", "outcome"]);
    expect(marker()).toMatchObject({ convention: "gen_ai", decision_written: "after" });
    expect((await verify()).ok).toBe(true);
  });
});
