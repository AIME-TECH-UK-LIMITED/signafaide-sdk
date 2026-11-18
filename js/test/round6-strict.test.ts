/** Fix round 6 (#52): the first strict refusal in a process prints one stderr line. */
import { describe, expect, it } from "vitest";
import { SignafaideBlocked, record } from "../src/index.js";
import { useProject } from "./helpers.js";

const ctx = useProject();

describe("#52: a strict tool refused for no_key", () => {
  it("prints one stderr line naming the tool and the fix, once per process", async () => {
    const said: string[] = [];
    const warn = console.warn;
    console.warn = (s: string) => said.push(s);
    let ran = 0;
    const refund = record(async () => ++ran, { name: "refund_payment", strict: true });
    const freeze = record(async () => ++ran, { name: "freeze_account", strict: true });
    try {
      // A framework that swallows the tool's error, as the Vercel AI SDK does.
      for (const tool of [refund, freeze, refund]) await tool().catch((e) => expect(e).toBeInstanceOf(SignafaideBlocked)); // protected in code: ruled as with a checks file (patch 0.5.1)
    } finally {
      console.warn = warn;
    }
    expect(ran).toBe(0);
    const lines = said.filter((l) => l.includes("protected tool"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('signafaide: protected tool "refund_payment" was refused and did not run (no_key)');
    expect(lines[0]).toContain("protected tools stop until a person runs `npx signafaide protect` in this project");
    expect(lines[0]).not.toMatch(/WARN/i);
    expect(ctx.service.calls).toEqual([]);
  });
});
