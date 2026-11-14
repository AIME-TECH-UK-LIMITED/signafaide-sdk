import * as fs from "node:fs";
import * as path from "node:path";
import { tool as lcTool } from "@langchain/core/tools";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { main } from "../src/cli.js";
import { flush, init, note, wrapTools } from "../src/index.js";
import { clientHeader, detectAgent } from "../src/telemetry.js";
import { VERSION } from "../src/version.js";
import { deadUrl, useProject } from "./helpers.js";

/** The result line without its check counts (§7), to compare the rest. */
const noCounts = (line: string | undefined): string => (line ?? "").replace(/: \d+ of 12 checks [^;]*; /, ": ").replace(/: \d+ of 12 checks [^;]*$/, "");


const ctx = useProject({ optIn: true });

describe("detectAgent", () => {
  it.each([
    [{ CLAUDECODE: "1" }, "claude-code"],
    [{ CLAUDE_CODE_ENTRYPOINT: "cli" }, "claude-code"],
    [{ CLAUDECODE: "1", CODEX_COMPANION_SESSION_ID: "x", TERM_PROGRAM: "cursor" }, "claude-code"],
    [{ CODEX_SANDBOX: "seatbelt" }, "codex"],
    [{ CODEX_COMPANION_SESSION_ID: "x" }, "unknown"],
    [{ CURSOR_TRACE_ID: "x" }, "cursor"],
    [{ TERM_PROGRAM: "cursor" }, "cursor"],
    [{ GEMINI_CLI: "1" }, "gemini-cli"],
    [{ COPILOT_AGENT: "1" }, "copilot"],
    [{ WINDSURF_SESSION: "1" }, "windsurf"],
    [{ TERM_PROGRAM: "vscode" }, "unknown"],
    [{}, "unknown"],
  ])("%j -> %s", (env, agent) => expect(detectAgent(env)).toBe(agent));
});

describe("X-Signafaide-Client", () => {
  const node = process.versions.node;

  it("has the agreed format, and drops adapter and agent on opt-out", () => {
    expect(clientHeader({ via: "cli", adapter: "langchain", agent: "codex", env: {} })).toBe(`signafaide-js/${VERSION} (node ${node}; adapter=langchain; agent=codex; via=cli)`);
    expect(clientHeader({ env: {} })).toBe(`signafaide-js/${VERSION} (node ${node}; adapter=none; agent=unknown; via=sdk)`);
    expect(clientHeader({ adapter: "langchain", agent: "codex", env: { SIGNAFAIDE_TELEMETRY: "0" } })).toBe(`signafaide-js/${VERSION} (node ${node}; via=sdk)`);
  });

  it("is on every request, and never guesses the coding agent per process", async () => {
    // A program started from a terminal inside a coding agent is not that agent: only set-up
    // time (init, agent setup) records the agent.
    process.env.CODEX_SANDBOX = "seatbelt";
    ctx.service.clientIds.length = 0; // the sandbox was created before this test chose its agent
    note("a", {});
    await flush();
    expect(ctx.service.clientIds.length).toBeGreaterThanOrEqual(2); // register, records
    for (const c of ctx.service.clientIds) expect(c).toMatch(/^signafaide-js\/\S+ \(node [^;]+; adapter=none; agent=unknown; via=sdk\)$/);
  });

  it("adds strict=1 once a strict tool ran", async () => {
    const { record } = await import("../src/index.js");
    await record(() => 1, { name: "pay", strict: true })();
    expect(ctx.service.clientIds.at(-1)).toMatch(/; via=sdk; strict=1\)$/);
    expect(clientHeader({ strict: true, env: { SIGNAFAIDE_TELEMETRY: "0" } })).toMatch(/\(node [^;]+; via=sdk\)$/);
  });

  it("carries the agent stored at init", async () => {
    process.env.GEMINI_CLI = "1";
    const rec = await init({ url: ctx.service.url, quiet: true });
    expect(fs.existsSync(path.join(rec.state.home, "config.json")) && JSON.parse(fs.readFileSync(path.join(rec.state.home, "config.json"), "utf8")).agent).toBeFalsy(); // the library's init() does not guess
    rec.rememberAgent(); // what `signafaide init` and `agent setup` do
    expect(JSON.parse(fs.readFileSync(path.join(rec.state.home, "config.json"), "utf8")).agent).toBe("gemini-cli");
    delete process.env.GEMINI_CLI; // later: production, no coding agent around
    ctx.service.clientIds.length = 0;
    note("a", {});
    await flush();
    for (const c of ctx.service.clientIds) expect(c).toContain("agent=gemini-cli;");
  });

  it("names the adapters in use", async () => {
    const echo = lcTool(async ({ text }: { text: string }) => text, { name: "echo", description: "Echo", schema: z.object({ text: z.string() }) });
    const tools = wrapTools({ weather: { execute: async () => "sunny" }, echo });
    await tools.echo.invoke({ text: "x" });
    await flush();
    expect(ctx.service.clientIds.at(-1)).toContain("adapter=langchain,vercel-ai;");
  });

  it("opt-out: no agent, no adapter, no config.json", async () => {
    process.env.SIGNAFAIDE_TELEMETRY = "0";
    process.env.CLAUDECODE = "1";
    const rec = await init({ url: ctx.service.url, quiet: true });
    expect(rec.state.config().agent).toBeUndefined();
    ctx.service.clientIds.length = 0;
    note("a", {});
    await flush();
    for (const c of ctx.service.clientIds) expect(c).toMatch(/^signafaide-js\/\S+ \(node [^;]+; via=sdk\)$/);
  });
});

describe("CLI events", () => {
  async function cli(...args: string[]): Promise<[number, string, string]> {
    const out: string[] = [];
    const err: string[] = [];
    const [log, error] = [console.log, console.error];
    console.log = (s: string) => out.push(s);
    console.error = (s: string) => err.push(s);
    try {
      return [await main(args), out.join("\n"), err.join("\n")];
    } finally {
      [console.log, console.error] = [log, error];
    }
  }

  async function exported(): Promise<string> {
    await cli("init");
    note("n", {});
    await cli("flush");
    const pack = path.join(ctx.root, "p.json");
    expect((await cli("export", "-o", pack))[0]).toBe(0);
    return pack;
  }

  it("reports verify and export, via=cli", async () => {
    const pack = await exported();
    expect((await cli("verify", pack))[0]).toBe(0);
    expect(ctx.service.events).toEqual(["export", "verify"]);
    expect(ctx.service.clientIds.some((c) => c?.includes("via=cli)"))).toBe(true);
  });

  it("never fails the command", async () => {
    const pack = await exported();
    const keys = path.join(ctx.root, "k.json");
    fs.writeFileSync(keys, JSON.stringify({ keys: [ctx.service.keyDoc] }));
    process.env.SIGNAFAIDE_URL = await deadUrl(); // the event cannot be delivered
    const [code, out, err] = await cli("verify", pack, "--keys", keys);
    expect(code).toBe(0);
    expect(noCounts(out.split("\n").at(-1))).toMatch(/^PASS: export of every agent, all records, generated /);
    expect(err).toBe("");
  });

  it("sends nothing when opted out", async () => {
    process.env.SIGNAFAIDE_TELEMETRY = "0";
    const pack = await exported();
    await cli("verify", pack);
    expect(ctx.service.events).toEqual([]);
  });
});
