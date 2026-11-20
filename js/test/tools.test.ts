/** Tool declarations (SPEC §2.6): `wrapTools` declares what it wraps, `declareTools` the agent's full list. */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { toolNote, toolNoteName } from "../src/coverage.js";
import {
  TOOL_SOURCE_MAX_AGE_MS,
  TOOL_SOURCE_REFRESH_MS,
  autoDeclareTools,
  declareTools,
  flush,
  note,
  record,
  verify,
  wrapTool,
  wrapTools,
} from "../src/index.js";
import { parseJson } from "../src/jcs.js";
import { recordHash } from "../src/records.js";
import { Recorder, configure, getRecorder } from "../src/runtime.js";
import { useProject } from "./helpers.js";

const ctx = useProject();
const chain = (agent = "claims-project") =>
  getRecorder()
    .state.chains()
    .filter((c) => c.split("/")[2] === agent)
    .flatMap((c) => getRecorder().state.readAll(c));
const names = (agent?: string) => chain(agent).map((r) => `${r.envelope.kind}:${r.envelope.name}`);
const coverage = async () => (await verify()).coverageLines().map((l) => l.replace(/^_pending\/nokey\//, ""));

describe("wrapTools declares the tools it wraps", () => {
  it("with the first recorded call: one header, one note per tool in name order, nothing between them", async () => {
    const tools = wrapTools({ refund: (id: string) => id, lookup: (id: string) => id }, { agent: "support-bot" });
    expect(getRecorder().state.chains()).toEqual([]); // wrapping writes nothing
    tools.refund("o1");
    expect(names("support-bot")).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/lookup",
      "note:signafaide.tool/refund",
      "decision:refund",
      "outcome:refund",
    ]);
    const [header, first, second, decision] = chain("support-bot");
    expect(header.content).toEqual({ source: "wrap_tools", tools: 2, recorded: 2, unrecorded: 0 });
    expect(first.content).toEqual({ tool: "lookup", recorded: true });
    expect([header, first, second, decision].map((r) => r.envelope.seq)).toEqual([1, 2, 3, 4]);
    expect(second.envelope.prev).toBe(recordHash(first));
    // Once per process for the same list.
    tools.lookup("o2");
    tools.refund("o3");
    expect(names("support-bot").filter((n) => n === "note:signafaide.tools")).toHaveLength(1);
    expect(await coverage()).toEqual(["support-bot: all 2 declared tools are recorded"]);
  });

  it("again when the list grows, and for each agent on its own", () => {
    const a = wrapTools({ one: () => 1 }, { agent: "bot-a" });
    a.one();
    const more = wrapTools([function two() {}], { agent: "bot-a" });
    const b = wrapTools({ other: () => 1 }, { agent: "bot-b" });
    more[0]();
    b.other();
    expect(names("bot-a")).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/one",
      "decision:one",
      "outcome:one",
      "note:signafaide.tools",
      "note:signafaide.tool/one",
      "note:signafaide.tool/two",
      "decision:two",
      "outcome:two",
    ]);
    expect(names("bot-b")).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/other",
      "decision:other",
      "outcome:other",
    ]);
  });

  it("a new recorder (a new process instance) declares again", () => {
    const tools = wrapTools({ one: () => 1 });
    tools.one();
    configure({ quiet: true, flushIntervalMs: 3_600_000 });
    tools.one();
    expect(names().filter((n) => n === "note:signafaide.tools")).toHaveLength(2);
  });

  it("can be turned off: declareTools: false, or SIGNAFAIDE_DECLARE_TOOLS=0", () => {
    wrapTools({ quiet: () => 1 }, { declareTools: false }).quiet();
    wrapTool(() => 2, { name: "single", declareTools: false })();
    expect(names()).toEqual(["decision:quiet", "outcome:quiet", "decision:single", "outcome:single"]);
    process.env.SIGNAFAIDE_DECLARE_TOOLS = "0";
    expect(autoDeclareTools()).toBe(false);
    wrapTools({ loud: () => 1 }).loud();
    expect(names().slice(4)).toEqual(["decision:loud", "outcome:loud"]);
    delete process.env.SIGNAFAIDE_DECLARE_TOOLS;
    expect(autoDeclareTools()).toBe(true);
  });

  it("record() alone declares nothing: the list is unknown", async () => {
    record(() => 1, { name: "approve" })();
    expect(names()).toEqual(["decision:approve", "outcome:approve"]);
    expect(await coverage()).toEqual([
      "claims-project: no tool list was declared, so the pack cannot show which of the agent's tools are recorded",
    ]);
  });

  it("a failure to write the declaration never fails the tool call", () => {
    const long = wrapTools({ ["bad\u0001name"]: () => "ran" });
    const errors: string[] = [];
    const error = console.error;
    console.error = (s: string) => errors.push(s);
    try {
      expect(long["bad\u0001name"]()).toBe("ran");
    } finally {
      console.error = error;
    }
    expect(errors).toEqual([
      expect.stringContaining(
        "signafaide: could not write the tool declaration for claims-project: a tool name must be a non-empty string without control characters",
      ),
    ]);
    expect(names()).toEqual(["decision:bad\u0001name", "outcome:bad\u0001name"]);
    long["bad\u0001name"](); // said once, not on every call
    expect(errors).toHaveLength(1);
  });
});

describe("declareTools: the agent's full tool list", () => {
  it("a tool is recorded when the SDK wrapped it here, otherwise not recorded", async () => {
    const tools = wrapTools({ refund: () => 1 }, { agent: "support-bot" });
    record(() => 1, { name: "lookup", agent: "support-bot" });
    const hash = declareTools(["refund", "lookup", "send_email", "delete_account"], { agent: "support-bot" });
    expect(names("support-bot")).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool_unrecorded/delete_account",
      "note:signafaide.tool/lookup",
      "note:signafaide.tool/refund",
      "note:signafaide.tool_unrecorded/send_email",
    ]);
    const [header, first] = chain("support-bot");
    expect(hash).toBe(recordHash(header));
    expect(header.content).toEqual({ source: "declared", tools: 4, recorded: 2, unrecorded: 2 });
    expect(first.content).toEqual({ tool: "delete_account", recorded: false });
    expect(await coverage()).toEqual(["support-bot: 2 declared tools are not recorded: delete_account, send_email"]);
    // The same list again writes nothing; calls write no second declaration (the list given wins over wrapTools' own).
    expect(declareTools(["refund", "lookup", "send_email", "delete_account"], { agent: "support-bot" })).toBe(hash);
    tools.refund();
    expect(names("support-bot").filter((n) => n === "note:signafaide.tools")).toHaveLength(1);
  });

  it("unrecorded names tools that are known not to be wrapped, whatever the SDK wrapped", async () => {
    wrapTools({ search: () => 1 });
    declareTools(["search"], { unrecorded: ["search", "browser"] });
    expect(names()).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool_unrecorded/browser",
      "note:signafaide.tool_unrecorded/search",
    ]);
    expect(await coverage()).toEqual(["claims-project: 2 declared tools are not recorded: browser, search"]);
  });

  it("a tool of the list that is wrapped later is declared again as recorded, with the next call", async () => {
    declareTools(["refund", "lookup"]);
    expect(names()).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool_unrecorded/lookup",
      "note:signafaide.tool_unrecorded/refund",
    ]);
    const tools = wrapTools({ refund: () => 1, extra: () => 2 });
    tools.refund();
    tools.extra();
    expect(names().slice(3)).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool_unrecorded/lookup",
      "note:signafaide.tool/refund",
      "decision:refund",
      "outcome:refund",
      "decision:extra",
      "outcome:extra",
    ]);
    expect(await coverage()).toEqual([
      "claims-project: 1 declared tool is not recorded: lookup",
      "claims-project: 1 recorded tool is not in the declared tool list: extra",
    ]);
  });

  it("rejects names that are not tool names; a long name is cut as the spec says", async () => {
    expect(() => declareTools(["ok", ""])).toThrow(/non-empty strings/);
    expect(() => declareTools([3 as unknown as string])).toThrow(/non-empty strings/);
    const long = "report_" + "quarterly_figures_".repeat(8);
    wrapTools({ [long]: () => 1 });
    declareTools([long, "short"]);
    expect(names()).toEqual([
      "note:signafaide.tools",
      `note:${toolNoteName(long, true)}`,
      "note:signafaide.tool_unrecorded/short",
    ]);
    expect([...toolNoteName(long, true)].length).toBe(117);
    expect(chain()[1].content).toEqual({ tool: long, recorded: true });
  });

  it("SIGNAFAIDE_DISABLED=1: nothing is written", () => {
    process.env.SIGNAFAIDE_DISABLED = "1";
    try {
      expect(declareTools(["a"])).toBe("");
      wrapTools({ a: () => 1 }).a();
      expect(getRecorder().state.chains()).toEqual([]);
    } finally {
      delete process.env.SIGNAFAIDE_DISABLED;
    }
  });

  it("test mode: declarations go to the temporary folder with the other records, and nothing is sent", async () => {
    process.env.SIGNAFAIDE_TEST = "1";
    const rec = configure({ quiet: true });
    try {
      expect(rec.test).toBe(true);
      wrapTools({ a: () => 1 }).a();
      expect(rec.state.home).not.toBe(path.join(ctx.root, ".signafaide"));
      expect(rec.state.readAll("_pending/nokey/claims-project").map((r) => r.envelope.name)).toEqual([
        "signafaide.tools",
        "signafaide.tool/a",
        "a",
        "a",
      ]);
      expect((await rec.flush()).shipped).toBe(0);
      expect(fs.existsSync(path.join(ctx.root, ".signafaide"))).toBe(false);
      expect(ctx.service.calls).toEqual([]);
    } finally {
      rec.close();
      process.env.SIGNAFAIDE_TEST = "0";
    }
  });
});

describe("declarations in the chain", () => {
  it("local first: written as drafts, then shipped like any record once a person opts in; the pack shows the coverage", async () => {
    const tools = wrapTools({ refund: () => 1, lookup: () => 2 }, { agent: "support-bot" });
    declareTools(["refund", "lookup", "send_email"], { agent: "support-bot" });
    tools.refund();
    expect(ctx.service.calls).toEqual([]);
    expect(chain("support-bot").every((r) => r.draft)).toBe(true);
    await ctx.rec.createSandbox();
    const r = await flush();
    expect([r.shipped, r.left]).toEqual([6, 0]); // the header and three tool notes count as records
    expect(ctx.service.project().used).toBe(6);
    const pack = parseJson(JSON.stringify(await ctx.rec.client().export("support-bot")));
    const report = await verify(pack);
    expect(report.ok, String(report)).toBe(true);
    expect(report.coverageLines()).toEqual(["support-bot: 1 declared tool is not recorded: send_email"]);
    expect(JSON.parse(JSON.stringify(report)).coverage).toEqual({
      "support-bot": {
        declared: [
          { name: "lookup", recorded: true },
          { name: "refund", recorded: true },
          { name: "send_email", recorded: false },
        ],
        undeclared_recorded: [],
        declared_at_seq: 1,
      },
    });
    // Hash-only: the witness never saw the notes' content, only their envelopes.
    expect(pack.records.every((x: any) => x.content === undefined)).toBe(true);
  });

  it("several sources on one machine: each declaration lists the agent's whole tool list, recorded when any source records it", async () => {
    const rec = getRecorder();
    rec.declareTools({ "files.read": true, "files.write": true }, { source: "gateway:files.", origin: "gateway" });
    wrapTools({ refund: () => 1 });
    declareTools(["refund", "files.read", "browser"]); // the application does not know the gateway records files.read
    const last = chain().slice(3);
    expect(last.map((r) => r.envelope.name)).toEqual([
      "signafaide.tools",
      "signafaide.tool_unrecorded/browser",
      "signafaide.tool/files.read",
      "signafaide.tool/files.write",
      "signafaide.tool/refund",
    ]);
    expect(last[0].content).toEqual({ source: "declared", tools: 4, recorded: 3, unrecorded: 1 });
    expect(rec.state.toolSources("claims-project")).toEqual({
      "gateway:files.": { "files.read": true, "files.write": true },
      sdk: { refund: true, "files.read": false, browser: false },
    });
    expect(JSON.parse(fs.readFileSync(rec.state.toolsPath("claims-project"), "utf8")).sources.sdk.at).toMatch(
      /^\d{4}-/,
    );
    // Another process (a new recorder) of one source declares again, and still lists the other's tools.
    const again = new Recorder({ quiet: true });
    again.declareTools({ "files.read": true }, { source: "gateway:files.", origin: "gateway" });
    again.close();
    expect(
      chain()
        .slice(8)
        .map((r) => r.envelope.name),
    ).toEqual([
      "signafaide.tools",
      "signafaide.tool_unrecorded/browser",
      "signafaide.tool/files.read",
      "signafaide.tool/refund",
    ]);
    expect(await coverage()).toEqual(["claims-project: 1 declared tool is not recorded: browser"]);
  });

  it("a declaration is one uninterrupted run, even while another process writes to the same chain", async () => {
    const dist = path.resolve(__dirname, "../dist/index.js");
    if (!fs.existsSync(dist)) throw new Error(`${dist} is not built: run \`npm run build\` in js/ (\`npm test\` does)`);
    note("first", {}); // the chain exists before both writers start
    const script = `import { note } from ${JSON.stringify(dist)};\nfor (let i = 0; i < 400; i++) note("other_writer", { i });\n`;
    fs.writeFileSync(path.join(ctx.root, "writer.mjs"), script);
    const child = spawn(process.execPath, [path.join(ctx.root, "writer.mjs")], {
      cwd: ctx.root,
      env: { PATH: process.env.PATH ?? "", SIGNAFAIDE_TEST: "0" },
      stdio: "ignore",
    });
    const closed = new Promise<number | null>((r) => child.on("close", r));
    const tools = Object.fromEntries(
      Array.from({ length: 25 }, (_, i) => [`tool_${String(i).padStart(2, "0")}`, true]),
    );
    let runs = 0;
    while (child.exitCode === null && runs < 200) {
      const rec = new Recorder({ quiet: true }); // each one declares, as a new process would
      rec.declareTools(tools, { source: "sdk", origin: "declared" });
      rec.close();
      runs++;
      await new Promise((r) => setTimeout(r, 2));
    }
    expect(await closed).toBe(0);
    const all = chain();
    expect(all.filter((r) => r.envelope.name === "other_writer")).toHaveLength(400);
    const headers = all.flatMap((r, i) => (r.envelope.name === "signafaide.tools" ? [i] : []));
    expect(headers.length).toBe(runs);
    expect(runs).toBeGreaterThan(3);
    for (const i of headers) {
      const run = all.slice(i + 1, i + 26);
      expect(run.map((r) => r.envelope.name)).toEqual(Object.keys(tools).map((t) => `signafaide.tool/${t}`));
    }
    // Both writers interleaved, and the chain is still one valid chain.
    const firstOther = all.findIndex((r) => r.envelope.name === "other_writer");
    expect(headers.some((i) => i > firstOther)).toBe(true);
    expect(all.map((r) => r.envelope.seq)).toEqual(all.map((_, i) => i + 1));
    expect(all.filter((r) => toolNote(r.envelope.kind, r.envelope.name)).length).toBe(runs * 26);
    expect((await verify()).ok).toBe(true);
  });
});

describe("the agent's tool list stays fresh (SPEC §8)", () => {
  const HOUR = 3_600_000;
  const ago = (ms: number): string => new Date(Date.now() - ms).toISOString();
  const file = () => getRecorder().state.toolsPath("claims-project");
  /** Write tools/<agent>.json as other sources left it. */
  const leave = (sources: Record<string, { at: string; tools: Record<string, boolean> }>): void => {
    fs.mkdirSync(path.dirname(file()), { recursive: true });
    fs.writeFileSync(file(), JSON.stringify({ sources }));
  };
  const entries = () =>
    JSON.parse(fs.readFileSync(file(), "utf8")).sources as Record<
      string,
      { at: string; tools: Record<string, boolean> }
    >;

  it("the two durations are an hour and 24 hours", () => {
    expect([TOOL_SOURCE_REFRESH_MS, TOOL_SOURCE_MAX_AGE_MS]).toEqual([HOUR, 24 * HOUR]);
  });

  it("a declaration drops a source not refreshed for more than 24 hours, and keeps a fresh one", async () => {
    const liveAt = ago(23 * HOUR);
    leave({
      "gateway:gone": { at: ago(25 * HOUR), tools: { "gone.delete": true } },
      "gateway:live": { at: liveAt, tools: { "live.read": true } },
      "gateway:broken": { at: "not a time", tools: { "broken.x": true } },
    });
    wrapTools({ refund: () => 1 }).refund();
    expect(names()).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/live.read",
      "note:signafaide.tool/refund",
      "decision:refund",
      "outcome:refund",
    ]);
    expect(Object.keys(entries())).toEqual(["gateway:live", "sdk"]);
    expect(entries()["gateway:live"].at).toBe(liveAt); // another source's time is not touched
    expect(Date.now() - Date.parse(entries().sdk.at)).toBeLessThan(60_000);
    expect(await coverage()).toEqual(["claims-project: all 2 declared tools are recorded"]);
  });

  it("a refresh updates the own entry's time; a source that stopped drops out, with a new declaration without its tools", async () => {
    const rec = getRecorder();
    leave({ "gateway:old": { at: ago(2 * HOUR), tools: { "old.delete": true } } });
    wrapTools({ refund: () => 1 }).refund();
    expect(names().slice(0, 3)).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/old.delete",
      "note:signafaide.tool/refund",
    ]);
    // Nothing changed: a refresh touches the file only.
    leave({ ...entries(), sdk: { ...entries().sdk, at: ago(2 * HOUR) } });
    rec.refreshToolSources();
    expect(Date.now() - Date.parse(entries().sdk.at)).toBeLessThan(60_000);
    expect(names()).toHaveLength(5);
    // The gateway stopped without a clean exit: 25 hours later its entry is dropped at the next refresh.
    leave({ ...entries(), "gateway:old": { ...entries()["gateway:old"], at: ago(25 * HOUR) } });
    rec.refreshToolSources();
    expect(Object.keys(entries())).toEqual(["sdk"]);
    expect(names().slice(5)).toEqual(["note:signafaide.tools", "note:signafaide.tool/refund"]);
    expect(chain()[5].content).toEqual({ source: "wrap_tools", tools: 1, recorded: 1, unrecorded: 0 });
    rec.refreshToolSources(); // and only once
    expect(names()).toHaveLength(7);
    expect(await coverage()).toEqual(["claims-project: the 1 declared tool is recorded"]);
  });

  it("an expired source whose tools another source still declares changes nothing in the chain", () => {
    leave({ "gateway:old": { at: ago(30 * HOUR), tools: { refund: true } } });
    wrapTools({ refund: () => 1 }).refund();
    expect(names()).toEqual([
      "note:signafaide.tools",
      "note:signafaide.tool/refund",
      "decision:refund",
      "outcome:refund",
    ]);
    leave({ ...entries(), "gateway:other": { at: ago(30 * HOUR), tools: { refund: true } } });
    getRecorder().refreshToolSources();
    expect(Object.keys(entries())).toEqual(["sdk"]);
    expect(names()).toHaveLength(4);
  });

  it("a clean shutdown removes the own entry and writes nothing to the chain", async () => {
    leave({ "gateway:live": { at: ago(HOUR), tools: { "live.read": true } } });
    const rec = getRecorder();
    declareTools(["refund"], { unrecorded: ["refund"] });
    expect(Object.keys(entries())).toEqual(["gateway:live", "sdk"]);
    const before = names().length;
    await rec.shutdown();
    expect(Object.keys(entries())).toEqual(["gateway:live"]);
    expect(names()).toHaveLength(before);
    rec.refreshToolSources(); // nothing left to refresh: the entry does not come back
    expect(Object.keys(entries())).toEqual(["gateway:live"]);
  });

  it("the hourly refresh never keeps a program alive, and a program that ends removes its entry", async () => {
    const rec = getRecorder();
    declareTools(["a"]);
    const timer = (rec as unknown as { toolTimer?: NodeJS.Timeout }).toolTimer;
    expect(timer?.hasRef()).toBe(false);
    rec.close();
    expect((rec as unknown as { toolTimer?: NodeJS.Timeout }).toolTimer).toBeUndefined();

    const dist = path.resolve(__dirname, "../dist/index.js");
    if (!fs.existsSync(dist)) throw new Error(`${dist} is not built: run \`npm run build\` in js/ (\`npm test\` does)`);
    const script = `import * as fs from "node:fs";\nimport { declareTools, getRecorder } from ${JSON.stringify(dist)};\ndeclareTools(["b"], { agent: "child-bot" });\nconsole.log(fs.readFileSync(getRecorder().state.toolsPath("child-bot"), "utf8"));\n`;
    fs.writeFileSync(path.join(ctx.root, "declare.mjs"), script);
    const started = Date.now();
    const child = spawn(process.execPath, [path.join(ctx.root, "declare.mjs")], {
      cwd: ctx.root,
      env: { PATH: process.env.PATH ?? "", SIGNAFAIDE_TEST: "0" },
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    expect(await new Promise((r) => child.on("close", r))).toBe(0);
    expect(Date.now() - started).toBeLessThan(10_000); // an hourly timer that held the process would time this test out
    expect(Object.keys(JSON.parse(out).sources)).toEqual(["sdk"]); // while it ran
    expect(getRecorder().state.toolSources("child-bot")).toEqual({}); // after its normal exit
  });
});
