/** Records survive process exit: the built package in a child process. */
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { hashJson } from "../src/crypto.js";
import { Recorder } from "../src/runtime.js";
import { deadUrl, useProject } from "./helpers.js";

const ctx = useProject();
const dist = path.resolve(__dirname, "../dist");

/** Async, so the fake service in this process keeps answering the child. */
function run(script: string, env: Record<string, string>): Promise<{ status: number | null; stderr: string }> {
  const file = path.join(ctx.root, "agent.mjs");
  fs.writeFileSync(file, script);
  const child = spawn(process.execPath, [file], { cwd: ctx.root, env: { PATH: process.env.PATH ?? "", ...env } });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  return new Promise((resolve) => child.on("close", (status) => resolve({ status, stderr })));
}

describe.skipIf(!fs.existsSync(path.join(dist, "index.js")))("process exit (built package)", () => {
  it("without a key: records locally, sends nothing, says so once", async () => {
    const p = await run(`import { record } from ${JSON.stringify(path.join(dist, "index.js"))};\nrecord(() => 1, { name: "x" })();\nrecord(() => 2, { name: "y" })();\n`, { SIGNAFAIDE_URL: ctx.service.url });
    expect(p.status, p.stderr).toBe(0);
    expect(ctx.service.calls).toEqual([]);
    expect(p.stderr.match(/recording locally/g)).toHaveLength(1);
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    expect(new Recorder({ quiet: true }).state.draftCount("_pending/nokey/claims-project")).toBe(4);
  });

  it("ships on exit once a person opted in", async () => {
    await new Recorder({ quiet: true, url: ctx.service.url }).createSandbox();
    const p = await run(`import { record } from ${JSON.stringify(path.join(dist, "index.js"))};\nrecord(() => 1, { name: "x" })();\n`, { SIGNAFAIDE_URL: ctx.service.url });
    expect(p.status, p.stderr).toBe(0);
    expect(p.stderr).not.toContain("recording locally");
    expect(new Recorder({ quiet: true }).state.outboxSize()).toBe(0);
    expect(ctx.service.calls).toContain("POST /v1/records");
  });

  it("keeps records offline, then ships them", async () => {
    const rec = new Recorder({ quiet: true, url: ctx.service.url });
    await rec.createSandbox(); // a real sandbox key in .env, which the child reads
    const p = await run(`import { record } from ${JSON.stringify(path.join(dist, "index.js"))};\nrecord(() => 1, { name: "x" })();\n`, {
      SIGNAFAIDE_URL: await deadUrl(),
    });
    expect(p.status, p.stderr).toBe(0);
    expect(p.stderr).toContain("2 records kept");
    expect(rec.state.outboxSize()).toBe(2);
    expect((await rec.flush()).shipped).toBe(2);
  });

  it("works from CommonJS", () => {
    const file = path.join(ctx.root, "agent.cjs");
    fs.writeFileSync(file, `const s = require(${JSON.stringify(path.join(dist, "index.cjs"))});\nconsole.log(typeof s.record, typeof s.wrapTools, s.hashJson({b:1,a:2}));\n`);
    const p = spawnSync(process.execPath, [file], { cwd: ctx.root, encoding: "utf8", env: { PATH: process.env.PATH ?? "" } });
    expect(p.status, p.stderr).toBe(0);
    expect(p.stdout.trim()).toBe(`function function ${hashJson({ a: 2, b: 1 })}`);
  });

  it("runs the CLI binary", () => {
    const p = spawnSync(process.execPath, [path.join(dist, "cli.js"), "--version"], { encoding: "utf8" });
    expect(p.status).toBe(0);
    expect(p.stdout).toMatch(/^signafaide \d/);
  });
});
