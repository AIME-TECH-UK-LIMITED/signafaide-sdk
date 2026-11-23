import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach } from "vitest";
import { configure, getRecorder, type Recorder } from "../src/runtime.js";
import { ADAPTERS } from "../src/telemetry.js";
import { resetToolRegistry } from "../src/record.js";
import { FakeService } from "./fake-service.js";

const AGENT_ENV = [
  "SIGNAFAIDE_",
  "CLAUDE",
  "CODEX_",
  "CURSOR_",
  "GEMINI_CLI",
  "COPILOT_",
  "GITHUB_COPILOT_",
  "WINDSURF_",
];

export interface Ctx {
  root: string;
  service: FakeService;
  rec: Recorder;
}

/** A fresh project folder (cwd), a fake service and a default recorder pointed at it. With
 * `optIn`, the person has run `signafaide init` (a sandbox key in .env), so records ship;
 * without it the project is local-only and nothing is sent. */
export function useProject(opts: { optIn?: boolean } = {}): Ctx {
  const ctx = {} as Ctx;
  const cwd = process.cwd();
  beforeEach(async () => {
    // tests decide which coding agent they run under
    for (const k of Object.keys(process.env)) if (AGENT_ENV.some((p) => k.startsWith(p))) delete process.env[k];
    delete process.env.TERM_PROGRAM;
    // The SDK turns test mode on by itself under Vitest; these tests exercise the real recorder.
    process.env.SIGNAFAIDE_TEST = "0";
    // Sessions stay in a temporary session.json, never in this machine's credential store.
    process.env.SIGNAFAIDE_CREDENTIAL_STORE = "file";
    ADAPTERS.clear();
    resetToolRegistry(); // tools wrapped by an earlier test are not this test's tool list
    ctx.root = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sfa-js-")), "Claims Project");
    fs.mkdirSync(path.join(ctx.root, ".git"), { recursive: true });
    process.chdir(ctx.root);
    ctx.service = await new FakeService().start();
    process.env.SIGNAFAIDE_URL = ctx.service.url;
    ctx.rec = configure({ quiet: true, flushIntervalMs: 3_600_000 });
    if (opts.optIn) await ctx.rec.createSandbox();
  });
  afterEach(async () => {
    ctx.rec.close();
    // No request of this test outlives it (a later test's fake service may get the same port).
    await ctx.rec.checks.settled();
    configure({ quiet: true }).close();
    await ctx.service.close();
    process.chdir(cwd);
    fs.rmSync(path.dirname(ctx.root), { recursive: true, force: true });
  });
  return ctx;
}

/** A URL nothing listens on. */
export async function deadUrl(): Promise<string> {
  const srv = net.createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as net.AddressInfo).port;
  await new Promise((r) => srv.close(r));
  return `http://127.0.0.1:${port}`;
}

/** The single chain id of `agent` in the (project, env, agent) layout. */
export function chainOf(agent = "claims-project"): string {
  const found = getRecorder()
    .state.chains()
    .filter((c) => c.split("/")[2] === agent);
  if (found.length !== 1) throw new Error(`expected one chain for ${agent}, got ${found.join(", ")}`);
  return found[0];
}

/** The chain's lines, drafts included: before the first flush the project is not known, so they are drafts (§8). */
export const records = (agent = "claims-project") => getRecorder().state.readAll(chainOf(agent));
export const chainFile = (agent = "claims-project") => getRecorder().state.chainPath(chainOf(agent));

export function errorFor(r: { errors: Record<string, any> }, agent = "claims-project"): any {
  let found = Object.entries(r.errors).filter(([c]) => c.split("/")[2] === agent);
  // Errors about the API key are named after the key, not a chain.
  if (!found.length) found = Object.entries(r.errors).filter(([c]) => c.startsWith("API key "));
  if (found.length !== 1) throw new Error(`expected one error for ${agent}, got ${Object.keys(r.errors).join(", ")}`);
  return found[0][1];
}
