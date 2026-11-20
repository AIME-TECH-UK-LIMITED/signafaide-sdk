/**
 * `signafaide gateway` as a program: the built command line (`npm run build`) in a child process,
 * with a fake MCP server behind it. Exit codes, signals, what goes to stdout, and a pack exported
 * after a gateway session checked by all three verifiers (TypeScript here, the Rust
 * `signafaide-verify` binary and the Python SDK).
 *
 * The cross-check needs the other two built: `cargo build --manifest-path verifier/Cargo.toml`
 * (or SIGNAFAIDE_VERIFY_BIN=<path of signafaide-verify>) and the Python SDK's environment,
 * `uv sync` in python/ (or SIGNAFAIDE_PYTHON=<a python that can import signafaide>).
 */
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { parseJson } from "../src/jcs.js";
import { loadDrandVerifier, parseAgentKeys, parseServiceKeys, verifyPack } from "../src/verifier.js";
import { Recorder } from "../src/runtime.js";
import { useProject } from "./helpers.js";

const ctx = useProject();
const repo = path.resolve(__dirname, "../..");
const CLI = path.resolve(__dirname, "../dist/cli.js");
const SERVER = path.resolve(__dirname, "fake-mcp-server.mjs");

class Gateway {
  readonly child: ChildProcessWithoutNullStreams;
  readonly closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  stdout = "";
  stderr = "";
  private wake: (() => void)[] = [];

  constructor(args: string[], env: Record<string, string> = {}, server: string[] = [process.execPath, SERVER]) {
    if (!fs.existsSync(CLI)) throw new Error(`${CLI} is not built: run \`npm run build\` in js/ (\`npm test\` does)`);
    this.child = spawn(process.execPath, [CLI, "gateway", ...args, ...(server.length ? ["--", ...server] : [])], {
      cwd: ctx.root,
      env: { PATH: process.env.PATH ?? "", SIGNAFAIDE_URL: ctx.service.url, SIGNAFAIDE_TEST: "0", ...env },
    });
    this.child.stdout.on("data", (d) => {
      this.stdout += d;
      this.wake.splice(0).forEach((w) => w());
    });
    this.child.stderr.on("data", (d) => (this.stderr += d));
    this.closed = new Promise((resolve) => this.child.on("close", (code, signal) => resolve({ code, signal })));
  }

  send(msg: object): void {
    this.child.stdin.write(JSON.stringify(msg) + "\n");
  }

  /** The answer to request `id`. */
  async answer(id: number, ms = 10_000): Promise<any> {
    const deadline = Date.now() + ms;
    for (;;) {
      for (const line of this.stdout.split("\n").slice(0, -1)) {
        const m = JSON.parse(line); // stdout holds protocol lines only: each one parses
        if (m.id === id && m.method === undefined) return m;
      }
      if (Date.now() > deadline) throw new Error(`no answer to ${id}; stdout ${this.stdout}; stderr ${this.stderr}`);
      await new Promise<void>((r) => {
        this.wake.push(r);
        setTimeout(r, 50);
      });
    }
  }

  end(): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
    this.child.stdin.end();
    return this.closed;
  }
}

/** The Rust verifier binary, built from this repository. */
function verifierBin(): string {
  const targets = [process.env.CARGO_TARGET_DIR, path.join(repo, "verifier/target")].filter(Boolean) as string[];
  if (process.env.SIGNAFAIDE_VERIFY_BIN) return process.env.SIGNAFAIDE_VERIFY_BIN;
  // The newest build, release or debug: an older one may be from before a change to the verifier.
  const built = targets
    .flatMap((t) => [path.join(t, "release/signafaide-verify"), path.join(t, "debug/signafaide-verify")])
    .filter((p) => fs.existsSync(p))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  if (!built.length)
    throw new Error(
      "the Rust verifier is not built: run `cargo build --manifest-path verifier/Cargo.toml` (or set SIGNAFAIDE_VERIFY_BIN)",
    );
  return built[0];
}

/** A Python that can import the Python SDK of this repository. */
function python(): string {
  const found = [process.env.SIGNAFAIDE_PYTHON, path.join(repo, "python/.venv/bin/python")].find(
    (p) => p && fs.existsSync(p),
  );
  if (!found)
    throw new Error("the Python SDK's environment is missing: run `uv sync` in python/ (or set SIGNAFAIDE_PYTHON)");
  return found;
}

describe("signafaide gateway (built command line)", () => {
  it("stdout holds only the relayed protocol lines; diagnostics and the server's stderr go to stderr; the exit code is the server's", async () => {
    const g = new Gateway(["--agent", "support-bot"]);
    g.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    await g.answer(1);
    g.send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect((await g.answer(2)).result.tools).toHaveLength(7);
    g.send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
    expect((await g.answer(3)).result.content[0].text).toBe('{"a":1}');
    g.send({ jsonrpc: "2.0", method: "test/exit", params: { code: 9 } });
    expect(await g.closed).toEqual({ code: 9, signal: null });
    const lines = g.stdout.split("\n").filter(Boolean);
    expect(lines.map((l) => JSON.parse(l).id)).toEqual([1, 2, 3]);
    expect(g.stderr).toContain("fake-mcp-server: started");
    expect(g.stderr).toContain("signafaide: recording locally in"); // no API key: said once, on stderr
    // Local first: nothing was sent, and the records are in the project's own folder.
    expect(ctx.service.calls).toEqual([]);
    const rec = new Recorder({ quiet: true });
    expect(rec.state.readAll("_pending/nokey/support-bot").map((r) => r.envelope.name)).toEqual([
      "signafaide.tools",
      ...["ask", "crash", "echo", "fail", "hang", "rpc_error", "slow"].map((t) => `signafaide.tool/${t}`),
      "echo",
      "echo",
    ]);
  });

  it("passes a signal on to the server, and ends by the signal that ended the server", async () => {
    const g = new Gateway([]);
    g.send({ jsonrpc: "2.0", id: 1, method: "ping" });
    await g.answer(1);
    g.child.kill("SIGTERM");
    expect(await g.closed).toEqual({ code: 143, signal: null }); // the fake server exits with 143 on SIGTERM
    expect(g.stderr).toContain("fake-mcp-server: SIGTERM");

    const k = new Gateway([]);
    k.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "hang" } });
    k.send({ jsonrpc: "2.0", id: 2, method: "ping" });
    await k.answer(2);
    k.send({ jsonrpc: "2.0", method: "test/kill", params: { signal: "SIGKILL" } });
    expect(await k.closed).toEqual({ code: null, signal: "SIGKILL" });
    // The call the server never answered has its outcome.
    const chain = new Recorder({ quiet: true }).state.readAll("_pending/nokey/claims-project");
    expect(chain.map((r) => `${r.envelope.kind}:${r.envelope.name}`)).toEqual(["decision:hang", "outcome:hang"]);
    expect(chain[1].content).toEqual({
      error: { type: "UpstreamExited", message: "the MCP server was ended by SIGKILL before it answered" },
    });
  });

  it("usage: no command is exit 2; --help prints the options and the limit; options after -- are the server's", async () => {
    const none = new Gateway(["--agent", "x"], {}, []);
    expect(await none.closed).toEqual({ code: 2, signal: null });
    expect(none.stderr).toContain(
      "usage: signafaide gateway [--agent X] [--name-prefix P] [--strict | --strict-tools a,b] [--store-content] -- <command> [args...]",
    );
    expect(none.stdout).toBe("");

    const help = spawnSync(process.execPath, [CLI, "gateway", "--help"], { encoding: "utf8" });
    expect(help.status).toBe(0);
    for (const flag of ["--agent", "--name-prefix", "--strict", "--strict-tools", "--store-content"])
      expect(help.stdout).toContain(flag);
    expect(help.stdout).toContain(
      "The gateway records every call that goes through it; a call the application makes around it is still not recorded, so the deployment has to make the gateway the only route to those tools.",
    );
    expect(help.stdout).toContain("npx -y mcp-remote https://mcp.example.com/mcp");

    const g = new Gateway([], {}, [process.execPath, SERVER, "--help", "--agent", "theirs"]);
    g.send({ jsonrpc: "2.0", id: 1, method: "ping" });
    await g.answer(1);
    expect(await g.end()).toEqual({ code: 0, signal: null });
    expect(g.stdout).not.toContain("usage:");
  });

  it("under a test runner the gateway is in test mode, like the SDK: nothing in the project folder, nothing sent", async () => {
    const g = new Gateway([], { SIGNAFAIDE_TEST: "", VITEST: "true" });
    g.send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    await g.answer(1);
    g.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo" } });
    await g.answer(2);
    expect(await g.end()).toEqual({ code: 0, signal: null });
    expect(fs.existsSync(path.join(ctx.root, ".signafaide", "chain"))).toBe(false);
    expect(ctx.service.calls).toEqual([]);
  });

  it("a pack exported after a gateway session verifies in all three verifiers, with the same coverage", async () => {
    await new Recorder({ quiet: true, url: ctx.service.url }).createSandbox(); // a person opted in: the key is in .env
    const g = new Gateway(["--agent", "support-bot", "--name-prefix", "files."]);
    g.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    await g.answer(1);
    g.send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    await g.answer(2);
    g.send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "echo", arguments: { path: "/data/a.txt" } },
    });
    await g.answer(3);
    g.send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "fail" } });
    await g.answer(4);
    expect(await g.end(), g.stderr).toEqual({ code: 0, signal: null });
    // The gateway shipped everything before it ended.
    const rec = new Recorder({ quiet: true, url: ctx.service.url });
    expect(rec.state.outboxSize()).toBe(0);
    expect(rec.status().outbox).toBe(0);

    const pack = await rec.client().export("support-bot");
    expect(pack.records).toHaveLength(12); // 1 header, 7 tool notes, 2 decisions, 2 outcomes
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-gateway-pack-"));
    try {
      const files = {
        pack: path.join(dir, "pack.json"),
        keys: path.join(dir, "keys.json"),
        agents: path.join(dir, "agent-keys.json"),
      };
      fs.writeFileSync(files.pack, JSON.stringify(pack));
      fs.writeFileSync(files.keys, JSON.stringify({ keys: [ctx.service.keyDoc] }));
      fs.writeFileSync(files.agents, JSON.stringify(rec.state.exportAgentKeys()));
      const line = "coverage: support-bot: all 7 declared tools are recorded";
      const args = [files.pack, "--keys", files.keys, "--agent-keys", files.agents, "--offline"];

      // TypeScript
      // The same inputs as the other two get: the pack, the service keys and the agent keys, offline.
      const ts = verifyPack(
        parseJson(fs.readFileSync(files.pack, "utf8")),
        parseServiceKeys({ keys: [ctx.service.keyDoc] }),
        { agentKeys: parseAgentKeys(rec.state.exportAgentKeys()), drand: await loadDrandVerifier() },
      );
      expect(ts.ok, String(ts)).toBe(true);
      expect(String(ts).split("\n")).toContain(line);
      const coverage = JSON.parse(JSON.stringify(ts)).coverage;
      expect(coverage["support-bot"].declared).toHaveLength(7);
      expect(coverage["support-bot"].declared[0]).toEqual({ name: "files.ask", recorded: true });
      expect(coverage["support-bot"]).toMatchObject({ undeclared_recorded: [], declared_at_seq: 1 });

      // Rust
      const rust = spawnSync(verifierBin(), args, { encoding: "utf8" });
      expect(rust.status, rust.stdout + rust.stderr).toBe(0);
      expect(rust.stdout.split("\n")).toContain(line);
      const rustJson = spawnSync(verifierBin(), [...args, "--json"], { encoding: "utf8" });
      expect(JSON.parse(rustJson.stdout).coverage).toEqual(coverage);

      // Python (run outside the project, so it reads only the files it is given)
      const env = { PATH: process.env.PATH ?? "", SIGNAFAIDE_TEST: "0", HOME: dir };
      const py = spawnSync(python(), ["-m", "signafaide", "verify", ...args], { encoding: "utf8", cwd: dir, env });
      expect(py.status, py.stdout + py.stderr).toBe(0);
      expect(py.stdout.split("\n")).toContain(line);
      const pyJson = spawnSync(python(), ["-m", "signafaide", "verify", ...args, "--json"], {
        encoding: "utf8",
        cwd: dir,
        env,
      });
      expect(JSON.parse(pyJson.stdout).coverage).toEqual(coverage);

      // The same result line from all three.
      const last = (text: string): string => text.trim().split("\n").at(-1)!;
      expect(last(rust.stdout)).toBe(ts.resultLine);
      expect(last(py.stdout)).toBe(ts.resultLine);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
