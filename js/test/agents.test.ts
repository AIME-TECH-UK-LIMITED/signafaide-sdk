import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { VERSION } from "../src/version.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AGENT_IDS, SETUP_NOTES, setup } from "../src/agents.js";
import { main } from "../src/cli.js";
import { SECTION_START, SKILL_BODY, claudeSkill } from "../src/skill.js";

let root: string;
let home: string;
let env: Record<string, string>;

beforeEach(() => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-agents-"));
  root = path.join(base, "proj");
  home = path.join(base, "home");
  fs.mkdirSync(root);
  fs.mkdirSync(home);
  env = { PATH: path.join(base, "bin"), CODEX_HOME: path.join(home, ".codex") };
});
afterEach(() => fs.rmSync(path.dirname(root), { recursive: true, force: true }));

const read = (f: string) => fs.readFileSync(path.join(root, f), "utf8");
const json = (f: string) => JSON.parse(read(f));
const run = (agents?: string[], dryRun = false) => setup({ root, agents, dryRun, env, home });
const SERVER = { command: "npx", args: ["-y", `signafaide@${VERSION}`, "mcp"] };

describe("agent setup", () => {
  it("writes every agent's native format", () => {
    const res = run(["all"]);
    expect(res.map((r) => r.agent)).toEqual(AGENT_IDS);
    expect(json(".mcp.json")).toEqual({ mcpServers: { signafaide: { type: "stdio", ...SERVER, env: {} } } });
    expect(read(".claude/skills/signafaide/SKILL.md")).toBe(claudeSkill());
    expect(read(".claude/skills/signafaide/SKILL.md")).toMatch(/^---\nname: signafaide\ndescription: Signed, tamper-evident/);
    expect(fs.readFileSync(path.join(home, ".codex/config.toml"), "utf8")).toBe(`[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide@${VERSION}", "mcp"]\n`);
    expect(json(".cursor/mcp.json")).toEqual({ mcpServers: { signafaide: { type: "stdio", ...SERVER } } });
    expect(read(".cursor/rules/signafaide.mdc")).toMatch(/^---\ndescription: .+\nalwaysApply: false\n---\n/);
    expect(json(".gemini/settings.json")).toEqual({ mcpServers: { signafaide: SERVER } });
    expect(json(".vscode/mcp.json")).toEqual({ servers: { signafaide: { type: "stdio", ...SERVER } } });
    expect(json(".devin/mcp_config.json")).toEqual({ mcpServers: { signafaide: SERVER } });
    for (const f of ["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".github/copilot-instructions.md"]) {
      expect(read(f).split(SECTION_START)).toHaveLength(2); // one section, even though codex and windsurf share AGENTS.md
      expect(read(f)).toContain("## Adopt it in 3 steps"); // headings one level down
    }
  });

  it("is idempotent and merges into existing files", () => {
    fs.writeFileSync(path.join(root, ".mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } }, extra: 1 }));
    fs.mkdirSync(path.join(root, ".gemini"));
    fs.writeFileSync(path.join(root, ".gemini/settings.json"), JSON.stringify({ theme: "dark" }));
    fs.writeFileSync(path.join(root, "AGENTS.md"), "# Team rules\n\nUse tabs.\n");
    fs.writeFileSync(path.join(root, "CLAUDE.md"), "# Project\n\nRun make test.\n");
    fs.mkdirSync(path.join(home, ".codex"));
    fs.writeFileSync(path.join(home, ".codex/config.toml"), 'model = "o3"\n\n[mcp_servers.signafaide]\ncommand = "old"\nenabled = false\n\n[mcp_servers.signafaide.env]\nX = "1"\n\n[other]\na = 1\n');

    const first = run(["claude-code", "gemini", "codex"]);
    expect(first.flatMap((r) => r.changes.map((c) => c.result))).toEqual(["updated", "created", "updated", "updated", "updated", "updated", "created"]); // in AGENT_IDS order
    expect(read("CLAUDE.md")).toMatch(/^# Project\n\nRun make test\.\n\n<!-- signafaide:start -->\n/);
    expect(json(".mcp.json")).toEqual({ mcpServers: { other: { command: "x" }, signafaide: { type: "stdio", ...SERVER, env: {} } }, extra: 1 });
    expect(json(".gemini/settings.json")).toEqual({ theme: "dark", mcpServers: { signafaide: SERVER } });
    expect(read("AGENTS.md")).toMatch(/^# Team rules\n\nUse tabs\.\n\n<!-- signafaide:start -->\n/);
    expect(fs.readFileSync(path.join(home, ".codex/config.toml"), "utf8")).toBe(
      `model = "o3"\n\n[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide@${VERSION}", "mcp"]\nenabled = false\n\n[mcp_servers.signafaide.env]\nX = "1"\n\n[other]\na = 1\n`,
    );

    const again = run(["claude-code", "gemini", "codex"]);
    expect(again.flatMap((r) => r.changes.map((c) => c.result)).every((r) => r === "unchanged")).toBe(true);
  });

  it("replaces an old section in place", () => {
    fs.writeFileSync(path.join(root, "GEMINI.md"), "a\n\n<!-- signafaide:start -->\nold\n<!-- signafaide:end -->\n\nb\n");
    run(["gemini-cli"]);
    const text = read("GEMINI.md");
    expect(text.startsWith("a\n\n<!-- signafaide:start -->\n")).toBe(true);
    expect(text.endsWith("<!-- signafaide:end -->\n\nb\n")).toBe(true);
    expect(text).not.toContain("\nold\n");
  });

  it("dry run writes nothing", () => {
    const res = run(["all"], true);
    expect(res.flatMap((r) => r.changes.map((c) => c.result)).every((r) => r === "created")).toBe(true);
    expect(fs.readdirSync(root)).toEqual([]);
    expect(fs.existsSync(path.join(home, ".codex"))).toBe(false);
  });

  it("never clobbers a file it cannot parse", () => {
    fs.mkdirSync(path.join(root, ".vscode"));
    const jsonc = '{\n  // my servers\n  "servers": {}\n}\n';
    fs.writeFileSync(path.join(root, ".vscode/mcp.json"), jsonc);
    const [r] = run(["copilot"]);
    expect(r.changes[0].result).toMatch(/^skipped \(not plain JSON/);
    expect(read(".vscode/mcp.json")).toBe(jsonc);
  });

  it("detects agents from PATH, project folders and home", () => {
    delete env.CODEX_HOME; // a Codex variable: it counts as running in Codex
    expect(run()).toEqual([]);
    const bin = env.PATH;
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "claude"), "");
    fs.mkdirSync(path.join(root, ".cursor"));
    fs.mkdirSync(path.join(home, ".gemini"));
    const res = run();
    expect(res.map((r) => [r.agent, r.reason])).toEqual([
      ["claude-code", "`claude` on PATH"],
      ["cursor", ".cursor/ in the project"],
      ["gemini-cli", "~/.gemini"],
    ]);
  });

  it("rejects unknown agents", () => {
    expect(() => run(["vim"])).toThrow(/unknown agent vim; use one of claude-code, codex/);
  });

  it("cli: one line per agent", async () => {
    const lines: string[] = [];
    const log = console.log;
    console.log = (s: string) => lines.push(s);
    const old = process.env.CODEX_HOME;
    process.env.CODEX_HOME = env.CODEX_HOME;
    try {
      expect(await main(["agent", "setup", "--dir", root, "--agent", "claude", "--agent", "codex,cursor", "--dry-run"])).toBe(0);
      expect(lines).toEqual([
        "dry run: nothing written",
        "claude-code: .mcp.json would be created, .claude/skills/signafaide/SKILL.md would be created, CLAUDE.md would be created; note: Claude Code asks once to approve the project's MCP servers when it next starts here",
        `codex: ${path.join(env.CODEX_HOME, "config.toml")} would be created, AGENTS.md would be created`,
        "cursor: .cursor/mcp.json would be created, .cursor/rules/signafaide.mdc would be created",
        ...SETUP_NOTES(),
      ]);
      expect(lines.join("\n")).toContain("what is sent: nothing yet");
      expect(lines.join("\n")).toContain("Full inputs and outputs stay in .signafaide/chain/<project>/<env>/<agent>.jsonl; storeContent (TypeScript) or store_content=True (Python) sends the content too");
      expect(await main(["agent", "nope"])).toBe(2);
    } finally {
      console.log = log;
      if (old === undefined) delete process.env.CODEX_HOME;
      else process.env.CODEX_HOME = old;
    }
  });
});

describe("agent setup --url", () => {
  const url = "https://witness.internal.example.com";
  const withEnv = { ...SERVER, env: { SIGNAFAIDE_URL: url } };

  it("writes SIGNAFAIDE_URL into every agent's MCP entry", () => {
    setup({ root, agents: ["all"], env, home, url: url + "/" });
    expect(json(".mcp.json")).toEqual({ mcpServers: { signafaide: { type: "stdio", ...withEnv } } });
    expect(json(".cursor/mcp.json")).toEqual({ mcpServers: { signafaide: { type: "stdio", ...withEnv } } });
    expect(json(".gemini/settings.json")).toEqual({ mcpServers: { signafaide: withEnv } });
    expect(json(".vscode/mcp.json")).toEqual({ servers: { signafaide: { type: "stdio", ...withEnv } } });
    expect(json(".devin/mcp_config.json")).toEqual({ mcpServers: { signafaide: withEnv } });
    const toml = path.join(home, ".codex/config.toml");
    expect(fs.readFileSync(toml, "utf8")).toBe(`[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide@${VERSION}", "mcp"]\nenv = { SIGNAFAIDE_URL = "${url}" }\n`);
    const again = setup({ root, agents: ["all"], env, home, url });
    expect(again.flatMap((r) => r.changes.map((c) => c.result)).every((r) => r === "unchanged")).toBe(true);
  });

  it("codex: sets it in an existing env table or inline env, keeping other variables", () => {
    const toml = path.join(home, ".codex/config.toml");
    fs.mkdirSync(path.dirname(toml), { recursive: true });
    fs.writeFileSync(toml, '[mcp_servers.signafaide]\ncommand = "old"\n\n[mcp_servers.signafaide.env]\nX = "1"\nSIGNAFAIDE_URL = "http://old"\n');
    setup({ root, agents: ["codex"], env, home, url });
    expect(fs.readFileSync(toml, "utf8")).toBe(`[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide@${VERSION}", "mcp"]\n\n[mcp_servers.signafaide.env]\nSIGNAFAIDE_URL = "${url}"\nX = "1"\n`);
    fs.writeFileSync(toml, '[mcp_servers.signafaide]\ncommand = "old"\nenv = { X = "1" }\n');
    setup({ root, agents: ["codex"], env, home, url });
    expect(fs.readFileSync(toml, "utf8")).toBe(`[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide@${VERSION}", "mcp"]\nenv = { X = "1", SIGNAFAIDE_URL = "${url}" }\n`);
    expect(setup({ root, agents: ["codex"], env, home, url })[0].changes[0].result).toBe("unchanged");
  });

  it("refuses a URL that is not an http(s) base URL", () => {
    for (const bad of ["ftp://x", "not a url", "https://u:p@x", "https://x/?a=1"]) expect(() => setup({ root, agents: ["claude-code"], env, home, url: bad })).toThrow(/--url/);
    expect(fs.readdirSync(root)).toEqual([]);
  });

  it("cli: --url, and the notes name it", async () => {
    const lines: string[] = [];
    const log = console.log;
    console.log = (s: string) => lines.push(s);
    try {
      expect(await main(["agent", "setup", "--dir", root, "--agent", "claude-code", "--url", url])).toBe(0);
    } finally {
      console.log = log;
    }
    expect(json(".mcp.json").mcpServers.signafaide.env).toEqual({ SIGNAFAIDE_URL: url });
    expect(lines.at(-1)).toContain(`witness: ${url} (SIGNAFAIDE_URL in each MCP entry)`);
  });
});

describe("agent setup safety", () => {
  it("pins the package version and never writes through a symbolic link", () => {
    expect(SERVER.args[1]).toBe(`signafaide@${VERSION}`);
    const target = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-elsewhere-"));
    fs.symlinkSync(target, path.join(root, ".cursor"));
    const r = run(["cursor"]);
    expect(r[0].changes.every((c) => c.result.startsWith("skipped") && c.result.includes("symbolic link"))).toBe(true);
    expect(fs.readdirSync(target)).toEqual([]);
  });
});

describe("skill text", () => {
  it("opens with the facts: what leaves the machine, no account, self-host, open source", () => {
    const head = SKILL_BODY.split("\n").slice(0, 8).join("\n");
    expect(head).toContain("each record's hashes, plus its tool name, agent name and time; never inputs or outputs");
    expect(head).toContain("never put personal data in agent or tool names");
    expect(head).not.toContain("personal data.");
    expect(head).toContain("Nothing at all is sent until a person runs `signafaide init` or sets `SIGNAFAIDE_API_KEY`");
    expect(head).toContain("agree to the signafAIde Terms and Privacy notice");
    expect(head).toContain("needs no account, email or card");
    expect(head).toContain("self-host the witness and set `SIGNAFAIDE_URL` (https://signafaide.com/docs/self-host)");
    expect(head).toContain("Apache-2.0, with a public protocol spec and an independent verifier");
  });

  it("says when, how and why, and nothing it cannot back", () => {
    expect(SKILL_BODY).toContain(
      "a self-written log, even signed, can't prove to a third party when a record was made or that it wasn't rebuilt; signafAIde records are co-signed and publicly timestamped",
    );
    for (const s of ["pay, send, approve, delete or change", "uv add signafaide", "python3 -m venv .venv", "npm install signafaide", "signafaide verify", "claim link", "do what they asked", "Do not run `signafaide init` yourself"])
      expect(SKILL_BODY).toContain(s);
    expect(SKILL_BODY.indexOf("**Use it when**")).toBeLessThan(SKILL_BODY.indexOf("## Adopt it in 3 steps"));
    expect(SKILL_BODY.indexOf("## Adopt it in 3 steps")).toBeLessThan(SKILL_BODY.indexOf("**Why not a self-written log:**"));
    for (const hype of ["revolution", "best-in-class", "seamless", "effortless", "world-class", "!\n", "! "]) expect(SKILL_BODY).not.toContain(hype);
    expect(SKILL_BODY.split("\n").length).toBeLessThan(60);
  });

  it("the plugin's SKILL.md is the generated one", () => {
    expect(fs.readFileSync(path.join(__dirname, "../../plugin/skills/signafaide/SKILL.md"), "utf8")).toBe(claudeSkill());
  });
});
