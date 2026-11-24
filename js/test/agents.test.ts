import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { VERSION } from "../src/version.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AGENT_IDS, SETUP_NOTES, setup } from "../src/agents.js";
import { main } from "../src/cli.js";
import {
  NOTE,
  SECTION_END,
  SECTION_START,
  SKILL_BODY,
  SKILL_DESCRIPTION,
  TEAM_NOTE,
  claudeSkill,
  cursorNoteRule,
  instructionsSection,
  llmsSnippet,
  pluginSkill,
  skillBody,
  teamFiles,
} from "../src/skill.js";
import { NOTE_FILES, noteFiles, noteSection, offerNote } from "../src/agents.js";
import { scriptedPrompter } from "../src/protect.js";

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
const SERVER = { command: "npx", args: ["-y", `signafaide-mcp@${VERSION}`] };

describe("agent setup", () => {
  it("writes every agent's native format", () => {
    const res = run(["all"]);
    expect(res.map((r) => r.agent)).toEqual(AGENT_IDS);
    expect(json(".mcp.json")).toEqual({ mcpServers: { signafaide: { type: "stdio", ...SERVER, env: {} } } });
    expect(read(".claude/skills/signafaide/SKILL.md")).toBe(claudeSkill());
    expect(read(".claude/skills/signafaide/SKILL.md")).toMatch(
      /^---\nname: signafaide\ndescription: Use when the user asks to add signafAIde, to check or block an AI agent's tool calls before they run/,
    );
    expect(fs.readFileSync(path.join(home, ".codex/config.toml"), "utf8")).toBe(
      `[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide-mcp@${VERSION}"]\n`,
    );
    expect(json(".cursor/mcp.json")).toEqual({ mcpServers: { signafaide: { type: "stdio", ...SERVER } } });
    expect(read(".cursor/rules/signafaide.mdc")).toMatch(/^---\ndescription: .+\nalwaysApply: false\n---\n/);
    expect(json(".gemini/settings.json")).toEqual({ mcpServers: { signafaide: SERVER } });
    expect(json(".vscode/mcp.json")).toEqual({ servers: { signafaide: { type: "stdio", ...SERVER } } });
    expect(json(".devin/mcp_config.json")).toEqual({ mcpServers: { signafaide: SERVER } });
    for (const f of ["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".github/copilot-instructions.md"]) {
      expect(read(f).split(SECTION_START)).toHaveLength(2); // one section, even though codex and windsurf share AGENTS.md
    }
    // CLAUDE.md and AGENTS.md get the short note; the agents with no skill file keep the whole skill.
    for (const f of ["CLAUDE.md", "AGENTS.md"]) expect(read(f)).toBe(noteSection());
    for (const f of ["GEMINI.md", ".github/copilot-instructions.md"]) expect(read(f)).toContain("### Steps"); // headings one level down
  });

  it("is idempotent and merges into existing files", () => {
    fs.writeFileSync(
      path.join(root, ".mcp.json"),
      JSON.stringify({ mcpServers: { other: { command: "x" } }, extra: 1 }),
    );
    fs.mkdirSync(path.join(root, ".gemini"));
    fs.writeFileSync(path.join(root, ".gemini/settings.json"), JSON.stringify({ theme: "dark" }));
    fs.writeFileSync(path.join(root, "AGENTS.md"), "# Team rules\n\nUse tabs.\n");
    fs.writeFileSync(path.join(root, "CLAUDE.md"), "# Project\n\nRun make test.\n");
    fs.mkdirSync(path.join(home, ".codex"));
    fs.writeFileSync(
      path.join(home, ".codex/config.toml"),
      'model = "o3"\n\n[mcp_servers.signafaide]\ncommand = "old"\nenabled = false\n\n[mcp_servers.signafaide.env]\nX = "1"\n\n[other]\na = 1\n',
    );

    const first = run(["claude-code", "gemini", "codex"]);
    expect(first.flatMap((r) => r.changes.map((c) => c.result))).toEqual([
      "updated",
      "created",
      "updated",
      "updated",
      "updated",
      "updated",
      "created",
    ]); // in AGENT_IDS order
    expect(read("CLAUDE.md")).toMatch(/^# Project\n\nRun make test\.\n\n<!-- signafaide:start -->\n/);
    expect(json(".mcp.json")).toEqual({
      mcpServers: { other: { command: "x" }, signafaide: { type: "stdio", ...SERVER, env: {} } },
      extra: 1,
    });
    expect(json(".gemini/settings.json")).toEqual({ theme: "dark", mcpServers: { signafaide: SERVER } });
    expect(read("AGENTS.md")).toMatch(/^# Team rules\n\nUse tabs\.\n\n<!-- signafaide:start -->\n/);
    expect(fs.readFileSync(path.join(home, ".codex/config.toml"), "utf8")).toBe(
      `model = "o3"\n\n[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide-mcp@${VERSION}"]\nenabled = false\n\n[mcp_servers.signafaide.env]\nX = "1"\n\n[other]\na = 1\n`,
    );

    const again = run(["claude-code", "gemini", "codex"]);
    expect(again.flatMap((r) => r.changes.map((c) => c.result)).every((r) => r === "unchanged")).toBe(true);
  });

  it("replaces an old section in place", () => {
    fs.writeFileSync(
      path.join(root, "GEMINI.md"),
      "a\n\n<!-- signafaide:start -->\nold\n<!-- signafaide:end -->\n\nb\n",
    );
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
      expect(
        await main(["agent", "setup", "--dir", root, "--agent", "claude", "--agent", "codex,cursor", "--dry-run"]),
      ).toBe(0);
      expect(lines).toEqual([
        "dry run: nothing written",
        "claude-code: .mcp.json would be created, .claude/skills/signafaide/SKILL.md would be created, CLAUDE.md would be created; note: Claude Code asks once to approve the project's MCP servers when it next starts here",
        `codex: ${path.join(env.CODEX_HOME, "config.toml")} would be created, AGENTS.md would be created`,
        "cursor: .cursor/mcp.json would be created, .cursor/rules/signafaide.mdc would be created",
        ...SETUP_NOTES(),
      ]);
      expect(lines.join("\n")).toContain("what is sent: nothing yet");
      expect(lines.join("\n")).toContain(
        "Full inputs and outputs stay in .signafaide/chain/<project>/<env>/<agent>.jsonl; storeContent (TypeScript) or store_content=True (Python) sends the content too",
      );
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
    expect(fs.readFileSync(toml, "utf8")).toBe(
      `[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide-mcp@${VERSION}"]\nenv = { SIGNAFAIDE_URL = "${url}" }\n`,
    );
    const again = setup({ root, agents: ["all"], env, home, url });
    expect(again.flatMap((r) => r.changes.map((c) => c.result)).every((r) => r === "unchanged")).toBe(true);
  });

  it("codex: sets it in an existing env table or inline env, keeping other variables", () => {
    const toml = path.join(home, ".codex/config.toml");
    fs.mkdirSync(path.dirname(toml), { recursive: true });
    fs.writeFileSync(
      toml,
      '[mcp_servers.signafaide]\ncommand = "old"\n\n[mcp_servers.signafaide.env]\nX = "1"\nSIGNAFAIDE_URL = "http://old"\n',
    );
    setup({ root, agents: ["codex"], env, home, url });
    expect(fs.readFileSync(toml, "utf8")).toBe(
      `[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide-mcp@${VERSION}"]\n\n[mcp_servers.signafaide.env]\nSIGNAFAIDE_URL = "${url}"\nX = "1"\n`,
    );
    fs.writeFileSync(toml, '[mcp_servers.signafaide]\ncommand = "old"\nenv = { X = "1" }\n');
    setup({ root, agents: ["codex"], env, home, url });
    expect(fs.readFileSync(toml, "utf8")).toBe(
      `[mcp_servers.signafaide]\ncommand = "npx"\nargs = ["-y", "signafaide-mcp@${VERSION}"]\nenv = { X = "1", SIGNAFAIDE_URL = "${url}" }\n`,
    );
    expect(setup({ root, agents: ["codex"], env, home, url })[0].changes[0].result).toBe("unchanged");
  });

  it("refuses a URL that is not an http(s) base URL", () => {
    for (const bad of ["ftp://x", "not a url", "https://u:p@x", "https://x/?a=1"])
      expect(() => setup({ root, agents: ["claude-code"], env, home, url: bad })).toThrow(/--url/);
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
    expect(lines.some((l) => l.includes(`witness: ${url} (SIGNAFAIDE_URL in each MCP entry)`))).toBe(true);
    expect(lines.at(-1)).toContain("agent names: give each agent an explicit name");
    expect(fs.readFileSync(path.join(root, ".claude/skills/signafaide/SKILL.md"), "utf8")).toContain(
      `the witness at \`${url}\``,
    );
  });
});

describe("agent setup safety", () => {
  it("pins the package version and never writes through a symbolic link", () => {
    expect(SERVER.args[1]).toBe(`signafaide-mcp@${VERSION}`);
    const target = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-elsewhere-"));
    fs.symlinkSync(target, path.join(root, ".cursor"));
    const r = run(["cursor"]);
    expect(r[0].changes.every((c) => c.result.startsWith("skipped") && c.result.includes("symbolic link"))).toBe(true);
    expect(fs.readdirSync(target)).toEqual([]);
  });
});

describe("skill text", () => {
  it("is plain: what it does, what is sent, when to use it", () => {
    const head = SKILL_BODY.split("\n").slice(0, 8).join("\n");
    // An agent decides from the request alone: the first line says when.
    expect(SKILL_BODY.split("\n")[2]).toMatch(
      /^Use this when the user asks for signafAIde, asks to check or block an AI agent's tool calls before they run, or asks for a signed audit trail of what an agent did\./,
    );
    expect(SKILL_DESCRIPTION).toMatch(
      /^Use when the user asks to add signafAIde, to check or block an AI agent's tool calls before they run/,
    );
    expect(head).toContain(
      "Nothing is sent until a person runs `signafaide protect` or `signafaide init`, or sets `SIGNAFAIDE_API_KEY`",
    );
    expect(head).toContain("Only hashes, tool names, agent names and times are sent, never inputs or outputs");
    expect(head).toContain("agent and tool names must not hold personal data");
    expect(head).toContain("the hosted witness (https://api.signafaide.co.uk)");
    for (const hype of [
      "revolution",
      "best-in-class",
      "seamless",
      "effortless",
      "world-class",
      "Why not",
      "!\n",
      "! ",
      "**",
    ])
      expect(SKILL_BODY).not.toContain(hype);
    expect(SKILL_BODY.split("\n").length).toBeLessThan(60); // the tool-call checks section adds 8 lines
  });

  it("asks for explicit agent names and leaves the opt-in to the person", () => {
    for (const s of [
      'agent="claims-bot"',
      '{ agent: "claims-bot" }',
      "uv add signafaide",
      "python3 -m venv .venv",
      "npm install signafaide",
      "signafaide verify",
      "Do not run `signafaide init` yourself",
      "SIGNAFAIDE_AGENT_KEY_<NAME>",
    ])
      expect(SKILL_BODY).toContain(s);
  });

  it("names the witness it was set up with (--url), not the hosted one", () => {
    const body = skillBody("https://witness.internal.example.com");
    expect(body).toContain("the witness at `https://witness.internal.example.com`");
    expect(body).not.toContain("api.signafaide.co.uk");
    expect(instructionsSection("https://witness.internal.example.com")).toContain(
      "https://witness.internal.example.com",
    );
  });

  it("the plugin's SKILL.md is the generated one", () => {
    expect(fs.readFileSync(path.join(__dirname, "../../plugin/skills/signafaide/SKILL.md"), "utf8")).toBe(
      pluginSkill(),
    );
  });
});

describe("the project note", () => {
  const words = /\b(flag|warn|verdict|trying|preset|egress|firewall|mediator|pipelock|bitcoin)/i;

  it("is one paragraph and three lines: install, wrap, the one command; plain words", () => {
    const [heading, blank, para, blank2, ...lines] = NOTE.trimEnd().split("\n");
    expect([heading, blank, blank2]).toEqual(["## signafAIde", "", ""]);
    expect(para).toContain(
      "Use it when adding or changing a tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config",
    );
    expect(para).toContain("nothing is sent and nothing is created online until a person opts in");
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^- Install: `npm install signafaide` .* `uv add signafaide`/);
    expect(lines[1]).toMatch(/^- Wrap: `protect\(/);
    expect(lines[1]).toContain("@signafaide.protect(");
    expect(lines[2]).toContain("`npx signafaide protect` (or `signafaide protect` in Python)");
    expect(lines[2]).toContain("protected tools stop until then");
    expect(lines[2]).toContain("npx signafaide protect --yes --tool <name> --limit-field amount --above 1000");
    expect(lines[2]).toContain("starts Calibrating");
    for (const t of [NOTE, SKILL_DESCRIPTION, SKILL_BODY, llmsSnippet()]) {
      expect(t).not.toMatch(words);
      expect(t).not.toContain("\u2014");
    }
  });

  it("the files in agents/ are the generated ones", () => {
    const dir = path.join(__dirname, "../../agents");
    expect(fs.readFileSync(path.join(dir, "AGENTS.md"), "utf8")).toBe(NOTE);
    expect(fs.readFileSync(path.join(dir, "CLAUDE.md"), "utf8")).toBe(NOTE);
    expect(fs.readFileSync(path.join(dir, "cursor-rules.mdc"), "utf8")).toBe(cursorNoteRule());
    expect(cursorNoteRule()).toMatch(
      /^---\ndescription: Use when the user asks .+\nalwaysApply: true\n---\n\n## signafAIde\n/,
    );
    expect(fs.readFileSync(path.join(dir, "llms-snippet.md"), "utf8")).toBe(llmsSnippet());
    expect(llmsSnippet().split("\n")[2]).toMatch(
      /^> Use signafAIde when adding or changing an AI agent tool that pays/,
    );
    // The organisation note, in each tool's format, and the same three lines as the project note.
    for (const [rel, text] of Object.entries(teamFiles()))
      expect(fs.readFileSync(path.join(dir, "team", rel), "utf8"), rel).toBe(text);
    for (const line of NOTE.split("\n").filter((l) => l.startsWith("- "))) expect(TEAM_NOTE).toContain(line);
    expect(TEAM_NOTE).toContain("installed per project");
    expect(JSON.parse(teamFiles()["claude-code/managed-settings.d/50-signafaide.json"])).toEqual({
      claudeMd: TEAM_NOTE,
    });
  });

  it("protect and init: into the AGENTS.md and CLAUDE.md that exist, AGENTS.md only when neither does", () => {
    expect(NOTE_FILES).toEqual(["AGENTS.md", "CLAUDE.md"]);
    expect(noteFiles(root)).toEqual([path.join(root, "AGENTS.md")]);
    fs.writeFileSync(path.join(root, "CLAUDE.md"), "# Project\n");
    expect(noteFiles(root)).toEqual([path.join(root, "CLAUDE.md")]);
    fs.writeFileSync(path.join(root, "AGENTS.md"), "# Team\n");
    expect(noteFiles(root)).toEqual([path.join(root, "AGENTS.md"), path.join(root, "CLAUDE.md")]);
  });

  it("asks first, appends a marked block, and never adds it twice", async () => {
    fs.writeFileSync(path.join(root, "CLAUDE.md"), "# Project\n\nRun make test.\n");
    const lines: string[] = [];
    // No: nothing written.
    let p = scriptedPrompter([false]);
    expect(await offerNote(root, p, (s) => lines.push(s))).toEqual([]);
    expect(p.asked).toEqual(["Add the signafAIde note to CLAUDE.md?"]);
    expect(read("CLAUDE.md")).toBe("# Project\n\nRun make test.\n");
    expect(fs.existsSync(path.join(root, "AGENTS.md"))).toBe(false);
    // Yes: appended after the file's own text.
    p = scriptedPrompter([true]);
    expect(await offerNote(root, p, (s) => lines.push(s))).toEqual([{ file: "CLAUDE.md", result: "updated" }]);
    expect(read("CLAUDE.md")).toBe("# Project\n\nRun make test.\n\n" + noteSection());
    // Again: not asked, not written.
    p = scriptedPrompter([]);
    expect(await offerNote(root, p, (s) => lines.push(s))).toEqual([]);
    expect(p.asked).toEqual([]);
    expect(read("CLAUDE.md").split(SECTION_START)).toHaveLength(2);
    // An older block (the whole skill, from an earlier agent setup) is replaced in place.
    fs.writeFileSync(path.join(root, "CLAUDE.md"), `a\n\n${SECTION_START}\n# old skill\n${SECTION_END}\n\nb\n`);
    expect(await offerNote(root, scriptedPrompter([true]), () => {})).toEqual([
      { file: "CLAUDE.md", result: "updated" },
    ]);
    expect(read("CLAUDE.md")).toBe(`a\n\n${noteSection()}\nb\n`);
    // The note's text pasted by hand, without the markers: left as it is.
    fs.writeFileSync(path.join(root, "AGENTS.md"), `# Team\n\n${NOTE}`);
    p = scriptedPrompter([]);
    expect(await offerNote(root, p, () => {})).toEqual([]);
    expect(read("AGENTS.md")).toBe(`# Team\n\n${NOTE}`);
  });

  it("agent setup: the note in CLAUDE.md and AGENTS.md; declined, they are left as they are", () => {
    fs.writeFileSync(path.join(root, "AGENTS.md"), "# Team\n");
    const res = setup({ root, agents: ["claude-code", "codex"], env, home, note: false });
    expect(
      res
        .flatMap((r) => r.changes)
        .filter((c) => /\.md$/.test(c.file) && !c.file.includes("SKILL"))
        .map((c) => c.result),
    ).toEqual(["left as it is (you said no to the note)", "left as it is (you said no to the note)"]);
    expect(fs.existsSync(path.join(root, "CLAUDE.md"))).toBe(false);
    expect(read("AGENTS.md")).toBe("# Team\n");
    setup({ root, agents: ["claude-code", "codex"], env, home });
    expect(read("AGENTS.md")).toBe("# Team\n\n" + noteSection());
    expect(read("CLAUDE.md")).toBe(noteSection());
  });
});
