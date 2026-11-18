/** Fix round 6: the instance-stop note and clean restarts (#51), one warning line when a strict
 * tool is refused (#52), and the skill's notes on containers without a persistent disk (#54).
 * The MCP `signafaide_init` confirmation (#49) is in mcp.test.ts. */
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_URL } from "../src/http.js";
import { init, verify } from "../src/index.js";
import { CLEAN_RESTART_NOTE, INSTANCE_NOTE, INSTANCE_START, INSTANCE_STOP } from "../src/records.js";
import { configure } from "../src/runtime.js";
import { verifyPack as verifyPackRaw } from "../src/verifier.js";
import { skillBody } from "../src/skill.js";
import { VERSION } from "../src/version.js";
import { useProject } from "./helpers.js";

const optedIn = useProject({ optIn: true });

describe("#51: clean and unclean restarts", () => {
  it("stop() writes a signed stop note; the next instance's start is a clean restart, a start with no stop keeps the warning", async () => {
    const ctx = optedIn;
    const dir = fs.mkdtempSync(path.join(ctx.root, "..", "vol-"));
    process.env.SIGNAFAIDE_HEAD_FILE = path.join(dir, "head.json");
    try {
      let r = configure({ quiet: true, flushIntervalMs: 3_600_000 });
      expect(r.instanceStop).toBe(true); // a head file means an ephemeral instance
      r.state.loadKey("risk-0");
      const doc = JSON.parse(fs.readFileSync(r.state.keyPath("risk-0"), "utf8"));
      r.write("note", "a", {}, { agent: "risk-0" });
      r.write("note", "b", {}, { agent: "risk-0" });
      const chain = `${r.state.bucket(r.apiKey)}/risk-0`;
      let s = await r.stop();
      expect(s.errors).toEqual({});
      expect([s.shipped, s.left, s.stopped]).toEqual([3, 0, [chain]]);
      let recs = r.state.readAll(chain) as any[];
      expect(recs.map((x) => [x.envelope.seq, x.envelope.kind, x.envelope.name])).toEqual([[1, "note", "a"], [2, "note", "b"], [3, "note", INSTANCE_STOP]]);
      expect(recs[2].content).toEqual({ stopped_after_seq: 2, stopped_after: recs[2].envelope.prev, outbox: "empty" });
      expect("receipt" in recs[2]).toBe(true);
      // Nothing new was written: a second stop adds no second note.
      s = await r.stop();
      expect([s.shipped, s.stopped]).toEqual([0, []]);
      expect(r.state.readAll(chain).length).toBe(3);

      // The container goes with its disk; a new one continues right after the stop note.
      fs.rmSync(r.state.home, { recursive: true, force: true });
      r = await init({ quiet: true, keyProvider: () => doc, flushIntervalMs: 3_600_000 });
      r.write("decision", "freeze_account", { input: { account: "A1" } }, { agent: "risk-0" });
      expect((await r.flush()).errors).toEqual({});
      recs = r.state.readAll(chain) as any[];
      expect(recs.map((x) => [x.envelope.seq, x.envelope.name])).toEqual([[4, INSTANCE_START], [5, "freeze_account"]]);
      expect(recs[0].content.earlier_unsent).toBe("none");
      expect(r.state.chainBase(chain)?.stop?.envelope).toMatchObject({ seq: 3, name: INSTANCE_STOP });
      let v = await verify();
      expect(v.ok).toBe(true);
      expect(v.check("chain").detail).toContain(`${CLEAN_RESTART_NOTE}: ${chain} after seq 3`);
      expect(v.check("chain").detail).not.toContain(INSTANCE_NOTE);
      // A stop note kept with the base that is not the head's record does not count.
      const basePath = r.state.chainPath(chain).replace(/\.jsonl$/, ".base.json");
      const base = JSON.parse(fs.readFileSync(basePath, "utf8"));
      fs.writeFileSync(basePath, JSON.stringify({ ...base, stop: { ...base.stop, envelope: { ...base.stop.envelope, name: "other" } } }));
      expect((await verify()).check("chain").detail).toContain(`${INSTANCE_NOTE}: ${chain} after seq 3`);
      fs.writeFileSync(basePath, JSON.stringify(base));

      // This instance is killed: no stop note. The next start is not clean.
      fs.rmSync(r.state.home, { recursive: true, force: true });
      r = await init({ quiet: true, keyProvider: () => doc, flushIntervalMs: 3_600_000 });
      r.write("decision", "freeze_account", { input: { account: "A2" } }, { agent: "risk-0" });
      expect((await r.flush()).errors).toEqual({});
      recs = r.state.readAll(chain) as any[];
      expect(recs.map((x) => [x.envelope.seq, x.envelope.name])).toEqual([[6, INSTANCE_START], [7, "freeze_account"]]);
      expect(recs[0].content.earlier_unsent).toBe("unknown");
      v = await verify();
      expect(v.check("chain").detail).toContain(`${INSTANCE_NOTE}: ${chain} after seq 5`);
      expect(v.check("chain").detail).not.toContain(CLEAN_RESTART_NOTE);

      // The whole chain as an auditor sees it: one clean restart, one with no stop before it.
      const pack = await r.client().export("risk-0");
      const pv = verifyPackRaw(pack, [ctx.service.keyDoc], { agentKeys: r.state.exportAgentKeys().keys });
      expect(pv.ok, String(pv)).toBe(true);
      const detail = pv.check("chain").detail;
      expect(detail).toContain(`${CLEAN_RESTART_NOTE}: risk-0 after seq 3`);
      expect(detail).toContain(`${INSTANCE_NOTE}: risk-0 after seq 5`);
      r.close();
    } finally {
      delete process.env.SIGNAFAIDE_HEAD_FILE;
    }
  });

  it("no stop note while records are unsent, without a head file by default, or when turned off", async () => {
    const ctx = optedIn;
    let r = configure({ quiet: true, flushIntervalMs: 3_600_000 });
    expect(r.instanceStop).toBe(false);
    r.write("note", "a", {}, { agent: "risk-1" });
    ctx.service.failAlways = [503, { error: { code: "unavailable", message: "down" } }];
    let s = await r.stop();
    expect(s.stopped).toEqual([]);
    expect(s.left).toBe(1);
    ctx.service.failAlways = null;
    s = await r.stop(); // an explicit stop() writes one once everything is sent
    expect(s.stopped.length).toBe(1);
    process.env.SIGNAFAIDE_HEAD_FILE = path.join(ctx.root, "..", "h.json");
    process.env.SIGNAFAIDE_INSTANCE_STOP = "0";
    try {
      r = configure({ quiet: true, flushIntervalMs: 3_600_000 });
      expect(r.instanceStop).toBe(false);
    } finally {
      delete process.env.SIGNAFAIDE_HEAD_FILE;
      delete process.env.SIGNAFAIDE_INSTANCE_STOP;
    }
    r.close();
  });
});

describe("#54: the skill", () => {
  it("covers containers without a persistent disk: the head file, stored content and stop()", () => {
    const body = skillBody();
    expect(body).toContain("## Containers without a persistent disk");
    expect(body).toContain("SIGNAFAIDE_HEAD_FILE");
    expect(body).toContain("store_content=True");
    expect(body).toContain("storeContent: true");
    expect(body).toContain("signafaide.stop()");
    expect(body).toContain("confirm_user_agreed: true");
    expect(body).not.toMatch(/—|–/);
  });

  it("the version is 0.5.1 everywhere the package says it", () => {
    expect(VERSION).toBe("0.5.1");
    expect(JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf8")).version).toBe(VERSION);
    expect(JSON.parse(fs.readFileSync(path.join(__dirname, "../mcp/package.json"), "utf8")).version).toBe(VERSION);
  });
});

describe("the service's domain", () => {
  it("the default witness is api.signafaide.co.uk, and the docs links use signafaide.co.uk", () => {
    expect(DEFAULT_URL).toBe("https://api.signafaide.co.uk");
    expect(skillBody()).toContain("https://signafaide.co.uk/docs/production");
    expect(skillBody()).toContain("https://api.signafaide.co.uk");
    expect(skillBody()).not.toMatch(new RegExp(["signafaide", "com"].join("\\.") + "\\b"));
  });
});

describe("#46: the release check", () => {
  // The files the check reads, copied into a scratch git repository so tags can be made freely.
  const FILES = [
    "scripts/release-check.mjs", "CHANGELOG.md", "js/package.json", "js/mcp/package.json", "js/src/version.ts", "js/src/http.ts",
    "python/pyproject.toml", "python/src/signafaide/_version.py", "python/src/signafaide/http.py", "plugin/.claude-plugin/plugin.json",
    "core/Cargo.toml", "verifier/Cargo.toml", "verifier/src/main.rs",
    "gemini-extension.json", ".cursor-plugin/plugin.json", "mcp.json", "README.md",
  ];
  const sdk = path.join(__dirname, "../..");
  const run = (dir: string): string => spawnSync(process.execPath, ["scripts/release-check.mjs", "--offline", "--no-build"], { cwd: dir, encoding: "utf8", env: { ...process.env, CARGO_TARGET_DIR: path.join(dir, "no-target") } }).stdout;
  const git = (dir: string, ...args: string[]): string => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" });

  it("fails when the version was not bumped since the last tag, or the changelog has no entry for it", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-release-"));
    try {
      for (const f of FILES) {
        fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
        fs.copyFileSync(path.join(sdk, f), path.join(dir, f));
      }
      git(dir, "init", "-q");
      git(dir, "add", "-A");
      git(dir, "commit", "-q", "-m", "release");
      // No tag yet, then the release tagged on HEAD: both fine.
      expect(run(dir)).toContain(`ok    no release tag yet; ${VERSION} would be the first`);
      git(dir, "tag", "-a", `v${VERSION}`, "-m", "release");
      let out = run(dir);
      expect(out).toContain(`ok    HEAD is the tagged release v${VERSION}`);
      expect(out).toContain(`ok    CHANGELOG.md has an entry for v${VERSION}`);
      expect(out).toContain("ok    every version is " + VERSION);
      // A change after the tag with the version left alone: uncommitted, then committed.
      fs.appendFileSync(path.join(dir, "js/src/http.ts"), "\n// a later change\n");
      expect(run(dir)).toContain(`FAIL  the version is still ${VERSION}, the last tag (v${VERSION}), but the source changed since`);
      git(dir, "commit", "-q", "-am", "later");
      expect(run(dir)).toContain(`FAIL  the version is still ${VERSION}, the last tag (v${VERSION}), but the source changed since`);
      // Bumped everywhere, but nothing written up.
      const bump = (f: string) => fs.writeFileSync(path.join(dir, f), fs.readFileSync(path.join(dir, f), "utf8").split(VERSION).join("9.9.9"));
      FILES.filter((f) => !/CHANGELOG|release-check|http\.|main\.rs/.test(f)).forEach(bump);
      const plugin = path.join(dir, "plugin/.claude-plugin/plugin.json");
      fs.writeFileSync(plugin, fs.readFileSync(plugin, "utf8").replace(/"version": "[^"]+"/, '"version": "9.9.9"'));
      out = run(dir);
      expect(out).toContain("ok    every version is 9.9.9");
      expect(out).toContain(`ok    9.9.9 is above the last tag v${VERSION}`);
      expect(out).toContain("FAIL  CHANGELOG.md has no entry for v9.9.9");
      fs.writeFileSync(path.join(dir, "CHANGELOG.md"), "# Changelog\n\n## v9.9.9 (2026-12-01)\n\n- A change.\n");
      expect(run(dir)).toContain("ok    CHANGELOG.md has an entry for v9.9.9");
      // A crate left behind is caught with the packages.
      fs.writeFileSync(path.join(dir, "verifier/Cargo.toml"), fs.readFileSync(path.join(dir, "verifier/Cargo.toml"), "utf8").replace("9.9.9", VERSION));
      expect(run(dir)).toMatch(new RegExp(`FAIL  versions disagree with js/package.json \\(9\\.9\\.9\\): verifier/Cargo.toml ${VERSION.replace(/\./g, "\\.")}`));
      // A reference to the .com domain anywhere in the repository is a failure.
      expect(run(dir)).toMatch(/ok    no reference to the \.com domain in \d+ files/);
      fs.appendFileSync(path.join(dir, "js/src/version.ts"), `// docs: https://${["signafaide", "com"].join(".")}/docs\n`);
      expect(run(dir)).toContain("FAIL  1 reference to the .com domain, which is not ours (the service is on signafaide.co.uk): js/src/version.ts:");
      // No verifier binary in this scratch copy: that is a failure too, never a silent pass.
      expect(run(dir)).toContain("FAIL  the verifier binary");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
