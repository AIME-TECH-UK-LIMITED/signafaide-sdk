/**
 * Setup uses the config it generates, and says what blocks (SPEC §8): `init` and `agent setup`
 * write the checks file, a program started afterwards in that project reads that very file, and
 * an edit of a rule in it changes what a call does. The output of setup says which checks are on,
 * in which mode, which tools are strict, which fields leave the machine and where to change it.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import { CheckError } from "../src/checks-runtime.js";
import { record } from "../src/record.js";
import { configure } from "../src/runtime.js";
import { records, useProject } from "./helpers.js";

const ctx = useProject();
const KEY = "AKIA" + "Z3XQ7PLM2NRT5VWY"; // made up

async function cli(...args: string[]): Promise<[number, string]> {
  const lines: string[] = [];
  const log = vi.spyOn(console, "log").mockImplementation((s: string) => void lines.push(String(s)));
  try {
    return [await main(args), lines.join("\n")];
  } finally {
    log.mockRestore();
  }
}

/** A program started afresh in `root`: nothing held from the process that ran setup. */
function freshProgram(root: string) {
  ctx.rec.close();
  return configure({ quiet: true, root, flushIntervalMs: 3_600_000 });
}

const send = () => {
  const ran: unknown[] = [];
  const tool = record((to: string, _body: string) => (ran.push(to), "sent"), { name: "send_mail" });
  return { ran, tool };
};

describe("setup uses the config it generates", () => {
  it("init: a call made afterwards meets the generated file, and a rule edited into it takes effect", () => {
    return (async () => {
      const [code] = await cli("init");
      expect(code).toBe(0);
      const file = path.join(ctx.root, "signafaide.checks.json");
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      expect(doc.mode).toBe("watch");

      // Watch mode, as generated: the secret is noted and the tool runs.
      freshProgram(ctx.root);
      let { ran, tool } = send();
      expect(tool("ops@example.com", `key ${KEY}`)).toBe("sent");
      expect(ran).toEqual(["ops@example.com"]);
      const [d] = records().filter((r) => r.envelope.kind === "decision");
      expect(d.envelope.checks!.results.find((e: any) => e.check === "secret")).toMatchObject({ result: "note", mode: "watch", enforce_result: "block", found: ["aws_access_key"] });

      // A local rule added to the generated file, in the mode the file says: noted, runs.
      doc.rules = { default: "allow", rules: [{ id: "no-ops", about: "Nothing to ops.", action: "block", tools: ["send_mail"], agents: null, when: [{ field: "/0", op: "eq", value: "ops@example.com" }] }] };
      fs.writeFileSync(file, JSON.stringify(doc));
      freshProgram(ctx.root);
      ({ ran, tool } = send());
      expect(tool("ops@example.com", "hello")).toBe("sent");
      const entry = records().filter((r) => r.envelope.kind === "decision").at(-1)!.envelope.checks!.results.find((e: any) => e.check === "rule");
      expect(entry).toMatchObject({ result: "note", mode: "watch", enforce_result: "block" });

      // The same file with the mode the owner chooses: the rule blocks, and the tool does not run.
      doc.mode = "enforce";
      fs.writeFileSync(file, JSON.stringify(doc));
      freshProgram(ctx.root);
      ({ ran, tool } = send());
      let err: unknown;
      try {
        tool("ops@example.com", "hello");
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(CheckError);
      expect((err as CheckError).rule).toBe("no-ops");
      expect(ran).toEqual([]);
    })();
  });

  it("agent setup --dir: the file lands in that project, and a program in that project uses it", async () => {
    const other = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sfa-setup-")), "Other Project");
    fs.mkdirSync(path.join(other, ".git"), { recursive: true });
    const cwd = process.cwd();
    try {
      const [code, out] = await cli("agent", "setup", "--dir", other, "--agent", "claude-code");
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(other, "signafaide.checks.json"))).toBe(true);
      expect(fs.existsSync(path.join(ctx.root, "signafaide.checks.json"))).toBe(false); // not where the command was run from
      expect(out).toContain("tool-call checks: on, Calibrating");
      process.chdir(other);
      freshProgram(other);
      const { ran, tool } = send();
      expect(tool("ops@example.com", `key ${KEY}`)).toBe("sent");
      expect(ran).toHaveLength(1);
      const [d] = records("other-project").filter((r) => r.envelope.kind === "decision");
      expect(d.envelope.checks!.results.find((e: any) => e.check === "secret")!.found).toEqual(["aws_access_key"]);
    } finally {
      process.chdir(cwd);
      fs.rmSync(path.dirname(other), { recursive: true, force: true });
    }
  });
});

describe("setup says what blocks, at install", () => {
  it("a new file: the checks on, the mode, that nothing blocks, no strict tool, no field leaves, where and how to change it", async () => {
    const [, out] = await cli("init");
    const file = path.join(ctx.root, "signafaide.checks.json");
    expect(out).toContain("tool-call checks: on, Calibrating");
    expect(out).toContain("secret, address, changed_tool, fingerprint, hidden_instruction");
    expect(out).toContain("never block");
    expect(out).toContain("No tool is protected and no field of a tool's arguments leaves the machine");
    expect(out).toContain(`change it in ${file}`);
    expect(out).toContain('`"mode": "enforce"` is On');
    expect(out).toContain('"strict": true');
    expect(out).toContain('"disclose"');
    expect(out).toContain("`signafaide checks status`");
  });

  it("agent setup prints the same, and with an existing file says what that file does: mode, strict tools and the fields they disclose", async () => {
    const file = path.join(ctx.root, "signafaide.checks.json");
    expect((await cli("init"))[0]).toBe(0);
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    doc.mode = "enforce";
    doc.tools = { pay: { strict: true, disclose: ["/amount"] } };
    fs.writeFileSync(file, JSON.stringify(doc));
    const [code, out] = await cli("agent", "setup", "--dir", ctx.root, "--agent", "claude-code");
    expect(code).toBe(0);
    expect(out).toContain("tool-call checks: on, On");
    expect(out).toContain("protected tool pay: if signafAIde can't be reached: Stop; discloses /amount");
    expect(out).toContain(`change it in ${file}`);
    expect(out).toContain("`signafaide checks status`");
    // A file with no strict tool says so.
    fs.writeFileSync(file, JSON.stringify({ ...doc, tools: {} }));
    expect((await cli("agent", "setup", "--dir", ctx.root, "--agent", "claude-code"))[1]).toContain("no tool is protected; only tool fingerprints leave the machine");
  });

  it("with checks off, setup says so", async () => {
    process.env.SIGNAFAIDE_CHECKS = "0";
    try {
      expect((await cli("init"))[1]).toContain("tool-call checks: off (SIGNAFAIDE_CHECKS=0)");
    } finally {
      delete process.env.SIGNAFAIDE_CHECKS;
    }
  });
});
