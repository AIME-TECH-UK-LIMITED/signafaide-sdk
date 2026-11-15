import * as fs from "node:fs";
import * as path from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ERRORS } from "../src/errors.js";
import { note, record } from "../src/index.js";
import { createServer } from "../src/mcp.js";
import { installCommand, pythonInstall } from "../src/project.js";
import { SKILL_BODY } from "../src/skill.js";
import { deadUrl, useProject } from "./helpers.js";

/** The result line without its check counts (§7), to compare the rest. */
const noCounts = (line: string | undefined): string => (line ?? "").replace(/: \d+ of 12 checks [^;]*; /, ": ").replace(/: \d+ of 12 checks [^;]*$/, "");


const ctx = useProject();
let client: Client;

beforeEach(async () => {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createServer().connect(b);
  client = new Client({ name: "test", version: "1" });
  await client.connect(a);
});
afterEach(() => client.close());

const AGREED = { confirm_user_agreed: true, user_words: "yes, create the sandbox" };

async function call(name: string, args: Record<string, unknown> = {}): Promise<[string, boolean]> {
  const r = await client.callTool({ name, arguments: args });
  return [(r.content as { text: string }[]).map((c) => c.text).join("\n"), !!r.isError];
}

const write = (f: string, s: string) => {
  fs.mkdirSync(path.dirname(path.join(ctx.root, f)), { recursive: true });
  fs.writeFileSync(path.join(ctx.root, f), s);
};

describe("mcp server", () => {
  it("never reaches outside the folder it started in", async () => {
    const [out, err] = await call("signafaide_status", { directory: "/" });
    expect(err).toBe(true);
    expect(out).toContain("outside");
    const [out2, err2] = await call("signafaide_verify", { pack: "/etc/passwd" });
    expect(err2).toBe(true);
    expect(out2).toContain("outside");
    expect(process.cwd()).toBe(fs.realpathSync(ctx.root));
  });

  it("lists the seven tools, each with a description", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual([
      "signafaide_setup",
      "signafaide_init",
      "signafaide_quickstart",
      "signafaide_verify",
      "signafaide_status",
      "signafaide_explain_error",
      "signafaide_claim_link",
    ]);
    for (const t of tools) expect(t.description!.length).toBeGreaterThan(60);
    expect(tools[0].description).toContain("audit");
    expect(tools[0].description).toContain("changes no file, creates nothing and sends nothing");
    expect(tools[1].description).toContain("Creates an external sandbox");
    expect(tools[1].description).toContain("ask the user and call it only after they agree");
    expect(tools[1].description).toContain("creates nothing unless confirm_user_agreed is true");
    expect(Object.keys((tools[1].inputSchema as any).properties)).toEqual(["directory", "confirm_user_agreed", "user_words"]);
  });

  it("setup: python with uv, a preview that changes nothing; signafaide_init creates the sandbox once", async () => {
    write("pyproject.toml", '[project]\nname = "claims"\ndependencies = []\n');
    write("uv.lock", "");
    write("agent.py", "def approve_payout(claim_id, amount):\n    pass\n\ndef escalate(claim_id):\n    pass\n\ndef helper():\n    pass\n");
    let [out, err] = await call("signafaide_setup");
    expect(err).toBe(false);
    expect(out).toContain("Language: python; framework: none detected");
    expect(out).toContain("1. Install: uv add signafaide");
    expect(out).toContain("@signafaide.record");
    expect(out).toContain("uv run signafaide verify");
    expect(out).toContain("- agent.py:1 approve_payout");
    expect(out).toContain("- agent.py:4 escalate");
    expect(out).not.toContain("helper");
    expect(out).toContain("API key: none. Records stay on this machine");
    expect(out).toContain(`What a sandbox would send (only after a person agrees: signafaide_init, or \`npx signafaide init\` run by them): one POST ${ctx.service.url}/v1/sandbox`);
    expect(out).toContain("{v, kind, project, env, agent, seq, prev, time, name, content_hash, ref}");
    expect(out).toContain("Content: hash-only by default. The full inputs and outputs stay in .signafaide/chain/<project>/<env>/<agent>.jsonl");
    expect(out).toContain("store_content=True sends the content too, encrypted at rest (live records need the Team plan)");
    expect(out).toContain("https://signafaide.co.uk/docs/self-host");
    expect(out.split("\n").at(-1)).toBe("Nothing was changed, created or sent by this preview.");
    expect(ctx.service.calls).toEqual([]);
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    expect(fs.existsSync(path.join(ctx.root, ".signafaide"))).toBe(false);
    expect(fs.existsSync(path.join(ctx.root, ".gitignore"))).toBe(false);

    // #49: the consent gate is an argument, not only a description.
    for (const args of [{}, { confirm_user_agreed: true }, { confirm_user_agreed: true, user_words: " " }, { confirm_user_agreed: false, user_words: "yes" }, { user_words: "yes, go ahead" }]) {
      [out, err] = await call("signafaide_init", args);
      expect(err, JSON.stringify(args)).toBe(true);
      expect(out).toContain("nothing was created");
      expect(out).toContain("confirm_user_agreed: true and user_words");
      expect(out).toContain(`${ctx.service.url}/legal/terms`);
    }
    expect(ctx.service.calls).toEqual([]);
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    [out, err] = await call("signafaide_init", AGREED);
    expect(err).toBe(false);
    expect(out).toMatch(/Created a sandbox at .*claim link.*\/claim\//s);
    expect(out).toContain(`Tell the human: By creating a sandbox you agree to the signafAIde Terms (${ctx.service.url}/legal/terms) and Privacy notice (${ctx.service.url}/legal/privacy).`);
    expect(fs.readFileSync(path.join(ctx.root, ".env"), "utf8")).toMatch(/^SIGNAFAIDE_API_KEY=sfa_test_/);
    expect(fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8").split("\n")).toEqual(expect.arrayContaining([".signafaide/", ".env"]));
    [out] = await call("signafaide_init");
    expect(out).toContain("Nothing was created.");
    expect(ctx.service.calls.filter((c) => c === "POST /v1/sandbox")).toHaveLength(1);
    [out] = await call("signafaide_setup");
    expect(out).toContain("API key: found (test env); record hashes are sent to");
    expect(out).toContain("claim: http");
    expect(out).not.toContain("What a sandbox would send");
  });

  it("setup: TypeScript frameworks and package managers", async () => {
    write("package.json", JSON.stringify({ dependencies: { ai: "^5" } }));
    write("tsconfig.json", "{}");
    write("pnpm-lock.yaml", "");
    write("src/tools.ts", "export async function sendEmail(to: string) {}\nexport const refundOrder = async (id: string) => {};\n");
    const [out] = await call("signafaide_setup");
    expect(out).toContain("Language: typescript; framework: vercel-ai");
    expect(out).toContain("pnpm add signafaide");
    expect(out).toContain("wrapTools({ weather: tool(");
    expect(out).toContain("- src/tools.ts:1 sendEmail");
    expect(out).toContain("- src/tools.ts:2 refundOrder");
    expect(out).toContain("{ agent: ... } to record()");
    expect(out).toContain("API key: none.");
    expect(out).toContain("storeContent: true sends the content too");
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
  });

  it("setup: unknown language, and another directory", async () => {
    let [out] = await call("signafaide_setup");
    expect(out).toContain("language is unknown");
    const other = path.join(ctx.root, "svc");
    fs.mkdirSync(other);
    fs.writeFileSync(path.join(other, "requirements.txt"), "langchain-core\n");
    fs.writeFileSync(path.join(other, "pyproject.toml"), "");
    [out] = await call("signafaide_setup", { directory: other });
    expect(out).toContain("framework: langchain");
    expect(out).toMatch(/1\. Install: (uv venv \.venv && uv pip install --python \.venv\/bin\/python|python3 -m venv \.venv && \.venv\/bin\/python -m pip install) signafaide, and add signafaide to requirements\.txt/);
    fs.mkdirSync(path.join(other, ".venv"));
    fs.writeFileSync(path.join(other, ".venv", "pyvenv.cfg"), "home = /usr/bin\n");
    fs.writeFileSync(path.join(other, "requirements.txt"), "langchain-core\nsignafaide>=0.1\n");
    [out] = await call("signafaide_setup", { directory: other });
    expect(out).toContain("1. Install: already a dependency (.venv/bin/python -m pip install signafaide updates it)");
    expect(out).toContain(".venv/bin/signafaide verify");
  });

  it("setup: a Python script with no dependency file is Python, even next to a package.json that only holds signafaide", async () => {
    write("agent.py", "def issue_refund(ticket_id, amount):\n    return {}\n");
    write("package.json", JSON.stringify({ dependencies: { signafaide: "file:signafaide-0.2.1.tgz" } }));
    let [out] = await call("signafaide_setup");
    expect(out).toContain("Language: python");
    expect(out).toContain("agent.py:1 issue_refund");
    write("index.ts", "export const x = 1;\n");
    [out] = await call("signafaide_setup");
    expect(out).toContain("Language: javascript");
  });

  it("setup makes no request, so it works offline", async () => {
    write("package.json", JSON.stringify({ dependencies: { express: "1" } }));
    process.env.SIGNAFAIDE_URL = await deadUrl();
    const [out, err] = await call("signafaide_setup");
    expect(err).toBe(false);
    expect(out).not.toContain("not reachable");
    expect(out).toContain("Language: javascript");
  });

  it("python install commands: uv, Poetry, a venv, VIRTUAL_ENV, else a new .venv; never a bare pip install", () => {
    const dir = (files: Record<string, string>) => {
      const d = fs.mkdtempSync(path.join(ctx.root, "py-"));
      for (const [f, c] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true });
        fs.writeFileSync(path.join(d, f), c);
      }
      return d;
    };
    const noUv = { PATH: "" };
    expect(pythonInstall(dir({ "pyproject.toml": "[tool.uv]\n" }), "", noUv)).toEqual(["uv add signafaide", "uv run signafaide verify"]);
    expect(pythonInstall(dir({ "pyproject.toml": "[tool.poetry]\nname='x'\n" }), "", noUv)).toEqual(["poetry add signafaide", "poetry run signafaide verify"]);
    expect(pythonInstall(dir({ "requirements.txt": "", "venv/pyvenv.cfg": "" }), "", noUv)).toEqual([
      "venv/bin/python -m pip install signafaide, and add signafaide to requirements.txt",
      "venv/bin/signafaide verify",
    ]);
    const active = dir({ "pyvenv.cfg": "" });
    expect(pythonInstall(dir({ "requirements.txt": "" }), "", { PATH: "", VIRTUAL_ENV: active })[0]).toBe(`${active}/bin/python -m pip install signafaide, and add signafaide to requirements.txt`);
    expect(pythonInstall(dir({ "requirements.txt": "" }), "", noUv)).toEqual([
      "python3 -m venv .venv && .venv/bin/python -m pip install signafaide, and add signafaide to requirements.txt",
      ".venv/bin/signafaide verify",
    ]);
    const bin = dir({ uv: "" });
    expect(pythonInstall(dir({ "requirements.txt": "" }), "", { PATH: bin })[0]).toBe("uv venv .venv && uv pip install --python .venv/bin/python signafaide, and add signafaide to requirements.txt");
    for (const q of [installCommand("python"), SKILL_BODY]) expect(q).not.toMatch(/(?<!-m |uv )pip install signafaide/m);
  });

  it("quickstart for every language and framework", async () => {
    const [py] = await call("signafaide_quickstart", { language: "python", framework: "openai-agents" });
    expect(py).toContain("uv add signafaide");
    expect(py).toContain("python3 -m venv .venv && .venv/bin/python -m pip install signafaide");
    expect(py).toContain("signafaide.wrap_tools([lookup_order, refund])");
    const [ts] = await call("signafaide_quickstart", { language: "typescript" });
    expect(ts).toContain("claimId: string");
    expect(ts).toContain("npx signafaide verify");
    const [js] = await call("signafaide_quickstart", { language: "javascript", framework: "langchain" });
    expect(js).toContain("bindTools");
    const [, bad] = await call("signafaide_quickstart", { language: "cobol" });
    expect(bad).toBe(true);
  });

  it("verify: nothing yet, then local PASS sending nothing, then ships after init, then fails on a tampered chain", async () => {
    let [out] = await call("signafaide_verify");
    expect(out).toContain("No records yet");
    write("requirements.txt", "");
    await call("signafaide_setup");
    record((x: number) => x * 2, { name: "approve_payout" })(2);
    note("why", { reason: "test" });
    [out] = await call("signafaide_verify");
    expect(out).not.toContain("waiting records first");
    expect(out).toMatch(/Client signatures +PASS +3 records/);
    expect(out).toMatch(/Merkle proofs +NOT CHECKED +0 records; nothing co-signed yet/);
    expect(out).toContain("co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host");
    expect(out.split("\n").at(-1)).toBe("PASS: 4 of 12 checks passed, 8 not checked (nothing co-signed yet)");
    expect(ctx.service.calls).toEqual([]);
    await call("signafaide_init", AGREED);
    [out] = await call("signafaide_verify");
    expect(out).toContain("shipped 3 waiting records first");
    expect(out).toMatch(/Client signatures +PASS/);
    expect(noCounts(out.split("\n").at(-1))).toBe("PASS (service keys fetched over plain http, not independent)");
    expect(ctx.service.events).toContain("verify");

    const chain = path.join(ctx.root, ".signafaide", "chain");
    const file = fs.readdirSync(chain, { recursive: true }).map(String).find((f) => f.endsWith(".jsonl"))!;
    const p = path.join(chain, file);
    fs.writeFileSync(p, fs.readFileSync(p, "utf8").replace('"approve_payout"', '"other"'));
    [out] = await call("signafaide_verify");
    expect(out).toContain("FAIL");
    expect(out).toContain("Do not edit .signafaide/");
  });

  it("status and claim link", async () => {
    let [out] = await call("signafaide_claim_link");
    expect(out).toContain("No sandbox in this project: records stay local");
    write("requirements.txt", "");
    await call("signafaide_init", AGREED);
    [out] = await call("signafaide_claim_link");
    expect(out).toMatch(/^Give the human the claim link .*\nclaim: http.*\/claim\//);
    [out] = await call("signafaide_status");
    expect(out).toContain("(env test)");
    expect(out).toContain("quota: 0 of");
  });

  it("explains every error code", async () => {
    for (const e of ERRORS) {
      const [out] = await call("signafaide_explain_error", { code: e.code });
      expect(out.split("\n")[0]).toContain(e.code);
      expect(out).toContain("How to fix it:");
      if (e.status) expect(out).toContain(`/docs/errors#${e.code}`);
    }
    const [out] = await call("signafaide_explain_error", { code: "nope" });
    expect(out).toContain("Known codes: chain_conflict");
  });
});

describe("error catalog", () => {
  it("covers every service error code in SPEC §6", () => {
    const spec = fs.readFileSync(path.join(__dirname, "../../spec/SPEC.md"), "utf8");
    const table = spec.slice(spec.indexOf("| code | status | when |"), spec.indexOf("**Idempotency:**"));
    const codes = [...table.matchAll(/^\| `([a-z_]+)` \| (\d+) \|/gm)].map((m) => [m[1], Number(m[2])]);
    expect(codes.length).toBe(11);
    for (const [code, status] of codes) expect(ERRORS.find((e) => e.code === code)?.status).toBe(status);
  });
});
