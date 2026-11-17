import * as fs from "node:fs";
import * as path from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ERRORS } from "../src/errors.js";
import { parseJson } from "../src/jcs.js";
import { note, record } from "../src/index.js";
import { defaultChecksFile } from "../src/checks.js";
import { createServer } from "../src/mcp.js";
import { FRAMEWORKS, LANGUAGES, installCommand, pythonInstall, snippet, steps } from "../src/project.js";
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

  it("lists the eleven tools, each with a description and annotations", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual([
      "signafaide_setup",
      "signafaide_init",
      "signafaide_quickstart",
      "signafaide_verify",
      "signafaide_status",
      "signafaide_explain_error",
      "signafaide_claim_link",
      "signafaide_records",
      "signafaide_flush",
      "signafaide_explain_ruling",
      "signafaide_show_rules",
    ]);
    const hints = Object.fromEntries(tools.map((t) => [t.name.replace("signafaide_", ""), t.annotations]));
    const readOnly = (service: boolean) => ({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: service });
    const sends = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };
    expect(hints).toEqual({
      setup: readOnly(false),
      init: sends,
      quickstart: readOnly(false),
      verify: sends,
      status: readOnly(true),
      explain_error: readOnly(false),
      claim_link: readOnly(true),
      records: readOnly(true),
      flush: sends,
      explain_ruling: readOnly(false),
      show_rules: readOnly(false),
    });
    const by = Object.fromEntries(tools.map((t) => [t.name.replace("signafaide_", ""), t.description!]));
    // Each tool names the sibling to use instead.
    expect(by.setup).toContain("use signafaide_quickstart instead");
    expect(by.quickstart).toContain("It reads nothing in the project");
    expect(by.quickstart).toContain("use signafaide_setup instead");
    expect(by.status).toContain("without a key it makes no request");
    expect(by.status).toContain("signafaide_claim_link when the user only needs the claim link");
    expect(by.claim_link).toContain("when the user only needs the claim link");
    expect(by.verify).toContain("With an API key it first ships waiting records");
    expect(by.verify).toContain("signafaide_flush");
    expect(by.records).toContain("the inputs and outputs of the tool calls are never returned");
    expect(by.flush).toContain("it never creates a sandbox and never opts in");
    expect(by.explain_ruling).toContain("never prints a disclosed value");
    expect(by.show_rules).toContain("Read-only");
    for (const d of Object.values(by)) expect(d).not.toMatch(/[\u2013\u2014]/);
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

  it("verify: a pack with tool-call checks, rulings and rule sets is read, and its tool-call checks lines are printed", async () => {
    const v = parseJson(fs.readFileSync(path.join(__dirname, "../../spec/vectors.json"), "utf8"));
    ctx.service.keyDoc = v.keys_document.keys[0]; // the witness that signed the vectors
    for (const c of v.variants.filter((x: any) => x.name.startsWith("tool-call checks:"))) {
      write("pack.json", JSON.stringify(c.pack));
      const [out, err] = await call("signafaide_verify", { pack: "pack.json" });
      expect(err, c.name).toBe(false);
      for (const title of ["Envelope schema", "Batch hashes and signatures", "Signed heads"]) expect(out, c.name).toMatch(new RegExp(`${title} +PASS`));
      expect(out, c.name).not.toMatch(/Content hashes +FAIL/);
      expect(c.expect.tool_call_checks_lines.length, c.name).toBeGreaterThan(0);
      for (const line of c.expect.tool_call_checks_lines) expect(out.split("\n"), c.name).toContain(`tool-call checks: ${line}`);
    }
  });

  it("explain_ruling and show_rules: a pack's ruling, never a disclosed value", async () => {
    const v = parseJson(fs.readFileSync(path.join(__dirname, "../../spec/vectors.json"), "utf8"));
    const c = v.variants.find((x: any) => x.name.startsWith("tool-call checks: a strict call ruled allow"));
    write("pack.json", JSON.stringify(c.pack));
    const hash: string = c.pack.records[0].receipt.record_hash;
    for (const id of [hash, hash.slice(0, 10), c.pack.records[1].receipt.record_hash]) {
      const [out, err] = await call("signafaide_explain_ruling", { record: id, pack: "pack.json" });
      expect(err, id).toBe(false);
      expect(out).toContain("ruling: allow (enforce mode)");
      expect(out).toContain("basis: rule; matched rules: known-payee");
      expect(out).toContain("rule set: rs_01JD2K8Z5X3V7N2M4K6H8G0F1A version 2");
      expect(out).toContain("disclosed fields: /amount, /currency, /payee/country, /payee/id (values are not shown)");
      expect(out).toContain("rule known-payee: allow");
      for (const value of ["acct_7", "GBP", "\"amount\""]) expect(out).not.toContain(value);
    }
    let [out, err] = await call("signafaide_explain_ruling", { record: "0".repeat(16), pack: "pack.json" });
    expect(err).toBe(true);
    expect(out).toContain("no record matches");
    [out, err] = await call("signafaide_explain_ruling", { record: "abc" });
    expect(err).toBe(true);
    [out, err] = await call("signafaide_explain_ruling", { record: hash, pack: "/etc/passwd" });
    expect(err).toBe(true);
    expect(out).toContain("outside");
  });

  it("explain_ruling and show_rules: a local blocked call names the field to add; a client block names its check", async () => {
    await ctx.rec.createSandbox();
    ctx.service.publishRules(ctx.rec.apiKey!, [{ id: "limit", about: "Big payouts.", action: "block", tools: ["pay"], agents: null, when: [{ field: "/amount", op: "gt", value: 1000 }] }]);
    write("signafaide.checks.json", JSON.stringify({ ...defaultChecksFile(), mode: "enforce", tools: { pay: { strict: true } } }));
    let [out] = await call("signafaide_show_rules");
    expect(out).toContain("rule set: none held");
    await ctx.rec.checks.pullRules();
    [out] = await call("signafaide_show_rules");
    expect(out).toContain("version 1, enforce mode, default allow");
    expect(out).toContain("limit: block (tools pay; every agent) when /amount gt 1000: Big payouts.");
    expect(out).toContain("strict tool pay: fail closed; discloses no field; the rule set needs /amount");
    expect(out).toContain("Read-only");
    const pay = record(async (_a: { amount: number }) => "paid", { name: "pay" });
    await expect(pay({ amount: 5 })).rejects.toThrow();
    await ctx.rec.flush();
    const d = ctx.rec.state.readAll(ctx.rec.state.chains()[0]).find((r) => r.envelope.kind === "decision")!;
    [out] = await call("signafaide_explain_ruling", { record: d.receipt!.record_hash });
    expect(out).toContain("ruling: block (");
    expect(out).toContain("basis: fields_missing; matched rules: none; missing fields: /amount");
    expect(out).toContain("to allow it: add /amount to the disclose list of pay in the checks file");
    expect(out).not.toMatch(/\b5\b.*value/);
    expect(ctx.service.calls.filter((x: any) => /explain|show/.test(JSON.stringify(x)))).toEqual([]);
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

  it("records: lists and filters the local records, metadata only", async () => {
    let [out, err] = await call("signafaide_records");
    expect(out).toContain("No records yet");
    write("requirements.txt", "");
    await call("signafaide_setup");
    record((claim: string) => ({ paid: `payout-for-${claim}` }), { name: "approve_payout", agent: "claims-bot" })("secret-claim-777");
    record((to: string) => `sent to ${to}`, { name: "send_email", agent: "mail-bot" })("private@example.org");
    note("why", { reason: "confidential-reason" }, { agent: "claims-bot" });
    [out, err] = await call("signafaide_records");
    expect(err).toBe(false);
    const rows = (o: string) => o.split("\n").filter((l) => /^\d{4}-\d{2}-\d{2}T/.test(l));
    expect(rows(out)).toHaveLength(5);
    for (const l of rows(out)) expect(l).toMatch(/^\S+Z  (claims-bot|mail-bot)  #\d+  (decision|outcome|note)  (approve_payout|send_email|why)  [0-9a-f]{64}  signed only, not co-signed yet$/);
    expect(out).toContain("total: 5 records matched; shown: 5; truncated: no");
    expect(out).toContain("The inputs and outputs of each call stay in the local files");
    // metadata only: no input, output or note content
    for (const secret of ["secret-claim-777", "payout-for", "private@example.org", "sent to", "confidential-reason"]) expect(out).not.toContain(secret);
    expect(JSON.stringify(ctx.rec.state.readAll(ctx.rec.state.chains()[0]))).toMatch(/secret-claim-777|private@example.org/);
    expect(ctx.service.calls).toEqual([]);

    [out] = await call("signafaide_records", { agent: "mail-bot" });
    expect(rows(out)).toHaveLength(2);
    expect(out).not.toContain("claims-bot");
    expect(out).toContain("total: 2 records matched; shown: 2; truncated: no");
    [out, err] = await call("signafaide_records", { agent: "nobody" });
    expect(err).toBe(true);
    expect(out).toContain('no local records for agent "nobody"');

    [out] = await call("signafaide_records", { limit: 2 });
    expect(rows(out)).toHaveLength(2);
    expect(out).toContain("total: 5 records matched; shown: 2; truncated: yes");
    [out] = await call("signafaide_records", { limit: 5000 });
    expect(rows(out)).toHaveLength(5);

    [out] = await call("signafaide_records", { from: "2999-01-01" });
    expect(rows(out)).toHaveLength(0);
    expect(out).toContain("total: 0 records matched; shown: 0; truncated: no");
    [out] = await call("signafaide_records", { from: "2000-01-01T00:00:00+01:00", to: new Date(Date.now() + 60_000).toISOString() });
    expect(rows(out)).toHaveLength(5);
    [out, err] = await call("signafaide_records", { from: "yesterday" });
    expect(err).toBe(true);
    expect(out).toContain("from must be YYYY-MM-DD or an ISO time");

    [out] = await call("signafaide_records", { agent: "claims-bot" });
    const decision = rows(out).find((l) => l.includes("  decision  "))!;
    const hash = decision.split("  ")[5];
    [out] = await call("signafaide_records", { record: hash.slice(0, 12) });
    expect(rows(out)).toHaveLength(2); // the decision and its outcome
    expect(rows(out).map((l) => l.split("  ")[3]).sort()).toEqual(["decision", "outcome"]);
    [out, err] = await call("signafaide_records", { record: "0".repeat(64) });
    expect(err).toBe(true);
    expect(out).toContain("no record matches");
    [, err] = await call("signafaide_records", { record: "abc" });
    expect(err).toBe(true);
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);
    expect(ctx.service.calls).toEqual([]);
  });

  it("flush: without a key it sends nothing and says why; with one it ships and reports", async () => {
    write("requirements.txt", "");
    await call("signafaide_setup");
    let [out, err] = await call("signafaide_flush");
    expect(err).toBe(false);
    expect(out).toContain("no API key: nothing was sent; 0 records stay local");
    record((x: number) => x * 2, { name: "approve_payout" })(2);
    note("why", { reason: "test" });
    [out, err] = await call("signafaide_flush");
    expect(err).toBe(false);
    expect(out.split("\n")[0]).toBe("no API key: nothing was sent; 3 records stay local. Run `signafaide init` (or set SIGNAFAIDE_API_KEY) to send hashes");
    expect(out).toContain("This tool never creates a sandbox. Sending starts only after the user agrees");
    expect(ctx.service.calls).toEqual([]);
    expect(fs.existsSync(path.join(ctx.root, ".env"))).toBe(false);

    [out] = await call("signafaide_init", AGREED);
    expect(out).toContain("call signafaide_flush to send them now");
    [out, err] = await call("signafaide_flush");
    expect(err).toBe(false);
    expect(out).toBe("shipped 3 records, 0 left in the outbox");
    expect(ctx.service.calls.filter((c) => c === "POST /v1/sandbox")).toHaveLength(1);
    [out] = await call("signafaide_flush");
    expect(out).toBe("shipped 0 records, 0 left in the outbox");
    [out] = await call("signafaide_status");
    expect(out).toContain("outbox: 0 records waiting");
    [out] = await call("signafaide_records");
    expect(out.split("\n").filter((l) => l.endsWith("  co-signed, public timestamp pending"))).toHaveLength(3);
    expect(out).toContain("Public timestamps are not kept in the local files");

    // The service cannot be reached: the error is reported, with its code, and the records wait.
    record((x: number) => x + 1, { name: "approve_payout" })(1);
    await ctx.service.close();
    [out, err] = await call("signafaide_flush");
    expect(err).toBe(true);
    expect(out).toMatch(/^could not ship /);
    expect(out).toMatch(/shipped 0 records, [12] left in the outbox/);
    expect(out).toContain("(see signafaide_explain_error)");
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

describe("shared guidance file", () => {
  // spec/guidance.json is read by this SDK and by the hosted service's remote MCP server.
  const guidance = JSON.parse(fs.readFileSync(path.join(__dirname, "../../spec/guidance.json"), "utf8"));

  it("lists the languages and frameworks the tools accept, with a snippet for each", () => {
    expect(guidance.languages).toEqual([...LANGUAGES]);
    expect(guidance.frameworks).toEqual([...FRAMEWORKS]);
    for (const l of LANGUAGES) {
      expect(typeof guidance.install[l]).toBe("string");
      expect(typeof guidance.verify[l]).toBe("string");
      expect(typeof guidance.snippets[l].plain).toBe("string");
      for (const f of Object.keys(guidance.snippets[l])) expect(FRAMEWORKS).toContain(f);
      for (const f of FRAMEWORKS) expect(snippet(l, f)).toBe(guidance.snippets[l][f] ?? guidance.snippets[l].plain);
    }
  });

  it("fills every placeholder of the steps", () => {
    for (const l of LANGUAGES)
      for (const f of FRAMEWORKS) {
        const out = steps(l, f, guidance.install[l], guidance.verify[l]);
        expect(out).not.toMatch(/\{(install|fence|snippet|declare_tools|verify|verify_tool)\}/);
        expect(out).toContain(`1. Install: ${guidance.install[l]}`);
        expect(out).toContain(`then: ${guidance.verify[l]}. Its last line must start with PASS.`);
      }
  });

  it("has no dash used as punctuation", () => {
    expect(JSON.stringify(guidance)).not.toMatch(/[\u2013\u2014]/);
  });
});
