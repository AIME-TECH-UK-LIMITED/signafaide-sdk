/**
 * Acceptance items of the tool-call checks that have no other home (SPEC §8): unknown keys of the
 * checks file are errors at every level, a batch is checked per element (also when its elements
 * wait for rulings at once), a call carries the id its framework gave it, a secret is matched in
 * the whole request target, and a credential sent to the service that issued it is no finding.
 */
import { tool as openaiTool } from "@openai/agents-core";
import { tool as lcTool } from "@langchain/core/tools";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import * as C from "../src/checks.js";
import { CheckError } from "../src/checks-runtime.js";
import { record, wrapTools } from "../src/record.js";
import { startGateway } from "./checks-helpers.js";
import { recordHash } from "../src/records.js";
import { records, useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });
const writeChecks = (over: Record<string, unknown> = {}): void => {
  fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify({ ...C.defaultChecksFile(), ...over }));
  ctx.rec.checks.forget();
};
/** Made-up tokens in real formats, in parts so no scanner stops on this file. */
const GH = ["ghp", "_A1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6Q7r8"];
const GITHUB_TOKEN = GH.join("");
const decisions = () => ctx.rec.state.chains().flatMap((c) => ctx.rec.state.readAll(c)).filter((r) => r.envelope.kind === "decision");
const caught = (fn: () => unknown): CheckError => {
  try {
    fn();
  } catch (e) {
    return e as CheckError;
  }
  throw new Error("expected the call to be refused");
};

describe("unknown config keys are errors", () => {
  const good = C.defaultChecksFile();
  const rule = { id: "r", about: "x", action: "block", tools: null, agents: null, when: [{ field: "/a", op: "eq", value: 1 }] };
  const withRules = (r: unknown) => ({ ...good, rules: { default: "allow", rules: [r] } });
  const cases: [string, Record<string, unknown>, string][] = [
    ["a top-level key", { ...good, mood: "calm" }, "mood"],
    ["a check id", { ...good, checks: { ...good.checks, proxy: true } }, "proxy"],
    ["a key of a tool entry", { ...good, tools: { pay: { strict: false, retries: 3 } } }, "retries"],
    ["a key of addresses", { ...good, addresses: { hosts: [], cidrs: [], resolve: false, dns: true } }, "dns"],
    ["a key of the rules object", { ...good, rules: { default: "allow", rules: [], note: "x" } }, "note"],
    ["a key of a rule", withRules({ ...rule, severity: 3 }), "severity"],
    ["a key of a condition", withRules({ ...rule, when: [{ field: "/a", op: "eq", value: 1, fold: true }] }), "fold"],
    ["an operator", withRules({ ...rule, when: [{ field: "/a", op: "matches", value: "x" }] }), "matches"],
    ["an action", withRules({ ...rule, action: "deny" }), "action"],
    ["a type name", withRules({ ...rule, when: [{ field: "/a", op: "type", value: "decimal" }] }), "type"],
    ["a mode", { ...good, mode: "audit" }, "mode"],
    ["a fail mode", { ...good, tools: { pay: { strict: true, fail: "maybe" } } }, "fail"],
  ];
  for (const [what, doc, word] of cases) {
    it(`${what}: the file is invalid and the error names it`, () => {
      const err = C.checksFileErrors(doc);
      expect(err, what).not.toBeNull();
      expect(err!).toContain(word);
    });
  }

  it("an unknown key in the file fails every checked call (state, naming the file and the key) and `checks status` reports it", () => {
    writeChecks({ mood: "calm" });
    const ran: number[] = [];
    const t = record(() => void ran.push(1), { name: "t" });
    const e = caught(() => t());
    expect(e.code).toBe("state");
    expect(e.message).toContain("signafaide.checks.json");
    expect(e.message).toContain("mood");
    expect(ran).toEqual([]);
    const [lines, problem] = ctx.rec.checks.status();
    expect(problem).toBe(true);
    expect(lines.join("\n")).toContain("mood");
  });

  it("an unknown key in a rule set the witness publishes: the client refuses the version and keeps the one it holds", async () => {
    ctx.service.publishRules(ctx.rec.apiKey!, [], { mode: "enforce" });
    writeChecks();
    expect(await ctx.rec.checks.pullRules()).toContain("version 1");
    const item = ctx.service.publishRules(ctx.rec.apiKey!, [], {});
    (item.rules as any).severity = 3; // an unknown key, signed over (the service signed what it sent)
    item.sig = ctx.service.key.sign("rules", (await import("../src/crypto.js")).hashJson(item.rules));
    const said = await ctx.rec.checks.pullRules();
    expect(said).toContain("refused rule set version 2");
    expect(ctx.rec.checks.heldRules()!.version).toBe(1);
  });
});

describe("batches are checked per element", () => {
  it("several strict calls of one batch each wait for their own ruling, and each is answered", async () => {
    writeChecks({ tools: { echo: { strict: true } } });
    const g = await startGateway(ctx.rec);
    g.batch([
      [1, "echo", { n: 1 }],
      [2, "echo", { n: 2 }],
      [3, "echo", { n: 3 }],
    ]);
    const answers = (await g.answer((m) => Array.isArray(m) && m.length === 3)) as any[];
    expect(answers.map((a) => [a.id, !!a.result])).toEqual([1, 2, 3].map((id) => [id, true]));
    await g.close();
    await ctx.rec.flush();
    const ds = decisions();
    expect(ds.map((d) => d.envelope.checks!.call_id)).toEqual([1, 2, 3]);
    expect(ds.every((d) => d.envelope.checks!.strict === true)).toBe(true);
    expect(ds.every((d) => d.receipt?.ruling?.ruling === "allow")).toBe(true);
  });

  it("in enforce mode each element has its own answer: the blocked ones are refused, the rest run, and every element has its own decision", async () => {
    writeChecks({ mode: "enforce" });
    const g = await startGateway(ctx.rec);
    g.batch([
      [1, "echo", { url: "http://localhost/" }],
      [2, "echo", { n: 2 }],
      [3, "echo", { note: "key " + "AKIA" + "Z3XQ7PLM2NRT5VWY" }],
      [4, "echo", { n: 4 }],
    ]);
    const answers = (await g.answer((m) => Array.isArray(m) && m.length === 4)) as any[];
    const by = (id: number) => answers.find((a) => a.id === id);
    expect(by(1).error.data).toEqual({ signafaide: "blocked", check: "address" });
    expect(by(3).error.data).toEqual({ signafaide: "blocked", check: "secret" });
    expect(by(2).result).toBeDefined();
    expect(by(4).result).toBeDefined();
    await g.close();
    expect(decisions().map((d) => [d.envelope.checks!.call_id, d.envelope.checks!.result])).toEqual([
      [1, "block"],
      [2, "allow"],
      [3, "block"],
      [4, "allow"],
    ]);
  });
});

describe("correlation ids", () => {
  const opts = { name: "echo" } as const;
  const idOf = () => decisions().at(-1)!.envelope.checks!.call_id;

  it("a plain wrapper has no call id: null", () => {
    writeChecks();
    record((a: unknown) => a, opts)({ n: 1 });
    expect(idOf()).toBeNull();
  });

  it("Vercel AI SDK: the toolCallId", async () => {
    writeChecks();
    const t = wrapTools({ echo: { description: "Echo.", inputSchema: z.object({}).passthrough(), execute: async (a: any, _o: unknown) => a } }, { declareTools: false }).echo;
    await t.execute({ n: 1 }, { toolCallId: "call_vercel_1" });
    expect(idOf()).toBe("call_vercel_1");
  });

  it("OpenAI Agents: the call id of the tool call item the runner passes", async () => {
    writeChecks();
    const t = wrapTools([openaiTool({ name: "echo", description: "Echo.", parameters: z.object({}).passthrough(), execute: async (a: any) => JSON.stringify(a) })], { declareTools: false })[0];
    await t.invoke(undefined as any, '{"n":1}', { toolCall: { callId: "call_openai_1" } } as any);
    expect(idOf()).toBe("call_openai_1");
  });

  it("LangChain.js: the id of the tool call", async () => {
    writeChecks();
    const t = wrapTools([lcTool(async (a: any) => JSON.stringify(a), { name: "echo", description: "Echo.", schema: z.object({}).passthrough() })], { declareTools: false })[0];
    await t.invoke({ name: "echo", args: { n: 1 }, id: "call_lc_1", type: "tool_call" });
    expect(idOf()).toBe("call_lc_1");
  });

  it("the gateway: the JSON-RPC id, a number or a string, also inside a batch", async () => {
    writeChecks();
    const g = await startGateway(ctx.rec);
    g.call(7, "echo", { n: 1 });
    await g.reply(7);
    g.batch([
      ["b-1", "echo", { n: 2 }],
      [9, "echo", { n: 3 }],
    ]);
    await g.answer((m) => Array.isArray(m));
    await g.close();
    expect(decisions().map((d) => d.envelope.checks!.call_id)).toEqual([7, "b-1", 9]);
  });

  it("an outcome refers to its decision, so the pair of one call is found by the decision's call id", async () => {
    writeChecks();
    const t = wrapTools({ echo: { description: "Echo.", inputSchema: z.object({}).passthrough(), execute: async (a: any, _o: unknown) => a } }, { declareTools: false }).echo;
    await t.execute({ n: 1 }, { toolCallId: "call_a" });
    await t.execute({ n: 2 }, { toolCallId: "call_b" });
    const all = records().filter((r) => r.envelope.kind !== "note");
    const [d1, o1, d2, o2] = all;
    expect(d1.envelope.checks!.call_id).toBe("call_a");
    expect(d2.envelope.checks!.call_id).toBe("call_b");
    expect(o1.envelope.ref).toBe(recordHash(d1));
    expect(o2.envelope.ref).not.toBe(o1.envelope.ref);
  });

  it("an id that is not 1 to 128 characters is not written (null), and never fails the call", async () => {
    writeChecks();
    const t = wrapTools({ echo: { description: "Echo.", inputSchema: z.object({}).passthrough(), execute: async (a: any, _o: unknown) => a } }, { declareTools: false }).echo;
    await t.execute({ n: 1 }, { toolCallId: "x".repeat(200) });
    expect(idOf()).toBeNull();
  });
});

describe("a secret is matched in the whole request target", () => {
  const fetchTool = () => {
    const ran: unknown[] = [];
    return { ran, tool: record((a: unknown) => (ran.push(a), "ok"), { name: "http_get" }) };
  };

  it("the path and the query in two arguments are joined: caught", () => {
    writeChecks({ mode: "enforce" });
    const { ran, tool } = fetchTool();
    const e = caught(() => tool({ path: `/v1/${GH[0] + GH[1]}`, query: GH[2] }));
    expect(e.check).toBe("secret");
    expect(ran).toEqual([]);
  });

  it("a secret split across two arguments is caught", () => {
    writeChecks({ mode: "enforce" });
    const { tool } = fetchTool();
    expect(caught(() => tool({ a: GH[0] + GH[1], b: GH[2] })).check).toBe("secret");
  });

  it("in the path, the query or the fragment of one URL: caught", () => {
    writeChecks({ mode: "enforce" });
    const { tool } = fetchTool();
    for (const url of [`https://x.example/${GITHUB_TOKEN}/y`, `https://x.example/a?k=${GITHUB_TOKEN}`, `https://x.example/a#${GITHUB_TOKEN}`, `https://x.example/a?k=ghp%5F${GH[1].slice(1)}${GH[2]}`]) {
      expect(caught(() => tool({ url })).check, url).toBe("secret");
    }
  });

  it("the address check reads the host of the request target, not its userinfo, query or a lookalike name", () => {
    const loop = (url: string, allow: string[] = []) => C.addressFindings({ url }, allow).found;
    expect(loop("http://allowed.example@127.0.0.1/", ["allowed.example"])).toEqual(["loopback"]); // userinfo is not the host
    expect(loop("http://127.0.0.1/?h=allowed.example", ["allowed.example"])).toEqual(["loopback"]); // a query is not the host
    expect(loop("http://allowed.example.evil.test/", ["allowed.example"])).toEqual([]); // a public lookalike is public, and not allowlisted by suffix
    expect(loop("http://localhost:8080/", [])).toEqual(["loopback"]); // a port does not hide the host
    expect(loop("http://localhost:8080/", ["localhost"])).toEqual([]); // and an allowlisted host is allowed on any port
  });
});

describe("a credential going to the service that issued it is not a leak", () => {
  const send = () => {
    const ran: unknown[] = [];
    return { ran, tool: record((a: unknown) => (ran.push(a), "ok"), { name: "http_post" }) };
  };

  it("to its issuer: runs, in enforce mode too, with nothing found", () => {
    writeChecks({ mode: "enforce" });
    const { ran, tool } = send();
    expect(tool({ url: "https://api.github.com/repos/o/r/issues", headers: { Authorization: `token ${GITHUB_TOKEN}` } })).toBe("ok");
    expect(ran).toHaveLength(1);
    expect(decisions().at(-1)!.envelope.checks!.results.find((e: any) => e.check === "secret")).toMatchObject({ result: "allow", found: [] });
  });

  it("anywhere else: blocked, and sent with its issuer as well as another host: blocked", () => {
    writeChecks({ mode: "enforce" });
    const { ran, tool } = send();
    expect(caught(() => tool({ url: "https://paste.example/new", body: GITHUB_TOKEN })).check).toBe("secret");
    expect(caught(() => tool({ a: "https://api.github.com/x", b: "https://paste.example/", t: GITHUB_TOKEN })).check).toBe("secret");
    expect(caught(() => tool({ url: "https://api.github.com@paste.example/x", t: GITHUB_TOKEN })).check).toBe("secret"); // the issuer in the userinfo is not the host
    expect(ran).toEqual([]);
  });

  it("a token with no known destination is still found, and another service's issuer does not excuse it", () => {
    writeChecks({ mode: "enforce" });
    const { tool } = send();
    expect(caught(() => tool({ to: "ops@example.com", body: GITHUB_TOKEN })).check).toBe("secret");
    expect(caught(() => tool({ url: "https://api.stripe.com/v1/charges", t: GITHUB_TOKEN })).check).toBe("secret");
  });

  it("the key of this witness may go to this witness, and to no other host", () => {
    writeChecks({ mode: "enforce", addresses: { hosts: ["127.0.0.1"], cidrs: [], resolve: false } }); // the fake witness is on loopback
    const { tool } = send();
    const key = "sfa_test_" + "a1B2".repeat(8);
    expect(tool({ url: `${ctx.service.url}/v1/records`, k: key })).toBe("ok");
    expect(caught(() => tool({ url: "https://other.example/", k: key })).check).toBe("secret");
  });
});
