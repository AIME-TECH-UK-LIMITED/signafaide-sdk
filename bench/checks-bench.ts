/**
 * Cost of the local tool-call checks of one call (spec §8), TypeScript SDK.
 *
 *   cd js && npx vite-node ../bench/checks-bench.ts            # prints a table
 *   cd js && npx vite-node ../bench/checks-bench.ts --json     # one JSON line
 *
 * Measured: `ChecksState.plan()`, which runs the decision checks (secret, address, changed_tool,
 * fingerprint, rule, and from spec 1.1 hidden_instruction on the tool's definition) of a call and
 * builds the `checks` of its decision, and `resultEntries()`, the result checks (secret and
 * hidden_instruction) on the result. The last row's call also carries a 3 KB base64 attachment,
 * which the secret check decodes (spec 1.1). The checks file is
 * on, with a 50-rule local rule set. The "connected" case adds a held project rule set of 50
 * rules and a shared fingerprint list. Nothing is sent: the fake service only signs the
 * rule set and the list once, before timing. Run under `systemd-run --user --scope -p MemoryMax=8G`.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { defaultChecksFile } from "../js/src/checks.js";
import { configure } from "../js/src/runtime.js";
import { FakeService } from "../js/test/fake-service.js";

const N = Number(process.env.BENCH_N ?? 20000);
const WARM = Math.min(2000, N);

function rules(n: number): any[] {
  const tools = ["pay", "delete_account", "send_email", "refund", "export_data"];
  return Array.from({ length: n }, (_, i) => ({
    id: `rule-${String(i + 1).padStart(2, "0")}`,
    about: `Rule ${i + 1}.`,
    action: i % 5 === 0 ? "allow" : "block",
    tools: i % 7 === 0 ? null : [tools[i % tools.length]],
    agents: i % 11 === 0 ? ["other-bot"] : null,
    when: [
      { field: "/amount", op: i % 2 ? "gt" : "lt", value: 1000 + i },
      ...(i % 3 === 0 ? [{ field: "/to", op: "suffix", value: `@blocked${i}.example` }] : []),
      ...(i % 4 === 0 ? [{ field: "/currency", op: "not_in", value: ["GBP", "EUR", "USD"] }] : []),
    ],
  }));
}

const tool = {
  name: "send_email",
  description: "Send an email to a customer on behalf of the claims team. Returns the message id.",
  inputSchema: { type: "object", properties: { to: { type: "string" }, subject: { type: "string" }, body: { type: "string" }, amount: { type: "number" }, currency: { type: "string" }, callback: { type: "string" } }, required: ["to", "body"] },
};
const args = {
  to: "customer@example.org",
  subject: "Your claim 48213 has been approved",
  body: "Hello, your claim has been approved and the payment of 120.00 GBP will reach your account within three working days. Reply to this message if anything looks wrong. Regards, the claims team.",
  amount: 120,
  currency: "GBP",
  callback: "https://api.example.com/v1/claims/48213/status",
};
/** A call with a 3 KB base64 attachment and a hex digest: the secret check decodes both (spec 1.1). */
const attachment = Buffer.from("Quarterly claims summary. ".repeat(118), "utf8").toString("base64");
const encodedArgs = { ...args, attachment, digest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" };
const output = { id: "msg_93f1", status: "queued", detail: "The message was accepted for delivery and will be sent within a minute." };

function pct(xs: number[], p: number): number {
  return xs[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))];
}

function time(fn: () => void): { p50: number; p95: number; p99: number; mean: number } {
  for (let i = 0; i < WARM; i++) fn();
  const us: number[] = [];
  for (let i = 0; i < N; i++) {
    const t = process.hrtime.bigint();
    fn();
    us.push(Number(process.hrtime.bigint() - t) / 1000);
  }
  us.sort((a, b) => a - b);
  return { p50: pct(us, 50), p95: pct(us, 95), p99: pct(us, 99), mean: us.reduce((a, b) => a + b, 0) / us.length };
}

async function scenario(name: string, connected: boolean, listSize: number, callArgs: Record<string, unknown> = args): Promise<Record<string, unknown>> {
  const root = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sfa-bench-")), "bench-project");
  fs.mkdirSync(path.join(root, ".git"), { recursive: true });
  const cwd = process.cwd();
  process.chdir(root);
  const service = await new FakeService().start();
  process.env.SIGNAFAIDE_URL = service.url;
  process.env.SIGNAFAIDE_TEST = "0";
  const rec = configure({ quiet: true, flushIntervalMs: 3_600_000 });
  try {
    fs.writeFileSync(path.join(root, "signafaide.checks.json"), JSON.stringify({ ...defaultChecksFile(), rules: { default: "allow", rules: rules(50) } }));
    if (connected) {
      await rec.createSandbox();
      service.publishRules(rec.apiKey!, rules(50), { mode: "watch" });
    }
    service.listUpdate(Array.from({ length: listSize }, (_, i) => ({ kind: "tool", fingerprint: (i + 1).toString(16).padStart(64, "0") })));
    if (!rec.apiKey) await rec.createSandbox();
    await rec.checks.pullList();
    if (connected) await rec.checks.pullRules();
    rec.checks.forget();
    const plan = rec.checks.plan(tool, "claims-bot", callArgs)!;
    const kinds = plan.checks.results.map((r: any) => r.check).join(",");
    const decision = time(() => void rec.checks.plan(tool, "claims-bot", callArgs));
    const result = time(() => void rec.checks.resultEntries(output));
    return { name, listSize, checks: kinds, decision, result };
  } finally {
    rec.close();
    await service.close();
    process.chdir(cwd);
    fs.rmSync(path.dirname(root), { recursive: true, force: true });
  }
}

const out = [await scenario("local rules only (50 local rules, list of 1,000)", false, 1000), await scenario("connected (50 local + 50 held rules, list of 1,000)", true, 1000), await scenario("connected, list of 20,000", true, 20000), await scenario("local rules, list of 1,000, a 3 KB base64 attachment", false, 1000, encodedArgs)];
if (process.argv.includes("--json")) console.log(JSON.stringify({ sdk: "typescript", node: process.version, iterations: N, scenarios: out }));
else {
  console.log(`typescript, node ${process.version}, ${N} calls per row, microseconds`);
  for (const s of out as any[]) {
    console.log(`${s.name}  [${s.checks}]`);
    for (const k of ["decision", "result"]) console.log(`  ${k.padEnd(9)} p50 ${s[k].p50.toFixed(1)}  p95 ${s[k].p95.toFixed(1)}  p99 ${s[k].p99.toFixed(1)}  mean ${s[k].mean.toFixed(1)}`);
  }
}
