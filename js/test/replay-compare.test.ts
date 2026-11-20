import * as fs from "node:fs";
import * as path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { compare, flush, note, record, replay, VerificationFailed } from "../src/index.js";
import { main } from "../src/cli.js";
import { hashJson } from "../src/crypto.js";
import { getRecorder } from "../src/runtime.js";
import { chainFile, records, useProject } from "./helpers.js";

const ctx = useProject({ optIn: true });
let approvePayout: (claim: { claim_id: string; amount: number }) => unknown;

beforeEach(async () => {
  approvePayout = record((c: { claim_id: string; amount: number }) => ({ approved: c.amount < 500 }), {
    name: "approve_payout",
  });
  for (let i = 0; i < 10; i++) approvePayout({ claim_id: `c-${i}`, amount: i * 100 });
  note("shift_end", { by: "ops" });
  expect((await flush()).left).toBe(0);
});

const snapshot = () => {
  const box = path.join(getRecorder().state.home, "outbox");
  return [
    fs.readFileSync(chainFile(), "utf8"),
    fs.existsSync(box) ? fs.readdirSync(box, { recursive: true }).sort() : [],
  ];
};

describe("replay", () => {
  it("shows verified inputs and outputs, paired", async () => {
    const r = await replay();
    expect(r.ok).toBe(true);
    expect(r.entries.length).toBe(21);
    const [d, o] = r.entries;
    expect([d.status, o.status]).toEqual(["verified", "verified"]);
    expect(d.content!.input).toEqual({ claim_id: "c-0", amount: 0 });
    expect(o.content).toEqual({ output: { approved: true } });
    expect(d.pair).toBe(o);
    const text = String(r);
    expect(text).toContain("approve_payout  -> outcome #2");
    expect(text.endsWith("each checked against its content_hash, its signature and its receipt")).toBe(true);
    const page = r.toHtml();
    expect(page).not.toMatch(/<script|<link|src=/);
    expect(page).toContain("c-9");
    expect((await replay({ record: o.hash.slice(0, 10) })).entries.map((e) => e.envelope.seq)).toEqual([1, 2]);
  });

  it("catches tampered content", async () => {
    const lines = fs.readFileSync(chainFile(), "utf8").trim().split("\n");
    const rec = JSON.parse(lines[4]);
    rec.content.input.amount = 1; // the agent saw 200
    lines[4] = JSON.stringify(rec);
    fs.writeFileSync(chainFile(), lines.join("\n") + "\n");
    const r = await replay();
    expect(r.ok).toBe(false);
    expect(r.report.firstFailed()).toBe("content");
    const bad = r.entries.filter((e) => e.problems.length);
    expect(bad.map((e) => e.envelope.seq)).toEqual([5]);
    expect(bad[0].status).toBe("FAIL");
    await expect(compare(() => ({ approved: true }))).rejects.toBeInstanceOf(VerificationFailed);
  });
});

describe("compare", () => {
  it("counts agreement, changes and errors without writing", async () => {
    const before = snapshot();
    const rep = await compare(
      async (c: { claim_id: string; amount: number }) => {
        if (c.claim_id === "c-9") throw new Error("model timeout");
        return { approved: c.amount < 300 };
      },
      { name: "approve_payout" },
    );
    expect([rep.n, rep.agreed, rep.changed, rep.errors]).toEqual([10, 7, 2, 1]);
    const changed = rep.rows.filter((r) => r.result === "changed");
    expect(changed.map((r) => (r.input as any).claim_id)).toEqual(["c-3", "c-4"]);
    expect(changed[0]).toMatchObject({ recorded: { approved: true }, candidate: { approved: false }, same: false });
    expect(rep.rows.find((r) => r.result === "error")).toMatchObject({ same: null, error: "Error: model timeout" });
    const loose = await compare(() => ({ approved: "yes" }), {
      same: (a: any, b: any) => !!a.approved === !!b.approved,
      limit: 3,
    });
    expect([loose.n, loose.agreed, loose.changed]).toEqual([3, 0, 3]);
    expect(snapshot()).toEqual(before);
  });

  it("never writes records, even through recorded tools", async () => {
    const before = snapshot();
    const ran: number[] = [];
    const sendMoney = record((amount: number) => ran.push(amount), { name: "send_money" });
    const rep = await compare(async (c: { amount: number }) => {
      await Promise.resolve();
      sendMoney(c.amount); // a real side effect: refused before it runs
      return { approved: true };
    });
    expect([rep.errors, rep.n]).toEqual([10, 10]);
    expect(ran).toEqual([]);
    expect(rep.rows[0].error).toMatch(/must be side-effect free/);
    expect(snapshot()).toEqual(before);
    approvePayout({ claim_id: "c-new", amount: 1 });
    expect(records().length).toBe(23);
  });

  it("uploads a hash-only payload by default", async () => {
    const rep = await compare((c: { amount: number }) => ({ approved: c.amount < 300 }), {
      name: "approve_payout",
      label: "v2 threshold",
    });
    const body = rep.payload() as any;
    expect(Object.keys(body).sort()).toEqual(["agent", "candidate", "label", "name", "rows"]);
    expect(Object.keys(body.rows[3]).sort()).toEqual(["candidate_hash", "outcome_hash", "record_hash", "result"]);
    expect(body.rows[3]).toMatchObject({ result: "changed", candidate_hash: hashJson({ approved: false }) });
    expect((rep.payload(true) as any).rows[3]).toMatchObject({
      recorded: { approved: true },
      candidate: { approved: false },
    });
    const out = await rep.upload();
    expect(out.url).toMatch(/\/app\/experiments\/1$/);
    expect(ctx.service.experiments[0]).toEqual(body);
    getRecorder().storeContent = true;
    await rep.upload();
    expect(ctx.service.experiments[1].rows[0]).toHaveProperty("recorded");
  });
});

describe("cli", () => {
  it("replay --html and compare --module --upload", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const errs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const page = path.join(ctx.root, "replay.html");
      expect(await main(["replay", "--html", page, "--to", "2999-01-01"])).toBe(0);
      expect(String(log.mock.calls[0][0])).toMatch(/^signafAIde replay: claims-project/);
      expect(fs.readFileSync(page, "utf8").startsWith("<!doctype html>")).toBe(true);
      const mod = path.join(ctx.root, "cand.mjs");
      fs.writeFileSync(mod, "export function approve(c) { return { approved: c.amount < 400 }; }\n");
      expect(await main(["compare", "--module", `${mod}:approve`, "--name", "approve_payout", "--upload"])).toBe(0);
      const out = String(log.mock.calls.at(-1)![0]);
      expect(out).toContain("n 10: agreed 9, changed 1, errors 0 (90.0% agreement)");
      expect(out).toContain("uploaded: ");
      expect(await main(["compare", "--module", "nope"])).toBe(1);
    } finally {
      log.mockRestore();
      errs.mockRestore();
    }
  });
});
