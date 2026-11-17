/** The claim step: why to claim, and how long an unclaimed sandbox has left (init, status,
 * claim, verify, the MCP tools). The Python tests (test_claim.py) check the same words. */

import * as fs from "node:fs";
import * as path from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { CLAIM_WHY, daysLeft, longDate, parseExpiry } from "../src/claim.js";
import { main } from "../src/cli.js";
import { record } from "../src/index.js";
import { createServer } from "../src/mcp.js";
import { configure } from "../src/runtime.js";
import { deadUrl, useProject } from "./helpers.js";

const ctx = useProject();

async function cli(...args: string[]): Promise<[number, string, string]> {
  const out: string[] = [];
  const err: string[] = [];
  const [log, error] = [console.log, console.error];
  console.log = (s: string) => out.push(s);
  console.error = (s: string) => err.push(s);
  try {
    const code = await main(args);
    // `init` also says how tool-call checks are set up (tested in checks-runtime.test.ts): not a claim line.
    return [code, out.filter((l) => !String(l).startsWith("tool-call checks: ")).join("\n"), err.join("\n")];
  } finally {
    [console.log, console.error] = [log, error];
  }
}

async function mcp(name: string, args: Record<string, unknown> = {}): Promise<string> {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createServer().connect(b);
  const client = new Client({ name: "test", version: "1" });
  await client.connect(a);
  try {
    const r = await client.callTool({ name, arguments: args });
    return (r.content as { text: string }[]).map((c) => c.text).join("\n");
  } finally {
    await client.close();
  }
}

const sandboxFile = () => path.join(ctx.root, ".signafaide", "sandbox.json");
const saved = () => JSON.parse(fs.readFileSync(sandboxFile(), "utf8"));
const save = (v: object) => fs.writeFileSync(sandboxFile(), JSON.stringify(v, null, 2));
const WHY = "claiming is free and needs no card: the sandbox moves into your own organisation and stops expiring, and you get the console, live keys and auditor links";
const KEPT = "Records on this machine are kept and still verify";
const left = (n: number, at: string) => `${n} days left: an unclaimed sandbox and its records on the service are deleted on ${longDate(at)}. ${KEPT}`;
const again = () =>
  `${KEPT}. To carry on with the service: remove SIGNAFAIDE_API_KEY from ${path.join(fs.realpathSync(ctx.root), ".env")} (or from the environment), run \`signafaide init\` for a new sandbox and claim it`;

describe("the claim step", () => {
  it("dates and days", () => {
    expect(CLAIM_WHY).toBe(WHY);
    expect(longDate("2026-12-15T09:30:00.000Z")).toBe("15 December 2026");
    expect(longDate("2027-01-01T00:00:00.000Z")).toBe("1 January 2027");
    const now = Date.parse("2026-12-03T10:00:00.000Z");
    expect(daysLeft("2026-12-15T09:30:00.000Z", now)).toBe(12);
    expect(daysLeft("2026-12-03T10:00:01.000Z", now)).toBe(1);
    expect(daysLeft("2026-12-03T09:00:00.000Z", now)).toBe(0);
    expect(parseExpiry("2026-12-15T09:30:00.000Z")).toBe("2026-12-15T09:30:00.000Z");
    for (const bad of [undefined, null, 30, "", "soon", "2026-13-45T00:00:00Z", "x".repeat(50)]) expect(parseExpiry(bad)).toBeNull();
  });

  it("init says why to claim and how long is left; status, claim and verify repeat it", async () => {
    let [code, out] = await cli("init");
    expect(code).toBe(0);
    const at = saved().expires_at;
    expect(at).toBe(ctx.service.project().expires_at);
    const url = saved().claim_url;
    const lines = out.split("\n");
    expect(lines[0]).toBe(`sandbox ready at ${ctx.service.url}, key saved to ${path.join(fs.realpathSync(ctx.root), ".env")}; claim it at ${url}`);
    expect(lines[1]).toBe(WHY);
    expect(lines[2]).toBe(left(30, at));
    expect(lines[3]).toMatch(/^By creating a sandbox you agree/);

    [code, out] = await cli("init"); // again: the key is there
    expect(out.split("\n").slice(-3)).toEqual([expect.stringMatching(/^key found \(sfa_test_0000\.\.\.\); claim the sandbox at http/), WHY, left(30, at)]);

    [code, out] = await cli("status");
    expect(out.split("\n").slice(-3)).toEqual([`claim: ${url}`, WHY, left(30, at)]);

    [code, out] = await cli("claim");
    expect([code, out.split("\n")]).toEqual([0, [url, WHY, left(30, at)]]);

    record((x: number) => x, { name: "act" })(1);
    await cli("flush");
    [code, out] = await cli("verify");
    expect(code).toBe(0);
    expect(out.split("\n").slice(-4)).toEqual([expect.stringMatching(/^PASS/), `claim: ${url}`, WHY, left(30, at)]);

    // --json: the same facts as data, and no prose.
    [code, out] = await cli("verify", "--json");
    expect(code).toBe(0);
    const json = JSON.parse(out);
    expect(json.sandbox).toEqual({ claim_url: url, claimed: false, expires_at: at, days_left: 30 });
    expect(json.result).toBe("PASS");
    expect(out).not.toContain("claiming is free");

    // Twelve days before the end.
    const soon = new Date(Date.now() + 12 * 86_400_000 - 60_000).toISOString();
    ctx.service.project().expires_at = soon;
    [code, out] = await cli("status");
    expect(out.split("\n").at(-1)).toBe(left(12, soon));
    expect(saved().expires_at).toBe(soon);
    ctx.service.project().expires_at = new Date(Date.now() + 3_600_000).toISOString();
    expect((await cli("status"))[1].split("\n").at(-1)).toMatch(/^1 day left: an unclaimed sandbox/);
  });

  it("a witness that sends no expires_at: nothing is said about days, and none are assumed", async () => {
    ctx.service.sandboxDays = null;
    let [code, out] = await cli("init");
    expect(code).toBe(0);
    expect(out.split("\n").slice(0, 3)).toEqual([expect.stringContaining("claim it at "), WHY, expect.stringMatching(/^By creating a sandbox/)]);
    expect("expires_at" in saved()).toBe(false);
    for (const cmd of [["status"], ["claim"], ["init"]]) {
      [code, out] = await cli(...cmd);
      expect(out).toContain(WHY);
      expect(out).not.toMatch(/days? left|deleted on/);
    }
    record((x: number) => x, { name: "act" })(1);
    await cli("flush");
    [code, out] = await cli("verify");
    expect(out.split("\n").slice(-2)).toEqual([`claim: ${saved().claim_url}`, WHY]);
    expect(JSON.parse((await cli("verify", "--json"))[1]).sandbox).toEqual({ claim_url: saved().claim_url, claimed: false, expires_at: null, days_left: null });
    expect(await mcp("signafaide_claim_link")).not.toMatch(/days? left|deleted on/);
    // A value that is not a time is not used either.
    ctx.service.project().expires_at = "in a month";
    expect((await cli("status"))[1]).not.toMatch(/days? left|deleted on/);
    expect("expires_at" in saved()).toBe(false);
  });

  it("a sandbox made by an older SDK learns its time from status", async () => {
    await cli("init");
    const { expires_at: at, ...old } = saved();
    save(old);
    const [, out] = await cli("status");
    expect(out.split("\n").at(-1)).toBe(left(30, at));
    expect(saved().expires_at).toBe(at);
  });

  it("claimed: done, and no countdown anywhere", async () => {
    await cli("init");
    record((x: number) => x, { name: "act" })(1);
    await cli("flush");
    ctx.service.project().claimed = true;
    let [code, out] = await cli("status");
    expect(out.split("\n").at(-1)).toBe("claim: done (this sandbox belongs to an organisation now)");
    expect(out).not.toMatch(/days? left|deleted on|claiming is free/);
    expect(saved().claimed).toBe(true);
    expect("expires_at" in saved()).toBe(false);
    [code, out] = await cli("claim");
    expect([code, out]).toEqual([0, "claim: done (this sandbox belongs to an organisation now)"]);
    [code, out] = await cli("verify");
    expect(out.split("\n").at(-1)).toMatch(/^PASS/);
    expect(JSON.parse((await cli("verify", "--json"))[1]).sandbox).toEqual({ claim_url: saved().claim_url, claimed: true, expires_at: null, days_left: null });
    expect((await cli("init"))[1]).toBe("key found (sfa_test_0000...); claim: done (this sandbox belongs to an organisation now)");
    expect(await mcp("signafaide_claim_link")).toBe("claim: done (this sandbox belongs to an organisation now)");
    expect(await mcp("signafaide_status")).not.toMatch(/days? left|deleted on/);
  });

  it("expired: says what the service does, that local records are kept, and how to carry on", async () => {
    await cli("init");
    record((x: number) => x, { name: "act" })(1);
    await cli("flush");
    const past = new Date(Date.now() - 3_600_000).toISOString();
    ctx.service.project().expires_at = past;
    const expired = [
      `claim: this sandbox expired on ${longDate(past)} without being claimed, so its claim link no longer works. The service deletes an expired sandbox and its records there within a day, and from then on refuses its key (invalid_key)`,
      again(),
    ];
    // Before the service's daily cleanup the key still answers.
    let [code, out, err] = await cli("status");
    expect(out.split("\n").slice(-2)).toEqual(expired);
    // After it the key is refused (401 invalid_key): the same words, from the saved time.
    ctx.service.cleanup();
    expect(ctx.service.projects.size).toBe(0);
    [code, out, err] = await cli("status");
    expect(out.split("\n").slice(-2)).toEqual(expired);
    [code, out, err] = await cli("claim");
    expect([code, out, err.split("\n")]).toEqual([1, "", expired]);
    expect((await mcp("signafaide_claim_link")).split("\n")).toEqual(["Tell the human:", ...expired]);
    // Local records still verify, and the lines follow the result.
    [code, out] = await cli("verify");
    expect(code).toBe(0);
    expect(out.split("\n").slice(-3)).toEqual([expect.stringMatching(/^PASS/), ...expired]);
    expect(JSON.parse((await cli("verify", "--json"))[1]).sandbox).toEqual({ claim_url: saved().claim_url, claimed: false, expires_at: past, days_left: 0 });

    // A sandbox whose time was never saved (an older SDK or witness): the refusal is what is known.
    const { expires_at: _gone, ...old } = saved();
    save(old);
    [code, out] = await cli("status");
    expect(out.split("\n").slice(-2)).toEqual([
      "claim: the service refuses this sandbox's key (invalid_key). The service deletes an unclaimed sandbox and its records there when it expires, and this one had not been claimed when this machine last asked",
      again(),
    ]);

    // Carrying on as the line says: remove the key, init again; the old chain stays and verifies.
    const env = path.join(ctx.root, ".env");
    fs.writeFileSync(env, fs.readFileSync(env, "utf8").split("\n").filter((l) => !l.startsWith("SIGNAFAIDE_API_KEY=")).join("\n"));
    [code, out] = await cli("init");
    expect(code).toBe(0);
    expect(out.split("\n")[2]).toBe(left(30, saved().expires_at));
    record((x: number) => x, { name: "act" })(2);
    expect((await cli("flush"))[0]).toBe(0);
    expect((await cli("verify"))[0]).toBe(0);
  });

  it("past its time while the service cannot be asked: no claim that it was lost", async () => {
    await cli("init");
    const past = new Date(Date.now() - 3_600_000).toISOString();
    save({ ...saved(), expires_at: past });
    process.env.SIGNAFAIDE_URL = await deadUrl();
    configure({ quiet: true }).close();
    const [, out] = await cli("claim");
    expect(out.split("\n")).toEqual([
      saved().claim_url,
      `this sandbox was due to be deleted on ${longDate(past)} unless it was claimed first, and the service could not be asked just now; run \`signafaide status\` when it can be reached. ${KEPT}`,
    ]);
  });

  it("the MCP tools pass the claim step on to the human", async () => {
    const created = await mcp("signafaide_init", { confirm_user_agreed: true, user_words: "yes, create the sandbox" });
    const at = saved().expires_at;
    const url = saved().claim_url;
    const step = ["Give the human the claim link and what follows it, in these words; do not open the link yourself:", `claim: ${url}`, WHY, left(30, at)];
    expect(created.split("\n")).toEqual([
      `Created a sandbox at ${ctx.service.url} (no account) and saved SIGNAFAIDE_API_KEY to ${path.join(fs.realpathSync(ctx.root), ".env")} (in .gitignore). Records written before now ship on the next run, or call signafaide_flush to send them now.`,
      ...step,
      expect.stringMatching(/^Tell the human: By creating a sandbox you agree/),
    ]);
    expect((await mcp("signafaide_claim_link")).split("\n")).toEqual(step);
    expect((await mcp("signafaide_status")).split("\n").slice(-3)).toEqual(step.slice(1));
    expect((await mcp("signafaide_init", { confirm_user_agreed: true, user_words: "yes" })).split("\n")).toEqual([
      `Nothing was created. API key: found (test env); record hashes are sent to ${ctx.service.url}.`,
      ...step,
    ]);
  });
});
