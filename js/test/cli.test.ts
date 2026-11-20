import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { COMMANDS, main } from "../src/cli.js";
import { note, record } from "../src/index.js";
import { makeDraft } from "../src/records.js";
import { getRecorder } from "../src/runtime.js";
import { deadUrl, useProject } from "./helpers.js";

/** The result line without its check counts (§7), to compare the rest. */
const noCounts = (line: string | undefined): string =>
  (line ?? "").replace(/: \d+ of 12 checks [^;]*; /, ": ").replace(/: \d+ of 12 checks [^;]*$/, "");

const ctx = useProject();

async function cli(...args: string[]): Promise<[number, string, string]> {
  const out: string[] = [];
  const err: string[] = [];
  const [log, error] = [console.log, console.error];
  console.log = (s: string) => out.push(s);
  console.error = (s: string) => err.push(s);
  try {
    const code = await main(args);
    return [code, out.join("\n"), err.join("\n")];
  } finally {
    [console.log, console.error] = [log, error];
  }
}

describe("cli", () => {
  it("has the same commands as the Python CLI, plus the coding-agent ones and the MCP gateway", () => {
    expect(Object.keys(COMMANDS).filter((c) => !["agent", "mcp", "gateway"].includes(c))).toEqual([
      "protect",
      "check",
      "pull",
      "prove",
      "start-fresh",
      "login",
      "logout",
      "whoami",
      "init",
      "status",
      "repair",
      "verify",
      "keys",
      "export",
      "replay",
      "compare",
      "claim",
      "flush",
      "checks",
      "rules",
    ]);
  });

  it("init, then claim", async () => {
    const [code, out] = await cli("init");
    expect(code).toBe(0);
    expect(out.split("\n")).toHaveLength(10); // ready + claim link, why claim, time left, terms, what is sent, which tool-call checks are on, how to change them, the project note and the file it went in, and CLAUDE.md importing it
    expect(out).toContain("agents: AGENTS.md created, with the signafAIde note for coding agents (a marked block)");
    expect(out).toContain("agents: CLAUDE.md created");
    expect(out).toContain("tool-call checks: on, Calibrating");
    expect(out).toContain(`claim it at ${ctx.service.url}/app/claim/`);
    expect(out).toContain(
      `By creating a sandbox you agree to the signafAIde Terms (${ctx.service.url}/legal/terms) and Privacy notice (${ctx.service.url}/legal/privacy).`,
    );
    expect(out).toContain("records written before now ship with their original times");
    const claim = out.split("\n")[0].split(" ").at(-1)!;
    expect(fs.readFileSync(path.join(ctx.root, ".env"), "utf8")).toMatch(
      /^SIGNAFAIDE_API_KEY=sfa_test_[^\n]+\nSIGNAFAIDE_URL=http:\/\/127\.0\.0\.1:\d+\n$/,
    ); // not the default service: its URL goes with the key
    const [, again] = await cli("init");
    expect(again).toContain("key found");
    expect(again).toContain(claim);
    expect((await cli("claim"))[1].split("\n")[0]).toBe(claim); // the link alone on the first line
  });

  it("without a key: status, flush and verify are local and send nothing", async () => {
    record((x: number) => x, { name: "act" })(1);
    let [code, out] = await cli("status");
    expect(code).toBe(0);
    expect(out).toContain("records stay on this machine");
    [code, out] = await cli("flush");
    expect([code, out]).toEqual([
      0,
      "no API key: nothing was sent; 2 records stay local. Run `signafaide init` (or set SIGNAFAIDE_API_KEY) to send hashes",
    ]);
    [code, out] = await cli("verify");
    expect(code).toBe(0);
    const lines = out.split("\n");
    expect(lines.at(-1)).toBe("PASS (local checks only): 4 of 12 checks passed, 8 not checked (nothing co-signed yet)");
    expect(lines.at(-2)).toBe(
      "co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)",
    );
    expect(out).toMatch(/^ 3\. Client signatures +PASS +2 records/m);
    expect(ctx.service.calls).toEqual([]);
  });

  it("claim without a sandbox", async () => {
    const [code, , err] = await cli("claim");
    expect(code).toBe(1);
    expect(err).toContain("signafaide init");
  });

  it("status, flush, verify, export", async () => {
    await cli("init");
    record((x: number) => x, { name: "act" })(1);
    let [code, out] = await cli("status");
    expect(code).toBe(0);
    expect(out).toContain("env test");
    // A chain new to this disk waits as drafts until the witness's head is known.
    expect(out).toMatch(
      /chain _pending\/[0-9a-f]{16}\/claims-project: key [0-9a-f]{16}, 2 records, drafts, signed for the project when they ship/,
    );
    expect(out).toContain("outbox: 2 records waiting");
    expect(out).toContain("quota: 0 of 1000");
    expect(out).toContain("claim: ");

    [code, out] = await cli("flush");
    expect([code, out]).toEqual([0, "shipped 2 records, 0 left in the outbox"]);
    expect((await cli("status"))[1]).toContain("last receipt seq 2");

    [code, out] = await cli("verify");
    expect(code).toBe(0);
    // The test service is plain http on this machine: accepted, and said not to be independent.
    // The result line, then the sandbox's claim step (three lines while it is unclaimed).
    expect(noCounts(out.split("\n").at(-4))).toBe("PASS (service keys fetched over plain http, not independent)");

    const pack = path.join(ctx.root, "pack.json");
    [code, out] = await cli("export", "-o", pack);
    expect(code).toBe(0);
    expect(out).toContain(`(2 records); check it with \`signafaide verify ${pack}\``);

    [code, out] = await cli("verify", pack);
    expect(code).toBe(0);
    expect(out).toMatch(/^12\. Content hashes +PASS +2 records/m);
    expect(noCounts(out.split("\n").at(-4))).toMatch(
      /^PASS \(service keys fetched over plain http, not independent\): export of every agent, all records, generated /,
    );
    expect(out).toMatch(/^head: this project's own/m); // the local head.json, with no flag
    [code, out] = await cli("verify", pack, "--json");
    expect(JSON.parse(out).result).toBe("PASS");

    const keys = path.join(ctx.root, "keys.json");
    fs.writeFileSync(keys, JSON.stringify({ keys: [ctx.service.keyDoc] }));
    const data = JSON.parse(fs.readFileSync(pack, "utf8"));
    data.records[0].envelope.name = "other";
    fs.writeFileSync(pack, JSON.stringify(data));
    [code, out] = await cli("verify", pack, "--keys", keys);
    expect(code).toBe(1);
    expect(noCounts(out.split("\n").at(-1))).toMatch(/^FAIL: export of every agent/);
    const [c2, , e2] = await cli("verify", pack, "--keys", "http://192.0.2.1/keys.json");
    expect(c2).toBe(2);
    expect(e2).toContain("plain http");
  });

  it("export takes every agent unless --agent narrows it; an empty pack fails verify", async () => {
    await cli("init");
    note("n", {});
    note("n", {}, { agent: "second-bot" });
    await cli("flush");
    const all = path.join(ctx.root, "all.json");
    let [code, out] = await cli("export", "-o", all);
    expect([code, out]).toEqual([0, `wrote ${all} (2 records); check it with \`signafaide verify ${all}\``]);
    expect(JSON.parse(fs.readFileSync(all, "utf8")).records.map((r: any) => r.envelope.agent)).toContain("second-bot");
    [code, out] = await cli("export", "--agent", "second-bot", "-o", path.join(ctx.root, "one.json"));
    expect(out).toContain("(1 record);");

    const empty = path.join(ctx.root, "empty.json");
    let err;
    [code, out, err] = await cli("export", "--agent", "nobody", "-o", empty);
    expect(code).toBe(0);
    expect(out).toContain("(0 records)");
    expect(err).toContain("agent 'nobody' has no records in this range; leave out --agent to export every agent");
    [code, out] = await cli("verify", empty);
    expect(code).toBe(1);
    expect(out).toContain("pack: no records");
    expect(out.split("\n").at(-1)).toMatch(
      /^FAIL: 1 of 12 checks failed \(envelope schema\).*; export of agent nobody/,
    );
  });

  it("--help on a command prints its usage", async () => {
    const [hcode, help] = await cli("replay", "--help");
    expect(hcode).toBe(0);
    expect(help).toContain("usage: signafaide replay [--agent X]");
  });

  it("warns about embedded keys", async () => {
    await cli("init");
    note("n", {});
    await cli("flush");
    const pack = path.join(ctx.root, "p.json");
    await cli("export", "-o", pack);
    const [code, out] = await cli("verify", pack, "--trust-embedded-keys");
    expect(code).toBe(0);
    expect(out).toContain("WARNING: service keys were taken from the pack itself");
  });

  it("exits 2 when inputs cannot be read", async () => {
    const [code, , err] = await cli("verify", path.join(ctx.root, "missing.json"));
    expect(code).toBe(2);
    expect(err.split("\n")).toHaveLength(1);
    fs.writeFileSync(path.join(ctx.root, "bad.json"), "{not json");
    expect((await cli("verify", path.join(ctx.root, "bad.json"), "--trust-embedded-keys"))[0]).toBe(2);
    const good = path.join(ctx.root, "p.json");
    fs.writeFileSync(
      good,
      JSON.stringify({
        format: "signafaide-pack/1",
        generated: "x",
        project: "p",
        env: "test",
        service_keys: [],
        agent_keys: [],
        records: [],
        anchors: [],
      }),
    );
    process.env.SIGNAFAIDE_URL = await deadUrl();
    const [c2, , e2] = await cli("verify", good);
    expect(c2).toBe(2);
    expect(e2).toContain("pass --keys");
    expect((await cli("verify", "--bogus"))[0]).toBe(2);
  });

  it("flush offline: one line, exit 1", async () => {
    fs.writeFileSync(path.join(ctx.root, ".env"), "SIGNAFAIDE_API_KEY=sfa_test_" + "x".repeat(32) + "\n");
    process.env.SIGNAFAIDE_URL = await deadUrl();
    note("n", {});
    const [code, out, err] = await cli("flush");
    expect(code).toBe(1);
    expect(err.split("\n")).toHaveLength(1);
    expect(err).toContain("Cannot reach the signafAIde service");
    expect(out).toContain("1 left in the outbox");
  });

  it("flush: a chain older than 7 days is kept on this machine only, and said so", async () => {
    const rec = getRecorder();
    const key = rec.key("claims-project");
    const old = new Date(Date.now() - 8 * 86_400_000).toISOString();
    rec.state.append(
      "_pending/nokey/claims-project",
      (seq, prev) =>
        makeDraft(
          key,
          { kind: "note", agent: "claims-project", seq, prev, name: "old", content: {}, time: old },
          false,
        ),
      (r) => r,
    );
    await cli("init");
    const [code, out, err] = await cli("flush");
    expect(code).toBe(1);
    expect(err).toContain("more than 7 days ago");
    expect(out).toBe("shipped 0 records, 0 left in the outbox; 1 record kept on this machine only (see above)");
  });

  it("errors are one line", async () => {
    process.env.SIGNAFAIDE_URL = await deadUrl();
    const [code, , err] = await cli("init");
    expect(code).toBe(1);
    expect(err).toMatch(/^signafaide: Cannot reach[^\n]*$/);
  });

  it("prints help and version", async () => {
    expect((await cli("--version"))[1]).toMatch(/^signafaide \d/);
    expect((await cli("--help"))[1]).toContain("verify");
    expect((await cli("nope"))[0]).toBe(1);
  });
});
