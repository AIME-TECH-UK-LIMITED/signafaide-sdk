import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/jcs.js";
import { makeDraft, makeRecord, manifestErrors, recordHash, wireRecord, type SignedRecord } from "../src/records.js";
import { State, StateError, appendEnvFile, ensureGitignore, findRoot, keyFingerprint, readEnvFile } from "../src/state.js";
import { useProject } from "./helpers.js";

const ctx = useProject();

const BUCKET = "prj_01JC0000000000000000000000/test";
const C = `${BUCKET}/bot`;

function append(st: State, n = 1, agent = "bot", chain = `${BUCKET}/${agent}`): SignedRecord[] {
  const key = st.loadKey(agent);
  return Array.from({ length: n }, () =>
    st.append(chain, (seq, prev) => makeRecord(key, { kind: "note", project: "prj_01JC0000000000000000000000", env: "test", agent, seq, prev, name: "n", content: { i: 1 } }), (r) => wireRecord(r, false))!,
  );
}

describe("local state", () => {
  it("lays out .signafaide and .gitignore", () => {
    const st = State.discover();
    st.ensure();
    expect(st.home).toBe(path.join(ctx.root, ".signafaide"));
    expect(fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8")).toBe(".signafaide/\n");
    fs.mkdirSync(path.join(ctx.root, "sub"));
    expect(findRoot(path.join(ctx.root, "sub"))).toBe(ctx.root);
    st.ensure();
    expect(fs.readFileSync(path.join(ctx.root, ".gitignore"), "utf8").match(/signafaide/g)).toHaveLength(1);
  });

  it("appends to .gitignore without touching other lines", () => {
    const gi = path.join(ctx.root, ".gitignore");
    fs.writeFileSync(gi, "node_modules\n*.log");
    ensureGitignore(gi, ".signafaide/");
    expect(fs.readFileSync(gi, "utf8")).toBe("node_modules\n*.log\n.signafaide/\n");
  });

  it("honours SIGNAFAIDE_HOME", () => {
    process.env.SIGNAFAIDE_HOME = path.join(ctx.root, "..", "elsewhere");
    const st = State.discover();
    st.ensure();
    expect(fs.existsSync(path.join(st.home, "chain"))).toBe(true);
    expect(fs.existsSync(path.join(ctx.root, ".gitignore"))).toBe(false);
  });

  it("keeps keys private and stable", () => {
    const st = State.discover();
    const k = st.loadKey("bot");
    const p = st.keyPath("bot");
    expect(fs.statSync(p).mode & 0o777).toBe(0o600);
    expect(st.loadKey("bot").keyId).toBe(k.keyId);
    expect(JSON.parse(fs.readFileSync(p, "utf8"))).toMatchObject({ agent: "bot", key_id: k.keyId });
    expect(st.keyCreated("bot")).toMatch(/Z$/);
    fs.writeFileSync(p, "garbage");
    expect(() => st.loadKey("bot")).toThrow(StateError);
  });

  it("chains records and fills the outbox", () => {
    const st = State.discover();
    const recs = append(st, 3);
    expect(recs.map((r) => r.envelope.seq)).toEqual([1, 2, 3]);
    expect(recs[1].envelope.prev).toBe(recordHash(recs[0]));
    expect(st.tail(C)).toEqual([3, recordHash(recs[2])]);
    expect(st.readChain(C)).toEqual(recs);
    expect(fs.readFileSync(st.chainPath(C), "utf8").split("\n")[0]).toBe(canonicalize(recs[0]));
    expect(st.outbox(C).map((r) => r.envelope.seq)).toEqual([1, 2, 3]);
    expect(st.outbox(C).every((r) => !("content" in r))).toBe(true);
    expect(st.outboxSize()).toBe(3);
    expect(st.outboxChains()).toEqual([C]);
  });

  it("fills receipts into the tail only", () => {
    const st = State.discover();
    const recs = append(st, 4);
    const h = recs.map(recordHash);
    expect(st.applyReceipts(C, new Map([[h[0], { n: 0 } as any], [h[1], { n: 1 } as any]]))).toBe(2);
    expect(st.applyReceipts(C, new Map([[h[2], { n: 2 } as any]]))).toBe(1);
    expect(st.readChain(C).map((r) => r.receipt ?? null)).toEqual([{ n: 0 }, { n: 1 }, { n: 2 }, null]);
    expect(fs.existsSync(st.chainPath(C) + ".tail")).toBe(false);
  });

  it("finishes an interrupted receipt rewrite", () => {
    const st = State.discover();
    const recs = append(st, 2);
    const p = st.chainPath(C);
    const offset = fs.readFileSync(p, "utf8").indexOf("\n") + 1;
    fs.writeFileSync(p + ".tail", `${offset}\n` + canonicalize({ ...recs[1], receipt: { ok: 1 } }) + "\n");
    fs.truncateSync(p, offset); // the crash happened right after truncation
    append(st, 1);
    const out = st.readChain(C);
    expect(out.map((r) => r.envelope.seq)).toEqual([1, 2, 3]);
    expect(out[1].receipt).toEqual({ ok: 1 });
  });

  it("re-queues a record whose outbox file was lost", () => {
    const st = State.discover();
    const recs = append(st, 2);
    fs.unlinkSync(path.join(st.outboxDir(C), "000000000002.json"));
    expect(st.reconcileOutbox(C, (r) => wireRecord(r, false))).toBe(1);
    expect(st.outbox(C).map(recordHash)).toEqual(recs.map(recordHash));
  });

  it("takes over a stale lock", () => {
    const st = State.discover();
    st.ensure();
    const lock = path.join(st.home, "chain", `${C}.lock`);
    fs.mkdirSync(path.dirname(lock), { recursive: true });
    fs.writeFileSync(lock, "999999");
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(lock, old, old);
    append(st, 1);
    expect(fs.existsSync(lock)).toBe(false);
  });

  it("reports a damaged chain line instead of repairing it", () => {
    const st = State.discover();
    append(st, 1);
    fs.appendFileSync(st.chainPath(C), '{"envelope": tor');
    expect(() => st.tail(C)).toThrow(/damaged line/);
  });

  it("keeps the newest head and flags truncation", () => {
    const st = State.discover();
    st.ensure();
    const h = (seq: number) => ({ head: { project: "prj_01JC0000000000000000000000", env: "test", agent: "bot", seq } as any, head_sig: "x" });
    expect(st.updateHeads([h(3)])).toEqual([]);
    expect(st.updateHeads([h(5)])).toEqual([]);
    expect(st.updateHeads([h(4)])[0]).toMatch(/truncation/);
    expect(st.heads()["prj_01JC0000000000000000000000"].test.bot.head.seq).toBe(5);
    expect(Object.keys(st.chainHeads())).toEqual([C]);
  });

  it("appends to .env without touching other lines", () => {
    const env = path.join(ctx.root, ".env");
    fs.writeFileSync(env, "# c\nOTHER='x y'\nexport A=1");
    appendEnvFile(env, "SIGNAFAIDE_API_KEY", "sfa_test_k");
    expect(fs.readFileSync(env, "utf8")).toBe("# c\nOTHER='x y'\nexport A=1\nSIGNAFAIDE_API_KEY=sfa_test_k\n");
    expect(readEnvFile(env)).toEqual({ OTHER: "x y", A: "1", SIGNAFAIDE_API_KEY: "sfa_test_k" });
  });

  it("names buckets after the API key's project", () => {
    const st = State.discover();
    expect(st.bucket(undefined)).toBe("_pending/nokey");
    const key = "sfa_live_" + "a".repeat(32);
    expect(st.bucket(key)).toBe(`_pending/${keyFingerprint(key)}`);
    st.learnProject(key, "prj_01JD0000000000000000000000", "live");
    expect(st.bucket(key)).toBe("prj_01JD0000000000000000000000/live");
    expect(fs.readFileSync(path.join(st.home, "config.json"), "utf8")).not.toContain(key);
  });

  it("signs pending drafts into the project chain, never merging", () => {
    const st = State.discover();
    const key = st.loadKey("bot");
    const draft = (kind: "note" | "outcome", ref: string | null = null) => (seq: number, prev: string | null) =>
      makeDraft(key, { kind, agent: "bot", seq, prev, name: "n", content: {}, ref }, false);
    const d1 = st.append("_pending/nokey/bot", draft("note"), (r) => wireRecord(r, false))!;
    st.append("_pending/nokey/bot", draft("outcome", recordHash(d1)), (r) => wireRecord(r, false));
    expect(st.outboxSize()).toBe(0);
    expect(st.readChain("_pending/nokey/bot")).toEqual([]);
    expect(st.draftCount("_pending/nokey/bot")).toBe(2);
    expect(st.adopt("_pending/nokey", BUCKET, () => key, (r) => wireRecord(r, false))).toEqual([]);
    expect(st.chains()).toEqual([C]);
    expect(st.outboxChains()).toEqual([C]);
    const signed = st.readChain(C);
    expect(signed.map((r) => `${r.envelope.project}/${r.envelope.env}`)).toEqual([BUCKET, BUCKET]);
    expect(signed[1].envelope.ref).toBe(recordHash(signed[0]));
    expect(st.translateRef(C, recordHash(d1))).toBe(recordHash(signed[0]));
    st.append("_pending/nokey/bot", draft("note"), (r) => wireRecord(r, false));
    expect(st.adopt("_pending/nokey", BUCKET, () => key, (r) => wireRecord(r, false))).toEqual([["_pending/nokey/bot", "exists"]]);
  });

  it("keeps a pending chain local when it starts before notBefore (the service's 7-day limit)", () => {
    const st = State.discover();
    const key = st.loadKey("old");
    const at = (time: string) => (seq: number, prev: string | null) => makeDraft(key, { kind: "note", agent: "old", seq, prev, name: "n", content: {}, time }, false);
    st.append("_pending/nokey/old", at("2026-01-01T00:00:00.000Z"), (r) => wireRecord(r, false));
    st.append("_pending/nokey/old", at("2026-01-02T00:00:00.000Z"), (r) => wireRecord(r, false));
    const notBefore = "2026-01-01T12:00:00.000Z";
    expect(st.adopt("_pending/nokey", BUCKET, () => key, (r) => wireRecord(r, false), notBefore)).toEqual([["_pending/nokey/old", "2026-01-01T00:00:00.000Z"]]);
    expect(st.chains()).toEqual(["_pending/nokey/old"]);
    expect(st.outboxSize()).toBe(0);
    // within the limit it is adopted with its original times
    expect(st.adopt("_pending/nokey", BUCKET, () => key, (r) => wireRecord(r, false), "2025-12-31T00:00:00.000Z")).toEqual([]);
    expect(st.readChain(`${BUCKET}/old`).map((r) => r.envelope.time)).toEqual(["2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z"]);
  });

  it("writes .env privately, one line per value, and refuses service paths", () => {
    const env = path.join(ctx.root, ".env");
    appendEnvFile(env, "SIGNAFAIDE_API_KEY", "sfa_test_" + "a".repeat(32));
    expect(fs.statSync(env).mode & 0o777).toBe(0o600);
    expect(() => appendEnvFile(env, "SIGNAFAIDE_API_KEY", "sfa_test_x\nNODE_OPTIONS=--require ./pwn.js")).toThrow(StateError);
    const st = State.discover();
    expect(() => st.learnProject("sfa_test_" + "a".repeat(32), "../../../escaped", "test")).toThrow(StateError);
    expect(() => st.learnProject("sfa_test_" + "a".repeat(32), "prj_01JD0000000000000000000000", "../x")).toThrow(StateError);
  });

  it("rotates keys and exports a self-signed manifest", () => {
    const st = State.discover();
    const old = st.loadKey("bot");
    const [o, next] = st.rotateKey("bot");
    expect(o.keyId).toBe(old.keyId);
    expect(next.keyId).not.toBe(old.keyId);
    let doc = st.exportAgentKeys();
    expect(doc.keys.map((k) => k.key_id).sort()).toEqual([old.keyId, next.keyId].sort());
    expect(doc.keys.every((k) => k.valid_to === null)).toBe(true); // not retired on the service yet
    expect(manifestErrors(doc)).toEqual([]);
    // Once the service says when it retired the old key, the manifest carries it, self-signed.
    expect(st.markRetired("bot", old.keyId, "2026-11-13T10:00:00.000Z")).toBe(true);
    doc = st.exportAgentKeys();
    expect(Object.fromEntries(doc.keys.map((k) => [k.key_id, k.valid_to]))).toEqual({ [old.keyId]: "2026-11-13T10:00:00.000Z", [next.keyId]: null });
    expect(manifestErrors(doc)).toEqual([]);
  });
});
