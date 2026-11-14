import * as fs from "node:fs";
import * as path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { SigningKey, auditPath, b64url, hashJson, merkleRoot } from "../src/crypto.js";
import { flush, loadContent, note, record, verify } from "../src/index.js";
import { getRecorder } from "../src/runtime.js";
import { MAGIC, TAG_BITCOIN, TAG_PENDING } from "../src/ots.js";
import { KeysRequired, serviceKeysHash, verifyPack as verifyPackRaw, type PackOptions, type Report } from "../src/verifier.js";
import { makeRecord, now } from "../src/records.js";

/** The pack verifier with this project's own agent keys as the independent set. */
const verifyPack = (p: any, k: any[] | null, o: PackOptions = {}): Report => verifyPackRaw(p, k, { agentKeys: getRecorder().state.exportAgentKeys().keys, ...o });
import { chainFile, deadUrl, useProject } from "./helpers.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { target } from "../src/timestamps.js";

/** The result line without its check counts (§7), to compare the rest. */
const noCounts = (line: string | undefined): string => (line ?? "").replace(/: \d+ of 12 checks [^;]*; /, ": ").replace(/: \d+ of 12 checks [^;]*$/, "");


const SCOPE = ": export of agent claims-project, all records, generated ";
/** What only the service can do: sign a changed pack's export statement again (§7). */
const resign = (p: any) => ctx.service.signExport(p);

/** A block header (regtest-easy proof of work) whose Merkle root is `root`, as an explorer serves it. */
function header(root: string): { hash: string; header: string } {
  const t = target(0x207fffff)!;
  for (let nonce = 0; ; nonce++) {
    const h = new Uint8Array(80);
    const dv = new DataView(h.buffer);
    dv.setUint32(0, 0x20000000, true);
    h.fill(1, 4, 36);
    h.set(hexToBytes(root), 36);
    dv.setUint32(68, 1763028000, true);
    dv.setUint32(72, 0x207fffff, true);
    dv.setUint32(76, nonce, true);
    const id = bytesToHex(sha256(sha256(h)).reverse());
    if (BigInt("0x" + id) <= t) return { hash: id, header: bytesToHex(h) };
  }
}

const ctx = useProject({ optIn: true });
const failed = (r: Report) => r.checks.filter((c) => c.status === "fail").map((c) => c.id);
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
let pack: any;
let keys: any[];

async function makePack(): Promise<any> {
  const approve = record((_claimId: string, amount: number) => amount < 100, { name: "approve_payout" });
  approve("c1", 10);
  await flush();
  approve("c2", 500);
  note("shift_end", { n: 2 });
  await flush();
  return getRecorder().client().export("claims-project");
}

describe("pack verifier", () => {
  beforeEach(async () => {
    pack = await makePack();
    keys = [ctx.service.keyDoc];
    expect(pack.records).toHaveLength(5);
  });

  it("passes a clean pack", () => {
    const r = verifyPack(pack, keys);
    expect(r.ok).toBe(true);
    const s = Object.fromEntries(r.checks.map((c) => [c.id, c.status]));
    for (const id of ["schema", "record_hash", "record_sig", "chain", "merkle", "batch_sig", "batch_chain", "head_sig"]) expect(s[id]).toBe("pass");
    for (const id of ["drand", "content"]) expect(s[id]).toBe("not_checked");
    // A fresh pack: its batches wait for the hourly anchor, so anchors and the public timestamp
    // are pending, never counted as passed.
    for (const id of ["anchor", "ots"]) expect(s[id]).toBe("pending");
    expect(r.resultLine).toMatch(/: 8 of 12 checks passed, 2 pending \(anchors, public timestamp\), 2 not checked \(drand rounds, content hashes\);/);
    const lines = String(r).split("\n");
    expect(lines[0]).toMatch(/^signafAIde pack prj_\w+ \(test\), 5 records$/);
    expect(lines[1]).toMatch(/^ 1\. Envelope schema +PASS +5 records$/);
    expect(lines).toHaveLength(16);
    expect(lines.at(-3)).toBe("pending: co-signed, waiting for the public timestamp (an anchor is made every hour and usually confirms within a few hours); never counted as passed");
    // Tool coverage (§7), a note before the result line: this agent declared no tool list.
    expect(lines.at(-2)).toBe("coverage: claims-project: no tool list was declared, so the pack cannot show which of the agent's tools are recorded");
    expect(r.coverage).toEqual({ "claims-project": { declared: [], undeclared_recorded: [], declared_at_seq: null } });
    expect(noCounts(lines.at(-1))).toBe(`PASS${SCOPE}${pack.generated}`);
  });

  it("checks content from the local chain", () => {
    const r = verifyPack(pack, keys, { contents: loadContent(path.join(getRecorder().state.home, "chain")) });
    expect(r.check("content")).toMatchObject({ status: "pass", checked: 5 });
  });

  it("catches an edited envelope", () => {
    pack.records[1].envelope.name = "deny_payout";
    const r = verifyPack(pack, keys);
    expect(r.firstFailed()).toBe("record_hash");
    expect(failed(r)).toEqual(expect.arrayContaining(["record_hash", "record_sig", "chain", "merkle"]));
    expect(noCounts(String(r).split("\n").at(-1))).toBe(`FAIL${SCOPE}${pack.generated}`);
  });

  it("catches edited content", () => {
    pack.records[0].content = { input: ["c1", 99999] };
    expect(failed(verifyPack(pack, keys))).toEqual(["content"]);
  });

  it("catches a swapped signature", () => {
    pack.records[2].sig = pack.records[3].sig;
    expect(failed(verifyPack(pack, keys))).toEqual(["record_sig"]);
  });

  it("fails dropped records unless the export filter explains them", () => {
    // Anyone who passes the pack on: the export statement no longer verifies.
    const middle = clone(pack);
    middle.records.splice(2, 1);
    expect(failed(verifyPack(middle, keys))).toEqual(["chain", "head_sig"]);
    const held = clone(pack);
    held.records.pop();
    held.filter.to = "2099-01-01T00:00:00.000Z";
    expect(failed(verifyPack(held, keys))).toEqual(["head_sig"]);
    // What the service signs must hold together too.
    const start = clone(pack);
    start.records.splice(0, 2); // the first batch: what follows was written after a flush, well after the key
    expect(failed(verifyPack(resign(start), keys))).toEqual(["chain"]);
    start.filter.from = start.records[0].envelope.time;
    expect(verifyPack(resign(start), keys).ok).toBe(true);
    const end = clone(pack);
    end.records.pop();
    const r = verifyPack(resign(end), keys);
    expect(failed(r)).toEqual(["head_sig"]);
    expect(String(r)).toContain("records missing at the end");
    end.filter.to = new Date(Date.parse(end.records.at(-1).envelope.time) + 1).toISOString(); // every kept record is before it
    expect(verifyPack(resign(end), keys).ok).toBe(true);
    end.filter.to = null;
    end.heads = [{ head: end.records.at(-1).receipt.head, head_sig: end.records.at(-1).receipt.head_sig }];
    const head = Object.values(getRecorder().state.chainHeads()) as any[];
    expect(failed(verifyPack(resign(end), keys, { heads: head }))).toEqual(["head_sig"]);
  });

  it("needs independent agent keys, or says they came from the pack", () => {
    const r = verifyPackRaw(pack, keys);
    expect(failed(r)).toEqual(["record_sig"]);
    expect(String(r)).toContain("NOT INDEPENDENT");
    const t = verifyPackRaw(pack, keys, { trustEmbeddedAgentKeys: true });
    expect(t.ok).toBe(true);
    expect(noCounts(String(t).split("\n").at(-1))).toBe(`PASS (agent keys taken from the pack, not independent)${SCOPE}${pack.generated}`);
  });

  it("fails a fork", () => {
    const twin = clone(pack.records[2]);
    twin.envelope.name = "other";
    twin.sig = getRecorder().key("claims-project").sign("record", hashJson(twin.envelope));
    twin.receipt.record_hash = hashJson(twin.envelope);
    pack.records.push(twin);
    const r = verifyPack(resign(pack), keys);
    expect(failed(r)).toContain("chain");
    expect(String(r)).toContain("fork");
  });

  it("fails with the wrong service key", () => {
    const other = SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n)));
    const fake = [{ key_id: pack.records[0].receipt.service_key_id, public_key: b64url(other.publicKey), valid_from: null, valid_to: null }];
    expect(failed(verifyPack(pack, fake))).toEqual(["batch_sig", "head_sig"]);
  });

  it("catches an edited batch and a forked batch chain", () => {
    const edited = clone(pack);
    for (const rec of edited.records) if (rec.receipt.batch.seq === 1) rec.receipt.batch.server_time = "2020-01-01T00:00:00.000Z";
    expect(failed(verifyPack(edited, keys))).toEqual(["chain", "batch_sig", "batch_chain"]);
    const rc = pack.records.at(-1).receipt;
    rc.batch = { ...rc.batch, prev: "11".repeat(32) };
    rc.batch_hash = hashJson(rc.batch);
    rc.batch_sig = ctx.service.key.sign("batch", rc.batch_hash);
    expect(failed(verifyPack(pack, keys))).toEqual(["batch_chain"]);
  });

  it("catches a bad proof", () => {
    pack.records[0].receipt.proof = ["00".repeat(32)];
    expect(failed(verifyPack(pack, keys))).toEqual(["merkle"]);
  });

  it("needs independent keys, or warns about embedded ones", () => {
    expect(() => verifyPack(pack, null)).toThrow(KeysRequired);
    const r = verifyPack(pack, null, { trustEmbeddedKeys: true });
    expect(r.ok).toBe(true);
    expect(String(r)).toContain("WARNING: service keys were taken from the pack itself");
  });

  it("honours key validity windows", () => {
    expect(failed(verifyPack(pack, [{ ...ctx.service.keyDoc, valid_to: "2021-01-01T00:00:00.000Z" }]))).toEqual(["batch_sig", "head_sig"]);
  });

  it("fails schema for a non-pack, a missing receipt or another project", () => {
    expect(verifyPack({ format: "x" }, []).firstFailed()).toBe("schema");
    const a = clone(pack);
    delete a.records[4].receipt;
    expect(failed(verifyPack(a, keys))).toEqual(["schema", "head_sig"]);
    pack.project = "prj_01JD0000000000000000000000";
    expect(verifyPack(pack, keys).firstFailed()).toBe("schema");
  });

  const ots = (digest: string, height?: number): string => {
    const vb = (b: Uint8Array) => Uint8Array.from([b.length, ...b]);
    const hex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
    let att: Uint8Array;
    if (height === undefined) att = Uint8Array.from([...hex(TAG_PENDING), ...vb(vb(new TextEncoder().encode("https://calendar.example")))]);
    else {
      const v: number[] = [];
      for (let x = height; ; x = Math.floor(x / 128)) {
        v.push((x & 0x7f) | (x > 0x7f ? 0x80 : 0));
        if (x <= 0x7f) break;
      }
      att = Uint8Array.from([...hex(TAG_BITCOIN), ...vb(Uint8Array.from(v))]);
    }
    return Buffer.from([...MAGIC, 1, 8, ...hex(digest), 0, ...att]).toString("base64");
  };

  const anchor = (height?: number, otsDigest?: string) => {
    const seqs = new Map<string, number>(pack.records.map((r: any) => [r.receipt.batch_hash, r.receipt.batch.seq]));
    const bhs = [...seqs.keys()].sort((a, b) => seqs.get(a)! - seqs.get(b)!);
    const leaves = [...bhs, hashJson("other project batch")];
    const created = now();
    const a = { v: 1, seq: 1, prev: null, root: merkleRoot(leaves), size: leaves.length, created, keys_hash: serviceKeysHash(keys, Date.parse(created)) };
    // The public timestamp covers the anchor hash (§4).
    return {
      anchor: { ...a, ots: ots(otsDigest ?? hashJson(a), height), status: height === undefined ? "pending" : "confirmed", bitcoin_block: height ?? null },
      anchor_sig: ctx.service.key.sign("anchor", hashJson(a)),
      paths: Object.fromEntries(bhs.map((h, i) => [h, { index: i, path: auditPath(leaves, i) }])),
    };
  };

  it("checks anchors and OTS proofs", () => {
    pack.anchors = [anchor()];
    let r = verifyPack(pack, keys);
    expect(r.ok).toBe(true);
    expect(r.check("anchor")).toMatchObject({ status: "pass", checked: 1 });
    expect(r.check("ots").value).toBe("pending");
    expect(String(r)).toContain("PENDING");
    pack.anchors = [anchor(900000)];
    r = verifyPack(pack, keys);
    expect(r.check("ots").status).toBe("not_checked");
    expect(r.check("ots").detail).toContain("claims block 900000");
    const { ots: _o, status: _s, bitcoin_block: _b, ...core } = pack.anchors[0].anchor;
    const digest = hashJson(core);
    r = verifyPack(pack, keys, { timestamps: new Map([[900000, [true, header(digest)]]]) });
    expect(r.check("ots").value).toBe("confirmed@900000");
    expect(String(r)).toContain("CONFIRMED");
    expect(String(r)).not.toContain("Bitcoin");
    expect(failed(verifyPack(pack, keys, { timestamps: new Map([[900000, [true, header("00".repeat(32))]]]) }))).toEqual(["ots"]);
    // A header that does not hash to its block, or an explorer that could not be asked: not checked.
    expect(verifyPack(pack, keys, { timestamps: new Map([[900000, [true, { ...header(digest), hash: "00".repeat(32) }]]]) }).check("ots").status).toBe("not_checked");
    expect(verifyPack(pack, keys, { timestamps: new Map([[900000, [false, "plain http"]]]) }).check("ots").status).toBe("not_checked");
  });

  it("catches anchor and OTS tampering", () => {
    const a = anchor();
    const [first, second] = Object.keys(a.paths);
    a.paths[first].path = a.paths[second].path;
    pack.anchors = [a];
    expect(failed(verifyPack(pack, keys))).toEqual(["anchor"]);
    pack.anchors = [anchor()];
    pack.anchors[0].anchor.root = "00".repeat(32);
    expect(failed(verifyPack(pack, keys))).toEqual(["anchor", "ots"]);
    pack.anchors = [anchor(undefined, "ab".repeat(32))];
    expect(failed(verifyPack(pack, keys))).toEqual(["ots"]);
  });

  it("serialises to the reference JSON shape", () => {
    const d = JSON.parse(JSON.stringify(verifyPack(pack, keys)));
    expect(d.result).toBe("PASS");
    expect(d.checks.map((c: any) => c.id).slice(0, 3)).toEqual(["schema", "record_hash", "record_sig"]);
  });
});

describe("local verifier", () => {
  it("passes with unshipped records", async () => {
    note("a", {});
    await flush();
    note("b", {});
    const r = await verify();
    expect(r.ok).toBe(true);
    expect(r.check("record_hash").detail).toContain("1 not yet shipped");
    expect(r.check("content").status).toBe("pass");
    expect(r.notes.some((n) => n.startsWith("service keys:"))).toBe(true);
  });

  it("catches truncation, gaps and edits", async () => {
    for (const i of [0, 1, 2]) note(`n${i}`, { amount: i });
    await flush();
    const p = chainFile();
    const lines = fs.readFileSync(p, "utf8").split("\n").filter(Boolean);
    fs.writeFileSync(p, lines.slice(0, 2).join("\n") + "\n");
    let r = await verify();
    expect(failed(r)).toEqual(["head_sig"]);
    expect(String(r)).toContain("truncated");
    fs.writeFileSync(p, [lines[0], lines[2]].join("\n") + "\n");
    r = await verify();
    expect(failed(r)).toContain("chain");
    expect(String(r)).toContain("missing seq 2..2");
    fs.writeFileSync(p, lines.join("\n").replace('"amount":1', '"amount":5') + "\n");
    expect(failed(await verify())).toEqual(["content"]);
  });

  it("needs service keys only once something was shipped", async () => {
    note("a", {});
    const rec = getRecorder();
    rec._url = await deadUrl();
    expect((await verify()).ok).toBe(true);
    rec._url = ctx.service.url;
    await flush();
    rec._url = await deadUrl();
    await expect(verify()).rejects.toThrow(/could not load service keys/);
  });
});

describe("drand", () => {
  it("verify() checks the BLS signature by default (@noble/curves is a dependency)", async () => {
    const v = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../spec/vectors.json"), "utf8"));
    const r = await verify(v.pack.pack, { keys: v.keys_document });
    expect(r.check("drand")).toMatchObject({ status: "pass", checked: 1 });
    expect(r.notes.join("\n")).not.toContain("drand: not checked");
  });
});

describe("key rotation", () => {
  it("registers a key rotated while this process holds the SDK (keys rotate), and verify passes", async () => {
    note("a", {});
    expect((await flush()).shipped).toBe(1); // the first key is registered in this process
    const rec = getRecorder();
    const agent = rec.defaultAgent;
    // What `signafaide keys rotate` does (from this process or another one): a new key file.
    const [old, next] = rec.state.rotateKey(agent);
    note("b", {}); // signed by the new key
    const r = await flush();
    expect(r.errors).toEqual({});
    expect(r.shipped).toBe(1);
    const prj = [...ctx.service.projects.values()][0];
    expect(prj.agents.get(agent).get(next.keyId).valid_to).toBeNull();
    expect(prj.agents.get(agent).get(old.keyId).valid_to).toBe(rec.state.retiredAt(agent, old.keyId));
    const v = await verify();
    expect(v.ok, String(v)).toBe(true);
    expect(v.check("record_sig").status).toBe("pass");
  });

  it("retires the old key: its earlier records ship first, then it cannot add records", async () => {
    note("a", {});
    await flush();
    note("b", {}); // signed by the first key, still in the outbox
    const rec = getRecorder();
    const agent = rec.defaultAgent;
    const [old, next] = rec.state.rotateKey(agent);
    note("c", {}); // signed by the new key
    expect((await flush()).shipped).toBe(2);
    const retired = rec.state.retiredAt(agent, old.keyId);
    expect(retired).not.toBeNull();
    const prj = [...ctx.service.projects.values()][0];
    expect(prj.agents.get(agent).get(old.keyId).valid_to).toBe(retired);
    const tip = prj.heads.get(agent).head;
    const forged = makeRecord(old, { kind: "note", project: prj.project, env: prj.env, agent, seq: tip.seq + 1, prev: tip.record_hash, name: "late", content: {} });
    const [status, body] = ctx.service.submit(prj, [{ envelope: forged.envelope, key_id: forged.key_id, sig: forged.sig }]) as [number, any];
    expect([status, body.error.code]).toEqual([400, "bad_signature"]);
    const manifest = rec.state.exportAgentKeys();
    expect(Object.fromEntries(manifest.keys.map((k) => [k.key_id, k.valid_to]))).toEqual({ [old.keyId]: retired, [next.keyId]: null });
    const pack = await rec.client().export(agent);
    const r = verifyPackRaw(pack, [ctx.service.keyDoc], { agentKeys: manifest.keys });
    expect(r.ok, String(r)).toBe(true);
  });
});
