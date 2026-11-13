/**
 * An in-process fake of the signafAIde service (SPEC §3, §5, §6) for tests. It really
 * validates and signs: schema, agent key, signature, chain and content are checked,
 * records are batched into an RFC 6962 tree and covered by service signatures.
 */

import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { SigningKey, auditPath, b64url, b64urlDecode, hashJson, keyId, merkleRoot, verifySig } from "../src/crypto.js";
import { now, recordErrors, recordHash, registration } from "../src/records.js";
import { exportStatement } from "../src/verifier.js";

type Reply = [number, unknown];
const err = (status: number, code: string, message: string, extra: object = {}): Reply => [
  status,
  { error: { code, message, docs: `https://docs.example/errors#${code}`, ...extra } },
];

export class FakeService {
  key = SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n)));
  keyDoc = { key_id: this.key.keyId, public_key: b64url(this.key.publicKey), valid_from: "2020-01-01T00:00:00.000Z", valid_to: null };
  projects = new Map<string, any>();
  calls: string[] = [];
  registrations: any[] = [];
  clientIds: (string | undefined)[] = []; // X-Signafaide-Client of every request
  events: string[] = [];
  experiments: any[] = [];
  fail: Reply | null = null;
  url = "";
  private server = http.createServer((req, res) => void this.handle(req, res));
  private n = 0;

  async start(): Promise<this> {
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this;
  }

  close(): Promise<void> {
    this.server.closeAllConnections?.();
    return new Promise((r) => this.server.close(() => r()));
  }

  addProject(apiKey: string, env: "test" | "live"): any {
    const prj = { project: `prj_01JC${String(this.projects.size + 1).padStart(22, "0")}`, env, agents: new Map(), heads: new Map(), records: new Map(), batches: [] as any[], used: 0 };
    this.projects.set(apiKey, prj);
    return prj;
  }

  project(): any {
    return [...this.projects.values()][0];
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const u = new URL(req.url!, "http://x");
    this.clientIds.push(req.headers["x-signafaide-client"] as string | undefined);
    const [status, body] = this.route(req.method!, u.pathname, Object.fromEntries(u.searchParams), raw ? JSON.parse(raw) : null, req.headers.authorization);
    const text = typeof body === "string" ? body : JSON.stringify(body);
    res.writeHead(status, { "content-type": typeof body === "string" ? "text/plain" : "application/json" });
    res.end(text);
  }

  private route(method: string, path: string, q: Record<string, string>, body: any, auth?: string): Reply {
    this.calls.push(`${method} ${path}`);
    if (method === "GET" && path === "/.well-known/signafaide-keys.json") return [200, { keys: [this.keyDoc] }];
    if (method === "POST" && path === "/v1/sandbox") {
      const key = "sfa_test_" + String(++this.n).padStart(32, "0");
      const prj = this.addProject(key, "test");
      return [200, { project: prj.project, api_key: key, claim_url: `${this.url}/app/claim/${this.n}`, free_quota: 1000 }];
    }
    if (method === "POST" && path === "/v1/events") {
      this.events.push(body.name);
      return [200, {}];
    }
    const prj = this.projects.get((auth ?? "").replace(/^Bearer /, ""));
    if (!prj) return err(401, "invalid_key", "The API key is not valid; run `signafaide init` for a new sandbox key.");
    if (method === "GET" && path === "/v1/project") return [200, { project: prj.project, env: prj.env }];
    if (method === "POST" && path === "/v1/agents") {
      const kid = keyId(b64urlDecode(body.public_key));
      for (const [name, keys] of prj.agents) if (name !== body.name && keys.has(kid)) return err(400, "invalid_record", "This key is registered to another agent.");
      const h = hashJson(registration(prj.project, prj.env, body.name, body.public_key, body.valid_from ?? ""));
      if (!verifySig(body.public_key, "register", h, body.proof ?? "")) return err(400, "bad_signature", "proof must be the new key's signature over the registration (domain register).");
      const keys = prj.agents.get(body.name) ?? new Map();
      const active = [...keys.values()].filter((k: any) => k.valid_to === null && k.key_id !== kid);
      if (active.length && !keys.has(kid)) {
        const by = active.find((k: any) => k.key_id === body.rotation?.key_id);
        if (!by || !verifySig(by.public_key, "rotate", h, body.rotation.sig)) return err(400, "bad_signature", "This agent already has an active key: sign the registration with it (rotation), or revoke it in the console first.");
        // A rotation retires the key that signed it (§2.4), after its newest record.
        const newest = [...prj.records.values()].filter(([r]: any) => r.key_id === by.key_id).map(([r]: any) => Date.parse(r.envelope.time));
        by.valid_to = new Date(Math.max(Date.now(), ...newest.map((t: number) => t + 1))).toISOString();
      }
      prj.agents.set(body.name, keys);
      this.registrations.push(body);
      if (!keys.has(kid)) keys.set(kid, { agent: body.name, key_id: kid, public_key: body.public_key, valid_from: body.valid_from, valid_to: null });
      const retired = [...keys.values()].filter((k: any) => k.valid_to !== null).map((k: any) => ({ key_id: k.key_id, valid_to: k.valid_to }));
      return [200, { agent: body.name, key_id: kid, retired }];
    }
    if (method === "POST" && path === "/v1/records") {
      if (this.fail) {
        const f = this.fail;
        this.fail = null;
        return f;
      }
      return this.submit(prj, body.records ?? []);
    }
    if (method === "GET" && path === "/v1/usage") return [200, { period: "2026-11", used: prj.used, quota: 1000 }];
    if (method === "GET" && path === "/v1/export") return [200, this.export(prj, q.agent, q.from, q.to)];
    if (method === "POST" && path === "/v1/experiments") {
      this.experiments.push(body);
      return [201, { id: `exp_${this.experiments.length}`, n: body.rows.length, url: `${this.url}/app/experiments/${this.experiments.length}` }];
    }
    return err(404, "not_found", "No such endpoint.");
  }

  submit(prj: any, records: any[]): Reply {
    const tips = new Map<string, [number, string | null]>([...prj.heads].map(([a, sh]: [string, any]) => [a, [sh.head.seq, sh.head.record_hash]]));
    const fresh: any[] = [];
    for (const r of records) {
      const errs = recordErrors(r);
      if (errs.length) return err(400, "invalid_record", `Record schema is invalid: ${errs.join("; ")}.`);
      const h = recordHash(r);
      if (prj.records.has(h)) continue;
      const env = r.envelope;
      if (env.project !== prj.project || env.env !== prj.env) return err(400, "invalid_record", "envelope.project and envelope.env must be this key's project and env.");
      const key = prj.agents.get(env.agent)?.get(r.key_id);
      if (!key) return err(400, "unknown_agent", `Agent ${env.agent} has no key ${r.key_id}; register it with POST /v1/agents.`);
      if (key.valid_to !== null) return err(400, "bad_signature", `key ${r.key_id} was retired or revoked at ${key.valid_to}; it cannot add records.`);
      if (!verifySig(key.public_key, "record", h, r.sig)) return err(400, "bad_signature", "The record signature does not verify.");
      if (r.content && hashJson(r.content) !== env.content_hash) return err(400, "content_mismatch", "content does not match content_hash.");
      const [seq, last] = tips.get(env.agent) ?? [0, null];
      if (env.seq !== seq + 1 || env.prev !== last) return err(409, "chain_conflict", "This record does not extend the service chain; the head is attached.", { head: { agent: env.agent, seq, record_hash: last } });
      tips.set(env.agent, [env.seq, h]);
      fresh.push(r);
    }
    const heads: any[] = [];
    if (fresh.length) {
      const hashes = fresh.map(recordHash);
      const batch = {
        v: 1,
        project: prj.project,
        env: prj.env,
        seq: prj.batches.length + 1,
        prev: prj.batches.at(-1)?.batch_hash ?? null,
        root: merkleRoot(hashes),
        size: hashes.length,
        server_time: now(),
        drand: null,
      };
      const bh = hashJson(batch);
      prj.batches.push({ batch, batch_hash: bh });
      const bsig = this.key.sign("batch", bh);
      for (const agent of [...new Set(fresh.map((r) => r.envelope.agent))].sort()) {
        const [seq, last] = tips.get(agent)!;
        const head = { project: prj.project, env: prj.env, agent, seq, record_hash: last, server_time: batch.server_time };
        const sh = { head, head_sig: this.key.sign("head", hashJson(head)) };
        prj.heads.set(agent, sh);
        heads.push(sh);
      }
      fresh.forEach((r, i) => {
        const sh = prj.heads.get(r.envelope.agent);
        const rc = { record_hash: hashes[i], index: i, proof: auditPath(hashes, i), batch, batch_hash: bh, batch_sig: bsig, service_key_id: this.key.keyId, head: sh.head, head_sig: sh.head_sig };
        prj.records.set(hashes[i], [r, rc]);
        prj.used++;
      });
    }
    return [200, { receipts: records.map((r) => prj.records.get(recordHash(r))[1]), heads }];
  }

  /** Every agent of the project unless `agent` narrows it, as the service does. */
  private export(prj: any, agent?: string, from?: string, to?: string): object {
    const recs = [...prj.records.values()]
      .filter(([r]: any) => (!agent || r.envelope.agent === agent) && (!from || r.envelope.time >= from) && (!to || r.envelope.time < to))
      .map(([r, rc]: any) => ({ ...r, receipt: rc }))
      .sort((a: any, b: any) => a.envelope.agent.localeCompare(b.envelope.agent) || a.envelope.seq - b.envelope.seq);
    // Heads of the agents with records in the pack only (§7).
    const agents = new Set<string>(recs.map((r: any) => r.envelope.agent));
    return this.signExport({
      format: "signafaide-pack/1",
      generated: now(),
      project: prj.project,
      env: prj.env,
      service_keys: [this.keyDoc],
      agent_keys: [...agents].flatMap((a) => [...(prj.agents.get(a)?.values() ?? [])]),
      filter: { agents: agent ? [agent] : null, from: from ?? null, to: to ?? null },
      heads: [...agents].filter((a) => prj.heads.has(a)).map((a) => prj.heads.get(a)),
      records: recs,
      anchors: [],
      export_sig: "",
    });
  }

  /** The export statement (§7): re-sign after the service itself changes a pack. */
  signExport(pack: any): any {
    pack.export_sig = "";
    pack.export_sig = this.key.sign("export", hashJson(exportStatement(pack)));
    return pack;
  }
}
