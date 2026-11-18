/**
 * An in-process fake of the signafAIde service (SPEC §3, §5, §6) for tests. It really
 * validates and signs: schema, agent key, signature, chain and content are checked,
 * records are batched into an RFC 6962 tree and covered by service signatures.
 */

import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { SigningKey, auditPath, b64url, b64urlDecode, contentHash, hashJson, keyId, merkleRoot, verifySig } from "../src/crypto.js";
import { now, recordErrors, recordHash, registration } from "../src/records.js";
import { exportStatement } from "../src/verifier.js";
import * as C from "../src/checks.js";

type Reply = [number, unknown];
const err = (status: number, code: string, message: string, extra: object = {}): Reply => [
  status,
  { error: { code, message, docs: `https://docs.example/errors#${code}`, ...extra } },
];

export class FakeService {
  key = SigningKey.generate((n) => crypto.getRandomValues(new Uint8Array(n)));
  keyDoc: { key_id: string; public_key: string; valid_from: string; valid_to: string | null } = { key_id: this.key.keyId, public_key: b64url(this.key.publicKey), valid_from: "2020-01-01T00:00:00.000Z", valid_to: null };
  /** More keys served after `keyDoc` (a rotation in progress). */
  extraKeys: { key_id: string; public_key: string; valid_from: string; valid_to: string | null }[] = [];
  projects = new Map<string, any>();
  calls: string[] = [];
  registrations: any[] = [];
  clientIds: (string | undefined)[] = []; // X-Signafaide-Client of every request
  events: string[] = [];
  experiments: any[] = [];
  fail: Reply | null = null;
  /** Answer every POST /v1/records with this until cleared (a refusal that persists). */
  failAlways: Reply | null = null;
  /** Answer `unknown_agent` (400) for heads of agents never registered, as witnesses did before round 4. */
  headsUnknownAgent = false;
  /** Monthly allowance per project; null: unlimited. */
  quota: number | null = null;
  /** Days an unclaimed sandbox is kept; null: a witness that sends no `expires_at` (an older one). */
  sandboxDays: number | null = 30;
  /** Wait this long before answering (a slow network). */
  delayMs = 0;
  /** Tool-call checks (§3.5, §10, §11): the signed rule set versions per project, the shared
   * list's signed updates, and how the witness answers a strict decision. */
  ruleItems = new Map<string, any[]>();
  listUpdates: any[] = [];
  listEntries: any[] = [];
  /** (version query, If-None-Match) of every GET /v1/rules. */
  rulesFetches: [string | undefined, string | undefined][] = [];
  /** A witness that does not rule: receipts without a ruling. */
  noRuling = false;
  /** e.g. "rules_unavailable": the receipt says why there is no ruling. */
  rulingError: string | null = null;
  /** record_hash -> [disclosed, disclosed_salt] the witness received. */
  disclosed = new Map<string, [any, string]>();
  /** Spec 1.1: device sign-ins (device_code -> state), person sessions, and how each rule set
   * version was published. */
  devices = new Map<string, { user_code: string; status: string; polls: number }>();
  sessions = new Map<string, { email: string; org: string; roles: Record<string, string> }>();
  published: { project: string; version: number; how: string; who: string | null }[] = [];
  auditorLinks: any[] = [];
  /** A console page: POST /v1/rules with a session answers 202 `{confirm_in_console: <it>}`. */
  confirmInConsole: string | null = null;
  /** A witness without POST /v1/auditor-links answers not_found. */
  auditorLinksOff = false;
  /** The plan's longest auditor link (plan_required above it), and whether the refusal says it as max_days. */
  auditorMaxDays: number | null = null;
  auditorMaxInBody = true;
  /** A witness of before agent_keys and head: bad_request when they are sent. */
  auditorLinksNoKeys = false;
  private ifNoneMatch?: string;
  url = "";
  private server = http.createServer((req, res) => void this.handle(req, res));
  private n = 0;
  private made = 0;

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
    // Ids are never reused, as on the service: a sandbox made after one was deleted is a new project.
    const prj = { project: `prj_01JC${String(++this.made).padStart(22, "0")}`, env, agents: new Map(), heads: new Map(), records: new Map(), batches: [] as any[], used: 0 };
    this.projects.set(apiKey, prj);
    return prj;
  }

  project(): any {
    return [...this.projects.values()][0];
  }

  /** The daily cleanup: delete every unclaimed sandbox whose time has passed; their keys are then refused. */
  cleanup(): void {
    for (const [key, prj] of this.projects) if (prj.expires_at && !prj.claimed && Date.parse(prj.expires_at) <= Date.now()) this.projects.delete(key);
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const u = new URL(req.url!, "http://x");
    this.clientIds.push(req.headers["x-signafaide-client"] as string | undefined);
    this.ifNoneMatch = req.headers["if-none-match"] as string | undefined;
    if (this.delayMs) await new Promise((r) => setTimeout(r, this.delayMs));
    const [status, body] = this.route(req.method!, u.pathname, Object.fromEntries(u.searchParams), raw ? JSON.parse(raw) : null, req.headers.authorization);
    if (status === 304) {
      res.writeHead(304);
      res.end();
      return;
    }
    const text = typeof body === "string" ? body : JSON.stringify(body);
    res.writeHead(status, { "content-type": typeof body === "string" ? "text/plain" : "application/json" });
    res.end(text);
  }

  private route(method: string, path: string, q: Record<string, string>, body: any, auth?: string): Reply {
    this.calls.push(`${method} ${path}`);
    if (method === "GET" && path === "/.well-known/signafaide-keys.json") return [200, { keys: [this.keyDoc, ...this.extraKeys] }];
    if (method === "POST" && path === "/v1/sandbox") {
      const key = "sfa_test_" + String(++this.n).padStart(32, "0");
      const prj = this.addProject(key, "test");
      if (this.sandboxDays !== null) prj.expires_at = new Date(Date.now() + this.sandboxDays * 86_400_000).toISOString();
      return [
        200,
        {
          project: prj.project,
          api_key: key,
          claim_url: `${this.url}/app/claim/${this.n}`,
          free_quota: 1000,
          ...(prj.expires_at ? { expires_at: prj.expires_at } : {}),
          terms_url: `${this.url}/legal/terms`,
          privacy_url: `${this.url}/legal/privacy`,
        },
      ];
    }
    if (method === "POST" && path === "/v1/device/code") {
      const n = this.devices.size + 1;
      const device_code = `dev${String(n).padStart(40, "0")}`;
      const user_code = `BCDF-${"GHJK".slice(0, 4)}`;
      this.devices.set(device_code, { user_code, status: "pending", polls: 0 });
      return [200, { device_code, user_code, verification_uri: `${this.url}/app/device`, verification_uri_complete: `${this.url}/app/device?code=${user_code}`, expires_in: 600, interval: 5 }];
    }
    if (method === "POST" && path === "/v1/device/token") {
      const d = this.devices.get(body?.device_code);
      if (!d) return [200, { status: "expired" }];
      d.polls++;
      if (d.status === "approved") {
        d.status = "used";
        const session = "sfa_user_" + String(this.sessions.size + 1).padStart(32, "0");
        this.sessions.set(session, { email: "owner@example.test", org: "Example Org", roles: this.pendingRoles });
        return [200, { status: "approved", session, expires_at: new Date(Date.now() + 12 * 3600_000).toISOString(), person: { email: "owner@example.test" }, organisation: { name: "Example Org" } }];
      }
      if (d.status === "used") return [200, { status: "expired" }];
      return [200, { status: d.status }];
    }
    if (method === "POST" && path === "/v1/events") {
      this.events.push(body.name);
      return [200, {}];
    }
    const bearer = (auth ?? "").replace(/^Bearer /, "");
    const person = this.sessions.get(bearer);
    if (person) {
      if (method === "GET" && path === "/v1/session") {
        // §6: the projects the person can see, with their role in each (owner, admin or developer).
        const projects = [...this.projects.values()].filter((p) => p.project in person.roles).map((p) => ({ project: p.project, name: "Claims", env: p.env, role: person.roles[p.project] }));
        return [200, { person: { email: person.email }, organisation: { name: person.org }, expires_at: new Date(Date.now() + 3600_000).toISOString(), projects }];
      }
      if (method === "DELETE" && path === "/v1/session") {
        this.sessions.delete(bearer);
        return [204, ""];
      }
      if (method === "POST" && path === "/v1/rules") {
        const target = [...this.projects.entries()].find(([, p]) => p.project === body.project && p.env === body.env);
        if (!target) return err(404, "not_found", "No such project.");
        if (person.roles[body.project] === "developer" && body.env === "live") return err(401, "invalid_key", "Only an admin publishes a live rule set.");
        // §6: loosening a live project's rules from the command line waits for a person in the console.
        if (this.confirmInConsole !== null) return [202, { confirm_in_console: this.confirmInConsole }];
        return this.publishDraft(target[0], body, "session", person.email);
      }
      return err(401, "invalid_key", "A person session is not an API key.");
    }
    const prj = this.projects.get(bearer);
    if (!prj) return err(401, "invalid_key", "The API key is not valid; run `signafaide init` for a new sandbox key.");
    if (method === "POST" && path === "/v1/rules") {
      // An API key publishes only into its own sandbox while it is unclaimed (§6).
      if (prj.env !== "test" || prj.claimed || body.project !== prj.project || body.env !== prj.env) return err(401, "invalid_key", "An API key cannot publish rules; sign in with `signafaide login`.");
      return this.publishDraft(bearer, body, "sandbox_key", null);
    }
    if (method === "POST" && path === "/v1/auditor-links") {
      if (this.auditorLinksOff) return err(404, "not_found", "No such route.");
      if (this.auditorMaxDays !== null && body.days > this.auditorMaxDays)
        return err(402, "plan_required", `An auditor link of an unclaimed sandbox expires within ${this.auditorMaxDays} days: ask for fewer days, or claim the sandbox in the console.`, this.auditorMaxInBody ? { max_days: this.auditorMaxDays } : {});
      if (this.auditorLinksNoKeys && ("agent_keys" in body || "head" in body)) return err(400, "bad_request", "Unknown field agent_keys.");
      this.auditorLinks.push(body);
      return [201, { url: `${this.url}/audit/aud_${this.auditorLinks.length}`, expires_at: new Date(Date.now() + body.days * 86_400_000).toISOString(), ...("agent_keys" in body ? { agent_keys: true } : {}) }];
    }
    // As the service: `expires_at` only while the sandbox is unclaimed.
    if (method === "GET" && path === "/v1/project") {
      return [200, { project: prj.project, env: prj.env, claimed: !!prj.claimed, name: prj.name ?? null, ...(prj.expires_at && !prj.claimed ? { expires_at: prj.expires_at } : {}) }];
    }
    if (method === "GET" && path.startsWith("/v1/heads/")) {
      const sh = prj.heads.get(decodeURIComponent(path.slice("/v1/heads/".length)));
      if (sh) return [200, sh];
      // A witness before round 4 answered 400 for an agent that was never registered.
      const agent = decodeURIComponent(path.slice("/v1/heads/".length));
      if (this.headsUnknownAgent && !prj.agents.has(agent)) return err(400, "unknown_agent", `Agent '${agent}' is not registered in this project and env: call POST /v1/agents first.`);
      return err(404, "not_found", "This agent has no records.");
    }
    if (method === "GET" && path.startsWith("/v1/records/")) {
      const got = prj.records.get(path.slice("/v1/records/".length));
      return got ? [200, { record: got[0], receipt: got[1], anchor: null }] : err(404, "not_found", "No record with this hash in this project.");
    }
    if (method === "POST" && path === "/v1/agents") {
      const kid = keyId(b64urlDecode(body.public_key));
      for (const [name, keys] of prj.agents) if (name !== body.name && keys.has(kid)) return err(400, "invalid_record", "This key is registered to another agent.");
      if (Date.parse(body.valid_from) > Date.now() + 60_000) return err(400, "invalid_record", `valid_from ${body.valid_from} is ahead of the service clock (${now()}): the client's clock is ahead.`);
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
      if (this.failAlways) return this.failAlways;
      if (this.fail) {
        const f = this.fail;
        this.fail = null;
        return f;
      }
      return this.submit(prj, body.records ?? []);
    }
    if (method === "GET" && path === "/v1/usage") return [200, { period: "2026-11", used: prj.used, quota: 1000, plan: prj.plan ?? "free" }];
    if (method === "GET" && path === "/v1/export") return [200, this.export(prj, q.agent, q.from, q.to)];
    if (method === "GET" && path === "/v1/rules") {
      const items = this.ruleItems.get(prj.project) ?? [];
      this.rulesFetches.push([q.version, this.ifNoneMatch]);
      if (!items.length) return [200, { rules: null }];
      const item = q.version === undefined ? items.at(-1) : items.find((i) => String(i.rules.version) === q.version);
      if (!item) return err(404, "not_found", "No such version.");
      if (this.ifNoneMatch === `"${hashJson(item.rules)}"`) return [304, ""];
      return [200, item];
    }
    if (method === "GET" && path === "/v1/fingerprints") {
      if (q.since === undefined) return [200, { snapshot: this.listSnapshot(), updates: [] }];
      return [200, { snapshot: null, updates: this.listUpdates.filter((u) => u.list.seq > Number(q.since)).slice(0, 1000) }];
    }
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
      // As the real service: an unknown agent is unknown_agent; a known agent's unregistered key is bad_signature.
      const keys = prj.agents.get(env.agent);
      if (!keys) return err(400, "unknown_agent", `agent '${env.agent}' is not registered in this project and env; call POST /v1/agents first.`);
      const key = keys.get(r.key_id);
      if (!key) return err(400, "bad_signature", `key ${r.key_id} is not registered for agent '${env.agent}'; register it with POST /v1/agents.`);
      if (key.valid_to !== null) return err(400, "bad_signature", `key ${r.key_id} was retired or revoked at ${key.valid_to}; it cannot add records.`);
      if (Date.parse(env.time) > Date.now() + 300_000) return err(400, "invalid_record", `time ${env.time} is more than 300 s ahead of the service clock (${now()}); check the client clock.`);
      if (env.time < key.valid_from) return err(400, "bad_signature", `time ${env.time} is before key ${r.key_id} was made (valid from ${key.valid_from}).`);
      if (!verifySig(key.public_key, "record", h, r.sig)) return err(400, "bad_signature", "The record signature does not verify.");
      if ((r.content === undefined) !== (r.salt === undefined) || (r.content && contentHash(r.content, r.salt) !== env.content_hash)) return err(400, "content_mismatch", "content does not match content_hash.");
      const ch = env.checks ?? {};
      if ((r.disclosed !== undefined) !== (ch.disclosed_hash != null)) return err(400, "invalid_record", "disclosed and disclosed_salt come exactly when checks.disclosed_hash is set.");
      if (r.disclosed !== undefined) {
        if (C.disclosedHash(r.disclosed, r.disclosed_salt) !== ch.disclosed_hash) return err(400, "content_mismatch", "disclosed does not hash to checks.disclosed_hash.");
        this.disclosed.set(h, [r.disclosed, r.disclosed_salt]);
      }
      const [seq, last] = tips.get(env.agent) ?? [0, null];
      if (env.seq !== seq + 1 || env.prev !== last) return err(409, "chain_conflict", "This record does not extend the service chain; the head is attached.", { head: { agent: env.agent, seq, record_hash: last } });
      const lastTime = seq ? (prj.records.get(last)?.[0].envelope.time ?? fresh.find((x) => recordHash(x) === last)?.envelope.time) : null;
      if (lastTime && env.time < lastTime) return err(400, "invalid_record", `time ${env.time} is earlier than the time of seq ${seq}.`);
      tips.set(env.agent, [env.seq, h]);
      fresh.push(r);
    }
    if (this.quota !== null && prj.used + fresh.length > this.quota) return err(429, "quota_exceeded", "This sandbox's monthly allowance is used up.");
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
        const rc: any = { record_hash: hashes[i], index: i, proof: auditPath(hashes, i), batch, batch_hash: bh, batch_sig: bsig, service_key_id: this.key.keyId, head: sh.head, head_sig: sh.head_sig };
        if (r.envelope.kind === "decision" && C.asksForRuling(r.envelope.checks)) {
          if (this.rulingError) rc.ruling_error = this.rulingError;
          else if (!this.noRuling) {
            const g = this.rule(prj, r, rc);
            rc.ruling = g;
            rc.ruling_sig = this.key.sign("ruling", hashJson(g));
          }
        }
        prj.records.set(hashes[i], [r, rc]);
        prj.used++;
      });
    }
    return [200, { receipts: records.map((r) => prj.records.get(recordHash(r))[1]), heads }];
  }

  // --- tool-call checks -----------------------------------------------------------------

  /** Publish a new rule set version for the key's project (§10). */
  publishRules(apiKey: string, rules: any[], o: { mode?: string; default?: string; fail?: any; addresses?: any; approved?: any; issued?: string; set?: string; fingerprintExceptions?: any[] } = {}): any {
    const prj = this.projects.get(apiKey);
    const items = this.ruleItems.get(prj.project) ?? [];
    this.ruleItems.set(prj.project, items);
    const prev = items.at(-1)?.rules;
    const doc = {
      format: "signafaide-rules/1",
      project: prj.project,
      env: prj.env,
      set: o.set ?? "rs_01JD2K8Z5X3V7N2M4K6H8G0F1A",
      version: items.length + 1,
      prev: prev ? hashJson(prev) : null,
      issued: o.issued ?? now(),
      mode: o.mode ?? "enforce",
      default: o.default ?? "allow",
      fail: o.fail ?? {},
      addresses: o.addresses ?? { hosts: [], cidrs: [] },
      approved: o.approved ?? null,
      rules,
      ...(o.fingerprintExceptions ? { fingerprint_exceptions: o.fingerprintExceptions } : {}),
    };
    const item = { rules: doc, sig: this.key.sign("rules", hashJson(doc)), service_key_id: this.key.keyId };
    items.push(item);
    return item;
  }

  /** POST /v1/rules (§6, spec 1.1): check `after` and the whole document, then sign it. */
  private publishDraft(apiKey: string, body: any, how: string, who: string | null): Reply {
    const prj = this.projects.get(apiKey);
    const items = this.ruleItems.get(prj.project) ?? [];
    const newest = items.at(-1)?.rules.version ?? null;
    if ((body.after ?? null) !== newest) return err(400, "bad_request", "Someone published meanwhile: fetch the rule set, merge and try again.");
    const d = body.draft ?? {};
    const item = this.publishRules(apiKey, d.rules, { mode: d.mode, default: d.default, fail: d.fail, addresses: d.addresses, approved: d.approved, fingerprintExceptions: d.fingerprint_exceptions });
    const bad = C.ruleSetErrors(item.rules);
    if (bad) {
      items.pop();
      return err(400, "bad_request", `The rule set is not valid: ${bad}`);
    }
    this.published.push({ project: prj.project, version: item.rules.version, how, who });
    return [201, item];
  }

  /** Approve (or refuse) the device sign-in of `userCode`, as a person on the console page does. */
  answerDevice(status: "approved" | "denied" = "approved", roles: Record<string, string> = {}): void {
    for (const d of this.devices.values()) if (d.status === "pending") d.status = status;
    this.pendingRoles = roles;
  }
  private pendingRoles: Record<string, string> = {};

  /** Publish an update of the shared fingerprint list (§11.2). */
  listUpdate(add: any[] = [], remove: any[] = []): void {
    const k = (e: any): string => `${e.kind} ${e.fingerprint}`;
    const cmp = (a: any, b: any): number => (k(a) < k(b) ? -1 : k(a) > k(b) ? 1 : 0);
    const rm = new Set(remove.map(k));
    this.listEntries = [...this.listEntries.filter((e) => !rm.has(k(e))), ...add].sort(cmp);
    const doc = {
      format: "signafaide-fingerprints/1",
      list: "shared",
      type: "update",
      seq: this.listUpdates.length + 1,
      prev: this.listUpdates.length ? hashJson(this.listUpdates.at(-1).list) : null,
      issued: now(),
      add: [...add].sort(cmp),
      remove: [...remove].sort(cmp),
      state_hash: C.stateHash(this.listEntries),
    };
    this.listUpdates.push({ list: doc, sig: this.key.sign("fingerprints", hashJson(doc)), service_key_id: this.key.keyId });
  }

  listSnapshot(): any {
    const doc = {
      format: "signafaide-fingerprints/1",
      list: "shared",
      type: "snapshot",
      seq: this.listUpdates.length,
      last: this.listUpdates.length ? hashJson(this.listUpdates.at(-1).list) : null,
      issued: now(),
      entries: this.listEntries,
      state_hash: C.stateHash(this.listEntries),
    };
    return { list: doc, sig: this.key.sign("fingerprints", hashJson(doc)), service_key_id: this.key.keyId };
  }

  /** The witness's ruling (§3.5), as the real one decides it (no rate limits here). */
  private rule(prj: any, r: any, rc: any): any {
    const env = r.envelope;
    const ch = env.checks;
    const values = r.disclosed ?? {};
    const items = this.ruleItems.get(prj.project) ?? [];
    const doc = items.at(-1)?.rules ?? null;
    const listed = new Set(this.listEntries.map((e) => `${e.kind} ${e.fingerprint}`));
    // A match the rule set excepts (§10.1 fingerprint_exceptions) is no match.
    const excepted = new Set((doc?.fingerprint_exceptions ?? []).map((e: any) => `${e.kind} ${e.fingerprint}`));
    const hit = ["tool", "description", "server"].some((k) => ch.tool[k] && listed.has(`${k} ${ch.tool[k]}`) && !excepted.has(`${k} ${ch.tool[k]}`));
    let missing: string[] = [];
    let res: { result: string; basis: string; matched: string[]; would_block?: string[]; not_calibrated?: string[]; excepted?: string[] };
    let mode = "enforce";
    let rules: any = null;
    if (!doc) res = hit ? { result: "block", basis: "fingerprint", matched: [] } : { result: "allow", basis: "default", matched: [] };
    else {
      mode = doc.mode;
      rules = { set: doc.set, version: doc.version, hash: hashJson(doc) };
      const client = ch.rules.find((x: any) => x.set === doc.set);
      missing = C.neededFields(doc, env.agent, env.name).filter((p) => !ch.disclosed.includes(p));
      if (client && client.version > doc.version) res = { result: "block", basis: "rules_version", matched: [] };
      else if (missing.length) res = { result: "block", basis: "fields_missing", matched: [] };
      else if (hit) res = { result: "block", basis: "fingerprint", matched: [] };
      else res = C.evaluate(doc, env.agent, env.name, (p) => (p in values ? values[p] : C.ABSENT), () => 0, (p) => ch.disclosed.includes(p));
    }
    const g: any = {
      v: 1,
      record_hash: rc.record_hash,
      batch_hash: rc.batch_hash,
      server_time: rc.batch.server_time,
      ruling: mode === "enforce" ? res.result : "allow",
      mode,
      basis: res.basis,
      matched: res.matched,
      missing: res.basis === "fields_missing" ? missing.slice(0, 64) : [],
      rules,
      fingerprints: this.listUpdates.length,
      reason: `${res.result === "allow" ? "Allowed" : "Blocked"} (${res.basis}).`,
    };
    if (mode === "watch") g.enforce_ruling = res.result;
    // Spec 1.1: what else the evaluation found, each only when not empty.
    if (["error", "rule", "default"].includes(res.basis)) for (const k of ["would_block", "not_calibrated", "excepted"]) if ((res as any)[k]?.length) g[k] = (res as any)[k];
    return g;
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
      // The signed rule set versions (§7): every version this project holds, in version order.
      ...((this.ruleItems.get(prj.project) ?? []).length ? { rule_sets: [...(this.ruleItems.get(prj.project) ?? [])] } : {}),
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
