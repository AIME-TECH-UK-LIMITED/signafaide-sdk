/** The recorder: writes signed records locally and ships them in the background. Node only. */

import { AsyncLocalStorage } from "node:async_hooks";
import * as fs from "node:fs";
import * as path from "node:path";
import { b64url, hashJson, type SigningKey } from "./crypto.js";
import { Client, DEFAULT_URL, SignafaideError } from "./http.js";
import { plural } from "./plural.js";
import { API_KEY_RE, AGENT_RE, agentName, makeDraft, makeRecord, now, recordHash, registration, validProjectId, wireRecord, type Kind, type Receipt, type SignedRecord } from "./records.js";
import { PENDING, State, StateError, appendEnvFile, ensureGitignore, keyFingerprint, readEnvFile } from "./state.js";
import { adapterField, clientHeader, detectAgent, telemetryEnabled } from "./telemetry.js";

const BATCH_MAX = 1000; // §6: at most 1000 records per POST /v1/records
/** §2.4: a registration's valid_from is at most 7 days old; keep an hour of margin. */
const KEY_MAX_AGE_MS = 7 * 86_400_000 - 3_600_000;

/** Set while a compare runs a candidate function: any record written in that context is
 * refused, so a candidate never adds to a chain (and a recorded tool it calls never runs). */
export const noWrites = new AsyncLocalStorage<string>();

export interface RecorderOptions {
  home?: string;
  /** The project folder (default: found from the cwd). */
  root?: string;
  url?: string;
  apiKey?: string;
  /** Send content to the service too (default false: hash-only). */
  storeContent?: boolean;
  flushIntervalMs?: number;
  flushSize?: number;
  quiet?: boolean;
  /** How requests are made, for the client header: "sdk" (default), "cli" or "mcp". */
  via?: string;
}

export interface FlushResult {
  shipped: number;
  left: number;
  errors: Record<string, SignafaideError>;
}

export class Recorder {
  readonly state: State;
  storeContent: boolean;
  readonly flushIntervalMs: number;
  readonly flushSize: number;
  readonly quiet: boolean;
  readonly via: string;
  /** A strict-mode tool ran in this process (client header). */
  strictUsed = false;
  /** @internal */ _url?: string;
  /** @internal */ _apiKey?: string;
  /** agent -> [key, the key file's identity when loaded] */
  private keys = new Map<string, [SigningKey, string]>();
  private registered = new Set<string>();
  private reconciled = new Set<string>();
  private blocked = new Map<string, SignafaideError>();
  private shipping: Promise<unknown> = Promise.resolve();
  private timer?: ReturnType<typeof setInterval>;
  private nextAttempt = 0;
  private failures = 0;
  private failing?: string;
  private pending = 0;
  private exitHooked = false;
  private toldLocal = false;
  private exitFlushed = false;
  private closed = false;

  constructor(opts: RecorderOptions = {}) {
    this.state = State.discover(opts.home, opts.root);
    this._url = opts.url;
    this._apiKey = opts.apiKey;
    this.storeContent = opts.storeContent ?? false;
    this.flushIntervalMs = opts.flushIntervalMs ?? 2000;
    this.flushSize = opts.flushSize ?? 100;
    this.quiet = opts.quiet ?? false;
    this.via = opts.via ?? "sdk";
  }

  // --- configuration ------------------------------------------------------------

  private setting(name: string): string | undefined {
    return process.env[name] || readEnvFile(path.join(this.state.root, ".env"))[name] || undefined;
  }

  get url(): string {
    return (this._url || this.setting("SIGNAFAIDE_URL") || DEFAULT_URL).replace(/\/+$/, "");
  }

  get apiKey(): string | undefined {
    return this._apiKey || this.setting("SIGNAFAIDE_API_KEY");
  }

  client(timeoutMs = 10_000, apiKey = this.apiKey): Client {
    return new Client(this.url, apiKey, timeoutMs, this.clientId());
  }

  /** The coding agent running now, else the one stored when the project was set up. */
  agent(): string {
    const now = detectAgent();
    return now !== "unknown" ? now : (this.state.config().agent ?? "unknown");
  }

  clientId(): string {
    return clientHeader({ via: this.via, adapter: adapterField(), agent: this.agent(), strict: this.strictUsed });
  }

  /** Store the detected coding agent in config.json (not when telemetry is off). */
  rememberAgent(): void {
    const agent = detectAgent();
    if (telemetryEnabled() && agent !== "unknown" && this.state.config().agent !== agent) this.state.saveConfig({ agent });
  }

  /** Fire-and-forget usage event; never throws, skipped when telemetry is off and when there
   * is no API key (nothing is sent before a human opts in). */
  async event(name: string): Promise<void> {
    if (!telemetryEnabled() || !this.apiKey) return;
    try {
      await this.client(2000).event(name);
    } catch {
      /* never fails the caller */
    }
  }

  get defaultAgent(): string {
    return agentName(path.basename(this.state.root));
  }

  /** Return the API key; create a sandbox project if there is none. Only an explicit human
   * opt-in calls this (`signafaide init`, the MCP `signafaide_init` tool): records never
   * create a sandbox by themselves. */
  async createSandbox(): Promise<string> {
    const existing = this.apiKey;
    if (existing) {
      try {
        await this.resolveProject(existing);
      } catch (e) {
        if ((e as { code?: string }).code !== "network") throw e;
      }
      return existing;
    }
    this.rememberAgent();
    const resp = await this.client().sandbox();
    // The service's answer names a file line and folders: check it before using it (§8).
    if (typeof resp?.api_key !== "string" || !API_KEY_RE.test(resp.api_key) || !resp.api_key.startsWith("sfa_test_") || !validProjectId(resp.project)) {
      throw new SignafaideError(`The service at ${this.url} answered POST /v1/sandbox with an invalid api_key or project; check SIGNAFAIDE_URL.`, { code: "bad_response" });
    }
    this.state.ensure();
    return this.state.lock("~init", () => {
      const raced = this.apiKey; // another process may have just created one
      if (raced) return raced;
      const envFile = path.join(this.state.root, ".env");
      appendEnvFile(envFile, "SIGNAFAIDE_API_KEY", resp.api_key);
      // A sandbox key only works on the service that issued it: keep that service with the key.
      if (this.url !== DEFAULT_URL && !readEnvFile(envFile).SIGNAFAIDE_URL) appendEnvFile(envFile, "SIGNAFAIDE_URL", this.url);
      ensureGitignore(path.join(this.state.root, ".gitignore"), ".env"); // the key must not be committed
      this.state.learnProject(resp.api_key, resp.project, "test");
      this.state.saveSandbox({ project: resp.project, claim_url: resp.claim_url, free_quota: resp.free_quota, url: this.url, created: now() });
      this._apiKey = resp.api_key;
      if (!this.quiet) console.error(`signafaide: sandbox ready, key saved to .env; claim it at ${resp.claim_url}`);
      return resp.api_key;
    });
  }

  /** Learn the API key's project (`GET /v1/project`) if it is not known yet, so envelopes
   * can name it (§2.2). Throws SignafaideError when the service cannot say. */
  async resolveProject(apiKey: string): Promise<void> {
    if (!this.state.bucket(apiKey).startsWith(PENDING + "/")) return;
    const resp = await this.client(10_000, apiKey).project();
    if (resp?.env !== envOf(apiKey) || !validProjectId(resp?.project)) {
      throw new SignafaideError(`The service at ${this.url} answered GET /v1/project with an invalid project or env; check SIGNAFAIDE_URL.`, { code: "bad_response" });
    }
    this.state.learnProject(apiKey, resp.project, resp.env);
  }

  /** Records waiting to ship, drafts included. */
  private waiting(): number {
    return this.state.outboxSize() + this.state.chains().filter((c) => c.startsWith(PENDING + "/")).reduce((n, c) => n + this.state.draftCount(c), 0);
  }

  // --- writing --------------------------------------------------------------------

  key(agent: string): SigningKey {
    // Reloaded when the key file changes: `signafaide keys rotate` in another process takes
    // effect at this process's next record (§2.4: the old key is retired when the new one registers).
    const stamp = (): string => {
      try {
        const s = fs.statSync(this.state.keyPath(agent), { bigint: true });
        return `${s.ino}:${s.mtimeNs}:${s.size}`;
      } catch {
        return "";
      }
    };
    const held = this.keys.get(agent);
    const now = stamp();
    if (held && held[1] === now && now) return held[0];
    const k = this.state.loadKey(agent);
    this.keys.set(agent, [k, stamp()]);
    return k;
  }

  /** Sign and chain one record locally (synchronous) and queue it for shipping.
   * The chain is this API key's `<project>/<env>/<agent>` (§8). */
  write(kind: Kind, name: string, content: Record<string, unknown>, opts: { agent?: string; ref?: string | null; storeContent?: boolean } = {}): SignedRecord {
    const why = noWrites.getStore();
    if (why) throw new SignafaideError(`${why} must not write records: candidate functions must be side-effect free (it tried to record "${name}")`, { code: "no_writes" });
    const agent = opts.agent || this.defaultAgent;
    if (!AGENT_RE.test(agent)) throw new Error(`agent "${agent}" is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)`);
    const key = this.key(agent);
    const sc = opts.storeContent ?? this.storeContent;
    const apiKey = this.apiKey;
    let rec: SignedRecord | null = null;
    while (!rec) {
      const bucket = this.state.bucket(apiKey);
      const chain = `${bucket}/${agent}`;
      if (!fs.existsSync(this.state.chainPath(chain))) for (const e of Object.values(this.adoptInto(bucket, apiKey))) this.report(`signafaide: ${e.message}`);
      const [project, env] = bucket.split("/") as [string, "test" | "live"];
      // Before the project is known, an envelope cannot name it: keep a draft, signed when it is (§8).
      const build = bucket.startsWith(PENDING + "/")
        ? (seq: number, prev: string | null) => makeDraft(key, { kind, agent, seq, prev, name, content, ref: opts.ref ?? null }, sc)
        : (seq: number, prev: string | null) => makeRecord(key, { kind, project, env, agent, seq, prev, name, content, ref: this.state.translateRef(chain, opts.ref) });
      rec = this.state.append(chain, build, (r) => wireRecord(r, sc), () => this.state.bucket(apiKey) === bucket);
    }
    this.pending++;
    this.exitFlushed = false;
    if (!apiKey && !this.toldLocal && !this.quiet) {
      this.toldLocal = true;
      console.error(
        `signafaide: recording locally in ${this.state.home} (signed and chained; no API key, so nothing is sent). ` +
          "Run `npx signafaide init` to send hashes for co-signature and public timestamps, or set SIGNAFAIDE_API_KEY.",
      );
    }
    this.start();
    if (this.pending >= this.flushSize) void this.tick(true);
    return rec;
  }

  /** Move pending chains (written before the project was known) under `bucket`. Returns the
   * chains that stay pending, with why (chain id -> error). */
  private adoptInto(bucket: string, apiKey: string | undefined): Record<string, SignafaideError> {
    const out: Record<string, SignafaideError> = {};
    if (bucket.startsWith(PENDING + "/")) return out;
    const sources = [`${PENDING}/nokey`];
    if (apiKey) sources.push(`${PENDING}/${keyFingerprint(apiKey)}`);
    // §2.4: a key's valid_from is at most 7 days before its registration, so the service accepts
    // records written up to 7 days (less an hour of margin) before they are sent.
    const notBefore = new Date(Date.now() - KEY_MAX_AGE_MS).toISOString();
    for (const src of sources) {
      for (const [chain, why] of this.state.adopt(src, bucket, (a) => this.key(a), (r) => wireRecord(r, this.storeContent), notBefore)) {
        const msg =
          why === "exists"
            ? `${chain} cannot join ${bucket}, which already has that agent's chain; it stays pending (local only) and still verifies with \`signafaide verify\``
            : `${chain} starts at ${why}, more than 7 days ago: the service accepts records up to 7 days old (§2.4), so this chain stays local; it still verifies with \`signafaide verify\`. New records of that agent start a new chain under ${bucket}`;
        out[chain] = new SignafaideError(msg, { code: why === "exists" ? "chain_exists" : "too_old" });
      }
    }
    return out;
  }

  // --- shipping -------------------------------------------------------------------

  /** Run shipping work one at a time in this process. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.shipping.then(fn);
    this.shipping = run.catch(() => undefined);
    return run;
  }

  /** Ship the outbox of this API key's project now. `errors` maps chain id to the
   * one-sentence fix. Records of other projects (an earlier key) wait for that key. */
  flush(timeoutMs = 10_000): Promise<FlushResult> {
    return this.serial(async () => {
      let shipped = 0;
      const errors: Record<string, SignafaideError> = {};
      if (!this.state.outboxSize() && !this.state.hasDrafts()) return { shipped, left: 0, errors };
      // Local-first: with no API key nothing is sent and no sandbox is created. A human opts in
      // with `signafaide init` or by setting SIGNAFAIDE_API_KEY.
      const key = this.apiKey;
      if (!key) return { shipped, left: this.waiting(), errors };
      const apiKey: string = key;
      try {
        await this.resolveProject(apiKey);
      } catch (e) {
        if (!(e instanceof SignafaideError) && !(e instanceof StateError)) throw e;
        const err = e instanceof SignafaideError ? e : new SignafaideError((e as Error).message, { code: "state" });
        const waiting = this.state.outboxChains().length ? this.state.outboxChains() : this.state.chains().filter((c) => c.startsWith(PENDING + "/"));
        return { shipped, left: this.waiting(), errors: Object.fromEntries(waiting.map((c) => [c, err])) };
      }
      const done = new Set<string>();
      for (;;) {
        const bucket = this.state.bucket(apiKey);
        Object.assign(errors, this.adoptInto(bucket, apiKey));
        const next = this.state.outboxChains(bucket).find((c) => !done.has(c));
        if (!next) break;
        done.add(next);
        try {
          shipped += (await this.shipChain(next, apiKey, timeoutMs)).size;
        } catch (e) {
          if (!(e instanceof SignafaideError)) throw e;
          errors[next] = e;
          if (e.retryable || e.code === "invalid_key" || e.code === "quota_exceeded") break; // same for every chain
        }
      }
      return { shipped, left: this.waiting(), errors };
    });
  }

  /** Strict mode: ship `rec`'s chain now and return its receipt, or throw. */
  ensureReceipt(rec: SignedRecord, timeoutMs = 10_000): Promise<Receipt> {
    this.strictUsed = true;
    return this.serial(async () => {
      const apiKey = this.apiKey;
      if (!apiKey) {
        throw new SignafaideError(
          "Strict mode needs the service's receipt, and there is no API key: run `npx signafaide init` (a free sandbox) or set SIGNAFAIDE_API_KEY.",
          { code: "no_key" },
        );
      }
      await this.resolveProject(apiKey);
      const bucket = this.state.bucket(apiKey);
      this.adoptInto(bucket, apiKey);
      const h = this.state.translateRef(`${bucket}/${rec.envelope.agent}`, recordHash(rec))!; // a draft is signed by now
      const got = (await this.shipChain(`${bucket}/${rec.envelope.agent}`, apiKey, timeoutMs)).get(h);
      if (!got) throw new SignafaideError(`The service did not return a receipt for record ${h.slice(0, 12)}; check \`signafaide status\`.`, { code: "not_recorded" });
      this.adoptInto(this.state.bucket(apiKey), apiKey);
      return got;
    });
  }

  /** Ship one chain's outbox in order. */
  private async shipChain(chain: string, apiKey: string, timeoutMs: number): Promise<Map<string, Receipt>> {
    const agent = chain.split("/")[2];
    const received = new Map<string, Receipt>();
    const blocked = this.blocked.get(chain);
    if (blocked) throw blocked;
    const wire = (r: SignedRecord) => wireRecord(r, this.storeContent);
    if (!this.reconciled.has(chain)) {
      this.state.reconcileOutbox(chain, wire);
      this.reconciled.add(chain);
    }
    const client = this.client(timeoutMs, apiKey);
    for (;;) {
      let batch = this.state.outbox(chain, BATCH_MAX);
      if (!batch.length) return received;
      const current = this.key(agent).keyId;
      if (batch[0].key_id !== current) {
        // Records signed before `keys rotate` go first, under the old key: registering the new
        // key retires the old one on the service (§2.4).
        const cut = batch.findIndex((r) => r.key_id === current);
        batch = cut < 0 ? batch : batch.slice(0, cut);
      } else await this.register(client, agent);
      let resp: { receipts: Receipt[]; heads: any[] };
      try {
        resp = await client.submit(batch);
      } catch (e) {
        if (!(e instanceof SignafaideError)) throw e;
        if (e.code === "unknown_agent") {
          this.registered.delete(`${client.apiKey}\n${agent}`);
          await this.register(client, agent);
          resp = await client.submit(batch);
        } else if (e.code === "chain_conflict") {
          const head = e.body.error?.head ?? {};
          const err = new SignafaideError(
            `${e.message} (chain ${chain}: service head is seq ${head.seq} ${head.record_hash}; local outbox starts at seq ${batch[0].envelope.seq}; ` +
              "nothing was rewritten, run `signafaide verify` and `signafaide status`)",
            { code: e.code, status: e.status, docs: e.docs, body: e.body },
          );
          this.blocked.set(chain, err);
          throw err;
        } else {
          if (!e.retryable && e.code !== "invalid_key" && e.code !== "quota_exceeded") this.blocked.set(chain, e);
          throw e;
        }
      }
      const got = new Map<string, Receipt>((resp.receipts ?? []).map((r) => [r.record_hash, r]));
      const bucket = chain.split("/").slice(0, 2).join("/");
      if ([...got.values()].some((r) => `${r.batch.project}/${r.batch.env}` !== bucket)) {
        throw new SignafaideError(`The service returned receipts for another project than ${bucket}; nothing was written. Check SIGNAFAIDE_URL and the API key.`, { code: "bad_response" });
      }
      this.state.applyReceipts(chain, got);
      this.state.dropOutbox(
        chain,
        batch.filter((r) => got.has(recordHash(r))).map((r) => r.envelope.seq),
      );
      for (const w of this.state.updateHeads(resp.heads ?? [])) console.warn(`signafaide: ${w}`);
      for (const [h, r] of got) received.set(h, r);
      this.pending = 0;
      if (!got.size) throw new SignafaideError("The service accepted the batch but returned no matching receipts.", { code: "no_receipts" });
    }
  }

  private async register(client: Client, agent: string): Promise<void> {
    const id = `${client.apiKey}\n${agent}`;
    if (this.registered.has(id)) return;
    // §2.4: the registration with its proof of possession, and a rotation signature by the
    // newest retired key when there is one.
    const k = this.key(agent);
    const [project, env] = this.state.bucket(client.apiKey).split("/");
    const floor = new Date(Date.now() - KEY_MAX_AGE_MS).toISOString().slice(0, 19) + ".000Z";
    const created = this.state.keyCreated(agent) ?? now();
    const validFrom = created > floor ? created : floor;
    const reg = registration(project, env, agent, b64url(k.publicKey), validFrom);
    const h = hashJson(reg);
    const retired = this.state.retiredKeys(agent)[0]?.[0];
    const rotation = retired ? { key_id: retired.keyId, sig: retired.sign("rotate", h) } : undefined;
    const resp = await client.registerAgent(agent, reg.public_key, validFrom, k.sign("register", h), rotation);
    if (resp?.key_id && resp.key_id !== k.keyId) {
      throw new SignafaideError(`The service registered key ${resp.key_id} for ${agent}, expected ${k.keyId}.`, { code: "key_mismatch" });
    }
    // The service says when it retired the agent's earlier keys: kept for `keys export` (§2.5).
    for (const r of Array.isArray(resp?.retired) ? resp.retired : []) {
      if (r && typeof r.key_id === "string" && typeof r.valid_to === "string") this.state.markRetired(agent, r.key_id, r.valid_to);
    }
    this.registered.add(id);
  }

  // --- background -----------------------------------------------------------------

  private start(): void {
    if (this.closed) return;
    if (!this.timer) {
      this.timer = setInterval(() => void this.tick(false), this.flushIntervalMs);
      this.timer.unref?.();
    }
    if (!this.exitHooked && typeof process !== "undefined") {
      this.exitHooked = true;
      process.on("beforeExit", this.onBeforeExit);
      process.on("exit", this.onExit);
    }
  }

  private async tick(force: boolean): Promise<void> {
    if (!force && Date.now() < this.nextAttempt) return;
    if (!this.apiKey || !this.waiting()) return; // no key: local only, nothing is sent
    const r = await this.flushLogged();
    if (r && !Object.keys(r.errors).length) {
      this.failures = 0;
      this.nextAttempt = 0;
    } else {
      this.failures++;
      this.nextAttempt = Date.now() + Math.min(60_000, this.flushIntervalMs * 2 ** this.failures);
    }
  }

  private async flushLogged(timeoutMs = 10_000): Promise<FlushResult | null> {
    let r: FlushResult;
    try {
      r = await this.flush(timeoutMs);
    } catch (e) {
      this.report(`signafaide: ${(e as Error).message}`);
      return null;
    }
    const errs = Object.entries(r.errors);
    if (errs.length) this.report("signafaide: " + errs.map(([a, e]) => `${a}: ${e.message}`).join("; "));
    else if (this.failing && r.shipped) {
      console.warn(`signafaide: service reachable again, shipped ${plural(r.shipped, "record")}`);
      this.failing = undefined;
    }
    return r;
  }

  private report(msg: string): void {
    if (msg !== this.failing) {
      console.warn(msg); // one line per distinct problem, not per retry
      this.failing = msg;
    }
  }

  private onBeforeExit = (): void => {
    if (this.exitFlushed || !this.apiKey || !this.waiting()) return;
    this.exitFlushed = true; // one attempt; beforeExit fires again once it settles
    void this.flushLogged(3000);
  };

  private onExit = (): void => {
    const left = this.waiting();
    if (left && !this.quiet && this.apiKey) {
      console.error(`signafaide: ${plural(left, "record")} kept in ${path.join(this.state.home, "outbox")}; they ship on the next run or with \`signafaide flush\``);
    }
  };

  /** Stop the background timer and exit hooks (records stay in the outbox). */
  close(): void {
    this.closed = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    if (this.exitHooked) {
      process.off("beforeExit", this.onBeforeExit);
      process.off("exit", this.onExit);
      this.exitHooked = false;
    }
  }

  // --- status ---------------------------------------------------------------------

  status() {
    const heads = this.state.chainHeads();
    const bucket = this.state.bucket(this.apiKey);
    const chains = this.state.chains().map((chain) => {
      const agent = chain.split("/")[2];
      const h = heads[chain]?.head;
      return {
        chain,
        agent,
        current: chain.startsWith(bucket + "/"),
        key_id: this.state.loadKey(agent, false)?.keyId ?? null,
        records: this.state.tail(chain)[0],
        waiting: this.state.outboxSize(chain),
        receipt_seq: h?.seq ?? null,
        receipt_time: h?.server_time ?? null,
      };
    });
    const key = this.apiKey;
    return { url: this.url, home: this.state.home, api_key: key ?? null, env: envOf(key), bucket, sandbox: this.state.sandbox(), chains, outbox: this.state.outboxSize() };
  }
}

export function envOf(key: string | undefined | null): string | null {
  if (!key) return null;
  return key.startsWith("sfa_test_") ? "test" : key.startsWith("sfa_live_") ? "live" : "unknown";
}

// --- default instance -------------------------------------------------------------

let current: Recorder | undefined;

export function getRecorder(): Recorder {
  return (current ??= new Recorder());
}

/** Replace the default recorder (used by `init` and tests). */
export function configure(opts: RecorderOptions = {}): Recorder {
  current?.close();
  current = new Recorder(opts);
  return current;
}
