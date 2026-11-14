/** The recorder: writes signed records locally and ships them in the background. Node only. */

import { AsyncLocalStorage } from "node:async_hooks";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { b64url, hashJson, type SigningKey } from "./crypto.js";
import { Client, DEFAULT_URL, SignafaideError, type Transport } from "./http.js";
import { nodeTransport } from "./nodehttp.js";
import { plural } from "./plural.js";
import {
  API_KEY_RE,
  AGENT_RE,
  INSTANCE_STOP,
  MAX_CLOCK_SKEW_MS,
  instanceStopContent,
  isStopNote,
  agentName,
  clampTime,
  makeDraft,
  makeRecord,
  now,
  recordHash,
  registration,
  validProjectId,
  wireRecord,
  withWallTime,
  type Kind,
  type Receipt,
  type SignedRecord,
} from "./records.js";
import { PENDING, State, StateError, agentKeyEnvName, monotonicMs, appendEnvFile, keyFingerprint, readEnvFile, scopeOf, type Base, type KeyProvider, type KeyScope } from "./state.js";
import { adapterField, clientHeader, detectAgent, telemetryEnabled } from "./telemetry.js";

const BATCH_MAX = 1000; // §6: at most 1000 records per POST /v1/records
/** §2.4: a registration's valid_from is at most 7 days old; keep an hour of margin. */
const KEY_MAX_AGE_MS = 7 * 86_400_000 - 3_600_000;
/** Problems found on this machine, not refusals by the witness: they never slow shipping down. */
const LOCAL_CODES = new Set(["too_old", "chain_exists"]);

/** Set while a compare runs a candidate function: any record written in that context is
 * refused, so a candidate never adds to a chain (and a recorded tool it calls never runs). */
export const noWrites = new AsyncLocalStorage<string>();

/** `SIGNAFAIDE_DISABLED=1`: `record()` and `wrapTools()` call the function and write nothing. */
export function recordingDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return /^(1|true|yes)$/i.test((env.SIGNAFAIDE_DISABLED ?? "").trim());
}

/** Test mode: records are written to a temporary folder and never sent, so unit tests never ship
 * records under a production agent name. On with `SIGNAFAIDE_TEST=1`, and by itself under
 * Vitest, Jest and `node --test` unless `SIGNAFAIDE_TEST=0`. */
export function testMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env.SIGNAFAIDE_TEST ?? "").trim();
  if (v) return /^(1|true|yes)$/i.test(v);
  return !!(env.VITEST || env.JEST_WORKER_ID || env.NODE_TEST_CONTEXT);
}

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
  /** Agent keys from a secret store: `(agent, scope) => keyFileJson | undefined` (undefined: use
   * `SIGNAFAIDE_AGENT_KEY_<NAME>`, then the key file). */
  keyProvider?: KeyProvider;
  /** The longest a finished program is kept open to ship the outbox (default 3000 ms, or
   * SIGNAFAIDE_EXIT_FLUSH_MS; 0: never). */
  exitFlushMs?: number;
  /** Also keep the newest signed heads in this file (default `SIGNAFAIDE_HEAD_FILE`): a path on
   * a persistent volume or mounted bucket, so an ephemeral container's heads outlive it. */
  headFile?: string;
  /** Called with the newest signed heads after every accepted batch, to keep them anywhere (an
   * object store, a database). An error it throws is reported and never stops recording. */
  onHead?: (heads: { head: Record<string, unknown>; head_sig: string }[]) => void | Promise<void>;
  /** Write a signed stop note when the program ends with nothing left to send (§8), so the next
   * instance's start is a clean restart. Default: on when a head file is set (an ephemeral
   * container), or `SIGNAFAIDE_INSTANCE_STOP=1`; `SIGNAFAIDE_INSTANCE_STOP=0` turns it off.
   * `stop()` always writes one. */
  instanceStop?: boolean;
}

export interface FlushResult {
  shipped: number;
  left: number;
  errors: Record<string, SignafaideError>;
}

export interface StopResult extends FlushResult {
  /** The chains whose stop note the witness co-signed. */
  stopped: string[];
}

/** Why a chain cannot ship, found on this machine or said by the witness. */
export interface Blocked {
  chain: string;
  /** The first record that cannot ship. */
  seq: number;
  code: string;
  reason: string;
  /** How many records wait behind it. */
  records: number;
  /** What to do. */
  next: string;
}

type IoMode = "fg" | "bg" | "exit";

/** Test-mode folders, deleted when the process ends (one exit hook for all of them). */
const testHomes = new Set<string>();
function removeAtExit(dir: string): void {
  if (!testHomes.size) process.once("exit", () => testHomes.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));
  testHomes.add(dir);
}

export class Recorder {
  readonly state: State;
  storeContent: boolean;
  readonly flushIntervalMs: number;
  readonly flushSize: number;
  readonly quiet: boolean;
  readonly via: string;
  readonly exitFlushMs: number;
  /** Test mode (see `testMode()`): local only, in a temporary folder. */
  readonly test: boolean;
  /** A strict-mode tool ran in this process (client header). */
  strictUsed = false;
  /** Write a stop note at a clean exit (see `RecorderOptions.instanceStop`). */
  readonly instanceStop: boolean;
  /** Agents this process wrote records for since its last stop note. */
  private wrote = new Set<string>();
  private toldStrict = false;
  /** @internal */ _url?: string;
  /** @internal */ _apiKey?: string;
  /** `<agent>\n<scope>` -> [key, the key file's identity when loaded] */
  private keys = new Map<string, [SigningKey, string]>();
  /** `<api key>\n<agent>\n<key id>` of each key registered by this process: a key rotated
   * while the process runs (`signafaide keys rotate`) is a new entry, so it gets registered. */
  private registered = new Set<string>();
  private reconciled = new Set<string>();
  /** Chains the witness refused, with the configuration they were refused under. */
  private blocked = new Map<string, { fp: string; err: SignafaideError }>();
  /** A refusal that applies to every chain (quota, API key): nothing is sent until the configuration changes. */
  private halted?: { fp: string; err: SignafaideError };
  private shipping: Promise<unknown> = Promise.resolve();
  private timer?: ReturnType<typeof setInterval>;
  /** Monotonic ms (`monotonicMs`) before which the background shipper waits: a wall-clock step never shortens or stretches the backoff. */
  private nextAttempt = 0;
  private failures = 0;
  private failing?: string;
  private pending = 0;
  private inFlight = false;
  private ioMode: IoMode = "fg";
  private bgAbort = new AbortController();
  private exitAbort?: AbortController;
  private exitHooked = false;
  private toldLocal = false;
  private toldBadKey = false;
  private exitFlushed = false;
  private closed = false;
  private onHead?: RecorderOptions["onHead"];

  constructor(opts: RecorderOptions = {}) {
    this.test = testMode();
    const temp = opts.home === undefined && this.test && !process.env.SIGNAFAIDE_HOME ? fs.mkdtempSync(path.join(os.tmpdir(), "signafaide-test-")) : undefined;
    // Test mode sends nothing and keeps nothing: the folder goes when the process ends.
    if (temp) removeAtExit(temp);
    const home = opts.home ?? temp;
    this.state = State.discover(home, opts.root);
    this.state.keyProvider = opts.keyProvider;
    this.state.headFile = opts.headFile || process.env.SIGNAFAIDE_HEAD_FILE || undefined;
    this.onHead = opts.onHead;
    const envStop = process.env.SIGNAFAIDE_INSTANCE_STOP;
    this.instanceStop = envStop === "0" ? false : (opts.instanceStop ?? (envStop === "1" || !!this.state.headFile));
    this._url = opts.url;
    this._apiKey = opts.apiKey;
    this.storeContent = opts.storeContent ?? false;
    this.flushIntervalMs = opts.flushIntervalMs ?? 2000;
    this.flushSize = opts.flushSize ?? 100;
    this.quiet = opts.quiet ?? false;
    this.via = opts.via ?? "sdk";
    const envMs = Number(process.env.SIGNAFAIDE_EXIT_FLUSH_MS);
    this.exitFlushMs = Math.max(0, opts.exitFlushMs ?? (process.env.SIGNAFAIDE_EXIT_FLUSH_MS !== undefined && Number.isFinite(envMs) ? envMs : 3000));
  }

  // --- configuration ------------------------------------------------------------

  private setting(name: string): string | undefined {
    return process.env[name] || readEnvFile(path.join(this.state.root, ".env"))[name] || undefined;
  }

  get url(): string {
    return (this._url || this.setting("SIGNAFAIDE_URL") || DEFAULT_URL).replace(/\/+$/, "");
  }

  /** SIGNAFAIDE_API_KEY as set, even when it is not a valid key. */
  get rawApiKey(): string | undefined {
    return this._apiKey || this.setting("SIGNAFAIDE_API_KEY");
  }

  /** The API key, or undefined: none set, test mode, or not a signafAIde key (checked here, so a
   * wrong value is never sent anywhere). */
  get apiKey(): string | undefined {
    if (this.test) return undefined;
    const k = this.rawApiKey;
    if (!k) return undefined;
    if (!API_KEY_RE.test(k)) {
      if (!this.toldBadKey && !this.quiet) {
        this.toldBadKey = true;
        console.warn(
          `signafaide: SIGNAFAIDE_API_KEY (${k.slice(0, 8)}...) is not a signafAIde key (sfa_test_ or sfa_live_ and 32 letters or digits); nothing is sent and records stay on this machine. Fix it or remove it.`,
        );
      }
      return undefined;
    }
    return k;
  }

  /** What shipping depends on: when it changes, refused chains are tried again. */
  private configFp(): string {
    const stamp = (d: string): string => {
      try {
        return String(fs.statSync(d).mtimeMs);
      } catch {
        return "0";
      }
    };
    const dirs = [this.state.keyDir(""), this.state.retiredDir(""), this.state.keyDir("live"), this.state.retiredDir("live")];
    return [this.url, this.apiKey ?? "", ...dirs.map(stamp)].join("\n");
  }

  client(timeoutMs = 10_000, apiKey = this.apiKey): Client {
    const mode = this.ioMode;
    const transport: Transport | undefined = typeof process !== "undefined" && process.versions?.node ? nodeTransport(() => mode !== "bg") : undefined;
    const signal = mode === "bg" ? this.bgAbort.signal : mode === "exit" ? this.exitAbort?.signal : undefined;
    // At exit every request shares one limit: a timeout names that limit, not a share of it.
    const timeoutLabel = mode === "exit" ? `no answer within the ${this.exitFlushMs / 1000} s allowed at exit (SIGNAFAIDE_EXIT_FLUSH_MS)` : undefined;
    return new Client(this.url, apiKey, timeoutMs, this.clientId(), { transport, signal, timeoutLabel });
  }

  /** The coding agent stored when the project was set up (`init`, `agent setup`). It is never
   * guessed per process: a program started from a terminal inside a coding agent is not that agent. */
  agent(): string {
    return this.state.config().agent ?? "unknown";
  }

  clientId(): string {
    return clientHeader({ via: this.via, adapter: adapterField(), agent: this.agent(), strict: this.strictUsed });
  }

  /** Store the detected coding agent in config.json (not when telemetry is off). Only `init`
   * and `agent setup` call it. */
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

  /** The Terms and Privacy notice links of this project's sandbox (from the service's answer). */
  legal(): { terms_url: string; privacy_url: string } {
    const s = this.state.sandbox();
    return legalLinks(s ?? {}, s?.url ?? this.url);
  }

  /** The one agent with records here, when there is exactly one (replay and compare without
   * `--agent`). */
  onlyAgent(): string | undefined {
    const names = new Set(this.state.chains().map((c) => c.split("/")[2]));
    return names.size === 1 ? [...names][0] : undefined;
  }

  /** The agent name used when none is given: the project folder's name. Give agents explicit
   * names in production (one per running instance); see the production guide. */
  get defaultAgent(): string {
    return agentName(path.basename(this.state.root));
  }

  /** Return the API key; create a sandbox project if there is none. Only an explicit human
   * opt-in calls this (`signafaide init`, the MCP `signafaide_init` tool): records never
   * create a sandbox by themselves. */
  async createSandbox(): Promise<string> {
    const raw = this.rawApiKey;
    if (raw && !API_KEY_RE.test(raw)) {
      throw new SignafaideError(`SIGNAFAIDE_API_KEY (${raw.slice(0, 8)}...) is not a signafAIde key (sfa_test_ or sfa_live_ and 32 letters or digits): fix it, or remove it to create a sandbox.`, { code: "invalid_key" });
    }
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
      this.state.ignoreInGit(".env"); // the key must not be committed
      this.state.learnProject(resp.api_key, resp.project, "test");
      const legal = legalLinks(resp, this.url);
      this.state.saveSandbox({ project: resp.project, claim_url: resp.claim_url, free_quota: resp.free_quota, url: this.url, created: now(), ...legal });
      this._apiKey = resp.api_key;
      if (!this.quiet) console.error(`signafaide: sandbox ready, key saved to .env; claim it at ${resp.claim_url}. ${termsNotice(legal)}`);
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

  /** `firstTime`: when a new key must sign records written earlier (drafts), its creation time. */
  key(agent: string, scope: KeyScope = "", firstTime?: string): SigningKey {
    // Reloaded when the key file changes: `signafaide keys rotate` in another process takes
    // effect at this process's next record (§2.4: the old key is retired when the new one registers).
    const stamp = (): string => {
      if (this.state.providedKey(agent, scope)) return "provided";
      try {
        const s = fs.statSync(this.state.keyPath(agent, scope), { bigint: true });
        return `${s.ino}:${s.mtimeNs}:${s.size}`;
      } catch {
        return "";
      }
    };
    const id = `${agent}\n${scope}`;
    const held = this.keys.get(id);
    const now = stamp();
    if (held && held[1] === now && now) return held[0];
    const k = this.state.loadKey(agent, true, scope, firstTime);
    this.keys.set(id, [k, stamp()]);
    return k;
  }

  /** The record's time (§2.2): never earlier than the previous record's or the key's valid_from.
   * When the clock read earlier, its reading is kept in `meta.wall_time`. */
  private timed(content: Record<string, unknown>, prevTime: string | null, agent: string, scope: KeyScope): [string, Record<string, unknown>] {
    const wall = now();
    const [time, raised] = clampTime(wall, prevTime, this.state.keyCreated(agent, scope) ?? null);
    return raised ? [time, withWallTime(content, wall)] : [time, content];
  }

  /** Sign and chain one record locally (synchronous) and queue it for shipping.
   * The chain is this API key's `<project>/<env>/<agent>` (§8). */
  write(kind: Kind, name: string, content: Record<string, unknown>, opts: { agent?: string; ref?: string | null; storeContent?: boolean } = {}): SignedRecord {
    const why = noWrites.getStore();
    if (why) throw new SignafaideError(`${why} must not write records: candidate functions must be side-effect free (it tried to record "${name}")`, { code: "no_writes" });
    const agent = opts.agent || this.defaultAgent;
    if (!AGENT_RE.test(agent)) throw new Error(`agent "${agent}" is invalid: use lowercase letters, digits, '.', '_' or '-' (max 64)`);
    const sc = opts.storeContent ?? this.storeContent;
    const apiKey = this.apiKey;
    let rec: SignedRecord | null = null;
    while (!rec) {
      const bucket = this.writeBucket(apiKey, agent);
      const scope = scopeOf(bucket);
      const key = this.key(agent, scope);
      const chain = `${bucket}/${agent}`;
      if (!fs.existsSync(this.state.chainPath(chain))) for (const e of Object.values(this.adoptInto(bucket, apiKey))) this.report(`signafaide: ${e.message}`);
      const [project, env] = bucket.split("/") as [string, "test" | "live"];
      // Before the project is known, an envelope cannot name it: keep a draft, signed when it is (§8).
      const build = bucket.startsWith(PENDING + "/")
        ? (seq: number, prev: string | null, prevTime: string | null) => {
            const [time, c] = this.timed(content, prevTime, agent, scope);
            return makeDraft(key, { kind, agent, seq, prev, name, content: c, ref: opts.ref ?? null, time }, sc);
          }
        : (seq: number, prev: string | null, prevTime: string | null) => {
            const [time, c] = this.timed(content, prevTime, agent, scope);
            return makeRecord(key, { kind, project, env, agent, seq, prev, name, content: c, ref: this.state.translateRef(chain, opts.ref), time });
          };
      rec = this.state.append(chain, build, (r) => wireRecord(r, sc), () => this.writeBucket(apiKey, agent) === bucket);
    }
    this.pending++;
    this.exitFlushed = false;
    if (name !== INSTANCE_STOP) this.wrote.add(agent);
    if (!apiKey && !this.toldLocal && !this.quiet && !this.test) {
      this.toldLocal = true;
      console.error(
        `signafaide: recording locally in ${this.state.home} (signed and chained; no API key, so nothing is sent). ` +
          "Run `npx signafaide init` to send hashes for co-signature and public timestamps, or set SIGNAFAIDE_API_KEY.",
      );
    }
    this.start();
    if (this.pending >= this.flushSize) void this.tick(); // honours the backoff and the one flush in flight
    return rec;
  }

  /** Where `agent`'s next record goes. A known project whose chain for `agent` is not on this
   * disk (an empty `SIGNAFAIDE_HOME` on Lambda or Cloud Run) may already have that chain on the
   * witness, so the record is a draft until the shipper has asked for the witness's head and
   * continues after it (§8). Writing never waits for the network. */
  private writeBucket(apiKey: string | undefined, agent: string): string {
    const bucket = this.state.bucket(apiKey);
    if (!apiKey || bucket.startsWith(PENDING + "/") || fs.existsSync(this.state.chainPath(`${bucket}/${agent}`))) return bucket;
    // Drafts already written for this agent before the key was set continue in place.
    const nokey = `${PENDING}/nokey`;
    return fs.existsSync(this.state.chainPath(`${nokey}/${agent}`)) ? nokey : `${PENDING}/${keyFingerprint(apiKey)}`;
  }

  /** Move pending chains (written before the project was known) under `bucket`. Returns the
   * chains that stay pending, with why (chain id -> error). `bases`: agent -> the service's head,
   * for a chain whose local file is gone (an ephemeral disk): its drafts continue after it. */
  private adoptInto(bucket: string, apiKey: string | undefined, bases: Record<string, Base> = {}): Record<string, SignafaideError> {
    const out: Record<string, SignafaideError> = {};
    if (bucket.startsWith(PENDING + "/")) return out;
    const sources = [`${PENDING}/nokey`];
    if (apiKey) sources.push(`${PENDING}/${keyFingerprint(apiKey)}`);
    // §2.4: a key's valid_from is at most 7 days before its registration, so the service accepts
    // records written up to 7 days (less an hour of margin) before they are sent.
    const notBefore = new Date(Date.now() - KEY_MAX_AGE_MS).toISOString();
    const scope = scopeOf(bucket);
    for (const src of sources) {
      for (const [chain, why] of this.state.adopt(src, bucket, (a, first) => this.key(a, scope, first), (r) => wireRecord(r, this.storeContent), notBefore, bases)) {
        const msg =
          why === "exists"
            ? `${chain} cannot join ${bucket}, which already has that agent's chain; it stays pending (local only) and still verifies with \`signafaide verify\``
            : `${chain} starts at ${why}, more than 7 days ago: the service accepts records up to 7 days old (§2.4), so this chain stays local; it still verifies with \`signafaide verify\`. New records of that agent start a new chain under ${bucket}`;
        out[chain] = new SignafaideError(msg, { code: why === "exists" ? "chain_exists" : "too_old" });
      }
    }
    return out;
  }

  /** The service's heads for pending agents that have no local chain under `bucket` yet (an
   * ephemeral disk lost it): their drafts continue the service's chain instead of conflicting. */
  private async remoteBases(bucket: string, apiKey: string): Promise<Record<string, Base>> {
    const out: Record<string, Base> = {};
    const agents = new Set<string>();
    for (const c of this.state.chains()) {
      if (!c.startsWith(`${PENDING}/nokey/`) && !c.startsWith(`${PENDING}/${keyFingerprint(apiKey)}/`)) continue;
      const a = c.split("/")[2];
      if (!fs.existsSync(this.state.chainPath(`${bucket}/${a}`))) agents.add(a);
    }
    const client = this.client(10_000, apiKey);
    for (const a of agents) {
      try {
        const sh = await client.head(a);
        const h = sh?.head;
        if (h && Number.isInteger(h.seq) && h.seq > 0 && /^[0-9a-f]{64}$/.test(h.record_hash) && `${h.project}/${h.env}` === bucket && h.agent === a) {
          out[a] = { seq: h.seq, record_hash: h.record_hash, signed: { head: h, head_sig: sh.head_sig } };
          // Is the head's record the earlier instance's stop note (a clean restart, §8)? When the
          // witness cannot say, the start note says "unknown" and counts as one with no stop.
          try {
            const got = (await client.record(h.record_hash))?.record;
            if (isStopNote(got, a, h.record_hash)) out[a].stop = { envelope: got.envelope, key_id: got.key_id, sig: got.sig };
          } catch (e) {
            if (!(e instanceof SignafaideError)) throw e;
          }
        }
      } catch (e) {
        // No head (no records yet) or no agent at all (not registered yet): the chain starts at
        // seq 1; the shipper registers the key first (§2.4).
        const code = (e as SignafaideError).code;
        if (code !== "not_found" && code !== "unknown_agent") throw e;
      }
    }
    return out;
  }

  // --- shipping -------------------------------------------------------------------

  /** Run shipping work one at a time in this process. */
  private serial<T>(mode: IoMode, fn: () => Promise<T>): Promise<T> {
    const run = this.shipping.then(async () => {
      this.ioMode = mode;
      try {
        return await fn();
      } finally {
        this.ioMode = "fg";
      }
    });
    this.shipping = run.catch(() => undefined);
    return run;
  }

  /** A label for errors that are about the API key, not a chain. */
  private keyLabel(apiKey: string): string {
    return `API key ${apiKey.slice(0, 13)}...`;
  }

  /** Ship the outbox of this API key's project now. `errors` maps chain id (or the API key, for
   * errors about the key) to the one-sentence fix. Records of other projects (an earlier key)
   * wait for that key. An explicit flush always tries, even after a refusal. */
  flush(timeoutMs = 10_000, mode: IoMode = "fg"): Promise<FlushResult> {
    if (mode === "fg") {
      this.halted = undefined;
      this.blocked.clear();
    }
    return this.serial(mode, async () => {
      let shipped = 0;
      const errors: Record<string, SignafaideError> = {};
      if (!this.state.outboxSize() && !this.state.hasDrafts()) return { shipped, left: 0, errors };
      // Local-first: with no API key nothing is sent and no sandbox is created. A human opts in
      // with `signafaide init` or by setting SIGNAFAIDE_API_KEY.
      const key = this.apiKey;
      if (!key) return { shipped, left: this.waiting(), errors };
      const apiKey: string = key;
      let bases: Record<string, Base> = {};
      try {
        await this.resolveProject(apiKey);
        const bucket = this.state.bucket(apiKey);
        if (this.state.hasDrafts()) bases = await this.remoteBases(bucket, apiKey);
      } catch (e) {
        if (!(e instanceof SignafaideError) && !(e instanceof StateError)) throw e;
        const err = e instanceof SignafaideError ? e : new SignafaideError((e as Error).message, { code: "state" });
        return { shipped, left: this.waiting(), errors: { [this.keyLabel(apiKey)]: err } };
      }
      const done = new Set<string>();
      for (;;) {
        const bucket = this.state.bucket(apiKey);
        Object.assign(errors, this.adoptInto(bucket, apiKey, bases));
        bases = {};
        const next = this.state.outboxChains(bucket).find((c) => !done.has(c));
        if (!next) break;
        done.add(next);
        try {
          shipped += (await this.shipChain(next, apiKey, timeoutMs)).size;
        } catch (e) {
          if (!(e instanceof SignafaideError)) throw e;
          const projectWide = e.retryable || e.code === "invalid_key" || e.code === "quota_exceeded" || e.code === "plan_required";
          errors[e.code === "invalid_key" ? this.keyLabel(apiKey) : next] = e;
          if (projectWide) break; // same for every chain
        }
      }
      return { shipped, left: this.waiting(), errors };
    });
  }

  /** A clean stop (§8): ship everything, then write and ship a signed stop note for each agent
   * this process wrote records for. The next instance's start right after it is a clean restart,
   * with no "earlier unsent records are not known" warning. Nothing is written while any record
   * is still unsent (the next start then carries the warning, as it should). Call it in the
   * shutdown handler of an ephemeral container (SIGTERM); a program that ends by itself with a
   * head file set does it at exit. */
  async stop(timeoutMs = 10_000, mode: IoMode = "fg"): Promise<StopResult> {
    const first = await this.flush(timeoutMs, mode);
    const apiKey = this.apiKey;
    const stopped: string[] = [];
    if (this.test || !apiKey || first.left || Object.keys(first.errors).length) return { ...first, stopped };
    const bucket = this.state.bucket(apiKey);
    if (bucket.startsWith(PENDING + "/")) return { ...first, stopped };
    for (const agent of [...this.wrote].sort()) {
      const chain = `${bucket}/${agent}`;
      const last = this.state.lastRecord(chain);
      if (!last || !("receipt" in last) || (last.envelope.kind === "note" && last.envelope.name === INSTANCE_STOP)) continue;
      this.write("note", INSTANCE_STOP, instanceStopContent(last.envelope.seq, recordHash(last)), { agent });
      stopped.push(chain);
    }
    this.wrote.clear();
    if (!stopped.length) return { ...first, stopped };
    const second = await this.flush(timeoutMs, mode);
    return { shipped: first.shipped + second.shipped, left: second.left, errors: second.errors, stopped: second.left ? [] : stopped };
  }

  /** One stderr line, the first time a strict tool is refused in this process (frameworks often
   * swallow the tool's error): the tool, why, and the fix. */
  warnStrictRefused(tool: string, err: SignafaideError): void {
    if (this.toldStrict) return;
    this.toldStrict = true;
    const fix =
      err.code === "no_key"
        ? "there is no API key, and strict mode needs the witness's receipt. Fix: run `npx signafaide init` (a free sandbox) or set SIGNAFAIDE_API_KEY, or drop strict for this tool"
        : err.message;
    console.warn(`signafaide: WARNING strict tool "${tool}" was refused and did not run (${err.code}): ${fix}. Later strict refusals in this process are not printed again.`);
  }

  /** Strict mode: ship `rec`'s chain now and return its receipt, or throw. */
  ensureReceipt(rec: SignedRecord, timeoutMs = 10_000): Promise<Receipt> {
    this.strictUsed = true;
    return this.serial("fg", async () => {
      const apiKey = this.apiKey;
      if (!apiKey) {
        throw new SignafaideError(
          "Strict mode needs the service's receipt, and there is no API key: run `npx signafaide init` (a free sandbox) or set SIGNAFAIDE_API_KEY.",
          { code: "no_key" },
        );
      }
      await this.resolveProject(apiKey);
      const bucket = this.state.bucket(apiKey);
      this.adoptInto(bucket, apiKey, this.state.hasDrafts() ? await this.remoteBases(bucket, apiKey) : {});
      const h = this.state.translateRef(`${bucket}/${rec.envelope.agent}`, recordHash(rec))!; // a draft is signed by now
      const got = (await this.shipChain(`${bucket}/${rec.envelope.agent}`, apiKey, timeoutMs)).get(h);
      if (!got) throw new SignafaideError(`The service did not return a receipt for record ${h.slice(0, 12)}; check \`signafaide status\`.`, { code: "not_recorded" });
      this.adoptInto(this.state.bucket(apiKey), apiKey);
      return got;
    });
  }

  /** The witness's refusal, in words that say what happened and what to do. */
  private explain(e: SignafaideError, chain: string, keyId: string, current: string): SignafaideError {
    const agent = chain.split("/")[2];
    let msg = `${e.message} (chain ${chain})`;
    if (e.code === "bad_signature" && /revoked|retired/.test(e.message)) {
      const scope = scopeOf(chain.split("/").slice(0, 2).join("/"));
      msg =
        keyId === current
          ? this.state.providedKey(agent, scope)
            ? `${chain}: agent key ${keyId} was revoked, so the witness refuses every record it signs. Put a new key for ${agent} in ${agentKeyEnvName(agent, scope)} (or your key provider), then run \`signafaide repair --agent ${agent}\`: it sets aside the records the revoked key signed after it ended, kept on this machine and still verifiable.`
            : `${chain}: agent key ${keyId} was revoked, so the witness refuses every record it signs. Run \`signafaide repair --agent ${agent}\`: it sets aside the records the revoked key signed after it ended, kept on this machine and still verifiable, and gives the agent a new key.`
          : `${chain}: records signed by agent key ${keyId} after it was revoked or retired cannot be co-signed, and new records wait behind them. Run \`signafaide repair --agent ${agent}\`: it sets them aside (kept on this machine, still verifiable) so the new key's records ship.`;
    } else if (/signafaide repair/.test(e.message)) {
      msg = `${e.message} (chain ${chain})`; // the witness already said what to do
    } else if (/ahead of the service clock|must not be in the future/.test(e.message)) {
      msg = `${e.message} (chain ${chain}). This machine's clock is ahead of the witness's. Fix the clock (NTP); records already written with future times ship once the witness's clock reaches them, or run \`signafaide repair --agent ${agent}\` to set them aside with a fresh key now.`;
    } else if (/not active at|earlier than the time of/.test(e.message)) {
      msg = `${e.message} (chain ${chain}). Run \`signafaide repair --agent ${agent}\`: it sets the records the witness cannot take aside (kept, still verifiable) and starts a new segment with a fresh key.`;
    }
    return new SignafaideError(msg, { code: e.code, status: e.status, docs: e.docs, body: e.body });
  }

  /** Ship one chain's outbox in order. */
  private async shipChain(chain: string, apiKey: string, timeoutMs: number): Promise<Map<string, Receipt>> {
    const agent = chain.split("/")[2];
    const scope = scopeOf(chain.split("/").slice(0, 2).join("/"));
    const received = new Map<string, Receipt>();
    const fp = this.configFp();
    const blocked = this.blocked.get(chain);
    if (blocked && blocked.fp === fp) throw blocked.err;
    this.blocked.delete(chain);
    const wire = (r: SignedRecord) => wireRecord(r, this.storeContent);
    if (!this.reconciled.has(chain)) {
      this.state.reconcileOutbox(chain, wire);
      this.reconciled.add(chain);
    }
    const client = this.client(timeoutMs, apiKey);
    for (;;) {
      let batch = this.state.outbox(chain, BATCH_MAX);
      if (!batch.length) return received;
      const current = this.key(agent, scope).keyId;
      if (batch[0].key_id !== current) {
        // Records signed before `keys rotate` go first, under the old key: registering the new
        // key retires the old one on the service (§2.4).
        const cut = batch.findIndex((r) => r.key_id === current);
        batch = cut < 0 ? batch : batch.slice(0, cut);
      } else await this.register(client, agent, scope);
      let resp: { receipts: Receipt[]; heads: any[] };
      try {
        try {
          resp = await client.submit(batch);
        } catch (e) {
          if (!(e instanceof SignafaideError) || e.code !== "unknown_agent") throw e;
          this.registered.delete(`${client.apiKey}\n${agent}\n${this.key(agent, scope).keyId}`);
          await this.register(client, agent, scope);
          resp = await client.submit(batch);
        }
      } catch (e) {
        if (!(e instanceof SignafaideError)) throw e;
        let err: SignafaideError;
        if (e.code === "chain_conflict") {
          const head = e.body.error?.head ?? {};
          err = new SignafaideError(
            `${e.message} (chain ${chain}: service head is seq ${head.seq} ${head.record_hash}; local outbox starts at seq ${batch[0].envelope.seq}; ` +
              "nothing was rewritten, run `signafaide verify` and `signafaide status`)",
            { code: e.code, status: e.status, docs: e.docs, body: e.body },
          );
        } else err = e.permanent ? this.explain(e, chain, batch[0].key_id, current) : e;
        if (err.permanent && !["invalid_key", "quota_exceeded", "plan_required"].includes(err.code)) {
          this.blocked.set(chain, { fp, err });
          this.state.setBlocked(chain, { code: err.code, message: err.message, seq: batch[0].envelope.seq });
        }
        throw err;
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
      if (this.onHead && resp.heads?.length) {
        try {
          await this.onHead(resp.heads);
        } catch (e) {
          console.warn(`signafaide: onHead failed (the heads are still in head.json): ${(e as Error).message}`);
        }
      }
      for (const [h, r] of got) received.set(h, r);
      this.pending = 0;
      if (!got.size) throw new SignafaideError("The service accepted the batch but returned no matching receipts.", { code: "no_receipts" });
      this.state.setBlocked(chain, null);
    }
  }

  /** `signafaide keys create`: a new key for `agent` in `env`, registered with the witness under
   * the API key (which must be of that env), writing no record. With `print`, nothing is written
   * here: the key file is returned for a secret store (`SIGNAFAIDE_AGENT_KEY_LIVE_<NAME>` for
   * live). Otherwise it becomes the agent's key file. Refused when the agent already has a key
   * here or from the environment; the witness refuses it when the agent already has an active
   * key there (`keys rotate` on the machine that holds it, or revoke it in the console first). */
  async createKey(agent: string, env: "test" | "live", print: boolean): Promise<{ doc: Record<string, string>; envName: string; file?: string; project: string }> {
    const apiKey = this.apiKey;
    if (!apiKey) throw new SignafaideError("keys create registers the new key with the witness: set SIGNAFAIDE_API_KEY to a key of that env first (a live key from the console for --env live).", { code: "no_key" });
    if (envOf(apiKey) !== env) throw new SignafaideError(`SIGNAFAIDE_API_KEY is a ${envOf(apiKey)} key; --env ${env} needs a ${env} key.`, { code: "invalid_key" });
    const scope: KeyScope = env === "live" ? "live" : "";
    if (this.state.providedKey(agent, scope)) throw new StateError(`agent ${agent} already has a key from ${agentKeyEnvName(agent, scope)} (or a key provider); unset it to make a new one, or use \`signafaide keys rotate\``);
    if (!print && fs.existsSync(this.state.keyPath(agent, scope))) throw new StateError(`agent ${agent} already has a key file (${this.state.keyPath(agent, scope)}); use \`signafaide keys rotate\` to replace it`);
    // The key's project, asked of the witness: with --print nothing is written here, not even
    // the project mapping in config.json.
    const known = this.state.bucket(apiKey);
    let project: string, keyEnv: string;
    if (!known.startsWith(PENDING + "/")) [project, keyEnv] = known.split("/");
    else {
      const resp = await this.client(10_000, apiKey).project();
      if (resp?.env !== env || !validProjectId(resp?.project)) {
        throw new SignafaideError(`The service at ${this.url} answered GET /v1/project with an invalid project or env; check SIGNAFAIDE_URL.`, { code: "bad_response" });
      }
      [project, keyEnv] = [resp.project, resp.env];
      if (!print) this.state.learnProject(apiKey, project, keyEnv);
    }
    const { key, doc } = this.state.newKeyFile(agent);
    const reg = registration(project, keyEnv, agent, doc.public_key, doc.created);
    const h = hashJson(reg);
    let resp;
    try {
      resp = await this.client(10_000, apiKey).registerAgent(agent, doc.public_key, doc.created, key.sign("register", h));
    } catch (e) {
      if (e instanceof SignafaideError && e.code === "bad_signature") {
        throw new SignafaideError(
          `agent ${agent} already has an active key on the witness, so a new one needs the old key's rotation signature: run \`signafaide keys rotate --agent ${agent} --env ${env}\` where that key is, or have an admin revoke it in the console, then run keys create again.`,
          { code: "bad_signature" },
        );
      }
      throw e;
    }
    if (resp?.key_id && resp.key_id !== key.keyId) throw new SignafaideError(`The service registered key ${resp.key_id} for ${agent}, expected ${key.keyId}.`, { code: "key_mismatch" });
    this.registered.add(`${apiKey}\n${agent}\n${key.keyId}`);
    const out = { doc, envName: agentKeyEnvName(agent, scope), project };
    return print ? out : { ...out, file: this.state.saveKeyFile(doc, scope) };
  }

  private async register(client: Client, agent: string, scope: KeyScope): Promise<void> {
    const k = this.key(agent, scope);
    const id = `${client.apiKey}\n${agent}\n${k.keyId}`;
    if (this.registered.has(id)) return;
    // §2.4: the registration with its proof of possession, and a rotation signature by the
    // newest retired key when there is one. valid_from is the key's creation time, kept within
    // the 7 days the service allows, and never after this machine's clock now (a key made while
    // the clock was ahead registers once the clock is right).
    const [project, env] = this.state.bucket(client.apiKey).split("/");
    const nowIso = now();
    const floor = new Date(Date.now() - KEY_MAX_AGE_MS).toISOString().slice(0, 19) + ".000Z";
    const created = this.state.keyCreated(agent, scope) ?? nowIso;
    let validFrom = created > floor ? created : floor;
    if (validFrom > nowIso) validFrom = nowIso;
    const reg = registration(project, env, agent, b64url(k.publicKey), validFrom);
    const h = hashJson(reg);
    const retired = this.state.retiredKeys(agent, scope)[0]?.[0];
    const rotation = retired ? { key_id: retired.keyId, sig: retired.sign("rotate", h) } : undefined;
    let resp;
    try {
      resp = await client.registerAgent(agent, reg.public_key, validFrom, k.sign("register", h), rotation);
    } catch (e) {
      if (e instanceof SignafaideError && e.permanent) throw this.explain(e, `${project}/${env}/${agent}`, k.keyId, k.keyId);
      throw e;
    }
    if (resp?.key_id && resp.key_id !== k.keyId) {
      throw new SignafaideError(`The service registered key ${resp.key_id} for ${agent}, expected ${k.keyId}.`, { code: "key_mismatch" });
    }
    // The service says when it retired the agent's earlier keys: kept for `keys export` (§2.5).
    for (const r of Array.isArray(resp?.retired) ? resp.retired : []) {
      if (r && typeof r.key_id === "string" && typeof r.valid_to === "string") this.state.markRetired(agent, r.key_id, r.valid_to, scope);
    }
    this.registered.add(id);
  }

  // --- background -----------------------------------------------------------------

  private start(): void {
    if (this.closed) return;
    if (!this.timer) {
      this.timer = setInterval(() => void this.tick(), this.flushIntervalMs);
      this.timer.unref?.();
    }
    if (!this.exitHooked && typeof process !== "undefined") {
      this.exitHooked = true;
      process.on("beforeExit", this.onBeforeExit);
      process.on("exit", this.onExit);
    }
  }

  /** One background attempt: never two at once, never inside the backoff, and never after a
   * refusal retrying cannot fix until the configuration (API key, URL, agent keys) changes. */
  private async tick(): Promise<void> {
    if (this.closed || this.inFlight || monotonicMs() < this.nextAttempt) return;
    if (!this.apiKey || !this.waiting()) return; // no key: local only, nothing is sent
    const fp = this.configFp();
    if (this.halted) {
      if (this.halted.fp === fp) return;
      this.halted = undefined;
    }
    this.inFlight = true;
    let r: FlushResult | null;
    try {
      r = await this.flushLogged(10_000, "bg");
    } finally {
      this.inFlight = false;
    }
    const errs = r ? Object.values(r.errors).filter((e) => !LOCAL_CODES.has(e.code)) : [];
    if (r && !errs.length) {
      this.failures = 0;
      this.nextAttempt = 0;
      return;
    }
    const wide = errs.find((e) => e.permanent && ["invalid_key", "quota_exceeded", "plan_required"].includes(e.code));
    if (wide) {
      this.halted = { fp, err: wide };
      this.report(`signafaide: sending stopped until the API key or SIGNAFAIDE_URL changes (\`signafaide flush\` tries again now): ${wide.message}`);
      return;
    }
    this.failures++;
    const base = Math.min(60_000, this.flushIntervalMs * 2 ** this.failures);
    this.nextAttempt = monotonicMs() + base * (0.8 + Math.random() * 0.4);
  }

  private async flushLogged(timeoutMs = 10_000, mode: IoMode = "fg"): Promise<FlushResult | null> {
    // A background attempt cut off at exit (the exit flush takes over) is not a network
    // problem: its abort is never reported as "no answer within 10 s".
    const cut = mode === "bg" ? this.bgAbort.signal : undefined;
    let r: FlushResult;
    try {
      r = await this.flush(timeoutMs, mode);
    } catch (e) {
      if (cut?.aborted) return null;
      this.report(`signafaide: ${(e as Error).message}`);
      return null;
    }
    if (cut?.aborted) return r;
    const errs = Object.entries(r.errors);
    if (errs.length) this.report("signafaide: " + errs.map(([a, e]) => (e.message.includes(a) ? e.message : `${a}: ${e.message}`)).join("; "));
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

  /** The program has nothing left to do: one last attempt, held open at most `exitFlushMs`.
   * Background requests never keep the process alive, so they are cut off here. */
  private onBeforeExit = (): void => {
    const stop = this.instanceStop && this.wrote.size > 0 && !this.test;
    if (this.exitFlushed || !this.exitFlushMs || !this.apiKey || (!this.waiting() && !stop)) return;
    this.exitFlushed = true; // one attempt; beforeExit fires again once it settles
    if (this.halted && this.halted.fp === this.configFp()) return;
    this.bgAbort.abort();
    this.bgAbort = new AbortController();
    const ctrl = new AbortController();
    this.exitAbort = ctrl;
    const timer = setTimeout(() => ctrl.abort(), this.exitFlushMs);
    const done = (): void => {
      clearTimeout(timer);
      this.exitFlushed = true; // a stop note written here does not ask for another attempt
    };
    if (!stop) void this.flushLogged(this.exitFlushMs, "exit").finally(done);
    // A clean exit of an ephemeral instance: the stop note, when everything else was sent.
    else void this.stop(this.exitFlushMs, "exit").then((r) => {
      const errs = Object.entries(r.errors);
      if (errs.length && !ctrl.signal.aborted) this.report("signafaide: " + errs.map(([a, e]) => (e.message.includes(a) ? e.message : `${a}: ${e.message}`)).join("; "));
    }, (e) => {
      if (!ctrl.signal.aborted) this.report(`signafaide: ${(e as Error).message}`);
    }).finally(done);
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
    this.bgAbort.abort();
    if (this.exitHooked) {
      process.off("beforeExit", this.onBeforeExit);
      process.off("exit", this.onExit);
      this.exitHooked = false;
    }
  }

  // --- blocked chains and repair -----------------------------------------------------

  /** Why each chain cannot ship, found on this machine (time going back, a clock ahead, a key
   * used after it ended) or said by the witness (blocked.json). Reads only the records without
   * a receipt. */
  diagnose(): Blocked[] {
    const out: Blocked[] = [];
    const saved = this.state.blocked();
    const nowMs = Date.now();
    for (const chain of this.state.chains()) {
      if (chain.startsWith(PENDING + "/")) continue;
      const agent = chain.split("/")[2];
      const scope = scopeOf(chain.split("/").slice(0, 2).join("/"));
      const tail: SignedRecord[] = [];
      let prevTime: string | null = null;
      for (const [, r] of this.state.reverse(chain)) {
        if (r.receipt) {
          prevTime = r.envelope.time;
          break;
        }
        tail.push(r);
      }
      tail.reverse();
      if (!tail.length) continue;
      const ended = new Map<string, string>();
      for (const [rk] of this.state.retiredKeys(agent, scope)) {
        const t = this.state.retiredAt(agent, rk.keyId, scope);
        if (t) ended.set(rk.keyId, t);
      }
      const created = new Map<string, string>();
      const cur = this.state.loadKey(agent, false, scope);
      const c0 = this.state.keyCreated(agent, scope);
      if (cur && c0) created.set(cur.keyId, c0);
      for (const [rk, c] of this.state.retiredKeys(agent, scope)) created.set(rk.keyId, c);
      const next = `run \`signafaide repair --agent ${agent}\` (sets these records aside, kept and verifiable, and starts a new segment with a fresh key)`;
      const wait = `fix the clock (NTP) and wait until it catches up with these records, which then ship, or run \`signafaide repair --agent ${agent}\` (sets them aside, kept and verifiable, and starts a new segment with a fresh key)`;
      let found: Blocked | null = null;
      for (const r of tail) {
        const t = r.envelope.time;
        const at = (code: string, reason: string): Blocked => ({ chain, seq: r.envelope.seq, code, reason, records: tail.length - tail.indexOf(r), next });
        if (prevTime && t < prevTime) found = at("time_back", `seq ${r.envelope.seq} has time ${t}, earlier than the record before it (${prevTime}): the clock went back while an older SDK was writing`);
        else if (created.has(r.key_id) && t < created.get(r.key_id)!) found = at("before_key", `seq ${r.envelope.seq} has time ${t}, before its key ${r.key_id} was made (${created.get(r.key_id)})`);
        else if (ended.has(r.key_id) && t >= ended.get(r.key_id)!) found = at("key_ended", `seq ${r.envelope.seq} is signed by key ${r.key_id} after it ended at ${ended.get(r.key_id)}`);
        else if (Date.parse(t) > nowMs + MAX_CLOCK_SKEW_MS)
          found = { ...at("clock_ahead", `seq ${r.envelope.seq} has time ${t}, ahead of this machine's clock now: the clock was ahead when it was written`), next: wait };
        if (found) break;
        prevTime = t;
      }
      const w = saved[chain];
      if (!found && w) {
        const first = tail.find((r) => w.seq === null || r.envelope.seq >= w.seq) ?? tail[0];
        // The line goes on with "; <n> records cannot ship": no trailing full stop here.
        const msg = (w.message.startsWith(`${chain}: `) ? w.message.slice(chain.length + 2) : w.message).replace(/[\s.]+$/, "");
        const ahead = /ahead of the service clock|must not be in the future/.test(msg);
        found = { chain, seq: first.envelope.seq, code: w.code, reason: `refused by the witness: ${msg}`, records: tail.length - tail.indexOf(first), next: ahead ? wait : next };
      }
      if (found) out.push(found);
    }
    return out;
  }

  /** `signafaide repair`: for each blocked chain (of `agent`, or every agent), set the records
   * from the first one that cannot ship aside into `held/` (kept, still verifiable locally), give
   * the agent a new key (rotation, §2.4), and write a `note` named `signafaide.repair` that
   * commits to the held records' hashes, so the new segment's first co-signed record fixes them
   * in time. Co-signed records are never touched. */
  repair(opts: { agent?: string; dryRun?: boolean } = {}): { chain: string; blocked: Blocked; held?: string; records?: number; newKey?: string; note?: string }[] {
    const out: { chain: string; blocked: Blocked; held?: string; records?: number; newKey?: string; note?: string }[] = [];
    for (const b of this.diagnose()) {
      const agent = b.chain.split("/")[2];
      if (opts.agent && agent !== opts.agent) continue;
      if (opts.dryRun) {
        out.push({ chain: b.chain, blocked: b });
        continue;
      }
      const bucket = b.chain.split("/").slice(0, 2).join("/");
      const scope = scopeOf(bucket);
      const { file, records } = this.state.holdTail(b.chain, b.seq);
      let newKey: string | undefined;
      if (!this.state.providedKey(agent, scope)) newKey = this.state.rotateKey(agent, scope)[1].keyId;
      this.keys.delete(`${agent}\n${scope}`);
      const content = {
        held: path.relative(this.state.home, file),
        from_seq: records[0].envelope.seq,
        to_seq: records[records.length - 1].envelope.seq,
        records: records.length,
        records_hash: hashJson(records.map((r) => recordHash(r))),
        code: b.code,
        reason: b.reason,
      };
      const [project, env] = bucket.split("/") as [string, "test" | "live"];
      const key = this.key(agent, scope);
      const note = this.state.append(
        b.chain,
        (seq, prev, prevTime) => {
          const [time, c] = this.timed(content, prevTime, agent, scope);
          return makeRecord(key, { kind: "note", project, env, agent, seq, prev, name: "signafaide.repair", content: c, ref: null, time });
        },
        (r) => wireRecord(r, this.storeContent),
      )!;
      this.state.setBlocked(b.chain, null);
      this.blocked.delete(b.chain);
      this.halted = undefined;
      out.push({ chain: b.chain, blocked: b, held: file, records: records.length, newKey, note: recordHash(note) });
    }
    return out;
  }

  // --- status ---------------------------------------------------------------------

  status() {
    const heads = this.state.chainHeads();
    const bucket = this.state.bucket(this.apiKey);
    const blocked = new Map(this.diagnose().map((b) => [b.chain, b]));
    const chains = this.state.chains().map((chain) => {
      const agent = chain.split("/")[2];
      const h = heads[chain]?.head;
      const scope = scopeOf(chain.split("/").slice(0, 2).join("/"));
      return {
        chain,
        agent,
        current: chain.startsWith(bucket + "/"),
        key_id: this.state.loadKey(agent, false, scope)?.keyId ?? null,
        records: this.state.tail(chain)[0],
        waiting: this.state.outboxSize(chain),
        receipt_seq: h?.seq ?? null,
        receipt_time: h?.server_time ?? null,
        blocked: blocked.get(chain) ?? null,
      };
    });
    const held = this.state.heldSegments().map(([chain, file, recs]) => ({ chain, file, records: recs.length }));
    const key = this.apiKey;
    return {
      url: this.url,
      home: this.state.home,
      api_key: key ?? null,
      api_key_invalid: !key && !!this.rawApiKey && !this.test,
      test_mode: this.test,
      env: envOf(key),
      bucket,
      sandbox: this.state.sandbox(),
      chains,
      held,
      // Drafts wait too: for the project, or for the witness's head of a chain new to this disk.
      outbox: this.waiting(),
    };
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

/** The Terms and Privacy notice links from a `POST /v1/sandbox` answer (or `sandbox.json`); a
 * service that sends none (or anything but an http(s) URL) gets `<url>/legal/terms` and `/legal/privacy`. */
export function legalLinks(resp: { terms_url?: unknown; privacy_url?: unknown }, url: string): { terms_url: string; privacy_url: string } {
  const ok = (v: unknown): v is string => typeof v === "string" && v.length <= 300 && /^https?:\/\/[^\s]+$/.test(v);
  const base = url.replace(/\/+$/, "");
  return { terms_url: ok(resp.terms_url) ? resp.terms_url : `${base}/legal/terms`, privacy_url: ok(resp.privacy_url) ? resp.privacy_url : `${base}/legal/privacy` };
}

/** The one line shown when a sandbox is created. */
export function termsNotice(l: { terms_url: string; privacy_url: string }): string {
  return `By creating a sandbox you agree to the signafAIde Terms (${l.terms_url}) and Privacy notice (${l.privacy_url}).`;
}
