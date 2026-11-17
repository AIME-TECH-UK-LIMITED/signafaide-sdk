/**
 * Tool-call checks in a running program (SPEC §8): the checks file and its live reload, the held
 * rule set and shared fingerprint list (fetched every 60 s, kept offline), local tool approvals,
 * the decision checks of a call, and the witness's ruling on a strict call. Node only.
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as C from "./checks.js";
import { declaredName } from "./coverage.js";
import { hashJson, newSalt, verifySig } from "./crypto.js";
import { Client, DEFAULT_URL, SignafaideError } from "./http.js";
import { canonicalBytes, canonicalize } from "./jcs.js";
import { nodeTransport } from "./nodehttp.js";
import { now, type Receipt, type SignedRecord } from "./records.js";
import { monotonicMs } from "./state.js";
import type { Recorder } from "./runtime.js";

type Json = Record<string, any>;

export const CHECKS_FILE = "signafaide.checks.json";

/** The public keys of the default witness (`DEFAULT_URL`), shipped with the SDK and pinned: with
 * the default URL, rule sets, the shared list and rulings verify with these keys only, and a key
 * set fetched from the network is never used (§8). A new key reaches clients with an SDK release. */
export const DEFAULT_SERVICE_KEYS: readonly C.ServiceKey[] = Object.freeze([
  { key_id: "7eb0111937aeef44", public_key: "Z0rlIr0TTqeoJM36r51U3qMO_5fsp2Jk8sMfkeNQAl8", valid_from: "2026-11-14T17:36:24.017Z", valid_to: null },
]);

/** Declared names of plain synchronous functions wrapped in this process (`record(fn)` without
 * `strict`): their callers do not wait, so the checks file cannot make them strict (§8, JS). */
const SYNC_TOOLS = new Set<string>();

/** @internal A plain synchronous function was wrapped under `name`. */
export function registerSyncTool(name: string): void {
  SYNC_TOOLS.add(declaredName(name));
}

/** @internal Forget the wrapped synchronous functions (tests). */
export function resetSyncTools(): void {
  SYNC_TOOLS.clear();
}

/** Why the checks file may not make `tool` strict: it is a plain synchronous function. */
export function syncStrictMessage(tool: string, file: string): string {
  return (
    `${tool} is a synchronous function, and ${file} makes it strict: a strict call waits for the witness's ruling, which a synchronous function's callers cannot await. ` +
    `Make the function async, or make it strict in code (record(fn, { strict: true }) returns an async function), or remove "strict": true for ${tool} from the checks file`
  );
}

/** A tool call that did not run: `blocked` (a check or the witness's ruling), `no_ruling`,
 * `rules_unavailable`, `no_key` (strict without a key) or `state` (the checks file is invalid).
 * `check`, `rule`, `rulesVersion` and `missing` say what to change. */
export class CheckError extends SignafaideError {
  override name = "CheckError";
  readonly check?: string;
  readonly rule?: string;
  readonly rulesVersion?: number;
  readonly missing: string[];

  constructor(message: string, code: string, opts: { check?: string; rule?: string | null; rulesVersion?: number | null; missing?: string[] } = {}) {
    super(message, { code });
    this.check = opts.check;
    this.rule = opts.rule ?? undefined;
    this.rulesVersion = opts.rulesVersion ?? undefined;
    this.missing = [...(opts.missing ?? [])];
  }
}

/** What the agent is shown of a tool (§11.1): its whole name, description, input schema and the
 * MCP server's `serverInfo` (none for a tool that does not come from one). */
export interface ToolInfo {
  name: string;
  description?: string | null;
  inputSchema?: unknown;
  serverInfo?: { name?: unknown; version?: unknown } | null;
}

/** The decision checks of one call (§8 steps 1 and 2). */
export interface Plan {
  checks: Json;
  strict: boolean;
  fail: "open" | "closed" | null;
  timeoutMs: number;
  disclosed?: Record<string, unknown>;
  disclosedSalt?: string;
  /** The first entry that blocks the call, with the words of its error. */
  blocked: CheckError | null;
  rulesVersion: number | null;
  /** Fields the held rule set needs for this call that the tool's `disclose` does not list. */
  notDisclosed: string[];
  /** The tool's declared name (§2.6), as the checks name it. */
  declared?: string;
  /** The checks file's `fail` for the tool, when it sets one. */
  fileFail?: "open" | "closed" | null;
}

export interface PlanOptions {
  /** Strict by code: a wrapper's strict mode, the gateway's `--strict` or `--strict-tools`. */
  strictCode?: boolean;
  /** The tool call id the framework gave the call, or the JSON-RPC id of an MCP call. */
  callId?: unknown;
  /** The OpenTelemetry plug-in: never blocks (every entry in watch mode, never strict). */
  telemetry?: boolean;
  /** A plain synchronous function (JS): the checks file cannot make it strict (§8). */
  syncOnly?: boolean;
  /** The declared name (§2.6) when it is not the tool's own name cut (a gateway's prefix). */
  declared?: string;
}

/** The checks file: `SIGNAFAIDE_CHECKS` names another, `SIGNAFAIDE_CHECKS=0` turns checks off. */
export function checksPath(root: string): string | null {
  const v = (process.env.SIGNAFAIDE_CHECKS ?? "").trim();
  if (/^(0|false|off|no)$/i.test(v)) return null;
  return v ? path.resolve(v) : path.join(root, CHECKS_FILE);
}

/** Pretty JSON with sorted keys, as the Python SDK writes these files. */
function pretty(value: unknown): string {
  const sortDeep = (v: unknown): unknown =>
    Array.isArray(v) ? v.map(sortDeep) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep((v as Json)[k])])) : v;
  return JSON.stringify(sortDeep(value), null, 2) + "\n";
}

function writeAtomic(p: string, text: string): void {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p + ".tmp", text);
  fs.renameSync(p + ".tmp", p);
}

function readJson(p: string): any {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function age(at: unknown): string {
  const t = typeof at === "string" ? Date.parse(at) : NaN;
  if (Number.isNaN(t)) return "unknown age";
  const s = Math.floor((Date.now() - t) / 1000);
  return s < 120 ? `${s} s old` : s < 7200 ? `${Math.floor(s / 60)} min old` : `${Math.floor(s / 3600)} h old`;
}

const LISTED = new WeakMap<object, ReadonlySet<string>>();
const HASHES = new WeakMap<object, string>();
/** `hashJson` of a rule set or local rules, made once for each parsed copy. */
function hashOf(doc: Json): string {
  let h = HASHES.get(doc);
  if (!h) HASHES.set(doc, (h = hashJson(doc)));
  return h;
}

const isObj = (x: unknown): x is Json => !!x && typeof x === "object" && !Array.isArray(x);

/** A name's addresses, looked up synchronously (the `address` check with `resolve: true` runs
 * inside a call that may be synchronous). [] when it does not resolve within 5 s. */
export function lookupSync(host: string): string[] {
  const script = "require('dns').lookup(process.argv[1],{all:true},(e,a)=>process.stdout.write(JSON.stringify(e?[]:a.map(x=>x.address))))";
  const r = spawnSync(process.execPath, ["-e", script, host], { encoding: "utf8", timeout: 5000, windowsHide: true });
  try {
    const out = JSON.parse(r.stdout || "[]");
    return Array.isArray(out) ? out.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}

/** One recorder's tool-call checks. */
export class ChecksState {
  /** What went wrong with the file, a fetched rule set or list update: name -> message. */
  readonly problems: Record<string, string> = {};
  private held: { path: string; stamp: string; doc: Json } | null = null;
  /** The file is invalid and no good version is in force. */
  private fileError: string | null = null;
  private told: string | null = null;
  private looked = -Infinity;
  /** The last fetch said the project has no rule set (§8, a strict call's fail mode). */
  private noRuleSet = false;
  private timer?: ReturnType<typeof setInterval>;
  private refreshing: Promise<void> | null = null;
  private again = false;

  constructor(private readonly rec: Recorder) {}

  // --- the checks file ----------------------------------------------------------------

  get home(): string {
    return path.join(this.rec.state.home, "checks");
  }

  path(): string | null {
    return checksPath(this.rec.state.root);
  }

  /** @internal Look at the file again at the next call (tests). */
  forget(): void {
    this.looked = -Infinity;
  }

  /** The checks file in force, or null when checks are off. Looked at at most once a second; a
   * broken edit keeps the previous version in force and prints one error line. A file that is
   * invalid with no earlier version in force throws `state`. */
  file(): Json | null {
    const p = this.path();
    if (p === null) return null;
    const t = monotonicMs();
    if (this.held && this.held.path === p && t - this.looked < 1000) return this.held.doc;
    if (!this.held && this.fileError !== null && t - this.looked < 1000) throw new CheckError(this.fileError, "state");
    this.looked = t;
    let st: fs.BigIntStats;
    try {
      st = fs.statSync(p, { bigint: true });
    } catch {
      this.held = null;
      this.fileError = null;
      delete this.problems.file;
      return null;
    }
    // inode, size and modification time, as the other held files: a file replaced within one
    // clock tick by another of the same size is still seen as changed.
    const stamp = `${st.ino}:${st.size}:${st.mtimeNs}`;
    if (this.held && this.held.path === p && this.held.stamp === stamp) return this.held.doc;
    let doc: unknown = null;
    let err: string | null;
    try {
      doc = JSON.parse(fs.readFileSync(p, "utf8"));
      err = C.checksFileErrors(doc);
    } catch (e) {
      err = `not valid JSON (${(e as Error).message})`;
    }
    // A new version that makes a plain synchronous function strict is refused like a broken edit
    // when a version is in force (§8, JS): its callers cannot wait for a ruling.
    const syncStrict = err === null && this.held && this.held.path === p ? [...SYNC_TOOLS].sort().find((t) => (doc as Json).tools[t]?.strict === true) : undefined;
    if (syncStrict) err = syncStrictMessage(syncStrict, p);
    if (err === null) {
      this.held = { path: p, stamp, doc: doc as Json };
      this.fileError = null;
      delete this.problems.file;
      this.told = null;
      return doc as Json;
    }
    const msg = `the checks file ${p} is invalid: ${err}`;
    this.problems.file = msg;
    if (this.held && this.held.path === p) {
      if (this.told !== msg) {
        this.told = msg;
        console.error(`signafaide: ${msg}; the previous version stays in force until it is fixed`);
      }
      return this.held.doc;
    }
    this.fileError = `${msg} (spec §8); fix it, or set SIGNAFAIDE_CHECKS=0 to turn checks off`;
    throw new CheckError(this.fileError, "state");
  }

  /** Whether checks are on: a checks file exists (valid or not). */
  enabled(): boolean {
    const p = this.path();
    return p !== null && fs.existsSync(p);
  }

  // --- held state ---------------------------------------------------------------------

  projectEnv(): [string, string] | null {
    const apiKey = this.rec.apiKey;
    if (!apiKey) return null;
    const bucket = this.rec.state.bucket(apiKey);
    if (bucket.startsWith("_pending/")) return null;
    const [p, e] = bucket.split("/");
    return [p, e];
  }

  /** `load()` for the file at `p`, kept until the file changes (its inode, size or modification time): a call
   * costs one `stat`, not a read, a parse and a check of everything the file holds. Not kept when `load`
   * returns null. */
  private stamped<T>(p: string, load: () => T | null, extra = ""): T | null {
    let stamp: string;
    try {
      const st = fs.statSync(p, { bigint: true });
      stamp = `${st.ino}:${st.size}:${st.mtimeNs}:${extra}`;
    } catch {
      this.cache.delete(p);
      return load();
    }
    const hit = this.cache.get(p);
    if (hit && hit.stamp === stamp) return hit.value as T;
    const value = load();
    if (value === null) this.cache.delete(p);
    else this.cache.set(p, { stamp, value });
    return value;
  }

  private readonly cache = new Map<string, { stamp: string; value: unknown }>();

  /** Whether the witness is the default one, whose keys are pinned (`DEFAULT_SERVICE_KEYS`). */
  private pinned(): boolean {
    return this.rec.url === DEFAULT_URL;
  }

  /** The witness's service keys (§5): the pinned ones for the default witness, else the ones held
   * in `checks/keys.json` for the witness's URL (none when they were fetched from another). */
  serviceKeys(): C.ServiceKey[] {
    if (this.pinned()) return [...DEFAULT_SERVICE_KEYS];
    const url = this.rec.url;
    return (
      this.stamped(
        path.join(this.home, "keys.json"),
        () => {
          const doc = readJson(path.join(this.home, "keys.json"));
          if (!isObj(doc) || !Array.isArray(doc.keys)) return null;
          // A file from before the URL was kept holds the keys of the witness in use then.
          return doc.url === undefined || doc.url === url ? (doc.keys as C.ServiceKey[]) : [];
        },
        url,
      ) ?? []
    );
  }

  private rulesPath(pe: [string, string]): string {
    return path.join(this.home, "rules", pe[0], `${pe[1]}.json`);
  }

  /** The held rule set version `{rules, sig, service_key_id}` (§8), checked again by §10.2 steps 1
   * to 3; null when none is held or it fails (it is then fetched again). */
  heldRulesItem(): Json | null {
    const pe = this.projectEnv();
    if (!pe) return null;
    const p = this.rulesPath(pe);
    const keys = path.join(this.home, "keys.json");
    let stamp = "";
    try {
      const st = fs.statSync(keys, { bigint: true });
      stamp = `${st.ino}:${st.size}:${st.mtimeNs}`;
    } catch {
      /* no keys held: nothing verifies */
    }
    // The signature check runs again only when the rule set file or the service keys change.
    const item = this.stamped(
      p,
      () => {
        const doc = readJson(p);
        return doc !== null && C.acceptRules(null, doc, this.serviceKeys(), pe[0], pe[1]) === null ? doc : null;
      },
      stamp,
    );
    if (item === null && readJson(p) !== null) this.wake();
    return item;
  }

  /** The pairs of a held list as a set, made once for each version of the list read. */
  private listed(held: C.HeldList): ReadonlySet<string> {
    let s = LISTED.get(held);
    if (!s) LISTED.set(held, (s = C.listedSet(held.entries)));
    return s;
  }

  heldRules(): Json | null {
    return this.heldRulesItem()?.rules ?? null;
  }

  /** The held shared list `{seq, last, entries}`; null when none is held (or it was dropped). */
  heldList(): C.HeldList | null {
    const p = path.join(this.home, "fingerprints.json");
    return this.stamped(p, () => {
      const doc = readJson(p);
      if (doc === null) return null;
      if (C.heldListErrors(doc)) {
        try {
          fs.unlinkSync(p);
        } catch {
          /* already gone */
        }
        return null;
      }
      return doc;
    });
  }

  private approvedPath(agent: string): string {
    return path.join(this.home, "approved", `${agent}.json`);
  }

  approvals(agent: string): Record<string, Json> {
    const p = this.approvedPath(agent);
    const doc = this.stamped(p, () => {
      const d = readJson(p);
      return isObj(d) ? d : null;
    });
    return doc ? { ...doc } : {}; // a copy: callers edit it, and the file is what changes the cache
  }

  /** A tool's local approval (§8): its fingerprints the first time the client sees it. */
  localApproval(agent: string, name: string, fps: C.ToolFingerprints): Json {
    const have = this.approvals(agent)[name];
    if (isObj(have) && "description" in have && "schema" in have) return have;
    const p = this.approvedPath(agent);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    return this.rec.state.lockAt(p.replace(/\.json$/, ".lock"), () => {
      const doc = this.approvals(agent);
      if (!(name in doc)) {
        doc[name] = { description: fps.description, schema: fps.schema, at: now() };
        writeAtomic(p, pretty(doc));
      }
      return doc[name];
    });
  }

  /** `signafaide checks approve <tool>`: drop the tool's local approval, so its next call approves
   * the description and schema it has then. Returns the agents it was dropped for. */
  approve(name: string, agent?: string): string[] {
    const dir = path.join(this.home, "approved");
    const agents = agent ? [agent] : fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort() : [];
    const done: string[] = [];
    for (const a of agents) {
      const p = this.approvedPath(a);
      if (!fs.existsSync(p)) continue;
      this.rec.state.lockAt(p.replace(/\.json$/, ".lock"), () => {
        const doc = this.approvals(a);
        if (name in doc) {
          delete doc[name];
          writeAtomic(p, pretty(doc));
          done.push(a);
        }
      });
    }
    return done;
  }

  // --- fetching (§8, §10.2, §11.2) ----------------------------------------------------

  /** A client for the checks' own requests. `hold`: keep the process alive until it settles (a
   * command); the background refresh never holds a finished program open. */
  private client(hold: boolean): Client {
    return new Client(this.rec.url, this.rec.apiKey, 10_000, this.rec.clientId(), { transport: nodeTransport(() => hold) });
  }

  /** Fetch the rule set and the list now and every 60 s in the background (with an API key). */
  start(): void {
    if (this.rec.test || !this.rec.apiKey || this.timer) return;
    this.timer = setInterval(() => this.wake(), C.RULES_REFRESH_MS);
    this.timer.unref?.();
    this.wake();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** Fetch now (in the background); a fetch already running is followed by one more. */
  wake(): void {
    if (this.rec.test || !this.rec.apiKey) return;
    if (this.refreshing) {
      this.again = true;
      return;
    }
    this.refreshing = this.refresh(false)
      .catch(() => undefined)
      .finally(() => {
        this.refreshing = null;
        if (this.again) {
          this.again = false;
          this.wake();
        }
      });
  }

  /** @internal Wait for the background fetch in flight (tests). */
  async settled(): Promise<void> {
    while (this.refreshing) await this.refreshing;
  }

  async refresh(hold = true): Promise<void> {
    if (!this.rec.apiKey) return;
    for (const [name, fn] of [
      ["rules", () => this.pullRules(hold)],
      ["fingerprints", () => this.pullList(hold)],
    ] as const) {
      try {
        await fn();
      } catch (e) {
        const err = e instanceof SignafaideError ? e : new SignafaideError((e as Error).message);
        if (err.code !== "network" && err.code !== "rate_limited" && err.status < 500) {
          this.problems[name] = `could not fetch the ${name === "rules" ? "rule set" : "shared fingerprint list"}: ${err.message}`;
        }
      }
    }
  }

  /** Fetch the witness's service keys (§5). Never for the default witness: its keys are pinned.
   * A fetched set that drops every key held before for the same witness is refused (a witness
   * rotates by adding a key first), and the keys held stay in force. */
  async pullKeys(hold = true): Promise<C.ServiceKey[]> {
    if (this.pinned()) return [...DEFAULT_SERVICE_KEYS];
    const doc = await this.client(hold).serviceKeys();
    const keys: unknown = isObj(doc) ? doc.keys : undefined;
    if (!Array.isArray(keys) || !keys.every((k) => isObj(k) && typeof k.key_id === "string" && typeof k.public_key === "string")) return this.serviceKeys();
    const before = this.serviceKeys();
    if (before.length && !before.some((b) => keys.some((k) => k.key_id === b.key_id && k.public_key === b.public_key))) {
      this.problems.keys = `bad_response: refused the service keys of ${this.rec.url}: they drop every key held before (spec §8); kept the keys held`;
      return before;
    }
    delete this.problems.keys;
    writeAtomic(path.join(this.home, "keys.json"), pretty({ keys, fetched: now(), url: this.rec.url }));
    return keys as C.ServiceKey[];
  }

  /** Fetch the rule set now (§10.2). Returns what happened, in words. */
  async pullRules(hold = true): Promise<string> {
    const apiKey = this.rec.apiKey;
    if (!apiKey) return "no API key: rule sets need one";
    await this.rec.resolveProject(apiKey);
    const pe = this.projectEnv();
    if (!pe) return "the API key's project is not known yet";
    const held = this.heldRulesItem();
    const item = await this.client(hold).rules(held ? hashJson(held.rules) : null);
    if (item === null) {
      delete this.problems.rules;
      this.noRuleSet = !held;
      return held ? `rule set version ${held.rules.version} is current` : "no rule set";
    }
    if (!isObj(item) || item.rules == null) {
      delete this.problems.rules;
      this.noRuleSet = !held;
      return held ? `kept rule set version ${held.rules.version}` : "the project has no rule set";
    }
    this.noRuleSet = false;
    let keys = this.serviceKeys();
    let err = C.acceptRules(held?.rules ?? null, item, keys, pe[0], pe[1]);
    if (err === "signature") {
      keys = await this.pullKeys(hold);
      err = C.acceptRules(held?.rules ?? null, item, keys, pe[0], pe[1]);
    }
    if (err !== null) {
      const v = isObj(item.rules) ? item.rules.version : "?";
      this.problems.rules = `bad_response: refused rule set version ${v} at step ${err} (spec §10.2); kept the version held`;
      return this.problems.rules;
    }
    writeAtomic(this.rulesPath(pe), canonicalize({ rules: item.rules, sig: item.sig, service_key_id: item.service_key_id }));
    writeAtomic(path.join(this.home, "rules", pe[0], `${pe[1]}.at.json`), pretty({ fetched: now() }));
    delete this.problems.rules;
    return `rule set version ${item.rules.version}`;
  }

  /** Fetch the shared fingerprint list now (§11.2). */
  async pullList(hold = true): Promise<string> {
    if (!this.rec.apiKey) return "no API key: the shared list needs one";
    const held = this.heldList();
    let cur = held ?? C.emptyList();
    const client = this.client(hold);
    let keys = this.serviceKeys();
    if (!keys.length) keys = await this.pullKeys(hold);
    let since: number | null = held ? held.seq : null;
    for (let round = 0; round < 100; round++) {
      const resp = await client.fingerprints(since);
      const updates: unknown[] = isObj(resp) && Array.isArray(resp.updates) ? resp.updates : [];
      const items = [...(isObj(resp) && resp.snapshot ? [resp.snapshot] : []), ...updates];
      let gap = false;
      for (const it of items) {
        let [next, err] = C.applyList(cur, it, keys);
        if (err === "signature") {
          keys = await this.pullKeys(hold);
          [next, err] = C.applyList(cur, it, keys);
        }
        if (err === "gap") {
          gap = true;
          break;
        }
        if (err !== null) {
          this.problems.fingerprints = `bad_response: refused a shared list item at step ${err} (spec §11.2); kept the list held`;
          this.saveList(cur);
          return this.problems.fingerprints;
        }
        cur = next;
      }
      this.saveList(cur);
      if (gap || updates.length >= 1000) {
        since = cur.seq;
        continue;
      }
      break;
    }
    delete this.problems.fingerprints;
    return `shared list seq ${cur.seq}`;
  }

  private saveList(cur: C.HeldList): void {
    writeAtomic(path.join(this.home, "fingerprints.json"), pretty({ seq: cur.seq, last: cur.last, entries: cur.entries }));
    writeAtomic(path.join(this.home, "fingerprints.at.json"), pretty({ fetched: now() }));
  }

  // --- a call (§8) --------------------------------------------------------------------

  witnessHost(): string | null {
    return C.urlHost(this.rec.url);
  }

  /** Steps 1 and 2 of a call (§8): the decision checks on `args`, the `checks` the decision
   * carries, and the values a strict call discloses. Null when checks are off. Throws
   * `CheckError` (`state`) when the checks file is invalid and no good version is in force. */
  plan(tool: ToolInfo, agent: string, args: unknown, opts: PlanOptions = {}): Plan | null {
    const f = this.file();
    if (!f) return null;
    this.start();
    const telemetry = !!opts.telemetry;
    const decl = opts.declared ?? declaredName(tool.name);
    const mode: string = telemetry ? "watch" : f.mode;
    const cfg: Json = f.tools[decl] ?? {};
    if (opts.syncOnly && !opts.strictCode && cfg.strict === true && !telemetry) {
      const msg = `${decl} did not run: ${syncStrictMessage(decl, this.path() ?? CHECKS_FILE)} (spec §8)`;
      this.problems[`strict ${decl}`] = syncStrictMessage(decl, this.path() ?? CHECKS_FILE);
      this.markSyncStrict(decl);
      throw new CheckError(msg, "state");
    }
    const strict = telemetry ? false : !!(opts.strictCode || cfg.strict);
    const rs = this.heldRules();
    const held = this.heldList();
    const fps = C.toolFingerprints(tool.name, tool.description ?? "", tool.inputSchema, tool.serverInfo ?? null);
    const on = f.checks;
    const results: Json[] = [];
    if (on.secret) results.push(C.entry("secret", C.secretFindings(args, this.witnessHost()), mode));
    if (on.address) {
      const hosts = [...f.addresses.hosts, ...(rs ? rs.addresses.hosts : [])];
      const cidrs = [...f.addresses.cidrs, ...(rs ? rs.addresses.cidrs : [])];
      results.push(C.entry("address", C.addressFindings(args, hosts, cidrs, f.addresses.resolve ? lookupSync : undefined), mode));
    }
    if (on.changed_tool) {
      const approved = rs && rs.approved !== null ? (rs.approved[decl] ?? null) : this.localApproval(agent, decl, fps);
      results.push(C.entry("changed_tool", C.changedToolFindings(fps, approved), mode));
    }
    if (on.fingerprint && held) results.push(C.entry("fingerprint", C.fingerprintFindingsIn(fps, this.listed(held), this.excepted(rs)), mode));
    const rulesUsed: Json[] = [];
    if (rs) {
      const m = telemetry ? "watch" : C.entryMode(rs.mode, strict, false);
      results.push(C.clientRuleEntry(rs, m, rs.set, agent, decl, args));
      rulesUsed.push({ set: rs.set, version: rs.version, hash: hashOf(rs) });
    }
    if (f.rules !== null) {
      results.push(C.clientRuleEntry(f.rules, mode, "local", agent, decl, args));
      rulesUsed.push({ set: "local", version: null, hash: hashOf(f.rules) });
    }
    const result = C.combined(results);
    const fail: "open" | "closed" | null = strict ? ((rs ? rs.fail[decl] : undefined) ?? cfg.fail ?? "closed") : null;
    const need = C.neededFields(rs, agent, decl);
    const disclose: string[] = cfg.disclose ?? [];
    const notDisclosed = need.filter((p) => !disclose.includes(p));
    let pointers: string[] = [];
    let values: Record<string, unknown> | undefined;
    let salt: string | undefined;
    if (strict && result !== "block") {
      pointers = need.filter((p) => disclose.includes(p));
      values = {};
      for (const p of pointers) {
        const x = C.resolve(args, p);
        if (x !== C.ABSENT) values[p] = x;
      }
      let tooBig: boolean;
      try {
        tooBig = canonicalBytes(values).length > C.DISCLOSED_MAX_BYTES;
      } catch {
        tooBig = true;
      }
      if (tooBig || !pointers.length) {
        pointers = [];
        values = undefined;
      } else salt = newSalt();
    }
    const cid = opts.callId;
    const callId = (typeof cid === "string" && [...cid].length >= 1 && [...cid].length <= 128) || C.isSafeInt(cid) ? cid : null;
    const checks: Json = {
      results,
      result,
      rules: rulesUsed,
      fingerprints: held ? held.seq : null,
      tool: fps,
      strict,
      fail,
      disclosed: pointers,
      disclosed_hash: pointers.length ? C.disclosedHash(values, salt!) : null,
      call_id: callId,
    };
    const plan: Plan = {
      checks,
      strict,
      fail,
      timeoutMs: f.ruling_timeout_ms ?? C.RULING_TIMEOUT_MS,
      disclosed: pointers.length ? values : undefined,
      disclosedSalt: pointers.length ? salt : undefined,
      blocked: null,
      rulesVersion: rs ? rs.version : null,
      notDisclosed,
      declared: decl,
      fileFail: cfg.fail ?? null,
    };
    if (result === "block") plan.blocked = this.blockError(decl, results.find((e) => e.result === "block")!, rs);
    return plan;
  }

  /** The fingerprints the held rule set excepts from the shared list, made once per version read. */
  private excepted(rs: Json | null): ReadonlySet<string> | undefined {
    if (!rs || !Array.isArray(rs.fingerprint_exceptions)) return undefined;
    let s = LISTED.get(rs.fingerprint_exceptions);
    if (!s) LISTED.set(rs.fingerprint_exceptions, (s = C.exceptedSet(rs)));
    return s;
  }

  /** Keep the tool's name so `signafaide checks status` in another process reports it too. */
  private markSyncStrict(tool: string): void {
    try {
      const p = path.join(this.home, "sync-strict.json");
      const doc = readJson(p);
      const out = isObj(doc) ? doc : {};
      if (out[tool]) return;
      out[tool] = now();
      writeAtomic(p, pretty(out));
    } catch {
      /* the call fails with state all the same */
    }
  }

  private blockError(tool: string, e: Json, rs: Json | null): CheckError {
    const c: string = e.check;
    const v = rs ? rs.version : null;
    if (c === "rule") {
      const rid: string | null = e.matched.length ? e.matched[0] : null;
      const local = e.set === "local";
      const where = local ? "the local rules (checks file)" : `rule set version ${v}`;
      const what = rid ? `rule ${rid} of ${where} blocked it` : `no rule of ${where} allows it, and its default is block`;
      const fix = local ? "change the rule in the checks file" : "change the rule in the console";
      return new CheckError(`${tool} did not run: ${what}. To allow it: ${fix}.`, "blocked", { check: "rule", rule: rid, rulesVersion: local ? null : v });
    }
    const fixes: Record<string, string> = {
      secret: "remove the secret from the call's arguments, or send it only to the service that issued it",
      address: "if the address is meant, add the host to addresses.hosts or addresses.cidrs in the checks file, or to the rule set's allowlist in the console",
      changed_tool: `re-approve the tool: \`signafaide checks approve ${tool}\`, or in the console when the rule set approves tools`,
      fingerprint: "remove or replace the tool: its fingerprint was reported as malicious and accepted after review",
    };
    return new CheckError(`${tool} did not run: the ${c} check found ${e.found.join(", ")}. To allow it: ${fixes[c]}.`, "blocked", { check: c, rulesVersion: v });
  }

  /** Step 4 of a strict call (§8): ship the decision, wait for its receipt up to the ruling
   * timeout, and read the ruling. Returns the outcome's `ruling` (`allow`, `block`, `none`) and
   * the error to throw when the tool must not run. */
  async ruling(d: SignedRecord, plan: Plan, tool: string): Promise<["allow" | "block" | "none", CheckError | null]> {
    const rec = this.rec;
    if (rec.test) return ["none", null]; // test mode sends nothing: strict calls run without a ruling
    let closed = plan.fail !== "open";
    if (!rec.apiKey) {
      const err = new CheckError(
        `${tool} did not run: strict mode needs the witness's ruling, and there is no API key. Run \`npx signafaide init\` (a free sandbox) or set SIGNAFAIDE_API_KEY, or drop strict for this tool.`,
        "no_key",
      );
      return ["none", closed ? err : null];
    }
    let why = "no receipt came";
    let code = "no_ruling";
    let receipt: Receipt | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // No rule set held (a cold start, or its file or the keys file was removed): fetch it now,
    // within the same ruling timeout, so its fail mode is known before the call may run.
    const fetching = !this.heldRules() && !this.noRuleSet ? this.fetchNow() : null;
    const late = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new SignafaideError(`no answer within ${plan.timeoutMs} ms`, { code: "network" })), plan.timeoutMs);
    });
    late.catch(() => undefined);
    try {
      receipt = await Promise.race([rec.ensureReceipt(d, plan.timeoutMs), late]);
    } catch (e) {
      why = `no receipt came within ${plan.timeoutMs} ms (${(e as Error).message})`;
    }
    if (fetching) await Promise.race([fetching, late]).catch(() => undefined);
    clearTimeout(timer);
    closed = this.failClosed(plan);
    if (receipt) {
      const g = receipt.ruling;
      if (g === undefined || g === null) {
        if (receipt.ruling_error === "rules_unavailable") {
          code = "rules_unavailable";
          why = "the witness could not load or sign the project's rule set";
        } else why = "the receipt has no ruling (a witness that does not rule)";
      } else {
        const bad = await this.rulingProblem(receipt);
        if (bad) why = bad;
        else {
          const heldRs = this.heldRules();
          if (isObj(g.rules) && (!heldRs || g.rules.version > heldRs.version)) this.wake(); // a newer version than the one held: fetch it at once (§8)
          if (g.ruling === "allow") return ["allow", null];
          return ["block", this.rulingError(tool, g)];
        }
      }
    }
    const err = new CheckError(
      `${tool} did not run: ${why}, and its fail mode is closed. Check the network and \`signafaide checks status\`, or set "fail": "open" for ${tool} in the checks file (unless the rule set sets it).`,
      code,
    );
    return ["none", closed ? err : null];
  }

  /** Fetch the rule set now (in the background fetcher), and wait for that fetch. */
  private fetchNow(): Promise<void> {
    this.wake();
    return this.settled();
  }

  /** The fail mode of a strict call that has no ruling (§8): the held rule set's for the tool,
   * else the checks file's when the witness said the project has no rule set, else closed. With
   * an API key and no rule set held, nothing local can open it: the rule set the witness holds
   * may say closed. */
  private failClosed(plan: Plan): boolean {
    const rs = this.heldRules();
    const decl = plan.declared;
    if (rs) return ((decl !== undefined ? rs.fail[decl] : undefined) ?? plan.fileFail ?? plan.fail ?? "closed") !== "open";
    if (this.noRuleSet) return plan.fail !== "open";
    return true;
  }

  private async rulingProblem(receipt: Receipt): Promise<string | null> {
    const g = receipt.ruling!;
    const sig = receipt.ruling_sig;
    const err = C.rulingErrors(g);
    if (err) return `the ruling is malformed (${err})`;
    if (g.record_hash !== receipt.record_hash || g.batch_hash !== receipt.batch_hash || g.server_time !== receipt.batch?.server_time) return "the ruling names another record than its receipt";
    let key = this.serviceKeys().find((k) => k.key_id === receipt.service_key_id);
    if (!key) {
      try {
        key = (await this.pullKeys()).find((k) => k.key_id === receipt.service_key_id);
      } catch {
        key = undefined;
      }
    }
    if (!key || typeof sig !== "string" || !verifySig(key.public_key, "ruling", hashJson(g), sig)) return "the ruling's signature does not verify with the witness's keys";
    // The key must be active when the witness ruled: a retired key never signs a new ruling.
    if (!C.keyActive(key, g.server_time)) return `the ruling's service key ${key.key_id} was not active at ${g.server_time}`;
    return null;
  }

  private rulingError(tool: string, g: Json): CheckError {
    const v = isObj(g.rules) ? g.rules.version : null;
    const rule = g.matched.length ? g.matched[0] : null;
    let msg = `${tool} did not run: the witness ruled block (${g.basis}): ${g.reason}`;
    if (g.basis === "fields_missing") msg += ` Add ${g.missing.join(", ")} to the disclose list of ${tool} in the checks file.`;
    return new CheckError(msg, "blocked", { check: ["rule", "error", "default"].includes(g.basis) ? "rule" : g.basis, rule, rulesVersion: v, missing: g.missing });
  }

  /** Step 5 (§8): the result checks of a call that ran (`hidden_instruction`). */
  resultEntries(output: unknown, telemetry = false): Json[] {
    let f: Json | null;
    try {
      f = this.file();
    } catch {
      return [];
    }
    if (!f || !f.checks.hidden_instruction) return [];
    return [C.entry("hidden_instruction", C.hiddenFindings(output), telemetry ? "watch" : f.mode)];
  }

  // --- status (signafaide checks status) ----------------------------------------------

  /** The lines of `signafaide checks status`, and whether there is a problem. */
  status(): [string[], boolean] {
    const lines: string[] = [];
    const p = this.path();
    if (p === null) return [["checks: off (SIGNAFAIDE_CHECKS=0)"], false];
    let f: Json | null;
    try {
      f = this.file();
    } catch (e) {
      return [[`checks: PROBLEM ${(e as Error).message}`], true];
    }
    if (!f) return [[`checks: off (no ${p}; \`signafaide init\` writes one in watch mode)`], false];
    const on = C.FILE_CHECKS.filter((k) => f!.checks[k]);
    lines.push(`checks: on, ${f.mode} mode (${p}); checks on: ${on.join(", ") || "none"}`);
    const item = this.heldRulesItem();
    const rs = item?.rules ?? null;
    const pe = this.projectEnv();
    if (rs) {
      const at = pe ? readJson(path.join(this.home, "rules", pe[0], `${pe[1]}.at.json`))?.fetched : undefined;
      lines.push(`rule set: ${rs.set} version ${rs.version}, ${rs.mode} mode, default ${rs.default}, issued ${rs.issued} (fetched copy ${age(at)})`);
    } else lines.push("rule set: none held" + (this.rec.apiKey ? "" : " (no API key)"));
    const held = this.heldList();
    const at = readJson(path.join(this.home, "fingerprints.at.json"))?.fetched;
    lines.push(held ? `shared fingerprint list: seq ${held.seq}, ${held.entries.length} entries (${age(at)})` : "shared fingerprint list: none held");
    lines.push(`ruling timeout: ${f.ruling_timeout_ms ?? C.RULING_TIMEOUT_MS} ms`);
    const strict = Object.keys(f.tools)
      .filter((n) => f!.tools[n].strict)
      .sort();
    for (const n of strict) {
      const t = f.tools[n];
      const fail = (rs ? rs.fail[n] : undefined) ?? t.fail ?? "closed";
      const disclose: string[] = t.disclose ?? [];
      lines.push(`strict tool ${n}: fail ${fail}; discloses ${disclose.join(", ") || "no field"}`);
    }
    if (rs) {
      for (const n of strict) {
        const need = new Set<string>();
        for (const r of rs.rules) if (r.tools === null || r.tools.includes(n)) for (const c of r.when) need.add(c.field);
        const missing = [...need].sort().filter((x) => !(f!.tools[n].disclose ?? []).includes(x));
        if (missing.length) lines.push(`strict tool ${n}: rule set version ${rs.version} needs ${missing.join(", ")}: add them to its disclose list, or its strict calls are ruled block (fields_missing)`);
      }
    }
    if (!strict.length) lines.push('strict tools: none (a tool is strict by code, the gateway\'s --strict, or "strict": true in the checks file)');
    // Synchronous functions the checks file makes strict (seen by this or an earlier process).
    const marked = readJson(path.join(this.home, "sync-strict.json"));
    for (const t of new Set([...SYNC_TOOLS].map((x) => declaredName(x)).concat(isObj(marked) ? Object.keys(marked) : []))) {
      if (f.tools[t]?.strict === true && !(`strict ${t}` in this.problems)) this.problems[`strict ${t}`] = syncStrictMessage(t, p);
    }
    let problem = false;
    for (const name of Object.keys(this.problems).sort()) {
      lines.push(`PROBLEM ${name}: ${this.problems[name]}`);
      problem = true;
    }
    return [lines, problem];
  }

  /** `signafaide rules test`: a call evaluated as a client does, against the held rule set and local rules. */
  testCall(tool: string, args: unknown, agent: string): string[] {
    const f = this.file() ?? C.defaultChecksFile();
    const rs = this.heldRules();
    const decl = declaredName(tool);
    const cfg: Json = f.tools[decl] ?? {};
    const out: string[] = [];
    const matched = (m: string[]): string => (m.length ? `: ${m.join(", ")}` : "");
    if (!rs && f.rules === null) out.push("no rule set held and no local rules: nothing to evaluate");
    if (rs) {
      const res = C.evaluate(rs, agent, decl, (p) => C.resolve(args, p));
      out.push(`rule set ${rs.set} version ${rs.version} (${rs.mode} mode): ${res.result} (${res.basis}${matched(res.matched)})`);
      if (!cfg.strict) out.push(`  ${decl} is not strict: the rule set binds only strict calls, so this call runs and the entry is a note in watch mode`);
      const need = C.neededFields(rs, agent, decl);
      const disclose: string[] = cfg.disclose ?? [];
      out.push(`  a strict call discloses: ${need.filter((p) => disclose.includes(p)).join(", ") || "no field"}`);
      const missing = need.filter((p) => !disclose.includes(p));
      if (missing.length) out.push(`  needed fields not in its disclose list: ${missing.join(", ")} (a strict call is ruled block, fields_missing)`);
    }
    if (f.rules !== null) {
      const res = C.evaluate(f.rules, agent, decl, (p) => C.resolve(args, p));
      out.push(`local rules (${f.mode} mode): ${res.result} (${res.basis}${matched(res.matched)})`);
    }
    return out;
  }
}

/** The `checks` of an outcome (§2.8). */
export function outcomeChecks(ran: boolean, ruling: string, results: Json[] = []): Json {
  return { ran, ruling, results, result: C.combined(results) };
}

/** The content of the outcome of a call that did not run (§8 steps 3 and 4). */
export function refusedContent(err: CheckError): Record<string, unknown> {
  const e: Json = { type: err.code === "blocked" ? "Blocked" : "NotRun", message: err.message };
  if (err.code !== "blocked") e.code = err.code;
  if (err.check) e.check = err.check;
  if (err.rule) e.rule = err.rule;
  return { error: e };
}
