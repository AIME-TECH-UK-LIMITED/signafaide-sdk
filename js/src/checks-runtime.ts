/**
 * Tool-call checks in a running program (SPEC §8): the checks file and its live reload, the held
 * rule set and shared fingerprint list (fetched every 60 s, kept offline), local tool approvals,
 * the decision checks of a call, and the witness's ruling on a strict call. Node only.
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as C from "./checks.js";
import { byCodePoint, declaredName } from "./coverage.js";
import { hashJson, newSalt, verifySig } from "./crypto.js";
import { Client, DEFAULT_URL, SignafaideError } from "./http.js";
import { canonicalBytes, canonicalize } from "./jcs.js";
import { nodeTransport } from "./nodehttp.js";
import { now, type Receipt, type SignedRecord } from "./records.js";
import { atomicWrite, monotonicMs } from "./state.js";
import type { Recorder } from "./runtime.js";
import { development } from "./notes.js";
import { failWord, modeWord, ruleWords } from "./words.js";

type Json = Record<string, any>;

export const CHECKS_FILE = "signafaide.checks.json";

/** Why a protected tool stops with no key or sandbox, and the one command that fixes it (one sentence). */
export const NO_KEY_WHY =
  "protected tools stop until a person runs `npx signafaide protect` in this project, because there is no signafAIde key or sandbox here yet to allow the call.";

/** A protected call retries a failed request within its ruling timeout: first after this many
 * ms, doubling, at most `RETRY_MAX_MS` apart (§8). */
export const RETRY_FIRST_MS = 250;
export const RETRY_MAX_MS = 2_000;

/** Why a protected call had no ruling when the witness refused its record for the project's
 * allowance (`quota_exceeded`, `plan_required`), and the fix, in one sentence. */
export function quotaWords(rec: Recorder, e: SignafaideError): string {
  const sandbox = (rec.apiKey ?? "").startsWith("sfa_test_");
  const claim = sandbox ? rec.state.sandbox()?.claim_url : undefined;
  const site = siteOf(rec.url);
  if (e.code === "plan_required")
    return `signafAIde could not rule on it: the project's plan does not include this (${e.message}). Upgrade the plan in the console (${site}/pricing).`;
  return sandbox
    ? `signafAIde could not rule on it: the sandbox's records for this month are used up (quota_exceeded). Keep the sandbox and choose a plan${claim ? ` at ${claim}` : " in the console"}, or wait for next month; until then protected tools stop.`
    : `signafAIde could not rule on it: the project's records for this month are used up (quota_exceeded). Upgrade the plan in the console (${site}/pricing), or wait for next month; until then protected tools stop.`;
}

/** The public keys of the default witness (`DEFAULT_URL`), shipped with the SDK and pinned: with
 * the default URL, rule sets, the shared list and rulings verify with these keys only, and a key
 * set fetched from the network is never used (§8). A new key reaches clients with an SDK release. */
export const DEFAULT_SERVICE_KEYS: readonly C.ServiceKey[] = Object.freeze([
  {
    key_id: "7eb0111937aeef44",
    public_key: "Z0rlIr0TTqeoJM36r51U3qMO_5fsp2Jk8sMfkeNQAl8",
    valid_from: "2026-11-14T17:36:24.017Z",
    valid_to: null,
  },
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

/** Why the rule set's `protect` cannot make `tool` strict here: it is a plain synchronous function
 * (§8, SDK 0.5.2). */
export function syncConsoleMessage(tool: string, version: number): string {
  return (
    `${tool} is a synchronous function, and the console protects it (rule set version ${version}): a protected call waits for the witness's ruling, which a synchronous function's callers cannot await. ` +
    `Make the function async, or protect it in code (\`protect(fn)\` returns an async function), or unprotect it in the console`
  );
}

/** Why the checks file may not make `tool` strict: it is a plain synchronous function. */
export function syncStrictMessage(tool: string, file: string): string {
  return (
    `${tool} is a synchronous function, and ${file} protects it (\`protect\` is \`true\`, or \`strict\` is \`true\` in a version 1 file): a protected call waits for the witness's ruling, which a synchronous function's callers cannot await. ` +
    `Make the function async, or protect it in code (\`record(fn, { strict: true })\` returns an async function), or set \`protect\` (version 1: \`strict\`) to \`false\` for ${tool} in the checks file, which leaves it Not protected`
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

  constructor(
    message: string,
    code: string,
    opts: { check?: string; rule?: string | null; rulesVersion?: number | null; missing?: string[] } = {},
  ) {
    super(message, { code });
    this.check = opts.check;
    this.rule = opts.rule ?? undefined;
    this.rulesVersion = opts.rulesVersion ?? undefined;
    this.missing = [...(opts.missing ?? [])];
  }
}

/** A protected or checked tool call that did not run (spec 1.1): one sentence that says what did
 * not run and why, the rule in words (§10.5) and its rule set version, and a console link. It is a
 * `CheckError` with the same fields (`code`, `check`, `rule` (the rule's id), `rulesVersion`,
 * `missing`), plus `tool`, `ruleText` (the rule in words), `ruledBy` (`witness`: the witness's
 * ruling; `client`: a check or the local rules on this machine), `record` (the decision's
 * record hash) and `link` (the call in the console; none without an API key). */
export class SignafaideBlocked extends CheckError {
  override name = "SignafaideBlocked";
  readonly tool: string;
  readonly ruleText?: string;
  readonly ruledBy: "witness" | "client";
  record?: string;
  link?: string;

  constructor(
    message: string,
    code: string,
    opts: {
      check?: string;
      rule?: string | null;
      rulesVersion?: number | null;
      missing?: string[];
      tool: string;
      ruleText?: string | null;
      ruledBy: "witness" | "client";
    },
  ) {
    super(message, code, opts);
    this.tool = opts.tool;
    this.ruleText = opts.ruleText ?? undefined;
    this.ruledBy = opts.ruledBy;
  }

  /** Name the decision this error refused, and the console link to it (when there is one). */
  attach(record: string, link: string | null): this {
    this.record = record;
    if (link) {
      this.link = link;
      this.message = `${this.message} ${link}`;
    }
    return this;
  }
}

/** The website of a witness: https://api.signafaide.co.uk -> https://signafaide.co.uk. */
export function siteOf(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host.replace(/^api\./, "")}`;
  } catch {
    return url;
  }
}

/** The console link to a call, by its decision's record hash (spec 1.1 `SignafaideBlocked.link`):
 * none in test mode or without an API key, where no witness holds the call. */
export function callLink(rec: Recorder, recordHash: string): string | null {
  if (rec.test || !rec.apiKey) return null;
  return `${siteOf(rec.url)}/r/${recordHash}`;
}

/** What the agent is shown of a tool (§11.1): its whole name, description, input schema and the
 * MCP server's `serverInfo` (none for a tool that does not come from one). */
export interface ToolInfo {
  name: string;
  description?: string | null;
  inputSchema?: unknown;
  serverInfo?: { name?: unknown; version?: unknown } | null;
  /** Which MCP server the tool comes from, when the caller knows better than `serverInfo.name`
   * (the gateway names its upstream command when the server gave no name). Keys the tool's local
   * approval, so two servers that offer one tool name never share it. */
  server?: string | null;
  /** The whole definition the agent is shown (an MCP `tools/list` entry), for the
   * `hidden_instruction` check; by default its name, description and input schema. */
  definition?: unknown;
  /** The names of the other tools listed with it (the gateway's `tools/list`), for the
   * `hidden_instruction` check's instructions about other tools (`tool_shadowing`). */
  others?: readonly string[];
}

/** The server a tool comes from, for its local approval: `server`, else `serverInfo.name`, else "" (a plain function). */
export function serverIdentity(tool: ToolInfo): string {
  if (typeof tool.server === "string" && tool.server) return tool.server;
  const n = tool.serverInfo?.name;
  return typeof n === "string" ? n : "";
}

/** The key of a local approval: the declared name alone for a tool with no server, else the pair
 * `["<server>","<name>"]` as compact JSON (the Python SDK writes the same text). */
export function approvalKey(server: string, name: string): string {
  return server ? JSON.stringify([server, name]) : name;
}

const isApproval = (v: unknown): v is Json => isObj(v) && "description" in v && "schema" in v;

/** The server and tool name of a `["<server>","<name>"]` approval key, else null. */
function keyedPair(key: string): [string, string] | null {
  if (!key.startsWith('["')) return null;
  try {
    const v = JSON.parse(key);
    return Array.isArray(v) && v.length === 2 && typeof v[0] === "string" && typeof v[1] === "string"
      ? [v[0], v[1]]
      : null;
  } catch {
    return null;
  }
}

/** The tool name of a `["<server>","<name>"]` approval key, else null. */
function keyedTool(key: string): string | null {
  return keyedPair(key)?.[1] ?? null;
}

/** What the agent is shown of a tool, as the `hidden_instruction` check reads it: null when the
 * client knows nothing of it but its name (a plain function). */
export function shownDefinition(tool: ToolInfo): unknown {
  if (tool.definition !== undefined) return tool.definition;
  if (!tool.description && (tool.inputSchema === undefined || tool.inputSchema === null)) return null;
  return { name: tool.name, description: tool.description ?? "", inputSchema: tool.inputSchema ?? null };
}

/** What the checks decided about a tool or a server's instructions when the agent was shown them
 * (§8 gateway): `withhold` (enforce mode: not shown), with the words to print; else words of a
 * note to print, or nothing. */
export interface Review {
  withhold: boolean;
  line: string | null;
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
  /** A strict call the held rule set (in enforce mode) would block: the witness rules on it all
   * the same; this applies only when there is no ruling (§8). */
  heldBlock?: SignafaideBlocked | null;
  /** Notes for the caller (§8 notes): a possible hidden instruction in the call's arguments. */
  notes: C.CallNote[];
  /** What protects a strict call (`meta.protected_by`, §8, SDK 0.5.2): `code`, `checks_file`,
   * `console`, in that order; empty when the call is not strict. */
  protectedBy: string[];
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
  /** `protect(fn)`: strict and fail closed, whatever a version 1 checks file says (the held rule
   * set's `fail` may still set another fail mode). */
  protect?: boolean;
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
    Array.isArray(v)
      ? v.map(sortDeep)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, sortDeep((v as Json)[k])]),
          )
        : v;
  return JSON.stringify(sortDeep(value), null, 2) + "\n";
}

function writeAtomic(p: string, text: string): void {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  atomicWrite(p, text);
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
/** The stand-in checks files of `fileFor`: a tool protected with no checks file. */
const DEFAULTS = new WeakSet<object>();
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
  const script =
    "require('dns').lookup(process.argv[1],{all:true},(e,a)=>process.stdout.write(JSON.stringify(e?[]:a.map(x=>x.address))))";
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
  /** The first fetch of this process (§8 protected from the console: a call waits for it). */
  private first: Promise<void> | null = null;
  private firstDone = false;
  /** A call was checked: the shared list is fetched from then on. */
  private planned = false;
  /** Per tool, whether the held version protected it at its last call (the stderr line, §8). */
  private consoleSeen = new Map<string, boolean>();

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
    const syncStrict =
      err === null && this.held && this.held.path === p
        ? [...SYNC_TOOLS].sort().find((t) => C.toolSettings(doc as Json, t).strict)
        : undefined;
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
  /** Whether checks are on: a checks file exists (valid or not). With `protect` (a tool protected
   * in code) they are on unless `SIGNAFAIDE_CHECKS=0` turns them off: without a checks file such a
   * tool runs every check in On, as `init` would write them (§8). */
  enabled(protect = false, tool?: string): boolean {
    const p = this.path();
    return p !== null && (protect || fs.existsSync(p) || (tool !== undefined && this.consoleProtects(tool)));
  }

  /** Whether the held rule set protects `tool` (a declared name) from the console (§8, SDK 0.5.2).
   * Never while checks are off. */
  consoleProtects(tool: string): boolean {
    if (this.path() === null) return false;
    return C.consoleProtects(this.heldRules(), tool);
  }

  /** Whether the held rule set protects any tool from the console. */
  consoleProtectsAny(): boolean {
    if (this.path() === null) return false;
    const rs = this.heldRules();
    return !!rs && isObj(rs.protect) && Object.keys(rs.protect).length > 0;
  }

  /** The stderr line of §8 (development only): the first call of a tool after the held version
   * starts or stops protecting it from the console. `others`: what else protects it. */
  observeConsole(tool: string, protectedNow: boolean, version: number | null, others: string[] = []): void {
    const before = this.consoleSeen.get(tool);
    this.consoleSeen.set(tool, protectedNow);
    if (!development(this.rec)) return;
    if (protectedNow && before !== true)
      console.error(`signafaide: ${tool} is now protected from the console (rule set version ${version})`);
    else if (!protectedNow && before === true) {
      const stays = others.length ? `; it stays protected ${C.sourceWords(others)}` : "";
      console.error(
        `signafaide: ${tool} is no longer protected from the console (rule set version ${version ?? "none"})${stays}`,
      );
    }
  }

  /** A call that may wait (§8): while no rule set version is held and the first fetch of this
   * process is running, the promise of that fetch, at most `RULES_START_WAIT_MS`; else null. */
  startWait(): Promise<void> | null {
    if (this.rec.test || !this.rec.apiKey || this.path() === null) return null;
    this.start();
    if (this.firstDone || !this.first || this.heldRulesItem() !== null) return null;
    return new Promise<void>((resolve) => {
      const t = setTimeout(resolve, C.RULES_START_WAIT_MS);
      t.unref?.();
      this.first!.then(
        () => {
          clearTimeout(t);
          resolve();
        },
        () => {
          clearTimeout(t);
          resolve();
        },
      );
    });
  }

  /** The checks file in force; for a tool protected in code with no checks file, the one `init`
   * writes with every check On (enforce): its calls are checked here and ruled by the witness all
   * the same (§8). */
  fileFor(protect: boolean, tool?: string): Json | null {
    const f = this.file();
    if (f === null && (protect || (tool !== undefined && this.consoleProtects(tool))) && this.path() !== null) {
      const d = { ...C.defaultChecksFile(), mode: "enforce" };
      DEFAULTS.add(d);
      return d;
    }
    return f;
  }

  /** Whether `f` is the stand-in file of a tool protected with no checks file (`fileFor`). */
  private isDefault(f: Json): boolean {
    return DEFAULTS.has(f);
  }

  /** What protects `tool` besides the console: the code, the checks file. */
  private otherSources(f: Json, tool: string, byCode: boolean): string[] {
    return [
      ...(byCode ? ["code"] : []),
      ...(!this.isDefault(f) && C.toolSettings(f, tool).strict ? ["checks_file"] : []),
    ];
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

  /** The names of the tools approved earlier for `agent` and the server `tool` comes from (local
   * approvals), as the tool's own name is written (without the part of `declared` before it, a
   * gateway's prefix), for `look_alike_name` (§8 hidden_instruction). */
  approvedNames(agent: string, tool: ToolInfo, declared: string): string[] {
    if (!tool.name || !declared.endsWith(tool.name)) return [];
    const prefix = declared.slice(0, declared.length - tool.name.length);
    const server = serverIdentity(tool);
    const out: string[] = [];
    for (const key of Object.keys(this.approvals(agent))) {
      const pair = keyedPair(key);
      const n = pair === null ? key : pair[0] === server ? pair[1] : null;
      if (n !== null && n.startsWith(prefix)) out.push(n.slice(prefix.length));
    }
    return out;
  }

  /** What `changed_tool` compares a tool with: the held rule set's approval, else its local
   * approval, written the first time, except for a tool whose name passes for another's
   * (`lookAlike`), which is never approved (its own `look_alike_name` finding says why). */
  private approvalFor(
    rs: Json | null,
    agent: string,
    tool: ToolInfo,
    declared: string,
    fps: C.ToolFingerprints,
    lookAlike: boolean,
  ): Json | null {
    if (rs && rs.approved !== null) return rs.approved[declared] ?? null;
    if (!lookAlike) return this.localApproval(agent, serverIdentity(tool), declared, fps);
    const have = this.approvals(agent)[approvalKey(serverIdentity(tool), declared)];
    return isApproval(have) ? have : { description: fps.description, schema: fps.schema };
  }

  /** The tool's look-alike context (§8 `look_alike_name`): the tools approved earlier, and whether
   * its name passes for one of them or of the tools listed with it. */
  private lookAlikeOf(
    on: Json,
    agent: string,
    tool: ToolInfo,
    declared: string,
  ): { approved: string[]; lookAlike: boolean } {
    if (!on.hidden_instruction || !tool.name) return { approved: [], lookAlike: false };
    const approved = this.approvedNames(agent, tool, declared);
    return { approved, lookAlike: C.lookAlikeName(tool.name, tool.others ?? [], approved) };
  }

  /** A tool's local approval (§8): its fingerprints the first time the client sees it, kept per
   * agent, server and tool name. An approval written before servers were part of the key (the
   * bare tool name) belongs to the first server that asks for that name. */
  localApproval(agent: string, server: string, name: string, fps: C.ToolFingerprints): Json {
    const key = approvalKey(server, name);
    const have = this.approvals(agent)[key];
    if (isApproval(have)) return have;
    const p = this.approvedPath(agent);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    return this.rec.state.lockAt(p.replace(/\.json$/, ".lock"), () => {
      const doc = this.approvals(agent);
      if (!(key in doc)) {
        if (key !== name && isApproval(doc[name])) {
          doc[key] = doc[name]; // migrated: the old key is this server's
          delete doc[name];
        } else {
          doc[key] = { description: fps.description, schema: fps.schema, at: now() };
        }
        writeAtomic(p, pretty(doc));
      }
      return doc[key];
    });
  }

  /** `signafaide checks approve <tool>`: drop the tool's local approvals (every server's), so its
   * next call approves the description and schema it has then. Returns the agents it was dropped for. */
  approve(name: string, agent?: string): string[] {
    const dir = path.join(this.home, "approved");
    const agents = agent
      ? [agent]
      : fs.existsSync(dir)
        ? fs
            .readdirSync(dir)
            .filter((f) => f.endsWith(".json"))
            .map((f) => f.slice(0, -5))
            .sort()
        : [];
    const done: string[] = [];
    for (const a of agents) {
      const p = this.approvedPath(a);
      if (!fs.existsSync(p)) continue;
      this.rec.state.lockAt(p.replace(/\.json$/, ".lock"), () => {
        const doc = this.approvals(a);
        const keys = Object.keys(doc).filter((k) => k === name || keyedTool(k) === name);
        if (keys.length) {
          for (const k of keys) delete doc[k];
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
    return new Client(this.rec.url, this.rec.apiKey, 10_000, this.rec.clientId(), {
      transport: nodeTransport(() => hold),
    });
  }

  /** Fetch the rule set and the list now and every 60 s in the background (with an API key). */
  start(): void {
    if (this.rec.test || !this.rec.apiKey || this.timer || this.path() === null) return;
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
        this.firstDone = true;
        if (this.again) {
          this.again = false;
          this.wake();
        }
      });
    this.first ??= this.refreshing;
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
      // Without a checks file the rule set is fetched for `protect` (§8); the shared list only
      // once a call is checked (a checks file, a tool protected in code or from the console).
      if (name === "fingerprints" && !hold && !this.planned && !this.enabled() && !this.consoleProtectsAny()) continue;
      try {
        await fn();
      } catch (e) {
        const err = e instanceof SignafaideError ? e : new SignafaideError((e as Error).message);
        if (err.code !== "network" && err.code !== "rate_limited" && err.status < 500) {
          this.problems[name] =
            `could not fetch the ${name === "rules" ? "rule set" : "shared fingerprint list"}: ${err.message}`;
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
    if (
      !Array.isArray(keys) ||
      !keys.every((k) => isObj(k) && typeof k.key_id === "string" && typeof k.public_key === "string")
    )
      return this.serviceKeys();
    const before = this.serviceKeys();
    if (
      before.length &&
      !before.some((b) => keys.some((k) => k.key_id === b.key_id && k.public_key === b.public_key))
    ) {
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
    writeAtomic(
      this.rulesPath(pe),
      canonicalize({ rules: item.rules, sig: item.sig, service_key_id: item.service_key_id }),
    );
    writeAtomic(path.join(this.home, "rules", pe[0], `${pe[1]}.at.json`), pretty({ fetched: now() }));
    delete this.problems.rules;
    return `rule set version ${item.rules.version}`;
  }

  /** Keep a version the client was handed (a publish's answer) as the held version, when §10.2
   * accepts it over the version held. Returns whether it was kept. */
  keepRules(item: Json): boolean {
    const pe = this.projectEnv();
    if (!pe || !isObj(item)) return false;
    const held = this.heldRules();
    if (C.acceptRules(held, item, this.serviceKeys(), pe[0], pe[1]) !== null) return false;
    writeAtomic(
      this.rulesPath(pe),
      canonicalize({ rules: item.rules, sig: item.sig, service_key_id: item.service_key_id }),
    );
    writeAtomic(path.join(this.home, "rules", pe[0], `${pe[1]}.at.json`), pretty({ fetched: now() }));
    this.noRuleSet = false;
    delete this.problems.rules;
    return true;
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
    writeAtomic(
      path.join(this.home, "fingerprints.json"),
      pretty({ seq: cur.seq, last: cur.last, entries: cur.entries }),
    );
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
    const telemetry = !!opts.telemetry;
    const decl = opts.declared ?? declaredName(tool.name);
    const rs = this.heldRules();
    // §8 (SDK 0.5.2): the held rule set's `protect` protects a tool the client wraps, as the
    // checks file's `protect: true` would; never a telemetry span (it never blocks).
    const fromConsole = !telemetry && this.path() !== null && C.consoleProtects(rs, decl);
    const byCode = !!(opts.strictCode || opts.protect);
    const f = this.fileFor(!telemetry && (byCode || fromConsole));
    if (!telemetry)
      this.observeConsole(
        decl,
        fromConsole,
        rs ? rs.version : null,
        f ? this.otherSources(f, decl, byCode) : byCode ? ["code"] : [],
      );
    if (!f) return null;
    this.planned = true;
    this.start();
    const ts = C.toolSettings(f, decl);
    let mode: string = telemetry ? "watch" : ts.mode;
    if (fromConsole && !ts.strict) mode = C.protection(rs, f, false, decl)!.mode;
    const cfg: Json = {
      strict: ts.strict,
      disclose: ts.disclose,
      fail: C.checksFileVersion(f) === 1 ? f.tools[decl]?.fail : undefined,
    };
    if (opts.protect) cfg.fail = undefined; // protect(fn): fail closed unless the rule set says otherwise
    if (opts.syncOnly && !opts.strictCode && (cfg.strict === true || fromConsole) && !telemetry) {
      const why =
        cfg.strict === true
          ? syncStrictMessage(decl, this.path() ?? CHECKS_FILE)
          : syncConsoleMessage(decl, rs!.version);
      this.problems[`strict ${decl}`] = why;
      if (cfg.strict === true) this.markSyncStrict(decl);
      throw new CheckError(`${decl} did not run: ${why} (spec §8)`, "state");
    }
    const strict = telemetry ? false : !!(opts.strictCode || cfg.strict || fromConsole);
    const protectedBy = strict
      ? [
          ...(byCode ? ["code"] : []),
          ...(ts.strict && !this.isDefault(f) ? ["checks_file"] : []),
          ...(fromConsole ? ["console"] : []),
        ]
      : [];
    const held = this.heldList();
    const fps = C.toolFingerprints(tool.name, tool.description ?? "", tool.inputSchema, tool.serverInfo ?? null);
    const on = f.checks;
    const results: Json[] = [];
    if (on.secret) results.push(C.entry("secret", C.secretFindings(args, this.witnessHost()), mode));
    if (on.address) {
      const hosts = [...f.addresses.hosts, ...(rs ? rs.addresses.hosts : [])];
      const cidrs = [...f.addresses.cidrs, ...(rs ? rs.addresses.cidrs : [])];
      results.push(
        C.entry("address", C.addressFindings(args, hosts, cidrs, f.addresses.resolve ? lookupSync : undefined), mode),
      );
    }
    const like = this.lookAlikeOf(on, agent, tool, decl);
    if (on.changed_tool) {
      const approved = this.approvalFor(rs, agent, tool, decl, fps, like.lookAlike);
      results.push(C.entry("changed_tool", C.changedToolFindings(fps, approved), mode));
    }
    if (on.fingerprint && held)
      results.push(C.entry("fingerprint", C.fingerprintFindingsIn(fps, this.listed(held), this.excepted(rs)), mode));
    const rulesUsed: Json[] = [];
    let heldEntry: Json | null = null;
    if (rs) {
      // The project's rule set is ruled on by the witness (§8): its entry never blocks here.
      const m = telemetry ? "watch" : C.entryMode(rs.mode, strict, false);
      heldEntry = C.clientRuleEntry(rs, m, rs.set, agent, decl, args);
      results.push(heldEntry);
      rulesUsed.push({ set: rs.set, version: rs.version, hash: hashOf(rs) });
    }
    if (f.rules !== null) {
      results.push(C.clientRuleEntry(f.rules, mode, "local", agent, decl, args));
      rulesUsed.push({ set: "local", version: null, hash: hashOf(f.rules) });
    }
    // hidden_instruction: what the agent is shown of the tool blocks; without a finding there, the
    // arguments are read too, a note only (a possible hidden instruction, handed to the caller).
    let notes: C.CallNote[] = [];
    if (on.hidden_instruction) {
      const shown = shownDefinition(tool);
      const def =
        shown !== null
          ? C.definitionFindings(shown, { self: tool.name, others: tool.others ?? [], approved: like.approved })
          : null;
      const argF = C.argumentFindings(args);
      const f = C.decisionInstructionFindings(def, argF);
      if (shown !== null || f.found.length) results.push(C.entry("hidden_instruction", f, mode));
      if (f === argF) notes = C.callNotes(decl, "arguments", argF);
    }
    const result = C.combined(results);
    const fail: "open" | "closed" | null = strict ? (C.ruleSetFail(rs, decl) ?? cfg.fail ?? "closed") : null;
    const disclose: string[] = cfg.disclose ?? [];
    // §10.4: a strict call sends the fields the held rule set can use for it that `disclose`
    // lists; a needed field it does not list makes the ruling fields_missing.
    const { sent, missing: notDisclosed } = C.disclosure(rs, agent, decl, disclose);
    let pointers: string[] = [];
    let values: Record<string, unknown> | undefined;
    let salt: string | undefined;
    if (strict && result !== "block") {
      pointers = sent;
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
    const callId =
      (typeof cid === "string" && [...cid].length >= 1 && [...cid].length <= 128) || C.isSafeInt(cid) ? cid : null;
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
      notes,
      protectedBy,
    };
    if (result === "block")
      plan.blocked = this.blockError(decl, results.find((e) => e.result === "block")!, rs, f.rules);
    else if (strict && rs && rs.mode === "enforce" && heldEntry?.enforce_result === "block")
      plan.heldBlock = this.heldBlockError(decl, heldEntry, rs);
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

  /** The words of a block on this machine (spec 1.1): what did not run, the rule in words, and
   * how to allow the call, in one sentence. */
  private blockError(tool: string, e: Json, rs: Json | null, local: Json | null): SignafaideBlocked {
    const c: string = e.check;
    const v = rs ? rs.version : null;
    const file = path.basename(this.path() ?? CHECKS_FILE);
    if (c === "rule") {
      const rid: string | null = e.matched.length ? e.matched[0] : null;
      const isLocal = e.set === "local";
      const doc = isLocal ? local : rs;
      const rule = rid && doc ? doc.rules.find((r: Json) => r.id === rid) : null;
      const text = rule
        ? ruleWords(rule)
        : rid
          ? `rule ${rid}`
          : `${doc?.default === "block" ? "Block" : "Allow"} every call that no rule matches`;
      const msg = isLocal
        ? `${tool} did not run: the rule on this machine blocked it ("${text}"); signafAIde did not rule on it. To allow it, change the rule in ${file}.`
        : `${tool} did not run: blocked here under signed rule set version ${v} ("${text}"); the witness did not rule on it. To allow such calls, change the rule in the console.`;
      return new SignafaideBlocked(msg, "blocked", {
        check: "rule",
        rule: rid,
        rulesVersion: isLocal ? null : v,
        tool,
        ruleText: text,
        ruledBy: "client",
      });
    }
    const why: Record<string, string> = {
      secret: `its arguments hold a secret (${e.found.join(", ")}). To allow it, remove the secret, or send it only to the service that issued it.`,
      address: `it goes to an address that is not public (${e.found.join(", ")}). If that address is meant, add the host to addresses in ${file}, or to the rule set's allowlist in the console.`,
      changed_tool: `the tool changed since it was approved (${e.found.join(", ")}). To allow it, re-approve the tool: \`npx signafaide checks approve ${tool}\`, or in the console when the rule set approves tools.`,
      fingerprint: `it is on the list of known bad tools (${e.found.join(", ")}). Remove or replace the tool.`,
      hidden_instruction: `what the agent is shown of the tool ${shownWhy(e.found)}. Review the tool's description and schema; if it is meant, set the tool's \`mode\` to \`"watch"\` in ${file} (Calibrating: it is shown and noted, nothing is blocked).`,
    };
    return new SignafaideBlocked(`${tool} did not run: ${why[c]}`, "blocked", {
      check: c,
      rulesVersion: v,
      tool,
      ruledBy: "client",
    });
  }

  /** A strict call with no ruling that the held version would block (§8): the client decides
   * alone, with the rules it holds, and says the witness was not asked or did not answer. */
  private heldBlockError(tool: string, e: Json, rs: Json): SignafaideBlocked {
    const rid: string | null = e.matched.length ? e.matched[0] : null;
    const rule = rid ? rs.rules.find((r: Json) => r.id === rid) : null;
    const text = rule ? ruleWords(rule) : rid ? `rule ${rid}` : "Block every call that no rule matches";
    return new SignafaideBlocked(
      `${tool} did not run: signafAIde did not rule on it, and the signed rule set version ${rs.version} held here blocks it ("${text}"). To allow such calls, change the rule in the console.`,
      "blocked",
      { check: "rule", rule: rid, rulesVersion: rs.version, tool, ruleText: text, ruledBy: "client" },
    );
  }

  /** Step 4 of a strict call (§8): ship the decision, wait for its receipt up to the ruling
   * timeout, sending a failed request again within it, and read the ruling. Every protected call asks
   * the witness, also when the rules held here would block it: the witness rules with the newest
   * version. Returns the outcome's `ruling` (`allow`, `block`, `none`) and the error to throw when
   * the tool must not run. */
  async ruling(d: SignedRecord, plan: Plan, tool: string): Promise<["allow" | "block" | "none", CheckError | null]> {
    const rec = this.rec;
    if (rec.test) return ["none", null]; // test mode sends nothing: strict calls run without a ruling
    let closed = plan.fail !== "open";
    if (!rec.apiKey) {
      const err = new SignafaideBlocked(`${tool} did not run: ${NO_KEY_WHY}`, "no_key", { tool, ruledBy: "client" });
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
      timer = setTimeout(
        () => reject(new SignafaideError(`no answer within ${plan.timeoutMs} ms`, { code: "network" })),
        plan.timeoutMs,
      );
    });
    late.catch(() => undefined);
    // A short restart of the witness must not stop the call: a request that failed for a reason
    // a new attempt can fix is sent again, with backoff, until the ruling timeout.
    const deadline = Date.now() + plan.timeoutMs;
    let pause = RETRY_FIRST_MS;
    let refused: SignafaideError | null = null;
    let blocked: SignafaideError | null = null; // the network here blocks the witness
    for (let attempt = 1; ; attempt++) {
      try {
        receipt = await Promise.race([rec.ensureReceipt(d, Math.max(1, deadline - Date.now())), late]);
        break;
      } catch (e) {
        const left = deadline - Date.now();
        const se = e instanceof SignafaideError ? e : null;
        if (se && !se.retryable && se.code !== "network") {
          if (se.code === "quota_exceeded" || se.code === "plan_required") refused = se;
          why = `no receipt came (${se.message})`;
          break;
        }
        blocked = se?.blocked ? se : null;
        why = `no receipt came within ${plan.timeoutMs} ms, ${attempt === 1 ? "1 attempt" : `${attempt} attempts`} (${(e as Error).message})`;
        if (left <= pause || blocked || /^no answer within/.test((e as Error).message)) break; // a network that blocks the witness does not open by waiting
        await new Promise((r) => setTimeout(r, pause));
        pause = Math.min(pause * 2, RETRY_MAX_MS);
      }
    }
    if (fetching) await Promise.race([fetching, late]).catch(() => undefined);
    clearTimeout(timer);
    closed = this.failClosed(plan);
    if (refused) {
      // The project's allowance is used up: no new attempt can fix it, so say so plainly.
      const err = new SignafaideBlocked(`${tool} did not run: ${quotaWords(rec, refused)}`, refused.code, {
        tool,
        ruledBy: "client",
      });
      if (plan.heldBlock) return ["none", plan.heldBlock];
      return ["none", closed ? err : null];
    }
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
    // No ruling: the client decides alone. The rules it holds still block what they block; else
    // the tool's If unreachable setting (Stop by default) decides.
    if (plan.heldBlock) return ["none", plan.heldBlock];
    if (blocked && !receipt) {
      const b = new SignafaideBlocked(
        `${tool} did not run: signafAIde did not rule on it, and this tool is set to stop. ${blocked.message}`,
        code,
        { tool, ruledBy: "client" },
      );
      return ["none", closed ? b : null];
    }
    const err = new SignafaideBlocked(
      `${tool} did not run: signafAIde did not rule on it (${why}), and this tool is set to stop. Check the network and \`npx signafaide checks status\`; the console sets whether it stops or runs.`,
      code,
      { tool, ruledBy: "client" },
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
    if (rs) return (C.ruleSetFail(rs, decl) ?? plan.fileFail ?? plan.fail ?? "closed") !== "open";
    if (this.noRuleSet) return plan.fail !== "open";
    return true;
  }

  private async rulingProblem(receipt: Receipt): Promise<string | null> {
    const g = receipt.ruling!;
    const sig = receipt.ruling_sig;
    const err = C.rulingErrors(g);
    if (err) return `the ruling is malformed (${err})`;
    if (
      g.record_hash !== receipt.record_hash ||
      g.batch_hash !== receipt.batch_hash ||
      g.server_time !== receipt.batch?.server_time
    )
      return "the ruling names another record than its receipt";
    let key = this.serviceKeys().find((k) => k.key_id === receipt.service_key_id);
    if (!key) {
      try {
        key = (await this.pullKeys()).find((k) => k.key_id === receipt.service_key_id);
      } catch {
        key = undefined;
      }
    }
    if (!key || typeof sig !== "string" || !verifySig(key.public_key, "ruling", hashJson(g), sig))
      return "the ruling's signature does not verify with the witness's keys";
    // The key must be active when the witness ruled: a retired key never signs a new ruling.
    if (!C.keyActive(key, g.server_time))
      return `the ruling's service key ${key.key_id} was not active at ${g.server_time}`;
    return null;
  }

  /** The words of the witness's block (spec 1.1): the rule in words when the held version is the
   * one it ruled under, the version, and how to allow the call. */
  private rulingError(tool: string, g: Json): SignafaideBlocked {
    const v = isObj(g.rules) ? g.rules.version : null;
    const rule = g.matched.length ? g.matched[0] : null;
    const rs = this.heldRules();
    const doc = rs && v !== null && rs.version === v ? rs : null;
    const found = rule && doc ? doc.rules.find((r: Json) => r.id === rule) : null;
    let text: string | null = found ? ruleWords(found) : null;
    if (!text && g.basis === "default" && doc) text = "Block every call that no rule matches";
    const check = ["rule", "error", "default"].includes(g.basis) ? "rule" : g.basis;
    const at = v !== null ? ` (rule set version ${v})` : "";
    let msg: string;
    if (g.basis === "fields_missing") {
      const fields = g.missing.map((p: string) => p.replace(/^\//, "") || "(the empty key)").join(", ");
      msg = `${tool} did not run: a rule needs ${fields}, which this machine does not send yet${at}; run npx signafaide pull (it adds ${g.missing.join(", ")} to the disclose list of ${tool} in the checks file).`;
    } else if (g.basis === "fingerprint")
      msg = `${tool} did not run: it is on the list of known bad tools${at}. Remove or replace the tool.`;
    else if (g.basis === "rules_version") msg = `${tool} did not run: ${g.reason}`;
    else if (g.basis === "error")
      msg = `${tool} did not run: signafAIde blocked it under "${text ?? `rule ${rule}`}"${at}, because a field had the wrong type for the rule. To allow it, send the field with the type the rule expects, or change the rule in the console.`;
    else
      msg = `${tool} did not run: signafAIde blocked it under "${text ?? (rule ? `rule ${rule}` : "Block every call that no rule matches")}"${at}. To allow such calls, change the rule in the console.`;
    return new SignafaideBlocked(msg, "blocked", {
      check,
      rule,
      rulesVersion: v,
      missing: g.missing,
      tool,
      ruleText: text,
      ruledBy: "witness",
    });
  }

  /** The notes of a call's result entries (§8 notes): a possible hidden instruction in the result. */
  resultNotes(tool: string, results: Json[]): C.CallNote[] {
    const e = results.find((x) => x.check === "hidden_instruction");
    return e ? C.callNotes(tool, "result", { result: e.enforce_result ?? e.result, found: e.found }) : [];
  }

  /** Step 5 (§8): the result checks of a call that ran (`hidden_instruction`), in the mode the
   * checks file sets for `tool` (its declared name). */
  resultEntries(output: unknown, telemetry = false, tool?: string, protect = false): Json[] {
    let f: Json | null;
    try {
      f = this.fileFor(protect && !telemetry, telemetry ? undefined : tool);
    } catch {
      return [];
    }
    if (!f) return [];
    let mode = telemetry ? "watch" : tool !== undefined ? C.toolSettings(f, tool).mode : (f.mode ?? "watch");
    // A tool protected from the console (§8): its checks are On unless the file names its mode.
    if (!telemetry && tool !== undefined && this.consoleProtects(tool) && !C.toolSettings(f, tool).strict)
      mode = C.protection(this.heldRules(), f, false, tool)!.mode;
    const out: Json[] = [];
    if (f.checks.secret) out.push(C.entry("secret", C.secretFindings(output, this.witnessHost(), true), mode));
    if (f.checks.hidden_instruction) out.push(C.entry("hidden_instruction", C.hiddenFindings(output), mode));
    return out;
  }

  /** The error that replaces a result the client withheld (§8 step 5): the tool ran, and its
   * result held a secret, so the agent is not given it. Null when no entry blocks. */
  withheld(tool: string, results: Json[]): SignafaideBlocked | null {
    const e = results.find((x) => x.result === "block");
    if (!e) return null;
    const file = path.basename(this.path() ?? CHECKS_FILE);
    return new SignafaideBlocked(
      `${tool} ran, but its result was withheld from the agent: it holds a secret (${e.found.join(", ")}). What the tool did stands. If the agent should see such results, set the tool's \`mode\` to \`"watch"\` in ${file} (Calibrating: the result goes through and the finding is noted).`,
      "withheld",
      { check: e.check, tool, ruledBy: "client" },
    );
  }

  /** The mode of checks on what a server shows the agent before any tool (its instructions): the
   * checks file's mode (version 1); version 2: enforce when it puts any tool in enforce mode. */
  serverMode(f: Json): string {
    if (C.checksFileVersion(f) === 1) return f.mode === "enforce" ? "enforce" : "watch";
    return Object.keys(f.tools).some((n) => C.toolSettings(f, n).mode === "enforce") ? "enforce" : "watch";
  }

  /** §8 gateway, `tools/list`: approve a tool the first time it is shown (local approvals), and
   * check it as shown now (`changed_tool`, `hidden_instruction`). In enforce mode a tool that a
   * check blocks is withheld from the list. Never throws: a broken checks file reviews nothing. */
  reviewTool(tool: ToolInfo, agent: string, declared: string): Review {
    let f: Json | null;
    try {
      f = this.fileFor(false, declared || undefined);
    } catch {
      return { withhold: false, line: null };
    }
    if (!f) return { withhold: false, line: null };
    let mode = C.toolSettings(f, declared).mode;
    if (declared && this.consoleProtects(declared) && !C.toolSettings(f, declared).strict)
      mode = C.protection(this.heldRules(), f, false, declared)!.mode;
    const why: string[] = [];
    let block = false;
    const like = this.lookAlikeOf(f.checks, agent, tool, declared);
    if (f.checks.changed_tool && tool.name) {
      const fps = C.toolFingerprints(tool.name, tool.description ?? "", tool.inputSchema, tool.serverInfo ?? null);
      const rs = this.heldRules();
      const approved = this.approvalFor(rs, agent, tool, declared, fps, like.lookAlike);
      const r = C.changedToolFindings(fps, approved);
      if (r.result !== "allow") {
        block ||= r.result === "block";
        why.push(
          r.found.includes("not_approved")
            ? "the rule set does not approve it (not_approved)"
            : `it changed since it was approved (${r.found.join(", ")}); re-approve it with \`npx signafaide checks approve ${declared}\`${rs && rs.approved !== null ? " or in the console" : ""}`,
        );
      }
    }
    const shown = f.checks.hidden_instruction ? shownDefinition(tool) : null;
    if (shown !== null) {
      const r = C.definitionFindings(shown, { self: tool.name, others: tool.others ?? [], approved: like.approved });
      if (r.result !== "allow") {
        block = true;
        why.push(`what it shows the agent ${shownWhy(r.found)}`);
      }
    }
    if (!why.length) return { withhold: false, line: null };
    const label = declared || "a tool without a name";
    if (block && mode === "enforce")
      return { withhold: true, line: `${label} was withheld from the tool list: ${why.join("; ")}` };
    return { withhold: false, line: `${label}: ${why.join("; ")}${block ? " (Calibrating: shown all the same)" : ""}` };
  }

  /** §8 gateway, `initialize`: the server's instructions as the agent would be shown them. In
   * enforce mode (`serverMode`) instructions with hidden instructions refuse the session. */
  reviewInstructions(instructions: string): Review {
    let f: Json | null;
    try {
      f = this.file();
    } catch {
      return { withhold: false, line: null };
    }
    if (!f || !f.checks.hidden_instruction) return { withhold: false, line: null };
    const r = C.definitionFindings(instructions);
    if (r.result === "allow") return { withhold: false, line: null };
    const what = `the MCP server's instructions ${shownWhy(r.found).replace(/^holds/, "hold")}`;
    if (this.serverMode(f) === "enforce")
      return {
        withhold: true,
        line: `${what}, so the session was not started. Review the server; if its instructions are meant, set \`mode\` to \`"watch"\` in ${path.basename(this.path() ?? CHECKS_FILE)} (Calibrating: the session goes on and the finding is noted).`,
      };
    return { withhold: false, line: `${what} (Calibrating: the session goes on)` };
  }

  /** A wrapper is shown a tool's definition (§8 changed_tool): approve its fingerprints the first
   * time, so a change before its first call is still a change. */
  seen(tool: ToolInfo, agent: string, declared: string, protect = false): void {
    try {
      const f = this.fileFor(protect, declared);
      if (!f || !f.checks.changed_tool || !tool.name) return;
      const rs = this.heldRules();
      if (rs && rs.approved !== null) return;
      if (this.lookAlikeOf(f.checks, agent, tool, declared).lookAlike) return; // never approved
      this.localApproval(
        agent,
        serverIdentity(tool),
        declared,
        C.toolFingerprints(tool.name, tool.description ?? "", tool.inputSchema, tool.serverInfo ?? null),
      );
    } catch {
      /* the call's own checks report a broken checks file */
    }
  }

  // --- status (signafaide checks status) ----------------------------------------------

  /** Whether this program has shown `tool` to signafAIde (§8, SDK 0.5.2): `wrapped` (a
   * declaration lists it as recorded, or a call of it was seen in this process), `unrecorded`
   * (declared as not recorded), or `unseen`. */
  wrappedState(tool: string): "wrapped" | "unrecorded" | "unseen" {
    if (this.consoleSeen.has(tool)) return "wrapped";
    let unrecorded = false;
    try {
      for (const agent of this.rec.state.agents()) {
        for (const tools of Object.values(this.rec.state.toolSources(agent))) {
          for (const [n, r] of Object.entries(tools)) {
            if (declaredName(n) !== tool) continue;
            if (r) return "wrapped";
            unrecorded = true;
          }
        }
      }
    } catch {
      /* no tool list held */
    }
    return unrecorded ? "unrecorded" : "unseen";
  }

  /** The tools the checks file makes strict (version 1 `strict`, version 2 `protect`), in name order. */
  strictTools(f: Json): string[] {
    return Object.keys(f.tools)
      .filter((n) => C.toolSettings(f, n).strict)
      .sort(byCodePoint);
  }

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
    const real = f;
    if (!f) {
      if (!this.consoleProtectsAny())
        return [
          [
            `checks: off for tools not protected in code or from the console (no ${p}; \`signafaide protect\` or \`signafaide init\` writes one); a tool protected in code or from the console runs every check in On`,
          ],
          false,
        ];
      f = { ...C.defaultChecksFile(), mode: "enforce" };
      DEFAULTS.add(f);
    }
    const on = C.FILE_CHECKS.filter((k) => f!.checks[k]);
    const v2 = C.checksFileVersion(f) === 2;
    lines.push(
      !real
        ? `checks: no ${p}: only tools protected in code or from the console are checked, every check On (${on.join(", ")})`
        : v2
          ? `checks: on, On or Calibrating per tool (${p}, version 2): protected tools are On, others Calibrating unless the file sets a tool's \`mode\`; checks on: ${on.join(", ") || "none"}`
          : `checks: on, ${modeWord(f.mode)} (${p}, version 1: \`mode\` is "${f.mode}"); checks on: ${on.join(", ") || "none"}`,
    );
    const item = this.heldRulesItem();
    const rs = item?.rules ?? null;
    const pe = this.projectEnv();
    if (rs) {
      const at = pe ? readJson(path.join(this.home, "rules", pe[0], `${pe[1]}.at.json`))?.fetched : undefined;
      lines.push(
        `rule set: ${rs.set} version ${rs.version}, ${modeWord(rs.mode)}, default ${rs.default}, issued ${rs.issued} (fetched copy ${age(at)})`,
      );
      for (const r of rs.rules)
        lines.push(`rule ${r.id}: ${ruleWords(r)} (${C.ruleState(rs, r) === "on" ? "On" : "Calibrating"})`);
    } else lines.push("rule set: none held" + (this.rec.apiKey ? "" : " (no API key)"));
    const held = this.heldList();
    const at = readJson(path.join(this.home, "fingerprints.at.json"))?.fetched;
    lines.push(
      held
        ? `shared fingerprint list: seq ${held.seq}, ${held.entries.length} entries (${age(at)})`
        : "shared fingerprint list: none held",
    );
    lines.push(`ruling timeout: ${f.ruling_timeout_ms ?? C.RULING_TIMEOUT_MS} ms`);
    const fromConsole = rs && isObj(rs.protect) ? Object.keys(rs.protect) : [];
    const strict = [...new Set([...(real ? this.strictTools(real) : []), ...fromConsole])].sort(byCodePoint);
    const word = "protected tool";
    for (const n of strict) {
      const t = C.toolSettings(f, n);
      const pr = C.protection(rs, real, false, n)!;
      const fail = C.ruleSetFail(rs, n) ?? (t.strict ? (v2 ? "closed" : (f.tools[n].fail ?? "closed")) : "closed");
      const showMode = v2 || !real || !t.strict;
      lines.push(
        `${word} ${n}: if signafAIde can't be reached: ${failWord(fail)}${showMode ? `, local checks ${modeWord(pr.mode)}` : ""}; discloses ${t.disclose.join(", ") || "no field"}; protected ${C.sourceWords(pr.sources, rs?.version)}`,
      );
    }
    // §8 (SDK 0.5.2): a tool the console protects that this program has not shown to signafAIde.
    for (const n of fromConsole.sort(byCodePoint)) {
      const where = this.wrappedState(n);
      if (where === "wrapped") continue;
      lines.push(
        where === "unrecorded"
          ? `${word} ${n}: protected from the console (rule set version ${rs!.version}), but the program declares it as not recorded: signafAIde never sees its calls, so it cannot protect them. Wrap it with record, protect or wrapTools, or run it through the gateway`
          : `${word} ${n}: protected from the console (rule set version ${rs!.version}), but no record or declaration of this program names it yet: if the program does not wrap it, signafAIde never sees its calls and cannot protect them (wrap it with record, protect or wrapTools, or run it through the gateway)`,
      );
    }
    if (rs) {
      for (const n of strict) {
        const d = C.disclosure(rs, this.rec.defaultAgent, n, C.toolSettings(f, n).disclose);
        if (d.missing.length)
          lines.push(
            `${word} ${n}: rule set version ${rs.version} needs ${d.missing.join(", ")}: run \`signafaide pull\` to approve sending ${d.missing.join(", ")} (it adds them to its disclose list), or its protected calls are ruled block (fields_missing)`,
          );
        if (d.unsent.length)
          lines.push(
            `${word} ${n}: Calibrating rules or exceptions of rule set version ${rs.version} can use ${d.unsent.join(", ")}, which it does not send: they are not calibrated until \`signafaide pull\` adds them`,
          );
      }
    }
    if (!strict.length) {
      lines.push(
        v2
          ? "protected tools: none (`signafaide protect <tool>` protects one)"
          : 'protected tools: none (a tool is protected by code, the gateway\'s --strict, or `"strict": true` in the checks file)',
      );
    }
    // Synchronous functions the checks file makes strict (seen by this or an earlier process).
    const marked = readJson(path.join(this.home, "sync-strict.json"));
    for (const t of new Set(
      [...SYNC_TOOLS].map((x) => declaredName(x)).concat(isObj(marked) ? Object.keys(marked) : []),
    )) {
      if (real && C.toolSettings(real, t).strict && !(`strict ${t}` in this.problems))
        this.problems[`strict ${t}`] = syncStrictMessage(t, p);
      else if (rs && C.consoleProtects(rs, t) && !(`strict ${t}` in this.problems))
        this.problems[`strict ${t}`] = syncConsoleMessage(t, rs.version);
    }
    let problem = false;
    for (const name of Object.keys(this.problems).sort()) {
      lines.push(`PROBLEM ${name}: ${this.problems[name]}`);
      problem = true;
    }
    return [lines, problem];
  }

  /** `signafaide check` and `signafaide rules test`: a call evaluated as a client does, against
   * the held rule set and the local rules, nothing recorded and nothing run. `blocked` is whether
   * the call would not run: a strict call blocked by an On rule (or any rule in watch mode at the
   * witness never blocks), a needed field the tool does not send, or the local rules in enforce
   * mode for the tool. */
  dryRun(tool: string, args: unknown, agent: string): { lines: string[]; blocked: boolean } {
    const f = this.file() ?? C.defaultChecksFile();
    const rs = this.heldRules();
    const decl = declaredName(tool);
    const ts = C.toolSettings(f, decl);
    const out: string[] = [];
    let blocked = false;
    const words = (doc: Json, ids: string[]): string =>
      ids.map((id) => ruleWords(doc.rules.find((r: Json) => r.id === id))).join("; ");
    if (!rs && f.rules === null) out.push("no rule set held and no local rules: nothing to evaluate");
    if (rs) {
      const res = C.evaluate(rs, agent, decl, (p) => C.resolve(args, p));
      const d = C.disclosure(rs, agent, decl, ts.disclose);
      const at = `version ${rs.version}`;
      if (res.result === "block" && ts.strict && rs.mode === "enforce") {
        blocked = true;
        out.push(
          `would block  ${res.basis === "default" ? "Block every call that no rule matches" : words(rs, res.matched)} (On, ${at})`,
        );
      } else if (res.result === "block") {
        out.push(
          `would note   ${res.basis === "default" ? "Block every call that no rule matches" : words(rs, res.matched)} (${modeWord(rs.mode)}, ${at})`,
        );
        if (!ts.strict)
          out.push(
            `             ${decl} is not protected: the rule set binds only protected calls, so this call runs and the rule is noted`,
          );
      } else if (res.basis === "rule") out.push(`allowed      ${words(rs, res.matched)} (${at})`);
      else
        out.push(
          `allowed      no rule matched; ${rs.default === "allow" ? "Allow" : "Block"} every call that no rule matches (${at})`,
        );
      if (res.would_block.length) out.push(`calibrating  would have blocked: ${words(rs, res.would_block)}`);
      if (res.excepted.length) out.push(`excepted     allowed by an exception to: ${words(rs, res.excepted)}`);
      if (ts.strict) {
        out.push(`sends        ${d.sent.map((p) => p.slice(1) || "(the empty key)").join(", ") || "no field"}`);
        if (d.missing.length) {
          blocked = true;
          out.push(
            `would block  a rule needs ${d.missing.join(", ")}, which this machine does not send yet; run npx signafaide pull`,
          );
        }
      }
    }
    if (f.rules !== null) {
      const res = C.evaluate(f.rules, agent, decl, (p) => C.resolve(args, p));
      const text =
        res.basis === "default"
          ? `${f.rules.default === "block" ? "Block" : "Allow"} every call that no rule matches`
          : words(f.rules, res.matched);
      if (res.result === "block" && ts.mode === "enforce") {
        blocked = true;
        out.push(`would block  ${text} (the rules on this machine, ${path.basename(this.path() ?? CHECKS_FILE)})`);
      } else
        out.push(
          `${res.result === "block" ? "would note  " : "allowed     "} ${text} (the rules on this machine, ${modeWord(ts.mode)})`,
        );
    }
    out.push(`             Dry run: nothing recorded, the tool did not run. Exit code ${blocked ? 1 : 0}.`);
    return { lines: out, blocked };
  }

  /** `signafaide rules test`: a call evaluated as a client does, against the held rule set and local rules. */
  testCall(tool: string, args: unknown, agent: string): string[] {
    const f = this.file() ?? C.defaultChecksFile();
    const rs = this.heldRules();
    const decl = declaredName(tool);
    const ts = C.toolSettings(f, decl);
    const out: string[] = [];
    const matched = (m: string[]): string => (m.length ? `: ${m.join(", ")}` : "");
    if (!rs && f.rules === null) out.push("no rule set held and no local rules: nothing to evaluate");
    if (rs) {
      const res = C.evaluate(rs, agent, decl, (p) => C.resolve(args, p));
      out.push(
        `rule set ${rs.set} version ${rs.version} (${modeWord(rs.mode)}): ${res.result} (${res.basis}${matched(res.matched)})`,
      );
      for (const id of res.matched) {
        const r = rs.rules.find((x: Json) => x.id === id);
        if (r) out.push(`  rule ${id}: ${ruleWords(r)} (${C.ruleState(rs, r) === "on" ? "On" : "Calibrating"})`);
      }
      if (res.would_block.length)
        out.push(`  Calibrating rules that would have blocked it: ${res.would_block.join(", ")}`);
      if (res.excepted.length) out.push(`  allowed by an exception to: ${res.excepted.join(", ")}`);
      if (!ts.strict)
        out.push(
          `  ${decl} is not protected: the rule set binds only protected calls, so this call runs and the entry is a note`,
        );
      const d = C.disclosure(rs, agent, decl, ts.disclose);
      out.push(`  a protected call discloses: ${d.sent.join(", ") || "no field"}`);
      if (d.missing.length)
        out.push(
          `  needed fields not in its disclose list: ${d.missing.join(", ")} (a protected call is ruled block, fields_missing)`,
        );
    }
    if (f.rules !== null) {
      const res = C.evaluate(f.rules, agent, decl, (p) => C.resolve(args, p));
      out.push(`local rules (${modeWord(ts.mode)}): ${res.result} (${res.basis}${matched(res.matched)})`);
    }
    return out;
  }
}

/** What a definition finding holds, in words (§8 hidden_instruction): hidden instructions,
 * content a reader cannot read, instructions about other tools. */
export function shownWhy(found: string[]): string {
  const parts: string[] = [];
  const codes = (xs: string[]): string => xs.join(", ");
  const hidden = found.filter((x) => x === "instruction_phrase" || x === "invisible_characters");
  if (hidden.length) parts.push(`holds hidden instructions (${codes(hidden)})`);
  if (found.includes("encoded_content")) parts.push("holds content it cannot read (encoded_content)");
  if (found.includes("tool_shadowing")) parts.push("instructs about other tools (tool_shadowing)");
  if (found.includes("look_alike_name")) parts.push("has a name that passes for another tool's (look_alike_name)");
  return parts.join(" and ") || `holds hidden instructions (${codes(found)})`;
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
