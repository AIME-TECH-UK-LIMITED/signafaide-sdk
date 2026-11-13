/**
 * Local state in `.signafaide/` (SPEC §8). Node only. Same layout and formats as the Python SDK.
 *
 * A chain is identified by `<project>/<env>/<agent>` (the service chains per project, env
 * and agent). Records written before the project of the API key is known go to
 * `_pending/<key fingerprint>/<agent>` (or `_pending/nokey/<agent>` without a key) and the
 * whole chain moves under its project once a sandbox response or a receipt names it.
 *
 * - `agents/<agent>.key`         private key (JSON with its `created` time, mode 0600)
 * - `chain/<chain>.jsonl`        one JCS line per record `{envelope, key_id, sig, content, receipt?}`
 * - `outbox/<chain>/<seq>.json`  signed records not yet accepted by the service
 * - `head.json`                  newest signed head, `{project: {env: {agent: {head, head_sig}}}}`
 * - `config.json`                coding agent; API key fingerprint -> {project, env}
 * - `sandbox.json`               the sandbox project and claim link
 *
 * Writers take a per-chain lock file, so several processes can record for the same agent
 * without forking its chain. Receipts are filled into the trailing chain lines through a
 * journal (`<agent>.jsonl.tail`), so a crash never loses a line.
 */

import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { SigningKey, b64url, b64urlDecode } from "./crypto.js";
import { canonicalize } from "./jcs.js";
import { AGENT_KEYS_FORMAT, AGENT_RE, manifestEntry, now, recordHash, signDraft, validProjectId, validTime, type AgentKeyEntry, type Receipt, type SignedRecord } from "./records.js";

const MARKERS = [".git", "pyproject.toml", "package.json"];
const LOCK_STALE_MS = 10_000;
const LOCK_WAIT_MS = 15_000;
export const PENDING = "_pending";

/** Names an API key in config.json without storing it: sha256, first 16 hex. */
export const keyFingerprint = (apiKey: string): string => createHash("sha256").update(apiKey).digest("hex").slice(0, 16);

/** Local state is unusable; the message says how to fix it. */
export class StateError extends Error {
  override name = "StateError";
}

export interface SignedHead {
  head: { project?: string; env?: string; agent: string; seq: number; record_hash: string; server_time: string };
  head_sig: string;
}

/** Project root: nearest folder with `.signafaide`, else with .git / pyproject.toml /
 * package.json (below the home folder), else the cwd. */
export function findRoot(start = process.cwd()): string {
  start = path.resolve(start);
  const home = path.resolve(os.homedir());
  const chain: string[] = [];
  for (let d = start; ; d = path.dirname(d)) {
    chain.push(d);
    if (path.dirname(d) === d) break;
  }
  for (const d of chain) if (isDir(path.join(d, ".signafaide"))) return d;
  for (const d of chain) {
    if (d === home || path.dirname(d) === d) break;
    if (MARKERS.some((m) => fs.existsSync(path.join(d, m)))) return d;
  }
  return start;
}

const isDir = (p: string): boolean => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};

const sleepSync = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

const pad = (seq: number): string => String(seq).padStart(12, "0");

export class State {
  constructor(
    readonly home: string,
    readonly root: string,
  ) {}

  /** `root`: the project folder (default: found from the cwd). */
  static discover(home?: string, root?: string): State {
    root = root ? path.resolve(root) : findRoot();
    home = home || process.env.SIGNAFAIDE_HOME;
    return new State(home ? path.resolve(home) : path.join(root, ".signafaide"), root);
  }

  // --- layout -----------------------------------------------------------------

  ensure(): void {
    for (const sub of ["agents", "chain", "outbox"]) fs.mkdirSync(path.join(this.home, sub), { recursive: true });
    if (this.home === path.join(this.root, ".signafaide")) ensureGitignore(path.join(this.root, ".gitignore"), ".signafaide/");
  }

  keyPath(agent: string): string {
    return path.join(this.home, "agents", `${agent}.key`);
  }

  chainPath(chain: string): string {
    return path.join(this.home, "chain", `${chain}.jsonl`);
  }

  outboxDir(chain: string): string {
    return path.join(this.home, "outbox", chain);
  }

  /** Every local chain id (`<project>/<env>/<agent>` or `_pending/<fp>/<agent>`). */
  chains(): string[] {
    return depth3(path.join(this.home, "chain"))
      .filter((c) => c.endsWith(".jsonl"))
      .map((c) => c.slice(0, -6))
      .sort();
  }

  agents(): string[] {
    const names = new Set<string>(this.chains().map((c) => c.split("/")[2]));
    for (const f of readdir(path.join(this.home, "agents"))) if (f.endsWith(".key")) names.add(f.slice(0, -4));
    for (const f of readdir(this.retiredDir())) if (f.endsWith(".key")) names.add(f.split(".")[0]);
    return [...names].filter((n) => AGENT_RE.test(n)).sort();
  }

  // --- projects -----------------------------------------------------------------

  /** `<project>/<env>` for this API key, or `_pending/<fp>` while its project is unknown. */
  bucket(apiKey: string | undefined | null): string {
    if (!apiKey) return `${PENDING}/nokey`;
    const fp = keyFingerprint(apiKey);
    const p = this.config().projects?.[fp];
    return p && validProjectId(p.project) && (p.env === "test" || p.env === "live") ? `${p.project}/${p.env}` : `${PENDING}/${fp}`;
  }

  /** Remember an API key's project. The values come from the service, so they are checked
   * before they can name a folder (§8). */
  learnProject(apiKey: string, project: unknown, env: unknown): void {
    if (!validProjectId(project) || (env !== "test" && env !== "live")) {
      throw new StateError(`the service named project ${JSON.stringify(project)} env ${JSON.stringify(env)}, which is not a valid project id and env; check SIGNAFAIDE_URL`);
    }
    this.saveConfig({ projects: { ...(this.config().projects ?? {}), [keyFingerprint(apiKey)]: { project, env } } });
  }

  /** Sign every draft chain of bucket `src` into `dst` (`<project>/<env>`) with its outbox
   * (§8), keeping each record's time. Returns the chains left pending, with why: `exists` (that
   * agent already has a chain under `dst`) or the first draft's time when it is before
   * `notBefore` (the service would refuse it, §2.4). */
  adopt(src: string, dst: string, key: (agent: string) => SigningKey, wire: (r: SignedRecord) => SignedRecord, notBefore?: string): [string, string][] {
    const [project, env] = dst.split("/") as [string, "test" | "live"];
    const conflicts: [string, string][] = [];
    for (const f of readdir(path.join(this.home, "chain", src)).filter((f) => f.endsWith(".jsonl")).sort()) {
      const agent = f.slice(0, -6);
      this.lock(`${src}/${agent}`, () =>
        this.lock(`${dst}/${agent}`, () => {
          const lines = this.lines(`${src}/${agent}`);
          const target = this.chainPath(`${dst}/${agent}`);
          const mapping = this.draftMap(`${dst}/${agent}`);
          const first = lines[0]?.envelope.time;
          const tooOld = !!notBefore && !!first && Date.parse(first) < Date.parse(notBefore);
          if (fs.existsSync(target)) {
            if (lines.length && lines.every((d) => recordHash(d) in mapping)) fs.unlinkSync(this.chainPath(`${src}/${agent}`));
            else conflicts.push([`${src}/${agent}`, tooOld ? first : "exists"]);
            return;
          }
          if (tooOld) {
            conflicts.push([`${src}/${agent}`, first]);
            return;
          }
          let prev: string | null = null;
          const out: [SignedRecord, boolean | undefined][] = [];
          for (const d of lines) {
            if (!d.draft) throw new StateError(`${this.chainPath(`${src}/${agent}`)} holds a signed record; pending chains hold drafts only. Move it aside and run \`signafaide verify\``);
            const ref = d.envelope.ref;
            const rec: SignedRecord = signDraft(key(agent), d, project, env, prev, ref ? (mapping[ref] ?? ref) : null);
            mapping[recordHash(d)] = prev = recordHash(rec);
            out.push([rec, d.store_content]);
          }
          fs.mkdirSync(path.dirname(target), { recursive: true });
          writeJson(this.mapPath(`${dst}/${agent}`), mapping);
          const fd = fs.openSync(target + ".tmp", "w");
          fs.writeSync(fd, out.map(([r]) => canonicalize(r) + "\n").join(""));
          fs.fsyncSync(fd);
          fs.closeSync(fd);
          for (const [rec, store] of out) this.writeOutbox(`${dst}/${agent}`, store === undefined ? wire(rec) : wireOf(rec, store));
          fs.renameSync(target + ".tmp", target);
          fs.unlinkSync(this.chainPath(`${src}/${agent}`));
        }),
      );
    }
    return conflicts;
  }

  private mapPath(chain: string): string {
    return path.join(this.home, "chain", `${chain}.drafts.json`);
  }

  private draftMap(chain: string): Record<string, string> {
    return readJson<Record<string, string>>(this.mapPath(chain)) ?? {};
  }

  /** A ref to a draft that has since been signed points at the signed record. */
  translateRef(chain: string, ref: string | null | undefined): string | null {
    if (!ref) return ref ?? null;
    return this.draftMap(chain)[ref] ?? ref;
  }

  hasDrafts(): boolean {
    return this.chains().some((c) => c.startsWith(PENDING + "/"));
  }

  draftCount(chain: string): number {
    return this.lines(chain).filter((r) => r.draft).length;
  }

  // --- keys -------------------------------------------------------------------

  /** When the key was generated: the `valid_from` sent at registration, so records
   * signed offline before registering still verify (§2.4). */
  keyCreated(agent: string): string | undefined {
    try {
      return JSON.parse(fs.readFileSync(this.keyPath(agent), "utf8")).created;
    } catch {
      return undefined;
    }
  }

  retiredDir(): string {
    return path.join(this.home, "agents", "retired");
  }

  /** [key, created] of the agent's retired keys, newest first. */
  retiredKeys(agent: string): [SigningKey, string][] {
    const out: [SigningKey, string][] = [];
    for (const f of readdir(this.retiredDir())) {
      if (!f.startsWith(agent + ".") || !f.endsWith(".key") || f.split(".").length !== 3) continue;
      try {
        const doc = JSON.parse(fs.readFileSync(path.join(this.retiredDir(), f), "utf8"));
        if (doc.agent === agent) out.push([new SigningKey(b64urlDecode(doc.private_key)), doc.created]);
      } catch {
        throw new StateError(`${path.join(this.retiredDir(), f)} is not a valid signafaide key file; restore it from backup`);
      }
    }
    return out.sort((a, b) => (a[1] < b[1] ? 1 : a[1] > b[1] ? -1 : 0));
  }

  /** When the service retired this key (§2.4 rotation), once it said so; null before. */
  retiredAt(agent: string, keyId: string): string | null {
    try {
      const v = JSON.parse(fs.readFileSync(path.join(this.retiredDir(), `${agent}.${keyId}.key`), "utf8")).retired;
      return typeof v === "string" && validTime(v) ? v : null;
    } catch {
      return null;
    }
  }

  /** Record the service's retirement time in a retired key's file (kept for keys export). */
  markRetired(agent: string, keyId: string, validTo: string): boolean {
    const p = path.join(this.retiredDir(), `${agent}.${keyId}.key`);
    if (!AGENT_RE.test(agent) || !validTime(validTo) || !/^[0-9a-f]{16}$/.test(keyId) || !fs.existsSync(p)) return false;
    const doc = JSON.parse(fs.readFileSync(p, "utf8"));
    if (doc.retired === validTo) return false;
    doc.retired = validTo;
    const tmp = p + ".tmp";
    fs.writeFileSync(tmp, canonicalize(doc) + "\n", { mode: 0o600 });
    fs.renameSync(tmp, p);
    return true;
  }

  /** Retire the agent's key and make a new one: [old, new]. The next registration is
   * signed by the old key (§2.4 rotation). */
  rotateKey(agent: string): [SigningKey, SigningKey] {
    if (!AGENT_RE.test(agent)) throw new StateError(`agent "${agent}" is invalid`);
    const old = this.loadKey(agent, false);
    if (!old) throw new StateError(`agent ${agent} has no key to rotate; it gets one with its first record`);
    fs.mkdirSync(this.retiredDir(), { recursive: true });
    fs.renameSync(this.keyPath(agent), path.join(this.retiredDir(), `${agent}.${old.keyId}.key`));
    return [old, this.loadKey(agent)];
  }

  /** Every current and retired agent key: `{agent, key_id, public_key, created, retired}`
   * (`retired`: when the service retired it, or null). */
  agentPublicKeys(): { agent: string; key_id: string; public_key: string; created: string; retired: string | null }[] {
    const out: { agent: string; key_id: string; public_key: string; created: string; retired: string | null }[] = [];
    for (const agent of this.agents()) {
      const k = this.loadKey(agent, false);
      if (k) out.push({ agent, key_id: k.keyId, public_key: b64url(k.publicKey), created: this.keyCreated(agent) ?? now(), retired: null });
      for (const [rk, created] of this.retiredKeys(agent)) out.push({ agent, key_id: rk.keyId, public_key: b64url(rk.publicKey), created, retired: this.retiredAt(agent, rk.keyId) });
    }
    return out;
  }

  /** The §2.5 manifest of every current and retired key, each entry self-signed. */
  exportAgentKeys(): { format: string; keys: AgentKeyEntry[] } {
    const keys: AgentKeyEntry[] = [];
    for (const agent of this.agents()) {
      const k = this.loadKey(agent, false);
      if (k) keys.push(manifestEntry(agent, k, this.keyCreated(agent) ?? now()));
      // A retired key carries the time the service retired it, signed by that key (§2.5).
      for (const [rk, created] of this.retiredKeys(agent)) keys.push(manifestEntry(agent, rk, created, this.retiredAt(agent, rk.keyId)));
    }
    return { format: AGENT_KEYS_FORMAT, keys };
  }

  loadKey(agent: string, create?: true): SigningKey;
  loadKey(agent: string, create: boolean): SigningKey | null;
  loadKey(agent: string, create = true): SigningKey | null {
    const p = this.keyPath(agent);
    if (!fs.existsSync(p)) {
      if (!create) return null;
      this.ensure();
      const key = SigningKey.generate((n) => new Uint8Array(randomBytes(n)));
      const doc = { agent, key_id: key.keyId, public_key: b64url(key.publicKey), private_key: b64url(key.seed()), created: now() };
      let fd: number;
      try {
        fd = fs.openSync(p, "wx", 0o600);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "EEXIST") return this.loadKey(agent, false);
        throw e;
      }
      fs.writeSync(fd, canonicalize(doc) + "\n");
      fs.closeSync(fd);
      return key;
    }
    try {
      return new SigningKey(b64urlDecode(JSON.parse(fs.readFileSync(p, "utf8")).private_key));
    } catch (e) {
      throw new StateError(`${p} is not a valid signafaide key file (${(e as Error).message}); restore it from backup`);
    }
  }

  // --- locking ----------------------------------------------------------------

  lock<T>(chain: string, fn: () => T): T {
    const p = path.join(this.home, "chain", `${chain}.lock`);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try {
        const fd = fs.openSync(p, "wx", 0o600);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try {
          if (Date.now() - fs.statSync(p).mtimeMs > LOCK_STALE_MS) {
            fs.unlinkSync(p);
            continue;
          }
        } catch {
          continue;
        }
        if (Date.now() > deadline) throw new StateError(`${p} is held by another process; delete it if no signafaide process is running`);
        sleepSync(2);
      }
    }
    try {
      this.recover(chain);
      return fn();
    } finally {
      try {
        fs.unlinkSync(p);
      } catch {
        /* already gone */
      }
    }
  }

  /** Finish an interrupted receipt rewrite (journal `.tail`). */
  private recover(chain: string): void {
    const file = this.chainPath(chain);
    const journal = file + ".tail";
    if (!fs.existsSync(journal)) return;
    const buf = fs.readFileSync(journal);
    const nl = buf.indexOf(10);
    const offset = Number(buf.subarray(0, nl).toString());
    const fd = fs.openSync(file, "r+");
    try {
      fs.ftruncateSync(fd, offset);
      fs.writeSync(fd, buf.subarray(nl + 1), 0, buf.length - nl - 1, offset);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.unlinkSync(journal);
  }

  // --- chain ------------------------------------------------------------------

  /** [seq, record_hash] of the last record in the local chain, [0, null] if empty. */
  tail(chain: string): [number, string | null] {
    for (const [, rec] of this.reverse(chain)) return [rec.envelope.seq, recordHash(rec)];
    return [0, null];
  }

  /** Under the chain lock: build the next record from (seq, prev), append it to the chain
   * and put `wire(record)` in the outbox. Returns null when `stillValid()` is false once
   * the lock is held (the chain was just moved under its project; resolve it again). */
  append(
    chain: string,
    build: (seq: number, prev: string | null) => SignedRecord,
    wire: (r: SignedRecord) => SignedRecord,
    stillValid: () => boolean = () => true,
  ): SignedRecord | null {
    this.ensure();
    return this.lock(chain, () => {
      if (!stillValid()) return null;
      const [seq, prev] = this.tail(chain);
      const rec = build(seq + 1, prev);
      fs.appendFileSync(this.chainPath(chain), canonicalize(rec) + "\n");
      if (!rec.draft) this.writeOutbox(chain, wire(rec)); // a draft ships once it is signed (adopt)
      return rec;
    });
  }

  private writeOutbox(chain: string, rec: SignedRecord): void {
    const d = this.outboxDir(chain);
    fs.mkdirSync(d, { recursive: true });
    const tmp = path.join(d, `.${pad(rec.envelope.seq)}.tmp`);
    fs.writeFileSync(tmp, canonicalize(rec));
    fs.renameSync(tmp, path.join(d, `${pad(rec.envelope.seq)}.json`));
  }

  private lines(chain: string): SignedRecord[] {
    const p = this.chainPath(chain);
    if (!fs.existsSync(p)) return [];
    return fs
      .readFileSync(p, "utf8")
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => parseLine(p, l));
  }

  /** Every line of a chain, drafts included (§8). */
  readAll(chain: string): SignedRecord[] {
    return this.lines(chain);
  }

  /** The signed records of a chain (drafts are skipped: they are not signed yet). */
  readChain(chain: string): SignedRecord[] {
    return this.lines(chain).filter((r) => !r.draft);
  }

  /** Lines from the end of the chain file: [offset, record]. */
  *reverse(chain: string): Generator<[number, SignedRecord]> {
    const p = this.chainPath(chain);
    let fd: number;
    try {
      fd = fs.openSync(p, "r");
    } catch {
      return;
    }
    try {
      let pos = fs.fstatSync(fd).size;
      let buf = Buffer.alloc(0);
      while (pos > 0) {
        const n = Math.min(65536, pos);
        pos -= n;
        const chunk = Buffer.alloc(n);
        fs.readSync(fd, chunk, 0, n, pos);
        buf = Buffer.concat([chunk, buf]);
        const parts: Buffer[] = [];
        let start = 0;
        for (let i = buf.indexOf(10); i !== -1; i = buf.indexOf(10, start)) {
          parts.push(buf.subarray(start, i));
          start = i + 1;
        }
        parts.push(buf.subarray(start));
        const head = parts.shift()!;
        let off = pos + head.length + 1;
        const complete: [number, Buffer][] = parts.map((ln) => {
          const item: [number, Buffer] = [off, ln];
          off += ln.length + 1;
          return item;
        });
        buf = Buffer.from(head);
        for (const [o, ln] of complete.reverse()) if (ln.toString().trim()) yield [o, parseLine(p, ln.toString())];
      }
      if (buf.toString().trim()) yield [0, parseLine(p, buf.toString())];
    } finally {
      fs.closeSync(fd);
    }
  }

  /** Fill receipts into the trailing chain lines that lack one. Returns how many were filled. */
  applyReceipts(chain: string, receipts: Map<string, Receipt>): number {
    const p = this.chainPath(chain);
    if (!fs.existsSync(p)) return 0;
    return this.lock(chain, () => {
      const suffix: [number, SignedRecord][] = [];
      for (const item of this.reverse(chain)) {
        if (item[1].receipt) break;
        suffix.push(item);
      }
      suffix.reverse();
      let filled = 0;
      const out = suffix.map(([, rec]) => {
        const r = receipts.get(recordHash(rec));
        if (r) {
          rec.receipt = r;
          filled++;
        }
        return canonicalize(rec) + "\n";
      });
      if (filled) {
        const journal = p + ".tail";
        const tmp = p + ".tail.tmp";
        const fd = fs.openSync(tmp, "w");
        fs.writeSync(fd, `${suffix[0][0]}\n` + out.join(""));
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fs.renameSync(tmp, journal);
        this.recover(chain);
      }
      return filled;
    });
  }

  /** Re-queue chain records that have neither a receipt nor an outbox file
   * (a crash between the chain write and the outbox write). */
  reconcileOutbox(chain: string, wire: (r: SignedRecord) => SignedRecord): number {
    if (!fs.existsSync(this.chainPath(chain))) return 0;
    return this.lock(chain, () => {
      let n = 0;
      for (const [, rec] of this.reverse(chain)) {
        if (rec.receipt || rec.draft) break;
        if (!fs.existsSync(path.join(this.outboxDir(chain), `${pad(rec.envelope.seq)}.json`))) {
          this.writeOutbox(chain, wire(rec));
          n++;
        }
      }
      return n;
    });
  }

  // --- outbox -----------------------------------------------------------------

  outbox(chain: string, limit = 1000): SignedRecord[] {
    const d = this.outboxDir(chain);
    const out: SignedRecord[] = [];
    for (const f of readdir(d)
      .filter((f) => f.endsWith(".json"))
      .sort()
      .slice(0, limit)) {
      try {
        out.push(JSON.parse(fs.readFileSync(path.join(d, f), "utf8")));
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      }
    }
    return out;
  }

  dropOutbox(chain: string, seqs: number[]): void {
    for (const s of seqs) fs.rmSync(path.join(this.outboxDir(chain), `${pad(s)}.json`), { force: true });
  }

  /** Chains with records waiting, optionally only those under `prefix` (a bucket). */
  outboxChains(prefix?: string): string[] {
    const d = path.join(this.home, "outbox");
    return depth3(d)
      .filter((c) => readdir(path.join(d, c)).some((f) => f.endsWith(".json")) && (!prefix || c.startsWith(prefix + "/")))
      .sort();
  }

  /** Records waiting: everything, a bucket (`<project>/<env>`) or one chain. */
  outboxSize(prefix?: string): number {
    const d = path.join(this.home, "outbox");
    return depth3(d)
      .filter((c) => !prefix || `${c}/`.startsWith(prefix + "/"))
      .reduce((n, c) => n + readdir(path.join(d, c)).filter((f) => f.endsWith(".json")).length, 0);
  }

  // --- heads, sandbox ---------------------------------------------------------

  /** `{project: {env: {agent: {head, head_sig}}}}`. */
  heads(): Record<string, Record<string, Record<string, SignedHead>>> {
    return readJson(path.join(this.home, "head.json")) ?? {};
  }

  /** The newest signed head per chain id `<project>/<env>/<agent>`. */
  chainHeads(): Record<string, SignedHead> {
    const out: Record<string, SignedHead> = {};
    for (const [p, envs] of Object.entries(this.heads())) for (const [e, agents] of Object.entries(envs)) for (const [a, sh] of Object.entries(agents)) out[`${p}/${e}/${a}`] = sh;
    return out;
  }

  /** Keep the newest head per (project, env, agent). Returns warnings for heads that go
   * backwards (the service showing a shorter chain = truncation). */
  updateHeads(signed: SignedHead[]): string[] {
    const warnings: string[] = [];
    const heads = this.heads();
    for (const sh of signed) {
      const { project = "", env = "", agent } = sh.head ?? ({} as SignedHead["head"]);
      const slot = ((heads[project] ??= {})[env] ??= {});
      const old = slot[agent]?.head;
      if (old && (sh.head.seq ?? 0) < (old.seq ?? 0)) {
        warnings.push(`service head for ${agent} went back from seq ${old.seq} to ${sh.head.seq}: keep .signafaide/head.json, it proves truncation`);
        continue;
      }
      slot[agent] = sh;
    }
    writeJson(path.join(this.home, "head.json"), heads);
    return warnings;
  }

  /** `config.json`: settings kept with the project (the coding agent that set it up). */
  config(): { agent?: string; projects?: Record<string, { project: string; env: string }> } {
    return readJson(path.join(this.home, "config.json")) ?? {};
  }

  saveConfig(values: Record<string, unknown>): void {
    this.ensure();
    writeJson(path.join(this.home, "config.json"), { ...this.config(), ...values });
  }

  sandbox(): { project?: string; claim_url?: string; free_quota?: number; url?: string; created?: string; terms_url?: string; privacy_url?: string } | null {
    return readJson(path.join(this.home, "sandbox.json"));
  }

  saveSandbox(info: object): void {
    this.ensure();
    writeJson(path.join(this.home, "sandbox.json"), info);
  }
}

function parseLine(p: string, line: string): SignedRecord {
  try {
    const rec = JSON.parse(line);
    if (typeof rec.envelope.seq !== "number") throw new Error();
    return rec;
  } catch {
    throw new StateError(`${p} has a damaged line; move that line aside and run \`signafaide verify\``);
  }
}

/** Relative paths three levels below `d` (`a/b/c`). */
function depth3(d: string): string[] {
  return readdir(d).flatMap((a) => readdir(path.join(d, a)).flatMap((b) => readdir(path.join(d, a, b)).map((c) => `${a}/${b}/${c}`)));
}

function readdir(d: string): string[] {
  try {
    return fs.readdirSync(d);
  } catch {
    return [];
  }
}

function readJson<T>(p: string): T | null {
  let text: string;
  try {
    text = fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new StateError(`${p} is not valid JSON; fix or delete it`);
  }
}

function writeJson(p: string, value: unknown): void {
  const sorted = (v: any): any =>
    Array.isArray(v) ? v.map(sorted) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v;
  fs.writeFileSync(p + ".tmp", JSON.stringify(sorted(value), null, 2) + "\n");
  fs.renameSync(p + ".tmp", p);
}

export function ensureGitignore(p: string, entry: string): void {
  const text = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "";
  const bare = entry.replace(/^\/+|\/+$/g, "");
  if (text.split(/\r?\n/).some((l) => l.trim().replace(/^\/+|\/+$/g, "") === bare)) return;
  fs.writeFileSync(p, text + (text && !text.endsWith("\n") ? "\n" : "") + entry + "\n");
}

export function readEnvFile(p: string): Record<string, string> {
  const out: Record<string, string> = {};
  let text: string;
  try {
    text = fs.readFileSync(p, "utf8");
  } catch {
    return out;
  }
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    let k = line.slice(0, line.indexOf("=")).trim();
    let v = line.slice(line.indexOf("=") + 1).trim();
    if (k.startsWith("export ")) k = k.slice(7).trim();
    if (v.length >= 2 && v[0] === v[v.length - 1] && (v[0] === '"' || v[0] === "'")) v = v.slice(1, -1);
    out[k] = v;
  }
  return out;
}

/** Append `key=value`; never touches other lines. The file holds a secret, so it is created
 * (and kept) with mode 0600, and a value can never add a line of its own. */
export function appendEnvFile(p: string, key: string, value: string): void {
  if (/[\r\n\0]/.test(value) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new StateError(`refusing to write ${key} to ${p}: the value is not a single line`);
  let link = false;
  try {
    link = fs.lstatSync(p).isSymbolicLink();
  } catch {
    /* does not exist yet */
  }
  if (link) throw new StateError(`refusing to write ${p}: it is a symbolic link`);
  const text = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "";
  fs.appendFileSync(p, (text && !text.endsWith("\n") ? "\n" : "") + `${key}=${value}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(p, 0o600);
  } catch {
    /* not ours to change */
  }
}

function wireOf(rec: SignedRecord, store: boolean): SignedRecord {
  const out: SignedRecord = { envelope: rec.envelope, key_id: rec.key_id, sig: rec.sig };
  if (store && rec.content !== undefined) out.content = rec.content;
  return out;
}
