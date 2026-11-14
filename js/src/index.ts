/**
 * signafAIde: signed, chained records of what your AI agents decided.
 *
 *   import { record } from "signafaide";
 *   const approvePayout = record(async (claimId: string, amount: number) => { ... }, { name: "approve_payout" });
 *
 * Every call writes a `decision` record before the function runs and an `outcome`
 * record after it, signed with the agent's own key and chained in `.signafaide/`.
 * Nothing is sent until a human opts in (`npx signafaide init`, or SIGNAFAIDE_API_KEY);
 * then the records ship in the background. Only hashes leave the machine unless `storeContent`.
 */

import { installNodeCrypto } from "./nodecrypto.js";
import * as fs from "node:fs";
import * as path from "node:path";
import { configure, getRecorder, type FlushResult, type Recorder, type RecorderOptions } from "./runtime.js";
import { parseJson } from "./jcs.js";
import { checkContent, verifySig } from "./crypto.js";
import { plural } from "./plural.js";
import { recordHash, type SignedRecord } from "./records.js";
import { DEFAULT_TIMESTAMP_URL, lookupTimestamps } from "./timestamps.js";
import {
  DRAND_NOT_CHECKED,
  KeysRequired,
  contentFromText,
  isLoopbackUrl,
  loadDrandVerifier,
  parseAgentKeys,
  parseHeadFile,
  parseServiceKeys,
  timestampHeights,
  verifyLocalState,
  verifyPack,
  type KeyDoc,
  type LocalContent,
  type Report,
} from "./verifier.js";

export * from "./core.js";

installNodeCrypto();
export { NotRecorded, note, record, toJsonable, wrapTool, wrapTools, type RecordOptions, type WrapOptions } from "./record.js";
export { Recorder, configure, getRecorder, recordingDisabled, testMode, type Blocked, type FlushResult, type RecorderOptions } from "./runtime.js";
export { State, StateError } from "./state.js";
export { Entry, Replay, loadServiceKeys, replay, type ReplayOptions } from "./replay.js";
export { ExperimentReport, VerificationFailed, compare, recordedValue, type CompareOptions, type ExperimentRow } from "./experiments.js";
export { DEFAULT_TIMESTAMP_URL, blockHeader, checkHeader, lookupTimestamps, rootsFromVector, type BlockHeader, type BlockRoots } from "./timestamps.js";

/**
 * Configure signafAIde (optional). Finds SIGNAFAIDE_API_KEY (env or .env). Without one,
 * records stay local (signed, chained, verifiable in `.signafaide/`) and nothing is sent: it
 * never creates a sandbox. A human opts in with `npx signafaide init` or by setting the key.
 * Never throws when the service is offline: records wait in the outbox.
 */
export async function init(opts: RecorderOptions = {}): Promise<Recorder> {
  const rec = configure(opts);
  const key = rec.apiKey;
  if (!key) return rec;
  try {
    await rec.resolveProject(key);
  } catch (e) {
    // A wrong key or an unreachable witness is a warning, never an exception in the caller's
    // program (records are kept locally until it is fixed).
    if (!(e instanceof Error)) throw e;
    if (!opts.quiet) console.error(`signafaide: ${e.message} Records are kept locally until then.`);
  }
  return rec;
}

/** Ship the outbox now. */
export function flush(timeoutMs?: number): Promise<FlushResult> {
  return getRecorder().flush(timeoutMs);
}

/** Key, env, agents, last receipts and outbox size. */
export function status() {
  return getRecorder().status();
}

export interface VerifyOptions {
  /** Service keys: a file path, an http(s) URL or the parsed document. Default: fetched from the service. */
  keys?: string | object;
  trustEmbeddedKeys?: boolean;
  /** The customer's agent keys (`signafaide keys export`): a file, URL or the parsed manifest.
   * Default for a pack: this project's own keys in `.signafaide/agents`. */
  agentKeys?: string | object;
  trustEmbeddedAgentKeys?: boolean;
  /** A client's `head.json` (file or parsed). */
  head?: string | object;
  /** Explorer API that confirms public timestamps (default https://mempool.space/api). */
  timestampCheck?: string;
  /** Do not look up public timestamps (they show NOT CHECKED). */
  offline?: boolean;
  /** Content to check: a chain .jsonl file or a folder of them. Default: the local `.signafaide/chain`. */
  content?: string;
  /** Local state: fail (exit 1) when any record has not been co-signed yet, for CI. A BLOCKED
   * chain always fails. */
  failOnPendingSend?: boolean;
}

/** Records `signafaide repair` set aside: their signatures (with the key that signed them),
 * chain links and content hashes still check; they are not co-signed. Failures name the check. */
export function checkHeld(rec: Recorder): { records: number; segments: number; failures: { check: "record_sig" | "chain" | "content"; item: string; message: string }[] } {
  const keys = new Map(rec.state.agentPublicKeys().map((k) => [k.key_id, k]));
  const failures: { check: "record_sig" | "chain" | "content"; item: string; message: string }[] = [];
  let records = 0;
  const segs = rec.state.heldSegments();
  for (const [chain, file, recs] of segs) {
    let prev: SignedRecord | null = null;
    for (const r of recs) {
      records++;
      const item = `${chain}#${r.envelope.seq} (held, ${path.basename(file)})`;
      const k = keys.get(r.key_id);
      if (!k) failures.push({ check: "record_sig", item, message: `no key ${r.key_id} for agent ${r.envelope.agent} on this machine` });
      else if (!verifySig(k.public_key, r.draft ? "draft" : "record", recordHash(r), r.sig)) failures.push({ check: "record_sig", item, message: "signature does not verify" });
      if (prev && (r.envelope.seq !== prev.envelope.seq + 1 || r.envelope.prev !== recordHash(prev))) failures.push({ check: "chain", item, message: "does not follow the held record before it" });
      try {
        const h = checkContent(r.content, r.salt, r.envelope.content_hash);
        if (h) failures.push({ check: "content", item, message: `content hashes to ${h}, envelope says ${r.envelope.content_hash}` });
      } catch (e) {
        failures.push({ check: "content", item, message: (e as Error).message });
      }
      prev = r;
    }
  }
  return { records, segments: segs.length, failures };
}

async function readInput(src: string | object, flag: string): Promise<unknown> {
  if (typeof src !== "string") return src;
  if (/^https?:\/\//.test(src)) {
    if (src.startsWith("http://")) {
      if (!isLoopbackUrl(src)) {
        throw new Error(`${flag} ${src} uses plain http://, which anyone on the network path can alter; use https:// (plain http is accepted only from this machine, e.g. http://127.0.0.1)`);
      }
      console.error(`WARNING: ${flag} ${src} uses plain http:// on this machine; the keys do not count as independent`);
    }
    return parseJson(JSON.stringify(await (await import("./http.js")).fetchJson(src)));
  }
  return parseJson(fs.readFileSync(src, "utf8"));
}

const plainHttp = (src: unknown): boolean => typeof src === "string" && src.startsWith("http://");

/** What the local verify could not check because the records have not reached a witness yet. */
export function notYet(unsent: number, total: number, hasKey: boolean): string[] {
  if (!unsent) return [];
  const what = unsent === total ? `all ${total}` : `${unsent} of ${total}`;
  return [
    `checked here: signatures, chain links and content hashes of ${what} record${total === 1 ? "" : "s"}, using this machine's keys`,
    hasKey
      ? `co-signature, public timestamp: not yet for ${what} (\`signafaide flush\` sends them now, or says why it cannot)`
      : "co-signature, public timestamp: not yet. Run `signafaide init` to send hashes, or self-host (SIGNAFAIDE_URL)",
  ];
}

/** record_hash -> {content, salt} from a chain .jsonl file or every *.jsonl below a folder (§7). */
export function loadContent(src: string): Map<string, LocalContent> {
  const out = new Map<string, LocalContent>();
  const walk = (p: string): void => {
    if (fs.statSync(p).isDirectory()) for (const f of fs.readdirSync(p).sort()) walk(path.join(p, f));
    else if (p === src || p.endsWith(".jsonl")) contentFromText(fs.readFileSync(p, "utf8"), out);
  };
  walk(src);
  return out;
}

/**
 * Run the §7 verifier on a pack (path or object) or, with no pack, on the local
 * `.signafaide` state. `String(report)` is one line per check and PASS or FAIL;
 * `report.ok` is the result. Throws `KeysRequired` when no service keys can be had,
 * and a file or JSON error when the pack cannot be read.
 */
export async function verify(pack?: string | object | null, opts: VerifyOptions = {}): Promise<Report> {
  const rec = getRecorder();
  const notes: string[] = [];
  let keys: KeyDoc[] | null = null;
  let keysPlain = false;
  if (opts.keys !== undefined) {
    keys = parseServiceKeys(await readInput(opts.keys, "--keys"));
    keysPlain = plainHttp(opts.keys);
    notes.push(`service keys: ${typeof opts.keys === "string" ? opts.keys : "given"}`);
  } else if (pack == null && !Object.keys(rec.state.chainHeads()).length) {
    keys = []; // nothing has been shipped, so nothing needs a service key: no request is made
  } else if (pack == null || !opts.trustEmbeddedKeys) {
    const url = `${rec.url}/.well-known/signafaide-keys.json`;
    if (url.startsWith("http://") && !isLoopbackUrl(url)) {
      throw new KeysRequired(`will not fetch service keys over plain http from ${url}: anyone on the network path can alter them; pass --keys <file|https url>`);
    }
    keysPlain = url.startsWith("http://");
    try {
      keys = parseServiceKeys(await rec.client().request("GET", "/.well-known/signafaide-keys.json", { auth: false }));
      notes.push(`service keys: ${url}${keysPlain ? " (plain http on this machine: not independent)" : ""}`);
    } catch (e) {
      if (pack != null || Object.keys(rec.state.chainHeads()).length) {
        throw new KeysRequired(`could not load service keys from ${url} (${(e as Error).message}); pass --keys <file|url>`);
      }
      keys = []; // nothing has been shipped, so nothing needs a service key
    }
  }
  const drand = await loadDrandVerifier();
  let report: Report;
  if (pack == null) {
    const st = rec.state;
    const agentKeys: KeyDoc[] = st.agentPublicKeys().map((k) => ({ agent: k.agent, key_id: k.key_id, public_key: k.public_key, valid_from: null, valid_to: k.retired }));
    const records: any[] = [];
    const chainIds: string[] = [];
    for (const chain of st.chains()) {
      // Drafts (§8) are signed locally too: they are verified like every other record.
      for (const r of st.readAll(chain)) {
        records.push(r);
        chainIds.push(chain);
      }
    }
    report = verifyLocalState({ records, chainIds, agentKeys, heads: st.chainHeads() }, keys ?? [], drand, keysPlain);
    notes.unshift(`local state: ${st.home}`);
    const unsent = records.filter((r) => !r.receipt).length;
    report.after.push(...notYet(unsent, records.length, !!rec.apiKey));
    const held = checkHeld(rec);
    if (held.segments) {
      for (const f of held.failures) {
        const c = report.check(f.check);
        c.failures.push({ item: f.item, message: f.message });
        c.status = "fail";
      }
      report.after.push(`held aside by \`signafaide repair\`: ${plural(held.records, "record")} in ${plural(held.segments, "segment")} (signatures, links and content hashes checked here; not co-signed)`);
    }
    for (const b of rec.diagnose()) report.blocked.push(`${b.chain}: ${b.reason}; ${plural(b.records, "record")} cannot ship. Next: ${b.next}`);
    if (opts.failOnPendingSend) report.notSent = unsent;
  } else {
    const p = typeof pack === "string" ? parseJson(fs.readFileSync(pack, "utf8")) : pack;
    const chainDir = path.join(rec.state.home, "chain");
    const content = opts.content ?? (fs.existsSync(chainDir) ? chainDir : undefined);
    let agentKeys: { agent: string; key_id: string; public_key: string; valid_from: string; valid_to: string | null }[] | null = null;
    if (opts.agentKeys !== undefined) {
      agentKeys = parseAgentKeys(await readInput(opts.agentKeys, "--agent-keys"));
      notes.push(`agent keys: ${typeof opts.agentKeys === "string" ? opts.agentKeys : "given"}`);
    } else if (!opts.trustEmbeddedAgentKeys) {
      const own = rec.state.agentPublicKeys().map((k) => ({ agent: k.agent, key_id: k.key_id, public_key: k.public_key, valid_from: k.created, valid_to: k.retired }));
      if (own.length) {
        agentKeys = own;
        notes.push(`agent keys: this project's own (${path.join(rec.state.home, "agents")})`);
      }
    }
    let heads = opts.head !== undefined ? parseHeadFile(await readInput(opts.head, "--head")) : null;
    if (opts.head === undefined) {
      // This project's own newest signed heads: a pack cut off before them fails.
      const own = parseHeadFile(rec.state.heads());
      if (own.length) {
        heads = own;
        notes.push(`head: this project's own (${path.join(rec.state.home, "head.json")})`);
      }
    }
    const heights = timestampHeights(p);
    const timestamps = opts.offline || !heights.length ? null : await lookupTimestamps(opts.timestampCheck ?? DEFAULT_TIMESTAMP_URL, heights);
    report = verifyPack(p, keys, {
      trustEmbeddedKeys: opts.trustEmbeddedKeys,
      agentKeys,
      trustEmbeddedAgentKeys: opts.trustEmbeddedAgentKeys,
      heads,
      timestamps,
      contents: content ? loadContent(content) : undefined,
      drand,
      serviceKeysPlainHttp: keysPlain,
      agentKeysPlainHttp: plainHttp(opts.agentKeys),
    });
    if (!agentKeys && !opts.trustEmbeddedAgentKeys) notes.push("no agent keys: ask the customer for `signafaide keys export -o agent-keys.json` and pass --agent-keys agent-keys.json");
  }
  if (!drand && report.check("drand").checked) notes.push(DRAND_NOT_CHECKED);
  report.notes.unshift(...notes);
  return report;
}
