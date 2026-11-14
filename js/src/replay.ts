/**
 * Replay: what an agent saw and did, from the local chain, proven.
 *
 * `await replay({ agent: "claims-bot" })` reads the agent's chain in `.signafaide/chain`, runs
 * the §7 verifier over it (signatures, chain links, receipts, and each record's content against
 * its `content_hash`), and returns the timeline of decisions and outcomes with their inputs and
 * outputs. `String(r)` is the terminal view; `r.toHtml()` a self-contained page. Node only.
 */

import * as fs from "node:fs";
import { hashJson } from "./crypto.js";
import { fetchJson } from "./http.js";
import { plural } from "./plural.js";
import type { SignedRecord } from "./records.js";
import { getRecorder, type Recorder } from "./runtime.js";
import { StateError } from "./state.js";
import { KeysRequired, loadDrandVerifier, parseServiceKeys, verifyLocalState, type KeyDoc, type Report } from "./verifier.js";

const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Service keys from a file path, an http(s) URL or the parsed document. */
export async function loadServiceKeys(src: string | object): Promise<KeyDoc[]> {
  if (typeof src !== "string") return parseServiceKeys(src);
  return parseServiceKeys(/^https?:\/\//.test(src) ? await fetchJson(src) : JSON.parse(fs.readFileSync(src, "utf8")));
}

/** `YYYY-MM-DD` or a protocol time as a protocol time; a bare date as an end bound means the end of that day. */
export function timeArg(value: string | undefined | null, name: string, end = false): string | undefined {
  if (!value) return undefined;
  if (DATE_RE.test(value)) {
    const d = new Date(`${value}T00:00:00.000Z`);
    if (Number.isNaN(d.getTime())) throw new SyntaxError(`${name} must be YYYY-MM-DD or a time like 2026-11-13T10:00:00.000Z`);
    if (end) d.setUTCDate(d.getUTCDate() + 1);
    return d.toISOString();
  }
  if (!TIME_RE.test(value)) throw new SyntaxError(`${name} must be YYYY-MM-DD or a time like 2026-11-13T10:00:00.000Z`);
  return value;
}

/** The chain to read for `agent`: the current API key's, else the only one there is. */
export function agentChain(rec: Recorder, agent: string): string {
  const current = `${rec.state.bucket(rec.apiKey)}/${agent}`;
  if (fs.existsSync(rec.state.chainPath(current))) return current;
  const found = rec.state.chains().filter((c) => c.split("/").pop() === agent);
  if (found.length === 1) return found[0];
  if (!found.length) throw new StateError(`no local chain for agent "${agent}" in ${rec.state.home}; agents here: ${rec.state.agents().join(", ") || "none"}`);
  throw new StateError(`agent "${agent}" has several chains (${found.join(", ")}); pass chain (--chain) to pick one`);
}

/** Run the §7 verifier over one local chain. */
export async function verifyChain(rec: Recorder, chain: string, keys?: string | object): Promise<Report> {
  const st = rec.state;
  const records = st.readAll(chain); // drafts (§8) are signed locally and verified too
  let serviceKeys: KeyDoc[];
  let note: string;
  if (keys !== undefined) {
    serviceKeys = await loadServiceKeys(keys);
    note = `service keys: ${typeof keys === "string" ? keys : "given"}`;
  } else if (!records.some((r) => r.receipt)) {
    serviceKeys = []; // no request: nothing has been co-signed
    note = "service keys: none needed (nothing co-signed yet)";
  } else {
    try {
      serviceKeys = parseServiceKeys(await rec.client().request("GET", "/.well-known/signafaide-keys.json", { auth: false }));
      note = `service keys: ${rec.url}/.well-known/signafaide-keys.json`;
    } catch (e) {
      if (records.some((r) => r.receipt)) throw new KeysRequired(`could not load service keys from ${rec.url} (${(e as Error).message}); pass keys (--keys <file|url>)`);
      serviceKeys = [];
      note = "service keys: none needed (nothing co-signed yet)";
    }
  }
  const agentKeys: KeyDoc[] = st.agentPublicKeys().map((k) => ({ agent: k.agent, key_id: k.key_id, public_key: k.public_key, valid_from: null, valid_to: k.retired }));
  const heads = Object.fromEntries(Object.entries(st.chainHeads()).filter(([c]) => c === chain));
  const base = rec.state.chainBase(chain);
  const report = verifyLocalState({ records, chainIds: records.map(() => chain), agentKeys, heads, bases: base ? { [chain]: base } : {} }, serviceKeys, await loadDrandVerifier());
  report.notes.unshift(`chain: ${chain}`, note);
  return report;
}

/** One record of the timeline. */
export class Entry {
  problems: string[] = [];
  /** The outcome of a decision, or the decision of an outcome. */
  pair: Entry | null = null;
  constructor(
    readonly record: SignedRecord,
    readonly hash: string,
  ) {}
  get envelope() {
    return this.record.envelope;
  }
  get content(): Record<string, unknown> | null {
    const c = this.record.content;
    return c && typeof c === "object" && !Array.isArray(c) ? (c as Record<string, unknown>) : null;
  }
  get receipt(): any {
    return (this.record as any).receipt ?? null;
  }
  /** Why the witness can never take this record (the chain is BLOCKED from here), or null. */
  blocked: string | null = null;
  /** `verified`, `signed` (not co-signed by the service yet), `BLOCKED` (can never be co-signed as it is) or `FAIL`. */
  get status(): "verified" | "signed" | "BLOCKED" | "FAIL" {
    return this.problems.length ? "FAIL" : this.receipt ? "verified" : this.blocked ? "BLOCKED" : "signed";
  }
  toJSON() {
    const e = this.envelope;
    const b = this.receipt?.batch ?? {};
    return {
      seq: e.seq, kind: e.kind, name: e.name, time: e.time, record_hash: this.hash, ref: e.ref, content_hash: e.content_hash,
      content: this.content, status: this.status, problems: this.problems, ...(this.blocked ? { blocked: this.blocked } : {}), batch_seq: b.seq ?? null, server_time: b.server_time ?? null,
      drand_round: b.drand?.round ?? null, pair: this.pair?.hash ?? null,
    };
  }
}

const esc = (s: unknown): string => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export class Replay {
  constructor(
    readonly agent: string,
    readonly chain: string,
    readonly entries: Entry[],
    readonly report: Report,
    readonly since: string | null,
    readonly until: string | null,
    readonly total: number,
  ) {}

  /** Why the chain cannot ship from some record on (`signafaide repair` fixes it), or null. */
  blocked: { seq: number; reason: string; next: string } | null = null;

  get ok(): boolean {
    return this.report.ok && !this.blocked;
  }

  /** PASS, FAIL or BLOCKED (a chain the witness refuses never passes). */
  get result(): string {
    return this.report.result === "PASS" && this.blocked ? "BLOCKED" : this.report.result;
  }

  toJSON() {
    return {
      agent: this.agent, chain: this.chain, since: this.since, until: this.until, total: this.total, shown: this.entries.length, result: this.result,
      ...(this.blocked ? { blocked: this.blocked } : {}), verification: this.report.toJSON(), entries: this.entries.map((e) => e.toJSON()),
    };
  }

  lines(): string[] {
    const out = [`signafAIde replay: ${this.agent}  (${this.chain})`, `window: ${this.since ?? "start"} to ${this.until ?? "now"}; ${this.entries.length} of ${plural(this.total, "record")} shown`];
    out.push(`verification: ${this.report.resultLine}` + (this.report.ok ? "" : ` (first failed check: ${this.report.firstFailed()})`));
    if (this.blocked) out.push(`BLOCKED from seq ${this.blocked.seq}: ${this.blocked.reason}. Next: ${this.blocked.next}`);
    out.push(...this.report.notes.map((n) => `  ${n}`), "");
    for (const e of this.entries) {
      const env = e.envelope;
      const link = e.pair ? (env.kind === "decision" ? `  -> outcome #${e.pair.envelope.seq}` : `  <- decision #${e.pair.envelope.seq}`) : "";
      const rc = e.receipt;
      const where = rc ? `batch ${rc.batch.seq}` + (rc.batch.drand ? `, drand ${rc.batch.drand.round}` : "") : e.blocked ? "the witness cannot take it" : "not co-signed yet";
      out.push(`#${String(env.seq).padEnd(5)} ${env.time}  ${env.kind.padEnd(8)} ${env.name}${link}`);
      out.push(`       ${e.hash.slice(0, 16)}  ${e.status.toUpperCase()} (${where})`);
      for (const p of e.problems) out.push(`       ! ${p}`);
      for (const [k, v] of Object.entries(e.content ?? {})) {
        let text = JSON.stringify(v);
        if (text.length > 100) text = JSON.stringify(v, null, 2).split("\n").map((l, i) => (i ? "         " + l : l)).join("\n");
        out.push(`       ${k.padEnd(7)} ${text}`);
      }
      if (!e.content) out.push("       (no local content for this record)");
      out.push("");
    }
    const failed = this.entries.filter((e) => e.problems.length).length;
    const signed = this.entries.filter((e) => !e.receipt && !e.problems.length).length;
    const blockedN = this.entries.filter((e) => e.status === "BLOCKED").length;
    const what = failed
      ? `${failed} failed`
      : signed
        ? `each checked against its content_hash and signature; ${signed} not co-signed yet${blockedN ? ` (${blockedN} BLOCKED)` : ""}, so their receipts could not be checked`
        : "each checked against its content_hash, its signature and its receipt";
    out.push(`${this.result}: ${plural(this.entries.length, "record")} shown, ${what}`);
    return out;
  }

  toString(): string {
    return this.lines().join("\n");
  }

  /** One self-contained page: inline CSS, no scripts, no external assets. */
  toHtml(): string {
    const rows = this.entries.map((e) => {
      const env = e.envelope;
      const rc = e.receipt;
      const link = e.pair ? `<span class="muted">${env.kind === "decision" ? "outcome" : "decision"} <a href="#r${e.pair.envelope.seq}">#${e.pair.envelope.seq}</a></span>` : "";
      const cls = { verified: "ok", signed: "warn", BLOCKED: "bad", FAIL: "bad" }[e.status];
      const body =
        Object.entries(e.content ?? {})
          .map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><pre>${esc(JSON.stringify(v, null, 2))}</pre></div>`)
          .join("") || '<p class="muted">No local content for this record.</p>';
      const probs = e.problems.map((p) => `<li>${esc(p)}</li>`).join("");
      const receipt = rc ? `batch ${rc.batch.seq} · ${esc(rc.batch.server_time)}` + (rc.batch.drand ? ` · drand ${rc.batch.drand.round}` : "") : e.blocked ? `BLOCKED: ${esc(e.blocked)}` : "not co-signed by the service yet";
      return (
        `<article id="r${env.seq}" class="${esc(env.kind)}"><header><span class="seq">#${env.seq}</span><span class="kind">${esc(env.kind)}</span><b>${esc(env.name)}</b>${link}<span class="st ${cls}">${e.status}</span></header>` +
        `<div class="meta"><code title="record_hash">${e.hash}</code> · ${esc(env.time)} · ${receipt}</div>` +
        (probs ? `<ul class="probs">${probs}</ul>` : "") +
        body +
        "</article>"
      );
    });
    const label = (c: Report["checks"][number]) => (c.status === "fail" ? "FAIL" : c.status === "not_checked" ? "NOT CHECKED" : c.status === "pending" ? "PENDING" : (c.value ?? "pass").toUpperCase());
    const checks = this.report.checks
      .map((c) => `<tr><td>${c.n}</td><td>${esc(c.title)}</td><td><span class="st ${c.status === "pass" ? "ok" : c.status === "fail" ? "bad" : ""}">${label(c)}</span></td><td>${esc(c.detail)}</td></tr>`)
      .join("");
    const notes = this.report.notes.map((n) => `<li>${esc(n)}</li>`).join("");
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Replay: ${esc(this.agent)}</title><style>${CSS}</style></head><body><main>
<p class="muted small">signafAIde replay</p><h1>${esc(this.agent)}</h1>
<p class="muted">${esc(this.chain)} · ${esc(this.since ?? "start")} to ${esc(this.until ?? "now")} · ${this.entries.length} of ${plural(this.total, "record")}</p>
<p class="result">Verification: <span class="st ${this.ok ? "ok" : "bad"}">${this.result}</span> <span class="muted small">${esc(this.report.resultLine)}</span></p>
${this.blocked ? `<p class="probs">BLOCKED from seq ${this.blocked.seq}: ${esc(this.blocked.reason)}. Next: ${esc(this.blocked.next)}</p>` : ""}
<details><summary>Checks</summary><ul class="small muted">${notes}</ul><table>${checks}</table></details>
${rows.join("")}
<footer>Each record was checked against its content_hash, its signature and the service's receipt. Generated by signafAIde from the local chain.</footer>
</main></body></html>`;
  }
}

const CSS = `
*{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#1a1d23;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 24px 64px}h1{margin:0;font-size:22px}a{color:#2456c4}
.muted{color:#5d6472}.small{font-size:12px}.result{font-weight:600}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}td{padding:4px 8px;border-bottom:1px solid #e3e6ec;vertical-align:top}
article{background:#fff;border:1px solid #e3e6ec;border-radius:8px;padding:12px 14px;margin:10px 0}
article.outcome{margin-left:28px}article header{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.seq{color:#5d6472;font-variant-numeric:tabular-nums}.kind{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5d6472}
.meta{font-size:12px;color:#5d6472;margin:4px 0 8px;word-break:break-all}code,pre{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{margin:2px 0 6px;padding:8px 10px;background:#f6f7f9;border-radius:6px;white-space:pre-wrap;word-break:break-word}
.kv>span{font-size:11.5px;font-weight:600;color:#4a5160}
.st{margin-left:auto;padding:1px 8px;border-radius:4px;font-size:11.5px;font-weight:700;background:#eceef2;color:#4a5160}
.st.ok{background:#e3f4ea;color:#1d6b3f}.st.warn{background:#fdf2dc;color:#7a5200}.st.bad{background:#fbe5e5;color:#9b1c1c}
.probs{color:#9b1c1c;font-size:12.5px;margin:4px 0}footer{margin-top:24px;font-size:12px;color:#5d6472}
@media print{body{background:#fff}article{break-inside:avoid}}
`;

export interface ReplayOptions {
  /** Default: the project folder name. */
  agent?: string;
  /** `YYYY-MM-DD` or a protocol time. */
  since?: string;
  /** `YYYY-MM-DD` (inclusive) or a protocol time (exclusive). */
  until?: string;
  /** A record hash (or a prefix of 8+ characters): that record and its decision or outcome. */
  record?: string;
  /** The chain id, when the agent has several. */
  chain?: string;
  /** Service keys: a file path, URL or the parsed document. Default: fetched from the service. */
  keys?: string | object;
}

/**
 * The agent's decisions and outcomes from the local chain, each checked against its
 * `content_hash`, its signature and its receipt. Never writes anything.
 */
export async function replay(opts: ReplayOptions = {}): Promise<Replay> {
  const rec = getRecorder();
  const agent = opts.agent ?? rec.onlyAgent() ?? rec.defaultAgent;
  const chain = opts.chain ?? agentChain(rec, agent);
  const lo = timeArg(opts.since, "since");
  const hi = timeArg(opts.until, "until", true);
  const report = await verifyChain(rec, chain, opts.keys);
  let entries = rec.state.readAll(chain).map((r) => new Entry(r, hashJson(r.envelope)));
  const byLabel = new Map<string, string[]>();
  for (const c of report.checks) for (const f of c.failures) byLabel.set(f.item, [...(byLabel.get(f.item) ?? []), `${c.title}: ${f.message}`]);
  const byHash = new Map(entries.map((e) => [e.hash, e]));
  for (const e of entries) {
    const env = e.envelope;
    const rc = e.receipt;
    e.problems = [...(byLabel.get(`${chain}#${env.seq}`) ?? [])];
    if (rc) e.problems.push(...(byLabel.get(`batch ${rc.batch.seq}`) ?? []), ...(byLabel.get(`head ${rc.head.agent}#${rc.head.seq}`) ?? []));
    const d = env.kind === "outcome" && env.ref ? byHash.get(env.ref) : undefined;
    if (d) [e.pair, d.pair] = [d, e];
  }
  const total = entries.length;
  if (opts.record) {
    const r = opts.record.toLowerCase();
    if (r.length < 8) throw new SyntaxError("record must be a record hash or a prefix of at least 8 characters");
    const hit = entries.filter((e) => e.hash.startsWith(r));
    if (hit.length !== 1) throw new StateError(`${hit.length ? hit.length : "no"} records match ${opts.record} in ${chain}`);
    entries = [hit[0], hit[0].pair].filter((x): x is Entry => !!x).sort((a, b) => a.envelope.seq - b.envelope.seq);
  }
  const b = rec.diagnose().find((x) => x.chain === chain);
  if (b) for (const e of entries) if (!e.receipt && e.envelope.seq >= b.seq) e.blocked = b.reason;
  entries = entries.filter((e) => (!lo || e.envelope.time >= lo) && (!hi || e.envelope.time < hi));
  const r = new Replay(agent, chain, entries, report, lo ?? null, hi ?? null, total);
  if (b) r.blocked = { seq: b.seq, reason: b.reason, next: b.next };
  return r;
}
