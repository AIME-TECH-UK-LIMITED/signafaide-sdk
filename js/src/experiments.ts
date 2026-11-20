/**
 * Experiments: A/B on past decisions.
 *
 * `await compare(candidate, { agent, name })` takes recorded decisions from the local chain
 * (verified first), calls `candidate` with each recorded input on this machine, with your own
 * models and keys, and compares its result with the recorded outcome.
 *
 * Candidate functions must be side-effect free: they get inputs only, nothing is recorded while
 * they run (a recorded tool called from a candidate throws instead of running), and compare
 * never writes to the chain. `report.upload()` sends the result to the service, hash-only by default.
 */

import { hashJson } from "./crypto.js";
import { canonicalize } from "./jcs.js";
import { plural } from "./plural.js";
import { toJsonable } from "./record.js";
import { agentChain, timeArg, verifyChain } from "./replay.js";
import { getRecorder, noWrites } from "./runtime.js";
import type { Report } from "./verifier.js";

/** The local chain did not verify, so its decisions are not compared. */
export class VerificationFailed extends Error {
  override name = "VerificationFailed";
}

/** What a candidate is compared with: the outcome's `output`, else the whole outcome content (an `error`). */
export function recordedValue(outcomeContent: Record<string, unknown>): unknown {
  return "output" in outcomeContent ? outcomeContent.output : outcomeContent;
}

export interface ExperimentRow {
  record_hash: string;
  outcome_hash: string;
  time: string;
  name: string;
  input: unknown;
  recorded: unknown;
  candidate: unknown;
  /** null when the candidate threw. */
  same: boolean | null;
  error: string | null;
  result: "agreed" | "changed" | "error";
}

export class ExperimentReport {
  uploaded: any = null;
  constructor(
    readonly agent: string,
    readonly chain: string,
    readonly name: string | null,
    readonly candidateName: string,
    readonly rows: ExperimentRow[],
    readonly skipped: number,
    readonly verification: Report,
    readonly since: string | null = null,
    readonly until: string | null = null,
    readonly label: string | null = null,
  ) {}

  get n(): number {
    return this.rows.length;
  }
  get agreed(): number {
    return this.rows.filter((r) => r.result === "agreed").length;
  }
  get changed(): number {
    return this.rows.filter((r) => r.result === "changed").length;
  }
  get errors(): number {
    return this.rows.filter((r) => r.result === "error").length;
  }
  get agreement(): number | null {
    return this.n ? this.agreed / this.n : null;
  }

  toJSON() {
    return {
      agent: this.agent,
      chain: this.chain,
      name: this.name,
      candidate: this.candidateName,
      since: this.since,
      until: this.until,
      n: this.n,
      agreed: this.agreed,
      changed: this.changed,
      errors: this.errors,
      skipped: this.skipped,
      rows: this.rows,
    };
  }

  toString(): string {
    const pct = this.n ? ` (${((this.agreed / this.n) * 100).toFixed(1)}% agreement)` : "";
    const out = [
      `compare ${this.candidateName} on ${this.agent}${this.name ? ` / ${this.name}` : ""} (${this.chain})`,
      `n ${this.n}: agreed ${this.agreed}, changed ${this.changed}, errors ${this.errors}${pct}`,
    ];
    if (this.skipped) out.push(`skipped ${plural(this.skipped, "decision")} without a co-signed outcome yet`);
    const off = this.rows.filter((r) => r.result !== "agreed");
    for (const r of off.slice(0, 20)) {
      const what =
        r.result === "error"
          ? `error ${r.error}`
          : `recorded ${canonicalize(r.recorded).slice(0, 80)}  candidate ${canonicalize(r.candidate).slice(0, 80)}`;
      out.push(`  ${r.result.padEnd(7)} ${r.record_hash.slice(0, 16)}  ${r.time}  ${what}`);
    }
    if (off.length > 20) out.push(`  ... and ${off.length - 20} more`);
    if (this.uploaded) out.push(`uploaded: ${this.uploaded.url}`);
    return out.join("\n");
  }

  /**
   * The `POST /v1/experiments` body. Hash-only unless `values`: record hashes, the result and
   * the hash of each candidate output; with `values`, the recorded and candidate values too
   * (accepted only for decisions whose content is stored with the service).
   */
  payload(values = false): Record<string, unknown> {
    const rows = this.rows.map((r) => ({
      record_hash: r.record_hash,
      outcome_hash: r.outcome_hash,
      result: r.result,
      candidate_hash: hashJson(r.candidate),
      ...(values ? { recorded: r.recorded, candidate: r.candidate } : {}),
    }));
    const body: Record<string, unknown> = {
      agent: this.agent,
      name: this.name,
      label: this.label,
      candidate: this.candidateName,
      since: this.since,
      until: this.until,
      rows,
    };
    return Object.fromEntries(Object.entries(body).filter(([, v]) => v !== null && v !== undefined));
  }

  /** Send the report to the service. `values` defaults to the recorder's `storeContent`. */
  async upload(values?: boolean): Promise<any> {
    const rec = getRecorder();
    this.uploaded = await rec
      .client(60_000)
      .request("POST", "/v1/experiments", { body: this.payload(values ?? rec.storeContent) });
    return this.uploaded;
  }
}

export interface CompareOptions {
  /** Default: the project folder name. */
  agent?: string;
  /** Only decisions of this action or tool name. */
  name?: string;
  /** `YYYY-MM-DD` or a protocol time. */
  since?: string;
  /** `YYYY-MM-DD` (inclusive) or a protocol time (exclusive). */
  until?: string;
  /** Only the newest N decisions. */
  limit?: number;
  /** Custom comparison; default: exact equality of canonical JSON. */
  same?: (recorded: unknown, candidate: unknown) => boolean;
  chain?: string;
  keys?: string | object;
  /** A name for this experiment in the console. */
  label?: string;
  upload?: boolean;
}

/**
 * Re-run recorded decisions with `candidate` and compare with what happened.
 *
 * The agent's local chain is verified first (throws `VerificationFailed` on FAIL). Decisions with
 * a co-signed outcome are taken; `candidate` receives each recorded input as recorded (the single
 * argument, or the argument list when the tool had several) and may be async. Its result is
 * compared with the outcome's `output`; a candidate that throws counts as an error.
 *
 * Never writes records and never calls recorded tools: candidates must be side-effect free.
 */
export async function compare(
  candidate: (input: any) => unknown,
  opts: CompareOptions = {},
): Promise<ExperimentReport> {
  const rec = getRecorder();
  const agent = opts.agent ?? rec.onlyAgent() ?? rec.defaultAgent;
  const chain = opts.chain ?? agentChain(rec, agent);
  const lo = timeArg(opts.since, "since");
  const hi = timeArg(opts.until, "until", true);
  const report = await verifyChain(rec, chain, opts.keys);
  if (!report.ok)
    throw new VerificationFailed(`the local chain ${chain} does not verify, so it is not compared:\n${report}`);
  const records = rec.state.readChain(chain) as any[];
  const outcomes = new Map(
    records.filter((r) => r.envelope.kind === "outcome" && r.receipt).map((r) => [r.envelope.ref, r]),
  );
  let picked: [string, any, any][] = [];
  let skipped = 0;
  for (const r of records) {
    const e = r.envelope;
    if (e.kind !== "decision" || (opts.name && e.name !== opts.name) || (lo && e.time < lo) || (hi && e.time >= hi))
      continue;
    const h = hashJson(e);
    const o = outcomes.get(h);
    const isObj = (c: unknown) => !!c && typeof c === "object" && !Array.isArray(c);
    if (!r.receipt || !o || !isObj(r.content) || !isObj(o.content)) {
      skipped++;
      continue;
    }
    picked.push([h, r, o]);
  }
  if (opts.limit !== undefined) picked = opts.limit > 0 ? picked.slice(-opts.limit) : [];
  const equal = opts.same ?? ((a: unknown, b: unknown) => canonicalize(a) === canonicalize(b));
  const fname = candidate.name || "candidate";
  const rows: ExperimentRow[] = await noWrites.run(`compare candidate ${fname}`, async () => {
    const out: ExperimentRow[] = [];
    for (const [h, d, o] of picked) {
      const recorded = recordedValue(o.content);
      const row: ExperimentRow = {
        record_hash: h,
        outcome_hash: hashJson(o.envelope),
        time: d.envelope.time,
        name: d.envelope.name,
        input: d.content.input,
        recorded,
        candidate: null,
        same: null,
        error: null,
        result: "error",
      };
      try {
        row.candidate = toJsonable(await candidate(d.content.input)) ?? null;
        row.same = !!equal(recorded, row.candidate);
        row.result = row.same ? "agreed" : "changed";
      } catch (e) {
        const err = e as { name?: string; message?: string };
        row.candidate = { error: { type: err?.name ?? typeof e, message: err?.message ?? String(e) } };
        row.error = `${err?.name ?? "Error"}: ${err?.message ?? String(e)}`;
      }
      out.push(row);
    }
    return out;
  });
  const result = new ExperimentReport(
    agent,
    chain,
    opts.name ?? null,
    fname,
    rows,
    skipped,
    report,
    lo ?? null,
    hi ?? null,
    opts.label ?? null,
  );
  if (opts.upload) await result.upload();
  return result;
}
