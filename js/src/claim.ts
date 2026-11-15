/**
 * The claim step: what `init`, `status`, `claim`, a passing `verify` and the MCP tools say about a
 * sandbox. Why to claim it, and how long an unclaimed one has left. The Python SDK
 * (`_claim.py`) says the same, word for word.
 *
 * The time left comes from the witness (`expires_at` of `POST /v1/sandbox` and
 * `GET /v1/project`, SPEC §6). A witness that does not send it gets no line about days: the SDK
 * never assumes a number.
 */

import * as path from "node:path";
import { plural } from "./plural.js";
import type { Recorder } from "./runtime.js";

const DAY_MS = 86_400_000;
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/** What is known about this project's sandbox. */
export interface SandboxView {
  claim_url: string;
  claimed: boolean;
  /** When the witness deletes the unclaimed sandbox and its records there; null when it did not say. */
  expires_at: string | null;
  /** Whole days until then, rounded up; 0 once it has passed; null when `expires_at` is. */
  days_left: number | null;
  /** The witness refused the sandbox's key (`invalid_key`): it deleted the sandbox. */
  refused: boolean;
  /** `expires_at` has passed and the witness could not be asked whether the sandbox was claimed first. */
  unconfirmed: boolean;
}

const EXPIRY_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** The witness's `expires_at` when it is an RFC 3339 time (SPEC §1 writes UTC with milliseconds), else null. */
export function parseExpiry(v: unknown): string | null {
  return typeof v === "string" && EXPIRY_RE.test(v) && Number.isFinite(Date.parse(v)) ? v : null;
}

/** Whole days from `now` to `expiresAt`, rounded up; 0 once it has passed. */
export function daysLeft(expiresAt: string, now: number = Date.now()): number {
  return Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / DAY_MS));
}

/** `15 December 2026`, the UTC date. */
export function longDate(time: string): string {
  const d = new Date(time);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** The sandbox of this project when its test key is in use, else null. Unless it is known to be
 * claimed, the witness is asked once (`GET /v1/project`, or `answer` when the caller already
 * has it; `refresh: false` asks nothing) and what it says is saved in `sandbox.json`. */
export async function sandboxView(
  rec: Recorder,
  opts: { answer?: { project?: string; claimed?: boolean; expires_at?: unknown } | null; refused?: boolean; refresh?: boolean; timeoutMs?: number; now?: number } = {},
): Promise<SandboxView | null> {
  const s = rec.state.sandbox() as (Record<string, unknown> & { claim_url?: string; project?: string; claimed?: boolean }) | null;
  if (!s?.claim_url || !rec.apiKey?.startsWith("sfa_test_")) return null;
  let claimed = !!s.claimed;
  let expires = parseExpiry(s.expires_at);
  let refused = false;
  let asked = false;
  // A test key of another project (pasted from the console) says nothing about this sandbox.
  const bucket = rec.state.bucket(rec.apiKey);
  const own = !s.project || bucket.startsWith("_pending/") || bucket === `${s.project}/test`;
  if (!claimed && own) {
    let answer = opts.answer;
    refused = !!opts.refused;
    if (answer === undefined && !refused && opts.refresh !== false) {
      try {
        answer = await rec.client(opts.timeoutMs ?? 3000).project();
      } catch (e) {
        refused = (e as { code?: string }).code === "invalid_key";
        answer = null;
      }
    }
    if (answer && typeof answer === "object" && (!s.project || answer.project === s.project)) {
      asked = true;
      const next: Record<string, unknown> = { ...s };
      if (answer.claimed === true) {
        claimed = true;
        expires = null;
        next.claimed = true;
        delete next.expires_at;
      } else {
        const told = parseExpiry(answer.expires_at);
        if (told) next.expires_at = expires = told;
      }
      if (next.claimed !== s.claimed || next.expires_at !== s.expires_at) {
        try {
          rec.state.saveSandbox(next);
        } catch {
          /* shown from the answer all the same */
        }
      }
    }
  }
  const days = expires ? daysLeft(expires, opts.now) : null;
  return { claim_url: s.claim_url, claimed, expires_at: claimed ? null : expires, days_left: claimed ? null : days, refused, unconfirmed: !claimed && days === 0 && !asked && !refused };
}

/** The sandbox as data, for `--json` output. */
export function sandboxJson(v: SandboxView): { claim_url: string; claimed: boolean; expires_at: string | null; days_left: number | null } {
  return { claim_url: v.claim_url, claimed: v.claimed, expires_at: v.expires_at, days_left: v.days_left };
}

export const CLAIM_DONE = "claim: done (this sandbox belongs to an organisation now)";
export const CLAIM_WHY = "claiming is free and needs no card: the sandbox moves into your own organisation and stops expiring, and you get the console, live keys and auditor links";
const KEPT = "Records on this machine are kept and still verify";

/** How to carry on once the witness has deleted the sandbox. */
const startAgain = (envFile: string): string =>
  `${KEPT}. To carry on with the service: remove SIGNAFAIDE_API_KEY from ${envFile} (or from the environment), run \`signafaide init\` for a new sandbox and claim it`;

/** The lines after the claim link: why to claim, and the time left when the witness gave it. */
export function claimNotes(v: SandboxView): string[] {
  const lines = [CLAIM_WHY];
  if (v.expires_at && v.days_left) {
    lines.push(`${plural(v.days_left, "day")} left: an unclaimed sandbox and its records on the service are deleted on ${longDate(v.expires_at)}. ${KEPT}`);
  }
  return lines;
}

/** Everything about the claim step, one plain line each; the first starts with `claim: `. */
export function claimLines(v: SandboxView, root: string): string[] {
  const envFile = path.join(root, ".env");
  if (v.claimed) return [CLAIM_DONE];
  if (v.unconfirmed) {
    return [
      `claim: ${v.claim_url}`,
      `this sandbox was due to be deleted on ${longDate(v.expires_at!)} unless it was claimed first, and the service could not be asked just now; run \`signafaide status\` when it can be reached. ${KEPT}`,
    ];
  }
  if (v.expires_at && v.days_left === 0) {
    return [
      `claim: this sandbox expired on ${longDate(v.expires_at)} without being claimed, so its claim link no longer works. The service deletes an expired sandbox and its records there within a day, and from then on refuses its key (invalid_key)`,
      startAgain(envFile),
    ];
  }
  if (v.refused) {
    return [
      "claim: the service refuses this sandbox's key (invalid_key). The service deletes an unclaimed sandbox and its records there when it expires, and this one had not been claimed when this machine last asked",
      startAgain(envFile),
    ];
  }
  return [`claim: ${v.claim_url}`, ...claimNotes(v)];
}

/** Whether the sandbox can no longer be claimed (expired, or its key refused). */
export function sandboxGone(v: SandboxView): boolean {
  return !v.claimed && !v.unconfirmed && ((!!v.expires_at && v.days_left === 0) || v.refused);
}
