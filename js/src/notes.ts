/**
 * Notes for the caller (SPEC §8 notes): a possible hidden instruction in a call's arguments or in
 * its result. Never a block: the call runs and its result is returned unchanged. The notes travel
 * on a side channel that changes nothing a caller already reads: an `onNote` callback (for every
 * call, or one tool's `record(fn, { onNote })`), `notes(result)` for a result that is an object,
 * and in development (no API key, a sandbox key or test mode) one line on stderr.
 */

import type { CallNote } from "./checks.js";

export type { CallNote } from "./checks.js";

/** A note handler: called once for each note, never awaited; an error it throws is ignored. */
export type NoteHandler = (note: CallNote) => void;

const HANDLERS = new Set<NoteHandler>();
const BY_RESULT = new WeakMap<object, CallNote[]>();

/** Call `handler` with every note of every recorded call in this process. Returns a function that
 * stops it. */
export function onNote(handler: NoteHandler): () => void {
  HANDLERS.add(handler);
  return () => {
    HANDLERS.delete(handler);
  };
}

/** The notes of a call whose result is `result` (an object or an array; a string, number or other
 * primitive cannot carry them: use `onNote`). [] when there are none. */
export function notes(result: unknown): CallNote[] {
  return result !== null && (typeof result === "object" || typeof result === "function") ? [...(BY_RESULT.get(result as object) ?? [])] : [];
}

/** @internal The words of a note's stderr line. */
export function noteLine(n: CallNote): string {
  const where = n.in === "arguments" ? "the arguments of" : "the result of";
  return `signafaide: note: possible hidden instruction in ${where} ${n.tool} (${n.found.join(", ")}); the call ran unchanged`;
}

/** @internal Hand `list` to the handlers (and `own`, a tool's own), print it in development, and
 * keep it for `notes(result)` when a result is given. */
export function deliver(list: readonly CallNote[], opts: { own?: NoteHandler; development: boolean; result?: unknown }): void {
  if (!list.length) return;
  const r = opts.result;
  if (r !== null && (typeof r === "object" || typeof r === "function")) BY_RESULT.set(r as object, [...(BY_RESULT.get(r as object) ?? []), ...list]);
  for (const n of list) {
    for (const h of [...(opts.own ? [opts.own] : []), ...HANDLERS]) {
      try {
        h(n);
      } catch {
        /* a handler never changes the call */
      }
    }
    if (opts.development) console.error(noteLine(n));
  }
}

/** @internal Whether this recorder runs in development: no API key, a sandbox key, or test mode. */
export function development(rec: { apiKey?: string | null; test?: boolean }): boolean {
  return !!rec.test || !rec.apiKey || !rec.apiKey.startsWith("sfa_live_");
}
