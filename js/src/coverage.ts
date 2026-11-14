/**
 * Tool declarations (SPEC §2.6) and the coverage they give (§7): which of an agent's tools are
 * recorded, read from envelopes alone (kind, name, seq), so it holds for hash-only records.
 * Pure: no I/O. The same names, rules and wording as the Rust core and the Python SDK.
 *
 * Coverage is a note, never a failure, and never a claim of completeness: a declaration is the
 * client's own signed statement of the tools the agent has.
 */

import { sha256Hex } from "./crypto.js";
import { plural } from "./plural.js";

/** The name of the note that starts a new tool declaration for the agent's chain. */
export const TOOLS = "signafaide.tools";
/** `signafaide.tool/<tool name>`: the agent has this tool and calls to it are recorded. */
export const TOOL_PREFIX = "signafaide.tool/";
/** `signafaide.tool_unrecorded/<tool name>`: the agent has this tool and calls to it are not recorded. */
export const TOOL_UNRECORDED_PREFIX = "signafaide.tool_unrecorded/";
/** The names the SDK reserves: a record named so is never a tool. */
export const RESERVED_PREFIX = "signafaide.";
/** The longest tool name a declaration holds as it is, in characters (Unicode code points): an
 * envelope name is at most 128 and the longer prefix takes 27. */
export const MAX_DECLARED_NAME = 101;
const KEPT = MAX_DECLARED_NAME - 9;

/** A tool's name as a declaration holds it: the name itself when it has at most 101 characters,
 * else its first 92 characters, `~`, and the first 8 hex characters of sha256(UTF-8 tool name).
 * A name that is already short maps to itself. */
export function declaredName(tool: string): string {
  const chars = [...tool];
  if (chars.length <= MAX_DECLARED_NAME) return tool;
  return `${chars.slice(0, KEPT).join("")}~${sha256Hex(new TextEncoder().encode(tool)).slice(0, 8)}`;
}

/** The envelope name of the note that declares `tool`. */
export function toolNoteName(tool: string, recorded: boolean): string {
  return (recorded ? TOOL_PREFIX : TOOL_UNRECORDED_PREFIX) + declaredName(tool);
}

/** What a record says about the agent's tool list, from its kind and name alone: `"header"`,
 * a tool, or null when it is not a tool-declaration note. */
export function toolNote(kind: unknown, name: unknown): "header" | { name: string; recorded: boolean } | null {
  if (kind !== "note" || typeof name !== "string") return null;
  if (name === TOOLS) return "header";
  const recorded = name.startsWith(TOOL_PREFIX);
  if (!recorded && !name.startsWith(TOOL_UNRECORDED_PREFIX)) return null;
  const rest = name.slice((recorded ? TOOL_PREFIX : TOOL_UNRECORDED_PREFIX).length);
  return rest ? { name: rest, recorded } : null;
}

export interface DeclaredTool {
  name: string;
  recorded: boolean;
}

/** What one agent's records show about its tools (§7 tool coverage). */
export interface Coverage {
  /** The tools of the agent's current declaration, in name order; empty when there is none. */
  declared: DeclaredTool[];
  /** The names of decision records that are not in the current declaration, in name order. */
  undeclared_recorded: string[];
  /** The seq of the `signafaide.tools` note that starts the current declaration, or null. */
  declared_at_seq: number | null;
}

/** Name order: by Unicode code point, as Rust and Python sort strings (JavaScript's own order is
 * by UTF-16 unit, which differs for characters outside the basic plane). */
export function byCodePoint(a: string, b: string): number {
  const [x, y] = [[...a], [...b]];
  for (let i = 0; i < x.length && i < y.length; i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d) return d;
  }
  return x.length - y.length;
}

/** The coverage of one agent's records, given in seq order. The current declaration is the one
 * started by the last `signafaide.tools` note; tool notes before the first such note belong to a
 * declaration the records do not hold and are ignored. Inside a declaration a later note for the
 * same tool replaces an earlier one. A `decision` counts as a recorded tool unless its name
 * starts with `signafaide.`; it is compared by its declared name. */
export function coverage(records: Iterable<{ seq: number; kind: unknown; name: unknown }>): Coverage {
  let at: number | null = null;
  let tools = new Map<string, boolean>();
  const called = new Set<string>();
  for (const { seq, kind, name } of records) {
    const t = toolNote(kind, name);
    if (t === "header") {
      at = seq;
      tools = new Map();
    } else if (t) {
      if (at !== null) tools.set(t.name, t.recorded);
    } else if (kind === "decision" && typeof name === "string" && !name.startsWith(RESERVED_PREFIX)) called.add(declaredName(name));
  }
  if (at === null) return { declared: [], undeclared_recorded: [], declared_at_seq: null };
  return {
    declared: [...tools.keys()].sort(byCodePoint).map((name) => ({ name, recorded: tools.get(name)! })),
    undeclared_recorded: [...called].filter((n) => !tools.has(n)).sort(byCodePoint),
    declared_at_seq: at,
  };
}

/** `1 declared tool is`, `2 declared tools are`. */
const countIs = (n: number, one: string): string => `${plural(n, one)} ${n === 1 ? "is" : "are"}`;

/** The coverage of `agent` in words (§7), one line each: what was declared, then the recorded
 * tools the declaration does not list. */
export function coverageLines(agent: string, c: Coverage): string[] {
  if (c.declared_at_seq === null) return [`${agent}: no tool list was declared, so the pack cannot show which of the agent's tools are recorded`];
  const unrecorded = c.declared.filter((t) => !t.recorded).map((t) => t.name);
  const out: string[] = [];
  if (!c.declared.length) out.push(`${agent}: the declared tool list is empty`);
  else if (!unrecorded.length) out.push(`${agent}: all ${countIs(c.declared.length, "declared tool")} recorded`);
  else out.push(`${agent}: ${countIs(unrecorded.length, "declared tool")} not recorded: ${unrecorded.join(", ")}`);
  if (c.undeclared_recorded.length) out.push(`${agent}: ${countIs(c.undeclared_recorded.length, "recorded tool")} not in the declared tool list: ${c.undeclared_recorded.join(", ")}`);
  return out;
}
