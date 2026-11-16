/** Every error code a signafAIde user can see, what it means and how to fix it (MCP `signafaide_explain_error`). */

import guidance from "../../spec/guidance.json" with { type: "json" };

export interface ErrorDoc {
  code: string;
  /** HTTP status for service errors; 0 for errors raised by the SDK itself. */
  status: number;
  means: string;
  fix: string;
}

/** The service codes are SPEC §6; the rest come from the SDKs. The text lives in one data file
 * that the hosted service's remote MCP server reads too. */
export const ERRORS: ErrorDoc[] = guidance.errors;

const fill = (template: string, values: Record<string, string>): string => template.replace(/\{([a-z_]+)\}/g, (whole, key: string) => values[key] ?? whole);

export function explainError(code: string, docsBase?: string): string {
  const t = guidance.error_text;
  const c = code.trim().toLowerCase();
  const e = ERRORS.find((x) => x.code === c);
  if (!e) return fill(t.unknown, { code, codes: ERRORS.map((x) => x.code).join(", ") });
  const values = { code: e.code, status: String(e.status), means: e.means, fix: e.fix, base: (docsBase ?? "").replace(/\/+$/, "") };
  const lines = [fill(e.status ? t.service : t.sdk, values), fill(t.means, values), fill(t.fix, values)];
  if (e.status && docsBase) lines.push(fill(t.docs, values));
  return lines.join("\n");
}
