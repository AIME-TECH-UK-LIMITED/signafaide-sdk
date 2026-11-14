/** Every error code a signafAIde user can see, what it means and how to fix it (MCP `signafaide_explain_error`). */

export interface ErrorDoc {
  code: string;
  /** HTTP status for service errors; 0 for errors raised by the SDK itself. */
  status: number;
  means: string;
  fix: string;
}

/** The service codes are SPEC §6; the rest come from the SDKs. */
export const ERRORS: ErrorDoc[] = [
  {
    code: "chain_conflict",
    status: 409,
    means: "The record's seq or prev does not follow the head the service holds for that agent, so the local chain and the service's chain differ. The SDK stops shipping that agent's records and never rewrites the local chain.",
    fix: "Run `signafaide status` and `signafaide verify` to see where the chains part. The usual cause is two machines or two copies of `.signafaide/` writing for the same agent name with the same key: give each its own agent name, or keep one `.signafaide/` per project.",
  },
  {
    code: "bad_signature",
    status: 400,
    means: "A record's signature does not verify; its key was not active at the record's time, or was revoked before the service received it; or an agent registration's proof of possession or rotation signature is missing or wrong.",
    fix: "Do not edit `.signafaide/` by hand. If an agent key file in `.signafaide/agents/` was replaced, restore it from backup. If the key was revoked, run `signafaide repair --agent <name>`: it sets aside the records the key signed after it ended (kept, still verifiable locally) and gives the agent a new key. To give an agent a new key otherwise, run `signafaide keys rotate` (the SDK signs the rotation with the old key), or have a developer or admin revoke the old key in the console first.",
  },
  {
    code: "unknown_agent",
    status: 400,
    means: "Records arrived for an agent whose key is not registered with the service.",
    fix: "The SDK registers agents itself and retries once. If it persists, run `signafaide flush` and check that `.signafaide/agents/<agent>.key` exists.",
  },
  {
    code: "content_mismatch",
    status: 400,
    means: "With store_content on, the content sent does not hash to the envelope's content_hash.",
    fix: "Content must be JSON-serialisable and must not change after the call. Wrap the function so the SDK hashes the exact value it sends.",
  },
  {
    code: "quota_exceeded",
    status: 429,
    means: "The monthly record quota of this project is used up. Records stay in the local outbox and nothing is lost. The SDK stops sending in the background until the API key or SIGNAFAIDE_URL changes, so it never floods the service.",
    fix: "Claim the sandbox (`signafaide claim`) and use a live key, or wait for the next month; then `signafaide flush`. `signafaide status` shows the quota.",
  },
  {
    code: "plan_required",
    status: 402,
    means: "The organization's plan does not include this feature, for example stored content on live records on Free. Records refused for it stay in the local outbox and nothing is lost.",
    fix: "An owner or admin upgrades the organization on the console's Billing page (the message has the link), then run `signafaide flush`. Or turn store_content off to keep records hash-only.",
  },
  {
    code: "invalid_key",
    status: 401,
    means: "The API key is missing, malformed or revoked.",
    fix: "Check SIGNAFAIDE_API_KEY in the environment or `.env`. Remove it and run `signafaide init` to create a new sandbox, or paste a live key from the console.",
  },
  {
    code: "invalid_record",
    status: 400,
    means: "A request or record breaks the rules of SPEC §2: a schema error (an agent name that is not lowercase, a name over 128 characters), an envelope for another project or env, a time more than 300 s ahead of the service clock or earlier than the agent's previous record, or a key registration with a valid_from more than 7 days back.",
    fix: "The message names the record and the rule. Agent names match ^[a-z0-9][a-z0-9._-]{0,63}$; record names are 1 to 128 characters and never personal data. For time errors, fix the machine's clock (NTP); records already written with a time the witness cannot take make the chain BLOCKED, and `signafaide repair` sets them aside and starts a new segment.",
  },
  {
    code: "rate_limited",
    status: 429,
    means: "Too many requests from this client (sandbox keys and sandbox creation are rate-limited).",
    fix: "Nothing to do: the SDK retries with backoff. For sustained volume, claim the project and use a live key.",
  },
  {
    code: "not_found",
    status: 404,
    means: "The record, agent head or route does not exist in this project and env.",
    fix: "Check the record hash or agent name, and that the API key belongs to the project that wrote it (a sandbox key and a live key are different projects).",
  },
  {
    code: "bad_request",
    status: 400,
    means: "A query parameter or request body (other than a record) is invalid.",
    fix: "The message names the field. For `signafaide export`, --from and --to are RFC 3339 times.",
  },
  {
    code: "network",
    status: 0,
    means: "The service could not be reached. Records are kept in `.signafaide/outbox/` and ship later; nothing is lost.",
    fix: "Check SIGNAFAIDE_URL and the network, then run `signafaide flush`. Only strict mode waits for the service.",
  },
  {
    code: "not_recorded",
    status: 0,
    means: "Strict mode: the decision got no receipt from the service, so the function did not run.",
    fix: "Fix the cause in the message (often `network`), then call again. Use strict mode only where an action must never run unrecorded.",
  },
  {
    code: "not_written",
    status: 0,
    means: "The gateway could not write the decision record on this machine, so it did not forward the tool call to the MCP server (it fails closed).",
    fix: "Fix the cause in the message, usually a folder that cannot be written: set SIGNAFAIDE_HOME to a writable folder for the gateway, then call the tool again.",
  },
  {
    code: "no_receipts",
    status: 0,
    means: "The service accepted a batch but returned no receipts matching it.",
    fix: "Run `signafaide flush` again and `signafaide verify`. If it repeats, report it with the output of `signafaide status`.",
  },
  {
    code: "bad_response",
    status: 0,
    means: "The service answered with values the SDK refuses to use: an API key, project id or env that is not well formed, or receipts for another project. Nothing was written to `.env` or `.signafaide/`.",
    fix: "Check SIGNAFAIDE_URL: it should be your signafAIde service, over https. A wrong URL in a cloned repo's `.env` is the usual cause.",
  },
  {
    code: "state",
    status: 0,
    means: "The local `.signafaide/` state could not be used, for example a folder that cannot be written (a read-only disk), a damaged chain line or a lock held by another process.",
    fix: "The message names the file. On a read-only disk, set SIGNAFAIDE_HOME to a writable folder (see the production guide), or SIGNAFAIDE_DISABLED=1 to turn recording off. Do not delete chain files: they are your evidence. Move a damaged line aside, then run `signafaide verify`.",
  },
  {
    code: "key_mismatch",
    status: 0,
    means: "The service has a different key registered for this agent name than the local key file.",
    fix: "Another machine registered this agent name first. Use a different agent name here, or restore the original key file.",
  },
  {
    code: "no_key",
    status: 0,
    means: "Strict mode needs the service's receipt before the function runs, and there is no API key. Without a key records stay local and nothing is sent, so a strict call cannot proceed.",
    fix: "A person opts in with `signafaide init` (a free sandbox, no account) or by setting SIGNAFAIDE_API_KEY (and SIGNAFAIDE_URL for a self-hosted witness). Or turn strict mode off for that tool.",
  },
  {
    code: "too_old",
    status: 0,
    means: "A chain written locally before the opt-in starts more than 7 days ago. The service accepts records only up to 7 days old (an agent key's valid_from is at most 7 days before its registration, spec §2.4), so that chain stays local.",
    fix: "Nothing to repair: the local chain still verifies with `signafaide verify`, and new records of that agent start a new chain that ships. Opt in sooner next time.",
  },
  {
    code: "chain_exists",
    status: 0,
    means: "A chain written before the project was known cannot join the project, because that agent already has a chain there. It stays pending, on this machine only.",
    fix: "Nothing to repair: it still verifies with `signafaide verify`. To ship such records, use a different agent name before opting in.",
  },
];

export function explainError(code: string, docsBase?: string): string {
  const c = code.trim().toLowerCase();
  const e = ERRORS.find((x) => x.code === c);
  if (!e) return `Unknown code "${code}". Known codes: ${ERRORS.map((x) => x.code).join(", ")}.`;
  const lines = [`${e.code}${e.status ? ` (HTTP ${e.status})` : " (raised by the SDK)"}`, `What it means: ${e.means}`, `How to fix it: ${e.fix}`];
  if (e.status && docsBase) lines.push(`Docs: ${docsBase.replace(/\/+$/, "")}/docs/errors#${e.code}`);
  return lines.join("\n");
}
