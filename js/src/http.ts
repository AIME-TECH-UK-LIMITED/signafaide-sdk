/** Minimal JSON client for the signafAIde HTTP API (SPEC §6). Built-in fetch only. */

import { HEADER, clientHeader } from "./telemetry.js";
import { VERSION } from "./version.js";

/** The hosted witness. Configurable with SIGNAFAIDE_URL (a self-hosted witness, or a local dev
 * server such as http://127.0.0.1:7474); a release test fails if this is ever a loopback address. */
export const DEFAULT_URL = "https://api.signafaide.co.uk";

/** Errors the SDK cannot fix by retrying: shipping stops until the configuration changes. */
export const NON_RETRYABLE = new Set(["quota_exceeded", "invalid_key", "plan_required", "bad_signature", "invalid_record", "content_mismatch", "chain_conflict", "unknown_agent", "key_mismatch", "bad_response"]);

/** A response, as the transport hands it to the client. */
export interface TransportResponse {
  status: number;
  contentType: string;
  text: string;
}

/** How a request is made. The default is `fetch`; the Node runtime passes one whose idle
 * sockets do not keep the process alive. `signal` aborts it. */
export type Transport = (req: { method: string; url: string; headers: Record<string, string>; body?: string; timeoutMs: number; signal?: AbortSignal }) => Promise<TransportResponse>;

/** The fetch transport (browsers, edge runtimes, Node). */
export const fetchTransport: Transport = async (req) => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error("timeout")), req.timeoutMs);
  const onAbort = () => ctrl.abort(new Error("aborted"));
  if (req.signal?.aborted) onAbort();
  else req.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const resp = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, signal: ctrl.signal });
    return { status: resp.status, contentType: resp.headers.get("content-type") ?? "", text: await resp.text() };
  } finally {
    clearTimeout(timer);
    req.signal?.removeEventListener("abort", onAbort);
  }
};

/**
 * An error from the service or the SDK. `message` is the one-sentence fix.
 * `code` is the service error code (`chain_conflict`, `invalid_key`...), or
 * `network` when the service could not be reached.
 */
export class SignafaideError extends Error {
  readonly code: string;
  readonly status: number;
  readonly docs?: string;
  readonly body: Record<string, any>;

  constructor(message: string, opts: { code?: string; status?: number; docs?: string; body?: Record<string, any> } = {}) {
    super(message);
    this.name = "SignafaideError";
    this.code = opts.code ?? "error";
    this.status = opts.status ?? 0;
    this.docs = opts.docs;
    this.body = opts.body ?? {};
  }

  get retryable(): boolean {
    return this.code === "network" || this.code === "rate_limited" || this.status >= 500;
  }

  /** The service refused for a reason retrying cannot change (quota, key, revoked agent key...). */
  get permanent(): boolean {
    return !this.retryable && NON_RETRYABLE.has(this.code);
  }
}

export class Client {
  readonly url: string;
  readonly clientId: string;
  readonly transport: Transport;
  readonly signal?: AbortSignal;

  constructor(
    url: string = DEFAULT_URL,
    readonly apiKey?: string,
    readonly timeoutMs = 10_000,
    clientId?: string,
    opts: { transport?: Transport; signal?: AbortSignal; timeoutLabel?: string } = {},
  ) {
    this.url = url.replace(/\/+$/, "");
    // The coding agent is detected only at set-up time (init, agent setup), never per request.
    this.clientId = clientId ?? clientHeader({});
    this.transport = opts.transport ?? fetchTransport;
    this.signal = opts.signal;
    this.timeoutLabel = opts.timeoutLabel;
  }

  /** Said instead of "no answer within <timeout> s" when the request shares a larger limit. */
  readonly timeoutLabel?: string;

  /** One request. Returns the JSON answer, or null for 304 Not Modified (a request with `If-None-Match`). */
  async request(method: string, path: string, opts: { body?: unknown; auth?: boolean; query?: Record<string, string | undefined>; headers?: Record<string, string> } = {}): Promise<any> {
    const auth = opts.auth ?? true;
    let url = this.url + path;
    const q = Object.entries(opts.query ?? {}).filter((e): e is [string, string] => e[1] != null);
    if (q.length) url += "?" + new URLSearchParams(q).toString();
    const headers: Record<string, string> = { Accept: "application/json", [HEADER]: this.clientId };
    if (typeof process !== "undefined" && process.versions?.node) headers["User-Agent"] = `signafaide-js/${VERSION}`;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    Object.assign(headers, opts.headers ?? {});
    if (auth) {
      if (!this.apiKey) throw new SignafaideError("No API key: run `signafaide init` or set SIGNAFAIDE_API_KEY.", { code: "invalid_key" });
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    let resp: TransportResponse;
    try {
      resp = await this.transport({ method, url, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body), timeoutMs: this.timeoutMs, signal: this.signal });
    } catch (e) {
      const err = e as { cause?: { code?: string }; code?: string; name?: string; message?: string };
      const raw = err.cause?.code ?? err.code ?? err.message ?? String(e);
      const reason = /abort|timeout/i.test(`${err.name} ${raw}`) ? (this.timeoutLabel ?? `no answer within ${this.timeoutMs / 1000} s`) : raw;
      throw new SignafaideError(`Cannot reach the signafAIde service at ${this.url} (${reason}); check the network or SIGNAFAIDE_URL.`, { code: "network" });
    }
    const { status, text, contentType: ctype } = resp;
    if (status === 304) return null;
    if (status < 200 || status >= 300) throw serviceError(status, text);
    return ctype.includes("json") || /^[[{]/.test(text) ? JSON.parse(text) : text;
  }

  sandbox(): Promise<{ project: string; api_key: string; claim_url: string; free_quota: number; expires_at?: string; terms_url?: string; privacy_url?: string }> {
    return this.request("POST", "/v1/sandbox", { body: {}, auth: false });
  }

  /** §2.4: the registration with its proof of possession (and rotation signature). */
  registerAgent(
    name: string,
    publicKey: string,
    validFrom: string,
    proof: string,
    rotation?: { key_id: string; sig: string },
  ): Promise<{ agent: string; key_id: string; retired?: { key_id: string; valid_to: string }[] }> {
    return this.request("POST", "/v1/agents", { body: { name, public_key: publicKey, valid_from: validFrom, proof, ...(rotation ? { rotation } : {}) } });
  }

  /** `{project, env}` of this API key (§6); `expires_at` while it is an unclaimed sandbox. */
  project(): Promise<{ project: string; env: string; claimed?: boolean; name?: string | null; expires_at?: string }> {
    return this.request("GET", "/v1/project");
  }

  submit(records: unknown[]): Promise<{ receipts: any[]; heads: any[] }> {
    return this.request("POST", "/v1/records", { body: { records } });
  }

  head(agent: string): Promise<any> {
    return this.request("GET", `/v1/heads/${encodeURIComponent(agent)}`);
  }

  /** `{record, receipt, anchor}` of one record of the key's project. */
  record(recordHash: string): Promise<any> {
    return this.request("GET", `/v1/records/${encodeURIComponent(recordHash)}`);
  }

  /** A verification pack (§7) of the whole project, or of one agent. */
  export(agent?: string, from?: string, to?: string): Promise<any> {
    return this.request("GET", "/v1/export", { query: { agent, from, to } });
  }

  usage(): Promise<{ period: string; used: number; quota: number | null; plan?: string }> {
    return this.request("GET", "/v1/usage");
  }

  /** Usage event (`verify`, `export`). Not part of SPEC §6 yet. */
  async event(name: string): Promise<void> {
    await this.request("POST", "/v1/events", { body: { name }, auth: !!this.apiKey });
  }

  serviceKeys(): Promise<{ keys: any[] }> {
    return this.request("GET", "/.well-known/signafaide-keys.json", { auth: false });
  }

  /** The project's signed rule set (§6, §10.2): `{rules, sig, service_key_id}`, `{"rules": null}`
   * without one, or null when `etag` (its `rules_hash`) is still current. */
  rules(etag?: string | null, version?: number): Promise<any> {
    return this.request("GET", "/v1/rules", { query: { version: version === undefined ? undefined : String(version) }, headers: etag ? { "If-None-Match": `"${etag}"` } : {} });
  }

  /** §6 (1.1): start a device sign-in. No auth. */
  deviceCode(client: string, host: string): Promise<{ device_code: string; user_code: string; verification_uri: string; verification_uri_complete?: string; expires_in: number; interval: number }> {
    return this.request("POST", "/v1/device/code", { body: { client, host }, auth: false });
  }

  /** §6 (1.1): poll a device sign-in. Always 200 with `{status}`. No auth. */
  deviceToken(deviceCode: string): Promise<{ status: string; session?: string; expires_at?: string; person?: { email?: string }; organisation?: { name?: string } }> {
    return this.request("POST", "/v1/device/token", { body: { device_code: deviceCode }, auth: false });
  }

  /** §6 (1.1): who a person session is, and the projects they can see (the client's key is the session). */
  session(): Promise<{ person: { email: string }; organisation: { name: string }; expires_at: string; projects: { project: string; name?: string; env: string; role: "owner" | "admin" | "developer" }[] }> {
    return this.request("GET", "/v1/session");
  }

  /** §6 (1.1): end a person session (`signafaide logout`). */
  endSession(): Promise<unknown> {
    return this.request("DELETE", "/v1/session");
  }

  /** §6 (1.1): publish the next version of a project's rule set: with a person session, or the
   * key of an unclaimed sandbox. Returns `{rules, sig, service_key_id}`. */
  publishRules(body: { project: string; env: string; after: number | null; draft: Record<string, unknown> }): Promise<any> {
    return this.request("POST", "/v1/rules", { body });
  }

  /** §6 (1.1) `POST /v1/auditor-links`: a read-only auditor link (`signafaide prove`), body
   * `{agent, tool?, from?, days, agent_keys?, head?}`, answer `{url, expires_at, agent_keys?}`
   * (`agent_keys: true` when the witness keeps the manifest for the auditor's browser check). A
   * witness without it answers `not_found`, and prove points at files instead. */
  auditorLink(body: { agent?: string; tool?: string; from?: string | null; days?: number; agent_keys?: unknown; head?: unknown }): Promise<{ url: string; expires_at?: string; agent_keys?: boolean }> {
    return this.request("POST", "/v1/auditor-links", { body });
  }

  /** The shared fingerprint list (§6, §11.2): `{snapshot, updates}`. */
  fingerprints(since?: number | null): Promise<any> {
    return this.request("GET", "/v1/fingerprints", { query: { since: since == null ? undefined : String(since) } });
  }
}

function serviceError(status: number, text: string): SignafaideError {
  try {
    const body = JSON.parse(text);
    const err = body.error;
    if (typeof err?.message === "string") return new SignafaideError(err.message, { code: err.code ?? "error", status, docs: err.docs, body });
  } catch {
    /* not JSON */
  }
  return new SignafaideError(`The service answered HTTP ${status}: ${text.trim().slice(0, 200) || "no body"}.`, { code: "http_error", status });
}

/** GET a JSON document (used for `--keys <url>`). */
export async function fetchJson(url: string, timeoutMs = 10_000): Promise<any> {
  const u = new URL(url);
  // a --keys URL may be anyone's: send only the SDK name and version there
  return new Client(u.origin, undefined, timeoutMs, `signafaide-js/${VERSION}`).request("GET", u.pathname + u.search, { auth: false });
}
