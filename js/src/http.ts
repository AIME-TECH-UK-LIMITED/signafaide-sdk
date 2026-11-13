/** Minimal JSON client for the signafAIde HTTP API (SPEC §6). Built-in fetch only. */

import { HEADER, clientHeader, detectAgent } from "./telemetry.js";
import { VERSION } from "./version.js";

export const DEFAULT_URL = "http://127.0.0.1:7474";

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
}

export class Client {
  readonly url: string;
  readonly clientId: string;

  constructor(
    url: string = DEFAULT_URL,
    readonly apiKey?: string,
    readonly timeoutMs = 10_000,
    clientId?: string,
  ) {
    this.url = url.replace(/\/+$/, "");
    this.clientId = clientId ?? clientHeader({ agent: detectAgent() });
  }

  async request(method: string, path: string, opts: { body?: unknown; auth?: boolean; query?: Record<string, string | undefined> } = {}): Promise<any> {
    const auth = opts.auth ?? true;
    let url = this.url + path;
    const q = Object.entries(opts.query ?? {}).filter((e): e is [string, string] => e[1] != null);
    if (q.length) url += "?" + new URLSearchParams(q).toString();
    const headers: Record<string, string> = { Accept: "application/json", [HEADER]: this.clientId };
    if (typeof process !== "undefined" && process.versions?.node) headers["User-Agent"] = `signafaide-js/${VERSION}`;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (auth) {
      if (!this.apiKey) throw new SignafaideError("No API key: run `signafaide init` or set SIGNAFAIDE_API_KEY.", { code: "invalid_key" });
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    let resp: Response;
    try {
      resp = await fetch(url, {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      const reason = (e as { cause?: { code?: string } }).cause?.code ?? (e as Error).message;
      throw new SignafaideError(`Cannot reach the signafAIde service at ${this.url} (${reason}); start it or set SIGNAFAIDE_URL.`, { code: "network" });
    }
    const text = await resp.text();
    if (!resp.ok) throw serviceError(resp.status, text);
    const ctype = resp.headers.get("content-type") ?? "";
    return ctype.includes("json") || /^[[{]/.test(text) ? JSON.parse(text) : text;
  }

  sandbox(): Promise<{ project: string; api_key: string; claim_url: string; free_quota: number }> {
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

  /** `{project, env}` of this API key (§6). */
  project(): Promise<{ project: string; env: string }> {
    return this.request("GET", "/v1/project");
  }

  submit(records: unknown[]): Promise<{ receipts: any[]; heads: any[] }> {
    return this.request("POST", "/v1/records", { body: { records } });
  }

  head(agent: string): Promise<any> {
    return this.request("GET", `/v1/heads/${encodeURIComponent(agent)}`);
  }

  /** A verification pack (§7) of the whole project, or of one agent. */
  export(agent?: string, from?: string, to?: string): Promise<any> {
    return this.request("GET", "/v1/export", { query: { agent, from, to } });
  }

  usage(): Promise<{ period: string; used: number; quota: number }> {
    return this.request("GET", "/v1/usage");
  }

  /** Usage event (`verify`, `export`). Not part of SPEC §6 yet. */
  async event(name: string): Promise<void> {
    await this.request("POST", "/v1/events", { body: { name }, auth: !!this.apiKey });
  }

  serviceKeys(): Promise<{ keys: any[] }> {
    return this.request("GET", "/.well-known/signafaide-keys.json", { auth: false });
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
