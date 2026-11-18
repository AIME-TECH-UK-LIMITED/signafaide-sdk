/** The Node transport for background shipping: `node:http(s)` with sockets and timers that do
 * not keep the process alive, so a witness that never answers cannot hold a finished program
 * open. Requests made while the process is exiting pass `hold: true`. Node only.
 *
 * It goes through the proxy the environment names, as curl and Python do: `HTTPS_PROXY` for an
 * https witness (a CONNECT tunnel, then TLS to the witness inside it), `HTTP_PROXY` for an http
 * one (the request in absolute form), else `ALL_PROXY`; lower case first, then upper case; never
 * for a host `NO_PROXY` names. A proxy that refuses the tunnel fails with code `EPROXYREFUSED`. */

import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as tls from "node:tls";
import type { Transport } from "./http.js";

type Env = Record<string, string | undefined>;

const envVar = (env: Env, name: string): string | undefined => env[name.toLowerCase()] || env[name.toUpperCase()] || undefined;
const bare = (host: string): string => host.replace(/^\[|\]$/g, "").toLowerCase();
const defaultPort = (u: URL): number => Number(u.port || (u.protocol === "https:" ? 443 : 80));

/** An entry of `NO_PROXY` as [host, port or null]: `example.com`, `.example.com`, `*.example.com`,
 * `host:8443`, `[::1]:8443`, `::1`. */
function noProxyEntry(entry: string): [string, number | null] {
  const v6 = entry.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) return [v6[1], v6[2] ? Number(v6[2]) : null];
  const hp = entry.match(/^([^:]+):(\d+)$/);
  if (hp) return [hp[1], Number(hp[2])];
  return [entry, null];
}

/** Whether `NO_PROXY` (comma or space separated) names the host of `u`: `*` names every host;
 * `example.com` and `.example.com` name it and its subdomains; `host:port` only that port. */
export function noProxy(u: URL, list: string | undefined): boolean {
  if (!list) return false;
  const host = bare(u.hostname);
  const port = defaultPort(u);
  for (const entry of list.split(/[\s,]+/).filter(Boolean)) {
    if (entry === "*") return true;
    const [h, p] = noProxyEntry(entry);
    if (p !== null && p !== port) continue;
    const name = bare(h).replace(/^\*?\./, "");
    if (name && (host === name || host.endsWith(`.${name}`))) return true;
  }
  return false;
}

/** The proxy the environment names for `u`, or null (none, `NO_PROXY` names the host, or the
 * proxy is not an http(s) one, such as socks5: then the request goes direct). */
export function proxyFor(u: URL, env: Env = process.env): URL | null {
  if (noProxy(u, envVar(env, "no_proxy"))) return null;
  const raw = (u.protocol === "https:" ? envVar(env, "https_proxy") : envVar(env, "http_proxy")) ?? envVar(env, "all_proxy");
  if (!raw) return null;
  try {
    const p = new URL(raw.includes("://") ? raw : `http://${raw}`);
    return p.protocol === "http:" || p.protocol === "https:" ? p : null;
  } catch {
    return null;
  }
}

/** `hold`: keep the process alive until the request settles (exit flush, CLI, strict mode).
 * `env`: where the proxy settings are read (the process environment). */
export function nodeTransport(hold: () => boolean, env: Env = process.env): Transport {
  return (req) =>
    new Promise((resolve, reject) => {
      const u = new URL(req.url);
      const keep = hold();
      const proxy = proxyFor(u, env);
      let settled = false;
      let current: http.ClientRequest | null = null;
      const done = (f: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        req.signal?.removeEventListener("abort", onAbort);
        f();
      };
      // An error on the way through a proxy says so: the witness's name was never looked up here.
      const fail = (e: Error): void => done(() => reject(proxy ? Object.assign(e, { viaProxy: true }) : e));
      const stop = (why: string): void => {
        if (current) current.destroy(new Error(why));
        else fail(new Error(why));
      };
      const timer = setTimeout(() => stop("timeout"), req.timeoutMs);
      const onAbort = (): void => stop("aborted");
      if (!keep) timer.unref();
      const headers: http.OutgoingHttpHeaders = { ...req.headers, ...(req.body !== undefined ? { "Content-Length": Buffer.byteLength(req.body) } : {}) };
      const send = (mod: typeof http | typeof https, opts: http.RequestOptions, url?: URL): void => {
        const onRes = (res: http.IncomingMessage): void => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => done(() => resolve({ status: res.statusCode ?? 0, contentType: String(res.headers["content-type"] ?? ""), text: Buffer.concat(chunks).toString("utf8"), viaProxy: !!proxy })));
          res.on("error", fail);
        };
        const r = url ? mod.request(url, opts, onRes) : mod.request(opts, onRes);
        current = r;
        if (!keep) r.on("socket", (s) => s.unref());
        r.on("error", fail);
        if (req.body !== undefined) r.write(req.body);
        r.end();
      };
      if (req.signal?.aborted) {
        onAbort();
        return;
      }
      req.signal?.addEventListener("abort", onAbort, { once: true });
      if (!proxy) {
        send(u.protocol === "https:" ? https : http, { method: req.method, headers, agent: false }, u);
        return;
      }
      const pmod = proxy.protocol === "https:" ? https : http;
      const auth: http.OutgoingHttpHeaders =
        proxy.username || proxy.password ? { "Proxy-Authorization": `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}` } : {};
      const at = { host: bare(proxy.hostname), port: defaultPort(proxy), agent: false as const };
      if (u.protocol !== "https:") {
        // http through the proxy: the request in absolute form.
        send(pmod, { ...at, method: req.method, path: u.href, headers: { ...headers, Host: u.host, ...auth } });
        return;
      }
      // https through the proxy: a CONNECT tunnel, then TLS to the witness inside it.
      const target = `${u.hostname}:${defaultPort(u)}`;
      const c = pmod.request({ ...at, method: "CONNECT", path: target, headers: { Host: target, ...auth } });
      current = c;
      if (!keep) c.on("socket", (s) => s.unref());
      c.on("error", fail);
      c.on("connect", (res, socket) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          fail(Object.assign(new Error(`proxy response (${res.statusCode}) to CONNECT ${target}`), { code: "EPROXYREFUSED", status: res.statusCode }));
          return;
        }
        if (!keep) socket.unref();
        const host = bare(u.hostname);
        const secure = tls.connect({ socket, host, ...(net.isIP(host) ? {} : { servername: host }) });
        // No `agent` here: with one (even `false`) Node opens its own connection and ignores this one.
        send(https, { method: req.method, headers, createConnection: () => secure } as https.RequestOptions, u);
      });
      c.end();
    });
}
