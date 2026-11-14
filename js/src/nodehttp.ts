/** The Node transport for background shipping: `node:http(s)` with sockets and timers that do
 * not keep the process alive, so a witness that never answers cannot hold a finished program
 * open. Requests made while the process is exiting pass `hold: true`. Node only. */

import * as http from "node:http";
import * as https from "node:https";
import type { Transport } from "./http.js";

/** `hold`: keep the process alive until the request settles (exit flush, CLI, strict mode). */
export function nodeTransport(hold: () => boolean): Transport {
  return (req) =>
    new Promise((resolve, reject) => {
      const u = new URL(req.url);
      const mod = u.protocol === "https:" ? https : http;
      const keep = hold();
      let settled = false;
      const done = (f: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        req.signal?.removeEventListener("abort", onAbort);
        f();
      };
      const r = mod.request(u, { method: req.method, headers: { ...req.headers, ...(req.body !== undefined ? { "Content-Length": Buffer.byteLength(req.body) } : {}) }, agent: false }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => done(() => resolve({ status: res.statusCode ?? 0, contentType: String(res.headers["content-type"] ?? ""), text: Buffer.concat(chunks).toString("utf8") })));
        res.on("error", (e) => done(() => reject(e)));
      });
      const timer = setTimeout(() => {
        r.destroy(new Error("timeout"));
      }, req.timeoutMs);
      const onAbort = (): void => {
        r.destroy(new Error("aborted"));
      };
      if (!keep) {
        timer.unref();
        r.on("socket", (s) => s.unref());
      }
      if (req.signal?.aborted) onAbort();
      else req.signal?.addEventListener("abort", onAbort, { once: true });
      r.on("error", (e) => done(() => reject(e)));
      if (req.body !== undefined) r.write(req.body);
      r.end();
    });
}
