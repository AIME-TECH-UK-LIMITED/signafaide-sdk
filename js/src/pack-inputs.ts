/** Reading a verifier's inputs from files and URLs (§7): shared by `signafaide verify` and the
 * standalone `signafaide-verify` package, so both read keys, heads and content the same way. */

import * as fs from "node:fs";
import * as path from "node:path";
import { parseJson } from "./jcs.js";
import { contentFromText, isLoopbackUrl, type LocalContent } from "./verifier.js";

/** A file path or an http(s) URL as parsed JSON (number literals kept); an object is returned as is.
 * Plain http is accepted only from this machine, with a warning, and never counts as independent. */
export async function readInput(src: string | object, flag: string): Promise<unknown> {
  if (typeof src !== "string") return src;
  if (/^https?:\/\//.test(src)) {
    if (src.startsWith("http://")) {
      if (!isLoopbackUrl(src)) {
        throw new Error(
          `${flag} ${src} uses plain http://, which anyone on the network path can alter; use https:// (plain http is accepted only from this machine, e.g. http://127.0.0.1)`,
        );
      }
      console.error(`WARNING: ${flag} ${src} uses plain http:// on this machine; the keys do not count as independent`);
    }
    return parseJson(JSON.stringify(await (await import("./http.js")).fetchJson(src)));
  }
  return parseJson(fs.readFileSync(src, "utf8"));
}

export const plainHttp = (src: unknown): boolean => typeof src === "string" && src.startsWith("http://");

/** record_hash -> {content, salt} from a chain .jsonl file or every *.jsonl below a folder (§7). */
export function loadContent(src: string): Map<string, LocalContent> {
  const out = new Map<string, LocalContent>();
  const walk = (p: string): void => {
    if (fs.statSync(p).isDirectory()) for (const f of fs.readdirSync(p).sort()) walk(path.join(p, f));
    else if (p === src || p.endsWith(".jsonl")) contentFromText(fs.readFileSync(p, "utf8"), out);
  };
  walk(src);
  return out;
}
