#!/usr/bin/env node
/**
 * `signafaide-verify` on npm: checks a verification pack (§7) and nothing else, for auditors who
 * do not install the SDK. It is the SDK's TypeScript verifier (`verifier.ts`, `pack-inputs.ts`),
 * bundled into one file with no dependencies. Its options, output and exit codes are those of the
 * Rust `signafaide-verify` binary (verifier/src/main.rs); scripts/verify-vectors.mjs runs the
 * spec's vectors and the input cases through both and compares.
 *
 *   signafaide-verify <pack.json> --agent-keys <file|url> [--keys <file|url>] [--head head.json]
 *     [--content <dir|file>] [--timestamp-check <explorer API>] [--offline] [--json]
 *
 * Without --keys the service keys are the ones pinned in this release (js/service-keys.json, the
 * same file as the other packages'); online they are also compared with the hosted witness's
 * published list, and any difference stops the run. It sends no SDK client header anywhere.
 *
 * Exit code 0 = PASS, 1 = FAIL, 2 = the inputs could not be read or the pinned keys differ.
 */
import * as fs from "node:fs";
import { installNodeCrypto } from "./nodecrypto.js";
import { parseJson } from "./jcs.js";
import { loadContent } from "./pack-inputs.js";
import { DEFAULT_TIMESTAMP_URL, lookupTimestamps } from "./timestamps.js";
import {
  cleanLine,
  isLoopbackUrl,
  loadDrandVerifier,
  parseAgentKeys,
  parseHeadFile,
  crossCheckKeys,
  serviceKeySet,
  timestampHeights,
  verifyPack,
  type KeyDoc,
} from "./verifier.js";
import { VERSION } from "./version.js";
import PINNED from "../service-keys.json";

const USAGE =
  "usage: signafaide-verify <pack.json> --agent-keys <file|url> [--keys <file|url>] [--head head.json] [--content <dir|file>] [--timestamp-check <explorer API URL>] [--offline] [--trust-embedded-keys] [--trust-embedded-agent-keys] [--json]\n       signafaide-verify --version | --help\n\nWithout --keys, the service keys pinned in this release are used and, unless --offline, checked against the hosted witness's published keys; a difference stops the run.";
/** Where the hosted witness publishes its service keys; the pinned copy is checked against it. */
/** The pinned keys document. Only the tests' build (dist-test, never packed) reads another from the
 * file named by SIGNAFAIDE_VERIFY_KEYS_URL_PINNED, so the tests can pin revocations. */
function pinnedDoc(): unknown {
  if (__SIGNAFAIDE_VERIFY_TEST_KEYS_URL__) {
    const f = process.env.SIGNAFAIDE_VERIFY_KEYS_URL_PINNED;
    if (f !== undefined) return JSON.parse(fs.readFileSync(f, "utf8"));
  }
  return PINNED;
}

const PUBLISHED_KEYS_URL = "https://signafaide.co.uk/.well-known/signafaide-keys.json";

interface Args {
  pack: string;
  keys?: string;
  agentKeys?: string;
  head?: string;
  content?: string;
  timestampCheck: string;
  offline: boolean;
  trustEmbeddedKeys: boolean;
  trustEmbeddedAgentKeys: boolean;
  json: boolean;
}

class Usage extends Error {}

function parseArgs(argv: string[]): Args | "help" | "version" {
  const a: Args = {
    pack: "",
    timestampCheck: DEFAULT_TIMESTAMP_URL,
    offline: false,
    trustEmbeddedKeys: false,
    trustEmbeddedAgentKeys: false,
    json: false,
  };
  let pack: string | undefined;
  const it = argv[Symbol.iterator]();
  const value = (why: string): string => {
    const n = it.next();
    if (n.done) throw new Usage(why);
    return n.value;
  };
  for (const arg of it) {
    switch (arg) {
      case "--keys":
        a.keys = value("--keys needs a file or URL");
        break;
      case "--agent-keys":
        a.agentKeys = value("--agent-keys needs a file or URL (from `signafaide keys export`)");
        break;
      case "--head":
        a.head = value("--head needs the client's .signafaide/head.json");
        break;
      case "--content":
        a.content = value("--content needs a directory or file");
        break;
      case "--timestamp-check":
      case "--bitcoin":
        a.timestampCheck = value("--timestamp-check needs an explorer API URL such as https://mempool.space/api");
        break;
      case "--offline":
        a.offline = true;
        break;
      case "--trust-embedded-keys":
        a.trustEmbeddedKeys = true;
        break;
      case "--trust-embedded-agent-keys":
        a.trustEmbeddedAgentKeys = true;
        break;
      case "--json":
        a.json = true;
        break;
      case "-h":
      case "--help":
        return "help";
      case "-V":
      case "--version":
        return "version";
      default:
        if (arg.startsWith("-")) throw new Usage(`unknown option ${arg}\n${USAGE}`);
        if (pack !== undefined) throw new Usage(`unexpected argument ${arg}\n${USAGE}`);
        pack = arg;
    }
  }
  if (pack === undefined) throw new Usage(USAGE);
  a.pack = pack;
  return a;
}

/** True only in the conformance tests' build (verify/dist-test): SIGNAFAIDE_VERIFY_KEYS_URL then
 * replaces the address the pinned keys are checked against. The release build is made with this
 * false and its dead branch removed, so the release bundle has no trace of the variable
 * (tsup.verify.config.ts; scripts/release-check.mjs checks the built file). */
declare const __SIGNAFAIDE_VERIFY_TEST_KEYS_URL__: boolean;
const LIMIT = 1 << 20;

/** GET `url` as text: no redirect is followed (an answer that is one is refused), at most 1 MiB
 * read (the read stops there), the bytes as sent (a byte order mark is kept, as in Rust), and no
 * SDK header or User-Agent. */
async function get(url: string): Promise<string> {
  const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(15_000) });
  if (r.status >= 300 && r.status < 400)
    throw new Error(
      `${url} answered a redirect (HTTP ${r.status}); redirects are not followed, give the final address`,
    );
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (r.body) {
    const reader = r.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > LIMIT) {
        await reader.cancel();
        throw new Error(`${url}: the answer is larger than 1 MiB`);
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    bytes.set(c, at);
    at += c.length;
  }
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
}

/** A file or an http(s) URL, and whether it came over plain http (accepted only from this machine,
 * with a warning, and then not independent). */
async function fetchInput(flag: string, src: string): Promise<[string, boolean]> {
  if (!/^https?:\/\//.test(src)) return [fs.readFileSync(src, "utf8"), false];
  const plain = src.startsWith("http://");
  if (plain && !isLoopbackUrl(src))
    throw new Error(
      `${flag} ${src} uses plain http://, which anyone on the network path can alter; use https:// (plain http is accepted only from this machine, e.g. http://127.0.0.1)`,
    );
  if (plain)
    console.error(`WARNING: ${flag} ${src} uses plain http:// on this machine; the keys do not count as independent`);
  return [await get(src), plain];
}

/** Service keys exactly as §5 publishes them: `{"keys": [...]}` (a bare list is refused, as in Rust). */
function serviceKeys(text: string, where: string): { keys: KeyDoc[]; revoked: string[] } {
  const doc = parseJson(text) as { keys?: unknown } | null;
  if (!doc || typeof doc !== "object" || Array.isArray(doc) || !Array.isArray(doc.keys))
    throw new Error(`${where}: service keys must be {"keys": [...]} as served at /.well-known/signafaide-keys.json`);
  // The SDK's one loader: the whole list (revoked keys too, for keys_hash) and the revoked ids.
  try {
    return serviceKeySet(doc);
  } catch (e) {
    throw new Error(`${where}: ${(e as Error).message}`);
  }
}

/** Where the pinned keys are checked: the hosted witness's published list. */
function publishedKeysUrl(): string {
  if (__SIGNAFAIDE_VERIFY_TEST_KEYS_URL__) {
    const env = process.env.SIGNAFAIDE_VERIFY_KEYS_URL;
    if (env !== undefined && !env.startsWith("https://"))
      throw new Error(`SIGNAFAIDE_VERIFY_KEYS_URL ${env} is not an https:// address`);
    if (env !== undefined) return env;
  }
  return PUBLISHED_KEYS_URL;
}

type CrossCheck =
  | {
      kind: "matched";
      url: string;
      newer: string[];
      retired: [string, string][];
      revoked: string[];
      applied: string[];
      keys: KeyDoc[];
    }
  | { kind: "unreachable"; url: string; why: string }
  | { kind: "offline" };

/** The published list against the pinned keys (§5, §7): the SDK's one cross-check
 * (`crossCheckKeys`, the same as the Rust core's). Throws when the list cannot be read. */
function compareKeys(published: string): {
  problems: string[];
  newer: string[];
  retired: [string, string][];
  revoked: string[];
  applied: string[];
  keys: KeyDoc[];
} {
  const r = crossCheckKeys(pinnedDoc(), published);
  if ("unreadable" in r) throw new Error(r.unreadable);
  const none = { newer: [], retired: [], revoked: [], applied: [], keys: [] };
  if ("differ" in r) return { problems: r.differ, ...none };
  return {
    problems: [],
    newer: r.newer,
    retired: r.retired,
    revoked: r.revoked,
    applied: r.document.revoked.map((x) => x.key_id),
    keys: r.document.keys,
  };
}

/** The pinned keys checked against the published list unless offline. Throws only when they
 * differ (KEYS DIFFER): nothing is verified then. */
async function crossCheck(offline: boolean): Promise<CrossCheck> {
  const url = publishedKeysUrl();
  if (offline) return { kind: "offline" };
  let text: string;
  try {
    text = await get(url);
  } catch (e) {
    return { kind: "unreachable", url, why: (e as Error).message };
  }
  let found;
  try {
    found = compareKeys(text);
  } catch (e) {
    return { kind: "unreachable", url, why: `${url}: ${(e as Error).message}` };
  }
  if (found.problems.length)
    throw new Error(
      `KEYS DIFFER: the service keys pinned in signafaide-verify ${VERSION} do not match the ones published at ${url}: ${found.problems.join("; ")}. Nothing was verified. Use the newest signafaide-verify, or pass --keys with keys you have checked yourself`,
    );
  return {
    kind: "matched",
    url,
    newer: found.newer,
    retired: found.retired,
    revoked: found.revoked,
    applied: found.applied,
    keys: found.keys,
  };
}

/** What the result line says when the keys given with --keys are not exactly the pinned set (§7). */
const NOT_PINNED_SET = "service keys from --keys differ from the pinned set";

/** True when the keys given are exactly the pinned set: the same entries (key id, public key,
 * valid_from, valid_to) and the same revocations as the pinned file, as the Rust binary decides it. */
function isPinnedSet(
  given: { keys: KeyDoc[]; revoked: string[] },
  pinned: { keys: KeyDoc[]; revoked: string[] },
): boolean {
  const entries = (k: KeyDoc[]) =>
    k
      .map((x) => JSON.stringify([x.key_id, x.public_key, x.valid_from, x.valid_to ?? null]))
      .sort()
      .join("\n");
  const ids = (r: string[]) => [...r].sort().join(",");
  return ids(given.revoked) === ids(pinned.revoked) && entries(given.keys) === entries(pinned.keys);
}

async function run(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args === "help") {
    console.log(`signafaide-verify ${VERSION}\n${USAGE}`);
    return 0;
  }
  if (args === "version") {
    console.log(`signafaide-verify ${VERSION}`);
    return 0;
  }
  if (process.env.NODE_EXTRA_CA_CERTS)
    console.error(`WARNING: trusting the CA certificates in ${process.env.NODE_EXTRA_CA_CERTS} for https`);
  const pack = parseJson(fs.readFileSync(args.pack, "utf8"));
  let keys: KeyDoc[] | null = null;
  let revoked: string[] = [];
  let keysPlain = false;
  let keysSource: string;
  let crossWord = "not_applicable";
  // The pinned file through the one loader: its revocations always apply (§5).
  const pinnedSet = serviceKeys(JSON.stringify(pinnedDoc()), "the pinned service keys");
  const pinnedKeys = pinnedSet.keys;
  let otherKeys = false;
  if (args.keys !== undefined) {
    const [text, plain] = await fetchInput("--keys", args.keys);
    const given = serviceKeys(text, "keys");
    keys = given.keys;
    revoked = given.revoked;
    keysPlain = plain;
    keysSource = `${args.keys} (--keys)`;
    otherKeys = !isPinnedSet(given, pinnedSet);
  } else if (args.trustEmbeddedKeys) {
    keysSource = "taken from the pack (--trust-embedded-keys)";
    // Keys from the pack: the release's pinned revocations still apply (spec §7).
    revoked = pinnedSet.revoked;
  } else {
    keys = pinnedKeys;
    revoked = pinnedSet.revoked;
    const pinned = `pinned in signafaide-verify ${VERSION}`;
    const c = await crossCheck(args.offline);
    if (c.kind === "offline") {
      keysSource = `${pinned}, not cross-checked (--offline)`;
      crossWord = "not_done_offline";
    } else if (c.kind === "unreachable") {
      console.error(
        `signafaide-verify: could not read the published service keys at ${c.url} (${c.why}); the pinned keys are used, not cross-checked`,
      );
      keysSource = `${pinned}, not cross-checked (published list unreachable)`;
      crossWord = "unreachable";
    } else {
      keys = c.keys;
      revoked = c.applied;
      keysSource = `${pinned}, cross-checked with ${c.url}`;
      for (const [id, to] of c.retired) keysSource += `; ${id} retired there at ${to}, applied`;
      for (const id of c.revoked) keysSource += `; ${id} revoked there, applied (no signature by it verifies)`;
      if (c.newer.length)
        keysSource += `; newer keys there, not pinned in this release: ${c.newer.join(", ")} (a pack made since one of them became valid needs a newer signafaide-verify)`;
      crossWord = "matched";
    }
  }
  let agentKeys = null;
  let agentPlain = false;
  if (args.agentKeys !== undefined) {
    const [text, plain] = await fetchInput("--agent-keys", args.agentKeys);
    agentKeys = parseAgentKeys(parseJson(text));
    agentPlain = plain;
  }
  if (!agentKeys && !args.trustEmbeddedAgentKeys)
    console.error(
      "signafaide-verify: no --agent-keys: check 3 fails as NOT INDEPENDENT. Ask the customer for `signafaide keys export -o agent-keys.json` and pass --agent-keys agent-keys.json",
    );
  // A file, as in the Rust binary.
  const heads = args.head !== undefined ? parseHeadFile(parseJson(fs.readFileSync(args.head, "utf8"))) : null;
  const contents = args.content !== undefined ? loadContent(args.content) : undefined;
  const timestamps = args.offline ? null : await lookupTimestamps(args.timestampCheck, timestampHeights(pack));
  const report = verifyPack(pack, keys, {
    trustEmbeddedKeys: args.trustEmbeddedKeys,
    agentKeys,
    trustEmbeddedAgentKeys: args.trustEmbeddedAgentKeys,
    heads,
    timestamps,
    contents,
    drand: await loadDrandVerifier(),
    serviceKeysPlainHttp: keysPlain,
    agentKeysPlainHttp: agentPlain,
    // The release's pinned revocations always apply, whatever the keys' source (spec §7).
    revokedServiceKeys: [...new Set([...revoked, ...pinnedSet.revoked])],
  });
  // Into the report's own result line (text and JSON alike), never by editing printed text.
  if (otherKeys) report.qualify(NOT_PINNED_SET);
  if (args.json) {
    // `notes` holds what the SDK's own verify adds; this command adds where the keys came from.
    const json = report.toJSON() as Record<string, unknown>;
    delete json.notes;
    json.service_keys_source = keysSource;
    json.service_keys_cross_check = crossWord;
    // True when the keys used are the pinned set (pinned, or the same keys given with --keys).
    json.service_keys_pinned_set = args.keys !== undefined ? !otherKeys : !args.trustEmbeddedKeys;
    console.log(JSON.stringify(json, null, 2));
  } else {
    // The report's lines with the key source just above the result line, each through cleanLine.
    const lines = report.lines();
    lines.splice(lines.length - 1, 0, `service keys: ${keysSource}`);
    console.log(lines.map(cleanLine).join("\n"));
  }
  return report.ok ? 0 : 1;
}

installNodeCrypto();
let code: number;
try {
  code = await run(process.argv.slice(2));
} catch (e) {
  console.error(`signafaide-verify: ${(e as Error).message}`);
  code = 2;
}
process.exitCode = code;
