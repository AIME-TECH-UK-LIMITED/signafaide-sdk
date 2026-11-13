/** `signafaide` command line. Add a command to `COMMANDS`. */

import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { SignafaideError } from "./http.js";
import { verify } from "./index.js";
import { VerificationFailed, compare } from "./experiments.js";
import { replay } from "./replay.js";
import { plural } from "./plural.js";
import { configure, envOf, termsNotice, type Recorder } from "./runtime.js";
import { StateError, findRoot } from "./state.js";
import { AGENT_IDS, SETUP_NOTES, setup } from "./agents.js";
import { KeysRequired } from "./verifier.js";
import { VERSION } from "./version.js";

export interface Command {
  help: string;
  options?: ParseArgsConfig["options"];
  usage?: string;
  run(values: Record<string, any>, positionals: string[]): Promise<number>;
}

const out = (s: string): void => console.log(s);
const err = (s: string): void => console.error(s);
const recorder = (): Recorder => configure({ quiet: true, via: "cli" });
const mask = (k?: string | null): string => (k ? `${k.slice(0, 13)}...` : "none");

/** The `status` report, also returned by the MCP `signafaide_status` tool. */
export async function statusLines(rec: Recorder): Promise<string[]> {
  const lines: string[] = [];
  const s = rec.status();
  lines.push(
    `key: ${mask(s.api_key)}` +
      (s.env ? ` (env ${s.env})` : "; records stay on this machine (signed and chained, nothing is sent). `signafaide init` creates a free sandbox and sends hashes; or set SIGNAFAIDE_API_KEY"),
  );
  lines.push(`service: ${s.url}`);
  lines.push(`home: ${s.home}`);
  if (!s.chains.length) lines.push("chains: none yet; wrap a function with record()");
  for (const c of s.chains) {
    const last = c.receipt_seq ? `last receipt seq ${c.receipt_seq} at ${c.receipt_time}` : "no receipt yet";
    const other = c.current || !c.waiting ? "" : `; ${c.waiting} waiting for the key of that project`;
    lines.push(`chain ${c.chain}: key ${c.key_id}, ${plural(c.records, "record")}, ${last}${other}`);
  }
  lines.push(`outbox: ${plural(s.outbox, "record")} waiting` + (s.outbox ? "; run `signafaide flush`" : ""));
  if (s.api_key) {
    try {
      const u = await rec.client(5000).usage();
      lines.push(`quota: ${u.used} of ${u.quota} used in ${u.period}`);
    } catch (e) {
      lines.push(`quota: unknown (${(e as Error).message})`);
    }
  }
  if (s.sandbox?.claim_url && s.api_key?.startsWith("sfa_test_")) lines.push(`claim: ${s.sandbox.claim_url}`);
  return lines;
}

export const COMMANDS: Record<string, Command> = {
  init: {
    help: "opt in to the witness: create a free sandbox if there is no API key (no account, email or card), print the claim link",
    async run() {
      const rec = recorder();
      rec.rememberAgent();
      const had = rec.apiKey;
      const key = await rec.createSandbox();
      const claim = rec.state.sandbox()?.claim_url;
      if (!had) {
        out(`sandbox ready at ${rec.url}, key saved to ${path.join(rec.state.root, ".env")}; claim it at ${claim}`);
        out(termsNotice(rec.legal()));
        out("from now on record hashes (never content) are sent for co-signature and public timestamps; records written before now ship with their original times on the next run or with `signafaide flush`");
      }
      else if (key.startsWith("sfa_test_") && claim) out(`key found (${mask(key)}); claim the sandbox at ${claim}`);
      else out(`key found (${mask(key)}, env ${envOf(key)}); nothing to create`);
      return 0;
    },
  },

  status: {
    help: "key and env, agents, last receipt, outbox size, quota",
    async run() {
      for (const line of await statusLines(recorder())) out(line);
      return 0;
    },
  },

  verify: {
    help: "verify a pack or the local state; exit 0 PASS, 1 FAIL, 2 unreadable input",
    usage:
      "verify [pack.json] [--keys <file|url>] [--agent-keys <file|url>] [--head head.json] [--timestamp-check <url>] [--offline] [--trust-embedded-keys] [--trust-embedded-agent-keys] [--content <file|dir>] [--json]",
    options: {
      keys: { type: "string" },
      "trust-embedded-keys": { type: "boolean" },
      "agent-keys": { type: "string" },
      "trust-embedded-agent-keys": { type: "boolean" },
      head: { type: "string" },
      "timestamp-check": { type: "string" },
      bitcoin: { type: "string" },
      offline: { type: "boolean" },
      content: { type: "string" },
      json: { type: "boolean" },
    },
    async run(v, pos) {
      const rec = recorder();
      let report;
      try {
        report = await verify(pos[0] ?? null, {
          keys: v.keys,
          trustEmbeddedKeys: v["trust-embedded-keys"],
          agentKeys: v["agent-keys"],
          trustEmbeddedAgentKeys: v["trust-embedded-agent-keys"],
          head: v.head,
          timestampCheck: v["timestamp-check"] ?? v.bitcoin,
          offline: v.offline,
          content: v.content,
        });
      } catch (e) {
        err(`signafaide: ${(e as Error).message}`);
        await rec.event("verify");
        return 2;
      }
      out(v.json ? JSON.stringify(report, null, 2) : String(report));
      await rec.event("verify");
      return report.ok ? 0 : 1;
    },
  },

  keys: {
    help: "export the agent public keys for auditors, or rotate an agent's key",
    usage: "keys export [-o agent-keys.json] | keys rotate [--agent X]",
    options: { output: { type: "string", short: "o" }, agent: { type: "string" } },
    async run(v, pos) {
      const rec = recorder();
      if (pos[0] === "export" && pos.length === 1) {
        const doc = rec.state.exportAgentKeys();
        if (!doc.keys.length) {
          err("signafaide: no agent keys here yet; they are made with the first record");
          return 1;
        }
        const file = v.output ?? "agent-keys.json";
        fs.writeFileSync(file, JSON.stringify(doc, null, 2) + "\n");
        out(`wrote ${file} (${plural(doc.keys.length, "key")}); give it to your auditors: signafaide verify pack.json --agent-keys ${file}`);
        return 0;
      }
      if (pos[0] === "rotate" && pos.length === 1) {
        const agent = v.agent ?? rec.defaultAgent;
        const [old, next] = rec.state.rotateKey(agent);
        out(
          `${agent}: new key ${next.keyId} signs from now on. Records the old key ${old.keyId} signed earlier ship first; the next record then registers the new key, signed by the old one, and the service retires the old key at that moment`,
        );
        return 0;
      }
      err(`usage: signafaide ${COMMANDS.keys.usage}`);
      return 2;
    },
  },

  export: {
    help: "download a verification pack of the whole project (every agent), or of one agent with --agent",
    usage: "export [--agent X] [--from T] [--to T] [-o pack.json]",
    options: { agent: { type: "string" }, from: { type: "string" }, to: { type: "string" }, output: { type: "string", short: "o" } },
    async run(v) {
      const rec = recorder();
      const agent: string | undefined = v.agent;
      let pack;
      try {
        pack = await rec.client(60_000).export(agent, v.from, v.to);
      } catch (e) {
        await rec.event("export");
        throw e;
      }
      const n = pack.records?.length ?? 0;
      const file = v.output ?? `${agent ?? pack.project}-pack.json`;
      fs.writeFileSync(file, JSON.stringify(pack, null, 2) + "\n");
      out(`wrote ${file} (${plural(n, "record")}); check it with \`signafaide verify ${file}\``);
      if (!n) err(agent ? `signafaide export: agent '${agent}' has no records in this range; leave out --agent to export every agent (\`signafaide status\` lists them)` : "signafaide export: this project has no records in this range, so the pack proves nothing");
      await rec.event("export");
      return 0;
    },
  },

  replay: {
    help: "show what an agent saw and did, from the local chain, each record verified; exit 1 on FAIL",
    usage: "replay [--agent X] [--from T] [--to T] [--record <hash>] [--chain <id>] [--keys <file|url>] [--html out.html] [--json]",
    options: {
      agent: { type: "string" },
      from: { type: "string" },
      to: { type: "string" },
      record: { type: "string" },
      chain: { type: "string" },
      keys: { type: "string" },
      html: { type: "string" },
      json: { type: "boolean" },
    },
    async run(v) {
      recorder();
      const r = await replay({ agent: v.agent, since: v.from, until: v.to, record: v.record, chain: v.chain, keys: v.keys });
      out(v.json ? JSON.stringify(r, null, 2) : String(r));
      if (v.html) {
        fs.writeFileSync(v.html, r.toHtml());
        err(`wrote ${v.html}`);
      }
      return r.ok ? 0 : 1;
    },
  },

  compare: {
    help: "re-run recorded decisions with a candidate function and compare the results",
    usage: "compare --module <file.js|package>:<function> [--agent X] [--name N] [--from T] [--to T] [--limit N] [--label L] [--upload [--values]] [--json]",
    options: {
      module: { type: "string" },
      agent: { type: "string" },
      name: { type: "string" },
      from: { type: "string" },
      to: { type: "string" },
      limit: { type: "string" },
      label: { type: "string" },
      chain: { type: "string" },
      keys: { type: "string" },
      upload: { type: "boolean" },
      values: { type: "boolean" },
      json: { type: "boolean" },
    },
    async run(v) {
      if (!v.module) {
        err(`usage: signafaide ${COMMANDS.compare.usage}`);
        return 2;
      }
      recorder();
      const limit = v.limit === undefined ? undefined : Number(v.limit);
      if (limit !== undefined && !Number.isInteger(limit)) throw new SyntaxError("--limit must be a whole number");
      const fn = await loadCandidate(v.module);
      const r = await compare(fn, { agent: v.agent, name: v.name, since: v.from, until: v.to, limit, label: v.label, chain: v.chain, keys: v.keys });
      if (v.upload) await r.upload(v.values ? true : undefined);
      out(v.json ? JSON.stringify({ ...r.toJSON(), ...(r.uploaded ? { uploaded: r.uploaded } : {}) }, null, 2) : String(r));
      return 0;
    },
  },

  claim: {
    help: "print the sandbox claim link again",
    async run() {
      const rec = recorder();
      if (rec.apiKey?.startsWith("sfa_live_")) {
        out("this project uses a live key; there is nothing to claim");
        return 0;
      }
      const claim = rec.state.sandbox()?.claim_url;
      if (!claim) {
        err("no sandbox here; run `signafaide init` first");
        return 1;
      }
      out(claim);
      return 0;
    },
  },

  agent: {
    help: "install the MCP server and the skill in your coding agents (Claude Code, Codex, Cursor, Gemini CLI, Copilot, Windsurf)",
    usage: "agent setup [--agent <name>]... [--url <self-hosted witness url>] [--dry-run] [--dir <project>]",
    options: { agent: { type: "string", multiple: true }, "dry-run": { type: "boolean" }, dir: { type: "string" }, url: { type: "string" } },
    async run(v, pos) {
      if (pos[0] !== "setup" || pos.length > 1) {
        err(`usage: signafaide ${COMMANDS.agent.usage}; agents: ${AGENT_IDS.join(", ")}, all`);
        return 2;
      }
      const dry = !!v["dry-run"];
      const root = v.dir ? path.resolve(v.dir) : findRoot();
      const results = setup({ root, agents: v.agent, dryRun: dry, url: v.url });
      if (!results.length) {
        out(`no coding agent found for ${root}; name one with --agent ${AGENT_IDS.join("|")} (or --agent all)`);
        return 1;
      }
      if (dry) out("dry run: nothing written");
      for (const r of results) {
        const what = r.changes.map((c) => `${c.file} ${dry && /^(created|updated)$/.test(c.result) ? `would be ${c.result}` : c.result}`).join(", ");
        out(`${r.agent}: ${what}${r.note ? `; note: ${r.note}` : ""}`);
      }
      for (const line of SETUP_NOTES(v.url)) out(line);
      return results.some((r) => r.changes.some((c) => c.result.startsWith("skipped"))) ? 1 : 0;
    },
  },

  mcp: {
    help: "run the signafAIde MCP server over stdio (for coding agents)",
    async run() {
      const { serve } = await import("./mcp.js");
      await serve();
      return 0;
    },
  },

  flush: {
    help: "ship the outbox now",
    async run() {
      const rec = recorder();
      const r = await rec.flush();
      for (const [agent, e] of Object.entries(r.errors)) err(`${agent}: ${e.message}`);
      if (!rec.apiKey) {
        out(`no API key: nothing was sent; ${plural(r.left, "record")} stay local. Run \`signafaide init\` (or set SIGNAFAIDE_API_KEY) to send hashes`);
        return 0;
      }
      // Chains the service cannot take (too_old, chain_exists) stay on this machine: not "left to ship".
      const local = Object.entries(r.errors)
        .filter(([, e]) => e.code === "too_old" || e.code === "chain_exists")
        .reduce((n, [c]) => n + rec.state.draftCount(c), 0);
      out(`shipped ${plural(r.shipped, "record")}, ${r.left - local} left in the outbox` + (local ? `; ${plural(local, "record")} kept on this machine only (see above)` : ""));
      return Object.keys(r.errors).length ? 1 : 0;
    },
  },
};

/** `path/to/file.js:function` or `package:function`. */
export async function loadCandidate(spec: string): Promise<(input: any) => unknown> {
  const i = spec.lastIndexOf(":");
  const [target, fn] = i > 0 ? [spec.slice(0, i), spec.slice(i + 1)] : ["", ""];
  if (!target || !fn) throw new SyntaxError("--module must be path/to/file.js:function or package:function");
  const local = /^[./]/.test(target) || /\.[cm]?[jt]s$/.test(target);
  let mod: any;
  try {
    mod = await import(local ? pathToFileURL(path.resolve(target)).href : target);
  } catch (e) {
    throw new SyntaxError(`cannot load the candidate ${target}: ${(e as Error).message}`);
  }
  const f = mod[fn] ?? mod.default?.[fn];
  if (typeof f !== "function") throw new SyntaxError(`${spec}: no function "${fn}" in ${target}`);
  return f;
}

function help(): string {
  const width = Math.max(...Object.keys(COMMANDS).map((c) => c.length));
  return ["usage: signafaide <command> [options]", "", ...Object.entries(COMMANDS).map(([c, d]) => `  ${c.padEnd(width)}  ${d.help}`)].join("\n");
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const [name, ...rest] = argv;
  if (name === "--version" || name === "-v") {
    out(`signafaide ${VERSION}`);
    return 0;
  }
  const cmd = name ? COMMANDS[name] : undefined;
  if (!cmd) {
    (name && name !== "--help" && name !== "-h" ? err : out)(help());
    return name && name !== "--help" && name !== "-h" ? 1 : 0;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    out(`${cmd.help}\nusage: signafaide ${cmd.usage ?? name}`);
    return 0;
  }
  let parsed;
  try {
    parsed = parseArgs({ args: rest, options: cmd.options ?? {}, allowPositionals: true, strict: true });
  } catch (e) {
    err(`signafaide ${name}: ${(e as Error).message}; usage: signafaide ${cmd.usage ?? name}`);
    return 2;
  }
  try {
    return await cmd.run(parsed.values, parsed.positionals);
  } catch (e) {
    if (e instanceof SignafaideError || e instanceof StateError || e instanceof KeysRequired || e instanceof VerificationFailed || e instanceof SyntaxError || (e as NodeJS.ErrnoException).code) {
      err(`signafaide: ${(e as Error).message}`);
      return 1;
    }
    throw e;
  }
}
