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
import { CLAIM_DONE, claimLines, claimNotes, sandboxGone, sandboxJson, sandboxView } from "./claim.js";
import { configure, envOf, termsNotice, type Recorder } from "./runtime.js";
import { StateError, findRoot } from "./state.js";
import { AGENT_IDS, NOTE_QUESTION, SETUP_NOTES, noteWhat, offerNote, setup } from "./agents.js";
import { runGateway } from "./gateway.js";
import { KeysRequired } from "./verifier.js";
import { FILE_CHECKS, defaultChecksFile } from "./checks.js";
import { checksPath } from "./checks-runtime.js";
import { CiError, ciCheck, ciLines } from "./ci-check.js";
import { flagPrompter, runProtect, runRulesPublish, terminalPrompter, type Prompter } from "./protect.js";
import { loadSession, login, logout, personWitness } from "./session.js";
import { runCheck, runProve, runPull, startFresh, statusTable } from "./tool-commands.js";
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

/** Say so when the project's `.env` names a witness that signing in does not use (§8). */
function envUrlNote(rec: Recorder, url: string): void {
  if (rec.url !== url) err(`note: SIGNAFAIDE_URL in the project's .env names ${rec.url}; signing in and saving rules use ${url} (--url, or SIGNAFAIDE_URL in the environment), never a project file.`);
}

/** The website of a witness: https://api.signafaide.co.uk -> https://signafaide.co.uk. */
export function siteOf(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host.replace(/^api\./, "")}`;
}

/** How `protect`, `pull` and `prove` ask: a person at a terminal, else nobody (defaults only,
 * never On, never a new field). Tests set their own. */
let makePrompter: ((yes: boolean) => Prompter & { close?(): void }) | null = null;
export function setPrompter(f: ((yes: boolean) => Prompter & { close?(): void }) | null): void {
  makePrompter = f;
}
function prompter(yes = false): Prompter & { close?(): void } {
  if (makePrompter) return makePrompter(yes);
  return process.stdin.isTTY ? terminalPrompter() : flagPrompter({ yes });
}

/** One plain line each, never in --json output. The verify one shows at most once a week. */
export const UPGRADE_LIMIT = (site: string): string =>
  `upgrade: Solo (£19 a month) takes 100,000 live records a month and keeps recording past them at £5 per 100,000: ${site}/pricing`;
export const UPGRADE_VERIFY = (site: string): string =>
  `upgrade: Solo (£19 a month) adds a verification report for a period and auditor links up to 90 days: ${site}/pricing`;
const HINT_EVERY_MS = 7 * 86_400_000;

/** After a passing verify on a live key of a Free organisation: one line, once a week. */
async function upgradeAfterVerify(rec: Recorder): Promise<void> {
  if (!rec.apiKey?.startsWith("sfa_live_")) return;
  const last = Date.parse(String(rec.state.config().upgrade_hint ?? ""));
  if (Number.isFinite(last) && Date.now() - last < HINT_EVERY_MS) return;
  try {
    if ((await rec.client(3000).usage())?.plan !== "free") return;
    rec.state.saveConfig({ upgrade_hint: new Date().toISOString() });
  } catch {
    return;
  }
  out(UPGRADE_VERIFY(siteOf(rec.url)));
}

/** The `status` report, also returned by the MCP `signafaide_status` tool. */
export async function statusLines(rec: Recorder): Promise<string[]> {
  const lines: string[] = [];
  const s = rec.status();
  if (s.test_mode) lines.push("test mode: records go to a temporary folder and nothing is sent (SIGNAFAIDE_TEST, or a test runner); SIGNAFAIDE_TEST=0 turns it off");
  lines.push(
    s.api_key_invalid
      ? `key: SIGNAFAIDE_API_KEY is set but is not a signafAIde key (sfa_test_ or sfa_live_ and 32 letters or digits); nothing is sent until it is fixed`
      : `key: ${mask(s.api_key)}` +
          (s.env ? ` (env ${s.env})` : "; records stay on this machine (signed and chained, nothing is sent). `signafaide init` creates a free sandbox and sends hashes; or set SIGNAFAIDE_API_KEY"),
  );
  lines.push(`service: ${s.url}`);
  let project: { project?: string; env?: string; claimed?: boolean; name?: string | null; expires_at?: string } = {};
  let answered = false;
  let refused = false;
  if (s.api_key) {
    try {
      project = (await rec.client(5000).project()) ?? {};
      answered = true;
    } catch (e) {
      project = {};
      refused = (e as { code?: string }).code === "invalid_key";
    }
  }
  const name = typeof project.name === "string" && project.name ? project.name : null;
  if (project.project) lines.push(name ? `project: ${name} (${project.project}, ${project.env})` : `project: ${project.project} (${project.env})`);
  lines.push(`home: ${s.home}`);
  if (!s.chains.length) lines.push("chains: none yet; wrap a function with record()");
  const blocked: string[] = [];
  for (const c of s.chains) {
    const last = c.receipt_seq ? `last receipt seq ${c.receipt_seq} at ${c.receipt_time}` : c.chain.startsWith("_pending/") ? "drafts, signed for the project when they ship" : "no receipt yet";
    const other = c.current || !c.waiting ? "" : `; ${c.waiting} waiting for the key of that project`;
    const shown = name && project.project && c.chain.startsWith(`${project.project}/`) ? `${name}/${c.chain.slice(project.project.length + 1)}` : c.chain;
    lines.push(`chain ${shown}: key ${c.key_id}, ${plural(c.records, "record")}, ${last}${other}${c.blocked ? "; BLOCKED" : ""}`);
    if (c.blocked) blocked.push(`BLOCKED ${c.chain}: ${c.blocked.reason}; ${plural(c.blocked.records, "record")} cannot ship. Next: ${c.blocked.next}`);
  }
  for (const c of s.chains) for (const line of c.telemetry) lines.push(`note: ${line}`);
  if (s.chains.some((c) => c.agent === rec.defaultAgent)) {
    lines.push(`note: agent "${rec.defaultAgent}" is named after the project folder; give agents explicit names in production (record(fn, { agent: "claims-bot" }))`);
  }
  for (const h of s.held) lines.push(`held: ${h.chain}: ${plural(h.records, "record")} set aside by \`signafaide repair\` in ${h.file} (kept, verifiable locally, not co-signed)`);
  lines.push(`outbox: ${plural(s.outbox, "record")} waiting` + (s.outbox && !blocked.length ? "; run `signafaide flush`" : ""));
  lines.push(...blocked);
  if (s.api_key) {
    try {
      const u = await rec.client(5000).usage();
      lines.push(`quota: ${u.used} of ${u.quota} used in ${u.period}`);
      if (u.plan === "free" && typeof u.quota === "number" && u.used >= u.quota && s.api_key.startsWith("sfa_live_")) lines.push(UPGRADE_LIMIT(siteOf(rec.url)));
    } catch (e) {
      lines.push(`quota: unknown (${(e as Error).message})`);
    }
  }
  // The claim step, from the answer above: the link and why to claim, the time left when the
  // witness gave it, "done" once claimed, and how to carry on when the sandbox is gone.
  const view = await sandboxView(rec, { answer: answered ? project : null, refused });
  if (view) lines.push(...claimLines(view, rec.state.root));
  return lines;
}

/** `flush`, also run by the MCP `signafaide_flush` tool: ship the outbox now and say what happened.
 * `errors` has one line per chain (or API key) that could not ship. With no API key nothing is sent. */
export async function flushReport(rec: Recorder): Promise<{ lines: string[]; errors: string[]; codes: string[]; failed: boolean; sent: boolean }> {
  const r = await rec.flush();
  const errors = Object.entries(r.errors).map(([agent, e]) => `${agent}: ${e.message}`);
  const codes = [...new Set(Object.values(r.errors).map((e) => e.code))];
  if (!rec.apiKey) {
    return { lines: [`no API key: nothing was sent; ${plural(r.left, "record")} stay local. Run \`signafaide init\` (or set SIGNAFAIDE_API_KEY) to send hashes`], errors, codes, failed: false, sent: false };
  }
  // Chains the service cannot take (too_old, chain_exists) stay on this machine: not "left to ship".
  const local = Object.entries(r.errors)
    .filter(([, e]) => e.code === "too_old" || e.code === "chain_exists")
    .reduce((n, [c]) => n + rec.state.draftCount(c), 0);
  const lines = [`shipped ${plural(r.shipped, "record")}, ${r.left - local} left in the outbox` + (local ? `; ${plural(local, "record")} kept on this machine only (see above)` : "")];
  for (const b of rec.diagnose()) lines.push(`BLOCKED ${b.chain}: ${plural(b.records, "record")} cannot ship as they are. Next: ${b.next}`);
  if (rec.apiKey.startsWith("sfa_live_") && Object.values(r.errors).some((e) => e.code === "quota_exceeded")) lines.push(UPGRADE_LIMIT(siteOf(rec.url)));
  return { lines, errors, codes, failed: errors.length > 0, sent: true };
}

export const COMMANDS: Record<string, Command> = {
  protect: {
    help:
      "find your agent's tools, ask what to block, write protect(...) into the code, make a free sandbox and save the rules; " +
      "a rule is On only when you answer On at the terminal, every other rule starts Calibrating",
    usage:
      "protect [tool] [--tool <name>] [--limit-field <field> --above <number>] [--local] [--yes] [--url <witness url>]\n" +
      "  tool, --tool: protect this one tool (default: proposes the tools that pay, delete or send)\n" +
      "  --limit-field, --above: block the tool when that field is above the number, without asking what to block\n" +
      "  --local: rules only on this machine (the checks file); no account, signafAIde does not rule\n" +
      "  --yes: without a terminal, accept the code change and the project note; rules then start Calibrating, no field is sent until `signafaide pull` at a terminal, and no sandbox is made\n" +
      "  --url: the witness that saves the rules (else SIGNAFAIDE_URL in the environment, else the hosted service; never the project's .env)",
    options: {
      local: { type: "boolean" },
      yes: { type: "boolean" },
      dir: { type: "string" },
      url: { type: "string" },
      tool: { type: "string" },
      "limit-field": { type: "string" },
      above: { type: "string" },
    },
    async run(v, pos) {
      const tool: string | undefined = v.tool ?? pos[0];
      if (v.tool && pos[0] && v.tool !== pos[0]) {
        err(`signafaide protect: two tools named (${pos[0]} and --tool ${v.tool}); name one`);
        return 2;
      }
      let limit: { field: string; above: number } | undefined;
      if (v["limit-field"] !== undefined || v.above !== undefined) {
        const above = Number(v.above);
        if (!v["limit-field"] || v.above === undefined || !(above > 0 && Number.isFinite(above)) || !tool) {
          err("signafaide protect: --limit-field <field> and --above <number above 0> go together, with the tool: protect --tool <name> --limit-field amount --above 1000");
          return 2;
        }
        limit = { field: String(v["limit-field"]), above };
      }
      const root = v.dir ? path.resolve(v.dir) : findRoot();
      const rec = configure({ quiet: true, via: "cli", root, url: v.url ? personWitness(v.url) : undefined });
      const p = prompter(!!v.yes);
      try {
        const r = await runProtect({ rec, root, tool, local: !!v.local, limit, prompt: p, out });
        return r.code;
      } finally {
        p.close?.();
      }
    },
  },

  check: {
    help: "a dry run of a tool call against the rules: records nothing, runs nothing; exit 1 when the call would be blocked. check --ci: exit 1 when a risky tool is not protected (for CI)",
    usage:
      "check <tool> <field>=<value>... [--agent X]   (a value is JSON when it reads as JSON, else text; a/b=v sets a field inside an object)\n" +
      "check --ci [--diff <base-ref>] [--allow <tool>]... [--dir <folder>] [--json]\n" +
      "  --ci: list the tools that pay, delete, send, run commands, push code or edit secrets or config and are not protected, one line each with the fix; exit 1 when there is one, 0 when none. Reads the code and the checks file only: no account, no key, nothing sent\n" +
      "  --diff: only the tools added or changed since this git base (a pull request's base commit)\n" +
      "  --allow: a reviewed exception (or list it with its reason in signafaide.checks.json: \"ci\": { \"allow\": [{ \"tool\", \"reason\" }] })",
    options: { agent: { type: "string" }, ci: { type: "boolean" }, diff: { type: "string" }, allow: { type: "string", multiple: true }, dir: { type: "string" }, json: { type: "boolean" } },
    async run(v, pos) {
      if (v.ci) {
        if (pos.length) {
          err(`signafaide check --ci takes no tool; usage: signafaide check --ci [--diff <base-ref>] [--allow <tool>]... [--json]`);
          return 2;
        }
        try {
          const r = ciCheck({ root: v.dir ? path.resolve(v.dir) : process.cwd(), base: v.diff ?? null, allow: v.allow ?? [] });
          if (v.json) out(JSON.stringify(r, null, 2));
          else for (const l of ciLines(r)) out(l);
          return r.ok ? 0 : 1;
        } catch (e) {
          if (!(e instanceof CiError)) throw e;
          err(`signafaide check --ci: ${e.message}`);
          return 2;
        }
      }
      if (v.diff !== undefined || v.allow !== undefined || v.json || v.dir !== undefined) {
        err("signafaide check: --diff, --allow, --dir and --json go with --ci");
        return 2;
      }
      if (!pos[0]) {
        err(`usage: signafaide ${COMMANDS.check.usage}`);
        return 2;
      }
      const [lines, code] = await runCheck(recorder(), pos[0], pos.slice(1), v.agent);
      for (const l of lines) out(l);
      return code;
    },
  },

  pull: {
    help: "fetch the project's rules and update the checks file; asks before any new field of a protected tool is sent to signafAIde",
    async run() {
      const p = prompter(false);
      try {
        return await runPull(recorder(), p, out);
      } finally {
        p.close?.();
      }
    },
  },

  prove: {
    help: "what to give your auditor: a read-only link (or files with --files), with the calls, the rules in words, what ran before protection and the tool coverage",
    usage:
      "prove [tool] [--agent X] [--days N] [--files] [--content] [--all]\n  --days: how long the link works (default 30, or the longest your plan allows); an active link for the same tool is reused unless --days is given\n  --files: write proof/<tool>/ (pack, agent keys, head, and the content when you say so)\n  --all: from the agent's first record, not from `signafaide start-fresh`",
    options: { agent: { type: "string" }, days: { type: "string" }, files: { type: "boolean" }, content: { type: "boolean" }, all: { type: "boolean" } },
    async run(v, pos) {
      let days: number | undefined;
      if (v.days !== undefined) {
        days = Number(v.days);
        if (!Number.isInteger(days) || days < 1 || days > 3650) {
          err("signafaide prove: --days takes a whole number of days from 1, e.g. --days 7");
          return 2;
        }
      }
      const p = prompter(false);
      try {
        return await runProve(recorder(), { tool: pos[0], agent: v.agent, days, files: !!v.files, content: v.content ? true : undefined, all: !!v.all, out, prompt: p });
      } finally {
        p.close?.();
      }
    },
  },

  "start-fresh": {
    help: "start the agent's proofs from now (the calls before stay recorded and can still be proved with prove --all)",
    usage: "start-fresh <agent>",
    async run(_v, pos) {
      if (!pos[0]) {
        err(`usage: signafaide ${COMMANDS["start-fresh"].usage}`);
        return 2;
      }
      const t = startFresh(recorder(), pos[0]);
      out(`${pos[0]}: proofs start at ${t} from now on. The old record is kept and can still be proved: npx signafaide prove --agent ${pos[0]} --all`);
      return 0;
    },
  },

  login: {
    help: "sign in to the console from this terminal (device code), so you can save rules; the session is kept outside the project",
    usage:
      "login [--url <witness url>] [--console <console origin>]\n" +
      "  the witness is --url, else SIGNAFAIDE_URL in the environment, else the hosted service (never the project's .env);\n" +
      "  --console: where a self-hosted witness's sign-in page is, when not on the witness's own origin",
    options: { url: { type: "string" }, console: { type: "string" } },
    async run(v) {
      const rec = recorder();
      const url = personWitness(v.url);
      envUrlNote(rec, url);
      const s = await login({ url, console: v.console, clientId: rec.clientId(), out });
      out(`Signed in as ${s.person?.email ?? "you"}${s.organisation?.name ? ` (${s.organisation.name})` : ""} at ${url} until ${s.expires_at}. Rules you save from this terminal name you.`);
      return 0;
    },
  },

  logout: {
    help: "end the console session this terminal holds",
    usage: "logout [--url <witness url>]",
    options: { url: { type: "string" } },
    async run(v) {
      const rec = recorder();
      const url = personWitness(v.url);
      const had = await logout(url, rec.clientId());
      out(had ? `Signed out of ${url}.` : `No session was held here for ${url}.`);
      return 0;
    },
  },

  whoami: {
    help: "who is signed in on this terminal (signafaide login), and until when",
    usage: "whoami [--url <witness url>]",
    options: { url: { type: "string" } },
    async run(v) {
      const s = loadSession(personWitness(v.url));
      out(s ? `${s.person?.email ?? "signed in"}${s.organisation?.name ? ` (${s.organisation.name})` : ""} until ${s.expires_at}` : "not signed in (signafaide login)");
      return s ? 0 : 1;
    },
  },

  init: {
    help:
      "opt in to the witness: create a free sandbox if there is no API key (no account, email or card), print the claim link and how long an unclaimed sandbox is kept. " +
      "The witness is https://api.signafaide.co.uk unless SIGNAFAIDE_URL names another (a self-hosted witness, or http://127.0.0.1:7474 for a local one). " +
      "Adds .signafaide/ and .env to .gitignore",
    usage: "init   (environment: SIGNAFAIDE_URL=<witness url>, SIGNAFAIDE_API_KEY=<existing key>)",
    async run() {
      const rec = recorder();
      rec.rememberAgent();
      rec.state.ignoreInGit();
      const had = rec.apiKey;
      const key = await rec.createSandbox();
      // A sandbox made just now is described from the witness's own answer; an existing one is asked about.
      const view = await sandboxView(rec, { refresh: !!had });
      if (!had) {
        out(`sandbox ready at ${rec.url}, key saved to ${path.join(rec.state.root, ".env")}; claim it at ${view?.claim_url}`);
        if (view) for (const line of claimNotes(view)) out(line);
        out(termsNotice(rec.legal()));
        out("from now on record hashes (never content) are sent for co-signature and public timestamps; records written before now ship with their original times on the next run or with `signafaide flush`");
      } else if (view) {
        const [first, ...rest] = claimLines(view, rec.state.root);
        out(view.claimed || sandboxGone(view) ? `key found (${mask(key)}); ${first}` : `key found (${mask(key)}); claim the sandbox at ${view.claim_url}`);
        for (const line of rest) out(line);
      } else out(`key found (${mask(key)}, env ${envOf(key)}); nothing to create`);
      initChecks(rec);
      const p = prompter();
      try {
        for (const c of await offerNote(rec.state.root, p, out)) out(`agents: ${c.file} ${c.result}, with ${noteWhat(c, true)}`);
      } finally {
        p.close?.();
      }
      return 0;
    },
  },

  status: {
    help: "one line per tool (recorded, protected, proof), then key and env, agents, last receipt, outbox size, quota; BLOCKED chains (exit 1 when any)",
    async run() {
      const rec = recorder();
      const table = await statusTable(rec);
      for (const line of table) out(line);
      if (table.length) out("");
      const lines = await statusLines(rec);
      for (const line of lines) out(line);
      return lines.some((l) => l.startsWith("BLOCKED ")) ? 1 : 0;
    },
  },

  repair: {
    help: "set aside records the witness can never take (clock went back, revoked key, clock ahead), rotate the agent's key and start a new segment; history is kept and verifiable",
    usage: "repair [--agent X] [--dry-run]",
    options: { agent: { type: "string" }, "dry-run": { type: "boolean" } },
    async run(v) {
      const rec = recorder();
      const dry = !!v["dry-run"];
      const done = rec.repair({ agent: v.agent, dryRun: dry });
      if (!done.length) {
        out(`nothing to repair${v.agent ? ` for agent ${v.agent}` : ""}: every chain can ship (\`signafaide status\` shows them)`);
        return 0;
      }
      for (const r of done) {
        out(`${r.chain}: ${r.blocked.reason}`);
        if (dry) {
          out(`  would set aside seq ${r.blocked.seq} onwards (${plural(r.blocked.records, "record")}), give the agent a new key and write a signafaide.repair note`);
          continue;
        }
        out(`  set aside ${plural(r.records!, "record")} in ${r.held} (kept; \`signafaide verify\` still checks their signatures and content hashes)`);
        out(r.newKey ? `  new key ${r.newKey} signs from now on; the old key is retired on the witness at the next send` : "  the key comes from a secret store: rotate it there if it was revoked");
        out(`  note ${r.note!.slice(0, 12)} (signafaide.repair) commits to the held records' hashes and ships with the next send`);
      }
      if (!dry) out("next: `signafaide flush` sends the new segment, then `signafaide keys export` for your auditors (it lists the old and new keys)");
      return 0;
    },
  },

  verify: {
    help: "verify a pack or the local state; exit 0 PASS, 1 FAIL, 2 unreadable input",
    usage:
      "verify [pack.json] [--keys <file|url>] [--agent-keys <file|url>] [--head head.json] [--timestamp-check <url>] [--offline] [--trust-embedded-keys] [--trust-embedded-agent-keys] [--content <file|dir>] [--fail-on-pending-send] [--json]\n" +
      "  --head: the customer's .signafaide/head.json (their newest receipt per agent). It proves no record was cut from the end of the pack; the customer sends it with the pack.\n" +
      "  without a pack: checks this machine's records; a BLOCKED chain always exits 1, and --fail-on-pending-send also fails while records wait to be co-signed (for CI)",
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
      "fail-on-pending-send": { type: "boolean" },
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
          failOnPendingSend: v["fail-on-pending-send"],
        });
      } catch (e) {
        err(`signafaide: ${(e as Error).message}`);
        await rec.event("verify");
        return 2;
      }
      // The sandbox's claim step goes with the result: as data in --json, as plain lines after a pass.
      const view = await sandboxView(rec, { refresh: !v.offline });
      out(v.json ? JSON.stringify(view ? { ...(report.toJSON() as object), sandbox: sandboxJson(view) } : report, null, 2) : String(report));
      await rec.event("verify");
      if (report.ok && !v.json) {
        if (view && !view.claimed) for (const line of claimLines(view, rec.state.root)) out(line);
        await upgradeAfterVerify(rec);
      }
      return report.ok ? 0 : 1;
    },
  },

  keys: {
    help: "export the agent public keys for auditors, make a key for a secret store, or rotate an agent's key",
    usage: "keys export [-o agent-keys.json] | keys create [--agent X] [--env test|live] [--print] | keys rotate [--agent X] [--env test|live]",
    options: { output: { type: "string", short: "o" }, agent: { type: "string" }, env: { type: "string" }, print: { type: "boolean" } },
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
        out(`wrote ${file} (${plural(doc.keys.length, "key")}); give it to your auditors with pack.json and head.json: signafaide verify pack.json --keys <witness>/.well-known/signafaide-keys.json --agent-keys ${file} --head head.json`);
        return 0;
      }
      if (pos[0] === "create" && pos.length === 1) {
        const agent = v.agent ?? rec.defaultAgent;
        const env = v.env ?? envOf(rec.apiKey);
        if (env !== "test" && env !== "live") throw new SyntaxError("--env must be test or live");
        const r = await rec.createKey(agent, env, !!v.print);
        if (v.print) {
          out(JSON.stringify(r.doc));
          err(
            `signafaide: registered key ${r.doc.key_id} for ${agent} (${r.project}, ${env}); no record was written and nothing was saved here. ` +
              `Store the line above in your secret store as ${r.envName} and keep a backup: it is the only copy of the private key.`,
          );
        } else {
          out(`${agent}: registered key ${r.doc.key_id} (${r.project}, ${env}) and saved it as ${r.file}; no record was written. For a secret store, store that file's content as ${r.envName}.`);
        }
        return 0;
      }
      if (pos[0] === "rotate" && pos.length === 1) {
        const agent = v.agent ?? rec.defaultAgent;
        const env = v.env ?? envOf(rec.apiKey);
        if (env && env !== "test" && env !== "live") throw new SyntaxError("--env must be test or live");
        const [old, next] = rec.state.rotateKey(agent, env === "live" ? "live" : "");
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
    help: "print the sandbox claim link again, why to claim it and how long an unclaimed sandbox has left",
    async run() {
      const rec = recorder();
      if (rec.apiKey?.startsWith("sfa_live_")) {
        out("this project uses a live key; there is nothing to claim");
        return 0;
      }
      const view = await sandboxView(rec);
      if (!view) {
        err("no sandbox here; run `signafaide init` first");
        return 1;
      }
      if (view.claimed) {
        out(CLAIM_DONE);
        return 0;
      }
      if (sandboxGone(view)) {
        for (const line of claimLines(view, rec.state.root)) err(line);
        return 1;
      }
      // The link alone on the first line, for scripts; then why to claim and the time left.
      const [, ...rest] = claimLines(view, rec.state.root);
      out(view.claim_url);
      for (const line of rest) out(line);
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
      // The note in CLAUDE.md and AGENTS.md: asked at a terminal; without one, running this command is the request.
      let note = true;
      if (!dry) {
        const preview = setup({ root, agents: v.agent, dryRun: true, url: v.url });
        const files = [...new Set(preview.flatMap((r) => r.changes).filter((c) => /^(CLAUDE|AGENTS)\.md$/.test(c.file) && c.result !== "unchanged").map((c) => c.file))];
        if (files.length) {
          const p = prompter();
          try {
            if (p.person) note = await p.confirm(`${NOTE_QUESTION} ${files.join(" and ")} (a short marked block that tells coding agents to protect the tools that pay, delete, send, run commands or push code)?`, true);
          } finally {
            p.close?.();
          }
        }
      }
      const results = setup({ root, agents: v.agent, dryRun: dry, url: v.url, note });
      if (!dry && results.length) {
        // Set-up time: the coding agent is remembered once here (telemetry), and the local state
        // is kept out of git here, never at runtime.
        const rec = configure({ quiet: true, via: "cli", root });
        rec.rememberAgent();
        rec.state.ignoreInGit();
      }
      if (!results.length) {
        out(`no coding agent found for ${root}; name one with --agent ${AGENT_IDS.join("|")} (or --agent all)`);
        return 1;
      }
      if (dry) out("dry run: nothing written");
      for (const r of results) {
        const what = r.changes.map((c) => `${c.file} ${dry && /^(created|updated)$/.test(c.result) ? `would be ${c.result}` : c.result}`).join(", ");
        out(`${r.agent}: ${what}${r.note ? `; note: ${r.note}` : ""}`);
      }
      if (!dry) initChecks(configure({ quiet: true, via: "cli", root }));
      for (const line of SETUP_NOTES(v.url)) out(line);
      return results.some((r) => r.changes.some((c) => c.result.startsWith("skipped"))) ? 1 : 0;
    },
  },

  mcp: {
    help: "run the signafAIde MCP server over stdio (the separate signafaide-mcp package; `agent setup` configures it)",
    async run() {
      // A variable specifier: bundlers leave it alone, so the SDK never ships the MCP server.
      const pkg = "signafaide-mcp";
      let mod: { serve(): Promise<void> };
      try {
        mod = await import(pkg);
      } catch {
        err(`signafaide: the MCP server is a separate package: run \`npx -y signafaide-mcp@${VERSION}\` (\`signafaide agent setup\` writes that into your coding agent's configuration)`);
        return 1;
      }
      await mod.serve();
      return 0;
    },
  },

  gateway: {
    help:
      "run an MCP server behind a recording proxy: every tool call that passes through it is recorded (a decision before the call is forwarded, an outcome when the answer arrives), " +
      "and the server's tools are declared as the agent's recorded tools",
    usage:
      "gateway [--agent X] [--name-prefix P] [--strict | --strict-tools a,b] [--store-content] -- <command> [args...]\n" +
      "  In the agent's MCP configuration, start the gateway in place of the server: {\"command\": \"npx\", \"args\": [\"-y\", \"signafaide\", \"gateway\", \"--agent\", \"support-bot\", \"--\", \"npx\", \"-y\", \"@modelcontextprotocol/server-filesystem\", \"/data\"]}\n" +
      "  --agent: the agent's chain name (default: the project folder's name)\n" +
      "  --name-prefix: put before each recorded tool name, for an agent with several servers (--name-prefix github.)\n" +
      "  --strict: protect every tool (forward a call only once the witness has co-signed its decision); --strict-tools a,b: protect only those tools\n" +
      "  --store-content: send inputs and outputs to the witness too (default: hash-only)\n" +
      "  A remote (HTTP) server: put a stdio bridge after the --, for example `signafaide gateway -- npx -y mcp-remote https://mcp.example.com/mcp`\n" +
      "  A call that cannot be recorded is not forwarded. The gateway records every call that goes through it; a call the application makes around it is still not recorded, " +
      "so the deployment has to make the gateway the only route to those tools.\n" +
      "  Nothing is sent until the project has run `signafaide init` or has an API key. Only protocol messages go to stdout; diagnostics go to stderr.",
    options: { agent: { type: "string" }, "name-prefix": { type: "string" }, strict: { type: "boolean" }, "strict-tools": { type: "string" }, "store-content": { type: "boolean" } },
    async run(v, pos) {
      if (!pos.length) {
        err(`usage: signafaide ${(COMMANDS.gateway.usage ?? "").split("\n")[0]}`);
        return 2;
      }
      const r = await runGateway({
        command: pos[0],
        args: pos.slice(1),
        agent: v.agent,
        namePrefix: v["name-prefix"],
        strict: !!v.strict,
        strictTools: typeof v["strict-tools"] === "string" ? v["strict-tools"].split(",").map((t: string) => t.trim()).filter(Boolean) : undefined,
        storeContent: v["store-content"] ? true : undefined,
      });
      // The server was ended by a signal: end the same way, so the client sees what happened.
      if (r.signal) {
        try {
          process.kill(process.pid, r.signal);
        } catch {
          /* falls through to the exit code */
        }
      }
      return r.code;
    },
  },

  flush: {
    help: "ship the outbox now",
    async run() {
      const r = await flushReport(recorder());
      for (const e of r.errors) err(e);
      for (const l of r.lines) out(l);
      return r.failed ? 1 : 0;
    },
  },

  checks: {
    help: "tool-call checks: `checks status` (exit 1 on a problem), `checks approve <tool>`",
    usage:
      "checks status | checks approve <tool> [--agent X]\n" +
      "  status: whether checks are on and whether each tool is On or Calibrating, each protected tool with what happens if signafAIde can't be reached (Stop or Let it run) and the fields it discloses, the held rule set and list, any problem\n" +
      "  approve <tool>: re-approve a changed tool (local approvals): its next call approves the description and schema it has then",
    options: { agent: { type: "string" } },
    async run(v, pos) {
      const rec = recorder();
      if (pos[0] === "approve") {
        const tool = pos[1];
        if (!tool) {
          err("signafaide checks approve: name the tool");
          return 2;
        }
        const agents = rec.checks.approve(tool, v.agent);
        const held = rec.checks.heldRules();
        if (held && held.approved !== null) {
          out(`${tool}: the rule set approves tools (version ${held.version}); re-approve it in the console, which publishes a new version`);
          return 1;
        }
        out(
          agents.length
            ? `${tool}: approval dropped for ${agents.join(", ")}; its next call approves the description and schema it has then`
            : `${tool}: no local approval held; its next call approves the description and schema it has then`,
        );
        return 0;
      }
      if (pos[0] !== "status" || pos.length > 1) {
        err(`usage: signafaide ${(COMMANDS.checks.usage ?? "").split("\n")[0]}`);
        return 2;
      }
      const [lines, problem] = rec.checks.status();
      for (const line of lines) out(line);
      return problem ? 1 : 0;
    },
  },

  rules: {
    help: "the project's rule set: `rules pull`, `rules show`, `rules test <tool> <arguments JSON>`, `rules publish <file>`",
    usage:
      "rules pull | rules show | rules test <tool> '<arguments JSON>' [--agent X] | rules publish <file>\n" +
      "  pull: fetch the project's rule set now; show: print the held one; test: evaluate a call as the client does;\n" +
      "  publish: save the file's rules as the next version, signed in (signafaide login), after you say yes at this terminal;\n" +
      "  --url: the witness to publish to (else SIGNAFAIDE_URL in the environment, else the hosted service; never the project's .env)",
    options: { agent: { type: "string" }, url: { type: "string" } },
    async run(v, pos) {
      const rec = v.url ? configure({ quiet: true, via: "cli", url: personWitness(v.url) }) : recorder();
      if (pos[0] === "pull") {
        out(await rec.checks.pullRules());
        return "rules" in rec.checks.problems ? 1 : 0;
      }
      if (pos[0] === "publish") {
        if (!pos[1]) {
          err(`usage: signafaide rules publish <file>`);
          return 2;
        }
        const p = prompter(false);
        try {
          return await runRulesPublish(rec, path.resolve(pos[1]), p, out);
        } finally {
          p.close?.();
        }
      }
      if (pos[0] === "show") {
        const item = rec.checks.heldRulesItem();
        if (!item) {
          out("no rule set held" + (rec.apiKey ? "" : " (no API key)") + "; `signafaide rules pull` fetches it");
          return 1;
        }
        out(JSON.stringify(item.rules, null, 2));
        return 0;
      }
      if (pos[0] !== "test" || !pos[1] || pos[2] === undefined) {
        err(`usage: signafaide ${(COMMANDS.rules.usage ?? "").split("\n")[0]}`);
        return 2;
      }
      let args: unknown;
      try {
        args = JSON.parse(pos[2]);
      } catch (e) {
        throw new SyntaxError(`the arguments are not JSON: ${(e as Error).message}`);
      }
      for (const line of rec.checks.testCall(pos[1], args, v.agent || rec.defaultAgent)) out(line);
      return 0;
    },
  },
};

/** Turn tool-call checks on in watch mode (§8): write the checks file when there is none, and say
 * which checks are on, in which mode, which tools are strict and which fields leave the machine. */
function initChecks(rec: Recorder): void {
  const p = checksPath(rec.state.root);
  if (p === null) {
    out("tool-call checks: off (SIGNAFAIDE_CHECKS=0)");
    return;
  }
  const how =
    `tool-call checks: change it in ${p}: \`"mode": "enforce"\` is On (it blocks) and \`"watch"\` is Calibrating (it only notes), \`"strict": true\` on a tool protects it (it asks the witness for a ruling; \`false\` is Not protected), \`"fail": "closed"\` is Stop and \`"open"\` is Let it run if signafAIde can't be reached, \`"disclose"\` lists the fields of its arguments that may leave the machine; ` +
    "`signafaide checks status` shows what is on, which tools are protected and which fields leave";
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, JSON.stringify(defaultChecksFile(), null, 2) + "\n");
    out(
      `tool-call checks: on, Calibrating (${path.basename(p)}, commit it with the code): ${FILE_CHECKS.join(", ")} and your rules note what they find and never block. ` +
        "No tool is protected and no field of a tool's arguments leaves the machine; only tool fingerprints do.",
    );
  } else {
    const [lines] = rec.checks.status();
    out("tool-call checks: " + lines[0].replace(/^checks: /, ""));
    // Which tools are strict and which fields leave the machine, as the file says.
    for (const l of lines.slice(1)) if (/^(protected tool |PROBLEM)/.test(l)) out("tool-call checks: " + l);
    if (!lines.some((l) => /^protected tool /.test(l))) out("tool-call checks: no tool is protected; only tool fingerprints leave the machine unless a tool lists fields in disclose");
  }
  out(how);
}

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

/** Commands that end the process when they return: nothing they leave open (the client's stdin)
 * may keep it alive. */
export const EXIT_WHEN_DONE = new Set(["gateway"]);

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
  // Options after `--` belong to the command the gateway runs.
  const own = rest.includes("--") ? rest.slice(0, rest.indexOf("--")) : rest;
  if (own.includes("--help") || own.includes("-h")) {
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
