/**
 * Console-made keys, claimed projects and state writes (0.5.1).
 *
 * 1. `protect --yes` with a console-made key: the console's origin is the hosted witness, and on a
 *    claimed project the default rules stay here as Calibrating local rules, with one console link.
 * 2. State files are written under unique temp names, so two writers never collide.
 * 3. The Node transport goes through HTTPS_PROXY / HTTP_PROXY (CONNECT for https), respects
 *    NO_PROXY, and says the network blocks the witness only when the proxy refuses.
 * 5. `prove --days N` says plainly when the witness gave the earlier link back.
 * 6. Rate rules read as the console says them; an approved field is not called unapproved.
 */
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import * as tls from "node:tls";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main, setPrompter } from "../src/cli.js";
import { Client, DEFAULT_URL, SignafaideError, witnessUrl } from "../src/http.js";
import { noProxy, nodeTransport, proxyFor } from "../src/nodehttp.js";
import { flagPrompter, publisher } from "../src/protect.js";
import { record } from "../src/record.js";
import { configure, getRecorder } from "../src/runtime.js";
import { consoleOrigin, personWitness } from "../src/session.js";
import { atomicWrite } from "../src/state.js";
import { ruleWords } from "../src/words.js";
import { useProject } from "./helpers.js";

const AGENT_TS = `export async function sendEmail(input: { to: string; subject: string; body: string }) {
  return input.to;
}
export async function issueRefund(input: { orderId: string; amount: number; currency: string }) {
  return input.orderId;
}
export async function deleteCustomerRecord(input: { customerId: string }) {
  return input.customerId;
}
export async function lookupInvoice(input: { invoiceId: string }) {
  return input.invoiceId;
}
`;

let xdg: string;
beforeEach(() => {
  xdg = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-xdg-"));
  process.env.XDG_CONFIG_HOME = xdg;
});
afterEach(() => {
  setPrompter(null);
  delete process.env.XDG_CONFIG_HOME;
  fs.rmSync(xdg, { recursive: true, force: true });
});

async function cli(...args: string[]): Promise<[number, string]> {
  const lines: string[] = [];
  const log = vi.spyOn(console, "log").mockImplementation((s: string) => void lines.push(String(s)));
  const error = vi.spyOn(console, "error").mockImplementation((s: string) => void lines.push(String(s)));
  try {
    return [await main(args), lines.join("\n")];
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

const ctx = useProject();
const read = (f: string): string => fs.readFileSync(path.join(ctx.root, f), "utf8");
function project(): void {
  fs.writeFileSync(path.join(ctx.root, "tools.ts"), AGENT_TS);
  fs.writeFileSync(
    path.join(ctx.root, "package.json"),
    JSON.stringify({ name: "support-bot", version: "1.0.0" }, null, 2),
  );
}

describe("the hosted witness by either address (1a)", () => {
  it("reads the console's origin as the hosted witness", () => {
    for (const u of [
      "https://signafaide.co.uk",
      "https://signafaide.co.uk/",
      " https://SIGNAFAIDE.co.uk ",
      "https://api.signafaide.co.uk/",
    ])
      expect(witnessUrl(u)).toBe(DEFAULT_URL);
    expect(witnessUrl("http://127.0.0.1:7484/")).toBe("http://127.0.0.1:7484");
    expect(personWitness("https://signafaide.co.uk")).toBe(DEFAULT_URL);
    expect(personWitness(undefined, { SIGNAFAIDE_URL: "https://signafaide.co.uk/" })).toBe(DEFAULT_URL);
    expect(consoleOrigin("https://signafaide.co.uk")).toBe("https://signafaide.co.uk");
  });

  it("a .env that names the hosted service by the console's origin blocks nothing", async () => {
    delete process.env.SIGNAFAIDE_URL;
    fs.writeFileSync(path.join(ctx.root, ".env"), "SIGNAFAIDE_URL=https://signafaide.co.uk\n");
    const rec = configure({ quiet: true, flushIntervalMs: 3_600_000 });
    expect(rec.url).toBe(DEFAULT_URL);
    // No key here, so nothing is asked of the network: the only reason left is the key's.
    expect(await publisher(rec)).toBe("there is no API key");
  });

  it("a .env that names another witness still saves nothing there", async () => {
    delete process.env.SIGNAFAIDE_URL;
    fs.writeFileSync(path.join(ctx.root, ".env"), "SIGNAFAIDE_URL=https://witness.example\n");
    const rec = configure({ quiet: true, flushIntervalMs: 3_600_000 });
    expect(await publisher(rec)).toMatch(/^SIGNAFAIDE_URL in the project's \.env names https:\/\/witness\.example/);
  });
});

describe("protect --yes on a claimed project (1b, 6)", () => {
  beforeEach(project);

  /** The add links in `out`, as a person reads them. */
  const addLinks = (out: string): string[] => out.match(/https?:\/\/[^\s]+\/tools\/[^\s]+\?add=[^\s]+/g) ?? [];

  it("keeps the default rules in the checks file, Calibrating, and prints one console link per tool from the witness's answer", async () => {
    await ctx.rec.createSandbox();
    ctx.service.project().claimed = true;
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "--yes");
    expect(c, out).toBe(1);
    expect(out).not.toMatch(/Rules\s+saved/);
    expect(out).toContain("Rules      kept in signafaide.checks.json as Calibrating (they block nothing). An API key");
    expect(out).toContain("cannot save rules in a project of an organisation: a person adds each one in the");
    const prj = ctx.service.project();
    const tools = `${ctx.service.url}/app/p/${prj.project}/test/tools`;
    const links = addLinks(out);
    expect(links).toHaveLength(3);
    for (const t of ["sendEmail", "issueRefund", "deleteCustomerRecord"])
      expect(out).toContain(`           Add ${t}'s rule: ${tools}/support-bot/${t}?add=`);
    const del = links.find((u) => u.includes("/deleteCustomerRecord?add="))!;
    const rule = JSON.parse(decodeURIComponent(new URL(del).searchParams.get("add")!.replace(/\+/g, "%2B")));
    expect(rule).toEqual({
      id: "deletecustomerrecord-rate",
      about: "deleteCustomerRecord: more than 5 calls a minute.",
      action: "block",
      tools: ["deleteCustomerRecord"],
      agents: null,
      when: [],
      limit: { calls: 5, seconds: 60, per: "agent_tool" },
    });
    expect(
      JSON.parse(decodeURIComponent(links.find((u) => u.includes("/issueRefund?add="))!.split("?add=")[1])),
    ).not.toHaveProperty("state");
    expect(out).toContain(
      "  - the rules are not saved for the project: a person adds each one in the console (the links above)",
    );
    expect(ctx.service.published).toEqual([]);
    // Every rule is in the checks file: the amount rule as a local rule, the rate rules held in
    // `proposed` (only the witness counts calls); a person at a terminal is offered each one.
    const f = JSON.parse(read("signafaide.checks.json"));
    expect(f.rules.rules.map((r: any) => r.id)).toEqual(["issuerefund-amount"]);
    expect(f.proposed.map((p: any) => (typeof p.rule === "string" ? p.rule : p.rule.id)).sort()).toEqual([
      "deletecustomerrecord-rate",
      "issuerefund-amount",
      "sendemail-rate",
    ]);
    for (const t of ["sendEmail", "issueRefund", "deleteCustomerRecord"])
      expect(read("signafaide.checks.json")).toMatch(new RegExp(`"tools":\\s*\\[\\s*"${t}"`));
    expect(f.tools.issueRefund).toMatchObject({ protect: true, mode: "watch" });
    // Calibrating: a call the rule would stop still runs.
    const [cc, co] = await cli("check", "issueRefund", "amount=1200", "currency=GBP");
    expect(cc, co).toBe(0);
  });

  it("the link is the one the Python SDK prints too", async () => {
    const { addLink } = await import("../src/protect.js");
    const r = {
      id: "x-rate",
      about: "x: more than 5 calls a minute.",
      action: "block",
      tools: ["x"],
      agents: null,
      when: [],
      limit: { calls: 5, seconds: 60, per: "agent_tool" },
      state: "calibrating",
    };
    expect(addLink("https://signafaide.co.uk/app/p/prj_X/test/tools/", "ops-bot", r)).toBe(
      "https://signafaide.co.uk/app/p/prj_X/test/tools/ops-bot/x?add=%7B%22id%22%3A%22x-rate%22%2C%22about%22%3A%22x%3A%20more%20than%205%20calls%20a%20minute.%22%2C%22action%22%3A%22block%22%2C%22tools%22%3A%5B%22x%22%5D%2C%22agents%22%3Anull%2C%22when%22%3A%5B%5D%2C%22limit%22%3A%7B%22calls%22%3A5%2C%22seconds%22%3A60%2C%22per%22%3A%22agent_tool%22%7D%7D",
    );
    expect(addLink("https://c/tools", "a", { ...r, about: "x".repeat(5000) })).not.toContain("xxxx");
    expect(
      addLink("https://c/tools", "a", {
        ...r,
        about: undefined,
        when: [{ field: "/a", op: "in", value: ["y".repeat(5000)] }],
      }),
    ).toBeNull();
  });

  it("a kept rate rule is offered to a person later", async () => {
    await ctx.rec.createSandbox();
    ctx.service.project().claimed = true;
    setPrompter(() => flagPrompter({ yes: true }));
    await cli("protect", "deleteCustomerRecord", "--yes");
    const f = JSON.parse(read("signafaide.checks.json"));
    expect(f.proposed).toEqual([
      {
        rule: expect.objectContaining({
          id: "deletecustomerrecord-rate",
          limit: { calls: 5, seconds: 60, per: "agent_tool" },
        }),
        by: "agent",
        on: expect.any(String),
      },
    ]);
    const { proposalFor } = await import("../src/protect.js");
    expect(proposalFor(f, "deleteCustomerRecord")?.rule.id).toBe("deletecustomerrecord-rate");
    expect(proposalFor(f, "sendEmail")).toBeNull();
  });

  it("a .env that names another witness: nothing is asked there, no link", async () => {
    await ctx.rec.createSandbox();
    ctx.service.project().claimed = true;
    const url = process.env.SIGNAFAIDE_URL!;
    delete process.env.SIGNAFAIDE_URL;
    fs.appendFileSync(path.join(ctx.root, ".env"), `SIGNAFAIDE_URL=${url}\n`);
    configure({ quiet: true, flushIntervalMs: 3_600_000 });
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "issueRefund", "--yes");
    expect(c, out).toBe(1);
    expect(out).toContain("Rules      not saved: SIGNAFAIDE_URL in the project's .env names");
    expect(addLinks(out)).toEqual([]);
    expect(out).toContain("Kept in signafaide.checks.json as Calibrating (they block nothing)");
  });

  it("--limit-field on a claimed project does not call an approved field unapproved", async () => {
    await ctx.rec.createSandbox();
    setPrompter(() => flagPrompter({ yes: true }));
    await cli("protect", "issueRefund", "--yes");
    // A person approved sending amount at a terminal (`pull`).
    const f = JSON.parse(read("signafaide.checks.json"));
    f.tools.issueRefund = { protect: true, disclose: ["/amount"] };
    fs.writeFileSync(path.join(ctx.root, "signafaide.checks.json"), JSON.stringify(f, null, 2));
    ctx.service.project().claimed = true;
    const [c, out] = await cli("protect", "issueRefund", "--limit-field", "amount", "--above", "5", "--yes");
    expect(c, out).toBe(1);
    expect(out).not.toMatch(/Rules\s+saved/);
    expect(addLinks(out)).toHaveLength(1);
    expect(out).not.toMatch(/sending amount .*is not approved/);
    expect(out).toContain(
      "Sends to signafAIde when issueRefund runs: amount (approved earlier; the fields your rule needs)",
    );
    expect(JSON.parse(read("signafaide.checks.json")).tools.issueRefund.disclose).toEqual(["/amount"]);
  });
});

describe("rate rules in the console's words (6)", () => {
  const rate = (seconds: number, calls = 5) => ({
    id: "r",
    action: "block",
    tools: ["delete_account"],
    agents: null,
    when: [],
    limit: { calls, seconds, per: "agent_tool" },
  });
  it("says the window as the console does", () => {
    expect(ruleWords(rate(60))).toBe(
      "Block delete_account when more than 5 calls in 1 minute by the same agent to the same tool",
    );
    expect(ruleWords(rate(300))).toBe(
      "Block delete_account when more than 5 calls in 5 minutes by the same agent to the same tool",
    );
    expect(ruleWords(rate(3600))).toBe(
      "Block delete_account when more than 5 calls in 1 hour by the same agent to the same tool",
    );
    expect(ruleWords(rate(86_400, 1_000_000))).toBe(
      "Block delete_account when more than 1,000,000 calls in 24 hours by the same agent to the same tool",
    );
    expect(ruleWords(rate(90))).toBe(
      "Block delete_account when more than 5 calls in 90 seconds by the same agent to the same tool",
    );
    expect(ruleWords(rate(1, 1))).toBe(
      "Block delete_account when more than 1 call in 1 second by the same agent to the same tool",
    );
  });
});

describe("state files under unique temp names (2)", () => {
  it("never writes through a fixed temp name, and leaves no temp file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-atomic-"));
    try {
      // What another writer's half-done temp file looks like under a fixed name: in the way.
      fs.mkdirSync(path.join(dir, "config.json.tmp"));
      const p = path.join(dir, "config.json");
      for (let i = 0; i < 20; i++) atomicWrite(p, `{"n": ${i}}\n`);
      expect(fs.readFileSync(p, "utf8")).toBe(`{"n": 19}\n`);
      expect(fs.readdirSync(dir).sort()).toEqual(["config.json", "config.json.tmp"]);
      expect(() => atomicWrite(path.join(dir, "missing", "x.json"), "{}")).toThrow(/ENOENT/);
      expect(fs.readdirSync(dir).sort()).toEqual(["config.json", "config.json.tmp"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the recorder's state files too", () => {
    const st = getRecorder().state;
    st.ensure();
    fs.mkdirSync(path.join(st.home, "config.json.tmp"));
    fs.mkdirSync(path.join(st.home, "sandbox.json.tmp"));
    st.saveConfig({ a: 1 });
    st.saveSandbox({ project: "prj_x" });
    expect(st.config()).toMatchObject({ a: 1 });
  });

  it("several processes writing the same state file at once all succeed", async () => {
    const dist = path.resolve(__dirname, "../dist/index.js");
    expect(fs.existsSync(dist), "build the SDK first (npm run build)").toBe(true);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-race-"));
    try {
      const script = `import { State } from ${JSON.stringify(dist)};
const st = new State(process.argv[1], process.argv[2]);
let errors = 0;
for (let i = 0; i < 300; i++) { try { st.saveConfig({ ["w" + process.argv[3]]: i }); st.saveSandbox({ n: i }); } catch (e) { errors++; console.error(String(e)); } }
process.exit(errors ? 1 : 0);`;
      const runs = Array.from(
        { length: 6 },
        (_, i) =>
          new Promise<number>((resolve) => {
            const c = spawn(
              process.execPath,
              ["--input-type=module", "-e", script, path.join(root, ".signafaide"), root, String(i)],
              { stdio: ["ignore", "ignore", "pipe"] },
            );
            c.on("exit", (code) => resolve(code ?? 1));
          }),
      );
      expect(await Promise.all(runs)).toEqual([0, 0, 0, 0, 0, 0]);
      expect(fs.readdirSync(path.join(root, ".signafaide")).filter((f) => f.endsWith(".tmp"))).toEqual([]);
      JSON.parse(fs.readFileSync(path.join(root, ".signafaide", "config.json"), "utf8"));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);
});

// --- 3. proxies ---------------------------------------------------------------------------------

const SENTENCE =
  "The network here blocks signafaide.co.uk (common in cloud coding agents and CI sandboxes): allow signafaide.co.uk and api.signafaide.co.uk in the environment's network settings, or run from a machine that can reach them; records stay signed on this machine meanwhile.";

/** A CONNECT proxy: `allow` maps a target (`host:port`) to a local port; any other target, and any
 * request when `allow` is null, gets 403. Plain requests in absolute form go the same way. */
async function proxy(
  allow: Record<string, number> | null,
): Promise<{ url: string; seen: string[]; close: () => Promise<void> }> {
  const seen: string[] = [];
  const open = new Set<net.Socket>();
  const srv = net.createServer((c) => {
    open.add(c);
    c.on("close", () => open.delete(c));
    let head = Buffer.alloc(0);
    const onData = (d: Buffer): void => {
      head = Buffer.concat([head, d]);
      const end = head.indexOf("\r\n\r\n");
      if (end < 0) return;
      c.off("data", onData);
      const first = head.subarray(0, head.indexOf("\r\n")).toString("latin1");
      seen.push(first);
      const [method, target] = first.split(" ");
      const hostPort =
        method === "CONNECT"
          ? target
          : (() => {
              const u = new URL(target);
              return `${u.hostname}:${u.port || 80}`;
            })();
      const port = allow?.[hostPort];
      if (!port) {
        c.end(
          "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 22\r\nConnection: close\r\n\r\nHost not in allowlist\n",
        );
        return;
      }
      const up = net.connect(port, "127.0.0.1", () => {
        open.add(up);
        if (method === "CONNECT") {
          c.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          up.write(head.subarray(end + 4));
        } else up.write(head);
        c.pipe(up).pipe(c);
      });
      up.on("error", () => c.destroy());
    };
    c.on("data", onData);
    c.on("error", () => undefined);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as net.AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    close: () =>
      new Promise((r) => {
        for (const s of open) s.destroy();
        srv.close(() => r());
      }),
  };
}

const answer = (_req: http.IncomingMessage, res: http.ServerResponse): void => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ keys: [], via: _req.url }));
};

/** A self-signed certificate for witness.test, from openssl; null where there is none. */
function cert(): { key: string; cert: string } | null {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-cert-"));
  try {
    const r = spawnSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        path.join(dir, "k.pem"),
        "-out",
        path.join(dir, "c.pem"),
        "-days",
        "1",
        "-subj",
        "/CN=witness.test",
        "-addext",
        "subjectAltName=DNS:witness.test",
      ],
      { stdio: "ignore" },
    );
    if (r.status !== 0) return null;
    return {
      key: fs.readFileSync(path.join(dir, "k.pem"), "utf8"),
      cert: fs.readFileSync(path.join(dir, "c.pem"), "utf8"),
    };
  } catch {
    return null;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function listen(srv: http.Server | https.Server): Promise<number> {
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as net.AddressInfo).port;
}

async function refusal(c: Client): Promise<SignafaideError> {
  try {
    await c.serviceKeys();
  } catch (e) {
    return e as SignafaideError;
  }
  throw new Error("no refusal");
}

describe("the Node transport and a proxy (3)", () => {
  it("reads HTTPS_PROXY, HTTP_PROXY, ALL_PROXY and NO_PROXY as curl does", () => {
    const u = new URL("https://api.signafaide.co.uk/v1/x");
    expect(proxyFor(u, {})).toBeNull();
    expect(proxyFor(u, { HTTPS_PROXY: "http://p:3128" })?.host).toBe("p:3128");
    expect(proxyFor(u, { https_proxy: "p2:8080", HTTPS_PROXY: "http://p:3128" })?.host).toBe("p2:8080");
    expect(proxyFor(u, { HTTP_PROXY: "http://p:3128" })).toBeNull();
    expect(proxyFor(new URL("http://127.0.0.1:7484/"), { HTTP_PROXY: "http://p:3128" })?.host).toBe("p:3128");
    expect(proxyFor(u, { ALL_PROXY: "http://all:1" })?.host).toBe("all:1");
    expect(proxyFor(u, { ALL_PROXY: "socks5://all:1" })).toBeNull();
    expect(proxyFor(u, { HTTPS_PROXY: "http://p:3128", NO_PROXY: "signafaide.co.uk" })).toBeNull();
    expect(proxyFor(u, { HTTPS_PROXY: "http://p:3128", no_proxy: "localhost, .signafaide.co.uk" })).toBeNull();
    expect(noProxy(u, "*")).toBe(true);
    expect(noProxy(u, "*.signafaide.co.uk")).toBe(true);
    expect(noProxy(u, "co.uk.example")).toBe(false);
    expect(noProxy(u, "ignafaide.co.uk")).toBe(false);
    expect(noProxy(u, "api.signafaide.co.uk:8443")).toBe(false);
    expect(noProxy(u, "api.signafaide.co.uk:443")).toBe(true);
    expect(noProxy(new URL("http://[::1]:7484/"), "[::1]:7484")).toBe(true);
    expect(noProxy(new URL("http://[::1]:7484/"), "::1")).toBe(true);
  });

  const pem = cert();
  it.skipIf(!pem)(
    "reaches an https witness through a CONNECT proxy that allows it; the name is never looked up here",
    async () => {
      const srv = https.createServer({ key: pem!.key, cert: pem!.cert }, answer);
      const port = await listen(srv);
      const p = await proxy({ "witness.test:443": port });
      const T = tls as unknown as {
        getCACertificates?: (k: string) => string[];
        setDefaultCACertificates?: (c: string[]) => void;
      };
      const before = T.getCACertificates?.("default");
      if (T.setDefaultCACertificates) T.setDefaultCACertificates([...(before ?? []), pem!.cert]);
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
      try {
        const c = new Client("https://witness.test", undefined, 5000, "test", {
          transport: nodeTransport(() => true, { HTTPS_PROXY: p.url }),
        });
        expect(await c.serviceKeys()).toMatchObject({ keys: [] });
        expect(p.seen).toEqual(["CONNECT witness.test:443 HTTP/1.1"]);
      } finally {
        if (T.setDefaultCACertificates && before) T.setDefaultCACertificates(before);
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        await p.close();
        srv.close();
      }
    },
  );

  it("an http witness through HTTP_PROXY: the request in absolute form", async () => {
    const srv = http.createServer(answer);
    const port = await listen(srv);
    const p = await proxy({ "witness.test:80": port });
    try {
      const c = new Client("http://witness.test", undefined, 5000, "test", {
        transport: nodeTransport(() => true, { HTTP_PROXY: p.url }),
      });
      expect(await c.serviceKeys()).toMatchObject({
        keys: [],
        via: "http://witness.test/.well-known/signafaide-keys.json",
      });
      expect(p.seen).toEqual(["GET http://witness.test/.well-known/signafaide-keys.json HTTP/1.1"]);
    } finally {
      await p.close();
      srv.close();
    }
  });

  it("a proxy that refuses the tunnel, or the request: the one sentence", async () => {
    const p = await proxy(null);
    try {
      const https_ = await refusal(
        new Client("https://api.signafaide.co.uk", undefined, 5000, "test", {
          transport: nodeTransport(() => true, { HTTPS_PROXY: p.url }),
        }),
      );
      expect(https_.message).toBe(SENTENCE);
      expect(https_.blocked).toBe(true);
      const http_ = await refusal(
        new Client("http://api.signafaide.co.uk", undefined, 5000, "test", {
          transport: nodeTransport(() => true, { HTTP_PROXY: p.url }),
        }),
      );
      expect(http_.message).toBe(SENTENCE);
      expect(p.seen).toEqual([
        "CONNECT api.signafaide.co.uk:443 HTTP/1.1",
        "GET http://api.signafaide.co.uk/.well-known/signafaide-keys.json HTTP/1.1",
      ]);
    } finally {
      await p.close();
    }
  });

  it("a proxy that is not there has refused nothing: no sentence", async () => {
    const dead = net.createServer();
    const port = await listen(dead as unknown as http.Server);
    await new Promise((r) => dead.close(r));
    const e = await refusal(
      new Client("https://api.signafaide.co.uk", undefined, 5000, "test", {
        transport: nodeTransport(() => true, { HTTPS_PROXY: `http://127.0.0.1:${port}` }),
      }),
    );
    expect(e.blocked).toBe(false);
    expect(e.message).toMatch(
      /^Cannot reach the signafAIde service at https:\/\/api\.signafaide\.co\.uk \(ECONNREFUSED\)/,
    );
  });

  it("NO_PROXY: the host it names is reached directly", async () => {
    const srv = http.createServer(answer);
    const port = await listen(srv);
    const p = await proxy(null);
    try {
      const c = new Client(`http://127.0.0.1:${port}`, undefined, 5000, "test", {
        transport: nodeTransport(() => true, { HTTP_PROXY: p.url, NO_PROXY: "localhost,127.0.0.1" }),
      });
      expect(await c.serviceKeys()).toMatchObject({ keys: [] });
      expect(p.seen).toEqual([]);
    } finally {
      await p.close();
      srv.close();
    }
  });
});

// --- 5. prove --days ------------------------------------------------------------------------------

describe("prove --days when the witness gives the earlier link back (5)", () => {
  async function ready(): Promise<void> {
    await ctx.rec.createSandbox();
    const fn = record(
      async function approve_payout(input: { amount: number }) {
        return input.amount;
      },
      { agent: "payout-bot" },
    );
    await fn({ amount: 10 });
    await getRecorder().flush();
  }

  it("says it is the earlier link, until when, why, and how to get a new one", async () => {
    await ready();
    ctx.service.auditorReuse = true;
    let [c, out] = await cli("prove", "approve_payout", "--days", "7");
    expect(c, out).toBe(0);
    expect(out).toContain("Send this link to your auditor:");
    expect(out).not.toContain("this is not a new link");
    [c, out] = await cli("prove", "approve_payout", "--days", "3");
    expect(c, out).toBe(0);
    expect(out).toContain("Send this link to your auditor (made earlier, still open):");
    expect(out).toMatch(
      /You asked for 3 days: this is not a new link\. The link made earlier is reused, open until \d+ \w+ \d{4}, because an unclaimed sandbox's plan allows one active link\./,
    );
    expect(out).toContain(
      "For a new link: keep the sandbox (the claim link from init), then revoke this one in the console",
    );
    expect(out).toContain("then run npx signafaide prove approve_payout --days 3 again.");
    ctx.service.project().claimed = true;
    [c, out] = await cli("prove", "approve_payout", "--days", "3");
    expect(out).toContain(
      "because the witness gives this API key its open link again for the same agent, tool and start.",
    );
    expect(out).toMatch(/For a new link: revoke this one in the console/);
  }, 60_000);

  it("a plan that makes a new link: the new link, with no such words", async () => {
    await ready();
    let [, out] = await cli("prove", "approve_payout", "--days", "7");
    [, out] = await cli("prove", "approve_payout", "--days", "3");
    expect(out).toContain("Send this link to your auditor:");
    expect(out).not.toContain("this is not a new link");
    expect(ctx.service.auditorLinks.at(-1).days).toBe(3);
  }, 60_000);
});
