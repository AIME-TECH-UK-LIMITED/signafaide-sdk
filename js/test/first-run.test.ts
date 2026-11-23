/**
 * `protect --yes`, tool declarations, proxies and keys found in code (0.5.1).
 *
 * 1. `protect --yes` saves default rules for every risky tool, all Calibrating.
 * 2. Without a terminal every risky tool is protected, not only the first.
 * 3. `declareTools` goes before the program's run (and is moved there when it is after it).
 * 4. A proxy or network policy that blocks the witness is said in one plain sentence.
 * 5. `protect` in a folder that is not a git repository prints nothing from git.
 * 6 and 7. A tool protected in code is protected everywhere, and checked here, without a checks file.
 * 8. A key next to `=`, `:`, quotes, brackets, URL delimiters, `_` or `-` is found.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as C from "../src/checks.js";
import { SignafaideBlocked } from "../src/checks-runtime.js";
import { main, setPrompter } from "../src/cli.js";
import { placeDeclaration } from "../src/find-tools.js";
import { Client, SignafaideError, blockedByNetwork, networkBlockedWords } from "../src/http.js";
import { flagPrompter } from "../src/protect.js";
import { protect, record } from "../src/record.js";
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

async function main() {
  process.exit(0);
}
main().catch(() => process.exit(1));
`;

/** A made-up AWS access key, built from parts so no whole key is in this file. */
const AWS = ["AK", "IA", "QX7M2", "ZP4LD9", "RT3WN"].join("");

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

describe("protect --yes (1, 2)", () => {
  beforeEach(project);

  it("protects every risky tool and saves Calibrating defaults in the sandbox", async () => {
    await ctx.rec.createSandbox();
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "--yes");
    expect(out).not.toContain("no rule was chosen");
    expect(out).toContain("Protect    sendEmail, issueRefund, deleteCustomerRecord: without a terminal");
    const code = read("tools.ts");
    for (const n of ["sendEmail", "issueRefund", "deleteCustomerRecord"])
      expect(code).toContain(`export const ${n} = protect(`);
    expect(code).toContain("export const lookupInvoice = record(");
    expect(out).toContain("Rules      saved in your sandbox as version 1");
    expect(out).toContain("All 3 rules start Calibrating");
    expect(out).toContain("Calibrating  Block issueRefund when amount is above 1,000");
    const held = ctx.rec.checks.heldRules()!;
    const byId = Object.fromEntries(held.rules.map((r: any) => [r.id, r]));
    expect(Object.keys(byId).sort()).toEqual(["deletecustomerrecord-rate", "issuerefund-amount", "sendemail-rate"]);
    expect(byId["issuerefund-amount"].when).toEqual([{ field: "/amount", op: "gt", value: 1000 }]);
    expect(byId["deletecustomerrecord-rate"].limit).toEqual({ calls: 5, seconds: 60, per: "agent_tool" });
    expect(byId["sendemail-rate"].limit.calls).toBe(20);
    for (const r of held.rules) expect(C.ruleState(held, r)).toBe("calibrating");
    expect(out).toContain("sending amount for issueRefund is not approved");
    expect(out).toContain("To finish: npx signafaide pull (at a terminal)");
    expect(c, out).toBe(0);
  });

  it("without a key keeps the rule it can keep on this machine", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    const [c, out] = await cli("protect", "--yes");
    expect(c, out).toBe(1);
    expect(out).not.toContain("no rule was chosen");
    expect(out).toContain("Rules      not saved yet: there is no key. They start Calibrating once saved.");
    const f = JSON.parse(read("signafaide.checks.json"));
    expect(f.rules.rules.map((r: any) => r.id)).toEqual(["issuerefund-amount"]);
    expect(Object.keys(f.tools).sort()).toEqual(["deleteCustomerRecord", "issueRefund", "sendEmail"]);
  });

  it("without a terminal and without --yes shows the change and writes nothing", async () => {
    const before = read("tools.ts");
    setPrompter(() => flagPrompter({ yes: false }));
    const [c, out] = await cli("protect");
    expect(c).toBe(1);
    expect(out).not.toContain("Rule:");
    expect(out).toContain("(not written)");
    expect(out).toContain("Nothing written: there is no terminal to ask before changing your files.");
    expect(read("tools.ts")).toBe(before);
    expect(fs.existsSync(path.join(ctx.root, "signafaide.checks.json"))).toBe(false);
  });
});

describe("declareTools placement (3)", () => {
  beforeEach(project);

  it("goes before the program's run call", async () => {
    setPrompter(() => flagPrompter({ yes: true }));
    await cli("protect", "--yes");
    const code = read("tools.ts");
    expect(code.indexOf("declareTools([")).toBeGreaterThan(code.lastIndexOf("lookupInvoice = record("));
    expect(code.indexOf("declareTools([")).toBeLessThan(code.indexOf("main().catch"));
  });

  it("is moved up when it comes after the run call, and left alone when it does not", async () => {
    fs.writeFileSync(
      path.join(ctx.root, "tools.ts"),
      `import { declareTools } from "signafaide";\n${AGENT_TS}\n// The agent's full tool list, so a proof shows every tool is recorded.\ndeclareTools(["sendEmail"], { agent: "support-bot" });\n`,
    );
    setPrompter(() => flagPrompter({ yes: true }));
    await cli("protect", "--yes");
    const code = read("tools.ts");
    expect(code.split("declareTools([").length).toBe(2);
    expect(code.indexOf("declareTools([")).toBeLessThan(code.indexOf("main().catch"));
    expect(code.trimEnd().endsWith("main().catch(() => process.exit(1));")).toBe(true);
    const good = `function a() {}\ndeclareTools(["a"]);\n\nif (import.meta.url === \`file://\${process.argv[1]}\`) a();\n`;
    expect(placeDeclaration(good, 0, null)).toBe(good);
    const guarded = placeDeclaration(
      `function a() {}\n\nif (require.main === module) {\n  a();\n}\n`,
      0,
      `declareTools(["a"]);`,
    );
    expect(guarded.indexOf("declareTools")).toBeLessThan(guarded.indexOf("require.main"));
  });
});

describe("a network that blocks the witness (4)", () => {
  const SENTENCE =
    "The network here blocks signafaide.co.uk (common in cloud coding agents and CI sandboxes): allow signafaide.co.uk and api.signafaide.co.uk in the environment's network settings, or run from a machine that can reach them; records stay signed on this machine meanwhile.";
  const failing = (e: unknown) => async () => {
    throw e;
  };
  const answering =
    (status: number, text: string, contentType = "text/html") =>
    async () => ({ status, text, contentType });
  async function refusal(c: Client): Promise<SignafaideError> {
    try {
      await c.serviceKeys();
    } catch (e) {
      return e as SignafaideError;
    }
    throw new Error("no refusal");
  }

  it("says it in one sentence for a proxy's 403 or 407, a refused tunnel or blocked DNS, not for a proxy that is not there", async () => {
    const url = "https://api.signafaide.co.uk";
    for (const t of [
      answering(403, "<html>Blocked by network policy</html>"),
      answering(407, "Proxy Authentication Required"),
      failing(
        Object.assign(new TypeError("fetch failed"), {
          cause: Object.assign(new Error("Proxy response (403) !== 200 when HTTP Tunneling"), {
            code: "UND_ERR_ABORTED",
          }),
        }),
      ),
      failing(
        Object.assign(new TypeError("fetch failed"), {
          cause: Object.assign(new Error("getaddrinfo ENOTFOUND api.signafaide.co.uk"), { code: "ENOTFOUND" }),
        }),
      ),
    ]) {
      const e = await refusal(new Client(url, undefined, 1000, "test", { transport: t }));
      expect(e.message).toBe(SENTENCE);
      expect(e.code).toBe("network");
      expect(e.blocked && e.retryable).toBe(true);
    }
    const refused = failing(
      Object.assign(new TypeError("fetch failed"), {
        cause: Object.assign(new Error("connect ECONNREFUSED 10.0.0.1:3128"), { code: "ECONNREFUSED" }),
      }),
    );
    const saved = process.env.HTTPS_PROXY;
    try {
      delete process.env.HTTPS_PROXY;
      expect((await refusal(new Client(url, undefined, 1000, "test", { transport: refused }))).blocked).toBe(false);
      // A proxy that refuses the connection has refused nothing: it is not there.
      process.env.HTTPS_PROXY = "http://10.0.0.1:3128";
      expect((await refusal(new Client(url, undefined, 1000, "test", { transport: refused }))).blocked).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.HTTPS_PROXY;
      else process.env.HTTPS_PROXY = saved;
    }
    expect(networkBlockedWords("https://witness.example:8443")).toContain("blocks witness.example");
    expect(blockedByNetwork(new Error("timeout"))).toBe(false);
  });

  it("a witness's own 403 is still the witness's", async () => {
    const e = await refusal(
      new Client("https://api.signafaide.co.uk", undefined, 1000, "test", {
        transport: answering(
          403,
          JSON.stringify({ error: { code: "invalid_key", message: "The API key is not valid." } }),
          "application/json",
        ),
      }),
    );
    expect(e.blocked).toBe(false);
    expect(e.message).toBe("The API key is not valid.");
  });

  it("a protected call and flush say it in one sentence", async () => {
    await ctx.rec.createSandbox();
    ctx.service.failAlways = [403, "<html>Blocked by network policy</html>"];
    const send = protect(async (input: { to: string; body: string }) => input.to, {
      name: "send_email",
      agent: "support-bot",
    });
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    let e: SignafaideBlocked | null = null;
    try {
      await send({ to: "ops@example.com", body: "hello" });
    } catch (x) {
      e = x as SignafaideBlocked;
    } finally {
      err.mockRestore();
    }
    const host = new URL(ctx.service.url).hostname;
    expect(e?.code).toBe("no_ruling");
    expect(
      e?.message.startsWith(
        `send_email did not run: signafAIde did not rule on it, and this tool is set to stop. ${networkBlockedWords(ctx.service.url)}`,
      ),
    ).toBe(true);
    expect(e?.message).toContain(`blocks ${host}`);
    expect(e?.message).not.toContain("no receipt came");
    const [c, out] = await cli("flush");
    expect(c).toBe(1);
    expect(out.split("The network here blocks").length - 1, out).toBe(1);
  });
});

describe("git (5)", () => {
  beforeEach(project);

  it("protect runs no git, so a folder that is not a repository prints nothing from it", async () => {
    fs.rmSync(path.join(ctx.root, ".git"), { recursive: true, force: true });
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), "sfa-bin-"));
    const log = path.join(bin, "git.log");
    fs.writeFileSync(
      path.join(bin, "git"),
      `#!/bin/sh\necho "$@" >> "${log}"\necho "fatal: not a git repository (or any of the parent directories): .git" >&2\nexit 128\n`,
      { mode: 0o755 },
    );
    const saved = process.env.PATH;
    process.env.PATH = `${bin}${path.delimiter}${saved}`;
    try {
      setPrompter(() => flagPrompter({ yes: true }));
      const [, out] = await cli("protect", "--yes");
      expect(out).toContain("Protect    sendEmail");
      expect(out).not.toContain("fatal");
      expect(fs.existsSync(log)).toBe(false);
    } finally {
      process.env.PATH = saved;
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });
});

describe("protected in code, no checks file (6, 7)", () => {
  it("runs the checks in On, asks the witness, and counts as protected in status and prove", async () => {
    await ctx.rec.createSandbox();
    expect(fs.existsSync(path.join(ctx.root, "signafaide.checks.json"))).toBe(false);
    const send = protect(async (input: { to: string; body: string }) => input.to, {
      name: "send_email",
      agent: "support-bot",
    });
    let blocked: SignafaideBlocked | null = null;
    try {
      await send({ to: "ops@example.com", body: `config: aws_access_key_id=${AWS} region=eu-west-2` });
    } catch (e) {
      blocked = e as SignafaideBlocked;
    }
    expect(blocked?.check).toBe("secret");
    expect(blocked?.message).toContain("aws_access_key");
    expect(await send({ to: "ops@example.com", body: "Your parcel arrives tomorrow." })).toBe("ops@example.com");
    await ctx.rec.flush();
    const chain = ctx.rec.state.chains().find((c) => c.split("/")[2] === "support-bot")!;
    const decisions = (ctx.rec.state.readAll(chain) as any[]).filter(
      (r) => r.envelope.kind === "decision" && r.envelope.name === "send_email",
    );
    expect(decisions.length).toBe(2);
    for (const d of decisions) expect(d.envelope.checks.strict).toBe(true);
    expect(decisions[1].receipt.ruling.ruling).toBe("allow");
    let [, out] = await cli("status");
    const line = out.split("\n").find((l) => l.startsWith("send_email"))!;
    expect(line, out).not.toMatch(/\bOff\b/);
    expect(line).toContain("On");
    [, out] = await cli("prove", "send_email", "--files");
    expect(out).not.toContain("before protection");
    expect(out).toContain("Before     none: send_email was protected before its first call");
  });

  it("record()-only tools keep today's behaviour, and SIGNAFAIDE_CHECKS=0 still turns checks off", async () => {
    await ctx.rec.createSandbox();
    const note = record(async (text: string) => text, { name: "note_it", agent: "support-bot" });
    expect(await note(`key=${AWS}`)).toBe(`key=${AWS}`);
    const chain = ctx.rec.state.chains().find((c) => c.split("/")[2] === "support-bot")!;
    expect(
      (ctx.rec.state.readAll(chain) as any[]).find((r) => r.envelope.kind === "decision").envelope.checks,
    ).toBeUndefined();
    process.env.SIGNAFAIDE_CHECKS = "0";
    try {
      const send = protect(async (input: { to: string; body: string }) => input.to, {
        name: "send_email",
        agent: "support-bot",
      });
      expect(await send({ to: "ops@example.com", body: `key=${AWS}` })).toBe("ops@example.com");
    } finally {
      delete process.env.SIGNAFAIDE_CHECKS;
    }
  });
});

describe("keys next to delimiters (8)", () => {
  it.each([
    `key=${AWS}`,
    `deploy with key=${AWS} today`,
    `aws_access_key_id=${AWS}`,
    `config: aws_access_key_id: ${AWS} region=eu-west-2`,
    `keys=["${AWS}"]`,
    `https://paste.example/new?id=1&key=${AWS}#top`,
    `aws_access_key_id_${AWS}`,
    `prod-${AWS}-old`,
    `(${AWS})`,
    `'${AWS}'`,
  ])("%s", (text) => {
    const r = C.secretFindings({ body: text });
    expect(r.result).toBe("block");
    expect(r.found).toContain("aws_access_key");
  });

  it("letters glued to a key are not a key", () => {
    expect(C.secretFindings({ body: `x${AWS}` }).found).not.toContain("aws_access_key");
  });
});
