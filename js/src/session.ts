/**
 * Signing in from the command line (SPEC §6 and §8, spec 1.1): `signafaide login` runs the device
 * sign-in, `signafaide logout` ends it. The person session is kept in the operating system's
 * credential store when there is one (macOS Keychain, Windows Credential Manager, the Secret
 * Service on Linux through `secret-tool`), else in `signafaide/session.json` under the user's
 * configuration directory with file mode 0600: never in the project, its `.signafaide/` folder or
 * its `.env`, and never in an environment variable the agent's process reads. `session.json` always
 * says which witness each session is for and where its secret is. Only the CLI uses it, and only to
 * publish rules; the SDK never reads it while a program records.
 *
 * Where a person signs in is never chosen by a file in the project: the witness is `--url`, else
 * `SIGNAFAIDE_URL` in the process environment, else the hosted service (`personWitness`). The
 * sign-in page the witness sends is shown and opened only when it is on that witness's console
 * (`consoleOrigin`), and a session is only ever sent to the witness it was made for.
 */

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client, DEFAULT_URL, HOSTED_CONSOLE, SignafaideError, witnessUrl } from "./http.js";
import { atomicWrite } from "./state.js";
import { VERSION } from "./version.js";

export const SESSION_RE = /^sfa_user_[0-9A-Za-z]{32}$/;

/** The console of the hosted witness (`DEFAULT_URL`): its sign-in page is on this origin. */
export const DEFAULT_CONSOLE = HOSTED_CONSOLE;

export interface Session {
  session: string;
  expires_at: string;
  url: string;
  person?: { email?: string };
  organisation?: { name?: string };
  /** Where the secret is kept: `file` (in session.json) or the credential store's name. */
  store?: string;
}


/** The witness a person signs in to and publishes rules with (§8): `given` (`--url`), else
 * `SIGNAFAIDE_URL` in the process environment, else the hosted service. Never the project's
 * `.env`: a file in a project must not choose where a person's sign-in or session goes. */
export function personWitness(given?: string, env: NodeJS.ProcessEnv = process.env): string {
  const u = witnessUrl(given || env.SIGNAFAIDE_URL || DEFAULT_URL);
  let parsed: URL;
  try {
    parsed = new URL(u);
  } catch {
    throw new SignafaideError(`${u} is not a witness URL (https://host, or http://127.0.0.1:port for a local one).`, { code: "bad_request" });
  }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || /[\s"'`\\<>^|]/.test(u)) throw new SignafaideError(`${u} is not a witness URL (https://host, or http://127.0.0.1:port for a local one).`, { code: "bad_request" });
  return u;
}

/** The origin the sign-in page of the witness at `witness` must be on (§8): `given` (`--console`)
 * when given, the hosted console for the hosted witness, else the witness's own origin. */
export function consoleOrigin(witness: string, given?: string): string {
  if (given) {
    const u = new URL(given);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new SignafaideError(`--console ${given} is not an http(s) origin.`, { code: "bad_request" });
    return u.origin;
  }
  if (witnessUrl(witness) === DEFAULT_URL) return DEFAULT_CONSOLE;
  return new URL(witness).origin;
}

/** `link` when it is an http(s) URL on `origin`, as the URL parser writes it; else null. */
export function onConsole(link: unknown, origin: string): string | null {
  if (typeof link !== "string") return null;
  try {
    const u = new URL(link);
    if ((u.protocol !== "https:" && u.protocol !== "http:") || u.origin !== origin || u.username || u.password) return null;
    return u.href;
  } catch {
    return null;
  }
}

/** The user's configuration directory: `$XDG_CONFIG_HOME`, else `%APPDATA%` on Windows, else `~/.config`. */
export function configDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.XDG_CONFIG_HOME) return env.XDG_CONFIG_HOME;
  if (process.platform === "win32" && env.APPDATA) return env.APPDATA;
  return path.join(os.homedir(), ".config");
}

export function sessionFile(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(configDir(env), "signafaide", "session.json");
}

// --- the operating system's credential store -------------------------------------------------

/** How a credential store command runs: no shell, the secret only ever on stdin. Tests set one. */
export type StoreRunner = (cmd: string, args: string[], input?: string) => { ok: boolean; stdout: string };
const spawnRunner: StoreRunner = (cmd, args, input) => {
  const r = spawnSync(cmd, args, { input, encoding: "utf8", timeout: 15_000, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "ignore"] });
  return { ok: !r.error && r.status === 0, stdout: typeof r.stdout === "string" ? r.stdout : "" };
};
let storeRunner: StoreRunner = spawnRunner;
/** @internal Tests: run credential store commands with `r` (null: the real commands). */
export function setStoreRunner(r: StoreRunner | null): void {
  storeRunner = r ?? spawnRunner;
}

export interface CredentialStore {
  name: string;
  get(url: string): string | null;
  set(url: string, secret: string): boolean;
  delete(url: string): void;
}

const SERVICE = "signafaide";
/** A PowerShell single-quoted string. */
const psq = (s: string): string => `'${s.replace(/'/g, "''")}'`;
/** Windows Credential Manager through the Win32 API from PowerShell (no native module): the
 * script, the secret within it, goes on stdin. */
const WINCRED = `$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using FT = System.Runtime.InteropServices.ComTypes.FILETIME;
public static class SfaCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct C { public int Flags; public int Type; public string TargetName; public string Comment; public FT LastWritten; public int BlobSize; public IntPtr Blob; public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredWriteW(ref C c, int flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string target, int type, int flags, out IntPtr c);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredDeleteW(string target, int type, int flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static void Write(string t, string s) { byte[] b = System.Text.Encoding.Unicode.GetBytes(s); C c = new C(); c.Type = 1; c.TargetName = t; c.UserName = "signafaide"; c.Persist = 2; c.BlobSize = b.Length; c.Blob = Marshal.AllocHGlobal(b.Length); try { Marshal.Copy(b, 0, c.Blob, b.Length); if (!CredWriteW(ref c, 0)) throw new Exception("CredWrite " + Marshal.GetLastWin32Error()); } finally { Marshal.FreeHGlobal(c.Blob); } }
  public static string Read(string t) { IntPtr p; if (!CredReadW(t, 1, 0, out p)) return ""; try { C c = (C)Marshal.PtrToStructure(p, typeof(C)); return Marshal.PtrToStringUni(c.Blob, c.BlobSize / 2); } finally { CredFree(p); } }
  public static void Delete(string t) { CredDeleteW(t, 1, 0); }
}
"@
`;
const ps = (body: string): { ok: boolean; stdout: string } => storeRunner("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "-"], WINCRED + body + "\n");

/** The credential store of this machine, or null: none, or `SIGNAFAIDE_CREDENTIAL_STORE=file`. */
export function credentialStore(env: NodeJS.ProcessEnv = process.env, platform: string = process.platform): CredentialStore | null {
  if ((env.SIGNAFAIDE_CREDENTIAL_STORE ?? "").trim().toLowerCase() === "file") return null;
  const secretOf = (r: { ok: boolean; stdout: string }): string | null => {
    const v = r.stdout.trim();
    return r.ok && SESSION_RE.test(v) ? v : null;
  };
  if (platform === "darwin")
    return {
      name: "keychain",
      get: (url) => secretOf(storeRunner("security", ["find-generic-password", "-s", SERVICE, "-a", url, "-w"])),
      // `security -i` reads the command from stdin, so the secret is never in a process's arguments.
      set: (url, secret) => !/["\\\s]/.test(url) && SESSION_RE.test(secret) && storeRunner("security", ["-i"], `add-generic-password -U -s ${SERVICE} -a "${url}" -w ${secret}\n`).ok,
      delete: (url) => void storeRunner("security", ["delete-generic-password", "-s", SERVICE, "-a", url]),
    };
  if (platform === "win32")
    return {
      name: "credential-manager",
      get: (url) => secretOf(ps(`[Console]::Out.Write([SfaCred]::Read(${psq(`${SERVICE}:${url}`)}))`)),
      set: (url, secret) => ps(`[SfaCred]::Write(${psq(`${SERVICE}:${url}`)}, ${psq(secret)})`).ok,
      delete: (url) => void ps(`[SfaCred]::Delete(${psq(`${SERVICE}:${url}`)})`),
    };
  // The attributes python-keyring's Secret Service backend reads too (service, username).
  return {
    name: "secret-service",
    get: (url) => secretOf(storeRunner("secret-tool", ["lookup", "service", SERVICE, "username", url])),
    set: (url, secret) => storeRunner("secret-tool", ["store", "--label", `signafAIde session for ${url}`, "service", SERVICE, "username", url], secret).ok,
    delete: (url) => void storeRunner("secret-tool", ["clear", "service", SERVICE, "username", url]),
  };
}

// --- session.json ----------------------------------------------------------------------------

function allSessions(env: NodeJS.ProcessEnv): Record<string, Session> {
  try {
    const doc = JSON.parse(fs.readFileSync(sessionFile(env), "utf8"));
    return doc && typeof doc.sessions === "object" && doc.sessions ? doc.sessions : {};
  } catch {
    return {};
  }
}

function writeSessions(sessions: Record<string, Session>, env: NodeJS.ProcessEnv): void {
  const file = sessionFile(env);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  atomicWrite(file, JSON.stringify({ sessions }, null, 2) + "\n", { mode: 0o600 });
}

/** The held session for the witness at `url`, or null (none, another witness's, malformed or
 * expired, or its secret gone from the credential store). */
export function loadSession(url: string, env: NodeJS.ProcessEnv = process.env): Session | null {
  const s = allSessions(env)[url];
  if (!s || typeof s !== "object" || s.url !== url) return null;
  if (typeof s.expires_at === "string" && Date.parse(s.expires_at) <= Date.now()) return null;
  let secret: string | null = typeof s.session === "string" ? s.session : null;
  if (s.store && s.store !== "file") {
    const store = credentialStore(env);
    secret = store && store.name === s.store ? store.get(url) : null;
  }
  if (!secret || !SESSION_RE.test(secret)) return null;
  return { ...s, session: secret };
}

/** Keep `s`: its secret in the credential store when there is one, else in session.json (0600).
 * Returns where the secret went. */
export function saveSession(s: Session, env: NodeJS.ProcessEnv = process.env): string {
  const store = credentialStore(env);
  const meta: Session = { ...s };
  if (store && store.set(s.url, s.session)) {
    meta.store = store.name;
    delete (meta as Partial<Session>).session;
  } else meta.store = "file";
  writeSessions({ ...allSessions(env), [s.url]: meta }, env);
  return meta.store;
}

export function forgetSession(url: string, env: NodeJS.ProcessEnv = process.env): boolean {
  const all = allSessions(env);
  if (!(url in all)) return false;
  const was = all[url];
  if (was?.store && was.store !== "file") {
    const store = credentialStore(env);
    if (store && store.name === was.store) store.delete(url);
  }
  delete all[url];
  writeSessions(all, env);
  return true;
}

// --- the browser -----------------------------------------------------------------------------

export interface BrowserDeps {
  platform?: string;
  env?: NodeJS.ProcessEnv;
  tty?: boolean;
  spawn?: (cmd: string, args: string[], opts: Record<string, unknown>) => { on(e: string, f: () => void): unknown; unref(): void };
}

/** Open an http(s) URL in the person's browser when this machine has one; never fails. The URL
 * is passed as one argument to the opener, never through a shell: `open` on macOS, `xdg-open`
 * elsewhere, and on Windows `rundll32 url.dll,FileProtocolHandler` (not `cmd /c start`, whose
 * shell would read `&` and `^` in it). Only a URL that parses as http(s) is opened, written as
 * the URL parser writes it (so it never starts with `-`). */
export function openBrowser(url: string, d: BrowserDeps = {}): boolean {
  const env = d.env ?? process.env;
  if (env.SIGNAFAIDE_NO_BROWSER || env.CI || !(d.tty ?? process.stdout.isTTY)) return false;
  let href: string;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" && u.protocol !== "http:") return false;
    href = u.href;
  } catch {
    return false;
  }
  const platform = d.platform ?? process.platform;
  const [cmd, args] = platform === "darwin" ? ["open", [href]] : platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", href]] : ["xdg-open", [href]];
  try {
    const p = (d.spawn ?? spawn)(cmd as string, args as string[], { stdio: "ignore", detached: true, shell: false, windowsHide: true });
    p.on("error", () => undefined);
    p.unref();
    return true;
  } catch {
    return false;
  }
}

export interface LoginOptions {
  /** The witness (`personWitness`): never taken from the project's `.env`. */
  url: string;
  clientId: string;
  /** The console origin its sign-in page must be on (`--console`; default `consoleOrigin(url)`). */
  console?: string;
  /** Lines for the person. */
  out: (s: string) => void;
  /** How to wait between polls (tests pass a fast one). */
  sleep?: (ms: number) => Promise<void>;
  env?: NodeJS.ProcessEnv;
  browser?: (url: string) => boolean;
}

/** `signafaide login`: the device sign-in of §6. Says which witness it signs in to, checks that
 * the page the witness sends is on that witness's console (else stops: a relay could send the
 * real console's page and keep the session the person approves), prints the code and the page,
 * opens the browser when it can, polls until the person approves or refuses, and keeps the
 * session for that witness only. */
export async function login(o: LoginOptions): Promise<Session> {
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const env = o.env ?? process.env;
  const url = witnessUrl(o.url);
  const origin = consoleOrigin(url, o.console);
  const client = new Client(url, undefined, 10_000, o.clientId);
  const host = (os.hostname() || "this machine").slice(0, 100);
  o.out(`Witness     ${url}`);
  const code = await client.deviceCode(`signafaide-js/${VERSION}`, host);
  if (typeof code?.device_code !== "string" || typeof code.user_code !== "string" || typeof code.verification_uri !== "string") {
    throw new SignafaideError(`The service at ${url} answered POST /v1/device/code without a code; check the witness URL.`, { code: "bad_response" });
  }
  const page = onConsole(code.verification_uri, origin);
  const full = code.verification_uri_complete == null ? page : onConsole(code.verification_uri_complete, origin);
  if (!page || !full) {
    const shown = String(code.verification_uri_complete ?? code.verification_uri).slice(0, 200);
    throw new SignafaideError(
      `Not signed in: the witness at ${url} sent a sign-in page (${shown}) that is not on its console (${origin}). Nothing was opened or saved. If this witness's console is elsewhere, run signafaide login --url ${url} --console <console origin>.`,
      { code: "bad_response" },
    );
  }
  if (!/^[A-Z0-9-]{1,20}$/.test(code.user_code)) throw new SignafaideError(`The service at ${url} answered POST /v1/device/code with a malformed code; nothing was saved.`, { code: "bad_response" });
  o.out(`Sign in at  ${page}`);
  o.out(`Your code   ${code.user_code}`);
  o.out(`            The page shows this machine (${host}); approve it only if you started this sign-in, for ${url}.`);
  if ((o.browser ?? openBrowser)(full)) o.out("            Opened your browser.");
  let interval = Math.max(1, Number(code.interval) || 5) * 1000;
  const until = Date.now() + Math.max(1, Number(code.expires_in) || 600) * 1000;
  while (Date.now() < until) {
    await sleep(interval);
    const t = await client.deviceToken(code.device_code);
    if (t?.status === "pending") continue;
    if (t?.status === "slow_down") {
      interval += 5000;
      continue;
    }
    if (t?.status === "denied") throw new SignafaideError("The sign-in was refused on the console page; nothing was saved.", { code: "denied" });
    if (t?.status === "expired") throw new SignafaideError("The code expired before anyone approved it; run `signafaide login` again.", { code: "expired" });
    if (t?.status === "approved" && typeof t.session === "string" && SESSION_RE.test(t.session)) {
      const s: Session = { session: t.session, expires_at: t.expires_at ?? new Date(Date.now() + 12 * 3600_000).toISOString(), url, person: t.person, organisation: t.organisation };
      s.store = saveSession(s, env);
      if (s.store === "file") o.out(`            note: no credential store on this machine; the session is in ${sessionFile(env)} (readable by you only).`);
      return s;
    }
    throw new SignafaideError(`The service at ${url} answered the sign-in with an unexpected status; run \`signafaide login\` again.`, { code: "bad_response" });
  }
  throw new SignafaideError("The code expired before anyone approved it; run `signafaide login` again.", { code: "expired" });
}

/** `signafaide logout`: end the session at the witness it was made for and forget it here. */
export async function logout(url: string, clientId: string, env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  url = witnessUrl(url);
  const s = loadSession(url, env);
  if (s) {
    try {
      await new Client(s.url, s.session, 10_000, clientId).endSession();
    } catch (e) {
      // An ended or expired session is gone already; anything else is said, and it is forgotten here all the same.
      if ((e as SignafaideError).code !== "invalid_key") {
        forgetSession(url, env);
        throw e;
      }
    }
  }
  return forgetSession(url, env) || !!s;
}
