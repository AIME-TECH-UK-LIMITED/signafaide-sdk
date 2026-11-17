/** Shared by the tool-call checks tests: the gateway in this process with the fake MCP server as its
 * child, spoken to over streams, one JSON-RPC message (or batch) at a time. */
import * as path from "node:path";
import { PassThrough } from "node:stream";
import { runGateway, type GatewayOptions } from "../src/gateway.js";
import type { Recorder } from "../src/runtime.js";

const SERVER = path.resolve(__dirname, "fake-mcp-server.mjs");

export interface GatewayClient {
  /** Write one message or batch. */
  send(m: unknown): void;
  /** The first line (parsed) that `match` accepts. */
  answer(match: (m: any) => boolean): Promise<any>;
  /** One `tools/call` as its own message. */
  call(id: number | string, name: string, args: unknown): void;
  /** A batch of `tools/call` messages, one per `[id, name, args]`. */
  batch(calls: [number | string, string, unknown][]): void;
  /** The answer to request `id`. */
  reply(id: number | string): Promise<any>;
  close(): Promise<unknown>;
}

export async function startGateway(recorder: Recorder, opts: Partial<GatewayOptions> = {}): Promise<GatewayClient> {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const lines: any[] = [];
  let buf = "";
  stdout.on("data", (d) => {
    buf += d;
    const parts = buf.split("\n");
    buf = parts.pop()!;
    for (const p of parts) lines.push(JSON.parse(p));
  });
  const done = runGateway({ command: process.execPath, args: [SERVER], recorder, stdin, stdout, stderr: new PassThrough(), forwardSignals: false, env: { PATH: process.env.PATH ?? "" }, ...opts });
  const client: GatewayClient = {
    send: (m) => void stdin.write(JSON.stringify(m) + "\n"),
    async answer(match) {
      for (let i = 0; i < 400; i++) {
        const m = lines.find(match);
        if (m) return m;
        await new Promise((r) => setTimeout(r, 25));
      }
      throw new Error(`no such line; got ${JSON.stringify(lines)}`);
    },
    call: (id, name, args) => client.send({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }),
    batch: (calls) => client.send(calls.map(([id, name, args]) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }))),
    reply: (id) => client.answer((m) => !Array.isArray(m) && m.id === id),
    close: async () => (stdin.end(), done),
  };
  // initialize and tools/list, as a client does before it calls (the tool fingerprints come from these).
  client.send({ jsonrpc: "2.0", id: "init", method: "initialize", params: {} });
  await client.reply("init");
  client.send({ jsonrpc: "2.0", id: "list", method: "tools/list" });
  await client.reply("list");
  return client;
}
