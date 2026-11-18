#!/usr/bin/env node
/**
 * A fake MCP server over stdio for the gateway tests: newline-delimited JSON-RPC, no MCP library.
 *
 * Environment:
 * - FAKE_TOOLS: JSON list of tool names (default: echo, fail, rpc_error, crash, slow, hang, ask)
 * - FAKE_PAGE: tools per `tools/list` page (default: all in one page)
 * - FAKE_LOG: a file that gets one line per message received, exactly as it arrived
 * - FAKE_INSTRUCTIONS: the `instructions` of the `initialize` result (none by default)
 *
 * Tools: `echo` answers with its arguments; `fail` answers with an `isError` result; `rpc_error`
 * with a JSON-RPC error; `crash` exits with code 3 without answering; `slow` answers after
 * `arguments.ms`; `hang` never answers; `ask` first sends the client a request of its own, with
 * the same id as the call, and answers the call with what the client said.
 * Methods for the tests: `test/raw` writes `params.line` to stdout as it is; `test/exit` exits
 * with `params.code`; `test/kill` ends the server with `params.signal`; `test/change_tools` replaces the tool list and sends
 * `notifications/tools/list_changed`; `test/change_defs` sets what `tools/list` shows of some
 * tools (`params.defs`: name -> members that replace the defaults). The tool `rot13` answers with
 * `arguments.text` in rot13.
 */
import * as fs from "node:fs";

let tools = JSON.parse(process.env.FAKE_TOOLS ?? '["echo","fail","rpc_error","crash","slow","hang","ask"]');
const page = Number(process.env.FAKE_PAGE) || 0;
const log = process.env.FAKE_LOG;
const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
/** Requests this server made to the client, by id: what to do with the answer. */
const asked = new Map();
/** What `tools/list` shows of a tool, beyond its name, when a test set it. */
let defs = {};
const rot13 = (t) => t.replace(/[a-z]/gi, (c) => String.fromCharCode(((c.toLowerCase().charCodeAt(0) - 97 + 13) % 26) + (c === c.toLowerCase() ? 97 : 65)));

process.stderr.write("fake-mcp-server: started\n");
process.on("SIGTERM", () => {
  process.stderr.write("fake-mcp-server: SIGTERM\n");
  process.exit(143);
});

function call(msg) {
  const { name, arguments: args = {} } = msg.params ?? {};
  const text = (t) => ({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: t }] } });
  if (name === "fail") return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "no such file" }], isError: true } });
  if (name === "rpc_error") return send({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: "bad arguments" } });
  if (name === "crash") return process.exit(3);
  if (name === "rot13") return send(text(rot13(String(args.text ?? ""))));
  if (name === "hang") return undefined;
  if (name === "slow") return void setTimeout(() => send(text(`slow ${args.tag}`)), args.ms ?? 50);
  if (name === "ask") {
    // A request of the server's own, with the id the client used for this call.
    asked.set(JSON.stringify(msg.id), (answer) => send(text(`client said ${JSON.stringify(answer.result)}`)));
    return send({ jsonrpc: "2.0", id: msg.id, method: "sampling/createMessage", params: { messages: [] } });
  }
  if (!tools.includes(name)) return send({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: `Unknown tool: ${name}` } });
  return send(text(JSON.stringify(args)));
}

function handle(msg) {
  if (typeof msg.method !== "string") {
    // An answer to a request this server made.
    const then = asked.get(JSON.stringify(msg.id));
    asked.delete(JSON.stringify(msg.id));
    return then?.(msg);
  }
  switch (msg.method) {
    case "initialize":
      return send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: true } }, serverInfo: { name: "fake", version: "1" }, ...(process.env.FAKE_INSTRUCTIONS ? { instructions: process.env.FAKE_INSTRUCTIONS } : {}) } });
    case "ping":
      return send({ jsonrpc: "2.0", id: msg.id, result: {} });
    case "tools/list": {
      const start = Number(msg.params?.cursor ?? 0);
      const end = page ? Math.min(tools.length, start + page) : tools.length;
      const result = { tools: tools.slice(start, end).map((name) => ({ name, description: name, inputSchema: { type: "object" }, ...(defs[name] ?? {}) })) };
      if (end < tools.length) result.nextCursor = String(end);
      return send({ jsonrpc: "2.0", id: msg.id, result });
    }
    case "tools/call":
      return call(msg);
    case "test/raw":
      return void process.stdout.write(msg.params.line + "\n");
    case "test/exit":
      return process.exit(msg.params.code);
    case "test/kill":
      return void process.kill(process.pid, msg.params.signal);
    case "test/change_defs":
      defs = msg.params.defs;
      return send({ jsonrpc: "2.0", id: msg.id, result: {} });
    case "test/change_tools":
      tools = msg.params.tools;
      return send({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
    default:
      if (msg.id !== undefined) send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } });
  }
  return undefined;
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  for (let i = buf.indexOf("\n"); i !== -1; i = buf.indexOf("\n")) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (log) fs.appendFileSync(log, line + "\n");
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (Array.isArray(msg)) {
      // A batch: one array of answers, as JSON-RPC 2.0 says.
      const answers = [];
      const real = process.stdout.write.bind(process.stdout);
      process.stdout.write = (s) => (answers.push(JSON.parse(s)), true);
      for (const m of msg) handle(m);
      process.stdout.write = real;
      if (answers.length) real(JSON.stringify(answers) + "\n");
    } else handle(msg);
  }
});
process.stdin.on("end", () => process.exit(0));
