import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "mail", version: "1.0.0" });

server.registerTool("send_email", { description: "Send an email.", inputSchema: { to: {}, body: {} } }, async ({ to, body }) => ({
  content: [{ type: "text", text: `sent to ${to}: ${body}` }],
}));
