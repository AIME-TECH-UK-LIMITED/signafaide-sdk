import { defineConfig } from "tsup";

// The MCP server package (`signafaide-mcp`, in ./mcp): the SDK code it uses is bundled in, so it
// depends only on the MCP SDK and zod (and the SDK's own small crypto dependencies).
export default defineConfig({
  entry: { cli: "src/mcp-bin.ts", index: "src/mcp.ts" },
  outDir: "mcp/dist",
  format: ["esm"],
  dts: { entry: { index: "src/mcp.ts" } },
  target: "node20",
  external: ["@modelcontextprotocol/server", "zod", "@noble/curves", "@noble/ed25519", "@noble/hashes"],
  clean: true,
});
