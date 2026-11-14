#!/usr/bin/env node
/** `signafaide-mcp`: the signafAIde MCP server over stdio (a separate package, so the SDK's own
 * install stays small). `signafaide agent setup` writes `npx -y signafaide-mcp@<version>`. */
import { serve } from "./mcp.js";

await serve();
