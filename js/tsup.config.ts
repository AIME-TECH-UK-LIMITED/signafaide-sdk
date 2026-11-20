import { defineConfig } from "tsup";

// ESM keeps the @noble packages external; CJS bundles @noble/ed25519,
// which ships as ESM only, so `require("signafaide")` works on Node 18.
export default defineConfig([
  {
    entry: { index: "src/index.ts", core: "src/core.ts", otel: "src/otel.ts", cli: "src/bin.ts" },
    format: ["esm"],
    dts: { entry: { index: "src/index.ts", core: "src/core.ts", otel: "src/otel.ts" } },
    target: "node18",
    splitting: true,
  },
  {
    entry: { index: "src/index.ts", core: "src/core.ts", otel: "src/otel.ts" },
    format: ["cjs"],
    dts: true,
    target: "node18",
    noExternal: ["@noble/ed25519"],
  },
]);
