import { defineConfig } from "vitest/config";

// forks, not threads: tests chdir into temporary project folders.
export default defineConfig({ test: { pool: "forks", testTimeout: 30_000, include: ["test/**/*.test.ts"] } });
