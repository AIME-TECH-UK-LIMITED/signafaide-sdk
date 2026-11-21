import { defineConfig } from "tsup";

// The standalone verifier package (`signafaide-verify`, in ./verify): the SDK's verifier and its
// @noble crypto bundled into one file, so an auditor installs nothing else. It sends no SDK client
// header or SDK User-Agent (__SIGNAFAIDE_VERIFY_BUNDLE__).
//
// Two builds. verify/dist: the release, where SIGNAFAIDE_VERIFY_KEYS_URL does not exist.
// verify/dist-test (never packed): the conformance tests' build, where that variable replaces the
// address the pinned keys are checked against, as the Rust feature `test-keys-url` does.
const base = {
  entry: { cli: "src/verify-bin.ts" },
  format: ["esm" as const],
  target: "node20",
  noExternal: [/.*/],
  splitting: false,
  clean: true,
  // Folds the defines below, so a branch they turn off is not in the file at all.
  esbuildOptions(options: { minifySyntax?: boolean }) {
    options.minifySyntax = true;
  },
};
export default defineConfig([
  {
    ...base,
    outDir: "verify/dist",
    // verify/dist/metafile-esm.json: which packages were bundled in, for THIRD-PARTY-NOTICES.md (prepack).
    metafile: true,
    define: { __SIGNAFAIDE_VERIFY_BUNDLE__: "true", __SIGNAFAIDE_VERIFY_TEST_KEYS_URL__: "false" },
  },
  {
    ...base,
    outDir: "verify/dist-test",
    define: { __SIGNAFAIDE_VERIFY_BUNDLE__: "true", __SIGNAFAIDE_VERIFY_TEST_KEYS_URL__: "true" },
  },
]);
