#!/usr/bin/env node
import { EXIT_WHEN_DONE, main } from "./cli.js";

main().then((code) => {
  process.exitCode = code;
  if (EXIT_WHEN_DONE.has(process.argv[2])) process.exit(code);
});
