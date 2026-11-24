# CI: protect checked on every pull request

`signafaide check --ci` fails a build when the code has an agent tool that pays, deletes, sends, runs commands, pushes code or edits secrets or config, and that tool is not protected. It needs no account and no API key, and it sends nothing: it reads the code and `signafaide.checks.json`.

## Run it

```
npx signafaide check --ci
```

Python:

```
pipx run signafaide check --ci
```

Each risky tool that is not protected is one line: where it is, why it looks risky, and the line that protects it.

```
src/git.ts:4: gitPush pushes code; not protected. Fix: wrapTool(<its tool(...) definition>, { name: "gitPush", agent: "payout-bot", strict: true }) (or: npx signafaide protect --tool gitPush)
src/mcp-server.ts:5: send_email sends messages; not protected. Fix: run the server as npx signafaide gateway --strict-tools send_email -- <server command>, and set "send_email": { "protect": true } in signafaide.checks.json
src/tools.ts:25: approve_payout pays money; not protected. Fix: approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }) (or: npx signafaide protect --tool approve_payout)
src/tools.ts:29: run_migration runs commands; allowed (checks file): runs only the migration files kept in this repository; reviewed 18 Nov 2026
signafaide check --ci: failed. 3 risky tools not protected (of 6; 2 protected, 1 allowed; TypeScript and JavaScript, 7 tools found).
A reviewed exception: add { "tool": "<name>", "reason": "<why it is safe>" } to "ci": { "allow": [...] } in signafaide.checks.json.
```

Exit codes: 1 when a risky tool is not protected, 0 when none is, 2 when the check cannot run (a git base missing from the clone, a checks file that is not valid).

| Option | What it does |
| --- | --- |
| `--diff <base>` | Only the tools added or changed since this git base, for pull requests. A tool counts as changed when a line of its code, or its entry in the checks file, changed since the merge base. |
| `--allow <tool>` | A reviewed exception for this run. Repeat it for more tools. |
| `--dir <folder>` | The folder to check (default: the current one). |
| `--json` | The result as JSON (`"format": "signafaide-ci/1"`). |

The npm CLI checks TypeScript and JavaScript; the Python CLI checks Python. Each says when the repository has files of the other language. The GitHub Action runs both.

## What counts as protected

- The code wraps the tool with `protect(...)`, `@signafaide.protect`, or `wrapTool(..., { strict: true })` for a framework tool.
- Or the tool is recorded (`record(...)`, `@signafaide.record`, or an MCP server run through `signafaide gateway`) and `signafaide.checks.json` sets `"protect": true` for it, or keeps a block rule on this machine that names it with the tool in `"mode": "enforce"` (what `protect --local` writes: no account, signafAIde does not rule on it). A rule that is Calibrating (`"mode": "watch"`) blocks nothing, so it does not count.

`npx signafaide protect --tool <tool>` (or `signafaide protect --tool <tool>` in Python) writes the change.

## Reviewed exceptions

A risky tool that should run without protection is listed in the checks file with the reason, so the reason is reviewed with the code:

```json
"ci": { "allow": [{ "tool": "run_migration", "reason": "runs only the migration files kept in this repository" }] }
```

Each tool is listed once; the reason is 1 to 1,000 characters. `ci` changes nothing at run time.

## GitHub Action

```yaml
name: signafaide
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: AIME-TECH-UK-LIMITED/signafaide-action@b4f8e2261e9123cc5eeadf1a9a248c6337e2604b # v0.5.6
```

On a pull request the action checks the tools the pull request adds or changes; on a push, every tool. It adds an error note on the line of each unprotected tool, writes a table with the fix to the job summary, and fails the job when there is one. Pin it by its full commit SHA.

Inputs: `version`, `working-directory`, `base`, `allow`, `python` (`auto`, `true`, `false`), and, optional and off by default, `record-runs` (`start`, `finish`) with `api-key`, `agent`, `fail-on-verification-failure` and `upload-pack`.

## Record and verify agent runs in the job (optional)

When an agent runs in CI, the same action can record its tool calls and check them at the end of the job: `record-runs: start` before the agent step (with `api-key` from a secret; without one it makes a sandbox: test records, kept 30 days, no account), and `record-runs: finish` after it. `finish` sends what is waiting, exports a verification pack of the job's records, verifies it with the open verifier, writes the result and the record count to the job summary, and uploads the pack as the artifact `signafaide-pack`. Each record is co-signed by the witness, outside the runner, so the pack can be checked later with the service keys published at `/.well-known/signafaide-keys.json`.

## Limits

- The check reads the code; it does not run it. It finds the shapes `protect` finds: a tools object or list, exported functions of files named like tools, Vercel AI SDK, OpenAI Agents and LangChain tools, MCP server tools, methods of a class named like tools, and Python functions with a tool decorator or named in a module-level `tools` list. A tool built another way is not seen.
- Whether a tool looks risky comes from the words of its name. A risky tool with a plain name is not listed.
- With `--diff`, tools the pull request does not touch are not listed, even when they are not protected.
- Recording covers what the recorded agent reports through the SDK or the gateway in that job; other steps of the workflow are not covered.
