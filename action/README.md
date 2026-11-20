# signafAIde check (GitHub Action)

Fails a pull request that adds an agent tool that pays, deletes, sends, runs commands, pushes code or edits secrets or config without signafAIde `protect`. No account, no API key, nothing sent: it reads the code and `signafaide.checks.json`.

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
      - uses: AIME-TECH-UK-LIMITED/signafaide-sdk/action@f1978456b60e985b6c46e0e259eb549a71047135 # 0.5.2
```

Pin the action by its full commit SHA, as above, not by a branch or tag.

## What it does

On a pull request it runs

```
npx signafaide@0.5.4 check --ci --diff <the pull request's base commit>
```

and, when the repository has Python files, the same check with the Python package (`pipx run signafaide check --ci`). On a push it checks every tool. For each risky tool that is not protected it prints one line, adds an error note on that line of the pull request, and writes a table to the job summary:

```
src/tools.ts:25: approve_payout pays money; not protected. Fix: approve_payout: protect(approve_payout, { args: ["payee", "amount", "currency"], agent: "payout-bot" }) (or: npx signafaide protect --tool approve_payout)
agent/tools.py:32: git_push pushes code; not protected. Fix: add @signafaide.protect(agent="payout-bot") right above def git_push (under the framework's decorator) (or: signafaide protect --tool git_push)
```

The job fails when there is one (exit 1), passes when there is none (exit 0), and fails with the reason when the check cannot run (exit 2: a base commit missing from the clone, a checks file that is not valid).

A tool counts as protected when its code wraps it with `protect(...)` (`@signafaide.protect` in Python, `wrapTool(..., { strict: true })` for a framework tool), or when it is recorded (`record(...)`, or an MCP server run through `signafaide gateway`) and `signafaide.checks.json` sets `"protect": true` for it or keeps a block rule on this machine for it in enforce mode (what `protect --local` writes).

## Reviewed exceptions

A risky tool that is meant to run without protection goes in the checks file, with the reason, so the reason is reviewed with the code:

```json
{
  "format": "signafaide-checks/2",
  "checks": { "secret": true, "address": true, "changed_tool": true, "fingerprint": true, "hidden_instruction": true },
  "tools": {},
  "addresses": { "hosts": [], "cidrs": [], "resolve": false },
  "rules": null,
  "ci": { "allow": [{ "tool": "run_migration", "reason": "runs only the migration files kept in this repository" }] }
}
```

The `allow` input does the same for one workflow, without a reason (`allow: run_migration, send_digest`).

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `version` | `0.5.4` | The signafaide version to run (npm and PyPI). |
| `working-directory` | `.` | The folder to check, where `signafaide.checks.json` is. |
| `base` | the pull request's base commit | Compare with this git base; empty checks every tool. |
| `allow` | | Reviewed exceptions, tool names separated by commas or new lines. |
| `python` | `auto` | Check Python too: `auto` when the repository has Python files, `true`, `false`. |
| `check` | `true` | Run the check. `false` on a later step that only finishes recording agent runs. |
| `record-runs` | `false` | Optional: `start` or `finish` (below). |
| `api-key` | | With `record-runs`: the signafAIde API key, from a secret. |
| `agent` | | With `record-runs: finish`: export only this agent's records. |
| `fail-on-verification-failure` | `true` | With `record-runs: finish`: fail the job when the pack does not verify. |
| `upload-pack` | `true` | With `record-runs: finish`: upload the pack folder as the artifact `signafaide-pack`. |

`--diff` needs the base commit in the clone: check out with `fetch-depth: 0`.

## Optional: record and verify agent runs in the job

When a coding agent or an agent job runs in CI, the same action can record its tool calls and check them at the end of the job. Off by default.

```yaml
      - uses: AIME-TECH-UK-LIMITED/signafaide-sdk/action@f1978456b60e985b6c46e0e259eb549a71047135 # 0.5.2
        with:
          check: false
          record-runs: start
          api-key: ${{ secrets.SIGNAFAIDE_API_KEY }}
      - run: npm run agent   # your agent, recording with the signafaide SDK or through signafaide gateway
      - uses: AIME-TECH-UK-LIMITED/signafaide-sdk/action@f1978456b60e985b6c46e0e259eb549a71047135 # 0.5.2
        if: always()
        with:
          check: false
          record-runs: finish
          agent: release-bot
```

`start` gives the key to the job's later steps (masked in the log) and notes the time the job's records start from. Without a key it makes a sandbox (`signafaide init`: test records, kept 30 days, no account; it also writes `.env`, `.gitignore` and a checks file in the working directory when they are missing). `finish` sends what is waiting, exports a verification pack of the records since `start`, verifies it with the open verifier, writes the result line and the record count to the job summary, and uploads the pack, the agent keys and the verifier's report as the artifact `signafaide-pack`. Each record is co-signed by the witness, outside the runner, so a relying party can check the pack later with the service keys published at `/.well-known/signafaide-keys.json`, not with anything from the runner.

## Limits

- The check reads the code; it does not run it. It finds the common shapes `signafaide protect` finds: a tools object or list, exported functions of files named like tools, Vercel AI SDK, OpenAI Agents and LangChain tools, MCP server tools, methods of a class named like tools, and in Python functions with a tool decorator or named in a module-level `tools` list. A tool built another way is not seen.
- Whether a tool looks risky comes from the words of its name (`approve_payout`, `git_push`, `update_secret`). A risky tool with a plain name (`process`) is not listed; a tool listed that is not risky goes in `ci.allow` with the reason.
- With `--diff`, a tool counts as changed when a line of its code, or its entry in the checks file, changed since the merge base. Tools the pull request does not touch are not listed, even when they are not protected; a push to the default branch checks every tool.
- One checks file, in `working-directory`. For a repository with several agents, add one step per folder.
- Recording covers what the recorded agent reports through the SDK or the gateway in that job. Other steps of the workflow are not covered, and a record that was never written cannot be shown; declared-tool coverage shows which declared tools were recorded.
- Tested on Linux runners. macOS and Windows runners are not tested yet.
