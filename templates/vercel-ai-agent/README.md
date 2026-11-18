# Payout agent: Vercel AI SDK

A Vercel AI SDK agent with two tools. `approve_payout` pays money, so it runs only when the rule in `signafaide.checks.json` allows it; `lookup_invoice` only reads, so it is recorded. Every call is signed and recorded on this machine in `.signafaide/`; nothing is sent and no account is made.

```sh
npm install
npm start                                   # the scripted model asks to pay 1,200: blocked
npm start -- Pay Ashgrove Catering Ltd 800 GBP
npm test                                    # pays 800, 1,200 blocked, then signafaide check --ci
```

`npm test` prints:

```text
ok   Pay Ashgrove Catering Ltd 800 GBP.
     paid 800 GBP to Ashgrove Catering Ltd
ok   Pay Ashgrove Catering Ltd 1200 GBP.
     SignafaideBlocked: approve_payout did not run: the rule on this machine blocked it ("Block approve_payout when amount is above 1,000"); signafAIde did not rule on it. To allow it, change the rule in signafaide.checks.json.
signafaide check --ci: passed. 1 risky tool: 1 protected, 0 allowed (TypeScript and JavaScript, 2 tools found).
```

## What is where

| file | what |
|---|---|
| `src/tools.ts` | the tools, wrapped with `wrapTool(...)`, and `declareTools(...)` with the full tool list |
| `src/agent.ts` | one `generateText` run with the tools, up to five steps |
| `src/scripted-model.ts` | a stand-in model (`MockLanguageModelV4` from `ai/test`): it calls `approve_payout` with the amount in the prompt |
| `signafaide.checks.json` | the rule, kept on this machine; `"mode": "enforce"` is On, `"watch"` is Calibrating (it only notes "Would have blocked") |
| `AGENTS.md`, `CLAUDE.md` | the note that tells coding agents to protect the next tool that pays, deletes, sends, runs commands or pushes code |

## A real model

Set `AI_MODEL` to a [Vercel AI Gateway](https://vercel.com/docs/ai-gateway) model id and `AI_GATEWAY_API_KEY`, then `npm start`. To use a provider package instead, pass its model to `runAgent` in `src/index.ts`.

## Then

- `npx signafaide status`: one line per tool, `npx signafaide verify`: the records' signatures and chain.
- `npx signafaide check approve_payout amount=1200`: a dry run, exit 1 when the rule would block.
- `npx signafaide protect`: at a terminal, to protect another tool or change the rule. To have signafAIde co-sign and timestamp the records, a person runs `npx signafaide init` (a free sandbox: no account, email or card).
