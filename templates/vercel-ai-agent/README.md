# Payout agent: Vercel AI SDK

A Vercel AI SDK agent with two tools. `approve_payout` pays money, so it is protected (`"protect": true` in `signafaide.checks.json`): the rule kept there blocks it above 1,000, and a call the rule lets through runs only when signafAIde rules allow it. `lookup_invoice` only reads, so it is recorded. Every call is signed and recorded on this machine in `.signafaide/`.

```sh
npm install
npm test                                    # pays 800, 1,200 blocked, then signafaide check --ci
npm start                                   # the scripted model asks to pay 1,200: blocked here
npx signafaide init                         # a person, once: a free sandbox that rules on calls
npm start -- Pay Ashgrove Catering Ltd 800 GBP
```

`npm test` runs in test mode (`src/test-mode.ts`, imported first by `src/smoke.ts`): records go to a temporary folder and nothing is sent, so the protected tool runs without a ruling, as under Vitest, Jest and `node --test`, and the rule on this machine still blocks 1,200. It prints:

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
| `src/smoke.ts`, `src/test-mode.ts` | the test, in test mode |
| `src/scripted-model.ts` | a stand-in model (`MockLanguageModelV4` from `ai/test`): it calls `approve_payout` with the amount in the prompt |
| `signafaide.checks.json` | `"protect": true` for `approve_payout` (`npx signafaide checks status` lists it as a protected tool) and the rule, kept on this machine; `"mode": "enforce"` is On, `"watch"` is Calibrating (it only notes "Would have blocked") |
| `AGENTS.md`, `CLAUDE.md` | the note that tells coding agents to protect the next tool that pays, deletes, sends, runs commands or pushes code |

## A real model

Set `AI_MODEL` to a [Vercel AI Gateway](https://vercel.com/docs/ai-gateway) model id and `AI_GATEWAY_API_KEY`, then `npm start`. To use a provider package instead, pass its model to `runAgent` in `src/index.ts`.

## Then

- `npx signafaide status`: one line per tool, `npx signafaide verify`: the records' signatures and chain.
- `npx signafaide check approve_payout amount=1200`: a dry run, exit 1 when the rule would block.
- `npx signafaide protect`: at a terminal, to protect another tool or change the rule.
- Outside the test, a protected call the rule here lets through asks signafAIde for a ruling. With no key or sandbox it stops with `no_key` ("protected tools stop until a person runs `npx signafaide protect` in this project"). A person runs `npx signafaide init` once (a free sandbox: no account, email or card), or sets `SIGNAFAIDE_API_KEY`; then calls are ruled on, co-signed and timestamped.
