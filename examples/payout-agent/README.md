# Payout agent

The quickstart's payout agent, in TypeScript and in Python: four tools (`approve_payout`, `delete_payee`, `send_receipt`, `lookup_invoice`), every call recorded, `approve_payout` protected. The code is what `signafaide protect` writes, with the agent name `payout-bot` in every call.

It runs against a free sandbox: no account, test data only, deleted after 30 days unless you keep it. Inside this repository it uses the SDK next to it; copied elsewhere, depend on the released `signafaide` instead (the files say where).

## TypeScript

```sh
cd typescript
npm install
npx signafaide protect      # tick approve_payout, "Payouts above an amount", 1000, On; yes to the sandbox
npm start
```

`protect` finds the tools already wrapped, asks what to block, makes the sandbox and saves the rule. `npm start` pays 800 and tries 1,200:

```text
paid 800 GBP to Ashgrove Catering Ltd
approve_payout did not run: signafAIde blocked it under "Block approve_payout when amount is above 1,000" (rule set version 1). To allow such calls, change the rule in the console. https://...
```

## Python

```sh
cd python
uv sync
uv run signafaide protect   # the same answers
uv run python run.py
```

## Then

```sh
npx signafaide check approve_payout amount=1200 currency=GBP   # a dry run: exit 1, it would block
npx signafaide status                                            # one line per tool
npx signafaide prove approve_payout                              # the auditor link (Python: uv run signafaide ...)
```

`prove` asks for a 30-day link, or the longest your plan allows (a sandbox: 7 days), and sends the agent's public keys with it, so the auditor's browser check is complete. `--days 3` asks for exactly 3 days. To keep the sandbox and its records, open the claim link `protect` printed.
