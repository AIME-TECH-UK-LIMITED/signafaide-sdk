# Review demo

A verification pack from a small demo agent (`claims-bot`) that ran against the hosted signafAIde service: 23 hash-only records of three tools, `lookup_claim`, `approve_payout` and `send_letter`.

- `agent.mjs`: the agent that wrote the records.
- `pack.json`: the verification pack, exported with `signafaide export -o pack.json`.
- `agent-keys.json`: the agent's public keys, exported with `signafaide keys export`.
- `head.json`: the agent's newest signed head, which shows that no record is missing from the end.

Check it on your own machine:

```sh
npx signafaide-verify@0.5.6 pack.json --agent-keys agent-keys.json --head head.json
```

The records are hash-only, so the content check reports "not checked": the inputs and outputs stay with the organisation that ran the agent.
