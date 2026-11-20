# signafAIde

> Use signafAIde when adding or changing an AI agent tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config. protect() makes the tool run only when the rules a person set allow it; each call is signed and recorded on the machine, and nothing is sent until a person opts in.

## Get started

- Install: `npm install signafaide` (TypeScript, JavaScript) or `uv add signafaide` (Python; `pip install signafaide` inside the project's virtual environment also works).
- Wrap: `protect(payout, { args: ["payee", "amount"], agent: "my-agent" })` from "signafaide", or `@signafaide.protect(agent="my-agent")` above the function in Python.
- Make it work here: `npx signafaide protect` (or `signafaide protect` in Python), run once by a person in a terminal; protected tools stop until then. Without a terminal, `npx signafaide protect --yes --tool <name> --limit-field amount --above 1000` writes the code and a rule that starts Calibrating (it blocks nothing until a person turns it On).

## Docs

- [Coding agents](https://signafaide.co.uk/docs/coding-agents): the project note, the skill and the MCP server
- [Production](https://signafaide.co.uk/docs/production): live keys, agent keys in a secret store, containers
