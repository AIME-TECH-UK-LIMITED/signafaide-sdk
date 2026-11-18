<!-- signafaide:start -->
## signafAIde

This project uses signafAIde to check an AI agent's tool calls before they run. Use it when adding or changing a tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config: wrap that tool with protect(), and it runs only when the rules a person set allow it, with each call signed and recorded. Records stay on this machine in .signafaide/; nothing is sent and nothing is created online until a person opts in.

- Install: `npm install signafaide` (TypeScript, JavaScript) or `uv add signafaide` (Python; `pip install signafaide` inside the project's virtual environment also works).
- Wrap: `protect(payout, { args: ["payee", "amount"], agent: "my-agent" })` from "signafaide", or `@signafaide.protect(agent="my-agent")` above the function in Python.
- Make it work here: `npx signafaide protect` (or `signafaide protect` in Python), run once by a person in a terminal; protected tools stop until then. Without a terminal, `npx signafaide protect --yes --tool <name> --limit-field amount --above 1000` writes the code and a rule that starts Calibrating (it blocks nothing until a person turns it On).
<!-- signafaide:end -->
