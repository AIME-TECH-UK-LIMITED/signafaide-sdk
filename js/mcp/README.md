# signafaide-mcp

The signafAIde MCP server for coding agents, over stdio (Node.js 20 or later). It is a separate
package so that `npm install signafaide` stays small: the SDK itself never needs the MCP SDK or zod.

To protect an agent's tools, the person runs `npx signafaide protect` in a terminal (Python:
`uv run signafaide protect`): it finds the tools, asks what to block, shows the code change and
asks before writing it, and saves the rules. Then `npx signafaide check <tool> field=value` (a dry
run), `npx signafaide pull` (the console's rules), `npx signafaide prove <tool>` (the auditor link)
and `npx signafaide login` (a person's sign-in for saving rules). This server helps a coding agent
with the rest: it previews the setup, explains errors, verifies records and shows status.

`npx signafaide agent setup` installs it for you in each coding agent's configuration, pinned to
the SDK's version:

```json
{"command": "npx", "args": ["-y", "signafaide-mcp@0.5.1"]}
```

## Tools

| tool | what it does |
|---|---|
| `signafaide_setup` | for work inside a project: reads the project and previews the install command and the exact code edit. Changes, creates and sends nothing |
| `signafaide_quickstart` | a reference snippet for a language and framework you name. Reads nothing in the project |
| `signafaide_init` | creates the external sandbox and returns the claim link. Call it only after the user has agreed, with `confirm_user_agreed: true` and `user_words`, what the user wrote; without both it creates nothing |
| `signafaide_verify` | checks every record and returns one line per check, then PASS or FAIL. With an API key it ships waiting records first |
| `signafaide_status` | the key, the service, each agent chain, the outbox, the quota and the claim step. Read-only; contacts the service only when a key exists |
| `signafaide_records` | lists and searches the records on this machine by agent, time or record hash. Read-only, metadata only: inputs and outputs stay in the local files |
| `signafaide_flush` | sends the waiting records now, like `signafaide flush`. Without an API key it sends nothing; it never creates a sandbox |
| `signafaide_explain_error` | what an error code means and how to fix it |
| `signafaide_explain_ruling` | explains a tool call's ruling from a record hash (local records, or a verification pack): the checks, the ruling and its basis, matched rules, rule set version, fields not disclosed, how to allow the call. Read-only; never prints a disclosed value |
| `signafaide_show_rules` | the rules held: rule set version, mode, default, each rule on one line, what happens to each protected tool if signafAIde can't be reached (Stop or Let it run) and the fields it discloses. Read-only |
| `signafaide_claim_link` | the sandbox claim link, for when the user only needs the link |

Nothing is sent until a person opts in with `signafaide init`, `signafaide_init` or `SIGNAFAIDE_API_KEY`.

## Recording everything an agent can call

The setup this server previews has two parts beyond wrapping tools. The MCP servers the
application's own agent uses are started through the gateway of the `signafaide` package,
`npx -y signafaide gateway --agent <name> -- <the server's command>`, which records every tool
call that passes through it and forwards none it cannot record. And the program gives the full
list of the tools it hands the agent, with `declareTools([...])` (TypeScript) or
`signafaide.declare_tools([...])` (Python), so `signafaide_verify` can say which of the agent's
tools are recorded.

The gateway records every call that goes through it; a call the application makes around it is
still not recorded, so the deployment has to make the gateway the only route to those tools. A
declaration is the program's own statement of its tools, not proof that the list is complete. A
tool list is as fresh as its last declaration: a source that stops leaves the list at its clean
exit, or within 24 hours after a crash.

Apache-2.0. Source: the `js/` folder of the signafAIde SDK repository.
