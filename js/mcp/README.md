# signafaide-mcp

The signafAIde MCP server for coding agents, over stdio. It is a separate package so that
`npm install signafaide` stays small: the SDK itself never needs the MCP SDK or zod.

`npx signafaide agent setup` installs it for you in each coding agent's configuration, pinned to
the SDK's version:

```json
{"command": "npx", "args": ["-y", "signafaide-mcp@0.3.2"]}
```

Tools: `signafaide_setup` (previews the install command and code edit, changes nothing),
`signafaide_verify`, `signafaide_status`, `signafaide_explain_error`, and `signafaide_init`
(creates the external sandbox; call it only after the user has agreed, with
`confirm_user_agreed: true` and `user_words`, what the user wrote; without both it creates nothing).

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
