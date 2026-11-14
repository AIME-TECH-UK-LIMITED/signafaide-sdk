# signafaide-mcp

The signafAIde MCP server for coding agents, over stdio. It is a separate package so that
`npm install signafaide` stays small: the SDK itself never needs the MCP SDK or zod.

`npx signafaide agent setup` installs it for you in each coding agent's configuration, pinned to
the SDK's version:

```json
{"command": "npx", "args": ["-y", "signafaide-mcp@0.2.1"]}
```

Tools: `signafaide_setup` (previews the install command and code edit, changes nothing),
`signafaide_verify`, `signafaide_status`, `signafaide_explain_error`, and `signafaide_init`
(creates the external sandbox; call it only after the user has agreed, with
`confirm_user_agreed: true` and `user_words`, what the user wrote; without both it creates nothing).

Apache-2.0. Source: the `js/` folder of the signafAIde SDK repository.
