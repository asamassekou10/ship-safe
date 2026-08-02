# Handle MCP environment variables safely

Project-local MCP configuration is part of the repository's trust boundary.
Passing a credential-bearing environment variable there grants the configured
server process access to that credential whenever the project is opened or the
server starts.

Avoid committed values and passthrough entries such as this:

```json
{
  "mcpServers": {
    "database": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "DATABASE_URL": "postgres://user:password@example.com/app"
      }
    }
  }
}
```

Keep credential provisioning outside the project-local configuration instead:

```json
{
  "mcpServers": {
    "database": {
      "command": "database-mcp-launcher"
    }
  }
}
```

Configure the launcher or process supervisor outside the repository to obtain a
short-lived, narrowly scoped credential from the operating system's credential
store or your secrets manager. Do not forward a developer's general-purpose
database URL or token when a server-specific credential will work.

Run `ship-safe scan .` to check project-local MCP configuration. Findings report
the environment variable name, such as `DATABASE_URL`, without printing its
value.
