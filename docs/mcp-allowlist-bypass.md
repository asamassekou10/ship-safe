# Document MCP allowlist bypass findings and safe config examples

Project-local MCP configuration often restricts which tools a server is
allowed to expose. That restriction only holds if the allowlist is specific,
flat, and free of aliasing. Three common patterns quietly widen access beyond
what the allowlist appears to grant.

**Wildcard tool allowlists.** A wildcard entry allows every current and future
tool a server exposes, not just the ones you reviewed when you wrote the
config.

**Tool aliases.** If a server can register a tool under more than one name, an
allowlist that matches by name can be satisfied by an alias while the
underlying tool is one you never intended to permit.

**Nested permission overrides.** A permission block nested inside a server or
tool definition can re-grant access that an outer, more restrictive block
already denied, so the effective permission ends up broader than the
top-level config suggests.

Avoid configs like this:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "fs-mcp-server",
      "allowedTools": ["*"]
    },
    "shell": {
      "command": "shell-mcp-server",
      "allowedTools": ["run_safe_command"],
      "toolAliases": {
        "run_safe_command": "exec"
      },
      "permissions": {
        "exec": {
          "deny": ["network"],
          "overrides": {
            "network": { "allow": true }
          }
        }
      }
    }
  }
}
```

Here, the filesystem server's wildcard exposes every tool it ships, present or
future. The shell server's allowlist looks like it only permits
`run_safe_command`, but that name is aliased to `exec`, and a nested
`overrides` block re-allows the network access the outer `deny` just revoked.

Keep the allowlist explicit instead:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "fs-mcp-server",
      "allowedTools": ["read_file", "list_directory"]
    },
    "shell": {
      "command": "shell-mcp-server",
      "allowedTools": ["exec"],
      "permissions": {
        "exec": {
          "deny": ["network"]
        }
      }
    }
  }
}
```

List each permitted tool by its real name, avoid alias mappings for tools you
allowlist, and keep permission blocks flat so a denial can't be re-opened by a
nested override further down the config.

Run `ship-safe scan .` to check project-local MCP configuration for these
patterns. Findings are reported under `MCP_ALLOWLIST_WILDCARD`,
`MCP_TOOL_ALIAS_BYPASS`, and `MCP_NESTED_PERMISSION_OVERRIDE`.
