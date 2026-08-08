# Codex integration

Ship Safe can be used by Codex through its MCP client configuration. This gives Codex access to Ship Safe's security tools while it works in a repository.

## Configure the MCP server

Add Ship Safe as a stdio MCP server in Codex's `config.toml`:

```toml
[mcp_servers.ship_safe]
command = "npx"
args = ["ship-safe", "mcp"]
```

For other MCP clients that use JSON configuration, the equivalent entry is:

```json
{
  "mcpServers": {
    "ship-safe": {
      "command": "npx",
      "args": ["ship-safe", "mcp"]
    }
  }
}
```

Restart Codex or start a new session after changing the MCP configuration. Once connected, Codex can call tools such as:

- `scan_repo` for a full multi-agent repository scan
- `scan_secrets` for credentials and API keys
- `analyze_file` for a focused file review
- `get_findings` for a saved report
- `get_checklist` for release-readiness checks
- `ship_safe_status` to confirm that the MCP connection is available in the current session

## What this integration does

The MCP server lets Codex request security checks as part of a task. It is useful for reviewing a repository before changes, checking a diff after changes, and validating a release candidate.

## What it does not claim

MCP access is not an automatic pre-tool or post-tool enforcement layer. It does not intercept every Codex action, and Ship Safe should not display a `Protected by Ship Safe` badge solely because the MCP server is configured.

That badge requires a separately verified lifecycle integration that can prove which actions were checked and whether a check blocked or allowed them. Until that exists, describe the connection as **Ship Safe available in Codex** rather than as continuous protection.

The `ship_safe_status` tool follows that distinction: it reports `state: available` and `protected: false`. A Codex plugin or future lifecycle API can build a richer UI around this status, but MCP alone cannot inject a persistent footer badge into Codex.

## Recommended workflow

Ask Codex to scan the repository before making security-sensitive changes, review modified files after implementation, and run a final scan before commit or release. Keep the scan scope limited to the authorized repository and avoid passing secrets through tool arguments.
