# Cursor integration

Ship Safe can be used by Cursor through Cursor's MCP client configuration. This gives Cursor's agent access to Ship Safe's security tools while it works in a repository.

## Supported surfaces

| Surface | Status |
| --- | --- |
| Cursor IDE (desktop app, local `stdio` MCP server) | Documented below. |
| Cursor CLI | Not verified. Cursor documents shared MCP configuration, but this setup has not been tested with the CLI. |
| Cursor cloud / background agents | Not verified. A local `stdio` server on your machine is not available to cloud agents. |

Do not treat the unverified surfaces as supported until they appear in [Tested versions](#tested-versions).

## Configure the MCP server

Cursor reads MCP servers from two locations:

- **Project:** `.cursor/mcp.json` in the repository root. Applies only to that project.
- **User:** `~/.cursor/mcp.json` in your home directory. Applies to every project you open.

Prefer the project configuration and deliberately select the repository you want to scan. Relative tool paths resolve from the server's working directory (the MCP workspace). Current read tools are not uniformly confined to that directory; the workspace checks on suppression writes and scan report output do not establish read isolation. Review every requested path. Pin the package version so the server does not change between sessions.

### Project configuration (recommended)

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ship-safe": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "ship-safe@11.0.0", "mcp"]
    }
  }
}
```

Replace `11.0.0` with the Ship Safe version you have reviewed. Pass an explicitly reviewed project path to tools. Use relative paths such as `"."` or `"src"` only after checking which directory the server uses. Project configuration is not a filesystem sandbox.

### User configuration

`~/.cursor/mcp.json` uses the same format. A user-level configuration applies across projects, so do not assume the server's working directory matches the project you have open.

Which directory Cursor uses as the server's working directory is not verified in this guide. `ship_safe_status` does not return a working directory or workspace root. Inspect the client launch configuration and logs, then use a small, non-sensitive fixture with a known marker and review the paths returned by a scan. This checks path resolution, not filesystem isolation. Do not rely on relative paths until you have confirmed their resolution.

### Credentials

Ship Safe's MCP server does not need API keys to run. Do not add `env` or `envFile` entries with credentials to `.cursor/mcp.json`. That file is often committed and is part of the repository's trust boundary. See [Handle MCP environment variables safely](../mcp-env-safety.md).

## Verify the connection

1. Save the configuration and reload Cursor (or open the project in a new window).
2. Open Cursor Settings > MCP (Customize in newer versions) and check that `ship-safe` is enabled and lists its tools.
3. In Agent chat, ask: `Call the ship-safe ship_safe_status tool.`
4. Approve the call. The response should report `state: available` and `protected: false`.

`ship_safe_status` takes no arguments, reads no files, and changes nothing, so it is a safe first call. It confirms tool availability, not workspace selection or confinement. After that, try `get_checklist` (which does not verify path resolution), or `scan_secrets` on an explicitly reviewed, non-sensitive fixture path. Use `path: "."` only after confirming the server's working directory.

Available tools include `scan_repo`, `scan_secrets`, `analyze_file`, `get_findings`, `get_checklist`, `suppress_finding`, and `ship_safe_status`. Note that `suppress_finding` edits files by adding `ship-safe-ignore` comments.

## Tool approvals

Cursor asks for approval before running MCP tools by default. Keep that default. Review each tool's arguments before approving, especially `path` values and any `suppress_finding` call.

Do not add a blanket allowlist or auto-approve every Ship Safe tool. If you allowlist anything, limit it to read-only tools such as `ship_safe_status` and `get_checklist`.

## What it does not claim

MCP access is not continuous enforcement. Ship Safe only runs when the agent chooses to call one of its tools. It does not intercept Cursor's file edits, terminal commands, or other tool calls, and it does not block anything on its own.

Describe this setup as **Ship Safe available in Cursor**, not as `Protected by Ship Safe`. `ship_safe_status` reports `protected: false` for that reason. Lifecycle enforcement exists today only for [Claude Code hooks](./claude-code.md).

## Troubleshooting

- **Server does not appear or shows an error:** open the Output panel, select **MCP Logs**, and check for startup errors.
- **`npx` not found:** Cursor must find `npx` on its `PATH`. Install Node.js, restart Cursor, or use the full path to `npx` in `command`.
- **First start is slow or times out:** `npx -y` downloads the package on first use. Run `npx -y ship-safe@11.0.0 --version` in a terminal once, then reload Cursor.
- **`Path must stay within the MCP workspace`:** a suppression write or scan report output path failed its workspace check. Confirm the server's working directory and choose a write path inside it. Read tools do not uniformly enforce this boundary, so a successful read does not prove confinement.
- **Tools missing after a change:** toggle the server off and on, or reload the window.

## Remove

1. Delete the `ship-safe` entry from `.cursor/mcp.json` and/or `~/.cursor/mcp.json`. Delete the file only if it contains no other servers.
2. Reload Cursor and confirm `ship-safe` no longer appears in the MCP list.

To pause it without removing it, toggle the server off in Cursor's MCP settings.

## Tested versions

| Cursor surface | Cursor version | Node.js version | Ship Safe version | OS | Result |
| --- | --- | --- | --- | --- | --- |
| IDE | 3.24.12 | 22.23.1 | 11.0.0 | Windows | `ship_safe_status` returned `state: available`, `protected: false` via project `.cursor/mcp.json`; 7 tools listed |

This smoke test establishes availability only. Working-directory selection, read isolation, and lifecycle enforcement were not verified by that result.
