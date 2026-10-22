# Claude Code integration

Ship Safe works with Claude Code in two separate ways:

| Integration | What it does | When it runs |
| --- | --- | --- |
| [MCP server](#mcp-server-quickstart) | Gives Claude access to Ship Safe tools such as `analyze_file` and `scan_repo` | Only when Claude chooses to call a tool, and you approve the call |
| [Hooks](#hooks) | `PreToolUse` and `PostToolUse` checks on Claude Code's `Write`, `Edit`, `MultiEdit`, and `Bash` tools | Automatically, for those tool calls only |

You can use either one on its own or both together. Neither intercepts every action Claude Code takes. See [What each integration covers](#what-each-integration-covers).

This guide is for the Claude Code CLI only. Claude Desktop and Claude on the web use different configuration and are not covered here. See [Other Claude clients](#other-claude-clients).

## MCP server quickstart

Official reference: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp).

### 1. Register a pinned local stdio server

Run this from the root of the repository you want Ship Safe to review:

```bash
claude mcp add --transport stdio --scope local ship-safe -- npx -y ship-safe@11.0.0 mcp
```

Replace `11.0.0` with the Ship Safe version you have reviewed. Pinning keeps the server from changing between sessions. Everything after `--` is the command Claude Code runs to start the server.

Ship Safe's MCP server needs no API keys. Do not add `--env` or `-e` options with credentials. See [Handle MCP environment variables safely](../mcp-env-safety.md).

### 2. Choose the scope

| Scope | Stored in | Applies to |
| --- | --- | --- |
| `local` (default) | `~/.claude.json`, under the current project path | You, in this project only |
| `project` | `.mcp.json` in the project root | Everyone who opens the project. Each user must approve it in an interactive `claude` session. |
| `user` | `~/.claude.json` | You, in every project |

Prefer `local` or `project`. With `user` scope the server runs in every project you open, so do not assume relative paths point at the repository you meant to scan.

With `--scope project` the command writes this `.mcp.json`:

```json
{
  "mcpServers": {
    "ship-safe": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "ship-safe@11.0.0", "mcp"],
      "env": {}
    }
  }
}
```

Until you approve it, `claude mcp list` shows ``⏸ Pending approval (run `claude` to approve)``. Start `claude` in the project and accept the prompt.

### 3. Check the connection

```bash
claude mcp get ship-safe
```

Expected output (local scope):

```text
ship-safe:
  Scope: Local config (private to you in this project)
  Status: ✔ Connected
  Type: stdio
  Command: npx
  Args: -y ship-safe@11.0.0 mcp
```

Inside a session, `/mcp` shows the same server and lists its tools.

Then ask Claude:

```text
Call the ship-safe ship_safe_status tool.
```

`ship_safe_status` takes no arguments, reads no files, and changes nothing. It should return `state: available` and `protected: false`. This confirms that the tools are available. It does not confirm which directory the server uses or that anything is being enforced.

### 4. Run one harmless review

[`docs/examples/claude-code-quickstart/sample-config.js`](../examples/claude-code-quickstart/sample-config.js) is an inert fixture. Its only value is a synthetic placeholder, not a credential. Copy it into the project root, then ask Claude:

```text
Call the ship-safe analyze_file tool with path sample-config.js.
```

Approve the call. `analyze_file` only reads the file. Expected result:

```json
{
  "file": "sample-config.js",
  "totalFindings": 1,
  "clean": false,
  "findings": [
    {
      "line": 5,
      "type": "Password Assignment",
      "severity": "medium",
      "description": "Hardcoded passwords are a critical vulnerability.",
      "fix": "Move to environment variable. Never commit to source control."
    }
  ],
  "summary": "Found 1 potential secret(s) in sample-config.js."
}
```

Ship Safe redacts local paths in tool output and does not echo the matched value. In the tested setup, relative paths resolved from the directory where `claude` was started. Check that on your setup before you rely on relative paths. Delete the copied fixture when you are done.

Other available tools: `scan_repo`, `scan_secrets`, `get_findings`, `get_checklist`, and `suppress_finding`. `suppress_finding` edits files by adding `ship-safe-ignore` comments, so review its arguments before approving.

### Tool approvals

Claude Code asks before it runs an MCP tool. Keep that default. If you allowlist anything in your [permission settings](https://code.claude.com/docs/en/permissions), limit it to read-only tools such as `mcp__ship-safe__ship_safe_status` and `mcp__ship-safe__get_checklist`.

### Remove the MCP server

```bash
claude mcp remove ship-safe --scope local
```

Use `--scope project` or `--scope user` if you added it there. For project scope this removes the entry from `.mcp.json` but leaves the file in place. Confirm with:

```bash
claude mcp get ship-safe
```

which should report `No MCP server named "ship-safe"`.

### Troubleshooting

- **Missing executable.** `claude mcp list` shows `✘ Failed to connect — ENOENT: Executable not found in $PATH: "<command>"`. Install Node.js (`^22.13.0` or `>=24`) so `npx` is on the `PATH` Claude Code sees, or use the absolute path to `npx` as the command. Run `npx -y ship-safe@11.0.0 --version` once in a terminal to check the package downloads and to warm the cache before the first connection.
- **Wrong working directory.** A tool returns `File does not exist: ./sample-config.js` or a scan reports files you did not expect. Relative paths resolve from the server's working directory, not from a `cd` Claude ran in Bash. Restart `claude` from the repository root or pass an explicit path. A suppression write or report output outside that directory fails with `Path must stay within the MCP workspace`. Read tools do not all enforce that boundary, so a successful read does not prove confinement.
- **Tools not available.** Run `claude mcp get ship-safe`. `⏸ Pending approval` means a project-scoped server was never approved: run `claude` and accept it. `⊘ Disabled for this project` means it was turned off: re-enable it from `/mcp`. `No MCP server named "ship-safe"` usually means it was added in a different project or scope. Start a new session after changing the configuration.
- **Running from a checkout of Ship Safe itself.** `npx ship-safe@...` resolves the checkout's own package and fails with `ship-safe: command not found`. Use `node /path/to/ship-safe/cli/bin/ship-safe.js mcp` as the command instead.

## Hooks

Official reference: [Claude Code hooks](https://code.claude.com/docs/en/hooks).

### Install

```bash
npx ship-safe@latest hooks install
```

The installer copies stable hook scripts to `~/.ship-safe/hooks/` and registers them in `~/.claude/settings.json`:

- `PreToolUse` on `Write`, `Edit`, `MultiEdit`, and `Bash` blocks critical secrets and dangerous shell commands before execution.
- `PostToolUse` on `Write`, `Edit`, and `MultiEdit` scans completed writes and reports advisory findings in the session.
- `statusLine` shows `Protected by Ship Safe` only when both enforcement hooks and their scripts are ready.

Check the installation with:

```bash
npx ship-safe@latest hooks status
npx ship-safe@latest hooks status --json
```

The machine-readable schema, state definitions, exit codes, privacy boundary,
and compatibility guidance are documented in the
[protection-status contract](./protection-status.md).

The status line is local and does not send source code or credentials anywhere. It is an indicator of the installed hook lifecycle, not a replacement for a full repository scan.

### Existing status lines

Claude Code supports one status-line command. If another integration already owns it, Ship Safe preserves that command and still installs its security hooks. The status output will show the conflict instead of claiming the badge is active.

### Remove

```bash
npx ship-safe@latest hooks remove
```

Removal only removes Ship Safe's registered hooks and status line. Other Claude Code settings are preserved.

## What each integration covers

The MCP server is not enforcement. It runs only when Claude calls one of its tools. It does not see or block Claude's file edits, shell commands, or calls to other MCP servers. `ship_safe_status` reports `protected: false` for that reason. Describe an MCP-only setup as **Ship Safe available in Claude Code**.

The hooks run automatically, but only for the matched tools listed above. They do not cover other Claude Code tools, other MCP servers, or changes made outside Claude Code. `Protected by Ship Safe` refers to that hook coverage, not to every action in the session.

New connected-agent tools are proposed in the [connected-agent contract](../connected-agent-contract.md). They are not available yet, and this guide will document them only once they ship.

## Other Claude clients

Claude Desktop and Claude on the web are separate products. They do not read Claude Code's `claude mcp` configuration or `~/.claude/settings.json`, and Ship Safe's hooks do not apply to them. Claude Desktop can run local stdio MCP servers through its own configuration file; see [Connect to local MCP servers](https://modelcontextprotocol.io/docs/develop/connect-local-servers). Claude on the web cannot start a local stdio server on your machine. Neither is tested in this guide.

## Tested versions

| Date | Claude Code | Node.js | Ship Safe | OS | Result |
| --- | --- | --- | --- | --- | --- |
| 2026-10-21 | 2.1.299 | 24.20.0 | 11.0.0 | macOS (arm64) | Local scope: `claude mcp get` reported `✔ Connected`; `ship_safe_status` returned `state: available`, `protected: false`; `analyze_file` on the sample fixture returned one medium finding; `claude mcp remove` removed the server. Project scope: `.mcp.json` written as shown and reported `Pending approval` until approved. |

This test covers availability, relative path resolution from the launch directory, and removal. It did not verify read isolation or hook behavior.
