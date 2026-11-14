# Codex integration

Ship Safe can be used by Codex through Codex's MCP client configuration. This gives Codex access to Ship Safe's security tools while it works in a repository.

## Supported surfaces

OpenAI documents that the Codex CLI, the Codex IDE extension and the ChatGPT desktop app share the same MCP configuration. This guide has only been checked against the Codex CLI's configuration commands. See [Tested versions](#tested-versions) for what was actually run.

| Surface | Status |
| --- | --- |
| Codex CLI (`codex mcp` commands, `config.toml`) | Registration, inspection and removal verified. A model-driven tool call inside a Codex session has not been verified. |
| Codex IDE extension | Not verified. It reads the same configuration, according to OpenAI's docs. |
| ChatGPT desktop app | Not verified. It reads the same configuration, according to OpenAI's docs. |
| Codex cloud tasks / ChatGPT web | Not supported by this setup. A local `stdio` server on your machine is not available to them, and ChatGPT web does not read local Codex configuration. |

Do not treat the unverified surfaces as supported until they appear in [Tested versions](#tested-versions).

## Configure the MCP server

Codex reads MCP servers from `config.toml`:

- **User:** `~/.codex/config.toml` (or `$CODEX_HOME/config.toml` if you set `CODEX_HOME`). Applies to every project.
- **Project:** `.codex/config.toml` in a repository. Codex loads it only after you trust the project.

Pin the package version so the server does not change between sessions. Replace `11.0.0` below with the Ship Safe version you have reviewed.

### Register with the CLI

```bash
codex mcp add ship-safe -- npx -y ship-safe@11.0.0 mcp
```

This writes a global entry to `~/.codex/config.toml`:

```toml
[mcp_servers.ship-safe]
command = "npx"
args = ["-y", "ship-safe@11.0.0", "mcp"]
```

### Set the workspace explicitly

The Ship Safe MCP server treats its working directory as the MCP workspace: relative tool paths resolve from it, and suppression writes and scan report output must stay inside it. `codex mcp add` has no option for the working directory, and the directory Codex uses when none is set is not documented. Add `cwd` to the entry yourself:

```toml
[mcp_servers.ship-safe]
command = "npx"
args = ["-y", "ship-safe@11.0.0", "mcp"]
cwd = "/path/to/your/repo"
startup_timeout_sec = 60
```

- `cwd` is the repository you want Ship Safe to work in. Use an absolute path.
- `startup_timeout_sec` gives `npx` time to download the package on first start. Codex's default is 10 seconds.

A global entry with a fixed `cwd` points at that one repository, whichever project you have open in Codex. To work across several repositories, either put a project entry in each repository's `.codex/config.toml`, or pass an explicitly reviewed absolute path to each tool.

The workspace check covers suppression writes and scan report output only. Read tools such as `scan_repo`, `scan_secrets` and `analyze_file` are not uniformly confined to `cwd`, so `cwd` is not a filesystem sandbox. Review every `path` argument.

### Credentials

Ship Safe's MCP server does not need API keys to run. Do not add `env` or `env_vars` entries with credentials to a Ship Safe entry, especially in a project `.codex/config.toml` that may be committed. See [Handle MCP environment variables safely](../mcp-env-safety.md).

### Other MCP clients

For MCP clients that use JSON configuration, the equivalent entry is:

```json
{
  "mcpServers": {
    "ship-safe": {
      "command": "npx",
      "args": ["-y", "ship-safe@11.0.0", "mcp"]
    }
  }
}
```

## Check the configuration

```bash
codex mcp list
codex mcp get ship-safe
```

`codex mcp list` should show `ship-safe` with status `enabled` and the `cwd` you set. `codex mcp get ship-safe` shows the full entry (add `--json` for machine-readable output). These commands read the configuration only. They do not start the server.

## Verify the connection

1. Start a new Codex session (`codex`) in the repository. Restart any running session after you change the configuration.
2. Run `/mcp` in the Codex TUI and check that `ship-safe` is listed with its tools. In the IDE extension, MCP servers are listed under the gear menu.
3. Ask: `Call the ship-safe ship_safe_status tool.`
4. Approve the call if Codex asks.

Expected result (the text content of the tool response):

```json
{
  "schemaVersion": 1,
  "integration": "mcp",
  "state": "available",
  "protected": false,
  "badge": "Ship Safe available in this session",
  "message": "Ship Safe MCP tools are connected. MCP does not automatically intercept every Codex or Claude action; use scan_repo or scan_secrets when you want a check.",
  "tools": ["scan_repo", "scan_secrets", "analyze_file", "get_findings", "get_checklist", "suppress_finding"]
}
```

`ship_safe_status` takes no arguments, reads no files and changes nothing, so it is a safe first call. It confirms that the tools are available. It does not confirm which directory the server uses or that reads are confined to it. After that, try `get_checklist`, or `scan_secrets` on a small, non-sensitive fixture path you have reviewed.

Available tools: `scan_repo`, `scan_secrets`, `analyze_file`, `get_findings`, `get_checklist`, `suppress_finding` and `ship_safe_status`. `suppress_finding` edits files by adding `ship-safe-ignore` comments.

## Tool approvals

Codex lets you set how MCP tool calls are approved with `default_tools_approval_mode` on the server entry (`auto`, `prompt`, `writes` or `approve`, per OpenAI's config reference). Keep Ship Safe calls reviewable:

```toml
[mcp_servers.ship-safe]
# ...
default_tools_approval_mode = "prompt"
```

Ship Safe's tools do not currently declare MCP read-only annotations, so `writes` mode will prompt for every Ship Safe tool, not only `suppress_finding`. Do not set `auto` for the whole server. Review each call's `path` arguments before approving, especially any `suppress_finding` call.

## What it does not claim

MCP access is not an automatic pre-tool or post-tool enforcement layer. Ship Safe only runs when Codex chooses to call one of its tools. It does not intercept Codex's file edits, shell commands or other tool calls, and it does not block anything on its own.

Describe this setup as **Ship Safe available in Codex**, not as `Protected by Ship Safe`. That badge requires a separately verified lifecycle integration that can prove which actions were checked and whether a check blocked or allowed them. `ship_safe_status` reports `protected: false` for that reason. MCP alone cannot inject a persistent footer badge into Codex. Lifecycle integration research for Codex is tracked in [#137](https://github.com/asamassekou10/ship-safe/issues/137).

## Recommended workflow

Ask Codex to scan the repository before making security-sensitive changes, review modified files after implementation, and run a final scan before commit or release. Keep the scan scope limited to the authorized repository and avoid passing secrets through tool arguments.

## Troubleshooting

- **`ship-safe` is missing from `/mcp`:** run `codex mcp list` to confirm the entry exists and is `enabled`. If it lives in a project `.codex/config.toml`, check that you have trusted the project. Then start a new session.
- **Startup times out on first use:** `npx -y` downloads the package the first time it runs. Run `npx -y ship-safe@11.0.0 --version` once in a terminal, or raise `startup_timeout_sec`.
- **`npx` not found:** Codex must find `npx` on its `PATH`. Install Node.js, restart your terminal or editor, or use the full path to `npx` in `command`.
- **`Path must stay within the MCP workspace`:** a suppression write or scan report output path is outside the server's working directory. Check `cwd` with `codex mcp get ship-safe` and choose a path inside it.
- **A relative path scans the wrong directory:** set `cwd` explicitly (see [Set the workspace explicitly](#set-the-workspace-explicitly)), or pass an absolute path.

## Remove

```bash
codex mcp remove ship-safe
codex mcp list
```

`codex mcp remove` deletes only the `ship-safe` entry from `~/.codex/config.toml`. If you added an entry to a project `.codex/config.toml`, delete the `[mcp_servers.ship-safe]` table there by hand. Start a new Codex session and confirm `ship-safe` no longer appears in `/mcp`.

To pause the server without removing it, set `enabled = false` on the entry.

## Tested versions

Tested 2026-11-14.

| What | Codex version | Node.js version | Ship Safe version | OS | Result |
| --- | --- | --- | --- | --- | --- |
| `codex mcp add` / `list` / `get` / `remove` | codex-cli 0.169.0 | 25.9.0 | 11.0.0 | Windows 11 | `add` wrote the entry shown above. `list` and `get` showed it as an enabled stdio server, including a hand-added `cwd`, `startup_timeout_sec` and `default_tools_approval_mode`. `remove` deleted the entry. Run against a throwaway `CODEX_HOME`. |
| Ship Safe MCP server over stdio (no Codex) | n/a | 25.9.0 | 11.0.0 | Windows 11 | `initialize` succeeded, `tools/list` returned 7 tools, and `ship_safe_status` returned the JSON shown above. |
| `ship_safe_status` called by Codex in a session | not verified | | | | Needs a signed-in Codex session. |
| IDE extension, ChatGPT desktop app | not verified | | | | |

These checks establish configuration and tool availability only. Working-directory selection when `cwd` is unset, read isolation and lifecycle enforcement were not verified.
