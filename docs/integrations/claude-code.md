# Claude Code integration

Ship Safe can protect Claude Code sessions with local `PreToolUse` and `PostToolUse` hooks.

## Install

```bash
npx ship-safe@latest hooks install
```

The installer copies stable hook scripts to `~/.ship-safe/hooks/` and registers them in `~/.claude/settings.json`:

- `PreToolUse` blocks critical secrets and dangerous shell commands before execution.
- `PostToolUse` scans completed writes and reports advisory findings in the session.
- `statusLine` shows `Protected by Ship Safe` only when both enforcement hooks and their scripts are ready.

Check the installation with:

```bash
npx ship-safe@latest hooks status
npx ship-safe@latest hooks status --json
```

The status line is local and does not send source code or credentials anywhere. It is an indicator of the installed hook lifecycle, not a replacement for a full repository scan.

## Existing status lines

Claude Code supports one status-line command. If another integration already owns it, Ship Safe preserves that command and still installs its security hooks. The status output will show the conflict instead of claiming the badge is active.

## Remove

```bash
npx ship-safe@latest hooks remove
```

Removal only removes Ship Safe's registered hooks and status line. Other Claude Code settings are preserved.
