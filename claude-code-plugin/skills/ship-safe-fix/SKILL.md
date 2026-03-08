---
name: ship-safe-fix
description: Auto-fix security issues — remediate hardcoded secrets and common vulnerabilities (TLS bypass, debug mode, XSS, shell injection, Docker :latest). Use when the user wants to automatically fix security findings.
argument-hint: "[path] [--all] [--dry-run]"
allowed-tools: Bash, Read, Edit, Write, Grep, Glob
---

# Ship Safe — Auto-Fix Security Issues

You are using Ship Safe's remediation engine to automatically fix security issues in this project.

## Step 1: Preview the fixes

Always start with a dry run to show what will change:

```bash
npx ship-safe@latest remediate $ARGUMENTS --dry-run 2>&1
```

If `$ARGUMENTS` is empty, default to `. --all` (fix both secrets and agent findings):

```bash
npx ship-safe@latest remediate . --all --dry-run 2>&1
```

**Flags:**
- No `--all` flag → only fixes hardcoded secrets (moves to env vars)
- With `--all` → also fixes: TLS bypass (`rejectUnauthorized: false`), Docker `:latest` tags, debug mode enabled, `dangerouslySetInnerHTML` without sanitization, `shell: true` in exec/spawn

## Step 2: Present the preview

Show the user what will be changed:
1. List each file that will be modified
2. Show the before/after for each change
3. Group by fix type (secrets, TLS, Docker, debug, XSS, shell)
4. Note any files that will be created (`.env.example`, `.env`)

## Step 3: Apply fixes (with confirmation)

Ask the user if they want to proceed. If yes:

```bash
npx ship-safe@latest remediate . --all --yes 2>&1
```

If the user only wants to fix secrets (not agent findings):

```bash
npx ship-safe@latest remediate . --yes 2>&1
```

## Step 4: Post-fix verification

After applying fixes:

1. Run a quick scan to verify secrets were removed:
   ```bash
   npx ship-safe@latest scan . --json 2>/dev/null
   ```

2. Report the results — how many issues were fixed vs. remaining

3. For remaining issues that couldn't be auto-fixed, offer to fix them manually by reading the code and applying targeted changes

## Step 5: Follow-up actions

Suggest:
- **Review `.env.example`** — make sure variable names make sense
- **Add `.env` to `.gitignore`** if not already there
- **Rotate exposed secrets** — run `npx ship-safe rotate .` for step-by-step guides
- **Update baseline** — run `/ship-safe-baseline .` to update after fixes
- **Stage changes** — offer to stage the modified files with git

## Important Notes

- Ship Safe creates a backup before modifying files — the user can revert if something breaks
- The `--all` flag is important for fixing agent-level findings beyond just secrets
- Never display actual secret values, even in the dry run output
- If a fix might break functionality (e.g., `shell: false` in exec), warn the user to test
- For `dangerouslySetInnerHTML` fixes, note that `DOMPurify` needs to be installed: `npm install dompurify`
