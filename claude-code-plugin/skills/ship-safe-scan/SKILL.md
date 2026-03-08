---
name: ship-safe-scan
description: Quick scan for leaked secrets — API keys, passwords, tokens, database URLs. Use when the user wants to check for hardcoded secrets or exposed credentials.
argument-hint: "[path]"
allowed-tools: Bash, Read, Edit, Write, Grep, Glob
---

# Ship Safe — Secret Scan

You are scanning this project for leaked secrets using Ship Safe's pattern matching and entropy analysis engine.

## Step 1: Run the scan

```bash
npx ship-safe@latest scan $ARGUMENTS --json 2>/dev/null
```

If `$ARGUMENTS` is empty, default to `.`:

```bash
npx ship-safe@latest scan . --json 2>/dev/null
```

The command exits 0 if clean, 1 if secrets found. Capture stdout regardless.

## Step 2: Parse the JSON output

The JSON output has this structure:

```json
{
  "filesScanned": 234,
  "totalFindings": 5,
  "clean": false,
  "findings": [
    {
      "file": "src/config.js",
      "findings": [
        {
          "line": 42,
          "type": "Stripe Live Secret Key",
          "severity": "critical",
          "description": "Hardcoded Stripe live secret key found",
          "matched": "sk_live_****"
        }
      ]
    }
  ]
}
```

## Step 3: Report

**If clean:** Confirm no secrets were found. Report how many files were scanned. This is good news!

**If secrets found:**

1. List each finding grouped by file:
   - File path and line number
   - Secret type (e.g., "AWS Access Key", "GitHub Token", "Database URL")
   - Severity level
2. **Never display actual secret values** — even partial matches should be referred to by type only
3. If multiple secrets are in the same file, group them together

## Step 4: Remediate

For each secret found, offer to fix it:

1. **Replace** the hardcoded secret with an environment variable reference:
   - JavaScript/TypeScript: `process.env.VARIABLE_NAME`
   - Python: `os.environ.get('VARIABLE_NAME')`
   - Use a descriptive variable name based on the secret type (e.g., `STRIPE_SECRET_KEY`, `DATABASE_URL`)

2. **Create or update `.env.example`** with placeholder values:
   ```
   STRIPE_SECRET_KEY=sk_live_your_key_here
   DATABASE_URL=postgresql://user:password@host:5432/db
   ```

3. **Ensure `.env` is in `.gitignore`** — check and add if missing

4. **Warn about git history** — if the secret was already committed, it exists in git history. Recommend:
   - Rotating the credential immediately (mention `npx ship-safe rotate`)
   - Consider using `git filter-branch` or BFG Repo Cleaner to remove from history

5. **Suggest auto-fix** — mention `/ship-safe-fix` for bulk remediation, or `/ship-safe-baseline` to baseline known findings

Read the file and surrounding context before making any changes. Apply fixes only after presenting the findings, unless the user asked for auto-fix.
