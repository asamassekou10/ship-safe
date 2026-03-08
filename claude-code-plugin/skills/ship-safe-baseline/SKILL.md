---
name: ship-safe-baseline
description: Manage your security baseline — accept current findings as known debt, then only report new regressions on future scans. Use when the user wants to adopt security scanning incrementally or suppress existing findings.
argument-hint: "[path] [--diff] [--clear]"
allowed-tools: Bash, Read, Grep, Glob
---

# Ship Safe — Baseline Management

You are helping the user manage their security baseline. A baseline lets teams "accept" current findings as known technical debt and only see new regressions on future scans.

## Understand the request

- **No flags or just a path** → Create/update the baseline
- **`--diff`** → Show what changed since the baseline was created
- **`--clear`** → Remove the baseline

## Step 1: Run the baseline command

```bash
npx ship-safe@latest baseline $ARGUMENTS 2>&1
```

If `$ARGUMENTS` is empty, default to `.`:

```bash
npx ship-safe@latest baseline . 2>&1
```

For diff mode:
```bash
npx ship-safe@latest baseline . --diff 2>&1
```

For clearing:
```bash
npx ship-safe@latest baseline --clear 2>&1
```

## Step 2: Explain the result

### If creating a baseline:
1. Report how many findings were baselined
2. Explain that `.ship-safe/baseline.json` was created
3. Tell the user they can now run `npx ship-safe audit . --baseline` (or `/ship-safe --baseline`) to only see new findings
4. Recommend adding `.ship-safe/baseline.json` to version control so the whole team shares the same baseline

### If showing diff:
1. Report new findings (not in baseline) — these are regressions
2. Report resolved findings (in baseline but no longer detected) — these are improvements
3. If no changes, confirm the codebase matches the baseline

### If clearing:
Confirm the baseline was removed. Future scans will show all findings again.

## Step 3: Suggest workflow

After creating a baseline, suggest this workflow:
- **CI pipeline**: Add `npx ship-safe audit . --baseline --json` to fail builds only on new findings
- **Periodic review**: Run `/ship-safe-baseline --diff` to track progress on reducing technical debt
- **After fixing**: Run `/ship-safe-baseline .` to update the baseline

## Important Notes

- The baseline uses content-based fingerprints (`rule:path:snippet`), not line numbers — so the baseline survives code reformatting and line shifts
- Creating a baseline does NOT mean the findings are safe — it means the team acknowledges them and will address them over time
