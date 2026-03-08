---
name: ship-safe-score
description: Get your project's security health score (0-100, A-F grade). Use when the user wants a quick security check or asks "is my code safe to ship?"
argument-hint: "[path] [--no-deps]"
allowed-tools: Bash, Read, Grep, Glob
---

# Ship Safe — Security Score

You are checking this project's security health score.

## Step 1: Run the score command

```bash
npx ship-safe@latest score $ARGUMENTS 2>&1
```

If `$ARGUMENTS` is empty, default to `.`:

```bash
npx ship-safe@latest score . 2>&1
```

If the user mentions skipping dependencies, add `--no-deps`.

The command outputs styled terminal text (not JSON). Parse the output for the score, grade, and category breakdown.

## Step 2: Present the results

Extract and present:

1. **Score and Grade**: The 0-100 score and A-F letter grade
2. **Category Breakdown**: Show deductions per category (Secrets, Code Vulnerabilities, Dependencies)
3. **Grade Meaning**:
   - A (90-100): Ship it! Your code looks secure.
   - B (75-89): Minor issues to review, but generally safe.
   - C (60-74): Fix issues before shipping to production.
   - D (40-59): Significant security risks present.
   - F (0-39): Not safe to ship. Critical issues found.

## Step 3: Recommendations

Based on the score:

- **A or B (75+)**: Congratulate the user. Suggest running `npx ship-safe guard` to install a pre-push git hook that maintains the score. Mention they can run `/ship-safe` for a detailed breakdown anytime.

- **C (60-74)**: Recommend running `/ship-safe` for a full audit to see exactly what needs fixing. Mention the most likely problem areas based on the category breakdown.

- **D or F (below 60)**: Strongly recommend running `/ship-safe` immediately. Offer to start the full audit right now. Emphasize that critical findings should be fixed before any deployment.

- For any score, mention `/ship-safe-baseline` to track progress over time and `/ship-safe-fix` for automated remediation.
