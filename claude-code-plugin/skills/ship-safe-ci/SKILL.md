---
name: ship-safe-ci
description: Run Ship Safe in CI mode — compact output, exit codes, SARIF generation. Use when the user wants to set up CI/CD security gates or test their pipeline configuration.
argument-hint: "[path] [--threshold <score>] [--fail-on <severity>] [--sarif <file>]"
---

# Ship Safe — CI Pipeline Mode

You are helping the user set up Ship Safe as a security gate in their CI/CD pipeline.

## Step 1: Run CI scan

```bash
npx ship-safe@latest ci $ARGUMENTS 2>/dev/null
```

Default: pass/fail based on score >= 75.

### Options:
- `--threshold 60` — custom passing score
- `--fail-on critical` — only fail on critical findings
- `--fail-on high` — fail on critical or high
- `--sarif results.sarif` — SARIF output for GitHub Code Scanning
- `--baseline` — only check new findings
- `--json` — JSON output for custom integrations
- `--no-deps` — skip dependency audit

## Step 2: Interpret results

The command outputs a compact one-line summary:
```
[ship-safe] Score: 82/100 (B) | Findings: 12 (0C 3H 9M) | CVEs: 2 | 4.2s
[ship-safe] PASS
```

Or on failure:
```
[ship-safe] Score: 58/100 (C) | Findings: 25 (3C 8H 14M) | CVEs: 5 | 6.1s
[ship-safe] FAIL: Score 58 < threshold 75
```

Exit code 0 = pass, exit code 1 = fail.

## Step 3: Help set up CI integration

Based on the user's CI platform, offer to create or update their workflow file:

### GitHub Actions
```yaml
- name: Security Scan
  run: npx ship-safe@latest ci . --threshold 75 --sarif results.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI
```yaml
security-scan:
  script:
    - npx ship-safe@latest ci . --threshold 75 --json > security-report.json
  artifacts:
    reports:
      sast: security-report.json
```

### Generic CI
```bash
npx ship-safe@latest ci . --threshold 75 || exit 1
```

## Step 4: Suggest baseline workflow

If there are many findings:
1. Create a baseline: `npx ship-safe baseline .`
2. Use `--baseline` in CI to only catch new vulnerabilities
3. Gradually fix baselined issues over time

## Important Notes

- CI mode suppresses all spinners and color for clean log output
- The SARIF file can be uploaded to GitHub Code Scanning for inline PR annotations
- Use `--fail-on critical` for a gradual rollout — start strict only for critical issues
