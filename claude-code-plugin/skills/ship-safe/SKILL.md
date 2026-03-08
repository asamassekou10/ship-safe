---
name: ship-safe
description: Run a full security audit on this project — 13 agents scan for secrets, injections, auth bypass, SSRF, supply chain attacks, Supabase RLS, misconfigs, and more. Use when the user wants a security audit, vulnerability scan, or asks if their code is safe to ship.
argument-hint: "[path] [--no-deps] [--baseline]"
allowed-tools: Bash, Read, Edit, Write, Grep, Glob
---

# Ship Safe — Full Security Audit

You are a senior security engineer using Ship Safe to audit this project. Your job is to run the audit, interpret the results clearly, and offer to fix the most critical issues.

## Step 1: Run the audit

Run the full security audit with JSON output:

```bash
npx ship-safe@latest audit $ARGUMENTS --json --no-ai 2>/dev/null
```

If `$ARGUMENTS` is empty, default to `.` (current directory):

```bash
npx ship-safe@latest audit . --json --no-ai 2>/dev/null
```

The command exits 1 when findings exist — this is expected. Capture stdout regardless of exit code.

If the command fails to produce JSON (e.g., no lockfile for deps), retry with `--no-deps`:

```bash
npx ship-safe@latest audit . --json --no-ai --no-deps 2>/dev/null
```

## Step 2: Parse the JSON output

The JSON output has this exact structure:

```json
{
  "score": 72,
  "grade": "C",
  "gradeLabel": "Fix before shipping",
  "totalFindings": 45,
  "totalDepVulns": 12,
  "categories": {
    "secrets": { "label": "Secrets", "findingCount": 10, "deduction": 15, "counts": { "critical": 2, "high": 5, "medium": 3 } },
    "code-vulnerabilities": { "label": "Code Vulnerabilities", "findingCount": 8, "deduction": 12, "counts": {} }
  },
  "findings": [
    {
      "file": "src/config.js",
      "line": 42,
      "severity": "critical",
      "category": "secrets",
      "rule": "STRIPE_LIVE_KEY",
      "title": "Stripe Live Secret Key",
      "description": "Hardcoded Stripe live secret key",
      "fix": "Move to environment variable",
      "confidence": "high",
      "codeContext": [
        { "line": 40, "text": "const config = {", "highlight": false },
        { "line": 41, "text": "  db: process.env.DATABASE_URL,", "highlight": false },
        { "line": 42, "text": "  stripe: 'sk_live_abc123...',", "highlight": true },
        { "line": 43, "text": "  debug: false,", "highlight": false }
      ],
      "cwe": "CWE-798",
      "owasp": "A07:2021"
    }
  ],
  "depVulns": [
    { "severity": "high", "package": "lodash@4.17.20", "description": "Prototype Pollution" }
  ],
  "remediationPlan": [
    {
      "priority": 1,
      "severity": "critical",
      "category": "secrets",
      "categoryLabel": "SECRETS",
      "title": "Stripe Live Secret Key",
      "file": "src/config.js:42",
      "action": "Move to environment variable or secrets manager",
      "effort": "low"
    }
  ],
  "recon": {
    "frameworks": ["Next.js", "Express"],
    "databases": ["PostgreSQL"],
    "authPatterns": ["JWT", "bcrypt"],
    "apiRoutes": ["/api/users", "/api/auth"]
  },
  "agents": [
    { "agent": "InjectionTester", "category": "injection", "findingCount": 5, "success": true }
  ]
}
```

## Step 3: Present the results

Present a clear, actionable security report in this order:

### 3a. Score Banner
Show the score prominently:
- Score (0-100), grade (A-F), and the grade label
- Grade meanings: A (90-100) Ship it! | B (75-89) Minor issues | C (60-74) Fix before shipping | D (40-59) Significant risks | F (0-39) Not safe to ship

### 3b. Category Breakdown
Show a table of each category with finding count and point deduction. Categories include: Secrets, Code Vulnerabilities, Dependencies, Auth & Access Control, Configuration, Supply Chain, API Security, AI/LLM Security.

### 3c. Critical and High Findings
List all critical and high severity findings. For each:
- File and line number
- Title and description
- The suggested fix from the `fix` field
- Code context if available (show the highlighted line with surrounding context)
- CWE/OWASP reference if available
- Confidence level (high, medium, low) — note that low-confidence findings may be false positives

Group by severity (critical first, then high).

### 3d. Dependency Vulnerabilities
If there are dep vulns, list them: package name, severity, description.

### 3e. Attack Surface
If recon data exists, briefly note: detected frameworks, databases, auth patterns, and API route count.

### 3f. Medium/Low Summary
Summarize medium and low findings by count and category — don't list each one unless the user asks.

## Step 4: Offer Remediation

After presenting results, proactively offer to fix the most critical issues. Prioritize in this order:

1. **Secrets** (any severity) — most urgent, could be actively exploited
   - Replace hardcoded values with `process.env.VARIABLE_NAME`
   - Create or update `.env.example` with placeholder values
   - Ensure `.env` is in `.gitignore`
   - Warn that committed secrets should be rotated

2. **Critical code vulnerabilities** — SQL injection, command injection, etc.
   - Add input validation or parameterized queries
   - Replace dangerous functions (eval, pickle.loads, etc.)

3. **High severity findings** — XSS, auth bypass, SSRF, etc.
   - Apply the fix described in each finding's `fix` field
   - Read the surrounding code context before making changes

4. **Config issues** — Docker, Terraform, CORS, etc.
   - Update configuration files as recommended

For each fix:
- Read the file first to understand the context
- Apply the minimal change needed
- Do not break existing functionality
- Explain what you changed and why

## Step 5: Suggest Next Steps

After fixing, suggest:
- `npx ship-safe baseline .` — to baseline remaining findings so future scans only show regressions
- `npx ship-safe guard` — to install a pre-push hook that blocks commits with secrets
- `npx ship-safe watch .` — for continuous monitoring during development

## Important Notes

- Never display actual secret values, even if partially shown in output
- The `--no-ai` flag is intentional — Claude Code itself is the AI layer, so ship-safe's built-in LLM classification is unnecessary
- If the user specifies a path in `$ARGUMENTS`, use it instead of `.`
- If the user says "no deps" or "quick", add `--no-deps` to skip dependency auditing
- If the user says "only new" or "baseline", add `--baseline` to filter out baselined findings
- Low-confidence findings in test files, docs, or comments are likely false positives — mention this when presenting them
