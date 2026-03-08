---
name: ship-safe-red-team
description: Run a multi-agent red team scan — 13 specialized security agents scan for 50+ attack classes including injection, auth bypass, SSRF, supply chain, Supabase RLS, LLM attacks, and more. Use when the user wants a deep security analysis beyond just secrets.
argument-hint: "[path] [--agents <list>]"
allowed-tools: Bash, Read, Edit, Write, Grep, Glob
---

# Ship Safe — Red Team Scan

You are running a multi-agent red team scan using Ship Safe's 13 security agents.

## Step 1: Run the red team scan

```bash
npx ship-safe@latest red-team $ARGUMENTS --json --no-ai 2>/dev/null
```

If `$ARGUMENTS` is empty, default to `.`:

```bash
npx ship-safe@latest red-team . --json --no-ai 2>/dev/null
```

If the user wants specific agents only, use the `--agents` flag:

```bash
npx ship-safe@latest red-team . --agents injection,auth,ssrf --json --no-ai 2>/dev/null
```

Available agents: `injection`, `auth`, `ssrf`, `supply-chain`, `config`, `llm`, `mobile`, `git-history`, `cicd`, `api`, `supabase-rls`

## Step 2: Parse and present results

The JSON output contains findings from each agent. Present results grouped by agent:

### For each agent that found issues:
1. **Agent name and category** (e.g., "InjectionTester — Code Vulnerabilities")
2. **Finding count** by severity
3. **Top findings** — list critical and high severity findings with:
   - File and line number
   - Rule name and description
   - Code context (if available, show the flagged line with surrounding lines)
   - Suggested fix
   - Confidence level

### Agent summary table
Show a table: Agent | Findings | Critical | High | Medium

### Agents with zero findings
List them briefly as clean — this is useful context.

## Step 3: Deep dive and remediation

For the most critical findings:
1. Read the actual source file for full context
2. Explain the vulnerability in plain language — what could an attacker do?
3. Offer to fix it with a concrete code change
4. After fixing, offer to re-run just that agent to verify: `npx ship-safe@latest red-team . --agents <agent>`

## Step 4: Recommendations

Based on the results, suggest:
- Which agents to focus on (highest finding count or most critical findings)
- Whether to create a baseline (`/ship-safe-baseline`) for the current state
- Framework-specific hardening tips based on detected stack (from recon agent)

## Important Notes

- The 13 agents are: InjectionTester, AuthBypassAgent, SSRFProber, SupplyChainAudit, ConfigAuditor, SupabaseRLSAgent, LLMRedTeam, MobileScanner, GitHistoryScanner, CICDScanner, APIFuzzer, ReconAgent, ScoringEngine
- Agents run in parallel — the scan should complete in under 60 seconds for most projects
- Low-confidence findings in test files or documentation are likely false positives
- Never display actual secret values
