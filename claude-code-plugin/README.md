# Ship Safe Plugin for Claude Code

Security audit your projects directly inside Claude Code. 16 agents, 80+ attack classes, zero setup.

## Install

```bash
claude plugin add github:asamassekou10/ship-safe
```

## Skills

| Command | Description |
|---------|-------------|
| `/ship-safe` | Full security audit — 16 agents, 80+ attack classes, prioritized remediation plan |
| `/ship-safe-scan` | Quick scan for leaked secrets (API keys, passwords, tokens) |
| `/ship-safe-score` | Security health score (0-100, A-F grade) |
| `/ship-safe-red-team` | Multi-agent red team scan — deep vulnerability analysis |
| `/ship-safe-baseline` | Manage security baseline — only report new regressions |
| `/ship-safe-fix` | Auto-fix security issues (secrets, TLS, debug mode, XSS, Docker) |
| `/ship-safe-deep` | LLM-powered deep taint analysis for critical/high findings |
| `/ship-safe-ci` | CI/CD pipeline setup — GitHub Actions, GitLab CI examples |

## How It Works

These skills invoke [ship-safe](https://www.npmjs.com/package/ship-safe) via `npx`, so you always get the latest version. No API keys required — Claude Code itself interprets the results, explains findings in plain language, and can directly fix issues in your codebase.

## Examples

```
> /ship-safe
Runs full audit with 16 security agents, shows score, findings grouped
by severity, and offers to fix critical issues in your code.

> /ship-safe-scan src/
Scans src/ directory for leaked secrets and offers to move them to
environment variables.

> /ship-safe-score
Quick score check — tells you if your project is safe to ship.

> /ship-safe-red-team . --agents injection,auth
Deep dive into injection and auth vulnerabilities with specialized agents.

> /ship-safe-baseline .
Accept current findings as baseline. Future scans only show new regressions.

> /ship-safe-fix . --all
Auto-fix hardcoded secrets AND common vulnerabilities (TLS bypass, debug
mode, XSS, Docker :latest, shell injection).
```

## What Gets Scanned

- Secrets (API keys, passwords, tokens, database URLs)
- Injection vulnerabilities (SQL, NoSQL, XSS, command injection)
- Auth bypass (JWT, CSRF, OAuth, IDOR)
- SSRF (user input in HTTP clients, cloud metadata)
- Supply chain (typosquatting, dependency confusion, wildcard versions)
- Supabase RLS (missing Row Level Security, service_role key exposure)
- Config (Docker, Terraform, Kubernetes, CORS, CSP)
- LLM security (prompt injection, system prompt leakage)
- MCP server security (tool poisoning, missing auth)
- Agentic AI (OWASP Agentic AI Top 10 — agent hijacking, privilege escalation)
- RAG pipelines (context injection, document poisoning)
- PII compliance (SSNs, credit cards, emails in source code)
- CI/CD (pipeline poisoning, unpinned actions)
- API (missing auth, rate limiting, OpenAPI spec issues)
- Dependencies (known CVEs in npm, pip, bundler)

## Requirements

- Node.js 18+
- Claude Code CLI

## Links

- [Ship Safe on npm](https://www.npmjs.com/package/ship-safe)
- [Ship Safe on GitHub](https://github.com/asamassekou10/ship-safe)
