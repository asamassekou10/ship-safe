<p align="center">
  <img src=".github/assets/logo%20ship%20safe.png" alt="Ship Safe Logo" width="180" />
</p>
<p align="center"><strong>AI-powered application security platform for developers.</strong></p>

<p align="center">
  <a href="https://www.npmjs.com/package/ship-safe"><img src="https://badge.fury.io/js/ship-safe.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/ship-safe"><img src="https://img.shields.io/npm/dm/ship-safe.svg" alt="npm downloads" /></a>
  <a href="https://github.com/asamassekou10/ship-safe/actions/workflows/ci.yml"><img src="https://github.com/asamassekou10/ship-safe/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/node/v/ship-safe" alt="Node.js version" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://github.com/asamassekou10/ship-safe/stargazers"><img src="https://img.shields.io/github/stars/asamassekou10/ship-safe?style=social" alt="GitHub stars" /></a>
</p>

---

16 security agents. 80+ attack classes. One command.

**Ship Safe v5.0** is an AI-powered security platform that runs 16 specialized agents in parallel against your codebase — scanning for secrets, injection vulnerabilities, auth bypass, SSRF, supply chain attacks, Supabase RLS misconfigs, Docker/Terraform/Kubernetes misconfigs, CI/CD pipeline poisoning, LLM/agentic AI security, MCP server misuse, RAG poisoning, PII compliance, and more. LLM-powered deep analysis verifies exploitability of critical findings. Secrets verification probes provider APIs to check if leaked keys are still active. A dedicated CI command (`ship-safe ci`) integrates into any pipeline with threshold-based gating and SARIF output.

---

## Quick Start

```bash
# Full security audit — secrets + 16 agents + deps + remediation plan
npx ship-safe audit .

# LLM-powered deep analysis (Anthropic, OpenAI, Google, Ollama)
npx ship-safe audit . --deep

# Red team scan only (16 agents, 80+ attack classes)
npx ship-safe red-team .

# Quick secret scan
npx ship-safe scan .

# Security health score (0-100)
npx ship-safe score .

# CI/CD pipeline mode — compact output, exit codes, SARIF
npx ship-safe ci .

# Accept current findings, only report regressions
npx ship-safe baseline .
npx ship-safe audit . --baseline

# Check if leaked secrets are still active
npx ship-safe audit . --verify

# Environment diagnostics
npx ship-safe doctor
```

![ship-safe terminal demo](.github/assets/ship%20safe%20terminal.jpg)

---

## The `audit` Command

One command that runs everything and generates a full report:

```bash
npx ship-safe audit .
```

```
════════════════════════════════════════════════════════════
  Ship Safe v5.0 — Full Security Audit
════════════════════════════════════════════════════════════

  [Phase 1/4] Scanning for secrets...         ✔ 49 found
  [Phase 2/4] Running 16 security agents...   ✔ 103 findings
  [Phase 3/4] Auditing dependencies...        ✔ 44 CVEs
  [Phase 4/4] Computing security score...     ✔ 25/100 F

  Remediation Plan
  ════════════════════════════════════════════════════════

  🔴 CRITICAL — fix immediately
  ────────────────────────────────────────────────────────
   1. [SECRETS] Rotate Stripe Live Secret Key
      .env:67 → Move to environment variable or secrets manager

   2. [INJECTION] Unsafe pickle.loads()
      backend/ai_processor.py:64 → Use JSON for untrusted data

  🟠 HIGH — fix before deploy
  ────────────────────────────────────────────────────────
   3. [XSS] dangerouslySetInnerHTML without sanitization
      frontend/src/utils/blogContentRenderer.jsx:50 → Add DOMPurify

  ... 149 more items in the full report

  📊 Full report: ship-safe-report.html
```

**What it runs:**
1. **Secret scan** — 50+ patterns with entropy scoring (API keys, passwords, tokens)
2. **16 security agents** — run in parallel with per-agent timeouts and framework-aware filtering (injection, auth, SSRF, supply chain, config, Supabase RLS, LLM, MCP, agentic AI, RAG, PII, mobile, git history, CI/CD, API)
3. **Dependency audit** — npm/pip/bundler CVE scanning
4. **Secrets verification** — probes provider APIs (GitHub, Stripe, OpenAI, etc.) to check if leaked keys are still active
5. **Deep analysis** — LLM-powered taint analysis verifies exploitability of critical/high findings (optional)
6. **Score computation** — confidence-weighted scoring across 8 categories (0-100, A-F)
7. **Context-aware confidence tuning** — downgrades findings in test files, docs, and comments
8. **Remediation plan** — prioritized fix list grouped by severity
9. **HTML report** — standalone dark-themed report with code context

**Flags:**
- `--json` — structured JSON output (clean for piping)
- `--sarif` — SARIF format for GitHub Code Scanning
- `--csv` — CSV export for spreadsheets
- `--md` — Markdown report
- `--html [file]` — custom HTML report path (default: `ship-safe-report.html`)
- `--compare` — show per-category score delta vs. last scan
- `--timeout <ms>` — per-agent timeout (default: 30s)
- `--no-deps` — skip dependency audit
- `--no-ai` — skip AI classification
- `--no-cache` — force full rescan (ignore cached results)
- `--baseline` — only show findings not in the baseline
- `--pdf [file]` — generate PDF report (requires Chrome/Chromium)
- `--deep` — LLM-powered taint analysis for critical/high findings
- `--local` — use local Ollama model for deep analysis
- `--model <model>` — LLM model to use for deep/AI analysis
- `--budget <cents>` — max spend in cents for deep analysis (default: 50)
- `--verify` — check if leaked secrets are still active (probes provider APIs)

---

## 16 Security Agents

| Agent | Category | What It Detects |
|-------|----------|-----------------|
| **InjectionTester** | Code Vulns | SQL/NoSQL injection, command injection, code injection (eval), XSS, path traversal, XXE, ReDoS, prototype pollution, Python f-string SQL injection, Python subprocess shell injection |
| **AuthBypassAgent** | Auth | JWT vulnerabilities (alg:none, weak secrets), cookie security, CSRF, OAuth misconfig, BOLA/IDOR, weak crypto, timing attacks, TLS bypass, Django `DEBUG = True`, Flask hardcoded secret keys |
| **SSRFProber** | SSRF | User input in fetch/axios, cloud metadata endpoints, internal IPs, redirect following |
| **SupplyChainAudit** | Supply Chain | Typosquatting (Levenshtein distance), git/URL dependencies, wildcard versions, suspicious install scripts, dependency confusion, scoped packages without registry pinning |
| **ConfigAuditor** | Config | Dockerfile (running as root, :latest tags), Terraform (public S3/RDS, open SG, CloudFront HTTP, Lambda admin, S3 no versioning), Kubernetes (privileged containers, `:latest` tags, missing NetworkPolicy), CORS, CSP, Firebase, Nginx |
| **SupabaseRLSAgent** | Auth | Supabase Row Level Security — `service_role` key in client code, `CREATE TABLE` without RLS, anon key inserts, unprotected storage operations |
| **LLMRedTeam** | AI/LLM | OWASP LLM Top 10 — prompt injection, excessive agency, system prompt leakage, unbounded consumption, RAG poisoning |
| **MCPSecurityAgent** | AI/LLM | MCP server security — unvalidated tool inputs, missing auth, excessive permissions, tool poisoning |
| **AgenticSecurityAgent** | AI/LLM | OWASP Agentic AI Top 10 — agent hijacking, privilege escalation, unsafe code execution, memory poisoning |
| **RAGSecurityAgent** | AI/LLM | RAG pipeline security — unvalidated embeddings, context injection, document poisoning, vector DB access control |
| **PIIComplianceAgent** | Compliance | PII detection — SSNs, credit cards, emails, phone numbers in source code, logs, and configs |
| **MobileScanner** | Mobile | OWASP Mobile Top 10 2024 — insecure storage, WebView JS injection, HTTP endpoints, excessive permissions, debug mode |
| **GitHistoryScanner** | Secrets | Leaked secrets in git commit history (checks if still active in working tree) |
| **CICDScanner** | CI/CD | OWASP CI/CD Top 10 — pipeline poisoning, unpinned actions, secret logging, self-hosted runners, script injection |
| **APIFuzzer** | API | Routes without auth, missing input validation, mass assignment, unrestricted file upload, GraphQL introspection, debug endpoints, missing rate limiting, OpenAPI spec security issues |
| **ReconAgent** | Recon | Attack surface discovery — frameworks, languages, auth patterns, databases, cloud providers, IaC, CI/CD pipelines |

**Post-processors:** ScoringEngine (8-category weighted scoring), VerifierAgent (secrets liveness verification), DeepAnalyzer (LLM-powered taint analysis)

---

## All Commands

### Core Audit Commands

```bash
# Full audit with remediation plan + HTML report
npx ship-safe audit .

# Red team: 16 agents, 80+ attack classes
npx ship-safe red-team .
npx ship-safe red-team . --agents injection,auth    # Run specific agents
npx ship-safe red-team . --html report.html         # HTML report
npx ship-safe red-team . --json                     # JSON output

# Secret scanner (pattern matching + entropy)
npx ship-safe scan .
npx ship-safe scan . --json          # JSON for CI
npx ship-safe scan . --sarif         # SARIF for GitHub

# Security health score (0-100, A-F)
npx ship-safe score .

# Dependency CVE audit
npx ship-safe deps .
npx ship-safe deps . --fix           # Auto-fix vulnerabilities
```

### AI-Powered Commands

```bash
# AI audit: scan + classify with Claude + auto-fix secrets
npx ship-safe agent .

# Auto-fix hardcoded secrets: rewrite code + write .env
npx ship-safe remediate .
npx ship-safe remediate . --all    # Also fix agent findings (TLS, debug, XSS, etc.)

# Revoke exposed keys — opens provider dashboards
npx ship-safe rotate .
```

### Baseline Management

```bash
# Accept current findings as baseline
npx ship-safe baseline .

# Audit showing only new findings since baseline
npx ship-safe audit . --baseline

# Show what changed since baseline
npx ship-safe baseline --diff

# Remove baseline
npx ship-safe baseline --clear
```

### CI/CD Pipeline

```bash
# CI mode — compact output, exit codes, threshold gating
npx ship-safe ci .
npx ship-safe ci . --threshold 80    # Custom passing score
npx ship-safe ci . --fail-on critical # Fail on severity
npx ship-safe ci . --sarif out.sarif  # SARIF for GitHub
```

### Deep Analysis & Verification

```bash
# LLM-powered deep analysis (Anthropic/OpenAI/Google/Ollama)
npx ship-safe audit . --deep
npx ship-safe audit . --deep --local     # Use local Ollama
npx ship-safe audit . --deep --budget 50 # Cap spend at 50 cents

# Check if leaked secrets are still active
npx ship-safe audit . --verify
```

### Diagnostics

```bash
# Environment check — Node.js, git, npm, API keys, cache, version
npx ship-safe doctor
```

### Infrastructure Commands

```bash
# Continuous monitoring (watch files for changes)
npx ship-safe watch .

# Generate CycloneDX SBOM
npx ship-safe sbom .

# Policy-as-code (enforce minimum score, fail on severity)
npx ship-safe policy init

# Block git push if secrets found
npx ship-safe guard

# Initialize security configs (.gitignore, headers)
npx ship-safe init

# Launch-day security checklist
npx ship-safe checklist

# MCP server for AI editors (Claude Desktop, Cursor, etc.)
npx ship-safe mcp
```

---

## Claude Code Plugin

Use Ship Safe directly inside Claude Code — no CLI needed:

```bash
claude plugin add github:asamassekou10/ship-safe
```

| Command | Description |
|---------|-------------|
| `/ship-safe` | Full security audit — 16 agents, remediation plan, auto-fix |
| `/ship-safe-scan` | Quick scan for leaked secrets |
| `/ship-safe-score` | Security health score (0-100) |
| `/ship-safe-deep` | LLM-powered deep taint analysis |
| `/ship-safe-ci` | CI/CD pipeline setup guide |

Claude interprets the results, explains findings in plain language, and can fix issues directly in your codebase.

---

## Incremental Scanning

Ship Safe caches file hashes and findings in `.ship-safe/context.json`. On subsequent runs, only changed files are re-scanned — unchanged files reuse cached results.

```
✔ [Phase 1/4] Secrets: 41 found (0 changed, 313 cached)
```

- **~40% faster** on repeated scans
- **Auto-invalidation** — cache expires after 24 hours or when ship-safe updates
- **`--no-cache`** — force a full rescan anytime

The cache is stored in `.ship-safe/` which is automatically excluded from scans.

### LLM Response Caching

When using AI classification (`--no-ai` to disable), results are cached in `.ship-safe/llm-cache.json` with a 7-day TTL. Repeated scans reuse cached classifications — reducing API costs significantly.

---

## Smart `.gitignore` Handling

Ship Safe respects your `.gitignore` for build output, caches, and vendor directories — but **always scans security-sensitive files** even if gitignored:

| Skipped (gitignore respected) | Always scanned (gitignore overridden) |
|-------------------------------|---------------------------------------|
| `node_modules/`, `dist/`, `build/` | `.env`, `.env.local`, `.env.production` |
| `*.log`, `*.pkl`, vendor dirs | `*.pem`, `*.key`, `*.p12` |
| Cache directories, IDE files | `credentials.json`, `*.secret` |

Why? Files like `.env` are gitignored *because* they contain secrets — which is exactly what a security scanner should catch.

---

## Multi-LLM Support

Ship Safe supports multiple AI providers for classification:

| Provider | Env Variable | Model |
|----------|-------------|-------|
| **Anthropic** | `ANTHROPIC_API_KEY` | claude-haiku-4-5 |
| **OpenAI** | `OPENAI_API_KEY` | gpt-4o-mini |
| **Google** | `GOOGLE_AI_API_KEY` | gemini-2.0-flash |
| **Ollama** | `OLLAMA_HOST` | Local models |

Auto-detected from environment variables. No API key required for scanning — AI is optional.

---

## Scoring System

Starts at 100. Each finding deducts points by severity and category, weighted by confidence level (high: 100%, medium: 60%, low: 30%) to reduce noise from heuristic patterns.

**8 Categories** (with weight caps):

| Category | Weight | Critical | High | Medium | Cap |
|----------|--------|----------|------|--------|-----|
| Secrets | 15% | -25 | -15 | -5 | -15 |
| Code Vulnerabilities | 15% | -20 | -10 | -3 | -15 |
| Dependencies | 15% | -20 | -10 | -5 | -15 |
| Auth & Access Control | 15% | -20 | -10 | -3 | -15 |
| Configuration | 10% | -15 | -8 | -3 | -10 |
| Supply Chain | 10% | -15 | -8 | -3 | -10 |
| API Security | 10% | -15 | -8 | -3 | -10 |
| AI/LLM Security | 10% | -15 | -8 | -3 | -10 |

**Grades:** A (90-100), B (75-89), C (60-74), D (40-59), F (0-39)

**Exit codes:** `0` for A/B (>= 75), `1` for C/D/F — use in CI to fail builds.

---

## Policy-as-Code

Create `.ship-safe.policy.json` to enforce team-wide security standards:

```bash
npx ship-safe policy init
```

```json
{
  "minimumScore": 70,
  "failOn": "critical",
  "requiredScans": ["secrets", "injection", "deps", "auth"],
  "ignoreRules": [],
  "customSeverityOverrides": {},
  "maxAge": { "criticalCVE": "7d", "highCVE": "30d", "mediumCVE": "90d" }
}
```

---

## CI/CD Integration

The dedicated `ci` command is optimized for pipelines — compact output, exit codes, threshold-based gating:

```bash
# Basic CI — fail if score < 75
npx ship-safe ci .

# Strict — fail on any critical finding
npx ship-safe ci . --fail-on critical

# Custom threshold + SARIF for GitHub Security tab
npx ship-safe ci . --threshold 80 --sarif results.sarif

# Only check new findings (not in baseline)
npx ship-safe ci . --baseline
```

**GitHub Actions example:**

```yaml
# .github/workflows/security.yml
name: Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Security gate
        run: npx ship-safe ci . --threshold 75 --sarif results.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

**Export formats:** `--json`, `--sarif`, `--csv`, `--md`, `--html`, `--pdf`

---

## Suppress False Positives

**Inline:** Add `# ship-safe-ignore` comment on a line:
```python
password = get_password()  # ship-safe-ignore
```

**File-level:** Create `.ship-safeignore` (gitignore syntax):
```gitignore
# Exclude test fixtures
tests/fixtures/
*.test.js

# Exclude documentation with code examples
docs/
```

---

## OWASP Coverage

| Standard | Coverage |
|----------|----------|
| **OWASP Top 10 Web 2025** | A01-A10: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Data Integrity, Logging Failures, SSRF |
| **OWASP Top 10 Mobile 2024** | M1-M10: Improper Credential Usage, Inadequate Supply Chain, Insecure Auth, Insufficient Validation, Insecure Communication, Inadequate Privacy, Binary Protections, Security Misconfiguration, Insecure Data Storage, Insufficient Cryptography |
| **OWASP LLM Top 10 2025** | LLM01-LLM10: Prompt Injection, Sensitive Info Disclosure, Supply Chain, Data Poisoning, Improper Output Handling, Excessive Agency, System Prompt Leakage, Vector/Embedding Weaknesses, Misinformation, Unbounded Consumption |
| **OWASP CI/CD Top 10** | CICD-SEC-1 to 10: Insufficient Flow Control, Identity Management, Dependency Chain Abuse, Poisoned Pipeline Execution, Insufficient PBAC, Credential Hygiene, Insecure System Config, Ungoverned Usage, Improper Artifact Integrity, Insufficient Logging |
| **OWASP Agentic AI Top 10** | ASI01-ASI10: Agent Hijacking, Tool Misuse, Privilege Escalation, Unsafe Code Execution, Memory Poisoning, Identity Spoofing, Excessive Autonomy, Logging Gaps, Supply Chain Attacks, Cascading Hallucination |

---

## What's Inside

### [`/configs`](./configs)
Drop-in security configs for Next.js, Supabase, and Firebase.

### [`/snippets`](./snippets)
Copy-paste security patterns: rate limiting, JWT, CORS, input validation.

### [`/ai-defense`](./ai-defense)
LLM security: prompt injection detection, cost protection, system prompt hardening.

### [`/checklists`](./checklists)
Manual security audits: launch-day checklist, framework-specific guides.

---

## Contributing

1. Fork the repo
2. Add your security pattern, agent, or config
3. Include comments explaining *why* it matters
4. Open a PR

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## Security Standards Reference

- [OWASP Top 10 Web 2025](https://owasp.org/Top10/)
- [OWASP Top 10 Mobile 2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)
- [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/)

---

## License

MIT - Use it, share it, secure your stuff.

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=asamassekou10/ship-safe&type=Date)](https://star-history.com/#asamassekou10/ship-safe&Date)

---

**Ship fast. Ship safe.**
