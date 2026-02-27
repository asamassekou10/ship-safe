# Ship-Safe v4.0 — Security Improvement Plan

**Date:** February 24, 2026
**Status:** Proposal
**Goal:** Transform ship-safe from a secret scanner into a comprehensive AI-agent-powered application security platform that protects against all known attack classes.

---

## Executive Summary

Ship-safe v3.2.0 provides strong secret detection (70+ patterns), basic code vulnerability scanning (18 patterns), AI-powered classification, and automated remediation. However, the 2025-2026 threat landscape has evolved dramatically:

- **Supply chain attacks grew 633% YoY** — the Shai-Hulud worm compromised 25,000+ repositories
- **SSRF attacks surged 452%** — now folded into OWASP A01:2025
- **Security misconfiguration rose to #2** in OWASP Top 10 2025
- **73% of AI deployments** are vulnerable to prompt injection
- **61% of organizations** expose secrets in public repositories
- **Kubernetes clusters face first attacks within 18 minutes** of creation

This plan introduces **Red Team Agents**, **expanded scanning modules**, and **deep CI/CD integration** to make ship-safe the most comprehensive open-source security tool for modern web and mobile applications.

---

## Architecture: Multi-Agent Security System

### Current Architecture (v3.2.0)
```
CLI Command → Regex Pattern Matching → Entropy Scoring → Findings → AI Classification → Remediation
```

### Proposed Architecture (v4.0)
```
                              ┌─────────────────────┐
                              │   ship-safe engine   │
                              │  (orchestrator)      │
                              └──────────┬──────────┘
                                         │
            ┌────────────────────────────┼────────────────────────────┐
            │                            │                            │
   ┌────────▼────────┐      ┌───────────▼──────────┐    ┌───────────▼──────────┐
   │  Scanner Agents  │      │   Red Team Agents    │    │  Remediation Agents  │
   │                  │      │                      │    │                      │
   │ • SecretScanner  │      │ • ReconAgent         │    │ • SecretRemediator   │
   │ • VulnScanner    │      │ • InjectionTester    │    │ • CodeFixer          │
   │ • DepsScanner    │      │ • AuthBypassAgent    │    │ • ConfigHardener     │
   │ • IaCScanner     │      │ • SSRFProber         │    │ • DependencyPatcher  │
   │ • ContainerScan  │      │ • SupplyChainAudit   │    │ • RotationGuide      │
   │ • APIScanner     │      │ • APIFuzzer          │    │ • SBOMGenerator      │
   │ • MobileScanner  │      │ • ConfigAuditor      │    │                      │
   │ • GitHistoryScan │      │ • LLMRedTeam         │    │                      │
   │ • CICDScanner    │      │                      │    │                      │
   └─────────────────┘      └──────────────────────┘    └──────────────────────┘
            │                            │                            │
            └────────────────────────────┼────────────────────────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   Scoring Engine     │
                              │ CVSS + EPSS + KEV    │
                              │ + Context Analysis   │
                              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   Output Adapters    │
                              │ CLI / SARIF / JSON / │
                              │ HTML / GitHub PR /   │
                              │ SBOM / Dashboard     │
                              └─────────────────────┘
```

---

## Phase 1: Red Team Agent Framework (v4.0-alpha)

### 1.1 Agent Architecture

Create a pluggable agent system where each agent specializes in a specific attack domain. Agents can be run individually or orchestrated together.

**New file:** `cli/agents/base-agent.js`
```
BaseAgent
├── name, description, category
├── analyze(codebase) → findings[]
├── classify(finding, context) → REAL | FALSE_POSITIVE | NEEDS_REVIEW
├── suggest(finding) → remediation
└── verify(finding, fix) → PASS | FAIL
```

**New file:** `cli/agents/orchestrator.js`
```
Orchestrator
├── registerAgent(agent)
├── runAll(codebase, options) → aggregated findings
├── runCategory(category, codebase) → category findings
├── parallelize(agents[]) → concurrent execution
└── deduplicate(findings[]) → unique findings
```

### 1.2 ReconAgent — Attack Surface Discovery

**Purpose:** Map the full attack surface before scanning. Understand what the application does, what frameworks it uses, and where attack vectors exist.

**Capabilities:**
- Detect frameworks: Next.js, Nuxt, SvelteKit, Remix, Express, Django, Flask, Rails, FastAPI, Spring Boot
- Map API routes (Next.js `/app/api/`, Express `router.get()`, Django `urls.py`)
- Identify authentication patterns (NextAuth, Clerk, Auth0, Supabase Auth, Firebase Auth)
- Discover database connections (Prisma, Drizzle, Sequelize, SQLAlchemy, TypeORM)
- Detect cloud providers from config files (vercel.json, netlify.toml, fly.toml, Dockerfile)
- Identify frontend exposure (env vars prefixed with `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`)
- Build a dependency graph of internal modules

**Output:** `recon-report.json` — A structured map of the application's attack surface used by all other agents.

### 1.3 InjectionTester Agent

**Purpose:** Detect all injection vulnerabilities by tracing data flow from user input to dangerous sinks.

**Attack Classes Covered:**

| Attack | Detection Method |
|--------|-----------------|
| SQL Injection | Trace template literals / string concat into query functions (Prisma raw, Sequelize literal, pg query, mysql2) |
| NoSQL Injection | Detect unsanitized user input in MongoDB queries (`$where`, `$regex`, `$gt` in user input) |
| Command Injection | Trace user input to `exec()`, `spawn()`, `system()`, subprocess calls |
| Code Injection | `eval()`, `Function()`, `vm.runInNewContext()` with user input |
| XSS (Reflected) | Trace request params to response output without encoding |
| XSS (Stored) | Detect database reads rendered without sanitization |
| XSS (DOM) | `innerHTML`, `document.write`, `dangerouslySetInnerHTML` with dynamic content |
| LDAP Injection | User input in LDAP filter construction |
| Expression Language Injection | Template engine injection (EJS, Pug, Handlebars with unescaped output) |
| Header Injection | User input in HTTP response headers (`res.setHeader`, `res.redirect`) |
| Path Traversal | User input in file path construction (`fs.readFile`, `path.join` with user input) |
| Log Injection | Unsanitized user input written to logs (enabling log forging) |
| GraphQL Injection | Missing query depth limits, introspection enabled in production, no cost analysis |

**AI-Enhanced Detection:**
- Send suspicious code blocks to Claude with surrounding context
- Ask: "Is this user input reaching this dangerous sink without sanitization?"
- Use the ReconAgent's framework detection to understand ORM-level protections (e.g., Prisma parameterizes by default)

### 1.4 AuthBypassAgent

**Purpose:** Detect authentication and authorization vulnerabilities.

**Checks:**

| Check | What It Detects |
|-------|----------------|
| Missing auth middleware | API routes without authentication checks |
| JWT algorithm confusion | Accepting `alg: none` or HS256 when RS256 expected |
| JWT secret strength | Weak HMAC secrets (short, dictionary words) |
| Broken Object-Level Authorization (BOLA) | Direct object references without ownership checks |
| Missing CSRF protection | State-changing endpoints without CSRF tokens |
| Session fixation | Session IDs not regenerated after login |
| Privilege escalation | Role checks missing on admin/privileged endpoints |
| Password policy | No password strength requirements enforced |
| MFA bypass | MFA checks skippable via direct API calls |
| OAuth misconfiguration | Missing `state` parameter, overly broad `redirect_uri`, no PKCE |
| Cookie security | Missing `httpOnly`, `secure`, `sameSite` flags |
| Rate limiting on auth | No brute-force protection on login/reset endpoints |

**Implementation:**
- Parse route files to build an endpoint map
- Check each endpoint for auth middleware/decorators
- Verify JWT configuration files (jsonwebtoken options, jose config)
- Cross-reference with ReconAgent's auth framework detection

### 1.5 SSRFProber Agent

**Purpose:** Detect Server-Side Request Forgery vulnerabilities — the fastest-growing attack vector (452% surge).

**Detection Patterns:**
- User input in URL construction for `fetch()`, `axios`, `got`, `http.get()`
- URL parameters passed to server-side HTTP clients
- Webhook URL validation (accepting internal IPs like `169.254.169.254`, `127.0.0.1`, `10.x.x.x`)
- DNS rebinding susceptibility (single DNS lookup before request)
- Protocol smuggling potential (`file://`, `gopher://`, `dict://` not blocked)
- Cloud metadata endpoint access (AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254`)
- Redirect-following HTTP clients that could redirect to internal services

**Framework-Specific Checks:**
- Next.js: `fetch()` in Server Components and API routes
- Express: Proxy middleware misconfiguration
- Django: `URLValidator` not enforcing scheme restrictions

### 1.6 SupplyChainAudit Agent

**Purpose:** Comprehensive supply chain security analysis beyond basic `npm audit`.

**Capabilities:**

| Check | Description |
|-------|-------------|
| Dependency confusion risk | Compare internal package names against public registries |
| Typosquatting detection | Flag dependencies with names similar to popular packages |
| Install script analysis | Detect packages with `preinstall`/`postinstall` scripts that execute suspicious code |
| Maintainer analysis | Flag packages with single maintainers, recent ownership transfers, or no GitHub links |
| License compliance | Detect copyleft licenses (GPL) in commercial projects |
| Lockfile integrity | Verify `package-lock.json` / `yarn.lock` integrity hashes |
| Phantom dependencies | Detect imports of packages not in `package.json` (relying on hoisting) |
| SBOM generation | Produce CycloneDX SBOM for the project |
| EPSS scoring | Query FIRST EPSS API for exploitation probability of each CVE |
| KEV flagging | Cross-reference with CISA Known Exploited Vulnerabilities catalog |
| Deprecated packages | Flag packages marked as deprecated on registries |
| Git source verification | Verify packages come from expected git repos (detect star-jacking) |

**AI-Enhanced Analysis:**
- For each flagged dependency, ask Claude to analyze the package's `postinstall` script and README for suspicious behavior
- Prioritize findings by EPSS exploitation probability rather than raw CVSS severity

### 1.7 APIFuzzer Agent

**Purpose:** Static analysis of API endpoints for security anti-patterns.

**Checks:**

| Category | Checks |
|----------|--------|
| Authentication | Endpoints missing auth middleware, inconsistent auth patterns |
| Authorization | Missing ownership checks, direct object references |
| Input Validation | Missing Zod/Joi/Yup schemas, unvalidated request bodies |
| Rate Limiting | No rate limiting on sensitive endpoints |
| CORS | Wildcard origins, credentials with wildcard, missing CORS headers |
| Error Handling | Stack traces in error responses, database errors exposed |
| Data Exposure | Returning full database objects instead of selected fields |
| Mass Assignment | Accepting arbitrary fields from request body into database operations |
| GraphQL Security | Introspection enabled, no query depth/cost limits, no field-level auth |
| gRPC Security | Reflection enabled in production, missing TLS, no auth interceptors |
| Pagination | Missing pagination allowing full database dumps |
| File Upload | No file type validation, no size limits, path traversal in filenames |

### 1.8 ConfigAuditor Agent

**Purpose:** Detect misconfigurations in infrastructure, deployment, and application configs.

**Scans:**

| Config Type | What It Checks |
|-------------|---------------|
| `Dockerfile` | Running as root, using `latest` tag, exposing unnecessary ports, `ADD` vs `COPY`, multi-stage builds missing, secrets in build args |
| `docker-compose.yml` | Privileged containers, host network mode, exposed ports, volume mounts to sensitive paths |
| `vercel.json` | Public environment variables, missing headers, permissive rewrites |
| `netlify.toml` | Redirect open redirects, missing security headers |
| `next.config.js` | Missing security headers, permissive `images.domains`, exposed experimental features |
| `terraform/*.tf` | Public S3 buckets, open security groups, wildcard IAM, unencrypted storage, missing logging |
| `kubernetes/*.yaml` | Privileged pods, host mounts, missing resource limits, no network policies, default service accounts |
| `.github/workflows/` | Secrets in logs, `pull_request_target` risks, unpinned actions, excessive permissions |
| `firebase.json` | Open security rules, unauthenticated functions |
| `.env.example` | Placeholder values that look like real secrets |
| `nginx.conf` / `Caddyfile` | Missing security headers, permissive CORS, directory listing enabled |

### 1.9 LLMRedTeam Agent

**Purpose:** Comprehensive AI/LLM security testing based on OWASP LLM Top 10 2025.

**Capabilities:**

| OWASP LLM Risk | Detection |
|-----------------|-----------|
| LLM01: Prompt Injection | Detect missing input sanitization before LLM calls, system prompts concatenated with user input |
| LLM02: Sensitive Info Disclosure | System prompts containing API keys, PII, or business logic; no output filtering |
| LLM03: Supply Chain | Unverified model downloads, untrusted Hugging Face models, no model hash verification |
| LLM04: Data/Model Poisoning | RAG pipelines ingesting unvalidated external data, no content filtering on embeddings |
| LLM05: Improper Output Handling | LLM output passed to `eval()`, `innerHTML`, SQL queries, or shell commands without sanitization |
| LLM06: Excessive Agency | LLM given access to database writes, file system, shell execution, or network requests without guardrails |
| LLM07: System Prompt Leakage | System prompts stored in client-accessible locations, no prompt extraction defenses |
| LLM08: Vector/Embedding Weaknesses | No access control on vector DB queries, no input validation on embedding inputs |
| LLM09: Misinformation | No fact-checking/citation layer on LLM outputs presented as factual |
| LLM10: Unbounded Consumption | No token limits, no cost caps, no rate limiting on LLM endpoints |

**Expanded Prompt Injection Patterns (50+ patterns):**
- Direct injection: "ignore previous instructions", "you are now DAN"
- Indirect injection: Hidden instructions in HTML comments, zero-width characters, Unicode RTL overrides
- Multimodal injection: Instructions embedded in image EXIF data, SVG text elements
- Encoding bypass: Base64-encoded instructions, ROT13, URL-encoded payloads
- Context window manipulation: Padding attacks to push system prompt out of context
- Second-order injection: Instructions stored in database fields consumed by LLM later

### 1.10 MobileScanner Agent

**Purpose:** Security scanning for React Native, Expo, Flutter, and native mobile codebases.

**Checks (based on OWASP Mobile Top 10 2024):**

| OWASP Mobile | Detection |
|--------------|-----------|
| M1: Improper Credentials | Hardcoded API keys in mobile bundles, secrets in `app.json`/`app.config.js` |
| M2: Supply Chain | Unvetted native modules, outdated SDKs with known CVEs |
| M3: Insecure Auth | Missing biometric auth, weak PIN requirements, no session timeout |
| M4: Input/Output Validation | WebView JavaScript injection, deep link parameter injection |
| M5: Insecure Communication | Missing certificate pinning, HTTP endpoints, TLS 1.0/1.1 |
| M6: Privacy Controls | Excessive permissions in `AndroidManifest.xml`/`Info.plist`, tracking without consent |
| M7: Insufficient Binary Protection | Missing ProGuard/R8 obfuscation, no root/jailbreak detection |
| M8: Misconfiguration | Debug mode in release builds, exported activities/services, backup enabled |
| M9: Insecure Data Storage | Secrets in `AsyncStorage`/`SharedPreferences`, sensitive data in logs |
| M10: Weak Cryptography | Custom crypto implementations, hardcoded encryption keys, ECB mode |

**React Native / Expo Specific:**
- Scan `app.json`, `app.config.js` for exposed API keys
- Check `expo-secure-store` usage vs `AsyncStorage` for sensitive data
- Detect OTA update security (Expo Updates signing)
- Verify CodePush/EAS Update integrity

### 1.11 GitHistoryScanner Agent

**Purpose:** Scan git commit history for secrets that were committed and later removed but remain in history.

**Capabilities:**
- Traverse all commits in the repository's history
- Apply the full 70+ secret pattern library to every historical file version
- Detect secrets that exist in history but not in the current working tree (most dangerous — developers think they're removed)
- Generate remediation steps: BFG Repo-Cleaner commands, `git filter-repo` instructions
- Check if detected historical secrets are still valid (optional API verification)
- Calculate risk score based on: how long ago, how many commits exposed, branch visibility

**Implementation:**
- Use `git log --all --diff-filter=D -p` and `git log --all -p` to efficiently scan diffs
- Focus on additions (lines starting with `+`) for efficiency
- Support `--since` flag for time-bounded scans
- Wrap TruffleHog or gitleaks as an optional backend for deep scans

### 1.12 CICDScanner Agent

**Purpose:** Detect security issues in CI/CD pipeline configurations based on OWASP Top 10 CI/CD Security Risks.

**Checks:**

| OWASP CI/CD Risk | Detection |
|------------------|-----------|
| CICD-SEC-1: Flow Control | Missing required reviewers, no branch protection rules |
| CICD-SEC-2: IAM | Overly permissive `GITHUB_TOKEN` permissions, service account sprawl |
| CICD-SEC-3: Dependency Chain | Unpinned dependencies in CI (`npm install` without lockfile) |
| CICD-SEC-4: Poisoned Pipeline | `pull_request_target` with `checkout` of PR branch, `workflow_run` without restrictions |
| CICD-SEC-5: PBAC | CI jobs with access to production secrets unnecessarily |
| CICD-SEC-6: Credential Hygiene | Secrets logged to CI output, secrets in workflow files, hardcoded tokens |
| CICD-SEC-7: Insecure Config | Self-hosted runners without isolation, debug mode enabled |
| CICD-SEC-8: Third-Party Services | Unpinned GitHub Actions (`uses: action@main` instead of SHA), unvetted marketplace actions |
| CICD-SEC-9: Artifact Integrity | Missing SLSA provenance, unsigned artifacts, no SBOM attestation |
| CICD-SEC-10: Logging | No audit trail of pipeline modifications, no alerting on workflow changes |

**Files Scanned:**
- `.github/workflows/*.yml` (GitHub Actions)
- `.gitlab-ci.yml` (GitLab CI)
- `Jenkinsfile` (Jenkins)
- `.circleci/config.yml` (CircleCI)
- `bitbucket-pipelines.yml` (Bitbucket)
- `.travis.yml` (Travis CI)
- `azure-pipelines.yml` (Azure DevOps)

---

## Phase 2: Enhanced Scoring Engine (v4.0-beta)

### 2.1 Risk-Based Scoring with EPSS + KEV

Replace pure CVSS severity scoring with a composite risk model:

```
Risk Score = CVSS Base × EPSS Probability × KEV Multiplier × Context Weight

Where:
  EPSS Probability = 0.0 to 1.0 (from FIRST EPSS API)
  KEV Multiplier   = 3.0 if in CISA KEV catalog, 1.0 otherwise
  Context Weight   = 1.5 if reachable, 0.5 if unused dependency
```

### 2.2 New Score Categories

Expand from 3 categories to 8:

| Category | Weight | Max Deduction |
|----------|--------|---------------|
| Secrets | 15% | -15 points |
| Code Vulnerabilities (Injection, XSS, etc.) | 15% | -15 points |
| Dependency CVEs | 15% | -15 points |
| Authentication & Authorization | 15% | -15 points |
| Configuration & Hardening | 10% | -10 points |
| Supply Chain Integrity | 10% | -10 points |
| API Security | 10% | -10 points |
| AI/LLM Security | 10% | -10 points |

### 2.3 Score Tracking Over Time

- Store scores in `.ship-safe/history.json`
- Show trend: "Score improved from 62 → 78 over last 5 scans"
- Track resolved vs new findings per scan
- Export historical data as CSV for dashboards

### 2.4 Benchmark Comparison

- "Your security score: 78/100 (Grade B)"
- "Better than 65% of Next.js projects scanned"
- Anonymous, opt-in benchmark data collection

---

## Phase 3: Expanded Output & Integration (v4.0-rc)

### 3.1 SBOM Generation

```bash
ship-safe sbom . --format cyclonedx  # CycloneDX JSON
ship-safe sbom . --format spdx       # SPDX 2.3
```

Generate Software Bill of Materials containing:
- All direct and transitive dependencies
- Version information and package URLs (purl)
- License information
- Vulnerability annotations from scan results
- Build metadata and timestamps

### 3.2 HTML Report Generation

```bash
ship-safe scan . --output report.html
```

Generate a standalone HTML report with:
- Executive summary with score and grade
- Finding breakdown by category with severity badges
- Code snippets with highlighted vulnerable lines
- Remediation steps for each finding
- SBOM summary
- Sharable with stakeholders who don't use CLI

### 3.3 GitHub PR Integration

```bash
ship-safe ci --github-pr  # Auto-comment on current PR
```

- Post findings as PR review comments on affected lines
- Add a summary comment with score and grade
- Update PR status checks (pass/fail based on policy)
- Support GitHub Security tab via SARIF upload

### 3.4 Multi-CI Pipeline Templates

Provide ready-to-use templates:
- `.github/workflows/ship-safe.yml` (GitHub Actions)
- `.gitlab-ci.yml` snippet (GitLab CI)
- `bitbucket-pipelines.yml` snippet (Bitbucket)
- `azure-pipelines.yml` snippet (Azure DevOps)

### 3.5 Policy-as-Code

**New file:** `.ship-safe.policy.json`

```json
{
  "minimumScore": 70,
  "failOn": "high",
  "requiredScans": ["secrets", "deps", "vulns", "auth"],
  "ignoreRules": ["GENERIC_API_KEY"],
  "customSeverityOverrides": {
    "CORS_WILDCARD": "critical"
  },
  "maxAge": {
    "criticalCVE": "7d",
    "highCVE": "30d",
    "mediumCVE": "90d"
  }
}
```

Teams define security policies that are enforced in CI. Replaces ad-hoc threshold flags with a centralized policy file.

---

## Phase 4: Multi-LLM Support (v4.0)

### 4.1 Provider Abstraction

```bash
ship-safe agent . --provider anthropic  # Default (Claude)
ship-safe agent . --provider openai     # GPT-4o
ship-safe agent . --provider ollama     # Local models (Llama, Mistral)
ship-safe agent . --provider google     # Gemini
```

**Implementation:** Abstract the LLM call behind a provider interface:

```
LLMProvider
├── analyze(code, context, systemPrompt) → response
├── classify(finding, context) → REAL | FALSE_POSITIVE
├── suggestFix(finding) → remediation code
└── estimateCost(inputTokens) → cost estimate
```

### 4.2 Offline Mode with Local Models

For air-gapped environments and privacy-conscious teams:
- Support Ollama for local model execution
- Ship a fine-tuned LoRA adapter for security classification
- Graceful degradation: regex-only scanning when no LLM available

### 4.3 Agent Memory & Learning

- Cache LLM classifications in `.ship-safe/cache.json`
- When re-scanning, skip findings already classified as FALSE_POSITIVE
- Track user feedback (when users override classifications) to improve prompts
- Share anonymized classification data (opt-in) to improve for all users

---

## Phase 5: Advanced Capabilities (v4.1+)

### 5.1 Live Secret Verification

```bash
ship-safe scan . --verify  # Check if detected secrets are still active
```

For supported providers, make safe API calls to verify if a detected secret is still valid:
- AWS: `sts:GetCallerIdentity`
- GitHub: `GET /user` with token
- OpenAI: `GET /v1/models`
- Stripe: `GET /v1/balance`
- Anthropic: `GET /v1/messages` (dry-run)

This dramatically reduces false positives and prioritizes truly active, exploitable credentials.

### 5.2 Continuous Monitoring Daemon

```bash
ship-safe watch .  # File watcher mode
```

- Watch for file changes using `chokidar`/`fs.watch`
- Incrementally scan only modified files
- Show desktop notifications for new findings
- Run as a background daemon or VS Code extension task

### 5.3 Threat Model Generation

```bash
ship-safe threat-model .  # AI-generated threat model
```

Using the ReconAgent's attack surface map, generate a STRIDE-based threat model:
- **S**poofing: Authentication weaknesses
- **T**ampering: Data integrity issues
- **R**epudiation: Logging and audit gaps
- **I**nformation Disclosure: Data exposure risks
- **D**enial of Service: Resource exhaustion vectors
- **E**levation of Privilege: Authorization flaws

Output as Markdown threat model document that can be reviewed and shared.

### 5.4 Compliance Mapping

Map findings to compliance frameworks:
- **SOC 2** Type II controls
- **HIPAA** technical safeguards
- **PCI-DSS** 4.0 requirements
- **GDPR** Article 32 (security of processing)
- **ISO 27001** Annex A controls

```bash
ship-safe scan . --compliance soc2  # Show SOC 2 mapping
```

### 5.5 Interactive Fix Mode

```bash
ship-safe fix --interactive  # Walk through each finding
```

For each finding, the AI agent:
1. Explains the vulnerability in plain English
2. Shows the vulnerable code with highlighting
3. Proposes a specific fix with a diff preview
4. Asks for confirmation before applying
5. Verifies the fix doesn't break anything (re-scan)
6. Optionally runs related tests

---

## Implementation Roadmap

### v4.0-alpha — Agent Framework & Core Scanners (8-10 weeks)

| Week | Deliverable |
|------|-------------|
| 1-2 | BaseAgent, Orchestrator, ReconAgent |
| 3-4 | InjectionTester, AuthBypassAgent, SSRFProber |
| 5-6 | SupplyChainAudit (EPSS + KEV + lockfile integrity) |
| 7-8 | ConfigAuditor (Dockerfile, vercel.json, next.config.js, GitHub Actions) |
| 9-10 | GitHistoryScanner, CICDScanner |

### v4.0-beta — Scoring & Integration (4-6 weeks)

| Week | Deliverable |
|------|-------------|
| 11-12 | EPSS/KEV scoring engine, expanded score categories |
| 13-14 | SBOM generation (CycloneDX), HTML report output |
| 15-16 | GitHub PR integration, multi-CI templates |

### v4.0-rc — AI & Advanced (4-6 weeks)

| Week | Deliverable |
|------|-------------|
| 17-18 | LLMRedTeam agent, MobileScanner agent |
| 19-20 | Multi-LLM provider support (OpenAI, Ollama, Gemini) |
| 21-22 | APIFuzzer agent, policy-as-code, agent memory |

### v4.0 — Release (2 weeks)

| Week | Deliverable |
|------|-------------|
| 23 | Integration testing, documentation, CHANGELOG |
| 24 | Release v4.0, GitHub Action v2, website update |

### v4.1+ — Post-Release (ongoing)

- Live secret verification
- Continuous monitoring daemon
- Threat model generation
- Compliance mapping
- Interactive fix mode
- VS Code extension
- Web dashboard

---

## New CLI Commands Summary

| Command | Description |
|---------|-------------|
| `ship-safe scan .` | Enhanced: now includes all scanner agents |
| `ship-safe agent .` | Enhanced: multi-agent orchestration with red team |
| `ship-safe recon .` | New: Attack surface discovery and mapping |
| `ship-safe history .` | New: Scan git history for leaked secrets |
| `ship-safe supply-chain .` | New: Comprehensive supply chain audit |
| `ship-safe cicd .` | New: CI/CD pipeline security scan |
| `ship-safe iac .` | New: Infrastructure as Code scanning |
| `ship-safe container .` | New: Dockerfile and container security |
| `ship-safe api .` | New: API endpoint security analysis |
| `ship-safe mobile .` | New: Mobile app security scanning |
| `ship-safe llm .` | New: AI/LLM security audit |
| `ship-safe sbom .` | New: SBOM generation |
| `ship-safe threat-model .` | New: AI-generated threat model |
| `ship-safe watch .` | New: Continuous monitoring mode |
| `ship-safe report .` | New: Generate HTML security report |
| `ship-safe policy init` | New: Create policy-as-code template |

---

## Attack Coverage Matrix

This table shows every major attack class from 2025-2026 threat research and how ship-safe v4.0 addresses it:

| # | Attack Class | OWASP Ref | Ship-Safe Agent | Status |
|---|-------------|-----------|-----------------|--------|
| 1 | Hardcoded secrets / credential leaks | A02, M1 | SecretScanner + GitHistoryScanner | Expand (history) |
| 2 | SQL / NoSQL injection | A05 | InjectionTester | New (data flow) |
| 3 | Command injection | A05 | InjectionTester | Expand |
| 4 | Code injection (eval, Function) | A05 | InjectionTester | Expand |
| 5 | Cross-Site Scripting (XSS) | A05 | InjectionTester | Expand |
| 6 | Server-Side Request Forgery (SSRF) | A01 | SSRFProber | New |
| 7 | Broken access control / BOLA | A01 | AuthBypassAgent | New |
| 8 | Authentication bypass | A07 | AuthBypassAgent | New |
| 9 | JWT algorithm confusion | A07 | AuthBypassAgent | New |
| 10 | OAuth / OIDC misconfiguration | A07 | AuthBypassAgent | New |
| 11 | CSRF | A01 | AuthBypassAgent | New |
| 12 | Session management flaws | A07 | AuthBypassAgent | New |
| 13 | Security misconfiguration | A02, M8 | ConfigAuditor | New |
| 14 | Dockerfile anti-patterns | — | ConfigAuditor | New |
| 15 | Kubernetes misconfig | — | ConfigAuditor | New |
| 16 | Terraform / IaC misconfig | — | ConfigAuditor | New |
| 17 | CI/CD pipeline poisoning | CICD-SEC-4 | CICDScanner | New |
| 18 | GitHub Actions security | CICD-SEC-8 | CICDScanner | New |
| 19 | Dependency confusion | A03 | SupplyChainAudit | New |
| 20 | Typosquatting | A03 | SupplyChainAudit | New |
| 21 | Malicious install scripts | A03 | SupplyChainAudit | New |
| 22 | Known CVE in dependencies | A03 | DepsScanner + EPSS | Expand |
| 23 | Prompt injection (direct) | LLM01 | LLMRedTeam | Expand |
| 24 | Prompt injection (indirect) | LLM01 | LLMRedTeam | New |
| 25 | System prompt leakage | LLM07 | LLMRedTeam | New |
| 26 | LLM output to dangerous sinks | LLM05 | LLMRedTeam | New |
| 27 | Excessive LLM agency | LLM06 | LLMRedTeam | New |
| 28 | RAG / vector poisoning | LLM08 | LLMRedTeam | New |
| 29 | Unbounded LLM consumption | LLM10 | LLMRedTeam | New |
| 30 | API missing authentication | — | APIFuzzer | New |
| 31 | API missing rate limiting | — | APIFuzzer | New |
| 32 | CORS misconfiguration | A02 | APIFuzzer | Expand |
| 33 | GraphQL introspection/depth | — | APIFuzzer | New |
| 34 | Mass assignment | — | APIFuzzer | New |
| 35 | Excessive data exposure | — | APIFuzzer | New |
| 36 | File upload vulnerabilities | — | APIFuzzer | New |
| 37 | Mobile hardcoded credentials | M1 | MobileScanner | New |
| 38 | Insecure mobile communication | M5 | MobileScanner | New |
| 39 | Insecure mobile data storage | M9 | MobileScanner | New |
| 40 | Missing certificate pinning | M5 | MobileScanner | New |
| 41 | Weak cryptography | A04, M10 | VulnScanner | Existing |
| 42 | Insecure deserialization | A08 | VulnScanner | Existing |
| 43 | Insufficient logging | A09 | ConfigAuditor | New |
| 44 | Error information leakage | A10 | APIFuzzer | New |
| 45 | Open redirect | A01 | InjectionTester | New |
| 46 | Clickjacking (missing X-Frame-Options) | A02 | ConfigAuditor | Expand |
| 47 | Missing security headers | A02 | ConfigAuditor | Expand |
| 48 | TLS misconfiguration | A04, M5 | ConfigAuditor | Expand |
| 49 | Cloud metadata exposure | A01 | SSRFProber | New |
| 50 | Container escape risks | — | ConfigAuditor | New |

**Total coverage: 50 attack classes across 12 specialized agents.**

---

## Technical Requirements

### Runtime
- Node.js 18+ (existing)
- Optional: Docker (for container scanning)
- Optional: Git (for history scanning — already required)

### New Dependencies (minimal)
- `@cyclonedx/bom` — SBOM generation
- `chokidar` — File watching (for `watch` command)
- `semver` — Version comparison for dependency analysis
- No new heavy dependencies — maintain the lightweight philosophy

### API Integrations (optional, for enhanced features)
- FIRST EPSS API — Exploitation probability scoring
- CISA KEV API — Known exploited vulnerabilities
- OSV.dev API — Vulnerability database
- NVD API — CVE details (fallback)

### Performance Targets
- Full scan of 10,000-file project: < 30 seconds (without AI)
- Incremental scan (watch mode): < 2 seconds per file change
- AI-enhanced scan: < 3 minutes (depends on LLM provider)
- SBOM generation: < 10 seconds

---

## Security of Ship-Safe Itself

Ship-safe must be secure in its own operation:

1. **No telemetry by default** — All data stays local unless user explicitly opts in
2. **No network calls in scan mode** — Only `agent`, `deps`, and `--verify` make network requests
3. **Secrets in transit** — When sending code context to LLM, strip actual secret values and replace with `[REDACTED]`
4. **Atomic file operations** — All file modifications use atomic writes (existing)
5. **No eval/exec** — Ship-safe itself must not use `eval()`, `Function()`, or `child_process.exec()` with user input
6. **Dependency minimalism** — Keep the dependency tree minimal to reduce supply chain risk
7. **SBOM for ship-safe itself** — Publish a CycloneDX SBOM with each release
8. **Signed releases** — NPM provenance attestation on published packages

---

## Success Metrics

| Metric | v3.2.0 (Current) | v4.0 (Target) |
|--------|-------------------|----------------|
| Secret patterns | 70+ | 100+ |
| Vulnerability patterns | 18 | 200+ (across all agents) |
| Attack classes covered | ~10 | 50 |
| Supported frameworks | 5 | 15+ |
| OWASP Top 10 coverage | 40% | 95% |
| OWASP Mobile Top 10 coverage | 0% | 80% |
| OWASP LLM Top 10 coverage | 30% | 90% |
| OWASP CI/CD Top 10 coverage | 0% | 80% |
| False positive rate | ~15% | < 5% (with AI) |
| LLM providers supported | 1 (Anthropic) | 4 (Anthropic, OpenAI, Google, Ollama) |
| Output formats | 4 (CLI, JSON, SARIF, table) | 7 (+HTML, SBOM, PR comment) |
| CI/CD platforms | 1 (GitHub) | 5 |

---

## Sources

### OWASP Standards
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP Mobile Top 10:2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP LLM Top 10:2025](https://genai.owasp.org/llm-top-10/)
- [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

### Threat Intelligence
- [Unit 42 - NPM Supply Chain Attacks 2025](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [CISA - Widespread Supply Chain Compromise](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Wiz - Kubernetes Security Report 2025](https://www.wiz.io/reports/kubernetes-security-report-2025)
- [Wiz - State of Code Security 2025](https://www.wiz.io/reports/state-of-code-security-2025)
- [HackerNews - 400 IPs Exploiting SSRF](https://thehackernews.com/2025/03/over-400-ips-exploiting-multiple-ssrf.html)
- [Unit 42 - Social Engineering Report 2025](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

### Tool Research
- [OpenAI Aardvark - Agentic Security Researcher](https://openai.com/index/introducing-aardvark/)
- [Semgrep Supply Chain](https://semgrep.dev/products/semgrep-supply-chain)
- [FIRST EPSS Scoring](https://www.first.org/epss/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
