<p align="center">
  <img src=".github/assets/logo%20ship%20safe.png" alt="Ship Safe Logo" width="180" />
</p>
<p align="center"><strong>AI-powered application security platform for developers.</strong></p>
<p align="center"><a href="https://shipsafecli.com">shipsafecli.com</a></p>

<p align="center">
  <a href="https://www.npmjs.com/package/ship-safe"><img src="https://badge.fury.io/js/ship-safe.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/ship-safe"><img src="https://img.shields.io/npm/dm/ship-safe.svg" alt="npm downloads" /></a>
  <a href="https://github.com/asamassekou10/ship-safe/actions/workflows/ci.yml"><img src="https://github.com/asamassekou10/ship-safe/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/node/v/ship-safe" alt="Node.js version" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://github.com/asamassekou10/ship-safe/stargazers"><img src="https://img.shields.io/github/stars/asamassekou10/ship-safe?style=social" alt="GitHub stars" /></a>
  <a href="https://github.com/sponsors/asamassekou10"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github" alt="Sponsor" /></a>
</p>

---

23 security agents. 80+ attack classes. One command.

**Ship Safe v9.2.1** is an AI-powered security platform that runs 23 specialized agents in parallel against your codebase — covering secrets, injection vulnerabilities, auth bypass, SSRF, supply chain attacks, AI integration supply chain (Vercel-class attacks), memory poisoning, Hermes Agent security, Supabase RLS, Docker/Terraform/Kubernetes misconfigs, CI/CD pipeline poisoning, LLM/agentic AI security, MCP server misuse, RAG poisoning, PII compliance, vibe coding patterns, exception handling, Claude Managed Agent configs, and more. Full OWASP Agentic AI Top 10 mapping (ASI-01–ASI-10) enriches every finding. Live OSV.dev advisory feed surfaces actively exploited CVEs within hours of disclosure. OWASP 2025 scoring with EPSS exploit probability. LLM-powered deep analysis verifies exploitability of critical findings. Secrets verification probes provider APIs to check if leaked keys are still active.

**v9.2.0:** **Ship Safe is now an agent.** Type `ship-safe` and you drop into an interactive REPL. Run `/agent` to scan, plan, and fix — the agent shows a diff for every proposed change, asks before writing, verifies the fix worked, and logs every edit to `.ship-safe/fixes.jsonl`. `/undo` reverses any fix. `--branch` isolates fixes on a git branch; `--pr` opens a pull request automatically. Multi-file plans coordinate source changes with `.env.example` and `.gitignore` updates in a single accept/skip decision. Exit with `/quit`, `Ctrl-D`, or `Ctrl-C`.

**v9.1.0:** **AgenticSupplyChainAgent & Vercel Breach Checker** — new 23rd agent detects AI integration supply chain attacks (Vercel-class): unpinned AI CI actions, OAuth scope abuse in platform integrations, unsigned webhook handlers, and MCP/Hermes cross-boundary token forwarding.

**v9.0.0:** **Agent Studio, Teams & Findings** — the web dashboard is now a full AI security operations platform. **Agent Studio** lets you build, configure, and deploy custom Hermes security agents from the UI — give each agent a role, tools, and memory, then deploy to a live container in one click. **Agent Teams** orchestrate multiple specialist agents under a lead agent that plans, delegates tasks in parallel, and synthesises an executive security report.

[Documentation](https://shipsafecli.com/docs) | [Blog](https://shipsafecli.com/blog) | [Pricing](https://shipsafecli.com/pricing)

---

## Quick Start

```bash
# Drop into the interactive REPL — scan, fix, ask questions in one session
npx ship-safe

# Interactive agent: scan → plan → diff → accept → verify → undo if needed
npx ship-safe agent .
npx ship-safe agent . --severity critical   # only critical findings
npx ship-safe agent . --branch --pr         # fix on a branch + open a PR
npx ship-safe agent . --yolo                # unattended / CI mode

# Undo the last fix (or all fixes)
npx ship-safe undo
npx ship-safe undo --all

# Full security audit — secrets + 23 agents + deps + remediation plan
npx ship-safe audit .

# LLM-powered deep analysis (Anthropic, OpenAI, Google, Ollama, Gemma 4)
npx ship-safe audit . --deep

# Agentic loop — scan → auto-annotate fixes → re-scan until score ≥ 75
npx ship-safe audit . --agentic
npx ship-safe audit . --agentic 5 --agentic-target 85

# Red team scan (23 agents, 80+ attack classes)
npx ship-safe red-team .

# Scan only changed files (fast pre-commit & PR scanning)
npx ship-safe diff
npx ship-safe diff --staged

# Live OSV.dev advisory feed — no API key, no stale data
npx ship-safe advisories .

# Continuous monitoring
npx ship-safe watch .                         # Lightweight file watcher
npx ship-safe watch . --deep                  # Full 23-agent scan on every change
npx ship-safe watch . --deep --threshold 80   # Fail if score drops below threshold
npx ship-safe watch . --status                # Show last deep-watch results

# Fun emoji security grade with shareable badge
npx ship-safe vibe-check .

# Compare your score against industry averages
npx ship-safe benchmark .

# Quick secret scan
npx ship-safe scan .

# Security health score (0-100)
npx ship-safe score .

# CI/CD pipeline mode — compact output, exit codes, PR comments
npx ship-safe ci .
npx ship-safe ci . --github-pr

# Accept current findings, only report regressions
npx ship-safe baseline .
npx ship-safe audit . --baseline

# Check if leaked secrets are still active
npx ship-safe audit . --verify

# Environment diagnostics
npx ship-safe doctor

# Install Claude Code hooks — real-time secret blocking + advisory scan
npx ship-safe hooks install
npx ship-safe hooks status
npx ship-safe hooks remove
```

---

## The `audit` Command

One command that runs everything and generates a full report:

```bash
npx ship-safe audit .
```

```
════════════════════════════════════════════════════════════
  Ship Safe v9.0 — Full Security Audit
════════════════════════════════════════════════════════════

  [Phase 1/4] Scanning for secrets...         ✔ 49 found
  [Phase 2/4] Running 23 security agents...   ✔ 103 findings
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
2. **23 security agents** — run in parallel with per-agent timeouts and framework-aware filtering
3. **Dependency audit** — npm/pip/bundler CVE scanning with EPSS exploit probability scores
4. **Secrets verification** — probes provider APIs (GitHub, Stripe, OpenAI, etc.) to check if leaked keys are still active
5. **Deep analysis** — LLM-powered taint analysis verifies exploitability of critical/high findings (optional)
6. **Score computation** — OWASP 2025 weighted scoring across 8 categories (0-100, A-F)
7. **Context-aware confidence tuning** — downgrades findings in test files, docs, and comments
8. **Compliance mapping** — maps findings to SOC 2 Type II, ISO 27001:2022, and NIST AI Risk Management Framework controls
9. **Remediation plan** — prioritized fix list grouped by severity
10. **Interactive HTML report** — standalone dark-themed report with severity filtering, search, collapsible findings, compliance summary, and click-to-copy ignore annotations

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
- `--provider <name>` — LLM provider: groq, together, mistral, deepseek, xai, perplexity, lmstudio, gemma4
- `--base-url <url>` — custom OpenAI-compatible base URL (e.g. LM Studio, vLLM)
- `--budget <cents>` — max spend in cents for deep analysis (default: 50)
- `--verify` — check if leaked secrets are still active (probes provider APIs)
- `--agentic [n]` — scan → annotate fixes → re-scan loop, up to n iterations (default: 3)
- `--agentic-target <score>` — stop agentic loop when score reaches this threshold (default: 75)

---

## 23 Security Agents

| Agent | Category | What It Detects |
|-------|----------|-----------------|
| **InjectionTester** | Code Vulns | SQL/NoSQL injection, command injection, code injection (eval), XSS, path traversal, XXE, ReDoS, prototype pollution, Python f-string SQL injection, Python subprocess shell injection |
| **AuthBypassAgent** | Auth | JWT vulnerabilities (alg:none, weak secrets), cookie security, CSRF, OAuth misconfig, BOLA/IDOR, weak crypto, timing attacks, TLS bypass, Django `DEBUG = True`, Flask hardcoded secret keys |
| **SSRFProber** | SSRF | User input in fetch/axios, cloud metadata endpoints, internal IPs, redirect following |
| **SupplyChainAudit** | Supply Chain | Typosquatting (Levenshtein distance), git/URL dependencies, wildcard versions, suspicious install scripts, dependency confusion, lockfile integrity, trojanized package behavioral signatures (env-var harvesting, DNS exfiltration, WebSocket C2) |
| **ConfigAuditor** | Config | Dockerfile (running as root, :latest tags), Terraform (public S3/RDS, open SG, CloudFront HTTP, Lambda admin, S3 no versioning), Kubernetes (privileged containers, `:latest` tags, missing NetworkPolicy), CORS, CSP, Firebase, Nginx |
| **SupabaseRLSAgent** | Auth | Supabase Row Level Security — `service_role` key in client code, `CREATE TABLE` without RLS, anon key inserts, unprotected storage operations |
| **LLMRedTeam** | AI/LLM | OWASP LLM Top 10 — prompt injection, excessive agency, system prompt leakage, unbounded consumption, RAG poisoning |
| **MCPSecurityAgent** | AI/LLM | MCP server security — unvalidated tool inputs, missing auth, excessive permissions, tool poisoning, typosquatting detection, over-permissioned tools, shadow config discovery |
| **AgenticSecurityAgent** | AI/LLM | OWASP Agentic AI Top 10 — agent hijacking, privilege escalation, unsafe code execution, memory poisoning |
| **RAGSecurityAgent** | AI/LLM | RAG pipeline security — unvalidated embeddings, context injection, document poisoning, vector DB access control |
| **MemoryPoisoningAgent** | AI/LLM | ASI-01/ASI-05 — instruction injection in `.claude/memory/`, `.cursorrules`, `.cursor/rules/`, `.windsurfrules`, `.continue/config.json`, `.gemini/`, `.cody/`, `.augment/` and docs; hidden Unicode payloads; persona hijacking; persistent trigger detection |
| **PIIComplianceAgent** | Compliance | PII detection — SSNs, credit cards, emails, phone numbers in source code, logs, and configs |
| **VibeCodingAgent** | Code Vulns | AI-generated code patterns — no input validation, empty catch blocks, hardcoded secrets, disabled security features, TODO-auth patterns |
| **ExceptionHandlerAgent** | Code Vulns | OWASP A10:2025 — empty catch blocks, unhandled promise rejections, missing React error boundaries, leaked stack traces, generic catch-all without rethrow |
| **AgentConfigScanner** | AI/LLM | AI agent config security — prompt injection in .cursorrules/CLAUDE.md/AGENTS.md/.windsurfrules, malicious Claude Code hooks (CVE-2026), OpenClaw public binding & malicious skills, claw-code config risks, Gemini CLI / Cody / Augment Code config risks, encoded/obfuscated payloads |
| **MobileScanner** | Mobile | OWASP Mobile Top 10 2024 — insecure storage, WebView JS injection, HTTP endpoints, excessive permissions, debug mode |
| **GitHistoryScanner** | Secrets | Leaked secrets in git commit history (checks if still active in working tree) |
| **CICDScanner** | CI/CD | OWASP CI/CD Top 10 — pipeline poisoning, unpinned actions, secret logging, self-hosted runners, script injection, AI agent danger flags |
| **APIFuzzer** | API | Routes without auth, missing input validation, mass assignment, unrestricted file upload, GraphQL introspection, debug endpoints, missing rate limiting, OpenAPI spec security issues |
| **ManagedAgentScanner** | AI/LLM | Claude Managed Agents misconfigurations — `always_allow` permission policies, unrestricted networking, bash without human confirmation, MCP servers over HTTP, hardcoded vault tokens, unpinned environment packages (ASI-03, ASI-04, ASI-05, ASI-07) |
| **HermesSecurityAgent** | AI/LLM | Hermes Agent deployments — tool registry poisoning, function-call injection (`<tool_call>` / `<function_calls>`), goal/plan hijacking, memory layer attacks, skill permission drift, sub-agent trust boundary violations, manifest attestation (ASI-01–ASI-10) |
| **AgentAttestationAgent** | Supply Chain | Agent manifest supply chain — unpinned versions (`latest`, `^`, `~`), missing integrity hashes on remote tool sources, unsigned manifests, `skipIntegrityCheck` bypass, dynamic `require()` of manifests from env vars, missing provenance fields (ASI-10, SLSA Level 0) |
| **AgenticSupplyChainAgent** *(new)* | Supply Chain | AI integration supply chain — over-privileged AI CI actions (Vercel/GitHub/Netlify), OAuth scope creep in AI platform integrations, unsigned AI webhook receivers (missing HMAC), MCP/Hermes cross-boundary token forwarding to third-party servers (ASI-02, ASI-06, ASI-09, CICD-SEC-8) |

**Post-processors:** ScoringEngine (8-category weighted scoring with OWASP Agentic AI Top 10 enrichment), VerifierAgent (secrets liveness verification), DeepAnalyzer (LLM-powered taint analysis)

---

## All Commands

### Core Audit Commands

```bash
# Full audit with remediation plan + HTML report
npx ship-safe audit .

# Red team: 23 agents, 80+ attack classes
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

### Interactive Agent & REPL

```bash
# Drop into the REPL (bare invocation on a TTY)
npx ship-safe

# Explicit shell command
npx ship-safe shell .

# Interactive fix agent: scan → plan → diff → [a]ccept/[s]kip/[e]dit/[q]uit → verify
npx ship-safe agent .
npx ship-safe agent . --plan-only           # preview plans, write nothing
npx ship-safe agent . --severity critical   # only critical findings
npx ship-safe agent . --branch              # commit fixes on a new git branch
npx ship-safe agent . --branch --pr         # push branch + open a PR via gh
npx ship-safe agent . --yolo --branch       # unattended CI mode
npx ship-safe agent . --auto-low            # auto-accept low-risk plans only

# Undo fixes
npx ship-safe undo          # revert last fix
npx ship-safe undo --all    # revert everything in fixes.jsonl
npx ship-safe undo --dry-run

# REPL slash commands
#   /scan            Re-scan the project
#   /agent           Run the fix loop
#   /findings        List findings
#   /show <n>        Detail on finding n
#   /plan <n>        Preview fix plan for finding n
#   /undo            Revert last fix
#   /diff            Show git working-tree diff
#   /provider <name> Switch LLM provider mid-session
#   /quit            Exit  (also Ctrl-D or Ctrl-C)

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

### Diff Scanning

```bash
# Scan only changed files (fast pre-commit & PR scanning)
npx ship-safe diff                   # All uncommitted changes
npx ship-safe diff --staged          # Only staged changes
npx ship-safe diff HEAD~3            # Changes in last 3 commits
npx ship-safe diff --json            # JSON output
```

### Vibe Check & Benchmark

```bash
# Fun emoji security grade
npx ship-safe vibe-check .
npx ship-safe vibe-check . --badge   # Generate shields.io README badge

# Compare your score against industry averages (OWASP, Synopsys, Snyk)
npx ship-safe benchmark .
npx ship-safe benchmark . --json     # JSON output
```

### CI/CD Pipeline

```bash
# CI mode — compact output, exit codes, threshold gating
npx ship-safe ci .
npx ship-safe ci . --threshold 80    # Custom passing score
npx ship-safe ci . --fail-on critical # Fail on severity
npx ship-safe ci . --sarif out.sarif  # SARIF for GitHub
npx ship-safe ci . --github-pr       # Post results as PR comment
```

### Deep Analysis & Verification

```bash
# LLM-powered deep analysis (Anthropic/OpenAI/Google/Ollama)
npx ship-safe audit . --deep
npx ship-safe audit . --deep --local               # Use local Ollama
npx ship-safe audit . --deep --budget 50           # Cap spend at 50 cents

# Use any OpenAI-compatible provider for deep analysis
npx ship-safe audit . --deep --provider groq
npx ship-safe audit . --deep --provider together
npx ship-safe audit . --deep --provider mistral
npx ship-safe audit . --deep --provider deepseek
npx ship-safe audit . --deep --provider lmstudio   # Local LM Studio
npx ship-safe audit . --deep --provider xai
npx ship-safe audit . --deep --provider perplexity
npx ship-safe audit . --deep --base-url http://localhost:1234/v1 --model my-model  # Custom

# Check if leaked secrets are still active
npx ship-safe audit . --verify
```

### Diagnostics

```bash
# Environment check — Node.js, git, npm, API keys, cache, version
npx ship-safe doctor
```

### Agent Security

```bash
# Focused OpenClaw security scan
npx ship-safe openclaw .

# Auto-harden OpenClaw configs (0.0.0.0->127.0.0.1, add auth, ws->wss)
npx ship-safe openclaw . --fix

# Red team: simulate ClawJacked, prompt injection, data exfil attacks
npx ship-safe openclaw . --red-team

# CI preflight — exit non-zero on critical findings
npx ship-safe openclaw . --preflight

# Scan a skill before installing it
npx ship-safe scan-skill https://clawhub.io/skills/some-skill
npx ship-safe scan-skill ./local-skill.json
npx ship-safe scan-skill --all              # Scan all skills from openclaw.json

# Scan an MCP server's tool manifest before connecting
npx ship-safe scan-mcp https://your-mcp-server/
npx ship-safe scan-mcp ./local-manifest.json
npx ship-safe scan-mcp https://your-mcp-server/ --json

# Legal risk audit — DMCA, leaked-source derivatives (openclaude, claw-code-js), IP disputes
npx ship-safe legal .

# Generate hardened OpenClaw config
npx ship-safe init --openclaw

# Generate Agent Bill of Materials (CycloneDX 1.5)
npx ship-safe abom .
```

#### openclaude and claw-code

Ship Safe detects security issues in both major Claude Code forks from the March 2026 source leak.

**openclaude** (`@gitlawb/openclaude`) is a CLI tool that routes Claude Code's toolset through any OpenAI-compatible provider. Its only persistent file artifact is `.openclaude-profile.json`. Ship Safe flags:
- `OPENAI_BASE_URL` using `http://` for non-localhost endpoints (unencrypted LLM traffic)
- The profile file present in a project not covered by `.gitignore` (API key exposure risk)

**claw-code** (`ultraworkers/claw-code`) is a clean-room Rust + Python rewrite of Claude Code's agent harness. Its config lives in `.claw.json`, `.claw/settings.json`, and `.claw/settings.local.json`. Ship Safe flags:
- `permissionMode: danger-full-access` or `dangerouslySkipPermissions: true` (no confirmation on any tool call)
- `sandbox.enabled: false` (filesystem isolation removed)
- Hook commands containing shell execution or remote download patterns
- MCP server connections over `ws://` or `http://` to non-localhost hosts

### Hermes Agent Integration

Ship Safe is a first-class Hermes Agent citizen. Register Ship Safe tools directly in your Hermes tool registry:

```js
import { registerWithHermes, verifyIntegrity } from 'ship-safe';

// Register all 5 Ship Safe tools with integrity verification
await registerWithHermes(toolRegistry);
```

Or use the bundled skill in your Hermes agent:

```yaml
# In your Hermes agent manifest
skills:
  - ./node_modules/ship-safe/skills/ship-safe-security.md
```

Available tools: `ship_safe_audit`, `ship_safe_scan_mcp`, `ship_safe_get_findings`, `ship_safe_suppress_finding`, `ship_safe_memory_list`.

### Threat Intelligence

```bash
# Update threat intel feed (ClawHavoc IOCs, malicious skills, config signatures)
npx ship-safe update-intel

# Ships with offline-first seed data — no internet required for scanning
```

### OpenClaw GitHub Action

Drop-in CI action that blocks PRs introducing agent config vulnerabilities:

```yaml
# .github/workflows/openclaw-security.yml
name: OpenClaw Security Check

on: [pull_request]

permissions:
  contents: read

jobs:
  openclaw:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: asamassekou10/ship-safe/.github/actions/openclaw-check@main
        with:
          fail-on-critical: 'true'
```

**Inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `fail-on-critical` | `true` | Fail the check if critical findings are found |
| `node-version` | `20` | Node.js version to use |

**Outputs:**

| Output | Description |
|--------|-------------|
| `findings` | Total number of findings detected |
| `critical` | Number of critical findings |

Scans `openclaw.json`, `.cursorrules`, `CLAUDE.md`, Claude Code hooks, and MCP configs. Checks against the bundled threat intelligence database for known ClawHavoc IOCs.

### Live Advisory Feed

```bash
# Query OSV.dev for actively exploited CVEs across all package ecosystems
npx ship-safe advisories .
npx ship-safe advisories . --json    # JSON output for CI
```

No API key required. Malware advisories (MAL-*) are sorted to the top. Results include EPSS exploit probability and remediation guidance.

### Defensive Hooks

```bash
# Install Claude Code defensive hooks (blocks curl|bash, exfil domains, rm -rf /)
npx ship-safe guard --generate-hooks

# Watch agent config files for drift (.cursorrules, CLAUDE.md, openclaw.json)
npx ship-safe watch . --configs
```

### Infrastructure Commands

```bash
# Lightweight file watcher — re-scans changed files on save
npx ship-safe watch .

# Deep watch — full 23-agent orchestrator on every change
npx ship-safe watch . --deep
npx ship-safe watch . --deep --threshold 80   # Fail if score drops below threshold
npx ship-safe watch . --deep --debounce 2000  # Custom debounce in ms (default: 1000)
npx ship-safe watch . --status                # Show last deep-watch results from .ship-safe/watch.json

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

## Claude Code Hooks

Install ship-safe as real-time Claude Code hooks — secrets are blocked **before** they ever touch disk:

```bash
npx ship-safe hooks install
```

Once installed, two hooks activate automatically on every Claude Code session:

| Hook | Trigger | Behaviour |
|------|---------|-----------|
| **PreToolUse** | Write / Edit / MultiEdit / Bash | Blocks the write if critical secrets are detected; blocks dangerous Bash patterns (curl\|bash, credential exfiltration, `rm -rf /`) |
| **PostToolUse** | Write / Edit / MultiEdit | Scans the saved file and injects advisory findings (high-severity patterns, DB URLs with credentials) directly into Claude's context — never blocks |

Hook scripts are copied to `~/.ship-safe/hooks/` at install time — a stable, user-owned location that survives `npx` cache rotations.

```bash
npx ship-safe hooks status   # Check installation
npx ship-safe hooks remove   # Uninstall
```

---

## Claude Code Plugin

Use Ship Safe directly inside Claude Code — no CLI needed:

```bash
claude plugin add github:asamassekou10/ship-safe
```

| Command | Description |
|---------|-------------|
| `/ship-safe` | Full security audit — 23 agents, remediation plan, auto-fix |
| `/ship-safe-scan` | Quick scan for leaked secrets |
| `/ship-safe-score` | Security health score (0-100) |
| `/ship-safe-deep` | LLM-powered deep taint analysis |
| `/ship-safe-ci` | CI/CD pipeline setup guide |
| `/ship-safe-hooks` | Install real-time Claude Code hooks (blocks secrets on write) |
| `/ship-safe-baseline` | Accept current findings as baseline; report only regressions |
| `/ship-safe-fix` | Auto-fix secrets and common vulnerabilities |
| `/ship-safe-red-team` | Run full red-team audit and open HTML report |

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

Ship Safe supports any AI provider for deep analysis and classification:

| Provider | Env Variable | Flag | Default Model |
|----------|-------------|------|---------------|
| **Anthropic** | `ANTHROPIC_API_KEY` | *(auto-detected)* | claude-haiku-4-5 |
| **OpenAI** | `OPENAI_API_KEY` | *(auto-detected)* | gpt-4o-mini |
| **Google** | `GOOGLE_AI_API_KEY` | *(auto-detected)* | gemini-2.0-flash |
| **Gemma 4 (Ollama)** | *(none)* | `--provider gemma4` | gemma4:e4b (256K ctx) |
| **Ollama** | `OLLAMA_HOST` | `--local` | gemma4:e4b |
| **Groq** | `GROQ_API_KEY` | `--provider groq` | llama-3.3-70b-versatile |
| **Together AI** | `TOGETHER_API_KEY` | `--provider together` | meta-llama/Llama-3-70b-chat-hf |
| **Mistral** | `MISTRAL_API_KEY` | `--provider mistral` | mistral-small-latest |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `--provider deepseek` | deepseek-chat |
| **xAI (Grok)** | `XAI_API_KEY` | `--provider xai` | grok-beta |
| **Perplexity** | `PERPLEXITY_API_KEY` | `--provider perplexity` | llama-3.1-sonar-small-128k-online |
| **LM Studio** | *(none)* | `--provider lmstudio` | Local server |
| **Custom** | *(any)* | `--base-url <url> --model <model>` | Any OpenAI-compatible |

Auto-detected from environment variables. Use `--provider <name>` to override. No API key required for scanning — AI is optional.

---

## Scoring System

Starts at 100. Each finding deducts points by severity and category, weighted by confidence level (high: 100%, medium: 60%, low: 30%) to reduce noise from heuristic patterns.

**8 Categories** (with weight caps):

| Category | Weight | Critical | High | Medium | Cap |
|----------|--------|----------|------|--------|-----|
| Secrets | 15% | -25 | -15 | -5 | -15 |
| Code Vulnerabilities | 15% | -20 | -10 | -3 | -15 |
| Dependencies | 13% | -20 | -10 | -5 | -13 |
| Auth & Access Control | 15% | -20 | -10 | -3 | -15 |
| Configuration | 8% | -15 | -8 | -3 | -8 |
| Supply Chain | 12% | -15 | -8 | -3 | -12 |
| API Security | 10% | -15 | -8 | -3 | -10 |
| AI/LLM Security | 12% | -15 | -8 | -3 | -12 |

*Weights aligned with OWASP Top 10 2025 risk rankings.*

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
        run: npx ship-safe ci . --threshold 75 --sarif results.sarif --github-pr

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
| **OWASP Agentic AI Top 10** | ASI-01–ASI-10: Goal Hijacking, Excessive Agency, Unsafe Tool Use, Unvalidated Actions, Untrusted Tools, Memory Poisoning, Lack of Oversight, Logging Gaps, Supply Chain Attacks, Cascading Failures |

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

### [`/skills`](./skills)
Hermes Agent skill definitions. Install `skills/ship-safe-security.md` to give any Hermes agent native security scanning capabilities.

---

## Add a Security Badge to Your README

Show the world your project is secure. After running `npx ship-safe audit .` or `npx ship-safe vibe-check . --badge`, add one of these to your README:

```markdown
<!-- Replace GRADE and COLOR with your results -->
[![Ship Safe](https://img.shields.io/badge/Ship_Safe-A+-22c55e)](https://shipsafecli.com)
```

| Grade | Badge |
|-------|-------|
| A+ | `[![Ship Safe](https://img.shields.io/badge/Ship_Safe-A+-22c55e)](https://shipsafecli.com)` |
| A | `[![Ship Safe](https://img.shields.io/badge/Ship_Safe-A-22c55e)](https://shipsafecli.com)` |
| B | `[![Ship Safe](https://img.shields.io/badge/Ship_Safe-B-06b6d4)](https://shipsafecli.com)` |
| C | `[![Ship Safe](https://img.shields.io/badge/Ship_Safe-C-eab308)](https://shipsafecli.com)` |
| D | `[![Ship Safe](https://img.shields.io/badge/Ship_Safe-D-ef4444)](https://shipsafecli.com)` |
| F | `[![Ship Safe](https://img.shields.io/badge/Ship_Safe-F-dc2626)](https://shipsafecli.com)` |

---

## Supply Chain Hardening

Ship Safe practices what it preaches. Our own supply chain is hardened against the [2026 Trivy/CanisterWorm attack chain](https://shipsafecli.com/blog/supply-chain-attacks-2026-how-we-hardened-ship-safe):

| Defense | What It Blocks |
|---------|---------------|
| All GitHub Actions pinned to full commit SHAs | Tag repointing (Trivy-style) |
| `permissions: contents: read` in CI | Excessive token scope |
| `npm ci --ignore-scripts` in all pipelines | CanisterWorm postinstall propagation |
| OIDC trusted publishing with provenance | Stolen npm token publishing |
| CODEOWNERS on `action.yml`, `.github/`, `package.json` | Unauthorized changes to critical paths |
| Strict `files` allowlist in package.json | Accidental inclusion of secrets/configs |
| Self-scanning with ship-safe in CI | Malicious code injection |
| 5 direct dependencies | Minimal transitive attack surface |

Verify provenance on any Ship Safe release:

```bash
npm audit signatures
```

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

## Sponsors

Ship Safe is MIT-licensed and free forever. If it saves you time or helps you ship more securely, consider sponsoring — it helps keep the project maintained and growing.

<p align="center">
  <a href="https://github.com/sponsors/asamassekou10">
    <img src="https://img.shields.io/badge/Sponsor%20Ship%20Safe-%E2%9D%A4-ea4aaa?style=for-the-badge&logo=github" alt="Sponsor Ship Safe" />
  </a>
</p>

---

## License

MIT - Use it, share it, secure your stuff.

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=asamassekou10/ship-safe&type=Date)](https://star-history.com/#asamassekou10/ship-safe&Date)

---

**Ship fast. Ship safe.** — [shipsafecli.com](https://shipsafecli.com)
