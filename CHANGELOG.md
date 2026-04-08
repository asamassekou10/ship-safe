# Changelog

All notable changes to ship-safe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [7.1.0] — 2026-04-08

### Added

- **`ManagedAgentScanner`** — new 20th scanning agent purpose-built for Claude Managed Agents configuration security. Anthropic's Managed Agents platform (beta, April 2026) runs Claude in cloud containers with bash, file system access, and web browsing. The default configuration is maximally permissive: all 8 tools enabled, `always_allow` permission policy, and unrestricted outbound networking. This agent detects 12 classes of misconfiguration across every security-relevant surface in the Managed Agents API.

  Detection rules:

  | Rule | Severity | OWASP |
  |------|----------|-------|
  | `MANAGED_AGENT_ALWAYS_ALLOW` | critical | ASI-03 |
  | `MANAGED_AGENT_BASH_NO_CONFIRM` | critical | ASI-03 |
  | `MANAGED_AGENT_ALL_TOOLS_DEFAULT` | high | ASI-05 |
  | `MANAGED_AGENT_MCP_ALWAYS_ALLOW` | high | ASI-05 |
  | `MANAGED_AGENT_UNRESTRICTED_NET` | high | ASI-04 |
  | `MANAGED_AGENT_NO_NETWORK_LIMIT` | medium | ASI-04 |
  | `MANAGED_AGENT_MCP_HTTP` | critical | ASI-04 |
  | `MANAGED_AGENT_CALLABLE_AGENTS` | medium | ASI-03 |
  | `MANAGED_AGENT_NO_SYSTEM_PROMPT` | low | ASI-07 |
  | `MANAGED_AGENT_HARDCODED_TOKEN` | critical | ASI-04 |
  | `MANAGED_AGENT_STATIC_BEARER_INLINE` | critical | ASI-04 |
  | `MANAGED_AGENT_UNPINNED_PACKAGE` | medium | ASI-04 |

  The scanner uses a relevance signal check (API calls, SDK usage, `agent_toolset_20260401` references) before running patterns, so it adds zero overhead to projects not using Managed Agents.

- **Blog post** — "Scanning Claude Managed Agents: 12 Security Rules for the OWASP Agentic Top 10" covering the full config schema, dangerous defaults, and a secure-by-default configuration checklist.

- **Webapp updates** — new FAQ entry, 4 new ThreatMarquee entries, updated JSON-LD structured data, agent count bumped to 20 throughout.

### Changed

- Agent pool bumped from 19 to 20 agents in `buildOrchestrator()`.
- `package.json` version bumped to `7.1.0`, description updated.
- README: all "19 agents" references updated to 20, v7.1.0 highlights added, ManagedAgentScanner added to the agent table.

---

## [6.4.0] — 2026-04-01

### Added

- **`ship-safe scan-mcp [target]`** — new command that fetches and analyzes an MCP server's tool manifest before you connect to it. Accepts a remote URL (queries `tools/list` via JSON-RPC 2.0, with fallbacks to `GET /tools` and root endpoint) or a local manifest file. Checks every tool definition for prompt injection in descriptions, silent exfiltration instructions, credential harvesting patterns, sensitive path references, output suppression, permission escalation, known exfiltration service domains, dangerous tool names (`exec`, `shell`, `bash`, `run_command`), unsafe input schema parameters (`command`, `code`, `script`, `eval`), and tools requiring sensitive credential parameters. Runs threat intel hash and signature matching on the full manifest. Exits non-zero on critical findings for use in CI. `--json` flag for machine-readable output.

- **openclaude detection** — `AgentConfigScanner` now detects `.openclaude-profile.json` (the only persistent file openclaude creates) and flags `OPENAI_BASE_URL` values using plain `http://` for non-localhost endpoints. This covers the real security surface of openclaude: a CLI tool whose config is env-var-only, with the profile file as the sole file artifact. Corrects earlier detection rules that were based on a server architecture openclaude does not have.

- **claw-code detection** — `AgentConfigScanner` now scans `.claw.json`, `.claw/settings.json`, and `.claw/settings.local.json` (the actual config files used by the claw-code Rust/Python rewrite). Detects: `permissionMode: danger-full-access` or `dangerouslySkipPermissions: true` (disables all confirmation dialogs), `sandbox.enabled: false` (removes filesystem isolation), hook commands containing shell execution or remote download patterns (RCE via committed `.claw.json`), and MCP server connections over unencrypted `ws://` or `http://` to non-localhost hosts.

- **CI/CD agent safety patterns** — four new rules in `CICDScanner`:
  - `CICD_AGENT_SKIP_PERMISSIONS` — flags `--dangerously-skip-permissions` in CI workflow steps (critical)
  - `CICD_AGENT_INSECURE_PROVIDER` — flags AI agent provider env vars using `http://` for non-localhost (high)
  - `CICD_OPENCLAUDE_IN_CI` — flags `openclaude` invoked in CI, reminding operators to verify secrets and profile hygiene (medium)
  - `CICD_CLAW_DANGER_MODE` — flags `claw --dangerously-skip-permissions` in CI (critical)

- **Legal dataset corrections** — removed `claw-code` from `LEGALLY_RISKY_PACKAGES`. The instructkr/claw-code repository has pivoted to a clean-room Rust + Python rewrite and explicitly removed the leaked Anthropic TypeScript. It is not a DMCA-covered derivative. `claw-code-js` and `openclaude`/`openclaude-core` remain flagged as leaked-source derivatives under active enforcement.

- **openclaude and claw-code blog posts** — two new security research posts on the Ship Safe blog: architecture breakdowns, real config surfaces, and concrete risks for teams running either tool.

- **KAIROS blog post** — analysis of the autonomous background agent mode discovered in the leaked Claude Code source. Documents why proactive/heartbeat-loop agents change the threat model for prompt injection, which attack vectors become practical, and what to configure in claw-code and openclaude to reduce exposure.

### Fixed

- **openclaude detection correctness** — previous release incorrectly modeled openclaude as a server with auth/host/port config fields. Replaced with accurate profile-file-based detection. Previous blog post claiming openclaude binds to `0.0.0.0:18789` has been corrected.
- **claw-code legal classification** — previous release classified claw-code as a DMCA-covered leaked-source derivative. Corrected after reading the actual repository: it is a clean-room rewrite.

---

## [6.3.0] — 2026-04-01

### Added
- **`ship-safe legal [path]`** — new standalone command that scans dependency manifests (`package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`) for packages carrying legal risk: DMCA takedowns, leaked-source derivatives, IP disputes, and license violations.
- **`LegalRiskAgent`** — new agent in `cli/agents/legal-risk-agent.js`. Exports `LEGALLY_RISKY_PACKAGES` — a structured dataset where each entry carries name, ecosystem, risk type (`dmca` | `ip-dispute` | `leaked-source` | `license-violation`), severity, human-readable detail, and reference URLs.
- **Initial legal dataset** — seeds five entries:
  - `claw-code` (npm, all versions) — DMCA, derived from leaked Anthropic Claude Code source (March 2026)
  - `claw-code-js` (npm, all versions) — leaked-source, JavaScript port of the same leak
  - `claude-code-oss` (npm, all versions) — leaked-source, open-source mirror of the Claude Code leak
  - `faker@6.6.6` (npm) — license-violation, deliberately sabotaged release (January 2022)
  - `colors@1.4.44-liberty-2` (npm) — license-violation, deliberate infinite-loop sabotage
- **`--include-legal` flag on `audit`** — `ship-safe audit . --include-legal` runs the legal risk scan as Phase 3b and merges findings into the final report and score.
- **`legal` category** — added to `CATEGORY_LABELS` and `EFFORT_MAP` in `audit.js` so legal findings appear correctly in HTML reports and remediation plans.
- **8 new unit tests** for `LegalRiskAgent` covering: DMCA detection, leaked-source detection, clean project pass, specific-version matching, safe-version pass, semver prefix stripping, Python manifest (no cross-ecosystem false positives), and category assertion.

---

## [6.2.0] — 2026-04-01

### Added
- **Claude Code hooks** — `npx ship-safe hooks install` registers `PreToolUse` and `PostToolUse` hooks in `~/.claude/settings.json`. Hooks block critical secrets before they land on disk and inject advisory scan results into Claude's context after every file write.
- **`cli/hooks/pre-tool-use.js`** — Blocks Write/Edit/MultiEdit/NotebookEdit if critical secrets detected; blocks dangerous Bash patterns (curl|bash pipe, PowerShell iex, credential file reads, env-var exfiltration, `rm -rf /`, `--unsafe-perm`). Warns on `.env` files not covered by `.gitignore`. Provides language-specific fix suggestions.
- **`cli/hooks/post-tool-use.js`** — Advisory-only scanner that runs after every successful file write. Reports critical and high-severity findings into Claude's context without blocking. Never scans `.env`, `.env.example`, test fixtures, or mocks.
- **`cli/hooks/patterns.js`** — Shared pattern module: 18 `CRITICAL_PATTERNS` (AWS, GitHub PAT × 4, Anthropic, OpenAI, Stripe × 2, Slack × 2, Twilio, Google, npm, PyPI, Supabase service role, PEM private key), 3 `HIGH_PATTERNS` with Shannon entropy gate, 7 `DANGEROUS_BASH_PATTERNS`, `scanCritical()`, `scanHigh()`, `buildFixSuggestion()`.
- **Stable hook script location** — hooks are copied to `~/.ship-safe/hooks/` at install time; registered paths point there rather than the volatile `npx` cache directory. Hooks survive `npx` cache rotations and package updates.
- **Universal LLM support** — `--provider <name>` and `--base-url <url>` flags on `audit` and `red-team`. Supports Groq, Together AI, Mistral, DeepSeek, xAI/Grok, Perplexity, LM Studio, and any OpenAI-compatible endpoint. Auto-detects `GROQ_API_KEY`, `TOGETHER_API_KEY`, `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY` from environment.
- **`OpenAICompatibleProvider`** — new provider class in `cli/providers/llm-provider.js` with preset configurations for 7 providers and generic custom-URL support.
- **Supply chain IOC detection** — `COMPROMISED_PACKAGES` list in `supply-chain-agent.js` with known-bad versions (`litellm 1.82.7/1.82.8`, `axios 1.8.2`, `telnyx 2.1.5`). `ICP_BLOCKCHAIN_PACKAGES` check for CanisterWorm-style C2 indicators in transitive deps.
- **CI/CD hardening patterns** — `CICD_ENV_EXFILTRATION` (secrets sent over network in Actions), `CICD_OIDC_BROAD_SUBJECT` (wildcard OIDC subjects), `CICD_OIDC_MISSING_SUBJECT` (id-token write without subject constraint) in `cicd-scanner.js`.
- **Unpinned action detection fix** — `CICD_UNPINNED_ACTION` now catches `@v1.2.3` semver tags in addition to `@main`/`@latest` (requires 40-char SHA hex to be considered pinned).
- **Hook pattern tests** — 30+ unit tests covering `scanCritical`, `scanHigh`, `shannonEntropy`, and `DANGEROUS_BASH_PATTERNS` in `cli/__tests__/agents.test.js`.

### Fixed
- **npx path instability** — `hooks install` no longer writes the volatile npx cache path to `~/.claude/settings.json`. Scripts are now copied to `~/.ship-safe/hooks/` before registration.
- **Supabase JWT false positives** — pattern now requires `c2VydmljZV9yb2xl` (base64 of `service_role`) in the payload section, eliminating matches on arbitrary HS256 JWTs.
- **Twilio Account SID false positives** — pattern tightened to `AC[a-f0-9]{32}` (lowercase hex only), removing matches on mixed-case alphanumeric strings.
- **`/dev/stdin` not available on Windows** — hooks now read stdin via async `process.stdin` event listeners with a 3-second safety timeout instead of synchronous `/dev/stdin` reads.

---

## [5.0.0] — 2026-03-16

### Added
- **3 new security agents** — MCPSecurityAgent (MCP server misuse, tool poisoning), AgenticSecurityAgent (OWASP Agentic AI Top 10), RAGSecurityAgent (RAG pipeline security, context injection), PIIComplianceAgent (PII detection in source code)
- **VerifierAgent** — post-processor that probes provider APIs (GitHub, OpenAI, Stripe, Slack, etc.) to verify if leaked secrets are still active
- **DeepAnalyzer** — LLM-powered taint analysis sends critical/high findings to LLM for exploitability verification; supports Anthropic, OpenAI, Google, Ollama with budget controls (`--budget <cents>`)
- **`ship-safe ci`** — dedicated CI/CD command with compact one-line output, threshold-based gating (`--threshold`, `--fail-on`), SARIF output for GitHub Code Scanning
- **Cross-agent awareness** — `sharedFindings` in orchestrator context allows later agents to see findings from earlier agents
- **Framework-aware scanning** — agents implement `shouldRun(recon)` to skip irrelevant projects (e.g., MobileScanner skips non-mobile projects)
- **`--deep` flag** — LLM-powered deep analysis on `audit` and `red-team` commands
- **`--local` flag** — use local Ollama model for deep analysis
- **`--verify` flag** — probe provider APIs to check if leaked secrets are still active
- **`--budget <cents>` flag** — cap LLM spend for deep analysis (default: 50 cents)
- **CRA-ready SBOM** — EU Cyber Resilience Act compliance fields: supplier, lifecycles, licenses, vulnerability attachment
- **OWASP Agentic AI Top 10 coverage** — ASI01-ASI10 via AgenticSecurityAgent
- **Claude Code plugin v3.0** — added `/ship-safe-deep` and `/ship-safe-ci` skills
- **90 unit tests** across 26 suites

---

## [4.3.0] — 2026-03-08

### Added
- **Supabase RLS Agent** — dedicated agent for Row Level Security auditing: detects `service_role` key in client code, `CREATE TABLE` without `ENABLE ROW LEVEL SECURITY`, anon key inserts, unprotected storage
- **Context-aware confidence tuning** — post-processing step downgrades confidence for test files, docs, comments, and example paths to reduce false positives by up to 70%
- **`ship-safe baseline`** — accept current findings as a baseline, only report new findings on subsequent runs (`--diff`, `--clear`)
- **`--baseline` flag on `audit`** — filter out baselined findings, only show regressions
- **`--pdf` flag on `audit`** — generate PDF report via Chrome headless (falls back to print-optimized HTML)
- **Expanded auto-fix** — `remediate --all` fixes 5 common agent patterns: TLS bypass, Docker `:latest`, debug mode, dangerouslySetInnerHTML, `shell: true`
- **Dependency confusion detection** — scoped packages without `.npmrc` registry pinning, suspicious install scripts (`curl`, `eval`, `base64`)
- **Rate limiting detection** — project-level check for Express/Fastify apps without rate-limiting libraries
- **OpenAPI spec scanning** — missing `securitySchemes`, HTTP server URLs, secrets in example values
- **Terraform patterns** — RDS public access, CloudFront HTTP, Lambda admin role, S3 no versioning
- **Kubernetes patterns** — `:latest` image tags, missing NetworkPolicy
- **Code context in findings** — 3 lines before/after with highlighted flagged line in HTML report and verbose output
- **API pagination check** — `.find({})` without `.limit()` detection
- **49 unit tests** (16 new) covering all v4.3 features

---

## [4.2.0] — 2026-03-05

### Added
- **Parallel agent execution** — all 12 agents run concurrently with configurable concurrency (default: 6)
- **Per-agent timeouts** — `--timeout <ms>` flag (default: 30s) prevents agent hangs
- **Confidence-weighted scoring** — low-confidence findings count for 30%, medium for 60%, reducing noise
- **`ship-safe doctor`** — environment diagnostics (Node.js, git, npm, API keys, cache, version)
- **`--compare` flag** — per-category score delta table vs. previous scan
- **`--csv` flag** — CSV export for spreadsheets
- **`--md` flag** — Markdown report export
- **LLM response caching** — AI classifications cached for 7 days in `.ship-safe/llm-cache.json`
- **False positive suppression tracking** — counts `ship-safe-ignore` comments per rule in JSON output and history
- **Python security patterns** — f-string SQL injection, `subprocess.run(shell=True)`
- **Go security patterns** — `fmt.Sprintf` SQL injection, unescaped `template.HTML()`
- **Rust security patterns** — `unsafe` blocks, `.unwrap()` in production code
- **Django/Flask patterns** — `DEBUG = True`, hardcoded `secret_key`
- **33 unit tests** — using Node.js built-in test runner (`node:test`)

### Fixed
- Patched ReDoS vulnerabilities in 6 regex patterns across agents
- Fixed command injection risk in dependency audit (`execFileSync` instead of `exec`)
- Fixed API key exposure in error messages
- Fixed false positive SQL injection detection in version strings

---

## [4.1.0] — 2025-02-26

### Added
- **`audit` command** — full security audit: secrets + 12 agents + deps + scoring + remediation plan
- **HTML report** — standalone dark-themed report with table of contents (`--html`)
- **Incremental scanning** — cache file hashes and findings, ~40% faster on repeated scans
- **Smart `.gitignore` handling** — respects gitignore but always scans `.env`, `*.pem`, `*.key`

---

## [4.0.0] — 2025-02-24

### Added
- **12 security agents** — InjectionTester, AuthBypassAgent, SSRFProber, SupplyChainAudit, ConfigAuditor, LLMRedTeam, MobileScanner, GitHistoryScanner, CICDScanner, APIFuzzer, ReconAgent, ScoringEngine
- **`red-team` command** — run agents standalone with `--agents` filter
- **`score` command** — 8-category weighted scoring (0-100, A-F grades)
- **`watch` command** — continuous monitoring with file change detection
- **`sbom` command** — CycloneDX SBOM generation
- **`policy init` command** — policy-as-code with `.ship-safe.policy.json`
- **`deps` command** — dependency CVE audit with `--fix` option
- **SARIF output** — `--sarif` flag on audit/scan for GitHub Code Scanning
- **Multi-LLM support** — Anthropic, OpenAI, Google AI, Ollama
- **Claude Code plugin** — `/ship-safe`, `/ship-safe-scan`, `/ship-safe-score`
- **OWASP coverage** — Web Top 10 2025, Mobile Top 10 2024, LLM Top 10 2025, CI/CD Top 10

---

## [3.1.0] — 2025-02-19

### Added
- `remediate` command — auto-fix detected secrets by replacing hardcoded values with environment variable references
- `rotate` command — guide for rotating leaked credentials across supported services (AWS, OpenAI, Stripe, GitHub, Supabase, and more)

---

## [3.0.0] — 2025-01-XX

### Added
- `guard` command — install a git pre-push or pre-commit hook that blocks commits/pushes when secrets are detected
- `fix` command — scan and auto-generate a `.env.example` file with placeholder values for every found secret type
- `mcp` command — start ship-safe as an MCP (Model Context Protocol) server; lets Claude Desktop, Cursor, Windsurf, and Zed call `scan_secrets`, `get_checklist`, and `analyze_file` directly
- `--sarif` flag on `scan` — outputs SARIF 2.1.0 format for GitHub Code Scanning integration
- Custom pattern support via `.ship-safe.json` in the project root

### Changed
- Major CLI restructure — all commands are now subcommands of `ship-safe`

---

## [2.1.0] — 2024-12-XX

### Added
- Shannon entropy scoring for generic secret patterns — filters out placeholder values like `your_api_key_here`
- `.ship-safeignore` support — gitignore-style path exclusions
- Test file exclusion by default — test/spec/fixture/mock/story files are skipped unless `--include-tests` is passed
- `// ship-safe-ignore` inline suppression comment

### Changed
- Reduced false positives significantly with entropy threshold (3.5 bits)
- Each finding now includes a `confidence` level: `high`, `medium`, or `low`

---

## [2.0.0] — 2024-11-XX

### Added
- Comprehensive security toolkit: configs, snippets, and checklists for Next.js, Supabase, and Firebase
- `init` command — copy pre-built security configs into a project (`.gitignore`, security headers)
- `checklist` command — interactive 10-point launch-day security checklist
- `/ai-defense` directory — LLM security checklist, prompt injection patterns, cost protection guide, system prompt armor
- `/snippets` directory — rate limiting, CORS, input validation, JWT security
- `/configs` directory — Supabase RLS templates, Firebase rules, Next.js security headers

---

## [1.2.0] — 2024-10-XX

### Added
- 50+ new secret detection patterns covering AI/ML providers, cloud platforms, databases, payment processors, communication services, and hosting providers
- Patterns now include: Anthropic, OpenAI, Replicate, Hugging Face, Cohere, Groq, Mistral, Perplexity, Together AI, Vercel, Netlify, Heroku, Railway, Fly.io, Render, DigitalOcean, Cloudflare, Linear, Notion, Airtable, Figma, Lemon Squeezy, Paddle, Slack, Discord, Telegram, Mailgun, Resend, Postmark, Mailchimp, Upstash, Turso, and more

---

## [1.0.0] — 2024-09-XX

### Added
- `scan` command — scan a directory or file for leaked secrets using pattern matching
- Initial secret patterns: AWS keys, GitHub tokens, Stripe keys, private keys, database URLs, OpenAI keys, Supabase keys, Clerk keys
- `--json` flag for CI pipeline integration (exit code `1` if secrets found)
- `-v` verbose mode
- GitHub Actions CI workflow
