# Changelog

All notable changes to ship-safe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
