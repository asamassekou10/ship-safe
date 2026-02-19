# Changelog

All notable changes to ship-safe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
