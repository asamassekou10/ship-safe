<p align="center">
  <img src=".github/assets/logo%20ship%20safe.png" alt="Ship Safe Logo" width="180" />
</p>
<p align="center"><strong>Don't let vibe coding leak your API keys.</strong></p>

<p align="center">
  <a href="https://www.npmjs.com/package/ship-safe"><img src="https://badge.fury.io/js/ship-safe.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/ship-safe"><img src="https://img.shields.io/npm/dm/ship-safe.svg" alt="npm downloads" /></a>
  <a href="https://github.com/asamassekou10/ship-safe/actions/workflows/ci.yml"><img src="https://github.com/asamassekou10/ship-safe/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/node/v/ship-safe" alt="Node.js version" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
</p>

---

You're shipping fast. You're using AI to write code. You're one `git push` away from exposing your database credentials to the world.

**Ship Safe** is a security toolkit for indie hackers and vibe coders who want to secure their MVP in 5 minutes, not 5 days.

---

## Quick Start

```bash
# AI-powered audit: scan, classify with Claude, auto-fix confirmed secrets
npx ship-safe agent .

# Scan for secrets AND code vulnerabilities (SQL injection, XSS, etc.)
npx ship-safe scan .

# Security health score (0-100, A–F grade)
npx ship-safe score .

# Audit dependencies for known CVEs
npx ship-safe deps .

# Auto-fix hardcoded secrets: rewrite code + write .env
npx ship-safe remediate .

# Revoke exposed keys — opens provider dashboards with step-by-step guide
npx ship-safe rotate .
```

Or if you prefer the manual toolkit:

```bash
npx ship-safe fix           # Generate .env.example from secrets
npx ship-safe guard         # Block git push if secrets found
npx ship-safe checklist     # Run launch-day security checklist
npx ship-safe init          # Add security configs to your project
```

![ship-safe terminal demo](.github/assets/ship%20safe%20terminal.jpg)

### Let AI Do It For You

Copy this prompt to your AI coding assistant:

```
Run "npx ship-safe scan ." on my project and fix any secrets you find.
Then run "npx ship-safe init" to add security configs.
Explain what you're doing as you go.
```

[More AI prompts for specific frameworks](./AI_SECURITY_PROMPT.md)

---

## Why This Exists

Vibe coding is powerful. You can build a SaaS in a weekend. But speed creates blind spots:

- AI-generated code often hardcodes secrets
- Default configs ship with debug mode enabled
- "I'll fix it later" becomes "I got hacked"

This repo is your co-pilot for security. Copy, paste, ship safely.

---

## CLI Commands

### `npx ship-safe agent [path]`

AI-powered security audit. Scans for both secrets and code vulnerabilities, sends findings to Claude for classification, auto-fixes confirmed secrets, and provides specific fix suggestions for code issues.

```bash
# Full AI audit (requires ANTHROPIC_API_KEY)
npx ship-safe agent .

# Preview classification without writing any files
npx ship-safe agent . --dry-run

# Use a specific Claude model
npx ship-safe agent . --model claude-opus-4-6
```

**Flow:**
1. Scan for secrets + code vulnerabilities (XSS, SQLi, command injection, etc.)
2. Send findings to Claude — classify each as `REAL` or `FALSE_POSITIVE`
3. For secrets: auto-remediate confirmed findings (rewrite code + write `.env`)
4. For code vulns: print Claude's verdict + specific 1-line fix suggestion
5. Re-scan to verify secrets are gone

No `ANTHROPIC_API_KEY`? Falls back to `remediate` for secrets automatically.

---

### `npx ship-safe scan [path]`

Scans your codebase for leaked secrets **and** code vulnerabilities.

```bash
# Scan current directory
npx ship-safe scan .

# Scan a specific folder
npx ship-safe scan ./src

# Get JSON output (for CI pipelines)
npx ship-safe scan . --json

# SARIF output for GitHub Code Scanning
npx ship-safe scan . --sarif

# Verbose mode (show files being scanned)
npx ship-safe scan . -v
```

**Exit codes:** Returns `1` if issues found (useful for CI), `0` if clean.

**Flags:**
- `--json` — structured JSON output for CI pipelines
- `--sarif` — SARIF format for GitHub Code Scanning
- `--include-tests` — also scan test/spec/fixture files (excluded by default)
- `-v` — verbose mode

**Suppress false positives:**
```bash
const apiKey = 'example-key'; // ship-safe-ignore
```
Or exclude paths with `.ship-safeignore` (gitignore syntax).

**Custom patterns** — create `.ship-safe.json` in your project root:
```json
{
  "patterns": [
    {
      "name": "My Internal API Key",
      "pattern": "MYAPP_[A-Z0-9]{32}",
      "severity": "high",
      "description": "Internal key for myapp services."
    }
  ]
}
```

**Detects 50+ secret patterns:**
- **AI/ML:** OpenAI, Anthropic, Google AI, Cohere, Replicate, Hugging Face
- **Auth:** Clerk, Auth0, Supabase Auth
- **Cloud:** AWS, Google Cloud, Azure
- **Database:** Supabase, PlanetScale, Neon, MongoDB, PostgreSQL, MySQL
- **Payment:** Stripe, PayPal
- **Messaging:** Twilio, SendGrid, Resend
- **And more:** GitHub tokens, private keys, JWTs, generic secrets

**Detects 18 code vulnerability patterns (OWASP Top 10):**
- **Injection:** SQL injection (template literals), command injection, code injection (`eval`)
- **XSS:** `dangerouslySetInnerHTML`, `innerHTML` assignment, `document.write`
- **Crypto:** MD5 / SHA-1 for passwords, weak random number generation
- **TLS:** `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false`, Python `verify=False`
- **Deserialization:** `pickle.loads`, `yaml.load` without `Loader`
- **Misconfiguration:** CORS wildcard (`*`), deprecated `new Buffer()`

---

### `npx ship-safe remediate [path]`

Auto-fix hardcoded secrets: rewrites source files to use `process.env` variables, writes a `.env` file with the actual values, and updates `.gitignore`.

```bash
# Auto-fix secrets
npx ship-safe remediate .

# Preview changes without writing any files
npx ship-safe remediate . --dry-run

# Apply all fixes without prompting (for CI)
npx ship-safe remediate . --yes

# Also run git add on modified files
npx ship-safe remediate . --stage
```

---

### `npx ship-safe rotate [path]`

Revoke and rotate exposed secrets. Detects which providers your secrets belong to and opens the right dashboard with step-by-step revocation instructions.

```bash
# Open dashboards for all detected secrets
npx ship-safe rotate .

# Rotate only a specific provider
npx ship-safe rotate . --provider github
npx ship-safe rotate . --provider stripe
npx ship-safe rotate . --provider openai
```

**Supports:** OpenAI, Anthropic, GitHub, Stripe, AWS, Google Cloud, Supabase, and more.

---

### `npx ship-safe deps [path]`

Audit your dependencies for known CVEs using the project's native package manager.

```bash
# Audit dependencies
npx ship-safe deps .

# Also run the package manager's auto-fix command
npx ship-safe deps . --fix
```

**Supported package managers:**
- `npm` → `npm audit`
- `yarn` → `yarn audit`
- `pnpm` → `pnpm audit`
- `pip` → `pip-audit` (install with `pip install pip-audit`)
- `bundler` → `bundle-audit` (install with `gem install bundler-audit`)

Auto-detected from your lock file. Gracefully skips if the tool isn't installed.

---

### `npx ship-safe score [path]`

Compute a 0–100 security health score for your project. Combines secret detection, code vulnerability detection, and dependency CVEs into a single grade. No API key needed — instant and free.

```bash
# Score the project
npx ship-safe score .

# Skip dependency audit (faster)
npx ship-safe score . --no-deps
```

**Scoring (starts at 100):**

| Category | Critical | High | Medium | Cap |
|----------|----------|------|--------|-----|
| Secrets | −25 | −15 | −5 | −40 |
| Code Vulns | −20 | −10 | −3 | −30 |
| Dependencies | −20 | −10 | −5 | −30 |

**Grades:**

| Score | Grade | Verdict |
|-------|-------|---------|
| 90–100 | A | Ship it! |
| 75–89 | B | Minor issues to review |
| 60–74 | C | Fix before shipping |
| 40–59 | D | Significant security risks |
| 0–39 | F | Not safe to ship |

**Exit codes:** Returns `0` for A/B (≥ 75), `1` for C/D/F.

---

### `npx ship-safe checklist`

Interactive 10-point security checklist for launch day.

```bash
# Interactive mode (prompts for each item)
npx ship-safe checklist

# Print checklist without prompts
npx ship-safe checklist --no-interactive
```

Covers: exposed .git folders, debug mode, RLS policies, hardcoded keys, HTTPS, security headers, rate limiting, and more.

---

### `npx ship-safe init`

Initialize security configs in your project.

```bash
# Add all security configs
npx ship-safe init

# Only add .gitignore patterns
npx ship-safe init --gitignore

# Only add security headers config
npx ship-safe init --headers

# Force overwrite existing files
npx ship-safe init -f
```

**What it copies:**
- `.gitignore` - Patterns to prevent committing secrets
- `security-headers.config.js` - Drop-in Next.js security headers

---

### `npx ship-safe fix`

Scan for secrets and auto-generate a `.env.example` file.

```bash
# Scan and generate .env.example
npx ship-safe fix

# Preview what would be generated without writing it
npx ship-safe fix --dry-run
```

---

### `npx ship-safe guard`

Install a git hook that blocks pushes if secrets are found. Works with or without Husky.

```bash
# Install pre-push hook (runs scan before every git push)
npx ship-safe guard

# Install pre-commit hook instead
npx ship-safe guard --pre-commit

# Remove installed hooks
npx ship-safe guard remove
```

**Suppress false positives:**
- Add `# ship-safe-ignore` as a comment on a line to skip it
- Create `.ship-safeignore` (gitignore syntax) to exclude paths

---

### `npx ship-safe mcp`

Start ship-safe as an MCP server so AI editors can call it directly.

**Setup (Claude Desktop)** — add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ship-safe": {
      "command": "npx",
      "args": ["ship-safe", "mcp"]
    }
  }
}
```

Works with Claude Desktop, Cursor, Windsurf, Zed, and any MCP-compatible editor.

**Available tools:**
- `scan_secrets` — scan a directory for leaked secrets
- `get_checklist` — return the security checklist as structured data
- `analyze_file` — analyze a single file for issues

---

## What's Inside

### [`/checklists`](./checklists)
**Manual security audits you can do in 5 minutes.**
- [Launch Day Checklist](./checklists/launch-day.md) - 10 things to check before you go live

### [`/configs`](./configs)
**Secure defaults for popular stacks. Drop-in ready.**

| Stack | Files |
|-------|-------|
| **Next.js** | [Security Headers](./configs/nextjs-security-headers.js) - CSP, X-Frame-Options, HSTS |
| **Supabase** | [RLS Templates](./configs/supabase/rls-templates.sql) \| [Security Checklist](./configs/supabase/security-checklist.md) \| [Secure Client](./configs/supabase/secure-client.ts) |
| **Firebase** | [Firestore Rules](./configs/firebase/firestore-rules.txt) \| [Storage Rules](./configs/firebase/storage-rules.txt) \| [Security Checklist](./configs/firebase/security-checklist.md) |

### [`/snippets`](./snippets)
**Copy-paste code blocks for common security patterns.**

| Category | Files |
|----------|-------|
| **Rate Limiting** | [Upstash Redis](./snippets/rate-limiting/upstash-ratelimit.ts) \| [Next.js Middleware](./snippets/rate-limiting/nextjs-middleware.ts) |
| **Authentication** | [JWT Security Checklist](./snippets/auth/jwt-checklist.md) |
| **API Security** | [CORS Config](./snippets/api-security/cors-config.ts) \| [Input Validation](./snippets/api-security/input-validation.ts) \| [API Checklist](./snippets/api-security/api-security-checklist.md) |

### [`/ai-defense`](./ai-defense)
**Protect your AI features from abuse and cost explosions.**

| File | Description |
|------|-------------|
| [LLM Security Checklist](./ai-defense/llm-security-checklist.md) | Based on OWASP LLM Top 10 - prompt injection, data protection, scope control |
| [Prompt Injection Patterns](./ai-defense/prompt-injection-patterns.js) | Regex patterns to detect 25+ injection attempts |
| [Cost Protection Guide](./ai-defense/cost-protection.md) | Prevent $50k surprise bills - rate limits, budget caps, circuit breakers |
| [System Prompt Armor](./ai-defense/system-prompt-armor.md) | Template for hardened system prompts |

### [`/scripts`](./scripts)
**Automated scanning tools. Run them in CI or locally.**
- [Secret Scanner](./scripts/scan_secrets.py) - Python version of the secret scanner

---

## AI/LLM Security

Building with AI? Don't let it bankrupt you or get hijacked.

### Quick Setup

```typescript
import { containsInjectionAttempt } from './ai-defense/prompt-injection-patterns';

async function handleChat(userInput: string) {
  // 1. Check for injection attempts
  const { detected } = containsInjectionAttempt(userInput);
  if (detected) {
    return "I can't process that request.";
  }

  // 2. Rate limit per user
  const { success } = await ratelimit.limit(userId);
  if (!success) {
    return "Too many requests. Please slow down.";
  }

  // 3. Check budget before calling
  await checkUserBudget(userId, estimatedCost);

  // 4. Make the API call with token limits
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages,
    max_tokens: 500, // Hard cap
  });

  return response;
}
```

### Cost Protection Layers

1. **Token limits** - Cap input/output per request
2. **Rate limits** - Cap requests per user (10/min)
3. **Budget caps** - Daily ($1) and monthly ($10) per user
4. **Circuit breaker** - Disable AI when global budget hit
5. **Provider limits** - Set hard limits in OpenAI/Anthropic dashboard

[Full cost protection guide →](./ai-defense/cost-protection.md)

---

## Database Security

### Supabase RLS Templates

```sql
-- Users can only see their own data
CREATE POLICY "Users own their data" ON items
  FOR ALL USING (auth.uid() = user_id);

-- Read-only public data
CREATE POLICY "Public read access" ON public_items
  FOR SELECT USING (true);
```

[6 more RLS patterns →](./configs/supabase/rls-templates.sql)

### Firebase Security Rules

```javascript
// Users can only access their own documents
match /users/{userId} {
  allow read, write: if request.auth != null
    && request.auth.uid == userId;
}
```

[Full Firestore rules template →](./configs/firebase/firestore-rules.txt)

---

## API Security

### CORS (Don't use `*` in production)

```typescript
const ALLOWED_ORIGINS = [
  'https://yourapp.com',
  'https://www.yourapp.com',
];

// Only allow specific origins
if (origin && ALLOWED_ORIGINS.includes(origin)) {
  headers['Access-Control-Allow-Origin'] = origin;
}
```

[CORS configs for Next.js, Express, Fastify, Hono →](./snippets/api-security/cors-config.ts)

### Input Validation (Zod)

```typescript
const createUserSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
});

const result = createUserSchema.safeParse(body);
if (!result.success) {
  return Response.json({ error: result.error.issues }, { status: 400 });
}
```

[Full validation patterns →](./snippets/api-security/input-validation.ts)

---

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for secrets and code vulnerabilities
        run: npx ship-safe scan . --json

      - name: Audit dependencies for CVEs
        run: npx ship-safe deps .

      - name: Security health score (fail if C or below)
        run: npx ship-safe score . --no-deps
```

Each command exits with code `1` on findings, failing your build. Use `--sarif` with `scan` to send results to GitHub's Security tab:

```yaml
      - name: Scan (SARIF for GitHub Security tab)
        run: npx ship-safe scan . --sarif > results.sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## The 5-Minute Security Checklist

1. ✅ Run `npx ship-safe agent .` — AI audit: finds + classifies + fixes secrets and code vulns
2. ✅ Run `npx ship-safe deps .` — audit your dependencies for known CVEs
3. ✅ Run `npx ship-safe score .` — check your overall security health score
4. ✅ Run `npx ship-safe init` — add security configs (.gitignore, security headers)
5. ✅ Run `npx ship-safe guard` — install git hook to block pushes if secrets found
6. ✅ Run `npx ship-safe checklist` — run the interactive launch-day security checklist
7. ✅ If using AI features, implement [cost protection](./ai-defense/cost-protection.md)
8. ✅ If using Supabase, check the [RLS checklist](./configs/supabase/security-checklist.md)
9. ✅ If using Firebase, check the [Firebase checklist](./configs/firebase/security-checklist.md)

---

## Philosophy

- **Low friction** - If it takes more than 5 minutes, people won't do it
- **Educational** - Every config has comments explaining *why*
- **Modular** - Take what you need, ignore the rest
- **Copy-paste friendly** - No complex setup, just grab and go

---

## Contributing

Found a security pattern that saved your app? Share it!

1. Fork the repo
2. Add your checklist, config, or script
3. Include educational comments explaining *why* it matters
4. Open a PR

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## Security Standards Reference

This toolkit is based on:
- [OWASP Top 10 Web 2025](https://owasp.org/Top10/)
- [OWASP Top 10 Mobile 2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)

---

## License

MIT - Use it, share it, secure your stuff.

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=asamassekou10/ship-safe&type=Date)](https://star-history.com/#asamassekou10/ship-safe&Date)

---

**Remember: Security isn't about being paranoid. It's about being prepared.**

Ship fast. Ship safe.
