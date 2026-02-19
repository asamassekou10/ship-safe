# Ship Safe — Full Feature Reference

Security toolkit for vibe coders and indie hackers. Catches secrets, blocks bad pushes, and plugs into your AI editor — all in one CLI.

---

## Commands

### `scan` — Secret Detection

The core command. Scans a directory or file for leaked secrets using pattern matching and entropy scoring.

```bash
npx ship-safe scan .
npx ship-safe scan ./src
npx ship-safe scan . --json
npx ship-safe scan . --sarif
npx ship-safe scan . --verbose
npx ship-safe scan . --include-tests
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (for CI pipelines) |
| `--sarif` | Output SARIF 2.1.0 format (for GitHub Code Scanning) |
| `--verbose` | Show every file being scanned |
| `--include-tests` | Also scan test/spec/fixture files (excluded by default) |
| `--no-color` | Disable colored output |

**Exit codes:** `0` = clean, `1` = secrets found

---

### `fix` — Auto-generate .env.example

Scans for secrets and generates a `.env.example` file with placeholder values for every secret type found.

```bash
npx ship-safe fix
npx ship-safe fix --dry-run
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--dry-run` | Preview generated `.env.example` without writing it |

Converts pattern names to env var format automatically (e.g. `OpenAI API Key` → `OPENAI_API_KEY=your_openai_api_key_here`). Skips if `.env.example` already exists.

---

### `guard` — Git Hook Protection

Installs a git hook that runs `ship-safe scan` before every push or commit. If secrets are found, the operation is blocked.

```bash
npx ship-safe guard              # Install pre-push hook
npx ship-safe guard --pre-commit # Install pre-commit hook instead
npx ship-safe guard remove       # Remove installed hooks
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--pre-commit` | Install as pre-commit hook instead of pre-push |

- Auto-detects **Husky** — installs to `.husky/` if present, otherwise `.git/hooks/`
- Appends to existing hooks instead of overwriting them
- Remove cleanly with `ship-safe guard remove`

---

### `checklist` — Launch-Day Security Checklist

Walks you through 10 security checks before going live. Each item includes how to verify it, the risk if skipped, and how to fix it.

```bash
npx ship-safe checklist             # Interactive mode
npx ship-safe checklist --no-interactive  # Print only, no prompts
```

**Checklist items:**
1. No exposed `.git` folder
2. Debug mode disabled in production
3. Database RLS / security rules enabled
4. No hardcoded API keys in frontend
5. HTTPS enforced
6. Security headers configured
7. Rate limiting on auth endpoints
8. No sensitive data in URLs
9. Error messages don't leak internals
10. Admin routes protected

Interactive mode prompts for each item (`y` done / `s` skip / `n` todo) and prints a summary with outstanding items.

---

### `init` — Copy Security Configs

Copies pre-built security config files into your project.

```bash
npx ship-safe init            # Copy all configs
npx ship-safe init --gitignore  # Only copy .gitignore
npx ship-safe init --headers    # Only copy security headers
npx ship-safe init -f           # Force overwrite existing files
```

**Files copied:**
- `.gitignore` — security-focused ignore patterns (merges with existing if present)
- `security-headers.config.js` — CSP, X-Frame-Options, HSTS, and more (Next.js-ready)

Auto-detects Next.js and shows integration instructions.

---

### `mcp` — MCP Server for AI Editors

Starts ship-safe as a Model Context Protocol server over stdio. Lets Claude, Cursor, Windsurf, and Zed call ship-safe's tools directly during conversations.

```bash
npx ship-safe mcp
```

**Setup (Claude Desktop):**
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

**Available MCP tools:**
| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan a directory or file for leaked secrets |
| `get_checklist` | Return the launch-day security checklist as structured data |
| `analyze_file` | Analyze a single file for security issues |

---

## Detection Engine

### Secret Patterns (70+)

Patterns are organized by severity and service category.

**Critical**
- AWS Access Key ID / Secret Access Key
- GitHub PAT, OAuth, App, and Fine-Grained tokens
- Stripe Live Secret Key
- Private Key blocks (RSA, EC, DSA, OpenSSH)
- PlanetScale passwords and OAuth tokens
- Clerk Secret Key
- Doppler Service Token
- HashiCorp Vault Token
- Neon Database connection strings
- MongoDB Atlas connection strings
- Auth0 domains with embedded client secrets

**High — AI/ML Providers**
- OpenAI API Key and Project Key
- Anthropic (Claude) API Key
- Google AI / Gemini API Key
- Replicate, Hugging Face, Perplexity, Groq, Cohere, Mistral, Together AI

**High — Communication & Email**
- Slack tokens and webhooks
- Discord webhooks and bot tokens
- Telegram bot tokens
- SendGrid, Mailgun, Resend, Postmark, Mailchimp

**High — Databases & Infrastructure**
- Firebase / Google service accounts
- Supabase service role keys
- Upstash Redis and QStash tokens
- Turso database URLs

**High — Hosting & Deployment**
- Vercel, Netlify, Heroku, DigitalOcean, Render, Fly.io, Railway, Cloudflare

**High — Payments**
- Stripe live/test secret keys, webhook secrets
- Lemon Squeezy, Paddle

**High — Productivity & SaaS**
- Linear, Notion, Airtable, Figma

**Medium — Generic (entropy-scored)**
- Generic API key assignments
- Generic secret assignments
- Hardcoded passwords
- Database URLs with credentials
- Bearer tokens in code
- Basic auth headers
- Private keys in env vars

---

### Shannon Entropy Scoring

Generic patterns (e.g. `api_key = "..."`) run through Shannon entropy scoring before being reported. Values below the threshold (3.5 bits) are filtered as likely placeholders — things like `your_api_key_here` or `xxxxxxxxxxxx`.

- Real secrets typically score > 3.5
- Placeholders and example values score < 3.0
- Prefix-specific patterns (AWS, GitHub, OpenAI, etc.) skip entropy — they're already precise

Each finding includes a **confidence level**: `high`, `medium`, or `low`.

---

### False Positive Controls

**Inline suppression**
Add `# ship-safe-ignore` on any line to skip it:
```js
const key = "example-only-not-real"; // ship-safe-ignore
```

**Path exclusions — `.ship-safeignore`**
Same syntax as `.gitignore`:
```
tests/fixtures/
src/docs/examples/
**/__mocks__/**
```

**Test file exclusion**
Test, spec, fixture, mock, and story files are excluded by default. Override with `--include-tests`.

Excluded patterns include: `.test.js`, `.spec.ts`, `__tests__/`, `tests/`, `fixtures/`, `mocks/`, `__mocks__/`, `.stories.jsx`, `.mock.ts`, and more.

---

### Custom Patterns — `.ship-safe.json`

Define your own secret patterns in a config file at the project root:

```json
{
  "patterns": [
    {
      "name": "Internal API Key",
      "pattern": "MYAPP_[A-Z0-9]{32}",
      "severity": "high",
      "description": "Internal service API key."
    }
  ]
}
```

Custom patterns are merged with built-in patterns and shown with a `[custom]` prefix.

---

## CI/CD Integration

### JSON output for CI
```bash
npx ship-safe scan . --json
# Exit code 1 if secrets found, 0 if clean
```

### GitHub Actions
```yaml
- name: Scan for secrets
  run: npx ship-safe scan . --json
```

### SARIF for GitHub Code Scanning
```bash
npx ship-safe scan . --sarif > results.sarif
```
Then upload with `github/codeql-action/upload-sarif@v3` to surface findings directly in the GitHub Security tab.

---

## File Scanning Behavior

**Skipped automatically:**
- `node_modules/`, `.git/`, `dist/`, `build/`, `.next/`, `.nuxt/`, `vendor/`, `.cache/`, `.vercel/`, `.netlify/`, and more
- Binary files: images, fonts, media, archives, executables
- Minified files: `.min.js`, `.min.css`
- Source maps: `.map`
- Lock files: `.lock`
- Files over 1MB

---

## Installation

```bash
# Run directly (no install)
npx ship-safe scan .

# Install globally
npm install -g ship-safe
ship-safe scan .
```

**Requirements:** Node.js 18+

---

## Open Source

MIT License — github.com/asamassekou10/ship-safe
