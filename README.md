# Ship Safe

**Don't let vibe coding leak your API keys.**

You're shipping fast. You're using AI to write code. You're one `git push` away from exposing your database credentials to the world.

**Ship Safe** is a security toolkit for indie hackers and vibe coders who want to secure their MVP in 5 minutes, not 5 days.

---

## Quick Start

```bash
# Scan your project for leaked secrets (no install required!)
npx ship-safe scan .

# Run the launch-day security checklist
npx ship-safe checklist

# Add security configs to your project
npx ship-safe init
```

That's it. Three commands to secure your MVP.

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

### `npx ship-safe scan [path]`

Scans your codebase for leaked secrets: API keys, passwords, private keys, database URLs.

```bash
# Scan current directory
npx ship-safe scan .

# Scan a specific folder
npx ship-safe scan ./src

# Get JSON output (for CI pipelines)
npx ship-safe scan . --json

# Verbose mode (show files being scanned)
npx ship-safe scan . -v
```

**Exit codes:** Returns `1` if secrets found (useful for CI), `0` if clean.

**Detects:** OpenAI keys, AWS credentials, GitHub tokens, Stripe keys, Supabase service keys, database URLs, private keys, and 20+ more patterns.

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

## What's Inside

### [`/checklists`](./checklists)
**Manual security audits you can do in 5 minutes.**
- [Launch Day Checklist](./checklists/launch-day.md) - 10 things to check before you go live

### [`/configs`](./configs)
**Secure defaults for popular stacks. Drop-in ready.**
- [Next.js Security Headers](./configs/nextjs-security-headers.js) - CSP, X-Frame-Options, and more

### [`/scripts`](./scripts)
**Automated scanning tools. Run them in CI or locally.**
- [Secret Scanner](./scripts/scan_secrets.py) - Python version of the secret scanner

### [`/snippets`](./snippets)
**Copy-paste code blocks for common security patterns.**
- Rate limiting, auth middleware, input validation (coming soon)

### [`/ai-defense`](./ai-defense)
**Protect your AI features from abuse.**
- [System Prompt Armor](./ai-defense/system-prompt-armor.md) - Prevent prompt injection attacks

---

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan for secrets
        run: npx ship-safe scan . --json
```

The scan exits with code `1` if secrets are found, failing your build.

---

## The 5-Minute Security Checklist

1. Run `npx ship-safe scan .` on your project
2. Run `npx ship-safe init` to add security configs
3. Add security headers to your Next.js config
4. Run `npx ship-safe checklist` before launching
5. If using AI features, add the [System Prompt Armor](./ai-defense/system-prompt-armor.md)

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

---

## Stack-Specific Guides (Coming Soon)

- [ ] Supabase Security Defaults
- [ ] Firebase Rules Templates
- [ ] Vercel Environment Variables
- [ ] Stripe Webhook Validation
- [ ] Clerk/Auth.js Hardening

---

## License

MIT - Use it, share it, secure your stuff.

---

**Remember: Security isn't about being paranoid. It's about being prepared.**

Ship fast. Ship safe.
