# Ship Safe

**Don't let vibe coding leak your API keys.**

You're shipping fast. You're using AI to write code. You're one `git push` away from exposing your database credentials to the world.

**Ship Safe** is a security toolkit for indie hackers and vibe coders who want to secure their MVP in 5 minutes, not 5 days.

[![npm version](https://badge.fury.io/js/ship-safe.svg)](https://www.npmjs.com/package/ship-safe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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

![ship-safe terminal demo](ship%20safe%20terminal.jpg)

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

**Detects 50+ secret patterns:**
- **AI/ML:** OpenAI, Anthropic, Google AI, Cohere, Replicate, Hugging Face
- **Auth:** Clerk, Auth0, Supabase Auth
- **Cloud:** AWS, Google Cloud, Azure
- **Database:** Supabase, PlanetScale, Neon, MongoDB, PostgreSQL, MySQL
- **Payment:** Stripe, PayPal
- **Messaging:** Twilio, SendGrid, Resend
- **And more:** GitHub tokens, private keys, JWTs, generic secrets

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

1. ✅ Run `npx ship-safe scan .` on your project
2. ✅ Run `npx ship-safe init` to add security configs
3. ✅ Add security headers to your Next.js config
4. ✅ Run `npx ship-safe checklist` before launching
5. ✅ If using AI features, implement [cost protection](./ai-defense/cost-protection.md)
6. ✅ If using Supabase, check the [RLS checklist](./configs/supabase/security-checklist.md)
7. ✅ If using Firebase, check the [Firebase checklist](./configs/firebase/security-checklist.md)

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

**Remember: Security isn't about being paranoid. It's about being prepared.**

Ship fast. Ship safe.
