# AI Security Audit Prompts

**Copy and paste these prompts to your AI coding assistant (Claude, ChatGPT, Cursor, etc.) to automatically secure your project.**

---

## The Complete Audit Prompt

```
I need you to run a comprehensive security audit on my project using ship-safe. Please do the following:

## Phase 1: Secret Scanning
1. Run: npx ship-safe scan .
2. If any secrets are found:
   - Help me move them to environment variables
   - Create a .env.example file with placeholder values
   - Make sure .env is in .gitignore

## Phase 2: Security Configs
3. Run: npx ship-safe init
4. Help me integrate the security headers into my framework config

## Phase 3: Security Checklist
5. Run: npx ship-safe checklist --no-interactive
6. For any checklist items that aren't done, help me implement them

## Priorities:
- No hardcoded API keys or secrets
- Environment variables properly configured
- Security headers set up
- Database has proper access controls (RLS/security rules)
- Rate limiting on sensitive endpoints

Be thorough but keep explanations simple - I'm learning as we go.
```

---

## Quick Version

For a faster audit:

```
Run "npx ship-safe scan ." on my project and fix any secrets you find.
Then run "npx ship-safe init" to add security configs.
Finally run "npx ship-safe checklist --no-interactive" and help me fix any issues.
Explain what you're doing as you go.
```

---

## Framework-Specific Prompts

### Next.js Projects

```
Run a security audit on my Next.js project:

1. SCAN: npx ship-safe scan .
2. INIT: npx ship-safe init --headers
3. HEADERS: Help me add the security headers from security-headers.config.js to next.config.js
4. API ROUTES: Check that my API routes:
   - Have proper authentication
   - Don't expose sensitive data in responses
   - Have rate limiting (use ship-safe's snippets/rate-limiting/nextjs-middleware.ts as reference)
5. ENV VARS: Verify NEXT_PUBLIC_ vars don't contain secrets
6. CORS: Help me configure CORS properly (reference: ship-safe's snippets/api-security/cors-config.ts)
```

### Supabase Projects

```
Run a security audit on my Supabase project:

1. SCAN: npx ship-safe scan .
   - Especially check for service_role key in frontend code

2. RLS POLICIES: Help me verify Row Level Security is enabled on all tables
   - Reference: ship-safe's configs/supabase/rls-templates.sql for common patterns
   - Check the security checklist: configs/supabase/security-checklist.md

3. CLIENT SETUP: Review my Supabase client initialization
   - Reference: ship-safe's configs/supabase/secure-client.ts
   - Make sure I'm only using anon key in client-side code
   - Service role key should only be in server-side code

4. AUTH: Check my authentication setup:
   - Email confirmation enabled?
   - Password requirements configured?
   - OAuth redirect URLs restricted?

5. STORAGE: If using Supabase Storage, verify bucket policies
```

### Firebase Projects

```
Run a security audit on my Firebase project:

1. SCAN: npx ship-safe scan .
   - Check for service account JSON files
   - Check for admin SDK credentials in frontend

2. FIRESTORE RULES: Review my Firestore security rules
   - Reference: ship-safe's configs/firebase/firestore-rules.txt
   - Check for "allow read, write: if true" (dangerous!)
   - Verify user data is protected with auth checks

3. STORAGE RULES: If using Firebase Storage, review rules
   - Reference: ship-safe's configs/firebase/storage-rules.txt
   - Check file type and size restrictions

4. CHECKLIST: Go through ship-safe's configs/firebase/security-checklist.md
   - App Check enabled?
   - API key restrictions configured?
   - Authentication settings secure?

5. ENVIRONMENT: Verify firebase config doesn't contain admin credentials
```

### Projects with AI/LLM Features

```
Run a security audit on my AI-powered app:

1. SCAN: npx ship-safe scan .
   - Check for OpenAI, Anthropic, Cohere, Replicate keys
   - Check for Hugging Face tokens

2. PROMPT INJECTION: Review my AI endpoints for injection vulnerabilities
   - Reference: ship-safe's ai-defense/prompt-injection-patterns.js
   - Help me add input validation using containsInjectionAttempt()
   - Check that user input is in 'user' role, not 'system'

3. COST PROTECTION: Implement safeguards against cost explosions
   - Reference: ship-safe's ai-defense/cost-protection.md
   - Add token limits (max_tokens parameter)
   - Add rate limiting per user
   - Set up daily/monthly budget caps
   - Configure provider-side hard limits

4. LLM SECURITY CHECKLIST: Go through ship-safe's ai-defense/llm-security-checklist.md
   - System prompt separated from user input?
   - Output validation implemented?
   - No PII sent to LLM?
   - No secrets in system prompts?

5. SYSTEM PROMPT: Harden my system prompt
   - Reference: ship-safe's ai-defense/system-prompt-armor.md
```

### API-Heavy Projects

```
Run a security audit on my API:

1. SCAN: npx ship-safe scan .

2. INPUT VALIDATION: Review all API endpoints for proper validation
   - Reference: ship-safe's snippets/api-security/input-validation.ts
   - Help me add Zod schemas for request validation
   - Check for SQL injection vulnerabilities
   - Validate file uploads (type, size)

3. AUTHENTICATION: Check all sensitive endpoints require auth
   - Reference: ship-safe's snippets/auth/jwt-checklist.md
   - Verify JWT implementation is secure
   - Check token expiration and refresh logic

4. RATE LIMITING: Add rate limiting to prevent abuse
   - Reference: ship-safe's snippets/rate-limiting/upstash-ratelimit.ts
   - Stricter limits on auth endpoints
   - Per-user and global limits

5. CORS: Configure CORS properly
   - Reference: ship-safe's snippets/api-security/cors-config.ts
   - No wildcard (*) origins in production
   - Explicit allowlist of domains

6. API CHECKLIST: Go through ship-safe's snippets/api-security/api-security-checklist.md
```

### Full-Stack SaaS Projects

```
Run a comprehensive security audit on my SaaS application:

## Phase 1: Secrets
- Run: npx ship-safe scan .
- Fix any leaked API keys, database URLs, or credentials

## Phase 2: Database Security
- If Supabase: Check RLS policies (reference: configs/supabase/)
- If Firebase: Check security rules (reference: configs/firebase/)
- Verify no SQL injection vulnerabilities

## Phase 3: Authentication
- Review JWT implementation (reference: snippets/auth/jwt-checklist.md)
- Check session management
- Verify password requirements

## Phase 4: API Security
- Add input validation with Zod (reference: snippets/api-security/input-validation.ts)
- Configure CORS (reference: snippets/api-security/cors-config.ts)
- Add rate limiting (reference: snippets/rate-limiting/)

## Phase 5: AI Features (if applicable)
- Check for prompt injection (reference: ai-defense/prompt-injection-patterns.js)
- Implement cost protection (reference: ai-defense/cost-protection.md)

## Phase 6: Infrastructure
- Run: npx ship-safe init
- Add security headers
- Run: npx ship-safe checklist --no-interactive

Help me prioritize fixes by severity.
```

---

## What Happens Next

Your AI assistant will:

1. **Scan** - Find leaked API keys, passwords, or secrets (50+ patterns)
2. **Fix** - Help you move secrets to environment variables
3. **Protect** - Add security headers, RLS policies, rate limiting
4. **Educate** - Explain why each fix matters

---

## Available Resources in ship-safe

| Category | Files |
|----------|-------|
| **Configs** | Next.js headers, Supabase RLS, Firebase rules |
| **Snippets** | Rate limiting, JWT security, CORS, input validation |
| **AI Defense** | Prompt injection, cost protection, LLM checklist |
| **Checklists** | Launch day, Supabase, Firebase, API, JWT |

---

## Pro Tips

- Run this audit **before** your first git push
- Re-run after adding new integrations (Stripe, auth providers, AI APIs, etc.)
- Add `npx ship-safe scan .` to your CI pipeline to catch future leaks
- For AI features, always implement cost protection BEFORE launch
- Use the framework-specific checklists for thorough coverage

---

## CI/CD Integration

Add to your GitHub Actions:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx ship-safe scan . --json
```

---

**Remember: Your AI assistant can help you ship fast AND ship safe.**
