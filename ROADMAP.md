# Ship Safe Roadmap

**Goal: Make ship-safe the definitive security reference for indie hackers and vibe coders.**

Based on current security research (OWASP 2025, industry breaches, emerging threats), here's the strategic plan.

---

## Phase 3: Expanded Secret Detection (v1.2)

### New Patterns to Add

Based on [39M+ secrets leaked on GitHub in 2024](https://gbhackers.com/massive-github-leak/):

| Pattern | Priority | Reason |
|---------|----------|--------|
| Anthropic API keys | Critical | AI apps everywhere |
| Clerk/Auth0 secrets | Critical | Auth provider keys |
| Resend/Postmark keys | High | Email services |
| Upstash Redis tokens | High | Serverless data |
| PlanetScale credentials | High | Serverless DB |
| Turso/LibSQL tokens | High | Edge databases |
| Neon Postgres strings | High | Serverless Postgres |
| Linear API keys | Medium | Project management |
| Notion API keys | Medium | Workspace access |
| Replicate API tokens | High | AI model hosting |
| Hugging Face tokens | High | ML models |
| DeepSeek API keys | High | AI provider |
| Groq API keys | High | AI inference |

**Files to modify:**
- `cli/utils/patterns.js` - Add new regex patterns

---

## Phase 4: Stack-Specific Security Configs (v1.3)

### Supabase Security Pack

Based on [CVE-2025-48757 and 83% of exposed Supabase DBs having RLS issues](https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/):

**Create:** `/configs/supabase/`

1. **`rls-templates.sql`** - Copy-paste RLS policies
   ```sql
   -- User can only see their own data
   CREATE POLICY "Users see own data" ON todos
     FOR SELECT USING (auth.uid() = user_id);
   ```

2. **`security-checklist.md`** - Supabase-specific audit
   - [ ] RLS enabled on ALL tables
   - [ ] Service role key NOT in frontend
   - [ ] Anon key only used client-side
   - [ ] HTTP extension not exposed to anon
   - [ ] Vault secrets not accessible to users

3. **`secure-client.ts`** - Safe Supabase client setup

### Firebase Security Pack

Based on [test mode being #1 cause of Firebase breaches](https://vibeappscanner.com/is-firebase-safe):

**Create:** `/configs/firebase/`

1. **`firestore-rules-templates.txt`** - Secure rules examples
2. **`storage-rules-templates.txt`** - Storage bucket rules
3. **`security-checklist.md`** - Firebase audit checklist
4. **`common-mistakes.md`** - What NOT to do

### Next.js Security Pack

**Expand:** `/configs/nextjs/`

1. **`middleware-auth.ts`** - Route protection middleware
2. **`api-rate-limit.ts`** - Rate limiting for API routes
3. **`env-validation.ts`** - Zod schema for env vars
4. **`csrf-protection.ts`** - CSRF token handling

---

## Phase 5: AI/LLM Security Module (v1.4)

Based on [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/):

### Expand `/ai-defense/`

1. **`prompt-injection-scanner.js`** - Detect injection attempts
   ```javascript
   const INJECTION_PATTERNS = [
     /ignore\s+(all\s+)?previous\s+instructions/i,
     /disregard\s+(all\s+)?(previous|prior)/i,
     /system\s*prompt/i,
     /DAN\s*mode/i,
     // ... more patterns
   ];
   ```

2. **`llm-security-checklist.md`** - OWASP LLM Top 10 checklist
   - [ ] Input validation before LLM
   - [ ] Output sanitization after LLM
   - [ ] Rate limiting on AI endpoints
   - [ ] Cost caps configured
   - [ ] No sensitive data in prompts
   - [ ] System prompt not exposed

3. **`cost-protection.md`** - Prevent API bill attacks
   - Token limits per request
   - Daily spend caps
   - User-level quotas
   - Alerting on anomalies

4. **`rag-security.md`** - Vector DB security
   - Based on new OWASP "Vector and Embedding Weaknesses" category
   - Secure Pinecone/Weaviate/Chroma configs

### New CLI Command

```bash
npx ship-safe scan-ai .  # Scan for AI-specific vulnerabilities
```

---

## Phase 6: Mobile Security Module (v1.5)

Based on [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/):

### Create `/mobile/`

1. **`react-native-checklist.md`**
   - [ ] No secrets in JS bundle
   - [ ] Certificate pinning enabled
   - [ ] Secure storage for tokens
   - [ ] Biometric auth implemented
   - [ ] Debug mode disabled in release

2. **`expo-security.md`** - Expo-specific guidance
3. **`flutter-checklist.md`** - Flutter security
4. **`api-security-mobile.md`** - Mobile API best practices

---

## Phase 7: Authentication Security (v1.6)

Based on [JWT/OAuth best practices 2025](https://jwt.app/blog/jwt-best-practices/):

### Create `/auth/`

1. **`jwt-checklist.md`**
   - [ ] Using RS256 or ES256 (not HS256 in production)
   - [ ] Short expiry (15-60 min)
   - [ ] Refresh token rotation
   - [ ] Tokens in httpOnly cookies
   - [ ] CSRF protection enabled

2. **`oauth-security.md`** - OAuth 2.0/2.1 best practices
3. **`session-security.md`** - Secure session management
4. **`clerk-security.ts`** - Clerk hardening config
5. **`auth0-security.ts`** - Auth0 hardening config
6. **`nextauth-security.ts`** - NextAuth.js secure config

---

## Phase 8: API Security (v1.7)

Based on [80% of breaches will involve APIs by 2026](https://devcom.com/tech-blog/api-security-best-practices-protect-your-data/):

### Create `/api-security/`

1. **`rate-limiting/`**
   - `express-rate-limit.js`
   - `nextjs-rate-limit.ts`
   - `upstash-ratelimit.ts`
   - `cloudflare-rules.md`

2. **`cors-configs/`**
   - `nextjs-cors.ts`
   - `express-cors.js`
   - `common-mistakes.md`

3. **`api-checklist.md`**
   - [ ] Authentication on all endpoints
   - [ ] Rate limiting configured
   - [ ] CORS allowlist (not `*`)
   - [ ] Input validation
   - [ ] Output encoding
   - [ ] No sensitive data in URLs
   - [ ] Proper error handling

---

## Phase 9: Serverless Security (v1.8)

Based on [serverless security risks 2026](https://blog.qualys.com/product-tech/2026/01/15/serverless-security-risks-identity-ssrf-rce):

### Create `/serverless/`

1. **`aws-lambda-checklist.md`**
   - [ ] Minimal IAM permissions
   - [ ] Environment variables encrypted
   - [ ] VPC configured (if needed)
   - [ ] Logging enabled
   - [ ] No hardcoded secrets

2. **`vercel-security.md`** - Vercel edge function security
3. **`cloudflare-workers.md`** - Workers security
4. **`iam-policies/`** - Least-privilege IAM examples

---

## Phase 10: CI/CD Security Scanner (v2.0)

### GitHub Action: `ship-safe-action`

```yaml
- uses: asamassekou10/ship-safe-action@v1
  with:
    scan-secrets: true
    scan-dependencies: true
    scan-ai: true
    fail-on: high
```

### Features
- Secret scanning (existing)
- Dependency vulnerability check (`npm audit`)
- SAST integration
- AI vulnerability scanning
- PR comments with findings
- SARIF output for GitHub Security tab

---

## Phase 11: Interactive Web Dashboard (v2.1)

### `ship-safe.dev` Website

1. **Online Scanner** - Paste code, get instant results
2. **Checklist Generator** - Select stack, get custom checklist
3. **Learning Center** - Interactive security tutorials
4. **Community Patterns** - User-submitted detection rules

---

## Implementation Priority

| Phase | Version | Priority | Impact |
|-------|---------|----------|--------|
| 3 - More Patterns | v1.2 | **HIGH** | Catches more leaks |
| 4 - Stack Configs | v1.3 | **HIGH** | Supabase/Firebase huge |
| 5 - AI Security | v1.4 | **HIGH** | Every app has AI now |
| 6 - Mobile | v1.5 | MEDIUM | Growing audience |
| 7 - Auth | v1.6 | **HIGH** | Core security |
| 8 - API | v1.7 | **HIGH** | 80% of breaches |
| 9 - Serverless | v1.8 | MEDIUM | Niche but critical |
| 10 - CI/CD | v2.0 | **HIGH** | Automation |
| 11 - Dashboard | v2.1 | LOW | Nice to have |

---

## Sources

### OWASP Standards
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)

### Industry Research
- [39M Secrets Leaked on GitHub](https://gbhackers.com/massive-github-leak/)
- [API Breaches 2024](https://salt.security/blog/its-2024-and-the-api-breaches-keep-coming)
- [Supabase RLS Vulnerabilities](https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/)
- [Firebase Misconfigurations](https://vibeappscanner.com/is-firebase-safe)
- [Serverless Security 2026](https://blog.qualys.com/product-tech/2026/01/15/serverless-security-risks-identity-ssrf-rce)
- [JWT Best Practices 2025](https://jwt.app/blog/jwt-best-practices/)
- [API Security 2026](https://devcom.com/tech-blog/api-security-best-practices-protect-your-data/)

---

## Contributing

Want to help build this? Pick a phase and open a PR!

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
