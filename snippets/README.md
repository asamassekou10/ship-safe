# Security Snippets

**Copy-paste code blocks for common security patterns.**

This folder contains drop-in code snippets for securing your application. Each snippet is heavily commented to explain *why* it works.

---

## Available Snippets

### Rate Limiting

| File | Description |
|------|-------------|
| [upstash-ratelimit.ts](./rate-limiting/upstash-ratelimit.ts) | Production-ready rate limiting with Upstash Redis. Includes different limiters for API, auth, and AI endpoints. |
| [nextjs-middleware.ts](./rate-limiting/nextjs-middleware.ts) | In-memory rate limiting at the Next.js middleware level. Good for development or simple deployments. |

**Quick Start:**
```typescript
import { apiRatelimit } from './rate-limiting/upstash-ratelimit';

const { success } = await apiRatelimit.limit(userId);
if (!success) {
  return new Response('Too Many Requests', { status: 429 });
}
```

---

### Authentication

| File | Description |
|------|-------------|
| [jwt-checklist.md](./auth/jwt-checklist.md) | Complete JWT security checklist. Covers algorithms, token lifetime, storage, validation, and revocation. |

**Key Points:**
- Use RS256/ES256, not HS256 with weak secrets
- Access tokens: 15-60 minutes max
- Store in httpOnly cookies, not localStorage
- Always validate issuer and audience claims

---

### API Security

| File | Description |
|------|-------------|
| [cors-config.ts](./api-security/cors-config.ts) | CORS configurations for Next.js, Express, Fastify, Hono, and Vercel Edge. |
| [input-validation.ts](./api-security/input-validation.ts) | Zod schemas and validation patterns for API endpoints. Includes file upload validation. |
| [api-security-checklist.md](./api-security/api-security-checklist.md) | Comprehensive API security checklist based on OWASP API Security Top 10. |

**Quick Start (CORS):**
```typescript
const ALLOWED_ORIGINS = ['https://yourapp.com'];

// Only allow specific origins
if (origin && ALLOWED_ORIGINS.includes(origin)) {
  headers['Access-Control-Allow-Origin'] = origin;
}
```

**Quick Start (Validation):**
```typescript
import { z } from 'zod';

const schema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
});

const result = schema.safeParse(body);
if (!result.success) {
  return Response.json({ error: result.error.issues }, { status: 400 });
}
```

---

## Usage Pattern

Each snippet follows this format:

```
// =============================================================================
// WHAT: Brief description
// WHY: What attack/vulnerability this prevents
// HOW: Integration instructions
// =============================================================================

[actual code with inline comments]
```

---

## Related Resources

- **[/configs](../configs/)** - Framework configs (Next.js headers, Supabase RLS, Firebase rules)
- **[/ai-defense](../ai-defense/)** - AI/LLM security (prompt injection, cost protection)
- **[/checklists](../checklists/)** - Security checklists (launch day)

---

## Contributing

Have a security snippet that saved your app? Add it here!

1. Create a new file in the appropriate subfolder
2. Add extensive comments explaining:
   - What attack this prevents
   - How to integrate it
   - Common gotchas
3. Open a PR

---

## What's Next

Future additions planned:
- Webhook signature verification (Stripe, GitHub)
- OAuth state parameter handling
- CSRF protection patterns
- Content Security Policy builder
