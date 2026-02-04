# API Security Checklist

**Secure your API endpoints before launch.**

Based on [OWASP API Security Top 10 2023](https://owasp.org/API-Security/) and real-world incidents.

---

## Critical: Authentication & Authorization

### 1. [ ] Authentication required on all sensitive endpoints

```typescript
// GOOD: Auth check at the start
export async function POST(request: Request) {
  const session = await auth();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  // ... proceed
}

// BAD: No auth check
export async function POST(request: Request) {
  const { userId } = await request.json();
  // Anyone can access this!
}
```

### 2. [ ] Authorization checked for resource access

```typescript
// GOOD: Check ownership before action
async function deletePost(postId: string, userId: string) {
  const post = await db.post.findUnique({ where: { id: postId } });

  if (!post) {
    throw new Error('Post not found');
  }

  // Check ownership
  if (post.authorId !== userId) {
    throw new Error('Not authorized to delete this post');
  }

  await db.post.delete({ where: { id: postId } });
}

// BAD: No ownership check (IDOR vulnerability)
async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } }); // Anyone can delete!
}
```

### 3. [ ] Object-level authorization (IDOR prevention)

```typescript
// Always verify user has access to the specific resource
async function getDocument(documentId: string, userId: string) {
  const doc = await db.document.findFirst({
    where: {
      id: documentId,
      // Include ownership/access check in query
      OR: [
        { ownerId: userId },
        { sharedWith: { some: { userId } } },
      ],
    },
  });

  if (!doc) {
    // Don't reveal if document exists
    return new Response('Not found', { status: 404 });
  }

  return doc;
}
```

### 4. [ ] Function-level authorization

```typescript
// Check user has permission for the action
const ADMIN_ONLY_ACTIONS = ['delete_user', 'view_all_users', 'modify_settings'];

function authorizeAction(user: User, action: string) {
  if (ADMIN_ONLY_ACTIONS.includes(action) && user.role !== 'admin') {
    throw new Error('Forbidden');
  }
}
```

---

## Critical: Input Validation

### 5. [ ] All input validated with strict schemas

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100),
  age: z.number().int().min(13).max(120).optional(),
});

export async function POST(request: Request) {
  const body = await request.json();
  const result = createUserSchema.safeParse(body);

  if (!result.success) {
    return Response.json({ error: result.error.issues }, { status: 400 });
  }

  // Safe to use result.data
}
```

### 6. [ ] Query parameters validated

```typescript
// Validate pagination to prevent resource exhaustion
const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20), // Cap limit!
});

export async function GET(request: Request) {
  const url = new URL(request.url);
  const params = Object.fromEntries(url.searchParams);

  const { page, limit } = paginationSchema.parse(params);
  // ...
}
```

### 7. [ ] File uploads validated

```typescript
const ALLOWED_TYPES = ['image/jpeg', 'image/png'];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

function validateFile(file: File) {
  if (!ALLOWED_TYPES.includes(file.type)) {
    throw new Error('Invalid file type');
  }
  if (file.size > MAX_SIZE) {
    throw new Error('File too large');
  }
}
```

### 8. [ ] No SQL injection via parameterized queries

```typescript
// GOOD: Parameterized (with Prisma)
const user = await prisma.user.findUnique({ where: { id: userId } });

// GOOD: Parameterized (with raw SQL)
const [user] = await sql`SELECT * FROM users WHERE id = ${userId}`;

// BAD: String concatenation
const query = `SELECT * FROM users WHERE id = '${userId}'`; // SQL INJECTION!
```

---

## High: Rate Limiting

### 9. [ ] Rate limiting per user

```typescript
import { Ratelimit } from '@upstash/ratelimit';

const ratelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(100, '1 m'), // 100 req/min
});

async function handler(request: Request, userId: string) {
  const { success, remaining } = await ratelimit.limit(userId);

  if (!success) {
    return new Response('Too Many Requests', { status: 429 });
  }
}
```

### 10. [ ] Stricter limits on sensitive endpoints

```typescript
const authRatelimit = new Ratelimit({
  limiter: Ratelimit.slidingWindow(5, '15 m'), // 5 attempts per 15 min
});

async function login(email: string) {
  const { success } = await authRatelimit.limit(`login:${email}`);
  if (!success) {
    throw new Error('Too many login attempts');
  }
}
```

### 11. [ ] Global rate limiting as backup

```typescript
const globalRatelimit = new Ratelimit({
  limiter: Ratelimit.fixedWindow(10000, '1 h'), // 10k total req/hour
  prefix: 'global',
});
```

---

## High: Security Headers & CORS

### 12. [ ] CORS configured with specific origins

```typescript
// GOOD: Specific origins
const ALLOWED_ORIGINS = ['https://yourapp.com'];

// BAD: Wildcard (allows any origin)
// 'Access-Control-Allow-Origin': '*'
```

### 13. [ ] Security headers set

```typescript
// next.config.js
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];
```

---

## High: Error Handling

### 14. [ ] Errors don't leak internal details

```typescript
// GOOD: Generic error message
catch (error) {
  console.error('Internal error:', error); // Log full error
  return Response.json(
    { error: 'An error occurred' }, // Return generic message
    { status: 500 }
  );
}

// BAD: Leaking internal details
catch (error) {
  return Response.json(
    { error: error.message, stack: error.stack }, // DON'T!
    { status: 500 }
  );
}
```

### 15. [ ] Consistent error response format

```typescript
interface ErrorResponse {
  error: string;
  code?: string;
  details?: { field: string; message: string }[];
}

// 400: Validation errors
{ error: 'Validation failed', details: [...] }

// 401: Authentication required
{ error: 'Authentication required' }

// 403: Permission denied
{ error: 'Permission denied' }

// 404: Resource not found
{ error: 'Resource not found' }

// 429: Rate limited
{ error: 'Too many requests', retryAfter: 60 }

// 500: Server error
{ error: 'Internal server error' }
```

---

## Medium: Data Protection

### 16. [ ] Sensitive data not exposed in responses

```typescript
// GOOD: Select only needed fields
const user = await prisma.user.findUnique({
  where: { id },
  select: {
    id: true,
    name: true,
    email: true,
    // NOT: password, apiKeys, internalNotes
  },
});

// Or use DTOs
function toPublicUser(user: User) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
  };
}
```

### 17. [ ] Audit logging for sensitive actions

```typescript
async function sensitiveAction(userId: string, action: string, data: any) {
  await db.auditLog.create({
    data: {
      userId,
      action,
      metadata: JSON.stringify(data),
      ip: request.headers.get('x-forwarded-for'),
      timestamp: new Date(),
    },
  });
}
```

---

## Medium: Resource Management

### 18. [ ] Response size limits

```typescript
// Limit array sizes in responses
const items = await db.item.findMany({
  take: Math.min(limit, 100), // Never return more than 100
});
```

### 19. [ ] Request timeout configured

```typescript
// Vercel
export const maxDuration = 10; // 10 seconds max

// Express
app.use(timeout('10s'));
```

### 20. [ ] Expensive operations limited

```typescript
// Limit complex queries
const MAX_FILTER_DEPTH = 3;
const MAX_INCLUDES = 5;

function validateQuery(query: any) {
  if (countNesting(query.where) > MAX_FILTER_DEPTH) {
    throw new Error('Query too complex');
  }
  if (Object.keys(query.include || {}).length > MAX_INCLUDES) {
    throw new Error('Too many includes');
  }
}
```

---

## Quick Reference

| Vulnerability | Mitigation |
|---------------|------------|
| Broken Authentication | Require auth, validate sessions |
| Broken Authorization | Check ownership, role-based access |
| IDOR | Include user context in queries |
| SQL Injection | Parameterized queries only |
| Mass Assignment | Explicit field selection |
| Rate Limit Bypass | Per-user + global limits |
| CORS Misconfiguration | Explicit origin allowlist |
| Verbose Errors | Log details, return generic messages |

---

## Testing Checklist

```
1. Try accessing resources without authentication
2. Try accessing other users' resources with your auth
3. Try SQL injection: ' OR 1=1 --
4. Try sending requests faster than rate limits
5. Try uploading files with spoofed MIME types
6. Try extremely large payloads
7. Try malformed JSON/XML
8. Try accessing admin endpoints as regular user
9. Try IDOR by changing IDs in requests
10. Check error responses for sensitive info
```

---

**Remember: Every endpoint is an attack surface. Validate everything, trust nothing.**
