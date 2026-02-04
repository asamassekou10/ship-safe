# JWT Security Checklist

**Secure your JWT implementation before launch.**

Based on [JWT Best Practices 2025](https://jwt.app/blog/jwt-best-practices/) and OWASP guidelines.

---

## Critical: Algorithm & Signing

### 1. [ ] Using secure algorithm (not HS256 in production)

```typescript
// BAD: HS256 with weak secret
jwt.sign(payload, 'my-secret', { algorithm: 'HS256' });

// GOOD: RS256 (asymmetric) for production
jwt.sign(payload, privateKey, { algorithm: 'RS256' });

// GOOD: ES256 (elliptic curve) - smaller keys, same security
jwt.sign(payload, privateKey, { algorithm: 'ES256' });
```

**Why:** HS256 secrets can be brute-forced. RS256/ES256 use public/private key pairs.

### 2. [ ] Algorithm specified in verification (not "auto")

```typescript
// BAD: Accepts any algorithm (algorithm confusion attack)
jwt.verify(token, key);

// GOOD: Explicitly specify allowed algorithms
jwt.verify(token, key, { algorithms: ['RS256'] });
```

### 3. [ ] Strong secret/key used

For HS256 (if you must use it):
- [ ] At least 256 bits (32 characters)
- [ ] Random, not dictionary words
- [ ] Stored in environment variable

```bash
# Generate a strong secret
openssl rand -base64 32
```

---

## Critical: Token Lifetime

### 4. [ ] Access tokens are short-lived

```typescript
// GOOD: 15 minutes for access tokens
jwt.sign(payload, key, { expiresIn: '15m' });

// BAD: Long-lived access tokens
jwt.sign(payload, key, { expiresIn: '30d' }); // Too long!
```

**Recommended lifetimes:**
- Access tokens: 15-60 minutes
- Refresh tokens: 7-30 days
- Remember me: 30-90 days (with re-auth for sensitive actions)

### 5. [ ] Expiration claim (exp) always set

```typescript
// Always verify expiration
jwt.verify(token, key, {
  algorithms: ['RS256'],
  clockTolerance: 30, // 30 seconds tolerance for clock skew
});
```

### 6. [ ] Refresh token rotation implemented

```typescript
// On each refresh:
// 1. Invalidate old refresh token
// 2. Issue new access token
// 3. Issue new refresh token

async function refreshTokens(oldRefreshToken: string) {
  // Verify and invalidate old token
  const payload = await verifyAndInvalidateRefreshToken(oldRefreshToken);

  // Generate new tokens
  const accessToken = generateAccessToken(payload.userId);
  const refreshToken = generateRefreshToken(payload.userId);

  return { accessToken, refreshToken };
}
```

---

## High: Storage & Transmission

### 7. [ ] Tokens stored securely

| Storage | Access Token | Refresh Token |
|---------|--------------|---------------|
| **httpOnly cookie** | Best | Best |
| **Memory (JS variable)** | OK | No |
| **sessionStorage** | OK (temporary) | No |
| **localStorage** | Avoid | Never |

```typescript
// GOOD: httpOnly cookie (not accessible via JavaScript)
res.cookie('accessToken', token, {
  httpOnly: true,
  secure: true,        // HTTPS only
  sameSite: 'strict',  // CSRF protection
  maxAge: 15 * 60 * 1000, // 15 minutes
});

// BAD: localStorage (vulnerable to XSS)
localStorage.setItem('accessToken', token);
```

### 8. [ ] Secure flag set (HTTPS only)

```typescript
res.cookie('token', value, {
  secure: process.env.NODE_ENV === 'production',
});
```

### 9. [ ] SameSite attribute configured

```typescript
res.cookie('token', value, {
  sameSite: 'strict', // Prevents CSRF
  // Or 'lax' if you need cross-site GET requests
});
```

---

## High: Validation

### 10. [ ] All claims validated

```typescript
jwt.verify(token, key, {
  algorithms: ['RS256'],  // Algorithm
  issuer: 'https://myapp.com',  // Who issued it
  audience: 'https://api.myapp.com',  // Who it's for
  clockTolerance: 30,  // Clock skew tolerance
});
```

### 11. [ ] Issuer (iss) validated

```typescript
// Prevent tokens from other services being accepted
if (payload.iss !== 'https://myapp.com') {
  throw new Error('Invalid issuer');
}
```

### 12. [ ] Audience (aud) validated

```typescript
// Prevent tokens meant for other services
if (payload.aud !== 'https://api.myapp.com') {
  throw new Error('Invalid audience');
}
```

---

## Medium: Token Revocation

### 13. [ ] Token revocation mechanism exists

JWTs can't be invalidated by default. Implement one of:

**Option A: Short expiry + refresh tokens**
- Access tokens are short-lived (15 min)
- Revoke refresh tokens to force re-authentication

**Option B: Token blacklist/denylist**
```typescript
const revokedTokens = new Set();

function verifyToken(token) {
  const payload = jwt.verify(token, key);
  if (revokedTokens.has(payload.jti)) {
    throw new Error('Token revoked');
  }
  return payload;
}
```

**Option C: Token versioning**
```typescript
// Store token version in database
// Increment on password change/logout
if (payload.tokenVersion !== user.tokenVersion) {
  throw new Error('Token invalidated');
}
```

### 14. [ ] Logout invalidates tokens

```typescript
async function logout(userId: string) {
  // Increment token version to invalidate all tokens
  await db.user.update({
    where: { id: userId },
    data: { tokenVersion: { increment: 1 } },
  });

  // Clear refresh tokens
  await db.refreshToken.deleteMany({
    where: { userId },
  });
}
```

---

## Medium: Payload Security

### 15. [ ] No sensitive data in payload

```typescript
// BAD: Sensitive data in JWT (readable by anyone with the token)
{
  sub: 'user123',
  email: 'user@example.com',
  passwordHash: '...',          // NEVER store passwords/hashes!
  ssn: '123-45-6789',           // NEVER!
  creditCard: '4111...',        // NEVER!
}

// GOOD: Minimal payload
{
  sub: 'user123',
  role: 'user',
  iat: 1234567890,
  exp: 1234568790,
}
```

### 16. [ ] JTI (JWT ID) included for tracking

```typescript
import { v4 as uuid } from 'uuid';

const token = jwt.sign({
  sub: userId,
  jti: uuid(),  // Unique token ID
}, key);
```

---

## Code Examples

### Complete JWT Service

```typescript
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';

const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

interface TokenPayload {
  sub: string;
  role: string;
  jti: string;
  iat: number;
  exp: number;
}

export function generateAccessToken(userId: string, role: string): string {
  return jwt.sign(
    {
      sub: userId,
      role,
      jti: randomUUID(),
    },
    process.env.JWT_PRIVATE_KEY!,
    {
      algorithm: 'RS256',
      expiresIn: ACCESS_TOKEN_EXPIRY,
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    }
  );
}

export function verifyAccessToken(token: string): TokenPayload {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY!, {
    algorithms: ['RS256'],
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE,
    clockTolerance: 30,
  }) as TokenPayload;
}
```

---

## Tools

- **jwt.io** - Decode and inspect JWTs
- **jwt-cli** - Command line JWT tool
- **ship-safe** - Scan for leaked tokens in code

```bash
npx ship-safe scan .
```

---

**Remember: JWTs are not encrypted by default. Anyone with the token can read the payload. Only the signature prevents tampering.**
