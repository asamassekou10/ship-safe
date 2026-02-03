# Security Snippets

**Copy-paste code blocks for common security patterns.**

This folder contains drop-in code snippets for securing your application. Each snippet is heavily commented to explain *why* it works.

---

## Coming Soon

- **Rate Limiting**
  - Express.js middleware
  - Next.js API route wrapper
  - Upstash Redis implementation

- **Authentication**
  - Secure session configuration
  - JWT validation middleware
  - OAuth state parameter handling

- **Input Validation**
  - Zod schemas for common patterns
  - SQL injection prevention
  - XSS sanitization

- **API Security**
  - CORS configuration
  - API key validation
  - Webhook signature verification (Stripe, GitHub)

---

## Contributing

Have a security snippet that saved your app? Add it here!

1. Create a new file: `snippets/your-snippet-name.{js,ts,py}`
2. Add extensive comments explaining:
   - What attack this prevents
   - How to integrate it
   - Common gotchas
3. Open a PR

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
