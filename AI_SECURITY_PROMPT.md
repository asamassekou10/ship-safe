# AI Security Audit Prompt

**Copy and paste this prompt to your AI coding assistant (Claude, ChatGPT, Cursor, etc.) to automatically secure your project.**

---

## The Prompt

```
I need you to run a security audit on my project. Please do the following:

1. Run this command to scan for leaked secrets:
   npx ship-safe scan .

2. If any secrets are found:
   - Help me move them to environment variables
   - Create a .env.example file with placeholder values
   - Make sure .env is in .gitignore

3. Run this command to add security configs:
   npx ship-safe init

4. If this is a Next.js project, help me integrate the security headers into next.config.js

5. Run through the security checklist:
   npx ship-safe checklist --no-interactive

6. For any checklist items that aren't done, help me implement them.

Focus on these priorities:
- No hardcoded API keys or secrets
- Environment variables properly configured
- Security headers set up
- Database has proper access controls

Be thorough but keep explanations simple - I'm learning as we go.
```

---

## Quick Version

For a faster audit, use this shorter prompt:

```
Run "npx ship-safe scan ." on my project and fix any secrets you find. Then run "npx ship-safe init" to add security configs. Explain what you're doing as you go.
```

---

## For Specific Frameworks

### Next.js Projects

```
Run a security audit on my Next.js project:
1. npx ship-safe scan .
2. npx ship-safe init --headers
3. Help me add the security headers to next.config.js
4. Check that my API routes don't expose sensitive data
5. Verify my environment variables are set up correctly
```

### Supabase Projects

```
Run a security audit on my Supabase project:
1. npx ship-safe scan .
2. Check that I'm not exposing the service_role key in frontend code
3. Help me verify my RLS policies are enabled
4. Make sure I'm only using the anon key in client-side code
```

### Projects with AI/LLM Features

```
Run a security audit on my AI-powered app:
1. npx ship-safe scan . (especially check for OpenAI/Anthropic keys)
2. Review my system prompts for injection vulnerabilities
3. Check that I have rate limiting on AI endpoints
4. Help me add the defensive prompt from ship-safe's ai-defense folder
```

---

## What Happens Next

Your AI assistant will:

1. **Scan** - Find any leaked API keys, passwords, or secrets
2. **Fix** - Help you move secrets to environment variables
3. **Protect** - Add security headers and .gitignore rules
4. **Educate** - Explain why each fix matters

---

## Pro Tips

- Run this audit **before** your first git push
- Re-run after adding new integrations (Stripe, auth providers, etc.)
- Add `npx ship-safe scan .` to your CI pipeline to catch future leaks

---

**Remember: Your AI assistant can help you ship fast AND ship safe.**
