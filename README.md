# Ship Safe

**Don't let vibe coding leak your API keys.**

You're shipping fast. You're using AI to write code. You're one `git push` away from exposing your database credentials to the world.

**Ship Safe** is a security toolkit for indie hackers and vibe coders who want to secure their MVP in 5 minutes, not 5 days.

---

## Why This Exists

Vibe coding is powerful. You can build a SaaS in a weekend. But speed creates blind spots:

- AI-generated code often hardcodes secrets
- Default configs ship with debug mode enabled
- "I'll fix it later" becomes "I got hacked"

This repo is your co-pilot for security. Copy, paste, ship safely.

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/asamassekou10/ship-safe.git

# Run the secret scanner on your project
python ship-safe/scripts/scan_secrets.py /path/to/your/project
```

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
- [Secret Scanner](./scripts/scan_secrets.py) - Finds leaked API keys in your codebase

### [`/snippets`](./snippets)
**Copy-paste code blocks for common security patterns.**
- Rate limiting, auth middleware, input validation (coming soon)

### [`/ai-defense`](./ai-defense)
**Protect your AI features from abuse.**
- [System Prompt Armor](./ai-defense/system-prompt-armor.md) - Prevent prompt injection attacks

---

## The 5-Minute Security Checklist

1. Run `scan_secrets.py` on your project
2. Copy the `.gitignore` from this repo
3. Add security headers to your config
4. Review the [Launch Day Checklist](./checklists/launch-day.md)
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
3. Include educational comments
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
