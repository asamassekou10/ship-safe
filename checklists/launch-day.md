# Launch Day Security Checklist

**Complete this checklist before you go live. Each item takes under 1 minute to verify.**

---

## The Checklist

### 1. [ ] No Exposed .git Folder
**Risk:** Attackers can download your entire codebase, including commit history with old secrets.

**How to check:**
```bash
curl -I https://yoursite.com/.git/config
```
If you get a 200 response, your git folder is exposed.

**Fix:** Configure your web server to deny access to `.git`:
- Nginx: `location ~ /\.git { deny all; }`
- Vercel/Netlify: Already blocked by default

---

### 2. [ ] Debug Mode Disabled
**Risk:** Debug mode exposes stack traces, environment variables, and internal paths.

**How to check:**
- Next.js: Ensure `NODE_ENV=production` in your deployment
- Django: `DEBUG = False` in settings
- Laravel: `APP_DEBUG=false` in .env
- Rails: Check `config/environments/production.rb`

**Fix:** Set production environment variables in your hosting platform.

---

### 3. [ ] Database RLS/Security Rules Enabled
**Risk:** Without row-level security, any authenticated user can read/write any data.

**How to check:**
- **Supabase:** Dashboard > Authentication > Policies (should have policies on every table)
- **Firebase:** Rules tab (should NOT be `allow read, write: if true`)

**Fix:** Define explicit RLS policies for each table/collection.

---

### 4. [ ] No Hardcoded API Keys in Frontend Code
**Risk:** Anyone can view your frontend source and steal your keys.

**How to check:**
```bash
# Run the ship-safe scanner
python scripts/scan_secrets.py ./src

# Or manually search
grep -r "sk-" ./src
grep -r "api_key" ./src
```

**Fix:** Move secrets to server-side environment variables. Use API routes to proxy requests.

---

### 5. [ ] HTTPS Enforced
**Risk:** HTTP traffic can be intercepted and modified (man-in-the-middle attacks).

**How to check:**
1. Visit `http://yoursite.com` (with http, not https)
2. It should redirect to `https://`

**Fix:**
- Most platforms (Vercel, Netlify, Cloudflare) do this automatically
- For custom servers, configure HTTP to HTTPS redirect

---

### 6. [ ] Security Headers Configured
**Risk:** Missing headers enable clickjacking, XSS, and data sniffing attacks.

**How to check:**
Visit [securityheaders.com](https://securityheaders.com) and enter your URL.

**Fix:** See `/configs/nextjs-security-headers.js` for a drop-in config.

Key headers to set:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000`

---

### 7. [ ] Rate Limiting on Auth Endpoints
**Risk:** Without rate limiting, attackers can brute-force passwords or spam your API.

**How to check:**
Try hitting your login endpoint 100 times quickly. Does it block you?

**Fix:**
- Use middleware like `express-rate-limit` or `@upstash/ratelimit`
- Most auth providers (Clerk, Auth0, Supabase Auth) include this

---

### 8. [ ] No Sensitive Data in URLs
**Risk:** URLs are logged by servers, browsers, and proxies. Tokens in URLs get leaked.

**How to check:**
Search your codebase for query parameters like:
- `?token=`
- `?api_key=`
- `?password=`

**Fix:** Send sensitive data in request headers or POST body, never in URLs.

---

### 9. [ ] Error Messages Don't Leak Info
**Risk:** Detailed errors help attackers understand your system.

**How to check:**
- Trigger an error (invalid login, bad input)
- Does the message reveal database names, file paths, or stack traces?

**Fix:**
- Show generic errors to users: "Something went wrong"
- Log detailed errors server-side only

---

### 10. [ ] Admin Routes Protected
**Risk:** Exposed admin panels are #1 target for attackers.

**How to check:**
Try accessing:
- `/admin`
- `/api/admin`
- `/dashboard`
- `/_next` (for Next.js internal routes)

**Fix:**
- Add authentication middleware to all admin routes
- Use separate subdomains for admin (e.g., `admin.yoursite.com`)
- IP whitelist if possible

---

## Bonus Checks (If You Have Time)

- [ ] **Dependency audit:** Run `npm audit` or `pip audit`
- [ ] **CORS configured:** Not set to `*` in production
- [ ] **Cookies secured:** `HttpOnly`, `Secure`, `SameSite` flags set
- [ ] **File uploads validated:** Check file types, not just extensions
- [ ] **SQL/NoSQL injection tested:** Try `'; DROP TABLE users;--` in input fields

---

## After Launch

Security is ongoing. Schedule monthly reviews:
1. Re-run this checklist
2. Check for dependency updates
3. Review access logs for suspicious activity
4. Rotate API keys quarterly

---

**You've got this. Ship it.**
