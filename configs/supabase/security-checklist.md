# Supabase Security Checklist

**Complete this checklist before launching your Supabase-powered app.**

Based on [CVE-2025-48757](https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/) and common pentesting findings.

---

## Critical: Row Level Security (RLS)

### 1. [ ] RLS is ENABLED on ALL tables

```sql
-- Check which tables DON'T have RLS
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'public'
AND tablename NOT IN (
  SELECT tablename::text FROM pg_class
  WHERE relrowsecurity = true
);
```

**If any tables appear, enable RLS immediately:**
```sql
ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;
```

### 2. [ ] Every table has at least one policy

```sql
-- Tables with RLS enabled but NO policies (locked to everyone!)
SELECT tablename FROM pg_tables
WHERE schemaname = 'public'
AND tablename IN (
  SELECT tablename::text FROM pg_class WHERE relrowsecurity = true
)
AND tablename NOT IN (
  SELECT tablename FROM pg_policies
);
```

### 3. [ ] Policies use `auth.uid()` not hardcoded values

**Good:**
```sql
USING (auth.uid() = user_id)
```

**Bad:**
```sql
USING (user_id = 'some-uuid')  -- Hardcoded!
```

### 4. [ ] INSERT policies have `WITH CHECK`

```sql
-- Without WITH CHECK, users can insert data for other users!
CREATE POLICY "Users insert own data"
ON your_table FOR INSERT
WITH CHECK (auth.uid() = user_id);  -- This is required!
```

### 5. [ ] UPDATE policies have both `USING` and `WITH CHECK`

```sql
-- USING: which rows can be updated
-- WITH CHECK: what the new values must satisfy
CREATE POLICY "Users update own data"
ON your_table FOR UPDATE
USING (auth.uid() = user_id)         -- Can only update own rows
WITH CHECK (auth.uid() = user_id);   -- Can't change user_id to someone else
```

---

## Critical: API Keys

### 6. [ ] `service_role` key is NEVER in frontend code

```bash
# Scan your codebase
npx ship-safe scan .

# Or manually grep
grep -r "service_role" ./src
grep -r "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ./src
```

**The `service_role` key bypasses ALL RLS. It should only exist in:**
- Server-side code (API routes, edge functions)
- Environment variables on your server
- Never in client bundles

### 7. [ ] `anon` key is only used where RLS protects data

The `anon` key is designed to be public, but only if RLS is properly configured.

```typescript
// Frontend: Use anon key (safe if RLS is set up)
const supabase = createClient(url, anonKey);

// Server: Use service_role key (for admin operations)
const supabaseAdmin = createClient(url, serviceRoleKey);
```

---

## High: Authentication Settings

### 8. [ ] Email confirmations enabled (if using email auth)

Dashboard > Authentication > Providers > Email
- [ ] Confirm email = ON
- [ ] Secure email change = ON

### 9. [ ] Rate limiting on auth endpoints

Supabase has built-in rate limiting, but verify:
- Dashboard > Authentication > Rate Limits
- Default: 30 requests per hour for signup/signin

### 10. [ ] Leaked password protection enabled

Dashboard > Authentication > Providers > Email
- [ ] Check for leaked passwords = ON

---

## High: Database Security

### 11. [ ] No sensitive tables exposed to PostgREST

By default, all tables in `public` schema are exposed via REST API.

```sql
-- Move sensitive tables to a private schema
ALTER TABLE sensitive_table SET SCHEMA private;

-- Or revoke access from anon/authenticated roles
REVOKE ALL ON sensitive_table FROM anon, authenticated;
```

### 12. [ ] Functions with `SECURITY DEFINER` are reviewed

```sql
-- List all SECURITY DEFINER functions
SELECT proname, prosecdef
FROM pg_proc
WHERE prosecdef = true;
```

`SECURITY DEFINER` functions run with the privileges of the creator, not the caller. Review each one for:
- SQL injection vulnerabilities
- Proper input validation
- Necessary privilege escalation

### 13. [ ] HTTP extension not exposed to anon users

```sql
-- Check if http extension functions are callable by anon
SELECT routine_name
FROM information_schema.routine_privileges
WHERE grantee = 'anon'
AND routine_schema = 'extensions';
```

If `http_get`, `http_post` appear, attackers can make SSRF requests.

---

## Medium: Storage Security

### 14. [ ] Storage buckets have proper policies

Dashboard > Storage > Policies

Each bucket should have:
- SELECT policy (who can download)
- INSERT policy (who can upload)
- UPDATE policy (who can replace)
- DELETE policy (who can remove)

### 15. [ ] File type validation on uploads

```typescript
const { error } = await supabase.storage
  .from('avatars')
  .upload(path, file, {
    contentType: 'image/png',  // Explicit content type
    upsert: false              // Prevent overwrites
  });
```

### 16. [ ] File size limits configured

Dashboard > Storage > Settings
- Set max file size per bucket
- Consider implementing client-side validation too

---

## Medium: Realtime Security

### 17. [ ] Realtime only enabled on necessary tables

Dashboard > Database > Replication

Only enable realtime for tables that need it. Each enabled table:
- Increases server load
- Broadcasts changes to subscribed clients
- Must have RLS to protect data

### 18. [ ] Broadcast/Presence channels authenticated

```typescript
// Require authentication for realtime channels
const channel = supabase.channel('room', {
  config: {
    broadcast: { self: true },
    presence: { key: user.id }
  }
});
```

---

## Bonus: Monitoring & Alerts

### 19. [ ] Database logs enabled

Dashboard > Database > Logs
- Enable query logging for debugging
- Set up alerts for failed auth attempts

### 20. [ ] Supabase email alerts configured

Dashboard > Settings > Alerts
- Database approaching limits
- High error rates
- Unusual activity

---

## Quick Commands

```sql
-- Enable RLS on all public tables at once (CAREFUL!)
DO $$
DECLARE
  t text;
BEGIN
  FOR t IN
    SELECT tablename FROM pg_tables WHERE schemaname = 'public'
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
END
$$;

-- List all policies
SELECT * FROM pg_policies;

-- Check RLS status for all tables
SELECT
  schemaname,
  tablename,
  rowsecurity
FROM pg_tables
JOIN pg_class ON tablename = relname
WHERE schemaname = 'public';
```

---

**Remember: Supabase makes it easy to build fast, but security is still your responsibility.**

Run `npx ship-safe scan .` to check for leaked keys before every deploy.
