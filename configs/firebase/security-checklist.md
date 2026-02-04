# Firebase Security Checklist

**Complete this checklist before launching your Firebase-powered app.**

Based on common Firebase security vulnerabilities found in bug bounty programs and penetration tests.

---

## Critical: Security Rules

### 1. [ ] NOT using test mode rules

**Check your Firestore rules don't contain:**
```javascript
// DANGEROUS: Test mode - allows anyone to read/write
allow read, write: if true;

// DANGEROUS: Time-based test mode (often forgotten)
allow read, write: if request.time < timestamp.date(2024, 12, 31);
```

**Fix:** Replace with proper authentication-based rules.

### 2. [ ] Firestore rules require authentication

```javascript
// GOOD: Requires authentication
allow read, write: if request.auth != null;

// BETTER: Requires authentication AND ownership
allow read, write: if request.auth.uid == userId;
```

### 3. [ ] Storage rules have file type validation

```javascript
// GOOD: Only allow specific image types
allow write: if request.resource.contentType.matches('image/.*')
  && request.resource.contentType in ['image/jpeg', 'image/png', 'image/webp'];
```

### 4. [ ] Storage rules have file size limits

```javascript
// GOOD: Limit to 5MB
allow write: if request.resource.size < 5 * 1024 * 1024;
```

### 5. [ ] Default deny rule at the end

```javascript
// Catch-all: deny everything not explicitly allowed
match /{document=**} {
  allow read, write: if false;
}
```

---

## Critical: API Keys

### 6. [ ] API key restrictions configured

Firebase Console > Project Settings > API Keys (in Google Cloud Console)

- [ ] Application restrictions (HTTP referrers for web, app signatures for mobile)
- [ ] API restrictions (only enable APIs you use)

### 7. [ ] Firebase config not containing sensitive data

Your `firebaseConfig` is designed to be public, but verify:

```javascript
// These are OK to be public:
const firebaseConfig = {
  apiKey: "...",           // OK - restricted by security rules
  authDomain: "...",       // OK - public
  projectId: "...",        // OK - public
  storageBucket: "...",    // OK - protected by storage rules
  messagingSenderId: "...", // OK - public
  appId: "..."             // OK - public
};

// NEVER include these in client code:
// - Service account private keys
// - Admin SDK credentials
// - Database URLs with embedded secrets
```

### 8. [ ] Service account keys not in client code

```bash
# Scan for service account files
npx ship-safe scan .

# Or manually search
find . -name "*.json" -exec grep -l "private_key" {} \;
grep -r "-----BEGIN PRIVATE KEY-----" .
```

---

## High: Authentication

### 9. [ ] Email enumeration protection enabled

Firebase Console > Authentication > Settings > User Actions
- [ ] Email enumeration protection = ON

This prevents attackers from discovering valid email addresses.

### 10. [ ] Password requirements configured

Firebase Console > Authentication > Sign-in method > Email/Password
- [ ] Minimum password length (recommend 8+)
- [ ] Require uppercase/lowercase/numbers (if supported)

### 11. [ ] OAuth providers properly configured

For each OAuth provider (Google, Facebook, etc.):
- [ ] Authorized domains list is correct
- [ ] Callback URLs are HTTPS only
- [ ] Client secrets are not exposed

### 12. [ ] Phone auth abuse protection

If using phone authentication:
- [ ] SMS region policy configured (limit to countries you serve)
- [ ] App verification enabled
- [ ] Rate limiting understood

---

## High: Database Security

### 13. [ ] No sensitive data in public collections

Review your data structure:
- [ ] User emails not in publicly readable collections
- [ ] Payment info not in Firestore (use Stripe)
- [ ] Passwords never stored (use Firebase Auth)

### 14. [ ] Indexes don't expose data patterns

Firebase Console > Firestore > Indexes

Complex indexes can reveal data structure. Review each index.

### 15. [ ] Backup and recovery plan exists

Firebase Console > Firestore > Backups
- [ ] Automated backups enabled
- [ ] Tested restore process

---

## Medium: Monitoring & Alerts

### 16. [ ] Firebase App Check enabled

Firebase Console > App Check
- [ ] reCAPTCHA for web
- [ ] Device Check for iOS
- [ ] Play Integrity for Android

App Check helps prevent abuse from unauthorized clients.

### 17. [ ] Budget alerts configured

Google Cloud Console > Billing > Budgets & alerts
- [ ] Budget set for expected usage
- [ ] Alerts at 50%, 90%, 100%

Prevents surprise bills from attacks or bugs.

### 18. [ ] Security rules monitoring

Firebase Console > Firestore > Rules > Monitor
- [ ] Review denied requests regularly
- [ ] Set up alerts for unusual patterns

---

## Quick Security Audit Commands

### Check for exposed Firebase configs

```bash
# Search for Firebase config in your codebase
grep -r "firebaseConfig" --include="*.js" --include="*.ts" .
grep -r "apiKey.*firebase" --include="*.js" --include="*.ts" .
```

### Test your security rules

```bash
# Install Firebase Emulator
npm install -g firebase-tools

# Run security rules tests
firebase emulators:start --only firestore
# Then run your test suite against localhost
```

### Scan for secrets

```bash
npx ship-safe scan .
```

---

## Testing Checklist

Before launch, test these scenarios:

1. [ ] Unauthenticated user cannot read private data
2. [ ] User A cannot read User B's private data
3. [ ] User cannot write to another user's document
4. [ ] File uploads are rejected if wrong type
5. [ ] Large file uploads are rejected
6. [ ] Rate limiting works (if implemented)

---

## Firebase Security Resources

- [Firebase Security Rules Documentation](https://firebase.google.com/docs/rules)
- [Firebase Security Checklist](https://firebase.google.com/support/guides/security-checklist)
- [Firebase App Check](https://firebase.google.com/docs/app-check)

---

**Remember: Firebase makes it easy to build fast, but "test mode" is not a security strategy.**

Run `npx ship-safe scan .` to check for leaked keys before every deploy.
