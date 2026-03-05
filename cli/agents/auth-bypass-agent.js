/**
 * AuthBypassAgent
 * ================
 *
 * Detects authentication and authorization vulnerabilities:
 * JWT misconfig, missing auth middleware, CSRF, session flaws,
 * OAuth misconfig, cookie security, broken access control.
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

const PATTERNS = [
  // ── JWT Issues ─────────────────────────────────────────────────────────────
  {
    rule: 'JWT_ALG_NONE',
    title: 'JWT Algorithm None Attack',
    regex: /algorithms?\s*:\s*\[?\s*['"]none['"]/gi,
    severity: 'critical',
    cwe: 'CWE-327',
    owasp: 'A02:2021',
    description: 'Accepting alg: "none" in JWT allows forging tokens without a signature.',
    fix: 'Explicitly set algorithms: ["RS256"] or ["ES256"]. Never accept "none".',
  },
  {
    rule: 'JWT_WEAK_SECRET',
    title: 'JWT Weak HMAC Secret',
    regex: /jwt\.sign\s*\([^)]*,\s*['"][^'"]{1,15}['"]/g,
    severity: 'high',
    cwe: 'CWE-326',
    owasp: 'A02:2021',
    description: 'Short JWT secret (<16 chars) is vulnerable to brute-force. Use a strong random secret.',
    fix: 'Use a 256-bit (32+ char) random secret: require("crypto").randomBytes(32).toString("hex")',
  },
  {
    rule: 'JWT_NO_EXPIRY',
    title: 'JWT Without Expiration',
    regex: /jwt\.sign\s*\([^)]*(?!expiresIn|exp)[^)]*\)/g,
    severity: 'medium',
    cwe: 'CWE-613',
    owasp: 'A07:2021',
    confidence: 'medium',
    description: 'JWTs without expiration never expire. Set a short expiresIn (15m-1h).',
    fix: 'Add { expiresIn: "15m" } to jwt.sign() options',
  },
  {
    rule: 'JWT_VERIFY_DISABLED',
    title: 'JWT Verification Disabled',
    regex: /jwt\.decode\s*\(/g,
    severity: 'high',
    cwe: 'CWE-345',
    owasp: 'A07:2021',
    confidence: 'medium',
    description: 'jwt.decode() does not verify the signature. Use jwt.verify() for authentication.',
    fix: 'Use jwt.verify(token, secret) instead of jwt.decode(token)',
  },

  // ── Cookie Security ────────────────────────────────────────────────────────
  {
    rule: 'COOKIE_NO_HTTPONLY',
    title: 'Cookie Missing httpOnly Flag',
    regex: /(?:cookie|Cookie|setCookie|set-cookie)[^;]{0,100}(?:secure|domain|path|maxAge|max-age)(?![^;]*httpOnly)/gi,
    severity: 'medium',
    cwe: 'CWE-1004',
    owasp: 'A05:2021',
    confidence: 'medium',
    description: 'Cookies without httpOnly can be stolen via XSS. Set httpOnly: true.',
    fix: 'Add httpOnly: true to cookie options',
  },
  {
    rule: 'COOKIE_NO_SECURE',
    title: 'Cookie Missing secure Flag',
    regex: /(?:res\.cookie|setCookie)\s*\([^)]*(?:httpOnly|domain)[^)]*(?!secure)/gi,
    severity: 'medium',
    cwe: 'CWE-614',
    owasp: 'A05:2021',
    confidence: 'medium',
    description: 'Cookies without secure flag are sent over HTTP. Set secure: true in production.',
    fix: 'Add secure: true to cookie options (ensures HTTPS-only transmission)',
  },
  {
    rule: 'COOKIE_SAMESITE_NONE',
    title: 'Cookie SameSite=None Without Secure',
    regex: /sameSite\s*:\s*['"]?none['"]?/gi,
    severity: 'high',
    cwe: 'CWE-1275',
    owasp: 'A05:2021',
    description: 'SameSite=None without Secure exposes cookies to CSRF. Set Secure with SameSite=None.',
    fix: 'Use sameSite: "strict" or "lax". If None is required, also set secure: true.',
  },

  // ── Session Security ───────────────────────────────────────────────────────
  {
    rule: 'SESSION_INSECURE_SECRET',
    title: 'Hardcoded Session Secret',
    regex: /session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]{1,20}['"]/g,
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    description: 'Hardcoded short session secret is guessable. Use a strong random value from env.',
    fix: 'Use process.env.SESSION_SECRET with a 256-bit random value',
  },
  {
    rule: 'SESSION_NO_REGENERATE',
    title: 'Session Not Regenerated After Login',
    regex: /(?:login|authenticate|signIn)\s*(?:=|:)\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)/g,
    severity: 'medium',
    cwe: 'CWE-384',
    owasp: 'A07:2021',
    confidence: 'low',
    description: 'Sessions should be regenerated after login to prevent session fixation.',
    fix: 'Call req.session.regenerate() after successful authentication',
  },

  // ── CSRF ───────────────────────────────────────────────────────────────────
  {
    rule: 'CSRF_DISABLED',
    title: 'CSRF Protection Disabled',
    regex: /csrf\s*(?::\s*false|=\s*false|\.disable\(\))/gi,
    severity: 'high',
    cwe: 'CWE-352',
    owasp: 'A01:2021',
    description: 'CSRF protection is explicitly disabled. State-changing requests need CSRF tokens.',
    fix: 'Enable CSRF protection or use SameSite=Strict cookies',
  },

  // ── OAuth / OIDC ───────────────────────────────────────────────────────────
  {
    rule: 'OAUTH_NO_STATE',
    title: 'OAuth Missing State Parameter',
    regex: /authorize_url|authorization_endpoint|auth_uri.*(?!state)/g,
    severity: 'high',
    cwe: 'CWE-352',
    owasp: 'A07:2021',
    confidence: 'low',
    description: 'OAuth without state parameter is vulnerable to CSRF. Include a random state value.',
    fix: 'Generate a random state parameter and verify it in the callback',
  },
  {
    rule: 'OAUTH_WILDCARD_REDIRECT',
    title: 'OAuth Permissive Redirect URI',
    regex: /redirect_uri\s*[:=]\s*['"]?\*/g,
    severity: 'critical',
    cwe: 'CWE-601',
    owasp: 'A07:2021',
    description: 'Wildcard redirect URI allows OAuth token theft via open redirect.',
    fix: 'Use exact redirect URIs. Never use wildcards in OAuth redirect configuration.',
  },

  // ── Password Security ──────────────────────────────────────────────────────
  {
    rule: 'WEAK_PASSWORD_HASH',
    title: 'Weak Password Hashing (MD5/SHA)',
    regex: /(?:createHash|hashlib\.)\s*\(\s*['"](?:md5|sha1|sha256)['"]\s*\).*(?:password|passwd)/gi,
    severity: 'critical',
    cwe: 'CWE-916',
    owasp: 'A02:2021',
    description: 'MD5/SHA are not suitable for password hashing. Use bcrypt, scrypt, or argon2.',
    fix: 'Use bcrypt.hash(password, 12) or argon2.hash(password)',
  },
  {
    rule: 'PLAINTEXT_PASSWORD_COMPARISON',
    title: 'Plaintext Password Comparison',
    regex: /(?:password|passwd)\s*(?:===?|==)\s*(?:req\.|request\.|body\.|query\.)/g,
    severity: 'critical',
    cwe: 'CWE-256',
    owasp: 'A02:2021',
    description: 'Comparing passwords in plaintext means they are stored unhashed. Hash passwords.',
    fix: 'Use bcrypt.compare(inputPassword, hashedPassword)',
  },

  // ── Missing Auth Checks ────────────────────────────────────────────────────
  {
    rule: 'BOLA_DIRECT_ID',
    title: 'Broken Object-Level Authorization (BOLA)',
    regex: /(?:findById|findOne|findUnique|findByPk)\s*\(\s*(?:req\.params|req\.query|ctx\.params)/g,
    severity: 'high',
    cwe: 'CWE-639',
    owasp: 'A01:2021',
    description: 'Fetching by user-supplied ID without ownership check enables BOLA/IDOR.',
    fix: 'Add ownership check: .findFirst({ where: { id: params.id, userId: session.user.id } })',
  },
  {
    rule: 'MASS_ASSIGNMENT',
    title: 'Mass Assignment Vulnerability',
    regex: /(?:\.create|\.update|\.insert)\s*\(\s*(?:req\.body|request\.body|ctx\.request\.body)/g,
    severity: 'high',
    cwe: 'CWE-915',
    owasp: 'A01:2021',
    description: 'Passing full request body to create/update enables mass assignment attacks.',
    fix: 'Destructure only allowed fields: const { name, email } = req.body; Model.create({ name, email })',
  },

  // ── Timing Attacks ─────────────────────────────────────────────────────────
  {
    rule: 'TIMING_ATTACK_COMPARISON',
    title: 'Timing Attack: String Comparison',
    regex: /(?:apiKey|api_key|token|secret|signature|hmac)\s*(?:===?|!==?)\s*/gi,
    severity: 'medium',
    cwe: 'CWE-208',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Direct string comparison of secrets is vulnerable to timing attacks.',
    fix: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))',
  },

  // ── Rate Limiting ──────────────────────────────────────────────────────────
  {
    rule: 'NO_RATE_LIMIT_LOGIN',
    title: 'No Rate Limiting on Authentication',
    regex: /(?:\/login|\/signin|\/auth|\/register|\/signup|\/reset-password)\s*['"]/g,
    severity: 'medium',
    cwe: 'CWE-307',
    owasp: 'A07:2021',
    confidence: 'low',
    description: 'Auth endpoints without rate limiting are vulnerable to brute-force attacks.',
    fix: 'Add rate limiting: express-rate-limit, @upstash/ratelimit, or Cloudflare rules',
  },

  // ── Weak Crypto ────────────────────────────────────────────────────────────
  {
    rule: 'WEAK_CRYPTO_MD5',
    title: 'Weak Cryptography: MD5',
    regex: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    severity: 'medium',
    cwe: 'CWE-328',
    owasp: 'A02:2021',
    description: 'MD5 is cryptographically broken. Use SHA-256 or SHA-3 for integrity checks.',
    fix: 'Use createHash("sha256") instead of createHash("md5")',
  },
  {
    rule: 'WEAK_CRYPTO_SHA1',
    title: 'Weak Cryptography: SHA-1',
    regex: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    severity: 'medium',
    cwe: 'CWE-328',
    owasp: 'A02:2021',
    description: 'SHA-1 is collision-prone. Use SHA-256 or SHA-3.',
    fix: 'Use createHash("sha256") instead of createHash("sha1")',
  },
  {
    rule: 'WEAK_CRYPTO_ECB',
    title: 'Weak Cryptography: ECB Mode',
    regex: /(?:AES|DES).*ECB|createCipheriv\s*\(\s*['"](?:aes-\d+-ecb|des-ecb)['"]/gi,
    severity: 'high',
    cwe: 'CWE-327',
    owasp: 'A02:2021',
    description: 'ECB mode leaks patterns in ciphertext. Use CBC or GCM mode.',
    fix: 'Use AES-256-GCM: createCipheriv("aes-256-gcm", key, iv)',
  },
  {
    rule: 'HARDCODED_CRYPTO_KEY',
    title: 'Hardcoded Encryption Key',
    regex: /createCipher(?:iv)?\s*\([^,]+,\s*['"][^'"]+['"]/g,
    severity: 'high',
    cwe: 'CWE-321',
    owasp: 'A02:2021',
    description: 'Hardcoded encryption key in source code. Load from environment variables.',
    fix: 'Use process.env.ENCRYPTION_KEY instead of hardcoded string',
  },
  {
    rule: 'WEAK_RANDOM',
    title: 'Insecure Random Number Generator',
    regex: /Math\.random\s*\(\s*\).*(?:token|secret|key|password|salt|nonce|csrf|session)/gi,
    severity: 'high',
    cwe: 'CWE-338',
    owasp: 'A02:2021',
    description: 'Math.random() is not cryptographically secure. Use crypto.randomBytes().',
    fix: 'Use crypto.randomBytes(32).toString("hex") or crypto.randomUUID()',
  },

  // ── Django/Flask Security ────────────────────────────────────────────────
  {
    rule: 'DJANGO_DEBUG_TRUE',
    title: 'Django: DEBUG = True',
    regex: /\bDEBUG\s*=\s*True\b/g,
    severity: 'high',
    cwe: 'CWE-215',
    owasp: 'A05:2021',
    description: 'Django DEBUG mode exposes stack traces, SQL queries, and settings to users.',
    fix: 'Set DEBUG = False in production. Use environment variable: DEBUG = os.getenv("DEBUG", "False") == "True"',
  },
  {
    rule: 'FLASK_SECRET_KEY_HARDCODED',
    title: 'Flask: Hardcoded Secret Key',
    regex: /app\.secret_key\s*=\s*['"][^'"]{1,30}['"]/g,
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    description: 'Flask secret key is hardcoded. Session cookies can be forged.',
    fix: 'Use os.environ.get("SECRET_KEY") with a 256-bit random value',
  },

  // ── TLS/SSL ────────────────────────────────────────────────────────────────
  {
    rule: 'TLS_REJECT_UNAUTHORIZED',
    title: 'TLS Certificate Verification Disabled',
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?/g,
    severity: 'critical',
    cwe: 'CWE-295',
    owasp: 'A02:2021',
    description: 'Disabling TLS verification exposes app to MITM attacks.',
    fix: 'Remove NODE_TLS_REJECT_UNAUTHORIZED=0. Use proper CA certificates.',
  },
  {
    rule: 'TLS_REJECT_UNAUTH_FALSE',
    title: 'TLS rejectUnauthorized: false',
    regex: /\brejectUnauthorized\s*:\s*false\b/g,
    severity: 'high',
    cwe: 'CWE-295',
    owasp: 'A02:2021',
    description: 'rejectUnauthorized: false disables TLS certificate checking.',
    fix: 'Remove rejectUnauthorized: false, or use a proper CA bundle',
  },
  {
    rule: 'TLS_VERIFY_FALSE_PYTHON',
    title: 'TLS verify=False (Python)',
    regex: /\brequests\.\w+\s*\([^)]*\bverify\s*=\s*False\b/g,
    severity: 'high',
    cwe: 'CWE-295',
    owasp: 'A02:2021',
    description: 'Python requests with verify=False disables SSL cert verification.',
    fix: 'Remove verify=False, or pass verify="/path/to/ca-bundle.crt"',
  },
];

export class AuthBypassAgent extends BaseAgent {
  constructor() {
    super('AuthBypassAgent', 'Detect authentication and authorization vulnerabilities', 'auth');
  }

  async analyze(context) {
    const { files } = context;
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.php', '.go'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }

    return findings;
  }
}

export default AuthBypassAgent;
