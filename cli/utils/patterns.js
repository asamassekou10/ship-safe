/**
 * Secret Detection Patterns
 * =========================
 *
 * These regex patterns detect common secret formats.
 * Each pattern includes:
 *   - name: Human-readable identifier
 *   - pattern: Regular expression
 *   - severity: 'critical' | 'high' | 'medium'
 *   - description: Why this matters
 *
 * MAINTENANCE NOTES:
 * - Patterns should have low false-positive rates
 * - Test new patterns against real codebases before adding
 * - Order doesn't matter (all patterns are checked)
 */

export const SECRET_PATTERNS = [
  // =========================================================================
  // CRITICAL: These are almost always real secrets
  // =========================================================================
  {
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'AWS Access Keys can access your entire AWS account. Rotate immediately if exposed.'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key)[\s]*[=:][\s]*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    description: 'AWS Secret Keys paired with Access Keys grant full AWS access.'
  },
  {
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub PATs can access repositories, create commits, and manage settings.'
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub OAuth tokens grant authorized application access.'
  },
  {
    name: 'GitHub App Token',
    pattern: /ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub App tokens have installation-level access to repositories.'
  },
  {
    name: 'Stripe Live Secret Key',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critical',
    description: 'Stripe live keys can process real payments and access customer data.'
  },
  {
    name: 'Stripe Live Publishable Key',
    pattern: /pk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'high',
    description: 'Stripe publishable keys are less sensitive but should not be in server code.'
  },
  {
    name: 'Private Key Block',
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    severity: 'critical',
    description: 'Private keys enable impersonation and decryption. Never commit these.'
  },

  // =========================================================================
  // HIGH: Very likely to be secrets
  // =========================================================================
  {
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    severity: 'high',
    description: 'OpenAI keys can rack up API charges and access your usage history.'
  },
  {
    name: 'Anthropic API Key',
    pattern: /sk-ant-[a-zA-Z0-9-]{32,}/g,
    severity: 'high',
    description: 'Anthropic API keys grant access to Claude and your usage quota.'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'high',
    description: 'Slack tokens can read messages, post content, and access workspace data.'
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: 'high',
    description: 'Slack webhooks allow posting messages to channels.'
  },
  {
    name: 'Discord Webhook',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
    severity: 'high',
    description: 'Discord webhooks allow posting messages to channels.'
  },
  {
    name: 'Discord Bot Token',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    severity: 'high',
    description: 'Discord bot tokens grant full control over your bot.'
  },
  {
    name: 'Twilio API Key',
    pattern: /SK[a-f0-9]{32}/g,
    severity: 'high',
    description: 'Twilio keys can send SMS/calls and access account data.'
  },
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'high',
    description: 'SendGrid keys can send emails from your account.'
  },
  {
    name: 'Mailgun API Key',
    pattern: /key-[a-zA-Z0-9]{32}/g,
    severity: 'high',
    description: 'Mailgun keys can send emails and access logs.'
  },
  {
    name: 'Firebase/Google Service Account',
    pattern: /"type":\s*"service_account"/g,
    severity: 'high',
    description: 'Service account JSON files grant broad GCP/Firebase access.'
  },
  {
    name: 'Supabase Service Role Key',
    pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    severity: 'high',
    description: 'Supabase service role keys bypass Row Level Security. Keep server-side only.'
  },
  {
    name: 'Vercel Token',
    pattern: /vercel_[a-zA-Z0-9]{24}/gi,
    severity: 'high',
    description: 'Vercel tokens can deploy and manage your projects.'
  },
  {
    name: 'NPM Token',
    pattern: /npm_[a-zA-Z0-9]{36}/g,
    severity: 'high',
    description: 'NPM tokens can publish packages under your account.'
  },
  {
    name: 'Heroku API Key',
    pattern: /[hH]eroku.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
    severity: 'high',
    description: 'Heroku API keys can manage apps and dynos.'
  },
  {
    name: 'DigitalOcean Token',
    pattern: /dop_v1_[a-f0-9]{64}/g,
    severity: 'high',
    description: 'DigitalOcean tokens can manage droplets and resources.'
  },

  // =========================================================================
  // MEDIUM: Likely secrets, but may have false positives
  // =========================================================================
  {
    name: 'Generic API Key',
    pattern: /["']?(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi,
    severity: 'medium',
    description: 'Hardcoded API keys should be moved to environment variables.'
  },
  {
    name: 'Generic Secret',
    pattern: /["']?(?:secret|secret[_-]?key)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi,
    severity: 'medium',
    description: 'Hardcoded secrets should be moved to environment variables.'
  },
  {
    name: 'Password Assignment',
    pattern: /["']?password["']?\s*[:=]\s*["']([^"']{8,})["']/gi,
    severity: 'medium',
    description: 'Hardcoded passwords are a critical vulnerability.'
  },
  {
    name: 'Database URL with Credentials',
    pattern: /(mongodb|postgres|postgresql|mysql|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: 'medium',
    description: 'Database URLs with embedded passwords expose your database.'
  },
  {
    name: 'Bearer Token',
    pattern: /["']Bearer\s+[a-zA-Z0-9_\-\.=]{20,}["']/gi,
    severity: 'medium',
    description: 'Hardcoded bearer tokens should not be in source code.'
  },
  {
    name: 'JWT Token',
    pattern: /["']?jwt["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)["']?/gi,
    severity: 'medium',
    description: 'JWTs in source code may be test tokens, but verify they\'re not production.'
  },
  {
    name: 'Basic Auth Header',
    pattern: /["']Basic\s+[A-Za-z0-9+/=]{10,}["']/gi,
    severity: 'medium',
    description: 'Basic auth headers contain base64-encoded credentials.'
  }
];

// =============================================================================
// FILES AND DIRECTORIES TO SKIP
// =============================================================================

export const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'venv',
  'env',
  '.venv',
  '__pycache__',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  '.output',
  'coverage',
  '.nyc_output',
  'vendor',
  '.bundle',
  '.cache',
  '.parcel-cache',
  '.turbo',
  'bower_components',
  'jspm_packages',
  '.vercel',
  '.netlify',
  '.serverless'
]);

export const SKIP_EXTENSIONS = new Set([
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
  // Fonts
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  // Media
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm', '.ogg',
  // Archives
  '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
  // Documents
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  // Lock files (usually very large and auto-generated)
  '.lock',
  // Minified files
  '.min.js', '.min.css',
  // Binaries
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
  // Maps
  '.map'
]);

// Maximum file size to scan (1MB)
export const MAX_FILE_SIZE = 1_000_000;
