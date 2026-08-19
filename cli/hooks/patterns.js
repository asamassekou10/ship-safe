/**
 * Shared hook patterns
 * ====================
 *
 * Single source of truth for all patterns used by pre-tool-use.js
 * and post-tool-use.js. Keeps both hooks in sync automatically.
 *
 * Design rules:
 *  - CRITICAL_PATTERNS: block on pre-tool-use. Must have SPECIFIC PREFIXES
 *    to keep false-positive rate near zero. No generic patterns here.
 *  - HIGH_PATTERNS: advisory only (post-tool-use). Broader, needs entropy gate.
 *  - DANGEROUS_BASH_PATTERNS: block on Bash tool calls.
 *  - ENV_FILE_RE: recognise .env files that SHOULD contain secrets.
 *  - SKIP_PATHS: files where reporting is never useful.
 */

import path from 'path';
import { createJwtClaimMatcher } from '../utils/jwt.js';

// =============================================================================
// SHANNON ENTROPY — used to filter generic token false positives
// =============================================================================

export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((sum, count) => {
    const p = count / str.length;
    return sum - p * Math.log2(p);
  }, 0);
}

// =============================================================================
// CRITICAL PATTERNS — block on write (precision over recall)
//
// Each entry:
//   name    — human-readable label shown in block message
//   re      — regex (stateless; reset lastIndex between uses)
//   envVar  — suggested environment variable name for the fix message
//
// Removed / demoted compared to earlier version:
//   Supabase JWT  → was ANY HS256 JWT; now requires service_role in payload
//   Twilio Auth Token (SK…) → no prefix, too many false positives; removed
//   Twilio Account SID → tightened to hex-only [a-f0-9]
//   Cloudflare API Token → broken lookahead, no reliable prefix; removed
// =============================================================================

export const CRITICAL_PATTERNS = [
  {
    name:   'AWS Access Key ID',
    re:     /AKIA[0-9A-Z]{16}/,
    envVar: 'AWS_ACCESS_KEY_ID',
  },
  {
    name:   'AWS Secret Access Key',
    re:     /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/,
    envVar: 'AWS_SECRET_ACCESS_KEY',
  },
  {
    name:   'GitHub PAT (classic)',
    re:     /ghp_[a-zA-Z0-9]{36}/,
    envVar: 'GITHUB_TOKEN',
  },
  {
    name:   'GitHub OAuth Token',
    re:     /gho_[a-zA-Z0-9]{36}/,
    envVar: 'GITHUB_TOKEN',
  },
  {
    name:   'GitHub App Token',
    re:     /(?:ghu_|ghs_)[a-zA-Z0-9]{36}/,
    envVar: 'GITHUB_TOKEN',
  },
  {
    name:   'GitHub Fine-Grained PAT',
    re:     /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
    envVar: 'GITHUB_TOKEN',
  },
  {
    name:   'Anthropic API Key',
    re:     /sk-ant-api03-[a-zA-Z0-9\-_]{93}/,
    envVar: 'ANTHROPIC_API_KEY',
  },
  {
    name:   'OpenAI API Key',
    re:     /sk-(?:proj-|None-)?[a-zA-Z0-9]{48}/,
    envVar: 'OPENAI_API_KEY',
  },
  {
    name:   'Stripe Live Secret Key',
    re:     /sk_live_[0-9a-zA-Z]{24,}/,
    envVar: 'STRIPE_SECRET_KEY',
  },
  {
    name:   'Stripe Restricted Key',
    re:     /rk_live_[0-9a-zA-Z]{24,}/,
    envVar: 'STRIPE_RESTRICTED_KEY',
  },
  {
    name:   'Slack Bot Token',
    re:     /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/,
    envVar: 'SLACK_BOT_TOKEN',
  },
  {
    name:   'Slack User Token',
    re:     /xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{32}/,
    envVar: 'SLACK_USER_TOKEN',
  },
  {
    name:   'Twilio Account SID',
    // Tightened: must be lowercase hex, not any alphanumeric
    re:     /AC[a-f0-9]{32}/,
    envVar: 'TWILIO_ACCOUNT_SID',
  },
  {
    name:   'Google API Key',
    re:     /AIza[0-9A-Za-z\-_]{35}/,
    envVar: 'GOOGLE_API_KEY',
  },
  {
    name:   'npm Auth Token',
    re:     /npm_[A-Za-z0-9]{36}/,
    envVar: 'NPM_TOKEN',
  },
  {
    name:   'PyPI API Token',
    re:     /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}/,
    envVar: 'PYPI_API_TOKEN',
  },
  {
    name:   'Supabase Service Role Key',
    // Decode the payload and require the exact service_role claim so valid
    // keys are not missed when JSON claim order changes.
    re:     createJwtClaimMatcher('role', 'service_role'),
    envVar: 'SUPABASE_SERVICE_ROLE_KEY',
  },
  {
    name:   'Private Key (PEM)',
    re:     /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    envVar: 'PRIVATE_KEY_PATH',
  },
];

// =============================================================================
// HIGH PATTERNS — advisory post-write scan only
// Broader patterns; generic ones gated by entropy check.
// =============================================================================

export const HIGH_PATTERNS = [
  {
    name:     'Hardcoded password assignment',
    severity: 'high',
    re:       /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/i,
    checkEntropy: true,  // run entropy on the captured value
  },
  {
    name:     'Database URL with credentials',
    severity: 'high',
    re:       /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]{4,}@/,
    checkEntropy: false,
  },
  {
    name:     'Generic high-entropy secret assignment',
    severity: 'high',
    re:       /(?:token|secret|api_key|apikey)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{32,})["']/i,
    checkEntropy: true,  // only report if entropy > threshold
  },
];

const ENTROPY_THRESHOLD = 3.5;

// =============================================================================
// DANGEROUS BASH PATTERNS — block on Bash tool calls
// =============================================================================

export const DANGEROUS_BASH_PATTERNS = [
  {
    name:   'Remote script execution (curl/wget piped to shell)',
    re:     /(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)/,
    reason: 'Executing remote scripts without verification is the #1 CI/CD supply chain attack vector (Trivy/CanisterWorm 2026). Download first, verify checksum, then execute.',
  },
  {
    name:   'Remote script execution (PowerShell iex/Invoke-Expression)',
    re:     /(?:iex|Invoke-Expression)\s*\(?.*(?:Invoke-WebRequest|iwr|curl|wget)/i,
    reason: 'PowerShell equivalent of curl|bash. Download the script first, inspect it, then execute.',
  },
  {
    name:   'Recursive force delete of system paths',
    re:     /rm\s+(?:-[a-z]*f[a-z]*\s+|--force\s+)?(?:-[a-z]*r[a-z]*\s+|--recursive\s+)?\/(?:\s|$|(?!tmp|var\/tmp|home)[a-z])/,
    reason: 'Destructive operation targeting system paths. Double-check the path before proceeding.',
  },
  {
    name:   'Elevated npm install permissions',
    re:     /npm\s+(?:i|install)\s+[^\n]*--unsafe-perm/,
    reason: '--unsafe-perm elevates install script privileges. Use sandboxed installs instead.',
  },
  {
    name:   'Credential file read (potential exfiltration)',
    re:     /(?:cat|type|Get-Content)\s+[^\n]*(?:~\/\.(?:aws|ssh|npmrc|pypirc|netrc|gitconfig|gnupg)|\/etc\/(?:passwd|shadow))/,
    reason: 'Reading sensitive credential files.',
  },
  {
    name:   'Env-var exfiltration via network call',
    re:     /(?:curl|wget|Invoke-WebRequest)\s+[^\n]*\$(?:AWS_|GITHUB_TOKEN|NPM_TOKEN|ANTHROPIC_|OPENAI_|GROQ_|SECRET|PASSWORD|TOKEN)/,
    reason: 'Sending an environment variable that likely contains credentials over the network.',
  },
  {
    name:   'Secret committed in git message',
    re:     /git\s+commit\s+[^\n]*-m\s+["'][^\n]*(?:sk-|ghp_|npm_|AKIA|xoxb-|sk_live_)[^\n]*/,
    reason: 'Possible secret hardcoded in a git commit message. Secrets in commit history are permanent.',
  },
];

// =============================================================================
// ENV FILE PATTERNS
// =============================================================================

/** Files that SHOULD contain secrets — write is allowed but gitignore is checked */
export const ENV_FILE_RE = /(?:^|[/\\])\.env(?:\.[a-zA-Z0-9]+)?$/;

/** Files that are purely documentation/examples — silently skip all checks */
export const ENV_EXAMPLE_RE = /(?:^|[/\\])\.env\.(?:example|sample|template|test)$/i;

// =============================================================================
// SKIP PATHS (post-tool-use advisory scan — never report on these)
// =============================================================================

export const SKIP_PATHS = [
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /__tests__[/\\]/,
  /[/\\]tests?[/\\]/,
  /[/\\]fixtures?[/\\]/,
  /[/\\]mocks?[/\\]/,
  ENV_EXAMPLE_RE,
  /\.sample$/,
  /CHANGELOG/i,
];

// Note: .md files are NOT skipped — secrets in docs are real issues.

// =============================================================================
// SCAN HELPERS
// =============================================================================

/**
 * Scan content for critical secrets.
 * Returns array of { name, line, envVar } — line is 1-based.
 */
export function scanCritical(content) {
  const lines = content.split('\n');
  const hits = [];
  for (const { name, re, envVar } of CRITICAL_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      // Reset regex state (stateless patterns, but be safe)
      re.lastIndex = 0;
      if (re.test(lines[i])) {
        hits.push({ name, line: i + 1, envVar });
        break; // one hit per pattern type is enough for the block message
      }
    }
  }
  return hits;
}

/**
 * Scan content for high-severity issues (advisory).
 * Applies entropy gate for patterns that request it.
 */
export function scanHigh(content) {
  const hits = [];
  for (const { name, severity, re, checkEntropy } of HIGH_PATTERNS) {
    re.lastIndex = 0;
    const m = re.exec(content);
    if (!m) continue;
    if (checkEntropy) {
      // Use captured group if present, otherwise the full match
      const value = m[1] || m[0];
      if (shannonEntropy(value) < ENTROPY_THRESHOLD) continue;
    }
    hits.push({ name, severity });
  }
  return hits;
}

/**
 * Build a specific fix suggestion for a detected secret.
 *
 * @param {string} envVar    — e.g. 'STRIPE_SECRET_KEY'
 * @param {string} filePath  — e.g. 'src/config.ts'
 */
export function buildFixSuggestion(envVar, filePath) {
  const ext = filePath ? path.extname(filePath).toLowerCase() : '';
  if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'].includes(ext)) {
    return `process.env.${envVar}`;
  }
  if (ext === '.py') {
    return `os.environ.get('${envVar}')`;
  }
  if (['.rb'].includes(ext)) {
    return `ENV['${envVar}']`;
  }
  if (['.go'].includes(ext)) {
    return `os.Getenv("${envVar}")`;
  }
  if (['.java', '.kt'].includes(ext)) {
    return `System.getenv("${envVar}")`;
  }
  if (['.cs'].includes(ext)) {
    return `Environment.GetEnvironmentVariable("${envVar}")`;
  }
  return `$ENV:${envVar}`;
}
