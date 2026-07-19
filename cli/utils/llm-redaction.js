const REDACTED = '[REDACTED]';

const PRIVATE_KEY_RE = /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----/g;
const AUTH_HEADER_RE = /(authorization\s*[:=]\s*["']?(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{12,}/gi;
const BEARER_RE = /(bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi;
const SECRET_ASSIGNMENT_RE = /((?:["']?[A-Z0-9_.-]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|PRIVATE[_-]?KEY|PASSWORD|PASSWD|SECRET|TOKEN)[A-Z0-9_.-]*["']?)\s*[:=]\s*["']?)([^\s"'`,;}]+)/gi;
const KNOWN_TOKEN_RE = /\b(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{12,})\b/g;

/**
 * Best-effort masking for repository text included in provider-bound prompts.
 * This reduces accidental credential disclosure, but callers should still use
 * --no-ai when content must remain entirely local.
 */
export function redactForLLM(value) {
  if (value === null || value === undefined) return '';

  return String(value)
    .replace(PRIVATE_KEY_RE, '[REDACTED PRIVATE KEY]')
    .replace(AUTH_HEADER_RE, `$1${REDACTED}`)
    .replace(BEARER_RE, `$1${REDACTED}`)
    .replace(SECRET_ASSIGNMENT_RE, `$1${REDACTED}`)
    .replace(KNOWN_TOKEN_RE, REDACTED);
}

export default redactForLLM;
