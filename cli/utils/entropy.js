/**
 * Shannon Entropy Scoring
 * =======================
 *
 * Used to reduce false positives in secret detection.
 *
 * CONCEPT:
 * Real secrets (API keys, tokens) are randomly generated and have HIGH entropy.
 * Placeholder values like "your-api-key-here" or "example123" have LOW entropy
 * because they follow predictable patterns or use common words.
 *
 * Shannon entropy measures the "randomness" of a string on a scale of 0-8.
 * - 0:   Completely uniform  ("aaaaaaaaaaaaaaaa")
 * - 2-3: Low entropy         ("your-api-key-here", "example_value")
 * - 3.5+: High entropy       ("xK9mP2nQ8vL4jR7s") - likely a real secret
 * - 5+:   Very high entropy  (random bytes, base64)
 *
 * We only apply entropy checks to "generic" patterns that lack specific prefixes.
 * Patterns with known prefixes (sk-ant-, ghp_, AKIA...) are already precise enough.
 */

// =============================================================================
// ENTROPY CALCULATION
// =============================================================================

/**
 * Calculate Shannon entropy of a string.
 * Returns a number between 0 and log2(charset size).
 */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  return Object.values(freq).reduce((sum, count) => {
    const p = count / str.length;
    return sum - p * Math.log2(p);
  }, 0);
}

// Minimum entropy to consider a match a real secret
// Real secrets: >3.5 | Placeholders: <3.0 | Safe buffer: 3.5
export const ENTROPY_THRESHOLD = 3.5;

// Strings shorter than this are unreliable for entropy analysis
const MIN_ENTROPY_LENGTH = 16;

// =============================================================================
// VALUE EXTRACTION
// =============================================================================

/**
 * Extract the actual secret value from a matched string.
 *
 * Patterns often match the full assignment, e.g.:
 *   apiKey = "abc123xyz..."
 *
 * We want to score just the value part, not the variable name,
 * because variable names are low-entropy and would skew the score.
 */
function extractSecretValue(matched) {
  // Match: = "value" or : "value" or = value
  const assignmentMatch = matched.match(/[:=]\s*["']?([a-zA-Z0-9_\-+/=.]{12,})["']?\s*$/);
  if (assignmentMatch) return assignmentMatch[1];

  // Match: Bearer <token>
  const bearerMatch = matched.match(/Bearer\s+([a-zA-Z0-9_\-+/=.]{12,})/i);
  if (bearerMatch) return bearerMatch[1];

  // Match: quoted value anywhere
  const quotedMatch = matched.match(/["']([a-zA-Z0-9_\-+/=.]{12,})["']/);
  if (quotedMatch) return quotedMatch[1];

  return matched;
}

// =============================================================================
// PUBLIC API
// =============================================================================

/**
 * Determine if a regex match looks like a real secret based on entropy.
 *
 * Returns true  → keep the finding (high entropy or can't determine)
 * Returns false → filter it out (low entropy, likely a placeholder)
 */
export function isHighEntropyMatch(matched) {
  const value = extractSecretValue(matched);

  // If we can't extract a meaningful value, keep the finding
  if (!value || value.length < MIN_ENTROPY_LENGTH) return true;

  // Common placeholder patterns - fast path rejection
  const PLACEHOLDER_PATTERNS = [
    /^(your[-_]?|my[-_]?|example[-_]?|test[-_]?|dummy[-_]?|fake[-_]?|sample[-_]?)/i,
    /^(xxx+|yyy+|zzz+|aaa+|000+)/i,
    /^(insert|replace|changeme|placeholder|todo|fixme)/i,
    /([-_]here|[-_]goes|[-_]key|[-_]token|[-_]secret)$/i,
    /^[a-z]+[-_][a-z]+[-_][a-z]+$/, // looks like-a-passphrase not a key
  ];

  if (PLACEHOLDER_PATTERNS.some(p => p.test(value))) return false;

  const entropy = shannonEntropy(value);
  return entropy >= ENTROPY_THRESHOLD;
}

/**
 * Get a human-readable confidence label for a finding.
 */
export function getConfidence(pattern, matched) {
  // Strict prefix patterns (e.g. sk-ant-, ghp_, AKIA) are always high confidence
  if (!pattern.requiresEntropyCheck) return 'high';

  const value = extractSecretValue(matched);
  if (!value || value.length < MIN_ENTROPY_LENGTH) return 'medium';

  const entropy = shannonEntropy(value);

  if (entropy >= 4.5) return 'high';
  if (entropy >= ENTROPY_THRESHOLD) return 'medium';
  return 'low'; // Should have been filtered, but just in case
}
