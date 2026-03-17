/**
 * Secrets Verifier
 * =================
 *
 * Checks if leaked secrets are still active by probing provider APIs.
 * Only makes safe, read-only API calls (e.g., account info endpoints).
 *
 * USAGE:
 *   const verifier = new SecretsVerifier();
 *   const results = await verifier.verify(findings);
 */

// =============================================================================
// PROVIDER PROBES
// =============================================================================

/**
 * Each probe defines how to test if a specific type of key is active.
 * All probes use read-only GET endpoints — no side effects.
 */
const PROBES = {
  // GitHub tokens
  GITHUB_TOKEN: {
    label: 'GitHub',
    test: async (token) => {
      const res = await safeFetch('https://api.github.com/user', {
        headers: { Authorization: `token ${token}`, 'User-Agent': 'ship-safe-verifier' },
      });
      if (res.status === 200) {
        const data = await res.json();
        return { active: true, info: `Authenticated as: ${data.login}` };
      }
      return { active: false };
    },
  },
  GITHUB_PAT: { label: 'GitHub PAT', test: (t) => PROBES.GITHUB_TOKEN.test(t) },

  // OpenAI
  OPENAI_API_KEY: {
    label: 'OpenAI',
    test: async (token) => {
      const res = await safeFetch('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { active: res.status === 200 };
    },
  },

  // Anthropic
  ANTHROPIC_API_KEY: {
    label: 'Anthropic',
    test: async (token) => {
      const res = await safeFetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': token,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        // Send minimal invalid request — 400 means key is valid, 401 means invalid
        body: JSON.stringify({ model: 'x', max_tokens: 1, messages: [] }),
      });
      // 400 = valid key, bad request; 401 = invalid key
      return { active: res.status !== 401 && res.status !== 403 };
    },
  },

  // Stripe
  STRIPE_LIVE_KEY: {
    label: 'Stripe',
    test: async (token) => {
      const res = await safeFetch('https://api.stripe.com/v1/balance', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { active: res.status === 200 };
    },
  },
  STRIPE_SECRET_KEY: { label: 'Stripe', test: (t) => PROBES.STRIPE_LIVE_KEY.test(t) },

  // AWS
  AWS_ACCESS_KEY: {
    label: 'AWS',
    test: async (token) => {
      // AWS keys need both access key and secret — we can only flag that the format is valid
      return { active: null, info: 'Cannot verify AWS keys without secret key pair' };
    },
  },

  // Slack
  SLACK_TOKEN: {
    label: 'Slack',
    test: async (token) => {
      const res = await safeFetch(`https://slack.com/api/auth.test?token=${encodeURIComponent(token)}`);
      if (res.status === 200) {
        const data = await res.json();
        return { active: data.ok === true, info: data.ok ? `Team: ${data.team}` : undefined };
      }
      return { active: false };
    },
  },
  SLACK_WEBHOOK: {
    label: 'Slack Webhook',
    test: async () => {
      // Don't probe webhooks — they'd send a message
      return { active: null, info: 'Webhook verification skipped (would send message)' };
    },
  },

  // Sendgrid
  SENDGRID_API_KEY: {
    label: 'SendGrid',
    test: async (token) => {
      const res = await safeFetch('https://api.sendgrid.com/v3/user/profile', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { active: res.status === 200 };
    },
  },

  // Twilio
  TWILIO_AUTH_TOKEN: {
    label: 'Twilio',
    test: async () => {
      return { active: null, info: 'Twilio requires Account SID + Auth Token pair' };
    },
  },

  // NPM
  NPM_TOKEN: {
    label: 'npm',
    test: async (token) => {
      const res = await safeFetch('https://registry.npmjs.org/-/whoami', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 200) {
        const data = await res.json();
        return { active: true, info: `Authenticated as: ${data.username}` };
      }
      return { active: false };
    },
  },
};

// =============================================================================
// SAFE FETCH
// =============================================================================

async function safeFetch(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch {
    return { status: 0, json: async () => ({}), text: async () => '' };
  } finally {
    clearTimeout(timeout);
  }
}

// =============================================================================
// SECRETS VERIFIER
// =============================================================================

export class SecretsVerifier {
  /**
   * Verify an array of secret findings.
   * Only probes findings that have a matching provider probe.
   *
   * @param {object[]} findings — Secret findings with rule and matched fields
   * @returns {Promise<object[]>} — Findings with verifyResult attached
   */
  async verify(findings) {
    const secretFindings = findings.filter(
      f => f.category === 'secrets' || f.category === 'secret'
    );

    const results = [];

    for (const finding of secretFindings) {
      const probe = this._findProbe(finding.rule);
      if (!probe) {
        results.push({ finding, result: { active: null, info: 'No probe available' } });
        continue;
      }

      // Extract the actual secret value from the match
      const secret = this._extractSecret(finding.matched);
      if (!secret) {
        results.push({ finding, result: { active: null, info: 'Could not extract key value' } });
        continue;
      }

      try {
        const result = await probe.test(secret);
        finding.verifyResult = {
          active: result.active,
          provider: probe.label,
          info: result.info || (result.active ? 'Key is ACTIVE — rotate immediately' : 'Key is inactive or revoked'),
        };
        results.push({ finding, result: finding.verifyResult });
      } catch {
        finding.verifyResult = { active: null, provider: probe.label, info: 'Verification failed' };
        results.push({ finding, result: finding.verifyResult });
      }
    }

    return results;
  }

  /**
   * Find the probe for a given rule name.
   */
  _findProbe(rule) {
    // Direct match
    if (PROBES[rule]) return PROBES[rule];

    // Partial match (rule may have extra suffixes)
    for (const [key, probe] of Object.entries(PROBES)) {
      if (rule.includes(key) || key.includes(rule)) return probe;
    }
    return null;
  }

  /**
   * Extract the secret value from a regex match.
   * Matches typically look like: API_KEY="sk-1234..." or token: 'ghp_...'
   */
  _extractSecret(matched) {
    if (!matched) return null;

    // Try to extract quoted value
    const quoted = matched.match(/['"]([^'"]{8,})['"]$/);
    if (quoted) return quoted[1];

    // Try to extract after = or :
    const assigned = matched.match(/[=:]\s*['"]?([a-zA-Z0-9_\-./+]{8,})['"]?$/);
    if (assigned) return assigned[1];

    // If the match itself looks like a token, use it
    if (/^[a-zA-Z0-9_\-]{20,}$/.test(matched)) return matched;

    return null;
  }
}

export default SecretsVerifier;
