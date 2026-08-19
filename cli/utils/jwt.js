const HS256_JWT_RE = /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(normalized + padding, 'base64').toString('utf8');
}

function decodePayload(token) {
  const payloadSegment = token.split('.')[1];
  if (!payloadSegment) return null;

  try {
    const payload = JSON.parse(decodeBase64Url(payloadSegment));
    return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : null;
  } catch {
    return null;
  }
}

/**
 * Create a RegExp-compatible matcher for a JWT payload claim.
 *
 * A base64 substring is not a reliable way to find a JSON claim because the
 * encoded bytes change when claim order or surrounding values change. This
 * matcher keeps the scanner's existing test/exec interface while validating
 * the decoded payload semantically.
 */
export function createJwtClaimMatcher(claim, expectedValue) {
  return {
    lastIndex: 0,

    test(input) {
      return this.exec(input) !== null;
    },

    exec(input) {
      const text = String(input);
      HS256_JWT_RE.lastIndex = this.lastIndex;

      let candidate;
      while ((candidate = HS256_JWT_RE.exec(text)) !== null) {
        const payload = decodePayload(candidate[0]);
        if (payload?.[claim] !== expectedValue) continue;

        this.lastIndex = HS256_JWT_RE.lastIndex;
        return {
          0: candidate[0],
          index: candidate.index,
          input: text,
          length: 1,
        };
      }

      this.lastIndex = 0;
      return null;
    },
  };
}
