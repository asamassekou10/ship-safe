import { createPublicKey, verify } from 'node:crypto';

export const A2A_SIGNATURE_STATES = Object.freeze({
  ABSENT: 'absent',
  UNVERIFIED: 'present but unverified',
  VERIFIED: 'verified against a pinned key',
});

// A2A signs JCS JSON with the top-level signatures removed. For v1 cards,
// omit empty optional repeated fields, retaining required repeated fields.
export function canonicalizeAgentCard(card) {
  const v1 = Array.isArray(card.supportedInterfaces);
  function encode(value, location = []) {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Non-finite JSON number');
    if (typeof value === 'string' && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      throw new Error('Unpaired surrogate in JSON string');
    }
    if (Array.isArray(value)) return `[${value.map((item, i) => encode(item, [...location, i])).join(',')}]`;
    if (value && typeof value === 'object') {
      return `{${Object.keys(value).sort().filter(key => {
        if (!location.length && key === 'signatures') return false;
        const optionalRepeated = (!location.length && key === 'securityRequirements')
          || (location.length === 1 && location[0] === 'capabilities' && key === 'extensions')
          || (location.length === 2 && location[0] === 'skills'
            && ['examples', 'inputModes', 'outputModes', 'securityRequirements'].includes(key));
        // Do not normalize arbitrary extension data: it is signed content.
        return !v1 || !optionalRepeated || !Array.isArray(value[key]) || value[key].length > 0;
      }).map(key => `${encode(key)}:${encode(value[key], [...location, key])}`).join(',')}}`;
    }
    return JSON.stringify(value);
  }
  return encode(card);
}

/** Pins come from the caller, never from the card, jku, or embedded jwk.
 * pinnedKeys: Map<kid, { algorithm: 'ES256'|'RS256', key: PEM|KeyObject }>.
 * Unsupported signatures and malformed keys stay unverified. No network I/O.
 */
export function agentCardSignatureState(card, pinnedKeys = new Map()) {
  if (card.signatures === undefined || (Array.isArray(card.signatures) && !card.signatures.length)) return A2A_SIGNATURE_STATES.ABSENT;
  if (!Array.isArray(card.signatures)) return A2A_SIGNATURE_STATES.UNVERIFIED;
  for (const entry of card.signatures) {
    try {
      if (!entry || !/^[A-Za-z0-9_-]+$/.test(entry.protected) || !/^[A-Za-z0-9_-]+$/.test(entry.signature)) continue;
      const header = JSON.parse(Buffer.from(entry.protected, 'base64url').toString('utf8'));
      const pin = pinnedKeys.get(header.kid);
      if (!pin || pin.algorithm !== header.alg || header.crit || header.b64 === false) continue;
      const key = pin.key?.type === 'public' ? pin.key : createPublicKey(pin.key);
      if (header.alg === 'ES256' && (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')) continue;
      if (header.alg === 'RS256' && key.asymmetricKeyType !== 'rsa') continue;
      if (!['ES256', 'RS256'].includes(header.alg)) continue;
      const payload = Buffer.from(canonicalizeAgentCard(card)).toString('base64url');
      if (verify('sha256', Buffer.from(`${entry.protected}.${payload}`),
        { key, ...(header.alg === 'ES256' ? { dsaEncoding: 'ieee-p1363' } : {}) },
        Buffer.from(entry.signature, 'base64url'))) return A2A_SIGNATURE_STATES.VERIFIED;
    } catch { /* Invalid input is evidence of neither authenticity nor trust. */ }
  }
  return A2A_SIGNATURE_STATES.UNVERIFIED;
}
