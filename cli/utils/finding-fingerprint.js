import crypto from 'crypto';
import path from 'path';

/**
 * Return a stable identifier for a finding.
 *
 * Line numbers and scan order are intentionally excluded so a harmless edit
 * above a finding does not create a second GitHub review comment.
 */
export function findingFingerprint(finding, rootPath = process.cwd()) {
  const relFile = path.relative(rootPath, finding?.file || '').replace(/\\/g, '/');
  const canonical = [
    finding?.rule || 'unknown-rule',
    relFile,
    finding?.title || '',
    finding?.matched || '',
  ].join('|');

  return `v1-${crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16)}`;
}

export function fingerprintMarker(fingerprint) {
  return `<!-- ship-safe:fingerprint=${fingerprint} -->`;
}

export function extractFingerprint(body = '') {
  return String(body).match(/ship-safe:fingerprint=([a-z0-9-]+)/i)?.[1] || null;
}
