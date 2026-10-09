import { isPrivateAddress } from './remote-fetch.js';

// Shared with SSRF_CLOUD_METADATA: keep cloud-specific hosts in one place.
export const CLOUD_METADATA_HOSTS = Object.freeze([
  '169.254.169.254', 'metadata.google.internal', '100.100.100.200',
]);
export const CLOUD_METADATA_PATTERN = CLOUD_METADATA_HOSTS.map(host => host.replaceAll('.', '\\.')).join('|');

export function destinationHostname(url) {
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function destinationAddress(url) {
  const host = destinationHostname(url);
  // URL normalizes alternate IPv4 spellings and IPv6. Decode mapped IPv4
  // before sharing the existing private-address classification.
  const mapped = host.match(/^::ffff:([a-f\d]{1,4}):([a-f\d]{1,4})$/);
  return mapped
    ? [parseInt(mapped[1], 16) >> 8, parseInt(mapped[1], 16) & 255,
      parseInt(mapped[2], 16) >> 8, parseInt(mapped[2], 16) & 255].join('.') : host;
}

export function isLoopbackDestination(url) {
  const host = destinationAddress(url);
  return host === 'localhost' || host === 'localhost.localdomain' || host.endsWith('.localhost')
    || /^127\./.test(host) || host === '::1';
}

export function isUnsafeCallbackDestination(url) {
  const host = destinationHostname(url);
  return !['http:', 'https:'].includes(url.protocol) || isLoopbackDestination(url)
    || CLOUD_METADATA_HOSTS.includes(host) || isPrivateAddress(destinationAddress(url))
    || /^ff[0-9a-f]{2}:/.test(host) || host.endsWith('.internal') || host.endsWith('.local');
}
