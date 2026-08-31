import dns from 'dns/promises';
import net from 'net';

const MAX_REDIRECTS = 3;
const LOOPBACK_HOSTNAMES = new Set(['localhost', 'localhost.localdomain']);

function normalizeHostname(hostname) {
  return String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
}

function isPrivateIpv4(address) {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some(Number.isNaN)) return false;
  const [a, b] = octets;
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0) || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51)
    || (a === 203 && b === 0) || a >= 224;
}

function isPrivateIpv6(address) {
  const normalized = address.toLowerCase().split('%')[0];
  if (normalized === '::' || normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd')
    || normalized.startsWith('fe8') || normalized.startsWith('fe9')
    || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;

  const mapped = normalized.match(/^(?:::ffff:|::|(?:0:){5}ffff:)(\d+\.\d+\.\d+\.\d+)$/);
  return Boolean(mapped && isPrivateIpv4(mapped[1]));
}

export function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return false;
}

function isLoopbackHostname(hostname) {
  return LOOPBACK_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost');
}

function isLoopbackAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return address.split('.')[0] === '127';
  return family === 6 && address.toLowerCase().split('%')[0] === '::1';
}

/**
 * Validate a remote destination before making a request.
 *
 * Local HTTP endpoints are permitted only when the caller explicitly opts in
 * for a local MCP/skill development workflow. Public requests must use HTTPS,
 * and both literal and DNS-resolved private addresses are rejected.
 */
export async function assertSafeRemoteUrl(input, { allowLoopback = false } = {}) {
  const url = input instanceof URL ? new URL(input.href) : new URL(input);
  const hostname = normalizeHostname(url.hostname);
  const loopback = isLoopbackHostname(hostname) || isLoopbackAddress(hostname);
  const privateDestination = isPrivateAddress(hostname);

  if (url.username || url.password) {
    throw new Error('Remote URLs must not contain embedded credentials');
  }
  if (privateDestination && !loopback) {
    throw new Error('Remote fetch blocked: private or loopback destination');
  }
  if (loopback && !allowLoopback) {
    throw new Error('Remote fetch blocked: private or loopback destination');
  }
  if (url.protocol !== 'https:' && !(allowLoopback && loopback && url.protocol === 'http:')) {
    throw new Error('Remote fetches require https://; http:// is allowed only for explicit loopback endpoints');
  }

  if (loopback || net.isIP(hostname)) return url;

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error('Remote host could not be resolved safely');
  }
  if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error('Remote fetch blocked: hostname resolves to a private destination');
  }
  return url;
}

export async function fetchSafeUrl(input, options = {}) {
  let current = input;
  let method = options.method || 'GET';
  let body = options.body;

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    const safeUrl = await assertSafeRemoteUrl(current, options);
    const response = await fetch(safeUrl, {
      ...options,
      method,
      body,
      redirect: 'manual',
    });

    if (![301, 302, 303, 307, 308].includes(response.status)) return response;

    const location = response.headers.get('location');
    if (!location) throw new Error('Remote server returned a redirect without a location');
    if (redirectCount === MAX_REDIRECTS) throw new Error('Remote fetch exceeded the redirect limit');

    current = new URL(location, safeUrl);
    if ([301, 302, 303].includes(response.status)) {
      method = 'GET';
      body = undefined;
    }
  }

  throw new Error('Remote fetch failed');
}
