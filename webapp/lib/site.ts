/**
 * Canonical site identity — one place, so changing domains is configuration
 * rather than a sweep across the codebase.
 *
 * The site is reachable on more than one domain and always will be: the CLI has
 * been published to npm many times with `shipsafecli.com` baked into its README,
 * and those links are immutable. Exactly one domain is canonical; the others
 * redirect to it. Everything user-visible — canonical tags, OG images, sitemap,
 * email links — must be built from CANONICAL_URL so the two can never drift.
 *
 * To move domains, set NEXT_PUBLIC_SITE_URL. Do not hardcode a host anywhere
 * else.
 */

/** The one domain users and search engines should see. */
export const CANONICAL_URL = (
  process.env.NEXT_PUBLIC_SITE_URL ||
  process.env.NEXT_PUBLIC_APP_URL ||
  'https://www.shipsafecli.com'
).replace(/\/+$/, '');

export const CANONICAL_HOST = new URL(CANONICAL_URL).host;

/**
 * Sending identity for transactional and lifecycle email.
 *
 * Deliberately separate from CANONICAL_URL. A sending domain carries warmed
 * reputation with the receiving providers, and moving it means fresh
 * SPF/DKIM/DMARC and a cold start on deliverability. That is its own migration
 * with its own risk, and tying it to the web domain would mean one change with
 * two independent ways to fail.
 */
export const EMAIL_DOMAIN = process.env.EMAIL_DOMAIN || 'shipsafecli.com';
export const DEFAULT_REPLY_TO = process.env.EMAIL_REPLY_TO || `hello@${EMAIL_DOMAIN}`;
export const DEFAULT_EMAIL_FROM = process.env.EMAIL_FROM || `Ship Safe <hello@${EMAIL_DOMAIN}>`;

/** Absolute URL for a site-relative path. */
export function siteUrl(pathname = '/'): string {
  return `${CANONICAL_URL}${pathname.startsWith('/') ? pathname : `/${pathname}`}`;
}

/** Host without protocol or `www.`, for display in copy and email footers. */
export const DISPLAY_HOST = CANONICAL_HOST.replace(/^www\./, '');
