/**
 * Ship Safe - Next.js Security Headers Configuration
 * ===================================================
 *
 * Drop this into your next.config.js to add essential security headers.
 *
 * WHY THESE HEADERS MATTER:
 * Without security headers, your app is vulnerable to:
 * - Clickjacking (your site loaded in malicious iframes)
 * - XSS attacks (malicious scripts injected into your pages)
 * - MIME sniffing (browsers misinterpreting file types)
 * - Protocol downgrade attacks (HTTPS -> HTTP)
 *
 * HOW TO USE:
 * 1. Copy this file to your Next.js project root
 * 2. Import and spread into your next.config.js (see example at bottom)
 *
 * TEST YOUR HEADERS:
 * After deploying, check your score at: https://securityheaders.com
 */

const securityHeaders = [
  // ==========================================================================
  // CLICKJACKING PROTECTION
  // ==========================================================================
  {
    key: 'X-Frame-Options',
    value: 'DENY'
    // WHAT: Prevents your site from being embedded in iframes
    // WHY: Attackers could overlay invisible buttons on your site (clickjacking)
    // OPTIONS:
    //   'DENY' - Never allow framing (most secure)
    //   'SAMEORIGIN' - Only allow framing by your own site
    // NOTE: Use 'SAMEORIGIN' if you need iframes for your own features
  },

  // ==========================================================================
  // XSS PROTECTION
  // ==========================================================================
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block'
    // WHAT: Enables browser's built-in XSS filter
    // WHY: Adds a layer of defense against reflected XSS attacks
    // NOTE: Modern browsers use CSP instead, but this helps older browsers
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
    // WHAT: Prevents browsers from MIME-sniffing (guessing file types)
    // WHY: Attackers could trick browsers into executing malicious content
    //      by serving scripts with incorrect MIME types
  },

  // ==========================================================================
  // HTTPS ENFORCEMENT
  // ==========================================================================
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload'
    // WHAT: Forces browsers to always use HTTPS for your site
    // WHY: Prevents protocol downgrade attacks and cookie hijacking
    // BREAKDOWN:
    //   max-age=31536000 - Remember for 1 year (in seconds)
    //   includeSubDomains - Apply to all subdomains too
    //   preload - Allow inclusion in browser's HSTS preload list
    // WARNING: Only enable 'preload' if you're CERTAIN all subdomains support HTTPS
  },

  // ==========================================================================
  // REFERRER POLICY
  // ==========================================================================
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin'
    // WHAT: Controls how much referrer info is sent to other sites
    // WHY: Prevents leaking sensitive URLs (with tokens, user IDs, etc.)
    // THIS SETTING: Send origin only (not full URL) for cross-origin requests
    // OPTIONS:
    //   'no-referrer' - Never send referrer (most private, may break analytics)
    //   'strict-origin' - Only send origin, never on HTTP downgrade
    //   'strict-origin-when-cross-origin' - Full URL same-site, origin cross-site
  },

  // ==========================================================================
  // PERMISSIONS POLICY (formerly Feature-Policy)
  // ==========================================================================
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    // WHAT: Disables browser features you don't need
    // WHY: Reduces attack surface; malicious scripts can't access these APIs
    // THIS SETTING: Disables camera, mic, location, and FLoC tracking
    // CUSTOMIZE: If you need camera/mic (e.g., for video chat), update this:
    //   camera=(self) - Allow camera only from your own origin
    //   microphone=(self "https://trusted-site.com") - Allow from specific origins
  },

  // ==========================================================================
  // CONTENT SECURITY POLICY (CSP)
  // ==========================================================================
  // CSP is your most powerful defense against XSS attacks.
  // It tells the browser exactly which resources are allowed to load.
  //
  // WARNING: CSP can break your site if misconfigured!
  // Start with 'Content-Security-Policy-Report-Only' to test without blocking.
  {
    key: 'Content-Security-Policy',
    value: [
      // DEFAULT: Block everything not explicitly allowed
      "default-src 'self'",

      // SCRIPTS: Only from your domain + inline scripts (needed for Next.js)
      // NOTE: 'unsafe-inline' is needed for Next.js. For maximum security,
      // use nonces instead (requires custom server setup)
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",

      // STYLES: Your domain + inline styles (needed for most CSS-in-JS)
      "style-src 'self' 'unsafe-inline'",

      // IMAGES: Your domain + data URIs + common CDNs
      // ADD your image CDN here if needed (e.g., images.unsplash.com)
      "img-src 'self' data: blob: https:",

      // FONTS: Your domain + Google Fonts
      "font-src 'self' https://fonts.gstatic.com",

      // CONNECTIONS (fetch, WebSocket, etc.): Your domain + your API
      // ADD your API domains here
      "connect-src 'self' https://api.openai.com https://api.anthropic.com",

      // FRAMES: Block all iframes by default
      // Change to 'self' if you need iframes from your own domain
      "frame-src 'none'",

      // PREVENT your site from being framed
      "frame-ancestors 'none'",

      // FORMS: Only submit to your own domain
      "form-action 'self'",

      // BASE URI: Prevent base tag injection
      "base-uri 'self'",

      // UPGRADE insecure requests to HTTPS
      "upgrade-insecure-requests",
    ].join('; ')
    //
    // DEBUGGING CSP:
    // 1. Open browser DevTools > Console
    // 2. Look for "Refused to load..." errors
    // 3. Add the blocked domain to the appropriate directive
    //
    // COMMON ADDITIONS:
    // - Google Analytics: Add to script-src and connect-src
    //   script-src: https://www.googletagmanager.com
    //   connect-src: https://www.google-analytics.com
    // - Stripe:
    //   script-src: https://js.stripe.com
    //   frame-src: https://js.stripe.com
  },
];

/**
 * Export the headers configuration for next.config.js
 *
 * USAGE IN next.config.js:
 *
 * const { securityHeadersConfig } = require('./nextjs-security-headers');
 *
 * module.exports = {
 *   ...securityHeadersConfig,
 *   // your other config options...
 * };
 *
 * OR for ES modules (next.config.mjs):
 *
 * import { securityHeadersConfig } from './nextjs-security-headers.js';
 *
 * export default {
 *   ...securityHeadersConfig,
 *   // your other config options...
 * };
 */
const securityHeadersConfig = {
  async headers() {
    return [
      {
        // Apply to all routes
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};

// =============================================================================
// COMPLETE EXAMPLE: next.config.js
// =============================================================================
/*
// next.config.js (CommonJS)
const { securityHeadersConfig } = require('./nextjs-security-headers');

module.exports = {
  ...securityHeadersConfig,
  reactStrictMode: true,
  // ... your other config
};

// OR next.config.mjs (ES Modules)
import { securityHeadersConfig } from './nextjs-security-headers.js';

export default {
  ...securityHeadersConfig,
  reactStrictMode: true,
  // ... your other config
};
*/

module.exports = { securityHeaders, securityHeadersConfig };
