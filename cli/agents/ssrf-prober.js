/**
 * SSRFProber Agent
 * =================
 *
 * Detects Server-Side Request Forgery vulnerabilities.
 * The fastest-growing attack vector (452% surge in 2025).
 *
 * Checks: user input in URL construction, webhook validation,
 * cloud metadata access, DNS rebinding, protocol smuggling.
 */

import path from 'path';
import { BaseAgent, isInsideJavaScriptNonCode } from './base-agent.js';

const PATTERNS = [
  {
    rule: 'SSRF_USER_URL_FETCH',
    langs: ['js'],   // fetch() is a JS/TS API; the req./ctx. shapes are Express and Koa.
    title: 'SSRF: User Input in fetch()',
    regex: /(?<![\w.])fetch\s*\(\s*(?:req\s*\.|request\s*\.|ctx\s*\.|(?:input|userInput|userUrl|untrustedUrl|suppliedUrl|targetUrl|destinationUrl)\b)/gi,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User-controlled URL passed to fetch() enables SSRF. Validate against an allowlist.',
    fix: 'Validate URL against allowlist: new URL(input).hostname must match allowed hosts',
  },
  {
    rule: 'SSRF_USER_URL_AXIOS',
    langs: ['js'],   // axios, got, superagent, node-fetch and undici are all npm clients.
    title: 'SSRF: User Input in axios/got/http',
    regex: /(?<![\w.])(?:axios|got|http|https|request|superagent|node-fetch|undici)(?:\.(?:get|post|put|delete|request))?\s*\(\s*(?:req\s*\.|request\s*\.|ctx\s*\.|(?:input|userInput|userUrl|untrustedUrl|suppliedUrl|targetUrl|destinationUrl)\b)/gi,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User-supplied URL in HTTP client enables SSRF. Validate and restrict to public IPs.',
    fix: 'Parse URL, block private IPs (127.0.0.1, 10.x, 172.16-31.x, 169.254.x), block file:// protocol',
  },
  {
    rule: 'SSRF_URL_TEMPLATE',
    langs: ['js'],   // backtick template literals only exist in JS/TS.
    title: 'SSRF: Template Literal in URL',
    regex: /(?<![\w.])(?:fetch|axios|got|http\.get|https\.get)\s*\(\s*`[^`]*\$\{(?:req\s*\.|request\s*\.|ctx\s*\.|(?:input|userInput|userUrl|untrustedUrl|suppliedUrl|targetUrl|destinationUrl)\b)/gi,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User input interpolated into URL for HTTP request enables SSRF.',
    fix: 'Validate and sanitize the URL before making the request',
  },
  {
    rule: 'SSRF_WEBHOOK_URL',
    title: 'SSRF: Unvalidated Webhook URL',
    regex: /webhook[_-]?url\s*[:=]\s*(?:req\s*\.|request\s*\.|ctx\s*\.)/gi,
    severity: 'high',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'Accepting user-supplied webhook URLs without validation enables SSRF.',
    fix: 'Validate webhook URL: must be HTTPS, public IP, not cloud metadata endpoint',
  },
  {
    rule: 'SSRF_CLOUD_METADATA',
    title: 'SSRF: Cloud Metadata Endpoint Access',
    // A blocklist must contain the metadata address, but that is defensive
    // code, not an outbound request. Require the literal inside a network
    // client call so `if (hostname === 'metadata.google.internal') return
    // false` is not reported as credential theft.
    regex: /\b(?:fetch|axios|got|request|superagent|node-fetch|undici|requests|httpx|http|https)(?:\.\w+)?\s*\([^)\n]*(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)[^)\n]*\)/gi,
    skipComments: true,
    isCodeMatch: ({ source, sourceOffset }) => !isInsideJavaScriptNonCode(source, sourceOffset),
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'Cloud metadata endpoint in code. If URL is user-controlled, this enables credential theft.',
    fix: 'Block metadata IPs in URL validation. Use IMDSv2 on AWS (requires token header).',
  },
  {
    rule: 'SSRF_INTERNAL_IP',
    title: 'SSRF: Internal IP Pattern',
    // A private IP literal on its own says nothing. Local-first software binds
    // loopback on purpose, and the old bare-literal pattern reported 312 times
    // on hermes-agent for doing exactly what its documentation says it does.
    //
    // The SSRF question is whether an internal address is the destination of a
    // request, so require an outbound-request context on the same line. A bind
    // address, a default host, or a docs example no longer counts.
    // A loopback OAuth redirect URI is RFC 8252's recommended practice for a
    // native app, not an SSRF sink, so exclude the callback shape outright.
    regex: /(?<!(?:redirect_?uri|callback_?url|redirect_?url)\s*[:=]\s*f?["'`])(?:fetch|axios|got|request|urlopen|requests\.\w+|httpx?\.\w+|curl|https?:\/\/|url\s*[:=]|endpoint\s*[:=]|baseURL\s*[:=]|proxy\s*[:=])[^\n]{0,80}(?:127\.0\.0\.|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.)\d+/gi,
    skipComments: true,
    // The local Chrome DevTools endpoint is a fixed loopback harness, not an
    // attacker-selected internal destination. Keep other loopback requests
    // visible, including the direct-request calibration case.
    isCodeMatch: ({ line }) => !/127\.0\.0\.1(?::\$\{[^}]+\}|:\d+)?\/json\/list\b/.test(line),
    severity: 'medium',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    confidence: 'low',
    description: 'Internal IP address used as a request destination. Verify it cannot be reached via a user-controlled URL.',
    fix: 'Block private IP ranges in URL validation for user-supplied URLs',
  },
  {
    rule: 'SSRF_REDIRECT_FOLLOW',
    langs: ['js'],   // maxRedirects is an axios option, and `key: true` is JS object syntax. Still runs on .json and .yml, which carry no language.
    title: 'SSRF: HTTP Client Follows Redirects',
    // `follow: true` is also a common SEO robots option. Tie the option to an
    // actual HTTP client call so page metadata and Next.js redirects do not
    // become SSRF findings.
    regex: /(?<![\w.])(?:fetch|axios|got|request|superagent|node-fetch|undici|http|https)(?:\.\w+)?\s*\([^)\n]*(?:follow|maxRedirects|redirect)\s*:\s*(?:true|['"]follow['"]|\d{2,})[^)\n]*\)/gi,
    skipComments: true,
    isCodeMatch: ({ source, sourceOffset }) => !isInsideJavaScriptNonCode(source, sourceOffset),
    severity: 'medium',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    confidence: 'low',
    description: 'Following redirects can bypass SSRF protections (redirect to internal IP).',
    fix: 'Disable redirect following or re-validate the redirect target URL',
  },
  {
    rule: 'SSRF_PYTHON_REQUESTS',
    langs: ['python'],   // requests + flask.request is Python.
    title: 'SSRF: Python requests with User Input',
    regex: /requests\.(?:get|post|put|delete|head|patch)\s*\(\s*(?:request\s*\.|flask\s*\.)/g,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User-controlled URL in Python requests enables SSRF.',
    fix: 'Validate URL scheme (https only), resolve DNS and check against private IP ranges',
  },
  {
    rule: 'SSRF_IMAGE_PROXY',
    title: 'SSRF: Image/Proxy URL from User Input',
    regex: /(?:imageUrl|image_url|proxyUrl|proxy_url|avatarUrl|avatar_url|iconUrl|icon_url)\s*[:=]\s*(?:req\.|request\.|query|params|body)/gi,
    severity: 'high',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'Image/proxy URLs from user input are common SSRF vectors.',
    fix: 'Validate URL, restrict to known CDN domains, or use an image proxy service',
  },
];

export class SSRFProber extends BaseAgent {
  constructor() {
    super('SSRFProber', 'Detect Server-Side Request Forgery vulnerabilities', 'ssrf');
  }

  async analyze(context) {
    const { files } = context;
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.php', '.go'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }
    return findings;
  }
}

export default SSRFProber;
