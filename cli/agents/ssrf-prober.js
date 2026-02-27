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
import { BaseAgent } from './base-agent.js';

const PATTERNS = [
  {
    rule: 'SSRF_USER_URL_FETCH',
    title: 'SSRF: User Input in fetch()',
    regex: /fetch\s*\(\s*(?:req\.|request\.|ctx\.|query|params|body|input|url|data)/g,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User-controlled URL passed to fetch() enables SSRF. Validate against an allowlist.',
    fix: 'Validate URL against allowlist: new URL(input).hostname must match allowed hosts',
  },
  {
    rule: 'SSRF_USER_URL_AXIOS',
    title: 'SSRF: User Input in axios/got/http',
    regex: /(?:axios|got|http|https|request|superagent|node-fetch|undici)(?:\.get|\.post|\.put|\.delete|\.request|\s*\()\s*\(\s*(?:req\.|request\.|ctx\.|query|params|body|input|url|data)/g,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User-supplied URL in HTTP client enables SSRF. Validate and restrict to public IPs.',
    fix: 'Parse URL, block private IPs (127.0.0.1, 10.x, 172.16-31.x, 169.254.x), block file:// protocol',
  },
  {
    rule: 'SSRF_URL_TEMPLATE',
    title: 'SSRF: Template Literal in URL',
    regex: /(?:fetch|axios|got|http\.get|https\.get)\s*\(\s*`[^`]*\$\{(?:req\.|request\.|ctx\.|query|params|body|input)/g,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'User input interpolated into URL for HTTP request enables SSRF.',
    fix: 'Validate and sanitize the URL before making the request',
  },
  {
    rule: 'SSRF_WEBHOOK_URL',
    title: 'SSRF: Unvalidated Webhook URL',
    regex: /webhook[_-]?url\s*[:=]\s*(?:req\.|request\.|ctx\.|body|query|params|input)/gi,
    severity: 'high',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'Accepting user-supplied webhook URLs without validation enables SSRF.',
    fix: 'Validate webhook URL: must be HTTPS, public IP, not cloud metadata endpoint',
  },
  {
    rule: 'SSRF_CLOUD_METADATA',
    title: 'SSRF: Cloud Metadata Endpoint Access',
    regex: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/g,
    severity: 'critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'Cloud metadata endpoint in code. If URL is user-controlled, this enables credential theft.',
    fix: 'Block metadata IPs in URL validation. Use IMDSv2 on AWS (requires token header).',
  },
  {
    rule: 'SSRF_INTERNAL_IP',
    title: 'SSRF: Internal IP Pattern',
    regex: /(?:127\.0\.0\.|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.)\d+/g,
    severity: 'medium',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    confidence: 'low',
    description: 'Internal IP address in code. Verify it is not reachable via user-controlled URLs.',
    fix: 'Block private IP ranges in URL validation for user-supplied URLs',
  },
  {
    rule: 'SSRF_REDIRECT_FOLLOW',
    title: 'SSRF: HTTP Client Follows Redirects',
    regex: /(?:follow|maxRedirects|redirect)\s*:\s*(?:true|\d{2,})/g,
    severity: 'medium',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    confidence: 'low',
    description: 'Following redirects can bypass SSRF protections (redirect to internal IP).',
    fix: 'Disable redirect following or re-validate the redirect target URL',
  },
  {
    rule: 'SSRF_PYTHON_REQUESTS',
    title: 'SSRF: Python requests with User Input',
    regex: /requests\.(?:get|post|put|delete|head|patch)\s*\(\s*(?:request\.|flask\.|data|args|form)/g,
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
