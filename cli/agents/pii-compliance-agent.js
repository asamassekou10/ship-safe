/**
 * PII Compliance Agent
 * ======================
 *
 * Detects privacy violations and PII (Personally Identifiable
 * Information) exposure in source code.
 *
 * Checks:
 *   - PII logged to console/files/external services
 *   - PII in URLs and query parameters
 *   - PII in error responses sent to clients
 *   - PII sent to third-party analytics/tracking
 *   - Hardcoded PII patterns (SSN, credit cards) in source
 *   - Unencrypted PII storage patterns
 *   - Missing data deletion endpoints (GDPR right to erasure)
 *
 * Maps to: GDPR Articles 5, 25, 32; CCPA; OWASP A01
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// PII COMPLIANCE PATTERNS
// =============================================================================

const PATTERNS = [
  // ── PII in Logging ───────────────────────────────────────────────────────
  {
    rule: 'PII_IN_CONSOLE_LOG',
    title: 'Privacy: PII Logged to Console',
    regex: /console\.(?:log|info|warn|error|debug)\s*\([\s\S]{0,100}(?:email|password|ssn|social.?security|credit.?card|phone.?number|date.?of.?birth|dob|passport|national.?id|driver.?license)/gi,
    severity: 'high',
    cwe: 'CWE-532',
    owasp: 'A09:2021',
    description: 'PII fields logged to console. Log output may be stored in log aggregation services, exposing sensitive user data.',
    fix: 'Remove PII from log statements. Use structured logging with PII redaction: logger.info({ userId: user.id }) instead of logging full user objects.',
  },
  {
    rule: 'PII_IN_LOGGER',
    title: 'Privacy: PII in Structured Logger',
    regex: /(?:logger|log|winston|pino|bunyan|morgan)\.(?:info|warn|error|debug|log)\s*\([\s\S]{0,200}(?:email|password|ssn|creditCard|credit_card|phoneNumber|phone_number|dateOfBirth|date_of_birth)/g,
    severity: 'high',
    cwe: 'CWE-532',
    owasp: 'A09:2021',
    description: 'PII fields passed to structured logger. These values persist in log storage and may violate data retention policies.',
    fix: 'Mask or redact PII before logging: email → "u***@example.com", phone → "***-***-1234".',
  },
  {
    rule: 'PII_FULL_OBJECT_LOG',
    title: 'Privacy: Full User Object Logged',
    regex: /console\.(?:log|info|warn|error)\s*\(\s*(?:user|customer|patient|member|account|profile|person)\s*\)/gi,
    severity: 'medium',
    cwe: 'CWE-532',
    owasp: 'A09:2021',
    confidence: 'medium',
    description: 'Full user/customer object passed to console.log. Likely contains PII fields (email, name, phone, address).',
    fix: 'Log only necessary identifiers: console.log({ userId: user.id, action: "login" }).',
  },

  // ── PII in Error Responses ───────────────────────────────────────────────
  {
    rule: 'PII_IN_ERROR_RESPONSE',
    title: 'Privacy: PII in Error Response to Client',
    regex: /(?:res\.(?:json|send|status)|response\.(?:json|send)|jsonify)\s*\(\s*(?:\{[\s\S]{0,200}(?:email|password|ssn|creditCard|phone|user|customer|patient)[\s\S]{0,100}\}|err|error)/g,
    severity: 'high',
    cwe: 'CWE-209',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'PII or user data included in error responses sent to clients. Exposes sensitive information to end users or attackers.',
    fix: 'Return generic error messages to clients. Log detailed errors server-side only.',
  },
  {
    rule: 'PII_STACK_TRACE_RESPONSE',
    title: 'Privacy: Stack Trace With PII in Response',
    regex: /(?:res\.(?:json|send)|response\.(?:json|send))\s*\(\s*\{[\s\S]{0,100}(?:stack|stackTrace|stack_trace)/g,
    severity: 'high',
    cwe: 'CWE-209',
    owasp: 'A01:2021',
    description: 'Stack traces sent in API responses may contain PII from variable values in the call chain.',
    fix: 'Never send stack traces to clients in production. Use error IDs for correlation.',
  },

  // ── PII in URLs ──────────────────────────────────────────────────────────
  {
    rule: 'PII_IN_URL_PARAMS',
    title: 'Privacy: PII in URL Query Parameters',
    regex: /(?:url|href|link|redirect|location)\s*[:=][\s\S]{0,100}(?:\?|&)(?:email|phone|ssn|name|address|dob|password)=/gi,
    severity: 'high',
    cwe: 'CWE-598',
    owasp: 'A01:2021',
    description: 'PII passed in URL query parameters. URLs are logged in server access logs, browser history, and CDN logs.',
    fix: 'Send PII in request body (POST) instead of URL parameters (GET). Use encrypted tokens for cross-page references.',
  },
  {
    rule: 'PII_IN_GET_REQUEST',
    title: 'Privacy: PII Sent via GET Request',
    regex: /(?:fetch|axios\.get|http\.get|requests\.get|got\.get)\s*\(\s*(?:`[^`]*\$\{[^}]*(?:email|phone|ssn|password|name|address)[^}]*\}`|.*\+\s*(?:email|phone|ssn|password))/g,
    severity: 'high',
    cwe: 'CWE-598',
    owasp: 'A01:2021',
    description: 'PII interpolated into GET request URLs. GET parameters are visible in logs, referrer headers, and browser history.',
    fix: 'Use POST requests for sending PII. Never include sensitive data in URL parameters.',
  },

  // ── PII to Third Parties ─────────────────────────────────────────────────
  {
    rule: 'PII_TO_ANALYTICS',
    title: 'Privacy: PII Sent to Analytics Service',
    regex: /(?:analytics|segment|mixpanel|amplitude|posthog|gtag|dataLayer|fbq|intercom|hotjar)[\s\S]{0,50}(?:\.track|\.identify|\.page|\.push|\.event)\s*\([\s\S]{0,200}(?:email|phone|name|address|ssn|dob|userId|user_id)/gi,
    severity: 'high',
    cwe: 'CWE-359',
    owasp: 'A01:2021',
    description: 'PII sent to third-party analytics service without visible consent check. May violate GDPR Article 6 (lawful basis) and CCPA.',
    fix: 'Hash or anonymize PII before sending to analytics. Implement consent management (check opt-in before tracking).',
  },
  {
    rule: 'PII_TO_ERROR_TRACKING',
    title: 'Privacy: PII Sent to Error Tracking Service',
    regex: /(?:Sentry|Bugsnag|Rollbar|TrackJS|LogRocket|DataDog|NewRelic)[\s\S]{0,100}(?:setUser|setContext|setExtra|captureException|notify|addBreadcrumb)[\s\S]{0,200}(?:email|phone|name|address|ssn|password)/gi,
    severity: 'high',
    cwe: 'CWE-359',
    owasp: 'A01:2021',
    description: 'PII attached to error tracking events. Error tracking services store data externally, potentially in different jurisdictions.',
    fix: 'Configure PII scrubbing in your error tracking service. Only send user IDs, not PII fields.',
  },

  // ── Hardcoded PII Patterns ───────────────────────────────────────────────
  {
    rule: 'PII_SSN_IN_CODE',
    title: 'Privacy: Social Security Number in Source Code',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: 'critical',
    cwe: 'CWE-312',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Pattern matching a US Social Security Number found in source code. May be test data or a real SSN.',
    fix: 'Remove SSNs from source code. Use environment variables or a secrets manager for test data.',
  },
  {
    rule: 'PII_CREDIT_CARD_IN_CODE',
    title: 'Privacy: Credit Card Number in Source Code',
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    severity: 'critical',
    cwe: 'CWE-312',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Pattern matching a credit card number found in source code. Violates PCI DSS requirements.',
    fix: 'Remove credit card numbers from source code immediately. Never store raw card numbers — use tokenization.',
  },
  {
    rule: 'PII_EMAIL_HARDCODED',
    title: 'Privacy: Real Email Address Hardcoded',
    regex: /['"][a-zA-Z0-9._%+-]+@(?!example\.com|test\.com|placeholder|fake|dummy)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}['"]/g,
    severity: 'medium',
    cwe: 'CWE-312',
    owasp: 'A02:2021',
    confidence: 'low',
    description: 'Real email address hardcoded in source code (not @example.com). May be PII or a credential.',
    fix: 'Use @example.com for test emails. Store real emails in environment variables or config.',
  },

  // ── Unencrypted PII Storage ──────────────────────────────────────────────
  {
    rule: 'PII_PLAINTEXT_PASSWORD_STORE',
    title: 'Privacy: Password Stored in Plaintext',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*(?:req\.|request\.|body\.|input\.|data\.)(?:password|passwd)/gi,
    severity: 'critical',
    cwe: 'CWE-256',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Password appears to be stored directly from user input without hashing. Passwords must be hashed before storage.',
    fix: 'Hash passwords with bcrypt, scrypt, or argon2 before storing: await bcrypt.hash(password, 12)',
  },
  {
    rule: 'PII_NO_ENCRYPTION_AT_REST',
    title: 'Privacy: PII Column Without Encryption',
    regex: /(?:CREATE\s+TABLE|addColumn|column|field|attribute)[\s\S]{0,200}(?:ssn|social_security|credit_card|card_number|bank_account|passport|national_id|driver_license)[\s\S]{0,100}(?:VARCHAR|TEXT|STRING|varchar|text|string)(?![\s\S]{0,100}encrypt)/gi,
    severity: 'high',
    cwe: 'CWE-311',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Database column storing sensitive PII (SSN, credit card, passport) without encryption-at-rest annotation.',
    fix: 'Encrypt sensitive PII columns at the application level or use database-level encryption.',
  },

  // ── IP Address & Geolocation Logging ─────────────────────────────────────
  {
    rule: 'PII_IP_LOGGING',
    title: 'Privacy: IP Address Logged Without Anonymization',
    regex: /(?:console\.log|logger\.\w+|log\.\w+)\s*\([\s\S]{0,100}(?:ip|ipAddress|ip_address|remoteAddress|x-forwarded-for|client.?ip)/gi,
    severity: 'medium',
    cwe: 'CWE-532',
    owasp: 'A09:2021',
    confidence: 'medium',
    description: 'IP addresses logged without anonymization. Under GDPR, IP addresses are personal data.',
    fix: 'Anonymize IP addresses in logs: mask the last octet (192.168.1.xxx) or hash before logging.',
  },
  {
    rule: 'PII_GEOLOCATION_STORAGE',
    title: 'Privacy: Precise Geolocation Stored',
    regex: /(?:latitude|longitude|lat|lng|geolocation|geoip|geo_location)[\s\S]{0,100}(?:save|store|insert|create|update|write|database|db|mongo|prisma|sequelize)/gi,
    severity: 'medium',
    cwe: 'CWE-359',
    owasp: 'A01:2021',
    confidence: 'low',
    description: 'Precise geolocation data stored in database. May require explicit consent under GDPR/CCPA.',
    fix: 'Reduce precision of stored geolocation (city-level, not street-level). Require explicit consent for precise location.',
  },

  // ── Cookie & Tracking Without Consent ────────────────────────────────────
  {
    rule: 'PII_TRACKING_NO_CONSENT',
    title: 'Privacy: Tracking Script Without Consent Check',
    regex: /(?:gtag|GoogleAnalytics|ga\s*\(|fbq\s*\(|_paq\.push|hotjar|hj\s*\(|intercom|drift|crisp)[\s\S]{0,100}(?:init|config|identify|track|page)(?![\s\S]{0,300}(?:consent|gdpr|cookie.?banner|opt.?in|permission|accept))/g,
    severity: 'medium',
    cwe: 'CWE-359',
    owasp: 'A01:2021',
    confidence: 'low',
    description: 'Analytics or tracking script initialized without visible consent check. May violate GDPR ePrivacy Directive.',
    fix: 'Load tracking scripts only after user consents. Use a consent management platform (CMP).',
  },
];

// =============================================================================
// PII COMPLIANCE AGENT
// =============================================================================

export class PIIComplianceAgent extends BaseAgent {
  constructor() {
    super(
      'PIIComplianceAgent',
      'Detect PII exposure, privacy violations, and GDPR/CCPA compliance gaps',
      'config'
    );
  }

  async analyze(context) {
    const { files } = context;

    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.php', '.go', '.java', '.sql'].includes(ext);
    });

    let findings = [];

    // ── 1. Scan code files with PII patterns ─────────────────────────────
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }

    // ── 2. Check for missing data deletion endpoint (GDPR right to erasure)
    findings = findings.concat(this._checkDataDeletion(context));

    return findings;
  }

  /**
   * Check if the project has user data deletion capability (GDPR Article 17).
   */
  _checkDataDeletion(context) {
    const { files } = context;
    const findings = [];

    // Check if there are user models/routes
    const hasUserModel = files.some(f =>
      /(?:user|account|customer|member|profile)(?:\.model|\.schema|\.entity|Model|Schema)/i.test(f)
    );

    if (!hasUserModel) return findings;

    // Check if there's a delete user endpoint or function
    const hasDeleteEndpoint = files.some(f => {
      const content = this.readFile(f);
      if (!content) return false;
      return /(?:delete.*user|remove.*account|erase.*data|destroy.*profile|gdpr.*delete|data.*deletion|right.*erasure|forget.*me)/i.test(content);
    });

    if (!hasDeleteEndpoint) {
      findings.push(createFinding({
        file: 'project',
        line: 0,
        severity: 'medium',
        category: this.category,
        rule: 'PII_NO_DATA_DELETION',
        title: 'Privacy: No User Data Deletion Capability',
        description: 'Project has user models but no visible data deletion endpoint or function. GDPR Article 17 requires the ability to erase personal data on request.',
        matched: 'No delete/erase/destroy user endpoint found',
        confidence: 'low',
        cwe: 'CWE-359',
        owasp: 'A01:2021',
        fix: 'Implement a user data deletion endpoint (DELETE /api/users/:id or similar) that removes all PII from your systems.',
      }));
    }

    return findings;
  }
}

export default PIIComplianceAgent;
