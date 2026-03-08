/**
 * APIFuzzer Agent
 * ================
 *
 * Static analysis of API endpoints for security anti-patterns.
 * Checks authentication, authorization, input validation,
 * rate limiting, CORS, error handling, data exposure,
 * mass assignment, GraphQL, file uploads, and pagination.
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

const PATTERNS = [
  // ── Missing Authentication ─────────────────────────────────────────────────
  {
    rule: 'API_NO_AUTH_CHECK',
    title: 'API: Route Without Auth Check',
    regex: /(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s+)?(?:\(req|function)/g,
    severity: 'high',
    cwe: 'CWE-306',
    owasp: 'A07:2021',
    confidence: 'medium',
    description: 'State-changing API route without visible auth middleware. Verify authentication is enforced.',
    fix: 'Add auth middleware: router.post("/api/data", authMiddleware, handler)',
  },

  // ── Input Validation ───────────────────────────────────────────────────────
  {
    rule: 'API_NO_VALIDATION',
    title: 'API: No Input Validation',
    regex: /(?:req\.body|request\.body|ctx\.request\.body)\s*(?:;|\))/g,
    severity: 'medium',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    confidence: 'low',
    description: 'Request body used without validation. Validate with Zod, Joi, or Yup.',
    fix: 'Validate: const data = schema.parse(req.body) using Zod or similar',
  },
  {
    rule: 'API_SPREAD_BODY',
    title: 'API: Spread Request Body into Operation',
    regex: /\.\.\.\s*(?:req\.body|request\.body|ctx\.request\.body)/g,
    severity: 'high',
    cwe: 'CWE-915',
    owasp: 'A01:2021',
    description: 'Spreading request body enables mass assignment. Only use allowed fields.',
    fix: 'Destructure specific fields: const { name, email } = req.body',
  },

  // ── Error Handling ─────────────────────────────────────────────────────────
  {
    rule: 'API_STACK_TRACE_RESPONSE',
    title: 'API: Stack Trace in Response',
    regex: /(?:res\.(?:json|send|status)|ctx\.body)\s*\(\s*(?:\{[^}]*(?:err\.stack|error\.stack|err\.message|error\.message)|err\b|error\b)/g,
    severity: 'medium',
    cwe: 'CWE-209',
    owasp: 'A05:2021',
    description: 'Error details sent in API response leak internal information.',
    fix: 'Log errors server-side. Return generic message: res.status(500).json({ error: "Internal error" })',
  },

  // ── Data Exposure ──────────────────────────────────────────────────────────
  {
    rule: 'API_EXCESSIVE_DATA',
    title: 'API: Returning Full Database Object',
    regex: /(?:res\.json|res\.send|ctx\.body)\s*\(\s*(?:user|users|record|result|data|row|document)\s*\)/g,
    severity: 'medium',
    cwe: 'CWE-200',
    owasp: 'A01:2021',
    confidence: 'low',
    description: 'Returning full DB objects may expose sensitive fields (password, email, etc.).',
    fix: 'Select specific fields: res.json({ id: user.id, name: user.name })',
  },

  // ── File Upload ────────────────────────────────────────────────────────────
  {
    rule: 'API_UNRESTRICTED_UPLOAD',
    title: 'API: Unrestricted File Upload',
    regex: /(?:multer|formidable|busboy|multiparty)\s*\(/g,
    severity: 'medium',
    cwe: 'CWE-434',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'File upload handler detected. Ensure file type validation, size limits, and secure storage.',
    fix: 'Add: fileFilter, limits: { fileSize: 5*1024*1024 }, and validate MIME type',
  },
  {
    rule: 'API_UPLOAD_NO_TYPE_CHECK',
    title: 'API: File Upload Without Type Validation',
    regex: /(?:originalname|filename)\s*(?:\)|;)/g,
    severity: 'high',
    cwe: 'CWE-434',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'File upload using original filename without type validation.',
    fix: 'Validate file extension and MIME type. Generate random filenames for storage.',
  },
  {
    rule: 'API_PATH_IN_FILENAME',
    title: 'API: Path Traversal in File Upload',
    regex: /path\.join\s*\([^)]*(?:originalname|filename|req\.file|req\.body)/g,
    severity: 'critical',
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    description: 'User-supplied filename in path construction enables directory traversal.',
    fix: 'Generate random filename: crypto.randomUUID() + path.extname(file.originalname)',
  },

  // ── GraphQL Security ───────────────────────────────────────────────────────
  {
    rule: 'GRAPHQL_INTROSPECTION',
    title: 'GraphQL: Introspection Enabled',
    regex: /introspection\s*:\s*true/g,
    severity: 'medium',
    cwe: 'CWE-200',
    owasp: 'A05:2021',
    description: 'GraphQL introspection enabled. Exposes full schema to attackers in production.',
    fix: 'Disable in production: introspection: process.env.NODE_ENV !== "production"',
  },
  {
    rule: 'GRAPHQL_NO_DEPTH_LIMIT',
    title: 'GraphQL: No Query Depth Limit',
    regex: /(?:ApolloServer|GraphQLServer|createYoga|makeExecutableSchema)\s*\(/g,
    severity: 'medium',
    cwe: 'CWE-400',
    confidence: 'low',
    description: 'GraphQL server without query depth limiting. Enables deeply nested DoS queries.',
    fix: 'Add depth limiting: graphql-depth-limit or @escape.tech/graphql-armor',
  },
  {
    rule: 'GRAPHQL_NO_COST_ANALYSIS',
    title: 'GraphQL: No Query Cost Analysis',
    regex: /(?:typeDefs|schema)\s*[:=].*(?:Query|Mutation)\s*\{/g,
    severity: 'low',
    cwe: 'CWE-400',
    confidence: 'low',
    description: 'GraphQL schema without query cost analysis. Complex queries can cause DoS.',
    fix: 'Add query complexity analysis: graphql-query-complexity or graphql-armor',
  },

  // ── API Versioning & Documentation ─────────────────────────────────────────
  {
    rule: 'API_DEBUG_ENDPOINT',
    title: 'API: Debug/Test Endpoint in Code',
    regex: /(?:app|router)\.(?:get|post|all)\s*\(\s*['"]\/(?:debug|test|admin|internal|_internal|healthcheck\/debug)/gi,
    severity: 'high',
    cwe: 'CWE-489',
    owasp: 'A05:2021',
    description: 'Debug/test/admin endpoint detected. Ensure it is not accessible in production.',
    fix: 'Remove debug endpoints or protect with auth + environment check',
  },

  // ── Response Headers ───────────────────────────────────────────────────────
  {
    rule: 'API_NO_SECURITY_HEADERS',
    title: 'API: Missing Security Headers (Helmet)',
    regex: /app\.(?:use|listen)\s*\(/g,
    severity: 'low',
    cwe: 'CWE-693',
    owasp: 'A05:2021',
    confidence: 'low',
    description: 'Express app without helmet middleware. Missing security headers (CSP, HSTS, etc.).',
    fix: 'Add helmet: app.use(helmet()) for automatic security headers',
  },

  // ── Sensitive Data in URL ──────────────────────────────────────────────────
  {
    rule: 'API_KEY_IN_URL',
    title: 'API: Secret in URL Query Parameter',
    regex: /(?:url|endpoint|href)\s*[:=]\s*[`"'][^`"']*\?[^`"']*(?:key|token|secret|password|apiKey|api_key)\s*=/gi,
    severity: 'high',
    cwe: 'CWE-598',
    owasp: 'A02:2021',
    description: 'API key or secret passed in URL query parameter. URLs are logged in server logs, browser history, and proxies.',
    fix: 'Move secrets to request headers (e.g., Authorization, x-api-key) instead of URL parameters.',
  },
  {
    rule: 'API_SECRET_IN_URL',
    title: 'API: Sensitive Data in URL Parameters',
    regex: /(?:app|router)\.(?:get|post)\s*\(\s*['"][^'"]*(?::token|:apiKey|:password|:secret|:key)\b/g,
    severity: 'high',
    cwe: 'CWE-598',
    owasp: 'A04:2021',
    description: 'Sensitive data in URL parameters gets logged in server logs, browser history, and proxies.',
    fix: 'Move sensitive data to request headers or body',
  },

  // ── Server Configuration ───────────────────────────────────────────────────
  {
    rule: 'API_TRUST_PROXY',
    title: 'API: Trust Proxy Not Configured',
    regex: /app\.set\s*\(\s*['"]trust proxy['"]\s*,\s*true\s*\)/g,
    severity: 'low',
    cwe: 'CWE-346',
    confidence: 'low',
    description: 'trust proxy set to true trusts all proxies. Specify trusted proxy IPs.',
    fix: 'Set specific proxy: app.set("trust proxy", "loopback") or IP address',
  },

  // ── Denial of Service ──────────────────────────────────────────────────────
  {
    rule: 'API_LARGE_BODY_NO_LIMIT',
    title: 'API: No Request Body Size Limit',
    regex: /(?:express\.json|bodyParser\.json)\s*\(\s*\)/g,
    severity: 'medium',
    cwe: 'CWE-400',
    confidence: 'low',
    description: 'No body size limit configured. Large payloads can cause memory exhaustion.',
    fix: 'Set limit: express.json({ limit: "1mb" })',
  },
  {
    rule: 'API_NO_PAGINATION',
    title: 'API: Query Without Limit',
    regex: /\.find\s*\(\s*\{?\s*\}\s*\)/g,
    severity: 'low',
    cwe: 'CWE-400',
    confidence: 'low',
    description: 'Database query returns all records without limit. Can exhaust memory on large tables.',
    fix: 'Add pagination: .find({}).limit(50).skip(offset)',
  },
];

// OpenAPI/Swagger spec patterns
const OPENAPI_PATTERNS = [
  {
    rule: 'OPENAPI_NO_SECURITY',
    title: 'OpenAPI: No Security Scheme Defined',
    regex: /(?:openapi|swagger)\s*:\s*["']?[23]\./g,
    severity: 'high',
    cwe: 'CWE-306',
    owasp: 'A07:2021',
    confidence: 'medium',
    description: 'OpenAPI spec detected without security schemes. API endpoints may be unprotected.',
    fix: 'Add securityDefinitions/securitySchemes to your OpenAPI spec',
  },
  {
    rule: 'OPENAPI_HTTP_SERVER',
    title: 'OpenAPI: Non-HTTPS Server URL',
    regex: /url\s*:\s*["']?http:\/\//g,
    severity: 'high',
    cwe: 'CWE-319',
    description: 'OpenAPI spec defines an HTTP (non-HTTPS) server URL. Use HTTPS in production.',
    fix: 'Change server URL to use https://',
  },
  {
    rule: 'OPENAPI_EXAMPLE_SECRETS',
    title: 'OpenAPI: Secrets in Examples',
    regex: /example\s*:\s*['"]?(?:sk-|sk_live_|ghp_|gho_|AKIA[0-9A-Z]|Bearer\s+ey[A-Za-z0-9])/g,
    severity: 'critical',
    cwe: 'CWE-798',
    description: 'Real API keys or tokens found in OpenAPI spec examples.',
    fix: 'Replace real secrets with placeholder values in examples',
  },
];

export class APIFuzzer extends BaseAgent {
  constructor() {
    super('APIFuzzer', 'API endpoint security analysis', 'api');
  }

  async analyze(context) {
    const { files } = context;
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.go'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }

    // ── Project-level: Rate limiting check ────────────────────────────────────
    let hasExpressApp = false;
    let hasRateLimiter = false;
    let expressAppFile = null;

    for (const file of codeFiles) {
      const content = this.readFile(file);
      if (!content) continue;
      if (/(?:express\s*\(\)|app\.listen|createServer)\s*/.test(content)) {
        hasExpressApp = true;
        if (!expressAppFile) expressAppFile = file;
      }
      if (/(?:express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|limiter|bottleneck|rateLimit)/i.test(content)) {
        hasRateLimiter = true;
      }
    }

    if (hasExpressApp && !hasRateLimiter && expressAppFile) {
      findings.push(createFinding({
        file: expressAppFile,
        line: 0,
        severity: 'medium',
        category: 'api',
        rule: 'API_NO_RATE_LIMIT',
        title: 'API: No Rate Limiting Detected',
        description: 'HTTP server detected without any rate-limiting library. APIs without rate limits are vulnerable to brute-force and DoS attacks.',
        matched: 'No rate-limiting middleware found',
        confidence: 'medium',
        cwe: 'CWE-307',
        owasp: 'A07:2021',
        fix: 'Add rate limiting: npm i express-rate-limit && app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }))',
      }));
    }

    // ── OpenAPI/Swagger spec scanning ─────────────────────────────────────────
    const specFiles = files.filter(f => {
      const basename = path.basename(f).toLowerCase();
      return /(?:openapi|swagger)\.(json|ya?ml)$/i.test(basename);
    });

    for (const file of specFiles) {
      const specFindings = this.scanFileWithPatterns(file, OPENAPI_PATTERNS);
      // Check if spec has securitySchemes
      const content = this.readFile(file);
      if (content && /(?:openapi|swagger)\s*:\s*["']?[23]\./.test(content)) {
        if (!/securitySchemes|securityDefinitions/i.test(content)) {
          findings.push(createFinding({
            file,
            line: 0,
            severity: 'high',
            category: 'api',
            rule: 'OPENAPI_NO_SECURITY',
            title: 'OpenAPI: No Security Scheme Defined',
            description: 'OpenAPI spec has no securitySchemes/securityDefinitions. API endpoints may be unprotected.',
            matched: 'Missing securitySchemes',
            confidence: 'high',
            cwe: 'CWE-306',
            fix: 'Add securitySchemes with Bearer token, API key, or OAuth2',
          }));
        }
      }
      // Add other OpenAPI pattern matches (HTTP server, example secrets)
      findings = findings.concat(
        specFindings.filter(f => f.rule !== 'OPENAPI_NO_SECURITY')
      );
    }

    return findings;
  }
}

export default APIFuzzer;
