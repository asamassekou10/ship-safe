/**
 * InjectionTester Agent
 * ======================
 *
 * Detects injection vulnerabilities by tracing data flow patterns
 * from user input to dangerous sinks.
 *
 * Covers: SQL Injection, NoSQL Injection, Command Injection,
 *         Code Injection, XSS, LDAP Injection, Template Injection,
 *         Header Injection, Path Traversal, Log Injection,
 *         GraphQL Injection, Open Redirect.
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// INJECTION PATTERNS
// =============================================================================

const PATTERNS = [
  // ── SQL Injection ──────────────────────────────────────────────────────────
  {
    rule: 'SQL_INJECTION_TEMPLATE_LITERAL',
    title: 'SQL Injection via Template Literal',
    regex: /`(?:SELECT|INSERT|UPDATE|DELETE|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE|CREATE|REPLACE|MERGE)[^`]*\$\{/gi,
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    description: 'SQL query with interpolated template variable. Use parameterized queries ($1, ?) or an ORM.',
    fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId])',
  },
  {
    rule: 'SQL_INJECTION_CONCAT',
    title: 'SQL Injection via String Concatenation',
    regex: /["'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']{4,}["']\s*\+/gi,
    severity: 'high',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    description: 'SQL built with string concatenation is vulnerable to injection. Use parameterized queries.',
    fix: 'Replace string concat with parameterized query or ORM method',
  },
  {
    rule: 'SQL_INJECTION_RAW',
    title: 'Raw SQL Query (Prisma/Sequelize/Knex)',
    regex: /(?:\$queryRaw|\.raw|knex\.raw)\s*\(\s*`[^`]*\$\{/gi,
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    description: 'ORM raw query with interpolated values bypasses parameterization. Use tagged templates or bind parameters.',
    fix: 'Prisma: use $queryRaw`...${Prisma.sql}...`; Sequelize: use bind parameters',
  },

  // ── NoSQL Injection ────────────────────────────────────────────────────────
  {
    rule: 'NOSQL_INJECTION_WHERE',
    title: 'NoSQL Injection via $where',
    regex: /\$where\s*:/g,
    severity: 'high',
    cwe: 'CWE-943',
    owasp: 'A03:2021',
    description: '$where in MongoDB executes JavaScript and is vulnerable to injection. Use standard query operators.',
    fix: 'Replace $where with standard MongoDB operators ($eq, $gt, $regex, etc.)',
  },
  {
    rule: 'NOSQL_INJECTION_DYNAMIC',
    title: 'NoSQL Injection via Dynamic Query',
    regex: /\.find\(\s*(?:req\.|request\.|ctx\.)/g,
    severity: 'high',
    cwe: 'CWE-943',
    owasp: 'A03:2021',
    description: 'Passing request data directly to MongoDB find() enables NoSQL injection. Validate and whitelist query fields.',
    fix: 'Validate input: only allow expected fields, cast types explicitly',
  },

  // ── Command Injection ──────────────────────────────────────────────────────
  {
    rule: 'CMD_INJECTION_EXEC_TEMPLATE',
    title: 'Command Injection via exec() Template',
    regex: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Shell command with interpolated values enables command injection. Use execFile() with argument arrays.',
    fix: 'Use execFile(cmd, [arg1, arg2]) instead of exec(`cmd ${arg}`)',
  },
  {
    rule: 'CMD_INJECTION_EXEC_CONCAT',
    title: 'Command Injection via exec() Concatenation',
    regex: /\bexec(?:Sync)?\s*\(\s*["'][^"']*["']\s*\+/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Shell command built with string concatenation enables injection. Use execFile() with arrays.',
    fix: 'Use execFile(cmd, [arg1, arg2]) or spawn(cmd, args) without shell: true',
  },
  {
    rule: 'CMD_INJECTION_SHELL_TRUE',
    title: 'Command Injection via shell: true',
    regex: /\bspawn(?:Sync)?\s*\([^)]*\bshell\s*:\s*true/g,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'shell: true in spawn enables shell expansion and command injection. Pass args as array without shell.',
    fix: 'Remove shell: true and pass arguments as an array',
  },
  {
    rule: 'CMD_INJECTION_PYTHON_OS',
    title: 'Command Injection via os.system/popen',
    regex: /\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen)\s*\([^)]*(?:f['"]|\.format\(|\s*\+\s*)/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Shell command with string formatting enables injection. Use subprocess.run() with args list.',
    fix: 'Use subprocess.run([cmd, arg1, arg2], shell=False)',
  },

  // ── Code Injection ─────────────────────────────────────────────────────────
  {
    rule: 'CODE_INJECTION_EVAL',
    title: 'Code Injection via eval()',
    regex: /\beval\s*\(\s*(?:req\.|request\.|ctx\.|params|query|body|input|data|user)/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'eval() with user input executes arbitrary code. Never pass user data to eval.',
    fix: 'Use JSON.parse() for data, a sandboxed interpreter, or restructure to avoid eval',
  },
  {
    rule: 'CODE_INJECTION_EVAL_GENERIC',
    title: 'Code Injection: eval() Usage',
    regex: /\beval\s*\(/g,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    confidence: 'medium',
    description: 'eval() executes arbitrary code. Replace with JSON.parse(), Function, or a safer alternative.',
    fix: 'Replace eval() with JSON.parse() or a domain-specific parser',
  },
  {
    rule: 'CODE_INJECTION_NEW_FUNCTION',
    title: 'Code Injection via new Function()',
    regex: /\bnew\s+Function\s*\(/g,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'new Function() is equivalent to eval(). Avoid dynamic code generation.',
    fix: 'Refactor to avoid dynamic code generation',
  },
  {
    rule: 'CODE_INJECTION_VM',
    title: 'Code Injection via vm.runInNewContext()',
    regex: /\bvm\.(?:runInNewContext|runInThisContext|compileFunction)\s*\(/g,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'Node.js vm module does not provide security isolation. Use vm2 or isolated-vm for untrusted code.',
    fix: 'Use isolated-vm or a proper sandbox for untrusted code execution',
  },

  // ── XSS ────────────────────────────────────────────────────────────────────
  {
    rule: 'XSS_DANGEROUS_HTML',
    title: 'XSS via dangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'dangerouslySetInnerHTML can introduce XSS if the value contains user input.',
    fix: 'Sanitize with DOMPurify: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}}',
  },
  {
    rule: 'XSS_INNERHTML',
    title: 'XSS via innerHTML Assignment',
    regex: /\.innerHTML\s*=\s*(?!['"]<)/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'innerHTML with dynamic data leads to XSS. Use textContent or DOMPurify.',
    fix: 'Use element.textContent for text, or DOMPurify.sanitize() for HTML',
  },
  {
    rule: 'XSS_DOCUMENT_WRITE',
    title: 'XSS via document.write()',
    regex: /\bdocument\.write(?:ln)?\s*\(/g,
    severity: 'medium',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'document.write() is deprecated and can introduce XSS. Use DOM manipulation.',
    fix: 'Use createElement/appendChild or textContent instead',
  },
  {
    rule: 'XSS_OUTERHTML',
    title: 'XSS via outerHTML Assignment',
    regex: /\.outerHTML\s*=/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'outerHTML with dynamic content enables XSS. Sanitize with DOMPurify.',
    fix: 'Sanitize HTML with DOMPurify before assigning to outerHTML',
  },
  {
    rule: 'XSS_JQUERY_HTML',
    title: 'XSS via jQuery .html()',
    regex: /\$\([^)]+\)\.html\s*\(\s*(?!['"])/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'jQuery .html() with dynamic data enables XSS. Use .text() or sanitize.',
    fix: 'Use .text() for plain text or sanitize HTML with DOMPurify before .html()',
  },
  {
    rule: 'XSS_V_HTML',
    title: 'XSS via Vue v-html Directive',
    regex: /v-html\s*=\s*["']/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'Vue v-html renders raw HTML and is vulnerable to XSS. Sanitize before rendering.',
    fix: 'Sanitize with DOMPurify or use v-text for plain text',
  },

  // ── Path Traversal ─────────────────────────────────────────────────────────
  {
    rule: 'PATH_TRAVERSAL_FS',
    title: 'Path Traversal in File Operations',
    regex: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|stat|statSync)\s*\(\s*(?:req\.|request\.|ctx\.|params|query|`[^`]*\$\{)/g,
    severity: 'critical',
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    description: 'User input in file path enables directory traversal (../../etc/passwd). Validate and restrict paths.',
    fix: 'Use path.resolve() + validate that resolved path starts with allowed directory',
  },
  {
    rule: 'PATH_TRAVERSAL_DOTDOT',
    title: 'Path Traversal: No ../ Validation',
    regex: /path\.join\s*\([^)]*(?:req\.|request\.|ctx\.|params|query|body)/g,
    severity: 'high',
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    description: 'path.join() with user input without ../​ validation enables traversal.',
    fix: 'After path.join, verify: if (!resolvedPath.startsWith(allowedDir)) throw new Error()',
  },

  // ── Template Injection ─────────────────────────────────────────────────────
  {
    rule: 'TEMPLATE_INJECTION_EJS',
    title: 'Server-Side Template Injection (EJS)',
    regex: /ejs\.render\s*\(\s*(?:req\.|request\.|ctx\.|body|query|params)/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'Passing user input as an EJS template enables server-side template injection (SSTI).',
    fix: 'Render from template files, pass user data only as template variables',
  },
  {
    rule: 'TEMPLATE_INJECTION_UNESCAPED',
    title: 'Unescaped Template Output',
    regex: /<%[-=]?\s*(?:req\.|request\.|body|query|params)/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'Unescaped template output with user data enables XSS. Use escaped output.',
    fix: 'Use <%- sanitize(userInput) %> or escape before rendering',
  },

  // ── Header Injection ───────────────────────────────────────────────────────
  {
    rule: 'HEADER_INJECTION',
    title: 'HTTP Header Injection',
    regex: /(?:setHeader|writeHead|header)\s*\([^,]*,\s*(?:req\.|request\.|ctx\.|body|query|params)/g,
    severity: 'high',
    cwe: 'CWE-113',
    owasp: 'A03:2021',
    description: 'User input in HTTP headers enables header injection / response splitting.',
    fix: 'Validate and sanitize: strip newlines (\\r\\n) from header values',
  },

  // ── Open Redirect ──────────────────────────────────────────────────────────
  {
    rule: 'OPEN_REDIRECT',
    title: 'Open Redirect',
    regex: /(?:res\.redirect|redirect|location\.href|window\.location)\s*(?:\(|=)\s*(?:req\.|request\.|ctx\.|query|params)/g,
    severity: 'medium',
    cwe: 'CWE-601',
    owasp: 'A01:2021',
    description: 'Redirecting to user-supplied URL enables phishing via open redirect.',
    fix: 'Validate redirect URL is relative or matches an allowlist of trusted domains',
  },

  // ── Log Injection ──────────────────────────────────────────────────────────
  {
    rule: 'LOG_INJECTION',
    title: 'Log Injection',
    regex: /(?:console\.log|logger\.\w+|log\.\w+)\s*\(\s*`[^`]*\$\{(?:req\.|request\.|ctx\.|body|query|params)/g,
    severity: 'medium',
    cwe: 'CWE-117',
    owasp: 'A09:2021',
    description: 'Unsanitized user input in logs enables log forging and injection attacks.',
    fix: 'Sanitize user input before logging: strip control characters and newlines',
  },

  // ── Regex DoS ──────────────────────────────────────────────────────────────
  {
    rule: 'REDOS',
    title: 'Regular Expression DoS (ReDoS)',
    regex: /new\s+RegExp\s*\(\s*(?:req\.|request\.|ctx\.|body|query|params|input|user)/g,
    severity: 'high',
    cwe: 'CWE-1333',
    owasp: 'A03:2021',
    description: 'User-controlled regex can cause catastrophic backtracking (ReDoS). Validate or use RE2.',
    fix: 'Use the re2 package for user-supplied patterns, or validate regex complexity',
  },
  {
    rule: 'REDOS_NESTED_QUANTIFIER',
    title: 'ReDoS: Nested Quantifiers in Regex',
    regex: /\/[^/]*\([^)]*[+*][^)]*\)[+*][^/]*\//g,
    severity: 'high',
    cwe: 'CWE-1333',
    owasp: 'A03:2021',
    description: 'Regex with nested quantifiers like (a+)+ or (\\w+)* causes catastrophic backtracking.',
    fix: 'Rewrite to avoid nested repetition or use a non-backtracking engine (re2 package).',
  },
  {
    rule: 'REDOS_DOT_STAR_LOOKAHEAD',
    title: 'ReDoS: .* with Lookahead',
    regex: /\/[^/]*\.\*[^/]*\(\?[!=][^/]*\//g,
    severity: 'medium',
    cwe: 'CWE-1333',
    owasp: 'A03:2021',
    description: 'Regex with .* followed by lookahead can cause catastrophic backtracking on non-matching input.',
    fix: 'Replace .* with a bounded class like [^\\n]{0,N} or use a non-backtracking engine (re2).',
  },

  // ── Command Injection with Secrets ────────────────────────────────────────
  {
    rule: 'CMD_INJECTION_SECRET_INTERPOLATION',
    title: 'Command Injection: Secret in Shell Command',
    regex: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{[^}]*(?:secret|password|token|apiKey|api_key|credential)[^}]*\}/gi,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Secret or credential interpolated into shell command. Both a command injection and credential exposure risk.',
    fix: 'Use execFileSync(cmd, [args]) with argument arrays. Never interpolate secrets into shell strings.',
  },

  // ── Prototype Pollution ────────────────────────────────────────────────────
  {
    rule: 'PROTOTYPE_POLLUTION',
    title: 'Prototype Pollution',
    regex: /(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|lodash\.merge)\s*\(\s*(?:\{\}|[a-zA-Z]+),\s*(?:req\.|request\.|ctx\.|body|query|params|input|data)/g,
    severity: 'high',
    cwe: 'CWE-1321',
    owasp: 'A03:2021',
    description: 'Merging user input into objects can pollute Object.prototype. Validate input keys.',
    fix: 'Validate keys against an allowlist, or use Object.create(null) as target',
  },

  // ── XXE ────────────────────────────────────────────────────────────────────
  {
    rule: 'XXE_PARSER',
    title: 'XML External Entity (XXE) Injection',
    regex: /(?:xml2js|libxmljs|DOMParser|parseString|parseXML)\s*(?:\.\w+\s*)?\(/g,
    severity: 'high',
    cwe: 'CWE-611',
    owasp: 'A05:2017',
    confidence: 'medium',
    description: 'XML parsers with default settings may be vulnerable to XXE. Disable external entity processing.',
    fix: 'Disable DTDs and external entities in parser configuration',
  },

  // ── Insecure Deserialization ────────────────────────────────────────────────
  {
    rule: 'UNSAFE_DESERIALIZE_PICKLE',
    title: 'Unsafe Deserialization: pickle',
    regex: /\bpickle\.loads?\s*\(/g,
    severity: 'critical',
    cwe: 'CWE-502',
    owasp: 'A08:2021',
    description: 'pickle.loads() on untrusted data enables arbitrary code execution.',
    fix: 'Use JSON, msgpack, or protobuf for untrusted data serialization',
  },
  {
    rule: 'UNSAFE_DESERIALIZE_YAML',
    title: 'Unsafe Deserialization: yaml.load()',
    regex: /\byaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)/g,
    severity: 'high',
    cwe: 'CWE-502',
    owasp: 'A08:2021',
    description: 'yaml.load() without SafeLoader can execute arbitrary Python code.',
    fix: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)',
  },
  {
    rule: 'UNSAFE_DESERIALIZE_UNSERIALIZE',
    title: 'Unsafe Deserialization: PHP unserialize()',
    regex: /\bunserialize\s*\(\s*\$/g,
    severity: 'critical',
    cwe: 'CWE-502',
    owasp: 'A08:2021',
    description: 'PHP unserialize() with user input enables object injection attacks.',
    fix: 'Use json_decode() instead, or validate input with allowed_classes option',
  },
];

// =============================================================================
// INJECTION TESTER AGENT
// =============================================================================

export class InjectionTester extends BaseAgent {
  constructor() {
    super('InjectionTester', 'Detect injection vulnerabilities across all classes', 'injection');
  }

  async analyze(context) {
    const { rootPath, files } = context;
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
              '.py', '.rb', '.php', '.go', '.java'].includes(ext);
    });

    let findings = [];

    for (const file of codeFiles) {
      const fileFindings = this.scanFileWithPatterns(file, PATTERNS);
      findings = findings.concat(fileFindings);
    }

    return findings;
  }
}

export default InjectionTester;
