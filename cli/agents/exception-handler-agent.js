/**
 * Exception Handling Agent
 * =========================
 *
 * Detects mishandling of exceptional conditions — OWASP A10:2025.
 *
 * This is a NEW OWASP Top 10 2025 category that addresses:
 *   - Empty catch blocks that swallow errors silently
 *   - Generic catch-all without proper handling
 *   - Unhandled promise rejections
 *   - Missing React/Vue error boundaries
 *   - Stack traces leaked to production responses
 *   - Error responses that expose internal details
 *   - Missing finally/cleanup in resource handling
 *
 * Maps to: OWASP A10:2025, CWE-390, CWE-754, CWE-755
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// EXCEPTION HANDLING PATTERNS
// =============================================================================

const PATTERNS = [
  // ── Empty/Silent Error Handling ────────────────────────────────────────────
  {
    rule: 'EXCEPTION_EMPTY_CATCH',
    category: 'quality',   // maintainability, not a vulnerability — reported, not scored
    title: 'Exception: Empty catch Block',
    regex: /catch\s*\(\s*(?:e|err|error|ex|exception|_)?\s*\)\s*\{\s*\}/g,
    severity: 'medium',
    cwe: 'CWE-390',
    owasp: 'A10:2025',
    description: 'Empty catch block silently swallows errors. Failures go undetected, masking bugs and security issues.',
    fix: 'Handle the error: catch (err) { logger.error("Context:", err); throw err; }',
  },
  {
    rule: 'EXCEPTION_CATCH_COMMENT_ONLY',
    category: 'quality',   // maintainability, not a vulnerability — reported, not scored
    title: 'Exception: catch Block With Only a Comment',
    regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\/\/[^\n]*\s*\}/g,
    severity: 'low',
    cwe: 'CWE-390',
    owasp: 'A10:2025',
    confidence: 'medium',
    description: 'Catch block contains only a comment — error is still silently swallowed.',
    fix: 'At minimum, log the error for debugging: catch (err) { /* expected for X */ logger.debug(err); }',
  },
  {
    rule: 'EXCEPTION_PYTHON_BARE_EXCEPT',
    category: 'quality',   // maintainability, not a vulnerability — reported, not scored
    title: 'Exception: Python Bare except: (catches everything)',
    regex: /^(\s*)except\s*:\s*$/gm,
    severity: 'high',
    cwe: 'CWE-396',
    owasp: 'A10:2025',
    description: 'Bare except: catches all exceptions including SystemExit and KeyboardInterrupt. Use except Exception instead.',
    fix: 'Use specific exception types: except ValueError as e: or at least except Exception as e:',
  },
  {
    rule: 'EXCEPTION_PYTHON_PASS',
    category: 'quality',   // maintainability, not a vulnerability — reported, not scored
    title: 'Exception: Python except with pass',
    regex: /except\s+\w+(?:\s+as\s+\w+)?:\s*\n\s+pass\s*$/gm,
    severity: 'medium',
    cwe: 'CWE-390',
    owasp: 'A10:2025',
    description: 'Python except block with only pass — error is silently ignored.',
    fix: 'Log the error: except Exception as e: logger.warning(f"Handled: {e}")',
  },

  // ── Unhandled Async Errors ────────────────────────────────────────────────
  {
    rule: 'EXCEPTION_UNHANDLED_PROMISE',
    title: 'Exception: Async Function Without Error Handling',
    regex: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*async\s+(?:\(\s*(?:req|request|ctx)\s*(?:,\s*(?:res|response|next))?\s*\)|(?:req|request|ctx))\s*=>\s*\{(?:(?!try\s*\{|\.catch\b).){0,500}\}/gs,
    severity: 'medium',
    cwe: 'CWE-755',
    owasp: 'A10:2025',
    confidence: 'low',
    description: 'Async route handler without try/catch or .catch(). Unhandled rejection will crash the process or return 500.',
    fix: 'Wrap in try/catch or use an async error wrapper: app.get("/path", asyncHandler(async (req, res) => { ... }))',
  },

  // ── Error Information Leakage ─────────────────────────────────────────────
  {
    rule: 'EXCEPTION_STACK_IN_RESPONSE',
    title: 'Exception: Stack Trace in Response',
    regex: /(?:res\.(?:json|send|status)|response\.(?:json|send))\s*\([^)]*(?:\.stack|stackTrace|stack_trace|err\.message)/g,
    severity: 'high',
    cwe: 'CWE-209',
    owasp: 'A10:2025',
    description: 'Error stack trace or raw error message sent in API response. Reveals internal paths, versions, and logic to attackers.',
    fix: 'Return generic error to client, log details server-side: res.status(500).json({ error: "Internal error", id: errorId })',
  },
  {
    rule: 'EXCEPTION_FULL_ERROR_RESPONSE',
    title: 'Exception: Full Error Object in Response',
    regex: /(?:res\.(?:json|send)|response\.(?:json|send))\s*\(\s*(?:err|error|e|ex)\s*\)/g,
    severity: 'high',
    cwe: 'CWE-209',
    owasp: 'A10:2025',
    description: 'Full error object sent directly in response. May contain stack traces, file paths, and sensitive context.',
    fix: 'Send only safe fields: res.json({ error: err.message, code: err.code })',
  },

  // ── Missing Error Boundaries ──────────────────────────────────────────────
  {
    rule: 'EXCEPTION_NO_ERROR_BOUNDARY',
    title: 'Exception: React App Without Error Boundary',
    regex: /(?:createRoot|ReactDOM\.render)\s*\(\s*(?:(?!ErrorBoundary|error-boundary|Sentry\.ErrorBoundary)[\s\S]){0,200}\)/g,
    severity: 'medium',
    cwe: 'CWE-755',
    owasp: 'A10:2025',
    confidence: 'low',
    description: 'React app rendered without an Error Boundary. Unhandled component errors will crash the entire UI.',
    fix: 'Wrap your app: <ErrorBoundary fallback={<ErrorPage />}><App /></ErrorBoundary>',
  },

  // ── Generic Catch-All Without Rethrow ─────────────────────────────────────
  {
    rule: 'EXCEPTION_CATCH_ALL_NO_RETHROW',
    category: 'quality',   // maintainability, not a vulnerability — reported, not scored
    title: 'Exception: catch(Exception) Without Rethrow',
    regex: /catch\s*\(\s*(?:Exception|Error|Throwable|BaseException)\s+\w+\s*\)\s*\{(?:(?!throw\b|rethrow\b).){0,200}\}/gs,
    severity: 'medium',
    cwe: 'CWE-396',
    owasp: 'A10:2025',
    confidence: 'low',
    description: 'Catching broad Exception/Error without rethrowing. Unexpected errors are silently absorbed.',
    fix: 'Either rethrow unexpected exceptions or catch only specific exception types you can handle.',
  },

  // ── Process-Level Missing Handlers ────────────────────────────────────────
  {
    rule: 'EXCEPTION_NO_UNCAUGHT_HANDLER',
    title: 'Exception: Missing uncaughtException Handler',
    regex: /(?:http\.createServer|express\(\)|new\s+Koa|fastify\(\)|new\s+Hono)(?:(?!uncaughtException|unhandledRejection).){0,2000}(?:\.listen|module\.exports)/gs,
    severity: 'medium',
    cwe: 'CWE-755',
    owasp: 'A10:2025',
    confidence: 'low',
    description: 'Server application without process.on("uncaughtException") handler. Unhandled errors will crash the process.',
    fix: 'Add: process.on("uncaughtException", (err) => { logger.error("Uncaught:", err); process.exit(1); })',
  },

  // ── Resource Cleanup ──────────────────────────────────────────────────────
  {
    rule: 'EXCEPTION_OPEN_WITHOUT_CLOSE',
    category: 'quality',   // maintainability, not a vulnerability — reported, not scored
    title: 'Exception: Resource Opened Without finally/close',
    regex: /(?:createConnection|createPool|open\(|connect\()[\s\S]{0,500}(?:(?!\.finally|\.close\(|\.end\(|\.release\(|\.destroy\(|finally\s*\{|with\s).){200,}$/gm,
    severity: 'low',
    cwe: 'CWE-404',
    owasp: 'A10:2025',
    confidence: 'low',
    description: 'Database connection or resource opened without visible close/finally block. Resource leaks under error conditions.',
    fix: 'Use try/finally or a connection pool: try { conn = await pool.connect(); ... } finally { conn.release(); }',
  },
];

// =============================================================================
// EXCEPTION HANDLER AGENT CLASS
// =============================================================================

export class ExceptionHandlerAgent extends BaseAgent {
  constructor() {
    super(
      'ExceptionHandlerAgent',
      'Detects mishandling of exceptional conditions (OWASP A10:2025)',
      'injection', // maps to Code Vulnerabilities
    );
  }

  async analyze(context) {
    const files = this.getFilesToScan(context);
    const findings = [];

    for (const file of files) {
      const ext = path.extname(file).toLowerCase();
      if (!['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
            '.py', '.rb', '.go', '.java', '.rs', '.php',
            '.vue', '.svelte'].includes(ext)) continue;

      const results = this.scanFileWithPatterns(file, PATTERNS);
      findings.push(...results);
    }

    return findings;
  }
}
