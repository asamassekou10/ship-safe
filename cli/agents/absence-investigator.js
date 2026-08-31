/**
 * AbsenceInvestigator — deciding rules that assert something is missing
 * ======================================================================
 *
 * A large share of findings are not about a value reaching a sink. They are
 * about a control that is not there: no helmet, no rate limiter, no tenant
 * filter, no authentication on the server. Data-flow tracing has nothing to say
 * about any of them — on OWASP NodeGoat every one of the 48 unresolved findings
 * was of this kind, and the tracer never looked at a single one.
 *
 * The reason those rules are noisy is that they are scoped to a file while the
 * claim they make is about an application. "This route file does not call
 * helmet" is true and uninteresting when `app.use(helmet())` is two directories
 * away. The rule cannot see that; a pass over the whole project can.
 *
 * Two questions, in order:
 *
 *   1. Is the precondition even met — is there a thing here that could hold the
 *      control? A rule about server authentication firing on a file with no
 *      server is not describing a weakness, it is describing nothing.
 *   2. Is the control present anywhere in the project?
 *
 * Present, or precondition unmet, refutes the finding and cites where. Absent
 * across the project raises it to 'likely' and never higher: a rate limiter may
 * live in nginx, an API gateway, or a middleware this pass does not recognise,
 * and "we looked and did not find it" is not the same as "it is not there".
 *
 * Deterministic, no network, no model.
 */

import fs from 'fs';
import path from 'path';
import { attachEvidence, createClaim } from '../utils/evidence.js';

// =============================================================================
// WHAT EACH ABSENCE RULE IS ACTUALLY CLAIMING
// =============================================================================

/**
 * A project that *uses* a web framework, rather than one that *is* one.
 *
 * The distinction decides whether "no helmet here" means anything at all.
 * Express's own lib/application.js defines `app.use`, so a looser precondition
 * matched the framework's implementation of the very method it was looking for
 * and raised five findings against a library that has no application to
 * protect. A consumer imports the framework; the framework does not import
 * itself.
 */
const FRAMEWORK_CONSUMER = /(?:require\s*\(\s*['"`]|from\s+['"`])(?:express|fastify|koa|@hapi\/hapi|next|@nestjs\/core)['"`]/;

/**
 * For each rule: the control whose presence settles it, and the precondition
 * that has to hold for the rule to be describing anything at all.
 *
 * `control` patterns require the control to be *used*, not merely imported. A
 * dependency on express-rate-limit proves a decision was considered, not that
 * it was carried out, and refuting a finding on an unused import would be
 * exactly the silent-loss error this layer exists to prevent.
 */
const ABSENCE_RULES = {
  API_NO_SECURITY_HEADERS: {
    what: 'security headers middleware',
    control: [
      /\b(?:app|server|router|fastify)\.(?:use|register)\s*\(\s*helmet\s*\(/,
      /\bhelmet\s*\(\s*\{?[\s\S]{0,200}?\)/,
      /setHeader\s*\(\s*['"`](?:Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options)/i,
      /\b(?:headers|setHeaders)\s*:\s*\{[^}]*(?:Content-Security-Policy|Strict-Transport-Security)/i,
    ],
    precondition: [FRAMEWORK_CONSUMER],
  },

  API_NO_RATE_LIMIT: { alias: 'RATE_LIMIT' },
  NO_RATE_LIMIT_LOGIN: { alias: 'RATE_LIMIT' },

  RATE_LIMIT: {
    what: 'rate limiting',
    control: [
      /\b(?:app|server|router|fastify)\.(?:use|register)\s*\(\s*\w*(?:rate)?[lL]imit/,
      /\brateLimit\s*\(|\bRateLimiter\w*\s*\(|\bslowDown\s*\(/,
      /\blimiter\.(?:consume|check|removeTokens)\s*\(/,
    ],
    precondition: [FRAMEWORK_CONSUMER],
  },

  MCP_SERVER_NO_AUTH: {
    what: 'authentication on the MCP server',
    control: [
      /\b(?:authenticate|authorize|verifyToken|checkAuth|requireAuth|validateToken)\s*\(/i,
      /\b(?:Authorization|Bearer)\b[\s\S]{0,80}(?:headers|token)/,
      /\bjwt\.verify\s*\(|\bverifyJwt\s*\(/,
    ],
    precondition: [/new\s+McpServer\s*\(|server\.(?:tool|resource|prompt)\s*\(|@(?:server|app)\.tool\b/],
  },

  RAG_NO_TENANT_ISOLATION: {
    what: 'tenant or namespace scoping on the vector store',
    control: [
      /\bnamespace\s*[:=]/,
      /\bfilter\s*:\s*\{[^}]*(?:tenant|user|org|customer)/i,
      /\b(?:tenantId|userId|orgId|workspaceId)\s*[:=][^=]/,
      /\.(?:collection|index)\s*\(\s*[`'"].*(?:tenant|user|org)/i,
    ],
    precondition: [/\b(?:vectorStore|vectordb|pinecone|weaviate|qdrant|chroma|milvus)\b/i, /\baddDocuments\s*\(|\bupsert\s*\(/],
  },

  RAG_UNSANITIZED_INGESTION: {
    what: 'sanitization before ingestion',
    control: [
      /\b(?:sanitize|scrub|clean|strip)\w*\s*\(/i,
      /\bDOMPurify\.sanitize\s*\(/,
      /\bdetectPromptInjection\s*\(|\bvalidateContent\s*\(/i,
    ],
    precondition: [/\baddDocuments\s*\(|\bupsert\s*\(|\bingest\w*\s*\(/i],
  },

  LLM_NO_OUTPUT_FILTER: {
    what: 'filtering of model output',
    control: [
      /\b(?:filter|sanitize|moderate|redact|validate)\w*\s*\([^)]*(?:completion|response|output|content|message)/i,
      /\bmoderations?\.create\s*\(/,
      /\b(?:schema|z)\.[\w.]*parse\s*\([^)]*(?:completion|response|output|content)/i,
    ],
    precondition: [/\b(?:openai|anthropic|completions?|chat)\b[\s\S]{0,60}\.create\s*\(/i, /\bcompletion\b/],
  },
};

/** Files worth searching for a control. */
const SEARCHABLE_EXT = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.py', '.rb', '.go', '.java', '.php',
]);

const MAX_SEARCHED_FILES = 4000;

// =============================================================================
// PASS
// =============================================================================

export class AbsenceInvestigator {
  constructor() {
    this.name = 'AbsenceInvestigator';
    this.description = 'Decides absence rules by searching the project for the control they say is missing';
  }

  investigate(findings, { rootPath = process.cwd(), files = null } = {}) {
    const applicable = findings.filter((f) => resolveRule(f.rule));
    if (!applicable.length) return findings;

    const corpus = this._corpus(files);
    if (!corpus.length) return findings;              // never crawls the disk on its own

    const cache = new Map();

    for (const finding of applicable) {
      const spec = resolveRule(finding.rule);

      const precondition = this._search(corpus, spec.precondition, cache);
      if (!precondition) {
        attachEvidence(finding, createClaim({
          source: 'presence',
          verdict: 'refuted',
          rationale: `Nothing in this project holds ${spec.what} because nothing here is the kind of thing that would: the rule's precondition is not met anywhere.`,
          citations: [],
        }));
        continue;
      }

      // Imports are excluded when looking for a control. A dependency on
      // express-rate-limit proves the idea occurred to someone; only a call
      // site proves it was carried out, and refuting on an unused import is
      // precisely the silent loss this layer exists to prevent.
      const control = this._search(corpus, spec.control, cache, { skipImports: true });
      if (control) {
        attachEvidence(finding, createClaim({
          source: 'presence',
          verdict: 'refuted',
          rationale: `${capitalize(spec.what)} is applied in this project, outside the file the rule looked at.`,
          citations: [{ file: control.file, line: control.line, excerpt: control.excerpt }],
          attackPath: [`${spec.what} found at ${path.relative(rootPath, control.file)}:${control.line}`],
        }));
        continue;
      }

      attachEvidence(finding, createClaim({
        source: 'presence',
        verdict: 'likely',
        rationale: `No ${spec.what} was found anywhere in this project, so the gap is not local to this file. It may still be provided outside the codebase — a proxy, gateway, or platform control this pass cannot see.`,
        citations: [{ file: precondition.file, line: precondition.line, excerpt: precondition.excerpt }],
        attackPath: [`the code this protects is at ${path.relative(rootPath, precondition.file)}:${precondition.line}`],
      }));
    }

    return findings;
  }

  _corpus(files) {
    return (files || [])
      .filter((file) => SEARCHABLE_EXT.has(path.extname(file).toLowerCase()))
      .slice(0, MAX_SEARCHED_FILES);
  }

  /** First place any of these patterns matches, or null. */
  _search(corpus, patterns, cache, { skipImports = false } = {}) {
    if (!patterns || !patterns.length) return null;

    for (const file of corpus) {
      let lines = cache.get(file);
      if (lines === undefined) {
        try { lines = fs.readFileSync(file, 'utf-8').split('\n'); } catch { lines = null; }
        cache.set(file, lines);
      }
      if (!lines) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // A commented-out control is not a control.
        if (/^\s*(?:\/\/|#|\*)/.test(line)) continue;
        if (skipImports && /^\s*(?:import\b|from\b|(?:const|let|var)\s[\s\S]*\brequire\s*\()/.test(line)) continue;
        if (patterns.some((pattern) => pattern.test(line))) {
          return { file, line: i + 1, excerpt: line.trim().slice(0, 120) };
        }
      }
    }
    return null;
  }
}

/**
 * Whether a rule asserts a missing control.
 *
 * The data-flow tracer consults this and stands down. On the safe LLM fixture it
 * would otherwise confirm LLM_NO_OUTPUT_FILTER because model output does reach
 * the line — which is true and beside the point. The finding claims there is no
 * filtering, and a trace of where the value came from cannot speak to that.
 */
export function isAbsenceRule(rule) {
  return Boolean(ABSENCE_RULES[rule]);
}

function resolveRule(rule) {
  const spec = ABSENCE_RULES[rule];
  if (!spec) return null;
  return spec.alias ? ABSENCE_RULES[spec.alias] : spec;
}

function capitalize(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
