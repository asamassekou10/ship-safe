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
/**
 * Two rules are deliberately absent from this table: AGENT_NO_COST_LIMIT and
 * AGENT_NO_AUDIT_LOG. Both say, in their own text, that the file issuing
 * completions or dispatching tools sets no ceiling or writes no log *anywhere
 * in it*. A project-wide search contradicts the claim rather than testing it:
 * max_tokens is a per-call argument and does not propagate, and a logger in
 * another module does not record this dispatcher's calls.
 *
 * Registering them refuted 25 and 7 findings against a single unrelated line in
 * one batch runner. Answering a question wrongly is worse than leaving it open,
 * so they stay unanswered until there is a pass that can follow a call into a
 * shared wrapper and see what it sets.
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

  /**
   * Local rather than project-wide. "This handler does not validate its input"
   * is answered by the handler, not by the repository: a `validate()` in some
   * other file is not a guard on this one, and searching the project for one
   * would refute every handler in any codebase that validates anywhere.
   */
  API_NO_VALIDATION: {
    what: 'input validation in this handler',
    scope: 'local',
    control: [
      // `if (!chatId || !message) return res.status(400)` — the guard clause
      // that follows a destructure, which is how most handlers actually do it.
      /\bif\s*\([^)]*\)\s*\{?\s*(?:return\s+)?(?:res|reply|ctx)\b/,
      /\bres(?:ponse)?\.status\s*\(\s*4\d\d\s*\)/,
      /\b(?:z|schema|joi|yup|v)\.[\w.]*(?:parse|validate|assert)\w*\s*\(/i,
      /\b(?:validate|assertValid|sanitize|check)\w*\s*\(/i,
      /\bthrow\s+new\s+\w*(?:Validation|BadRequest|Invalid)\w*Error\b/,
      /\b(?:Array\.isArray|typeof\s+\w+\s*===)/,
    ],
    precondition: [/./],
  },

  /**
   * Local. The rule is about one dispatch site: whether the assistant message
   * that requested a tool call is preserved beside the tool result appended
   * next to it. Another file getting this right says nothing about this one.
   */
  AGENT_TOOL_CALL_REPLAY_MISSING_ASSISTANT: {
    what: 'the assistant tool-call message beside the tool result',
    scope: 'local',
    control: [
      /\btool_calls\b/,
      /\btool_call_id\b/,
      /\brole\s*[:=]\s*['"`]assistant['"`]/,
    ],
    precondition: [/./],
  },

  /** Local: validation belongs beside the query it guards. */
  LLM_RAG_NO_VALIDATION: {
    what: 'validation before the query reaches the retriever',
    scope: 'local',
    control: [
      /\b(?:validate|sanitize|check|clean)\w*\s*\(/i,
      /\blen\s*\(|\.length\s*[<>]=?/,
      /\b(?:z|schema|joi|yup|pydantic)\b/i,
      /\bif\s*\(?[^)\n]*\)?\s*:?\s*\{?\s*(?:return|raise|throw)\b/,
    ],
    precondition: [/./],
  },

  /**
   * Local. Whether *this* workflow verifies what it downloads is not settled by
   * a checksum in some other workflow.
   */
  CICD_NO_ARTIFACT_VERIFY: {
    what: 'integrity verification of the artifact',
    scope: 'local',
    control: [
      /\b(?:sha256sum|sha512sum|md5sum|shasum|cosign|slsa|attest\w*)\b/i,
      /\bchecksum\b|\bdigest\b|\bintegrity\b/i,
      /\bgpg\s+--verify\b|\bsigstore\b/i,
    ],
    precondition: [/./],
  },

  /** Project-wide, same reasoning as HTTP rate limiting. */
  LLM_NO_RATE_LIMIT: {
    what: 'rate limiting on the AI endpoint',
    control: [
      /\brateLimit\w*\s*\(|\bRateLimiter\w*\s*\(|\bslowDown\s*\(/,
      /\blimiter\.(?:consume|check|removeTokens|hit)\s*\(/,
      /\b(?:app|server|router|fastify)\.(?:use|register)\s*\(\s*\w*(?:rate)?[lL]imit/,
      /\b(?:throttle|backoff|semaphore)\w*\s*\(/i,
    ],
    precondition: [/\b(?:completions?|messages|chat)\.create\s*\(|\bgenerate_content\s*\(/i],
  },

  /** Local: the confirmation gate sits at the dispatch it gates. */
  AGENT_TOOL_NO_CONFIRMATION: {
    what: 'a confirmation step before the tool runs',
    scope: 'local',
    control: [
      /\b(?:confirm|approve|prompt|ask|consent|require_?approval)\w*\s*\(/i,
      /\b(?:requiresApproval|needsConfirmation|human_?in_?the_?loop|awaiting_?approval)\b/i,
      /\bif\s*\(?[^)\n]*\b(?:approved|confirmed|allowed)\b/i,
    ],
    precondition: [/./],
  },

  /**
   * Local. Filtering retrieved chunks is done where they are assembled into the
   * prompt, and the data-flow tracer must not answer this one: it would confirm
   * that retrieved text reaches the prompt, which is the rule's own premise
   * rather than evidence for it.
   */
  RAG_NO_RETRIEVAL_FILTER: {
    what: 'filtering of retrieved chunks before they enter the prompt',
    scope: 'local',
    control: [
      /\b(?:filter|sanitize|scrub|strip|clean|redact)\w*\s*\(/i,
      /\b(?:allowlist|denylist|blocklist)\b/i,
      /\bdetect_?prompt_?injection\s*\(/i,
    ],
    precondition: [/./],
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

/** How far past a finding a local guard clause may reasonably sit. */
const LOCAL_WINDOW = 15;

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
    const projectScoped = applicable.some((f) => resolveRule(f.rule).scope !== 'local');
    if (!corpus.length && projectScoped) return findings;   // never crawls the disk on its own

    const cache = new Map();

    for (const finding of applicable) {
      const spec = resolveRule(finding.rule);

      if (spec.scope === 'local') {
        this._investigateLocally(finding, spec, cache);
        continue;
      }

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

  /**
   * Some absences are a property of the handler, not the project. The window
   * runs forward from the finding because a guard clause follows the
   * destructure it guards; a validator above it usually belongs to whatever
   * came before.
   */
  _investigateLocally(finding, spec, cache) {
    let lines = cache.get(finding.file);
    if (lines === undefined) {
      try { lines = fs.readFileSync(finding.file, 'utf-8').split('\n'); } catch { lines = null; }
      cache.set(finding.file, lines);
    }
    if (!lines) return;

    // Start below the finding. The rule fired because of what is on that line,
    // so accepting it as the control refutes the finding with its own evidence:
    // AGENT_TOOL_CALL_REPLAY matched `tool_calls` on the very line whose
    // handling of tool_calls it was objecting to.
    const start = finding.line;
    const end = Math.min(lines.length, start + LOCAL_WINDOW);

    for (let i = start; i < end; i++) {
      const line = lines[i];
      if (/^\s*(?:\/\/|#|\*)/.test(line)) continue;
      if (!spec.control.some((pattern) => pattern.test(line))) continue;

      attachEvidence(finding, createClaim({
        source: 'presence',
        verdict: 'refuted',
        rationale: `${capitalize(spec.what)} is present: found ${i - finding.line + 1} line(s) below the finding.`,
        citations: [{ file: finding.file, line: i + 1, excerpt: line.trim().slice(0, 120) }],
      }));
      return;
    }

    attachEvidence(finding, createClaim({
      source: 'presence',
      verdict: 'likely',
      rationale: `No ${spec.what} was found in the ${LOCAL_WINDOW} lines that follow, where it would be.`,
      citations: [{ file: finding.file, line: finding.line }],
    }));
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
