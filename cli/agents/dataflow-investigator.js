/**
 * DataflowInvestigator — trace the value, not the neighbourhood
 * ==============================================================
 *
 * VerifierAgent asks whether the words "req.query" and "sanitize" appear within
 * a few lines of a finding. That is cheap and it is why it settles two of the
 * twelve corpus findings: proximity is not a data path. A validator three lines
 * above the sink may guard a different variable entirely, and the value that
 * reaches the sink may have been assigned six lines earlier from a constant.
 *
 * This pass follows the actual value. From the sink it takes the identifiers
 * that feed it, walks backwards through assignments, destructurings, and
 * parameters, and asks what each one resolves to — an untrusted source, a
 * literal, a sanitizer's return value, or nothing it can determine. Every hop
 * it takes becomes a citation, so the claim it files can be checked line by
 * line rather than believed.
 *
 * It ranks above the LLM pass deliberately. A traced path is a stronger fact
 * than a model's reading of the same file, and when the two disagree the trace
 * should win.
 *
 * Deliberate limits, because a tracer that guesses is worse than one that
 * abstains:
 *
 *   - JavaScript and TypeScript only. Python and Go get no claim at all rather
 *     than a JS-shaped guess about their syntax.
 *   - Within one file. Cross-file tracing needs the import graph, and a
 *     half-built version of it would produce confident nonsense about the
 *     wrong function.
 *   - Taint-shaped rules only. A hardcoded secret is *proven* by its value
 *     being a literal; concluding "refuted, it is a constant" there would
 *     invert the finding. Categories where a literal is the vulnerability are
 *     skipped outright.
 *
 * When the trace dies, the pass files nothing. Silence keeps the verdict at
 * whatever a better-informed pass concluded, which is the correct outcome for a
 * pass that learned nothing.
 */

import fs from 'fs';
import path from 'path';
import { attachEvidence, createClaim } from '../utils/evidence.js';

// =============================================================================
// VOCABULARY
// =============================================================================

const TRACEABLE_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);

/**
 * Categories where the value reaching the sink is what makes the finding real.
 * Everything else — secrets, supply chain, configuration, licensing — is about
 * the value being present, not about where it came from.
 */
const TAINT_CATEGORIES = new Set(['vulnerability', 'api', 'injection', 'auth', 'llm']);

/** Expressions that introduce a value an attacker controls. */
const UNTRUSTED_SOURCE = [
  { re: /\breq(?:uest)?\.(?:body|query|params|headers|cookies|url|originalUrl)\b/, what: 'the HTTP request' },
  { re: /\bctx\.(?:request|query|params|body|headers)\b/,                          what: 'the HTTP request' },
  { re: /\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b/,        what: 'the invocation event' },
  { re: /\b(?:searchParams|URLSearchParams)\b/,                                    what: 'the URL query string' },
  { re: /\bformData\b/,                                                            what: 'submitted form data' },
  { re: /\bprocess\.argv\b/,                                                       what: 'the command line' },
  { re: /\bawait\s+(?:req|request)\.(?:json|text|formData)\s*\(/,                  what: 'the HTTP request body' },
  { re: /\b(?:completion|response|message|choice)s?\.(?:content|text|message|output)\b/, what: 'model output' },
  { re: /\bwindow\.location\b|\bdocument\.(?:URL|referrer|cookie)\b/,              what: 'the browser environment' },
];

/**
 * Calls whose return value is no longer the attacker's to shape. Applied only
 * to the expression actually assigned to the traced variable — a validator
 * called on some other value is not a mitigation, which is precisely the
 * mistake the heuristic pass makes.
 */
const SANITIZER = [
  { re: /\b(?:parseInt|parseFloat|Number|BigInt)\s*\(/,        what: 'numeric coercion' },
  { re: /\bencodeURIComponent\s*\(/,                           what: 'URI encoding' },
  { re: /\b(?:escape|escapeHtml|sanitize\w*|purify|DOMPurify\.sanitize)\s*\(/i, what: 'escaping or sanitization' },
  { re: /\b\w*(?:[sS]chema|validator)\w*\.(?:parse|validate|assert)\s*\(/,      what: 'schema validation' },
  { re: /\bz\.[\w.]+\.parse\s*\(/,                             what: 'zod validation' },
  { re: /\b(?:validate|assertValid|checkAllowed|isAllowed)\w*\s*\(/i,           what: 'an explicit validation call' },
  { re: /\bALLOW(?:ED|LIST)\w*\.(?:includes|has)\s*\(/i,       what: 'an allowlist membership test' },
  { re: /\.(?:includes|indexOf)\s*\(\s*\w+\s*\)\s*\?/,         what: 'an allowlist ternary' },
];

/** A value written into the source rather than arriving from outside. */
const LITERAL = /^\s*(?:'[^']*'|"[^"]*"|`[^`$]*`|-?\d+(?:\.\d+)?|true|false|null)\s*$/;

const MAX_HOPS = 12;
const MAX_SEEDS = 4;

// =============================================================================
// PASS
// =============================================================================

export class DataflowInvestigator {
  constructor() {
    this.name = 'DataflowInvestigator';
    this.description = 'Traces a finding\'s value back to its origin and files a cited claim';
  }

  /**
   * Investigate findings in place. Returns the same array so this composes with
   * the other passes in the orchestrator.
   */
  investigate(findings, { rootPath = process.cwd() } = {}) {
    const fileCache = new Map();

    for (const finding of findings) {
      if (!this._traceable(finding)) continue;

      const lines = this._read(finding.file, fileCache);
      if (!lines) continue;

      const trace = this._trace(finding, lines);
      if (!trace) continue;

      attachEvidence(finding, createClaim({
        source: 'dataflow',
        verdict: trace.verdict,
        rationale: trace.rationale,
        citations: trace.hops.map((hop) => ({
          file: path.resolve(rootPath, finding.file),
          line: hop.line,
          excerpt: hop.excerpt,
        })),
        attackPath: trace.hops.map((hop) => hop.text),
      }));
    }

    return findings;
  }

  _traceable(finding) {
    if (!finding.file || !finding.line) return false;
    if (!TRACEABLE_EXT.has(path.extname(finding.file).toLowerCase())) return false;
    return TAINT_CATEGORIES.has(finding.category);
  }

  _read(file, cache) {
    if (cache.has(file)) return cache.get(file);
    let lines;
    try {
      lines = fs.readFileSync(file, 'utf-8').split('\n');
    } catch { lines = null; }
    cache.set(file, lines);
    return lines;
  }

  // ── The trace ────────────────────────────────────────────────────────────

  _trace(finding, lines) {
    const sinkLine = lines[finding.line - 1];
    if (sinkLine === undefined) return null;

    const hops = [{
      line: finding.line,
      excerpt: sinkLine.trim().slice(0, 120),
      text: `value reaches ${finding.rule} here`,
    }];

    // A source written directly into the sink needs no walk.
    const direct = matchAny(UNTRUSTED_SOURCE, sinkLine);
    if (direct) {
      return {
        verdict: 'confirmed',
        rationale: `The value passed to the sink comes directly from ${direct.what}, with no intervening assignment to validate it.`,
        hops,
      };
    }

    const seeds = identifiersIn(sinkLine).slice(0, MAX_SEEDS);
    if (!seeds.length) return null;

    const traces = seeds.map((seed) => this._walk(seed, finding.line, lines, hops.slice(), 0));

    // One tainted input is enough to confirm: the sink receives a value the
    // caller shaped, whatever else it also receives.
    const tainted = traces.find((t) => t && t.verdict === 'confirmed');
    if (tainted) return tainted;

    // Refutation is the opposite — it requires *every* value reaching the sink
    // to be accounted for. Returning on the first safe seed is how a tracer
    // refutes `${coercedId} ... '${rawThreshold}'` by looking only at the half
    // that was coerced, which is a live injection reported as handled.
    const refuted = traces.filter((t) => t && t.verdict === 'refuted');
    if (refuted.length === seeds.length) {
      return {
        verdict: 'refuted',
        rationale: seeds.length === 1
          ? refuted[0].rationale
          : `Every value reaching the sink is accounted for: ${refuted.map((r) => r.rationale.replace(/\.$/, '')).join('; ')}.`,
        hops: dedupeHops(refuted.flatMap((r) => r.hops)),
      };
    }

    // Some input could not be resolved. Saying nothing is the only honest
    // outcome; a partial trace is not a mitigation.
    return null;
  }

  /** Walk one identifier backwards through the file. */
  _walk(name, fromLine, lines, hops, depth) {
    if (depth >= MAX_HOPS) return null;

    for (let i = fromLine - 2; i >= 0; i--) {
      const line = lines[i];
      const rhs = assignmentTo(name, line);
      if (rhs === null) continue;

      const hop = {
        line: i + 1,
        excerpt: line.trim().slice(0, 120),
        text: `${name} is assigned here`,
      };
      const path_ = [...hops, hop];

      const sanitizer = matchAny(SANITIZER, rhs);
      if (sanitizer) {
        return {
          verdict: 'refuted',
          rationale: `${name} is the result of ${sanitizer.what} on the path to the sink, so the value reaching it is not the caller's to shape.`,
          hops: path_,
        };
      }

      const source = matchAny(UNTRUSTED_SOURCE, rhs);
      if (source) {
        return {
          verdict: 'confirmed',
          rationale: `${name} is assigned from ${source.what} and reaches the sink without validation on that path.`,
          hops: path_,
        };
      }

      if (LITERAL.test(rhs)) {
        return {
          verdict: 'refuted',
          rationale: `${name} resolves to a literal written into the source, so no caller controls the value reaching the sink.`,
          hops: path_,
        };
      }

      // The value came from another identifier — keep walking that one.
      const next = identifiersIn(rhs).find((id) => id !== name);
      if (next) return this._walk(next, i + 1, lines, path_, depth + 1);

      return null;
    }

    // Not defined in this file. A parameter of the enclosing function is the
    // common case, and where it was called from is not knowable here.
    return null;
  }
}

// =============================================================================
// SYNTAX HELPERS
// =============================================================================

/** Merge hop lists from several seeds, keeping each line once and in order. */
function dedupeHops(hops) {
  const seen = new Set();
  return hops
    .filter((hop) => (seen.has(hop.line) ? false : seen.add(hop.line)))
    .sort((a, b) => a.line - b.line);
}

function matchAny(patterns, text) {
  return patterns.find((p) => p.re.test(text)) || null;
}

const KEYWORD = new Set([
  'const', 'let', 'var', 'function', 'return', 'await', 'async', 'new', 'typeof',
  'if', 'else', 'for', 'while', 'true', 'false', 'null', 'undefined', 'this',
  'try', 'catch', 'throw', 'class', 'extends', 'import', 'from', 'export', 'default',
]);

/**
 * Identifiers a line reads, in the order they matter.
 *
 * Order is the whole trick. In `db.raw(`SELECT ... ${userId}`)` the only
 * identifier worth walking is the one inside the interpolation; the words
 * SELECT and FROM are prose inside a string, and seeding from them wastes the
 * walk and returns nothing. So: interpolations first, then call arguments, and
 * string contents never.
 */
function identifiersIn(line) {
  const body = line.replace(/^\s*(?:const|let|var)\s+[\w{}[\],\s:]+=\s*/, '');

  const interpolated = [...body.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]).join(' ');
  const scope = interpolated || stripStrings(body);

  const names = [];
  for (const match of scope.matchAll(/\b([A-Za-z_$][\w$]*)\b(?!\s*\()/g)) {
    const name = match[1];
    if (KEYWORD.has(name) || names.includes(name)) continue;
    names.push(name);
  }
  return names;
}

/** Remove quoted text so words inside a message are never mistaken for values. */
function stripStrings(text) {
  return text
    .replace(/'[^']*'/g, "''")
    .replace(/"[^"]*"/g, '""')
    .replace(/`(?:[^`$]|\$(?!\{))*`/g, '``');
}

/**
 * The right-hand side if this line assigns to `name`, otherwise null.
 * Handles declarations, bare reassignment, and object destructuring.
 */
function assignmentTo(name, line) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const declaration = line.match(new RegExp(`(?:const|let|var)\\s+${escaped}\\s*(?::[^=]+)?=\\s*(.+?);?\\s*$`));
  if (declaration) return declaration[1];

  const reassignment = line.match(new RegExp(`^\\s*${escaped}\\s*=\\s*(.+?);?\\s*$`));
  if (reassignment) return reassignment[1];

  // const { name } = expr  /  const { other: name } = expr
  const destructured = line.match(new RegExp(`(?:const|let|var)\\s*\\{[^}]*\\b${escaped}\\b[^}]*\\}\\s*=\\s*(.+?);?\\s*$`));
  if (destructured) return destructured[1];

  return null;
}
