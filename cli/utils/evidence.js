/**
 * Evidence — the record of why a finding is believed
 * ===================================================
 *
 * A detector says "this line looks like SSRF". That is a claim, not a verdict.
 * Everything that runs afterwards — the heuristic verifier, LLM taint analysis,
 * an attack-chain pass, a sandboxed reproduction — produces another claim about
 * the same finding, and those claims disagree constantly.
 *
 * Before this module each pass expressed itself differently: VerifierAgent set
 * `finding.verified`, DeepAnalyzer set `finding.deepAnalysis`, and both quietly
 * mutated `finding.confidence`. Nothing recorded *who* concluded what, on what
 * basis, or which pass won when they conflicted.
 *
 * Evidence makes that explicit. Each pass appends a claim carrying its source,
 * its verdict, its rationale, and citations into real code. The finding's
 * verdict is then *derived* from the claims by fixed precedence — never written
 * directly — so the same claim set always resolves the same way, and a report
 * can show the reasoning instead of just the conclusion.
 *
 * USAGE:
 *   import { attachEvidence, createClaim, validateCitations } from './evidence.js';
 *
 *   const claim = createClaim({
 *     source: 'dataflow',
 *     verdict: 'confirmed',
 *     rationale: 'req.query.url reaches fetch() with no host validation',
 *     citations: [{ file: 'src/hooks.js', line: 12 }, { file: 'src/hooks.js', line: 40 }],
 *   });
 *   validateCitations(claim, { rootPath });
 *   attachEvidence(finding, claim);   // finding.evidence.verdict === 'confirmed'
 */

import fs from 'fs';
import path from 'path';

// =============================================================================
// VOCABULARY
// =============================================================================

/**
 * What a pass concluded about the finding.
 *
 *   'confirmed' — an attack path was traced end to end, or reproduced.
 *   'likely'    — the path is plausible and no mitigating control was found.
 *   'unknown'   — not enough was established either way. The honest default.
 *   'refuted'   — a mitigating control or unreachable path was actually found.
 */
export const VERDICTS = Object.freeze(['confirmed', 'likely', 'unknown', 'refuted']);

/**
 * Who produced a claim, ranked by how much the evidence is worth.
 *
 * Rank decides which pass wins a disagreement. Executing an exploit beats
 * tracing data flow, which beats a model's reading of one file, which beats a
 * regex looking for the word "sanitize" nearby. A cheaper pass never overturns
 * a more expensive one — that ordering is the whole point of the ranking.
 */
export const CLAIM_SOURCES = Object.freeze({
  detector:      0,   // the deterministic rule that raised the finding
  heuristic:     0,   // pattern-based second pass (VerifierAgent)
  analysis:      1,   // LLM reading of the finding and its file (DeepAnalyzer)
  dataflow:      2,   // traced source→sink path across the code graph
  chain:         2,   // cross-agent capability/attack-chain construction
  reproduction:  3,   // executed in a sandbox and observed
});

const VERDICT_SET = new Set(VERDICTS);

/** Citation states. A claim is usable unless its citations were checked and failed. */
export const CITATION_STATUS = Object.freeze(['unchecked', 'valid', 'invalid']);

// =============================================================================
// CLAIMS
// =============================================================================

/**
 * Build one claim. Throws on an unknown source or verdict rather than silently
 * accepting it: a typo'd source would otherwise rank 0 and lose every conflict
 * it should have won.
 */
export function createClaim({
  source,
  verdict,
  rationale = '',
  citations = [],
  attackPath = [],
  reproduction = null,
  cost = null,
  at = new Date().toISOString(),
}) {
  if (!(source in CLAIM_SOURCES)) {
    throw new TypeError(`Unknown evidence source: ${source}. Expected one of ${Object.keys(CLAIM_SOURCES).join(', ')}`);
  }
  if (!VERDICT_SET.has(verdict)) {
    throw new TypeError(`Unknown verdict: ${verdict}. Expected one of ${VERDICTS.join(', ')}`);
  }

  return {
    source,
    verdict,
    rationale: String(rationale || ''),
    citations: (Array.isArray(citations) ? citations : []).map(normalizeCitation).filter(Boolean),
    attackPath: Array.isArray(attackPath) ? attackPath.map((step) => String(step)) : [],
    reproduction,
    cost,
    citationStatus: 'unchecked',
    at,
  };
}

function normalizeCitation(citation) {
  if (!citation || !citation.file) return null;
  const line = Number(citation.line) || 0;
  return {
    file: String(citation.file),
    line,
    endLine: Number(citation.endLine) || line,
    ...(citation.excerpt ? { excerpt: String(citation.excerpt) } : {}),
  };
}

// =============================================================================
// CITATION VALIDATION
// =============================================================================

/**
 * Check that a claim's citations point at code that exists.
 *
 * A model asked to justify a verdict will produce a fluent rationale whether or
 * not it read anything, and an invented `auth.js:88` reads exactly like a real
 * one. Resolving every citation against the filesystem is the cheapest way to
 * tell the two apart, so an unresolvable citation invalidates the claim and
 * `resolveVerdict` then ignores it entirely.
 *
 * When a citation carries an excerpt, the excerpt must also appear in the lines
 * it names — that catches a real file cited for a line it does not contain.
 *
 * @returns {{status: string, invalid: object[]}}
 */
export function validateCitations(claim, { rootPath = process.cwd() } = {}) {
  if (!claim) return { status: 'unchecked', invalid: [] };

  // A claim citing nothing is not disproven, only unsupported. Ranking already
  // keeps such a claim from outweighing one that did the work.
  if (!claim.citations.length) {
    claim.citationStatus = 'unchecked';
    return { status: 'unchecked', invalid: [] };
  }

  const invalid = [];

  for (const citation of claim.citations) {
    const absolute = path.isAbsolute(citation.file)
      ? citation.file
      : path.resolve(rootPath, citation.file);

    let lines;
    try {
      lines = fs.readFileSync(absolute, 'utf-8').split('\n');
    } catch {
      invalid.push({ ...citation, reason: 'file not found' });
      continue;
    }

    if (citation.line < 1 || citation.line > lines.length) {
      invalid.push({ ...citation, reason: `line ${citation.line} outside file (${lines.length} lines)` });
      continue;
    }

    if (citation.excerpt) {
      const span = lines.slice(citation.line - 1, Math.max(citation.line, citation.endLine)).join('\n');
      if (!normalizeWhitespace(span).includes(normalizeWhitespace(citation.excerpt))) {
        invalid.push({ ...citation, reason: 'excerpt not present at cited line' });
      }
    }
  }

  claim.citationStatus = invalid.length ? 'invalid' : 'valid';
  if (invalid.length) claim.invalidCitations = invalid;

  return { status: claim.citationStatus, invalid };
}

function normalizeWhitespace(value) {
  return String(value).replace(/\s+/g, ' ').trim();
}

// =============================================================================
// EVIDENCE CONTAINER
// =============================================================================

/** The container every finding carries from birth, so no pass has to create one. */
export function emptyEvidence() {
  return { verdict: 'unknown', claims: [], conflict: false };
}

/**
 * Append a claim and re-derive the verdict.
 *
 * Mutates and returns the finding — passes run over large arrays in place, and
 * copying every finding to record one claim would be wasteful and would lose
 * the mutations later passes expect to see.
 */
export function attachEvidence(finding, claim) {
  if (!finding || !claim) return finding;

  if (!finding.evidence || !Array.isArray(finding.evidence.claims)) {
    finding.evidence = emptyEvidence();
  }

  finding.evidence.claims.push(claim);
  const resolved = resolveVerdict(finding.evidence);
  finding.evidence.verdict = resolved.verdict;
  finding.evidence.conflict = resolved.conflict;
  finding.evidence.decidedBy = resolved.decidedBy;

  // `evidenceLevel` predates this module and feeds scoring and report snapshots.
  // Only the two verdicts that settle the question move it; 'likely' and
  // 'unknown' leave the detector's own assessment standing.
  if (resolved.verdict === 'confirmed') finding.evidenceLevel = 'strong';
  else if (resolved.verdict === 'refuted') finding.evidenceLevel = 'advisory';

  return finding;
}

/**
 * Derive a verdict from a claim set.
 *
 * Highest-ranked usable claims win. If claims at that rank disagree, the result
 * is 'unknown' with `conflict` set — a contradiction between two passes of equal
 * standing is a real absence of knowledge, and picking the scarier of the two
 * would be the kind of unearned certainty this whole structure exists to avoid.
 */
export function resolveVerdict(evidence) {
  const claims = (evidence?.claims || []).filter((c) => c && c.citationStatus !== 'invalid');
  if (!claims.length) return { verdict: 'unknown', conflict: false, decidedBy: null };

  const topRank = Math.max(...claims.map((c) => CLAIM_SOURCES[c.source] ?? 0));
  const deciding = claims.filter((c) => (CLAIM_SOURCES[c.source] ?? 0) === topRank);
  const verdicts = new Set(deciding.map((c) => c.verdict));

  if (verdicts.size === 1) {
    return {
      verdict: deciding[deciding.length - 1].verdict,
      conflict: false,
      decidedBy: [...new Set(deciding.map((c) => c.source))],
    };
  }

  // 'unknown' alongside a substantive verdict is not a disagreement — a pass
  // that established nothing should not cancel out one that did.
  const substantive = new Set([...verdicts].filter((v) => v !== 'unknown'));
  if (substantive.size === 1) {
    const [verdict] = [...substantive];
    return {
      verdict,
      conflict: false,
      decidedBy: [...new Set(deciding.filter((c) => c.verdict === verdict).map((c) => c.source))],
    };
  }

  return { verdict: 'unknown', conflict: true, decidedBy: [...new Set(deciding.map((c) => c.source))] };
}

// =============================================================================
// READING EVIDENCE
// =============================================================================

/** True once some pass has actually said something about this finding. */
export function hasEvidence(finding) {
  return Boolean(finding?.evidence?.claims?.length);
}

/** The claim that decided the verdict, for reports that show one line of why. */
export function decidingClaim(finding) {
  const claims = (finding?.evidence?.claims || []).filter((c) => c && c.citationStatus !== 'invalid');
  if (!claims.length) return null;
  const topRank = Math.max(...claims.map((c) => CLAIM_SOURCES[c.source] ?? 0));
  const deciding = claims.filter((c) => (CLAIM_SOURCES[c.source] ?? 0) === topRank);
  return deciding[deciding.length - 1] || null;
}

/**
 * Compact, serializable view for machine reports. Rationales are authored by
 * this tool's own passes, but citations carry workstation paths, so they are
 * emitted relative to the scan root the same way finding snapshots are.
 */
export function summarizeEvidence(finding, rootPath = process.cwd()) {
  const evidence = finding?.evidence;
  if (!evidence) return null;

  return {
    verdict: evidence.verdict || 'unknown',
    conflict: Boolean(evidence.conflict),
    decidedBy: evidence.decidedBy || null,
    claims: (evidence.claims || []).map((claim) => ({
      source: claim.source,
      verdict: claim.verdict,
      rationale: claim.rationale,
      citationStatus: claim.citationStatus,
      citations: claim.citations.map((c) => ({
        file: path.isAbsolute(c.file) ? path.relative(rootPath, c.file).replace(/\\/g, '/') : c.file,
        line: c.line,
        ...(c.endLine !== c.line ? { endLine: c.endLine } : {}),
      })),
      ...(claim.attackPath.length ? { attackPath: claim.attackPath } : {}),
      ...(claim.reproduction ? { reproduction: claim.reproduction } : {}),
    })),
  };
}
