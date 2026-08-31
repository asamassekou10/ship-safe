/**
 * VerifierAgent — Second-Pass Finding Confirmation
 * ==================================================
 *
 * Runs after all agents complete. Takes high-confidence findings
 * and attempts to confirm or downgrade them by analyzing surrounding
 * code context.
 *
 * Checks:
 *   - Is the flagged value static/hardcoded or dynamic (from user input)?
 *   - Is there upstream sanitization or validation?
 *   - Is the code inside error handling that neutralizes it?
 *   - Is the finding in dead/unreachable code?
 *
 * Impact: Unverified findings get downgraded one confidence level.
 */

import fs from 'fs';
import path from 'path';
import { attachEvidence, createClaim } from '../utils/evidence.js';

// =============================================================================
// HEURISTIC PATTERNS
// =============================================================================

/** Sources of user input — if a finding's matched code references these, it's more likely real */
const USER_INPUT_SOURCES = [
  /req\.body/,
  /req\.query/,
  /req\.params/,
  /req\.headers/,
  /request\.body/,
  /request\.query/,
  /request\.params/,
  /request\.form/,
  /request\.args/,
  /request\.json/,
  /ctx\.request/,
  /ctx\.query/,
  /ctx\.params/,
  /event\.body/,
  /event\.queryStringParameters/,
  /searchParams/,
  /formData/,
  /userinput/i,
  /user_input/i,
  /input\s*\(/,
  /argv/,
  /process\.env/,
  /getenv/,
];

/** Sanitization/validation indicators — presence near a finding suggests it's protected */
const SANITIZATION_PATTERNS = [
  /sanitize/i,
  /validate/i,
  /escape/i,
  /purify/i,
  /DOMPurify/,
  /xss\s*\(/i,
  /htmlencode/i,
  /encodeURI/,
  /encodeURIComponent/,
  /parameterized/i,
  /prepared\s*statement/i,
  /placeholder/i,
  /\?\s*,/,
  /\$\d+/,
  /bindParam/i,
  /bindValue/i,
  /zod/i,
  /yup/i,
  /joi\./i,
  /ajv/i,
  /schema\.parse/i,
  /safeParse/i,
  /validator\./i,
  /parseInt\s*\(/,
  /parseFloat\s*\(/,
  /Number\s*\(/,
  /\.trim\s*\(/,
  /\.replace\s*\(/,
  /allowlist/i,
  /whitelist/i,
  /blocklist/i,
  /blacklist/i,
];

/** Error handling wrappers — findings inside these are less exploitable */
const ERROR_HANDLING_PATTERNS = [
  /}\s*catch\s*\(/,
  /\.catch\s*\(/,
  /try\s*\{/,
  /if\s*\(\s*err/,
  /on\s*\(\s*['"]error['"]/,
  /\.on\s*\(\s*['"]error['"]/,
];

/** Static/hardcoded value indicators — finding uses a constant, not user input */
const STATIC_VALUE_PATTERNS = [
  /['"][^'"]{0,200}['"]/,
  /const\s+\w+\s*=\s*['"][^'"]*['"]/,
  /^\s*\/\//,
  /^\s*\*/,
  /^\s*#/,
  /TODO|FIXME|HACK|NOTE/,
];

/** Dead code indicators */
const DEAD_CODE_PATTERNS = [
  /return\s+/,
  /throw\s+/,
  /process\.exit/,
  /^\s*\/\//,
];

// =============================================================================
// VERIFIER AGENT
// =============================================================================

/**
 * Which of the first `upto` lines sit inside a comment.
 *
 * Line prefixes are not enough: a block comment wrapping real-looking code
 * leaves the inner lines bare, which is exactly the shape of a commented-out
 * fix sitting above the bug it was meant to replace.
 *
 * String literals are not tracked, so a `/*` inside a quoted string would start
 * a phantom block. That direction is safe — it marks more lines as commented,
 * which makes this pass abstain rather than refute.
 */
function commentMask(lines, upto = lines.length) {
  const mask = new Array(Math.min(upto, lines.length)).fill(false);
  let inBlock = false;

  for (let i = 0; i < mask.length; i++) {
    const line = lines[i] || '';
    const trimmed = line.trim();

    if (inBlock) {
      mask[i] = true;
      if (line.includes('*/')) inBlock = false;
      continue;
    }

    if (trimmed.startsWith('//') || trimmed.startsWith('#')) { mask[i] = true; continue; }

    const open = line.indexOf('/*');
    if (open !== -1 && !line.includes('*/', open)) {
      inBlock = true;
      // The opener line may hold code before the comment starts, so it is only
      // fully commented when nothing precedes it.
      mask[i] = line.slice(0, open).trim() === '';
    }
  }

  return mask;
}

/** True when a line opens more brackets than it closes. */
function unclosed(line) {
  let depth = 0;
  for (const char of line) {
    if (char === '(' || char === '[' || char === '{') depth += 1;
    else if (char === ')' || char === ']' || char === '}') depth -= 1;
  }
  return depth > 0;
}

export class VerifierAgent {
  constructor() {
    this.name = 'VerifierAgent';
    this.description = 'Second-pass verification of findings';
  }

  /**
   * Verify an array of findings by analyzing surrounding code context.
   * Returns findings with added `verified` and `verifierNote` fields.
   *
   * @param {object[]} findings — Findings from all agents (post-dedup)
   * @param {object}   options  — { verbose }
   * @returns {object[]} — Findings with verification metadata
   */
  verify(findings, options = {}) {
    const fileCache = new Map();

    for (const finding of findings) {
      // Only verify critical and high severity findings
      if (finding.severity !== 'critical' && finding.severity !== 'high') {
        finding.verified = null; // not checked
        continue;
      }

      const result = this._verifyFinding(finding, fileCache);
      finding.verified = result.verified;
      finding.verifierNote = result.note;

      // Record the reasoning as a claim. This pass is regex over a window of
      // lines, so it ranks lowest and never states more than 'likely' — a
      // later data-flow or reproduction pass overturns it without argument.
      attachEvidence(finding, createClaim({
        source: 'heuristic',
        verdict: result.verified === true ? 'likely'
               : result.verified === false ? 'refuted'
               : 'unknown',
        rationale: result.note,
        citations: finding.file && finding.line
          ? [{ file: finding.file, line: finding.line }]
          : [],
      }));

      // Only a conclusive negative may lower confidence. `null` means the
      // generic verifier lacks enough evidence and must preserve the detector's
      // original assessment.
      if (result.verified === false) {
        if (finding.confidence === 'high') finding.confidence = 'medium';
        else if (finding.confidence === 'medium') finding.confidence = 'low';
      }
    }

    return findings;
  }

  /**
   * Verify a single finding by reading surrounding code.
   */
  _verifyFinding(finding, fileCache) {
    const { file, line, matched } = finding;
    if (!file || !line) {
      return { verified: null, note: 'Missing file or line info' };
    }

    // Read the file (cached)
    let lines;
    if (fileCache.has(file)) {
      lines = fileCache.get(file);
    } else {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        lines = content.split('\n');
        fileCache.set(file, lines);
      } catch {
        return { verified: null, note: 'Could not read file' };
      }
    }

    // Get a 30-line window around the finding (15 before, 15 after)
    const windowStart = Math.max(0, line - 16);
    const windowEnd = Math.min(lines.length, line + 15);
    const window = lines.slice(windowStart, windowEnd);
    const windowText = window.join('\n');

    // Get lines BEFORE the finding (for upstream checks)
    const beforeStart = Math.max(0, line - 16);
    const beforeEnd = Math.max(0, line - 1);
    const beforeText = lines.slice(beforeStart, beforeEnd).join('\n');

    // Get the finding line itself
    const findingLine = lines[line - 1] || '';

    // ── Check 1: Is user input involved? ──────────────────────────
    const hasUserInput = USER_INPUT_SOURCES.some(p => p.test(windowText));

    // ── Check 2: Is there sanitization/validation upstream? ───────
    const hasSanitization = SANITIZATION_PATTERNS.some(p => p.test(beforeText));

    // ── Check 3: Is the value static/hardcoded? ───────────────────
    const isStatic = this._isStaticValue(findingLine, matched);

    // ── Check 4: Is it inside error handling? ─────────────────────
    const inErrorHandler = ERROR_HANDLING_PATTERNS.some(p => p.test(beforeText));

    // ── Check 5: Is it in dead/unreachable code? ──────────────────
    const isDeadCode = this._isDeadCode(lines, line);

    // ── Decision logic ────────────────────────────────────────────
    if (isDeadCode) {
      return {
        verified: false,
        note: 'Finding appears to be in unreachable code (after return/throw)',
      };
    }

    // A hardcoded secret is confirmed by being static; staticness is not a
    // mitigation for supply-chain, configuration, or access-control rules.
    if (['secret', 'secrets', 'history'].includes(finding.category) && isStatic) {
      return {
        verified: true,
        note: 'Hardcoded secret evidence is static by definition',
      };
    }

    if (hasSanitization) {
      return {
        verified: null,
        note: 'Nearby validation was found, but its data flow to this sink is unproven',
      };
    }

    if (hasUserInput && !hasSanitization) {
      return {
        verified: true,
        note: 'User input flows to this sink without visible sanitization',
      };
    }

    if (inErrorHandler) {
      return {
        verified: null,
        note: 'Error handling is present but does not prove the unsafe operation is neutralized',
      };
    }

    if (isStatic) {
      return {
        verified: null,
        note: 'Static input lowers immediate exploitability but does not disprove the rule',
      };
    }

    // Default: cannot determine, keep as-is
    return {
      verified: null,
      note: 'Could not determine verification status from code context',
    };
  }

  /**
   * Check if the matched code is using a static/hardcoded value.
   */
  _isStaticValue(line, matched) {
    // If the finding line is a comment, it's static
    if (/^\s*(?:\/\/|#|\*|\/\*)/.test(line)) return true;

    // If the matched text is just a string literal with no interpolation
    if (/^['"][^'"]*['"]$/.test(matched)) return true;

    // If the line is a const assignment to a string literal
    if (/const\s+\w+\s*=\s*['"][^'"]*['"]/.test(line)) return true;

    // If it looks like a TODO/placeholder comment
    if (/TODO|FIXME|EXAMPLE|PLACEHOLDER|SAMPLE/i.test(line)) return true;

    return false;
  }

  /**
   * Check if a line is after a return/throw (dead code).
   */
  _isDeadCode(lines, lineNum) {
    const commented = commentMask(lines, lineNum);

    // Check the 5 lines before the finding for return/throw
    for (let i = Math.max(0, lineNum - 6); i < lineNum - 1; i++) {
      const l = lines[i]?.trim() || '';
      // A `throw` inside a commented-out block is not a `throw`. Reading one as
      // real makes the live code after it look unreachable, and this pass then
      // refutes a finding that is genuinely exploitable — the one error class
      // that loses a vulnerability silently. Observed on NodeGoat's
      // allocations-dao.js, where a commented-out fix sits directly above the
      // live NoSQL injection it was meant to replace.
      if (commented[i]) continue;

      // A `return {` or `throw new Error(` that has not closed its brackets is
      // the opening of a multi-line statement, and a finding below it is inside
      // that statement rather than stranded after it. Counting it as preceding
      // dead code refutes the very line it belongs to.
      if (unclosed(l)) continue;
      // If a return/throw is found and there's no conditional/block opener after
      if (/^(?:return\s|throw\s|process\.exit)/.test(l)) {
        // Check if there's a } or else between the return and our line
        const between = lines.slice(i + 1, lineNum - 1).join('\n');
        if (!/[{}]|else|case/.test(between)) {
          return true;
        }
      }
    }
    return false;
  }
}

export default VerifierAgent;
