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

      // Downgrade unverified findings one confidence level
      if (!result.verified) {
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

    if (isStatic && !hasUserInput) {
      return {
        verified: false,
        note: 'Value appears to be static/hardcoded, not user-controlled',
      };
    }

    if (hasSanitization) {
      return {
        verified: false,
        note: 'Sanitization or validation detected upstream of finding',
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
        verified: false,
        note: 'Finding is inside error handling context, reducing exploitability',
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
    // Check the 5 lines before the finding for return/throw
    for (let i = Math.max(0, lineNum - 6); i < lineNum - 1; i++) {
      const l = lines[i]?.trim() || '';
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
