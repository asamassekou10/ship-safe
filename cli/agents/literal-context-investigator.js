/**
 * LiteralContextInvestigator — is this literal a problem here?
 * =============================================================
 *
 * A third kind of question, after "where did this value come from" and "is the
 * control missing". Some rules fire on a value written into the source: an
 * internal IP address, an email, a private range. The value is exactly what the
 * rule says it is, and the finding is still usually noise, because the answer
 * depends on what surrounds it.
 *
 * On hermes-agent this was the single largest unresolved group — 96
 * SSRF_INTERNAL_IP findings, and the four sampled were, in order: a loopback
 * default for a local model server, a loopback default constant, a help string
 * reading "(default: http://127.0.0.1:1933)", and a prompt reading "(e.g.
 * http://192.168.1.10:1234)". None is a request an attacker can redirect.
 *
 * Three questions settle most of them, none needing a model:
 *
 *   Is the line prose? An address in a docstring is documented, not contacted.
 *   Is the string meant for a person? A help string describes an address.
 *   Is the value reserved for exactly this? Loopback, the RFC 5737 ranges, and
 *     example.com exist so that documentation has something safe to say.
 *
 * When none of them holds the pass files nothing. It is a noise reducer, and
 * inventing a verdict for the remainder would be the same over-claim it exists
 * to remove.
 */

import fs from 'fs';
import { attachEvidence, createClaim } from '../utils/evidence.js';
import { commentMask, isHumanReadableString } from '../utils/source-context.js';

// =============================================================================
// WHAT COUNTS AS RESERVED
// =============================================================================

/** Addresses that exist so documentation and local development have one. */
const RESERVED_ADDRESS = [
  { re: /\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\blocalhost\b|\[?::1\]?/i,
    what: 'loopback, which is this machine talking to itself rather than a request an attacker can redirect' },
  { re: /\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/,
    what: 'an RFC 5737 documentation range, reserved so examples have an address that routes nowhere' },
  { re: /\b0\.0\.0\.0\b/,
    what: 'the unspecified address, which is a bind target rather than a destination' },
];

/** Addresses reserved so examples never name a real person. */
const RESERVED_EMAIL = [
  { re: /@(?:example|test|invalid|localhost)\.(?:com|net|org|test|invalid|localhost)\b|@example\b/i,
    what: 'an RFC 2606 reserved domain, which cannot belong to anyone' },
  { re: /\b(?:no-?reply|do-?not-?reply|noreply|postmaster|abuse|webmaster|admin|support|info)@/i,
    what: 'a role address rather than a person' },
  { re: /\b\w+@(?:s\.whatsapp\.net|g\.us|lid)\b/i,
    what: 'a platform identifier rather than an email address' },
];

/**
 * Rules whose subject is code that executes. A match on a comment line is a
 * description of the vulnerability, not the vulnerability — a doc comment
 * reading `eval(req.body.x)` produced three critical findings in this project's
 * own repository.
 *
 * Named explicitly rather than derived from a category. Some rules read prose on
 * purpose: an instruction in a CLAUDE.md telling an agent to run something is
 * the finding, and refuting it because it sits in a document would delete the
 * whole trust-boundary class.
 */
const EXECUTION_RULE = /^(?:CODE_INJECTION|SQL_INJECTION|NOSQL_INJECTION|CMD_INJECTION|XSS_|SSRF_USER|PATH_TRAVERSAL|VIBE_EVAL|PYTHON_SQL|TEMPLATE_INJECTION|LDAP_INJECTION|PROTOTYPE_POLLUTION)/;

/**
 * Categories where a comment cannot be the vulnerability, so a match on one is
 * a description of the problem rather than the problem.
 *
 * Secrets and compliance are deliberately absent: a key or an SSN written in a
 * comment has leaked exactly as thoroughly as one written in code.
 */
const PROSE_REFUTABLE_CATEGORY = new Set(['vulnerability', 'injection', 'api', 'auth', 'agentic', 'llm', 'quality']);

/**
 * Files an agent reads as content rather than compiles. Prose in a document is
 * not a comment about code — it is the thing the agent acts on, and a rule
 * pointing at it is describing a real trust boundary.
 */
const AGENT_READABLE = /\.(?:md|mdx|markdown|txt|rst)$|(?:^|[/\\])(?:\.cursorrules|\.windsurfrules|\.clinerules)$/i;

const LITERAL_RULES = {
  SSRF_INTERNAL_IP:    { what: 'an internal address', reserved: RESERVED_ADDRESS },
  PII_EMAIL_HARDCODED: { what: 'an email address',    reserved: RESERVED_EMAIL },
};

// =============================================================================
// PASS
// =============================================================================

export class LiteralContextInvestigator {
  constructor() {
    this.name = 'LiteralContextInvestigator';
    this.description = 'Decides findings about a written-in value by what surrounds it';
  }

  investigate(findings, { rootPath = process.cwd() } = {}) {
    const cache = new Map();

    for (const finding of findings) {
      if (!finding.file || !finding.line) continue;

      const spec = LITERAL_RULES[finding.rule];
      const proseRefutable = EXECUTION_RULE.test(finding.rule)
        || (PROSE_REFUTABLE_CATEGORY.has(finding.category) && !AGENT_READABLE.test(finding.file));
      if (!spec && !proseRefutable) continue;

      const lines = this._read(finding.file, cache);
      if (!lines || finding.line > lines.length) continue;

      const line = lines[finding.line - 1];
      const claim = spec
        ? this._classify(finding, spec, lines, line)
        : this._classifyProse(finding, lines);
      if (claim) attachEvidence(finding, claim);
    }

    return findings;
  }

  _classify(finding, spec, lines, line) {
    const cite = [{ file: finding.file, line: finding.line }];

    const mask = commentMask(lines, { upto: finding.line, file: finding.file });
    if (mask[finding.line - 1]) {
      return createClaim({
        source: 'presence',
        verdict: 'refuted',
        rationale: `The line is a comment or docstring, so ${spec.what} here is being documented rather than used.`,
        citations: cite,
      });
    }

    if (isHumanReadableString(line)) {
      return createClaim({
        source: 'presence',
        verdict: 'refuted',
        rationale: `${capitalize(spec.what)} appears inside a message written for a person — a help string, prompt, or example — which describes an address rather than contacting one.`,
        citations: cite,
      });
    }

    const reserved = spec.reserved.find((entry) => entry.re.test(line));
    if (reserved) {
      return createClaim({
        source: 'presence',
        verdict: 'refuted',
        rationale: `The value is ${reserved.what}.`,
        citations: cite,
      });
    }

    // Not prose, not documentation, not reserved. That is worth knowing and it
    // is not a conclusion: whether a real internal address in real code is
    // reachable is a question this pass cannot answer, and answering it anyway
    // is the failure it was built to remove.
    return null;
  }

  /** For a rule about code, only one question applies: does this line run? */
  _classifyProse(finding, lines) {
    const mask = commentMask(lines, { upto: finding.line, file: finding.file });
    if (!mask[finding.line - 1]) return null;

    return createClaim({
      source: 'presence',
      verdict: 'refuted',
      rationale: 'The line is a comment or docstring. Whatever it describes is not code that runs, so there is nothing here to exploit.',
      citations: [{ file: finding.file, line: finding.line }],
    });
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
}

function capitalize(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
