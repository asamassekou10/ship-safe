/**
 * BaseAgent — Foundation for all security scanning agents
 * ========================================================
 *
 * Every agent in ship-safe extends BaseAgent. It provides:
 *   - Standard finding format
 *   - File discovery with skip-list support
 *   - Severity classification
 *   - Consistent output interface
 *
 * USAGE:
 *   class MyAgent extends BaseAgent {
 *     constructor() { super('MyAgent', 'Description', 'category'); }
 *     async analyze(context) { return [findings]; }
 *   }
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import { SKIP_DIRS, SKIP_EXTENSIONS, SKIP_FILENAMES, MAX_FILE_SIZE, loadGitignorePatterns } from '../utils/patterns.js';
import { emptyEvidence } from '../utils/evidence.js';

const DOC_EXTENSIONS = new Set(['.md', '.mdx', '.txt', '.rst', '.adoc', '.rdoc']);

/**
 * Classify where code lives without changing the existing project/environment
 * meaning of `scope`. Unknown paths stay in posture scoring for compatibility.
 */
export function inferCodeScope(file = '') {
  const normalized = String(file).replace(/\\/g, '/').toLowerCase();
  const ext = path.extname(normalized);

  if (DOC_EXTENSIONS.has(ext) || /(?:^|\/)docs?(?:\/|$)/.test(normalized)) return 'docs';
  if (/(?:^|\/)(?:fixtures?|testdata|malicious-fixtures?|examples?|samples?|demos?|mocks?)(?:\/|$)/.test(normalized)) return 'fixture';
  if (/(?:^|\/)benchmarks?(?:\/|$)/.test(normalized)) return 'benchmark';
  if (/(?:^|\/)(?:__tests__|tests?|spec)(?:\/|$)|\.(?:test|spec)\.[^./]+$/.test(normalized)) return 'test';
  if (/(?:^|\/)(?:dist|build|coverage|generated)(?:\/|$)|\.(?:min\.js|map)$/.test(normalized)) return 'generated';
  return normalized ? 'production' : 'unknown';
}

/**
 * Re-derive every finding's code scope against the root actually being scanned.
 *
 * `inferCodeScope` classifies a path, and at the moment a finding is created the
 * only path available is absolute. That asks the wrong question: not "is this
 * file a test within its project" but "does anything in this machine's
 * directory structure look like a test". A repository checked out at
 * ~/projects/test/myapp had every finding classified as test code and dropped
 * from its own score, reporting 100/100 while holding real findings.
 *
 * Scope is therefore settled once, centrally, where the scan root is known.
 */
export function resolveCodeScopes(findings, rootPath) {
  if (!rootPath) return findings;

  for (const finding of findings) {
    if (!finding?.file) continue;
    const relative = path.relative(rootPath, finding.file);
    // A finding outside the scanned tree keeps whatever it was born with:
    // there is no project-relative path to judge it by.
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) continue;
    finding.codeScope = inferCodeScope(relative);
  }

  return findings;
}

export function evidenceLevelForConfidence(confidence = 'high') {
  if (confidence === 'high') return 'strong';
  if (confidence === 'medium') return 'heuristic';
  return 'advisory';
}

/** Add score-contract metadata to findings from legacy and plugin detectors. */
export function normalizeFindingMetadata(finding) {
  const confidence = finding.deterministicConfidence || finding.confidence || 'high';
  return {
    ...finding,
    codeScope: finding.codeScope || inferCodeScope(finding.file),
    evidenceLevel: finding.evidenceLevel || evidenceLevelForConfidence(confidence),
    reachability: finding.reachability || 'unknown',
    exposure: finding.exposure || 'unknown',
    evidence: finding.evidence || emptyEvidence(),
  };
}

// =============================================================================
// FINDING FACTORY
// =============================================================================

/**
 * Create a standardized finding object.
 *
 * `scope` separates what a finding is about:
 *
 *   'project'     — something in the scanned repository. The default.
 *   'environment' — something about the machine running the scan, such as a
 *                   globally configured MCP server. Useful to a developer
 *                   locally, meaningless to a pipeline, and never safe to put
 *                   in machine output: the names of someone's personal agent
 *                   servers should not end up in a repository's security tab.
 *
 * Environment findings are kept out of the score, out of --json/--sarif/--csv,
 * and out of `ci` unless explicitly requested. Making that a property of the
 * finding rather than a special case in one agent means the next environment
 * check inherits the handling instead of repeating the bug.
 */
export function createFinding({
  file,
  line = 0,
  column = 0,
  severity = 'medium',
  category = 'vulnerability',
  rule,
  title,
  description,
  matched = '',
  confidence = 'high',
  cwe = null,
  owasp = null,
  fix = null,
  scope = 'project',
  codeScope = inferCodeScope(file),
  evidenceLevel = evidenceLevelForConfidence(confidence),
  reachability = 'unknown',
  exposure = 'unknown',
  evidence = emptyEvidence(),
}) {
  return {
    file,
    line,
    column,
    severity,
    category,
    rule,
    title,
    description,
    matched,
    confidence,
    cwe,
    owasp,
    fix,
    scope,
    codeScope,
    evidenceLevel,
    reachability,
    exposure,
    // Every finding carries an evidence container from birth so no later pass
    // has to test for its absence before recording what it concluded.
    evidence,
  };
}

// =============================================================================
// LANGUAGE RESOLUTION
// =============================================================================

/**
 * Map a file extension to the language a rule can be written against.
 *
 * Rules are overwhelmingly shaped by one language's syntax, but agents scan
 * several. 9.6.4 fixed an Express file-upload rule that matched the substring
 * `path.join(` inside Python's `os.path.join(self.root_path, filename)` and
 * reported critical on Flask's own config loader. That was not a bad regex so
 * much as a missing abstraction: nothing let the rule say which language it
 * described.
 *
 * A pattern declares `langs: ['js']` and stops being applied to Ruby. Anything
 * without the field keeps running everywhere, so this is additive.
 */
const EXT_LANGUAGE = {
  '.js': 'js', '.jsx': 'js', '.mjs': 'js', '.cjs': 'js',
  '.ts': 'js', '.tsx': 'js', '.mts': 'js', '.cts': 'js',
  '.py': 'python', '.pyi': 'python',
  '.rb': 'ruby', '.rake': 'ruby',
  '.php': 'php',
  '.go': 'go',
  '.java': 'java',
  '.rs': 'rust',
  '.cs': 'csharp',
  '.sql': 'sql',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
};

/**
 * Language for a path, or null when we have no opinion.
 *
 * Null means "do not filter". A rule scoped to `['js']` still runs against a
 * .json config or a .md file, because those carry no language of their own and
 * silently skipping them would be a detection loss dressed up as precision.
 */
export function languageOf(filePath) {
  return EXT_LANGUAGE[path.extname(String(filePath || '')).toLowerCase()] || null;
}

// =============================================================================
// SUPPRESSION FLOOR
// =============================================================================

/**
 * Severities an inline `ship-safe-ignore` comment cannot silence.
 *
 * The comment was designed for a human deciding a finding is a false positive.
 * That assumption no longer holds on its own: the code under scan is often
 * written by an AI agent, and an agent that can emit a line of source can emit
 * `// ship-safe-ignore` on the line that matters — including via our own
 * `ship_safe_suppress_finding` tool. Suppression is therefore attacker-writable
 * for anything an agent touches.
 *
 * Critical findings (hardcoded secrets, RCE, confirmed injection) are the ones
 * where a silent suppression is indistinguishable from a clean scan, so they
 * are reported regardless. Everything below critical keeps working exactly as
 * before, so existing suppressions are unaffected.
 *
 * An attempt to suppress a floor finding is itself recorded — someone marking a
 * critical finding as safe is a signal, not a no-op.
 */
export const SUPPRESSION_FLOOR_SEVERITIES = new Set(['critical']);

/** Findings about the scanned repository, safe for scoring and machine output. */
export function projectFindings(findings) {
  return (findings || []).filter(f => (f.scope || 'project') !== 'environment');
}

/** Findings about the machine running the scan. Interactive display only. */
export function environmentFindings(findings) {
  return (findings || []).filter(f => f.scope === 'environment');
}

const NON_PRODUCTION_SCOPES = new Set(['test', 'fixture', 'benchmark', 'docs', 'generated']);

/** Findings that describe deployable code and belong in repository posture. */
export function postureFindings(findings, { includeNonProduction = false } = {}) {
  return projectFindings(findings).filter(f => {
    if (includeNonProduction) return true;
    return !NON_PRODUCTION_SCOPES.has(f.codeScope || inferCodeScope(f.file));
  });
}

/** Whether a finding of this severity may be silenced by an inline comment. */
export function isSuppressible(severity) {
  return !SUPPRESSION_FLOOR_SEVERITIES.has(String(severity || '').toLowerCase());
}

// =============================================================================
// BASE AGENT CLASS
// =============================================================================

export class BaseAgent {
  /**
   * @param {string} name        — Agent name (e.g. 'InjectionTester')
   * @param {string} description — What this agent does
   * @param {string} category    — Finding category for scoring
   */
  constructor(name, description, category) {
    this.name = name;
    this.description = description;
    this.category = category;
    // Suppression accounting. A scan that silenced findings must never read
    // the same as a scan that had none to report.
    this.suppressedCount = 0;
    this.floorSuppressionAttempts = 0;
  }

  /**
   * Run the agent's analysis on a codebase.
   * Subclasses MUST override this method.
   *
   * @param {object} context — { rootPath, files, recon, options }
   * @returns {Promise<object[]>} — Array of finding objects
   */
  async analyze(context) {
    throw new Error(`${this.name}.analyze() not implemented`);
  }

  /**
   * Whether this agent should run given the recon results.
   * Override in subclasses to skip irrelevant scans.
   * Default: always run.
   */
  shouldRun(recon) {
    return true;
  }

  // ── Helpers available to all agents ─────────────────────────────────────────

  /**
   * Discover all scannable files in a directory.
   * Respects SKIP_DIRS, SKIP_EXTENSIONS, and MAX_FILE_SIZE.
   */
  async discoverFiles(rootPath, extraGlobs = ['**/*']) {
    const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

    // Respect .gitignore patterns
    const gitignoreGlobs = loadGitignorePatterns(rootPath);
    globIgnore.push(...gitignoreGlobs);

    // Load .ship-safeignore patterns
    const ignorePatterns = this._loadIgnorePatterns(rootPath);
    for (const p of ignorePatterns) {
      if (p.endsWith('/')) {
        globIgnore.push(`**/${p}**`);
      } else {
        globIgnore.push(`**/${p}`);
        globIgnore.push(p);
      }
    }

    const allFiles = await fg(extraGlobs, {
      cwd: rootPath,
      absolute: true,
      onlyFiles: true,
      ignore: globIgnore,
      dot: true,
    });

    return allFiles.filter(file => {
      const ext = path.extname(file).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) return false;
      const basename = path.basename(file);
      if (SKIP_FILENAMES.has(basename)) return false;
      if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) return false;
      try {
        const stats = fs.statSync(file);
        if (stats.size > MAX_FILE_SIZE) return false;
      } catch {
        return false;
      }
      return true;
    });
  }

  /**
   * Load .ship-safeignore patterns from the project root.
   */
  _loadIgnorePatterns(rootPath) {
    const ignorePath = path.join(rootPath, '.ship-safeignore');
    try {
      if (!fs.existsSync(ignorePath)) return [];
      return fs.readFileSync(ignorePath, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
    } catch {
      return [];
    }
  }

  /**
   * Get the files this agent should scan.
   * If incremental scanning is active (changedFiles in context), returns only changed files.
   * Otherwise returns all files. Agents that need the full file list can use context.files directly.
   */
  getFilesToScan(context) {
    return context.changedFiles || context.files;
  }

  /**
   * Read a file safely, returning null on failure.
   */
  readFile(filePath) {
    try {
      return fs.readFileSync(filePath, 'utf-8');
    } catch {
      return null;
    }
  }

  /**
   * Read a file and return its lines with line numbers.
   */
  readLines(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    return content.split('\n');
  }

  /**
   * Get surrounding code context for a finding.
   */
  getContext(filePath, lineNum, radius = 3) {
    const lines = this.readLines(filePath);
    if (lines.length === 0) return '';
    const start = Math.max(0, lineNum - 1 - radius);
    const end = Math.min(lines.length, lineNum + radius);
    return lines.slice(start, end).join('\n');
  }

  /**
   * Check if a line has the ship-safe-ignore suppression comment.
   *
   * Pass the severity of the finding being considered so the floor can apply:
   * a critical finding is reported even on a suppressed line (see
   * SUPPRESSION_FLOOR_SEVERITIES). Called without a severity, behaviour is
   * unchanged from before the floor existed.
   *
   * Either way the outcome is counted, so a report can state how much it was
   * asked not to say.
   */
  isSuppressed(line, severity = null) {
    if (!/ship-safe-ignore/i.test(line)) return false;

    if (severity !== null && !isSuppressible(severity)) {
      this.floorSuppressionAttempts++;
      return false;
    }

    this.suppressedCount++;
    return true;
  }

  /**
   * Scan file lines against an array of regex patterns.
   * Returns findings for every match.
   */
  scanFileWithPatterns(filePath, patterns) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const lang = languageOf(filePath);
    const lines = content.split('\n');
    const findings = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Suppression is decided per pattern, not per line: the floor depends on
      // the severity of the specific finding, which isn't known until we know
      // which pattern matched.
      const lineMarked = /ship-safe-ignore/i.test(line);

      // Some rules describe code and nothing else. A comment explaining why a
      // codebase *avoids* the cloud metadata endpoint is not a finding about
      // the cloud metadata endpoint, and prose that happens to contain a
      // keyword is not code. Opt-in per pattern, because other rules
      // deliberately target comments (hidden instructions, TODO markers).
      const isCommentLine = /^\s*(?:#|\/\/|\*|<!--|--\s|;)/.test(line);

      for (const p of patterns) {
        if (p.skipComments && isCommentLine) continue;
        // A pattern that declares `langs` only runs against those languages.
        // Absent, it runs everywhere, so existing rules are unaffected and the
        // field can be adopted agent by agent.
        if (p.langs && lang && !p.langs.includes(lang)) continue;
        const severity = p.severity || 'medium';

        // Collect matches first. Suppression is only meaningful for a pattern
        // that actually fired, and it counts once per (line, rule) rather than
        // once per match, so the tally reflects findings silenced.
        p.regex.lastIndex = 0;
        const matches = [];
        let m;
        while ((m = p.regex.exec(line)) !== null) {
          matches.push(m);
          if (!p.regex.global) break;
        }
        if (matches.length === 0) continue;
        if (lineMarked && this.isSuppressed(line, severity)) continue;

        for (const match of matches) {
          const finding = createFinding({
            file: filePath,
            line: i + 1,
            column: match.index + 1,
            severity,
            // A pattern may override its agent's category. Used to route
            // maintainability rules to `quality`, which is reported but never
            // scored — an agent can hold both kinds, and the distinction is
            // per rule, not per agent.
            category: p.category || this.category,
            rule: p.rule,
            title: p.title,
            description: p.description,
            matched: match[0],
            confidence: p.confidence || 'high',
            cwe: p.cwe || null,
            owasp: p.owasp || null,
            fix: p.fix || null,
          });
          // Attach surrounding code context (3 lines before/after)
          const start = Math.max(0, i - 3);
          const end = Math.min(lines.length, i + 4);
          finding.codeContext = lines.slice(start, end).map((l, idx) => ({
            line: start + idx + 1,
            text: l,
            highlight: (start + idx) === i,
          }));
          findings.push(finding);
        }
      }
    }

    return findings;
  }

  /**
   * Check if content imports or requires a specific module.
   */
  hasImport(content, moduleName) {
    const importRe = new RegExp(
      `(?:import\\s+.*from\\s+['"]${moduleName}['"])|` +
      `(?:require\\s*\\(\\s*['"]${moduleName}['"]\\s*\\))`,
      'g'
    );
    return importRe.test(content);
  }
}

export default BaseAgent;
