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
import { SKIP_DIRS, SKIP_EXTENSIONS, MAX_FILE_SIZE, loadGitignorePatterns } from '../utils/patterns.js';

// =============================================================================
// FINDING FACTORY
// =============================================================================

/**
 * Create a standardized finding object.
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
  };
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
   */
  isSuppressed(line) {
    return /ship-safe-ignore/i.test(line);
  }

  /**
   * Scan file lines against an array of regex patterns.
   * Returns findings for every match.
   */
  scanFileWithPatterns(filePath, patterns) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const lines = content.split('\n');
    const findings = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (this.isSuppressed(line)) continue;

      for (const p of patterns) {
        p.regex.lastIndex = 0;
        let match;
        while ((match = p.regex.exec(line)) !== null) {
          const finding = createFinding({
            file: filePath,
            line: i + 1,
            column: match.index + 1,
            severity: p.severity || 'medium',
            category: this.category,
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
