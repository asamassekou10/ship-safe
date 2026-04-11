/**
 * Scan Playbook
 * =============
 *
 * Hermes-inspired repo-specific intelligence that accumulates across scans
 * and gets injected into the DeepAnalyzer system prompt as project context.
 *
 * After each scan, the playbook is updated with:
 *   - Tech stack (frameworks, databases, runtimes)
 *   - Auth patterns detected
 *   - Known suppressed rules (from memory)
 *   - Scan statistics (score trend, most common finding categories)
 *   - Custom notes added by the user
 *
 * DeepAnalyzer reads the playbook and prepends it to every LLM call so the
 * model has richer context than the generic system prompt alone — reducing
 * both false positives and missed findings.
 *
 * PLAYBOOK FILE: .ship-safe/playbook.md
 *
 * USAGE:
 *   import { ScanPlaybook } from '../utils/scan-playbook.js';
 *
 *   const playbook = new ScanPlaybook(rootPath);
 *
 *   // After each scan — update with latest recon + score
 *   playbook.update(recon, scoreResult, suppressedRules);
 *
 *   // Get the context string to inject into LLM prompts
 *   const context = playbook.getPromptContext();
 *
 *   // CLI
 *   playbook.show()   — print current playbook
 *   playbook.addNote(text) — add a custom note
 */

import fs from 'fs';
import path from 'path';

const PLAYBOOK_DIR  = '.ship-safe';
const PLAYBOOK_FILE = 'playbook.md';
const HISTORY_FILE  = 'scan-history.json';

/** Minimum number of scans before the playbook is considered reliable */
const MIN_SCANS_FOR_PLAYBOOK = 2;

export class ScanPlaybook {
  constructor(rootPath) {
    this.rootPath     = rootPath;
    this.playbookDir  = path.join(rootPath, PLAYBOOK_DIR);
    this.playbookPath = path.join(this.playbookDir, PLAYBOOK_FILE);
    this.historyPath  = path.join(this.playbookDir, HISTORY_FILE);
  }

  // ===========================================================================
  // UPDATE — called after every scan
  // ===========================================================================

  /**
   * Update the playbook with the latest scan data.
   *
   * @param {object} recon        — from ReconAgent
   * @param {object} scoreResult  — { score, grade, totalFindings, ... }
   * @param {object[]} findings   — all findings (used for category frequency)
   * @param {string[]} suppressedRules — rules currently in memory
   */
  update(recon, scoreResult, findings = [], suppressedRules = []) {
    // Ensure dir exists
    if (!fs.existsSync(this.playbookDir)) {
      fs.mkdirSync(this.playbookDir, { recursive: true });
    }

    // Update scan history
    const history = this._loadHistory();
    history.push({
      date:          new Date().toISOString(),
      score:         scoreResult?.score ?? null,
      grade:         scoreResult?.grade?.letter ?? scoreResult?.grade ?? null,
      totalFindings: scoreResult?.totalFindings ?? findings.length,
    });
    // Keep last 50 entries
    while (history.length > 50) history.shift();
    this._saveHistory(history);

    // Only update the playbook markdown after MIN_SCANS
    if (history.length < MIN_SCANS_FOR_PLAYBOOK) return;

    // Preserve user-written custom notes from existing playbook
    const existingNotes = this._extractCustomNotes();

    const content = this._buildPlaybook(recon, history, findings, suppressedRules, existingNotes);
    fs.writeFileSync(this.playbookPath, content, 'utf-8');
  }

  // ===========================================================================
  // READ — injected into LLM prompts
  // ===========================================================================

  /**
   * Returns a compact context string to prepend to LLM system prompts.
   * Empty string if the playbook doesn't exist yet.
   */
  getPromptContext() {
    if (!fs.existsSync(this.playbookPath)) return '';

    try {
      const content = fs.readFileSync(this.playbookPath, 'utf-8');
      // Extract the machine-readable section between <!-- context-start --> and <!-- context-end -->
      const match = content.match(/<!-- context-start -->([\s\S]*?)<!-- context-end -->/);
      if (match) return match[1].trim();

      // Fallback: return first 1500 chars of playbook
      return content.slice(0, 1500);
    } catch {
      return '';
    }
  }

  /**
   * Whether the playbook has enough data to be useful.
   */
  get isReady() {
    return fs.existsSync(this.playbookPath);
  }

  // ===========================================================================
  // CLI
  // ===========================================================================

  show() {
    if (!fs.existsSync(this.playbookPath)) {
      console.log('\n  No playbook yet. Run `ship-safe audit` at least twice to generate one.\n');
      return;
    }
    const content = fs.readFileSync(this.playbookPath, 'utf-8');
    console.log('\n' + content);
  }

  /**
   * Append a custom user note to the playbook.
   */
  addNote(text) {
    if (!fs.existsSync(this.playbookPath)) {
      console.error('  No playbook yet — run ship-safe audit first.');
      return;
    }
    const existing = fs.readFileSync(this.playbookPath, 'utf-8');
    const timestamp = new Date().toISOString().slice(0, 10);
    const noteSection = existing.includes('## Custom Notes')
      ? existing.replace('## Custom Notes', `## Custom Notes\n\n- [${timestamp}] ${text}`)
      : existing + `\n\n## Custom Notes\n\n- [${timestamp}] ${text}\n`;
    fs.writeFileSync(this.playbookPath, noteSection, 'utf-8');
    console.log('  Note added to playbook.');
  }

  // ===========================================================================
  // INTERNALS
  // ===========================================================================

  _loadHistory() {
    try {
      if (fs.existsSync(this.historyPath)) {
        return JSON.parse(fs.readFileSync(this.historyPath, 'utf-8'));
      }
    } catch { /* start fresh */ }
    return [];
  }

  _saveHistory(history) {
    try {
      fs.writeFileSync(this.historyPath, JSON.stringify(history, null, 2), 'utf-8');
    } catch { /* non-fatal */ }
  }

  _extractCustomNotes() {
    if (!fs.existsSync(this.playbookPath)) return '';
    try {
      const content = fs.readFileSync(this.playbookPath, 'utf-8');
      const match = content.match(/## Custom Notes([\s\S]*)$/);
      return match ? match[0] : '';
    } catch { return ''; }
  }

  _buildPlaybook(recon, history, findings, suppressedRules, customNotes) {
    const repoName  = path.basename(this.rootPath);
    const lastScore = history.at(-1)?.score ?? '?';
    const lastGrade = history.at(-1)?.grade ?? '?';
    const scanCount = history.length;
    const avgScore  = history.length > 0
      ? Math.round(history.reduce((s, h) => s + (h.score ?? 0), 0) / history.length)
      : 0;

    // Score trend
    const trend = history.length >= 2
      ? (history.at(-1).score ?? 0) - (history.at(-2).score ?? 0)
      : 0;
    const trendStr = trend > 0 ? `↑ +${trend}` : trend < 0 ? `↓ ${trend}` : '→ stable';

    // Category frequency
    const catCounts = {};
    for (const f of findings) {
      catCounts[f.category || 'other'] = (catCounts[f.category || 'other'] || 0) + 1;
    }
    const topCategories = Object.entries(catCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([cat, count]) => `${cat} (${count})`)
      .join(', ') || 'none';

    // Tech stack
    const frameworks = recon?.frameworks?.length ? recon.frameworks.join(', ') : 'unknown';
    const databases  = recon?.databases?.length  ? recon.databases.join(', ')  : 'none detected';
    const authPat    = recon?.authPatterns?.length ? recon.authPatterns.join(', ') : 'none detected';
    const runtime    = recon?.runtime || 'unknown';
    const packageManager = recon?.packageManager || 'unknown';
    const language   = recon?.language || recon?.primaryLanguage || 'unknown';

    const suppressedSection = suppressedRules.length > 0
      ? suppressedRules.map(r => `- ${r}`).join('\n')
      : '- none';

    const historyTable = history.slice(-10).map(h =>
      `| ${h.date.slice(0, 10)} | ${h.score ?? '?'}/100 | ${h.grade ?? '?'} | ${h.totalFindings ?? '?'} |`
    ).join('\n');

    return `# Ship Safe Playbook — ${repoName}

> Auto-generated after ${scanCount} scan(s). Do not edit the section between the
> \`<!-- context-start -->\` and \`<!-- context-end -->\` markers — it is overwritten on each scan.
> Add custom notes at the bottom under **Custom Notes**.

<!-- context-start -->
REPO: ${repoName}
LANGUAGE: ${language}
RUNTIME: ${runtime}
PACKAGE_MANAGER: ${packageManager}
FRAMEWORKS: ${frameworks}
DATABASES: ${databases}
AUTH_PATTERNS: ${authPat}
LAST_SCORE: ${lastScore}/100 (${lastGrade})
TREND: ${trendStr}
AVG_SCORE: ${avgScore}/100 over ${scanCount} scans
TOP_FINDING_CATEGORIES: ${topCategories}
SUPPRESSED_RULES: ${suppressedRules.join(', ') || 'none'}
SCANS_COMPLETED: ${scanCount}
<!-- context-end -->

## Security Profile

| Property | Value |
|----------|-------|
| Language | ${language} |
| Runtime  | ${runtime} |
| Frameworks | ${frameworks} |
| Databases | ${databases} |
| Auth patterns | ${authPat} |

## Score History (last 10 scans)

| Date | Score | Grade | Findings |
|------|-------|-------|----------|
${historyTable}

**Current:** ${lastScore}/100 ${lastGrade} (${trendStr})

## Known Suppressions

The following rules are currently suppressed in \`.ship-safe/memory.json\`:

${suppressedSection}

## Top Finding Categories

${topCategories}

${customNotes || '## Custom Notes\n\n_Add project-specific context here with: `ship-safe playbook add-note "..."`_\n'}
`;
  }
}

// =============================================================================
// CLI COMMAND  (ship-safe playbook)
// =============================================================================

import chalk from 'chalk';

export async function playbookCommand(subcommand, args = [], options = {}) {
  const rootPath = path.resolve(options.path || '.');
  const playbook = new ScanPlaybook(rootPath);

  switch (subcommand) {
    case 'show':
    case undefined:
      playbook.show();
      break;

    case 'add-note': {
      const text = args.join(' ').trim();
      if (!text) {
        console.error('  Usage: ship-safe playbook add-note "your note here"');
        process.exit(1);
      }
      playbook.addNote(text);
      break;
    }

    default:
      console.error(`  Unknown playbook subcommand: ${subcommand}`);
      console.log('  Usage: ship-safe playbook [show|add-note "..."]');
      process.exit(1);
  }
}
