/**
 * Security Memory
 * ================
 *
 * Hermes-inspired persistent memory for false-positive learning.
 *
 * After deep analysis confirms a finding is a false-positive, the verdict is
 * written to `.ship-safe/memory.json`. On the next scan, the SecurityMemory
 * filter runs before scoring and suppresses any finding whose (rule + file +
 * matched-snippet hash) appears in memory — avoiding the same LLM call twice.
 *
 * Memory entries are per-repo (stored in `.ship-safe/` inside the project
 * root), so suppressions don't bleed across unrelated projects.
 *
 * USAGE:
 *   import { SecurityMemory } from '../utils/security-memory.js';
 *
 *   const memory = new SecurityMemory(rootPath);
 *
 *   // After deep analysis — auto-learn false positives
 *   memory.learnFromAnalysis(findings);
 *
 *   // Filter findings against memory before scoring
 *   const { kept, suppressed } = memory.filter(findings);
 *
 *   // Manual suppression (from `ship-safe memory add`)
 *   memory.suppress(finding, 'Not reachable from user input');
 *
 *   // CLI commands
 *   memory.list()   → all suppressed entries
 *   memory.forget(id) → remove one entry
 *   memory.clear()  → wipe all entries
 */

import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';

const MEMORY_DIR  = '.ship-safe';
const MEMORY_FILE = 'memory.json';

/** How many chars of the matched snippet to hash (stable across reformatting) */
const SNIPPET_HASH_LEN = 120;

export class SecurityMemory {
  constructor(rootPath) {
    this.rootPath   = rootPath;
    this.memoryDir  = path.join(rootPath, MEMORY_DIR);
    this.memoryPath = path.join(this.memoryDir, MEMORY_FILE);
    this._data      = null; // lazy-loaded
  }

  // ===========================================================================
  // PERSISTENCE
  // ===========================================================================

  _load() {
    if (this._data) return this._data;

    try {
      if (fs.existsSync(this.memoryPath)) {
        this._data = JSON.parse(fs.readFileSync(this.memoryPath, 'utf-8'));
      }
    } catch { /* corrupt file — start fresh */ }

    if (!this._data || typeof this._data !== 'object') {
      this._data = { version: 1, entries: [] };
    }
    if (!Array.isArray(this._data.entries)) {
      this._data.entries = [];
    }

    return this._data;
  }

  _save() {
    try {
      if (!fs.existsSync(this.memoryDir)) {
        fs.mkdirSync(this.memoryDir, { recursive: true });
      }
      fs.writeFileSync(this.memoryPath, JSON.stringify(this._data, null, 2), 'utf-8');
    } catch { /* non-fatal */ }
  }

  // ===========================================================================
  // KEY GENERATION
  // ===========================================================================

  /**
   * Generate a stable key for a finding.
   * Key = SHA-256(rule + file-basename + first N chars of matched).
   * Deliberately excludes line number so the suppression survives minor refactors.
   */
  static keyOf(finding) {
    const rule     = finding.rule    || '';
    const file     = finding.file    ? path.basename(finding.file) : '';
    const snippet  = (finding.matched || finding.title || '').slice(0, SNIPPET_HASH_LEN);
    return createHash('sha256').update(`${rule}::${file}::${snippet}`).digest('hex').slice(0, 16);
  }

  // ===========================================================================
  // CORE API
  // ===========================================================================

  /**
   * Learn from deep analysis results.
   * Any finding with exploitability === 'false_positive' is auto-added to memory.
   *
   * @param {object[]} findings — findings array (with deepAnalysis attached)
   * @returns {number} — count of new entries added
   */
  learnFromAnalysis(findings) {
    const data = this._load();
    const existingKeys = new Set(data.entries.map(e => e.key));
    let added = 0;

    for (const f of findings) {
      if (f.deepAnalysis?.exploitability !== 'false_positive') continue;

      const key = SecurityMemory.keyOf(f);
      if (existingKeys.has(key)) continue;

      data.entries.push({
        key,
        rule:          f.rule,
        file:          f.file ? path.basename(f.file) : '',
        title:         f.title,
        severity:      f.severity,
        reason:        f.deepAnalysis.reasoning || 'Auto-detected false positive by deep analysis',
        source:        'deep-analysis',
        suppressedAt:  new Date().toISOString(),
      });

      existingKeys.add(key);
      added++;
    }

    if (added > 0) this._save();
    return added;
  }

  /**
   * Manually suppress a finding with a reason.
   *
   * @param {object} finding
   * @param {string} reason
   * @returns {string} — the key added
   */
  suppress(finding, reason = '') {
    const data = this._load();
    const key  = SecurityMemory.keyOf(finding);

    if (data.entries.some(e => e.key === key)) {
      return key; // already suppressed
    }

    data.entries.push({
      key,
      rule:         finding.rule,
      file:         finding.file ? path.basename(finding.file) : '',
      title:        finding.title,
      severity:     finding.severity,
      reason:       reason || 'Manually suppressed',
      source:       'manual',
      suppressedAt: new Date().toISOString(),
    });

    this._save();
    return key;
  }

  /**
   * Filter findings against memory.
   * Returns { kept, suppressed } — suppressed findings get a .memorySuppressed flag.
   *
   * @param {object[]} findings
   * @returns {{ kept: object[], suppressed: object[], suppressedCount: number }}
   */
  filter(findings) {
    const data  = this._load();
    if (data.entries.length === 0) {
      return { kept: findings, suppressed: [], suppressedCount: 0 };
    }

    const keySet = new Set(data.entries.map(e => e.key));
    const kept       = [];
    const suppressed = [];

    for (const f of findings) {
      const key    = SecurityMemory.keyOf(f);
      const entry  = data.entries.find(e => e.key === key);
      if (entry) {
        suppressed.push({ ...f, memorySuppressed: true, suppressionReason: entry.reason });
      } else {
        kept.push(f);
      }
    }

    return { kept, suppressed, suppressedCount: suppressed.length };
  }

  /**
   * Remove a single entry by key.
   */
  forget(key) {
    const data = this._load();
    const before = data.entries.length;
    data.entries = data.entries.filter(e => e.key !== key);
    const removed = before - data.entries.length;
    if (removed > 0) this._save();
    return removed;
  }

  /**
   * Wipe all memory entries.
   */
  clear() {
    this._data = { version: 1, entries: [] };
    this._save();
  }

  /**
   * Return all entries.
   */
  list() {
    return this._load().entries;
  }

  /**
   * Count of suppressed entries.
   */
  get size() {
    return this._load().entries.length;
  }
}

// =============================================================================
// CLI COMMAND  (ship-safe memory)
// =============================================================================

import chalk from 'chalk';
import * as output from './output.js';

export async function memoryCommand(subcommand, args = [], options = {}) {
  const rootPath = path.resolve(options.path || '.');
  const memory   = new SecurityMemory(rootPath);

  switch (subcommand) {
    case 'list':
    case undefined: {
      const entries = memory.list();
      if (entries.length === 0) {
        console.log('\n  No suppressed findings in memory.\n');
        return;
      }
      console.log(`\n  ${chalk.cyan.bold('Security Memory')} — ${entries.length} suppressed finding(s)\n`);
      for (const e of entries) {
        const sev = e.severity === 'critical' ? chalk.red.bold(e.severity)
          : e.severity === 'high'     ? chalk.yellow(e.severity)
          : chalk.gray(e.severity);
        console.log(`  ${chalk.gray(e.key)}  ${sev}  ${chalk.white(e.rule)}`);
        console.log(`    ${chalk.gray('File:')} ${e.file}  ${chalk.gray('Source:')} ${e.source}  ${chalk.gray('Date:')} ${e.suppressedAt.slice(0, 10)}`);
        console.log(`    ${chalk.gray('Reason:')} ${e.reason}`);
        console.log();
      }
      break;
    }

    case 'forget': {
      const key = args[0];
      if (!key) {
        output.error('Usage: ship-safe memory forget <key>');
        process.exit(1);
      }
      const removed = memory.forget(key);
      if (removed) {
        console.log(chalk.green(`  Removed memory entry: ${key}`));
      } else {
        console.log(chalk.yellow(`  Key not found in memory: ${key}`));
      }
      break;
    }

    case 'clear': {
      const before = memory.size;
      memory.clear();
      console.log(chalk.green(`  Cleared ${before} memory entry/entries.`));
      break;
    }

    default:
      output.error(`Unknown memory subcommand: ${subcommand}`);
      console.log('  Usage: ship-safe memory [list|forget <key>|clear]');
      process.exit(1);
  }
}
