/**
 * GitHistoryScanner Agent
 * ========================
 *
 * Scans git commit history for secrets that were committed
 * and later removed but remain in repository history.
 * These are the most dangerous secrets — developers think
 * they're deleted but they're still accessible.
 */

import { execSync } from 'child_process';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';
import { SECRET_PATTERNS } from '../utils/patterns.js';

// Compile a fast combined regex from all secret patterns
const FAST_SECRET_PATTERNS = SECRET_PATTERNS.map(p => ({
  name: p.name,
  pattern: p.pattern,
  severity: p.severity,
}));

export class GitHistoryScanner extends BaseAgent {
  constructor() {
    super('GitHistoryScanner', 'Scan git history for leaked secrets', 'history');
  }

  async analyze(context) {
    const { rootPath, options } = context;
    const findings = [];

    // Check if this is a git repository
    if (!this.isGitRepo(rootPath)) return [];

    try {
      // Get recent commits (default: last 50, configurable)
      const maxCommits = options?.maxCommits || 50;
      const since = options?.since || null;

      let gitLogCmd = `git -C "${rootPath}" log --all --diff-filter=A --diff-filter=M -p --no-color --max-count=${maxCommits}`;
      if (since) {
        gitLogCmd += ` --since="${since}"`;
      }

      let diffOutput;
      try {
        diffOutput = execSync(gitLogCmd, {
          cwd: rootPath,
          encoding: 'utf-8',
          maxBuffer: 50 * 1024 * 1024, // 50MB buffer
          timeout: 60000, // 60s timeout
        });
      } catch {
        // git log failed — might be a shallow clone or no history
        return [];
      }

      if (!diffOutput) return [];

      // Parse the diff output
      let currentFile = '';
      let currentCommit = '';
      let currentDate = '';
      const lines = diffOutput.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Track current commit
        if (line.startsWith('commit ')) {
          currentCommit = line.slice(7, 17); // First 10 chars of hash
        }
        if (line.startsWith('Date:')) {
          currentDate = line.slice(5).trim();
        }

        // Track current file
        if (line.startsWith('diff --git ')) {
          const match = line.match(/diff --git a\/(.+) b\//);
          if (match) currentFile = match[1];
        }

        // Only check added lines (lines starting with +)
        if (!line.startsWith('+') || line.startsWith('+++')) continue;

        const addedLine = line.slice(1); // Remove the leading +

        // Check against all secret patterns
        for (const p of FAST_SECRET_PATTERNS) {
          p.pattern.lastIndex = 0;
          const match = p.pattern.exec(addedLine);
          if (match) {
            // Check if this secret still exists in current working tree
            const stillExists = this.existsInWorkingTree(rootPath, match[0]);

            findings.push(createFinding({
              file: path.join(rootPath, currentFile),
              line: 0, // Line number not meaningful in history
              severity: stillExists ? p.severity : this.elevateSeverity(p.severity),
              category: 'history',
              rule: 'GIT_HISTORY_SECRET',
              title: `Historical Secret: ${p.name}`,
              description: stillExists
                ? `Secret found in current code AND in git history (commit ${currentCommit}).`
                : `Secret was removed from code but still exists in git history (commit ${currentCommit}, ${currentDate}). Anyone with repo access can retrieve it.`,
              matched: this.maskSecret(match[0]),
              confidence: 'high',
              fix: stillExists
                ? 'Remove from code, rotate the credential, then clean git history with BFG or git filter-repo'
                : 'Rotate this credential immediately, then clean history: npx bfg --replace-text passwords.txt',
            }));
          }
        }
      }

      // Deduplicate by matched value (same secret in multiple commits)
      const seen = new Set();
      return findings.filter(f => {
        const key = `${f.matched}:${f.title}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

    } catch (err) {
      // Don't fail the entire scan if git history scan fails
      return [];
    }
  }

  isGitRepo(dir) {
    try {
      execSync('git rev-parse --is-inside-work-tree', { cwd: dir, stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  existsInWorkingTree(rootPath, secret) {
    try {
      const result = execSync(`git -C "${rootPath}" grep -l "${secret.slice(0, 12)}" -- "*.js" "*.ts" "*.py" "*.env" "*.json" 2>/dev/null`, {
        cwd: rootPath,
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return result.trim().length > 0;
    } catch {
      return false;
    }
  }

  elevateSeverity(sev) {
    // Secrets in history-only are MORE dangerous (developer thinks they're gone)
    if (sev === 'medium') return 'high';
    if (sev === 'high') return 'critical';
    return sev;
  }

  maskSecret(secret) {
    if (secret.length <= 10) return secret.slice(0, 4) + '***';
    return secret.slice(0, 8) + '***' + secret.slice(-4);
  }
}

export default GitHistoryScanner;
