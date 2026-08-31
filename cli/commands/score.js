/**
 * Score Command
 * =============
 *
 * Compute a 0-100 security health score for your project.
 * Combines secret detection, code vulnerability detection, and dependency auditing.
 *
 * USAGE:
 *   npx ship-safe score [path]          Score the project in the current directory
 *   npx ship-safe score . --no-deps     Skip dependency audit (faster)
 *
 * Uses the shared versioned posture scorer also used by audit and CI. Findings
 * in tests, fixtures, documentation, benchmarks, and generated output remain
 * observable but do not lower repository posture by default.
 *
 * GRADES:
 *   A  90–100  Ship it!
 *   B  75–89   Minor issues to review
 *   C  60–74   Fix before shipping
 *   D  40–59   Significant security risks
 *   F  0–39    Not safe to ship
 *
 * EXIT CODES:
 *   0 - Score is A or B (90+/75+)
 *   1 - Score is C or below (< 75)
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import chalk from 'chalk';
import ora from 'ora';
import {
  SECRET_PATTERNS,
  SECURITY_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  SKIP_FILENAMES,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import { isHighEntropyMatch } from '../utils/entropy.js';
import { runDepsAudit } from './deps.js';
import * as output from '../utils/output.js';
import { ScoringEngine } from '../agents/scoring-engine.js';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function scoreCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  console.log();
  output.header('Security Health Score');
  console.log();

  const runDeps = options.deps !== false; // --no-deps sets options.deps = false

  // ── 1. Scan for secrets and code vulns ──────────────────────────────────────
  const spinner = ora({ text: 'Scanning for secrets and vulnerabilities...', color: 'cyan' }).start();

  let findings = [];
  let filesScanned = 0;

  try {
    const files = await findFiles(absolutePath);
    filesScanned = files.length;
    spinner.text = `Scanning ${files.length} files...`;

    for (const file of files) {
      const fileFindings = scanFile(file);
      findings = findings.concat(fileFindings);
    }
    spinner.stop();
  } catch (err) {
    spinner.fail('Scan failed');
    output.error(err.message);
    process.exit(1);
  }

  // ── 2. Dependency audit ──────────────────────────────────────────────────────
  let depVulns = [];
  let pm = null;

  if (runDeps) {
    const depSpinner = ora({ text: 'Auditing dependencies...', color: 'cyan' }).start();
    try {
      const result = await runDepsAudit(absolutePath);
      pm = result.pm;
      depVulns = result.vulns;
      depSpinner.stop();
    } catch {
      depSpinner.stop();
      // Dep audit failure doesn't block scoring — just skip
    }
  }

  // ── 3. Compute score ─────────────────────────────────────────────────────────
  const scoreResult = new ScoringEngine().compute(findings, depVulns);
  const score = Math.round(scoreResult.score * 10) / 10;
  const grade = scoreResult.grade;
  const secrets = scoreResult.categories.secrets;
  const injection = scoreResult.categories.injection;
  const deps = scoreResult.categories.deps;

  // ── 4. Print results ─────────────────────────────────────────────────────────
  printScore(score, grade, {
    secretDeduction: secrets.deduction,
    vulnDeduction: injection.deduction,
    depDeduction: deps.deduction,
    secretCounts: secrets.counts,
    vulnCounts: injection.counts,
    depCounts: deps.counts,
    filesScanned, pm, runDeps
  });

  // Exit 0 for A/B, exit 1 for C/D/F
  process.exit(score >= 75 ? 0 : 1);
}

// =============================================================================
// OUTPUT
// =============================================================================

const GRADE_COLOR = {
  A: chalk.green.bold,
  B: chalk.cyan.bold,
  C: chalk.yellow.bold,
  D: chalk.red,
  F: chalk.red.bold,
};

function printScore(score, grade, ctx) {
  const gradeColor = GRADE_COLOR[grade.letter] || chalk.white;
  const scoreColor = score >= 75 ? chalk.green.bold : score >= 60 ? chalk.yellow.bold : chalk.red.bold;

  // ── Score headline ───────────────────────────────────────────────────────────
  console.log(
    chalk.white.bold('  Ship Safe Score: ') +
    scoreColor(`${score}/100`) +
    chalk.gray('  ') +
    gradeColor(`${grade.letter}`) +
    chalk.gray(` — ${grade.label}`)
  );
  console.log(chalk.cyan('  ' + '─'.repeat(58)));
  console.log();

  // ── Row: Secrets ─────────────────────────────────────────────────────────────
  const secretCount = Object.values(ctx.secretCounts).reduce((a, b) => a + b, 0);
  const secretIcon = secretCount === 0 ? chalk.green('✔') : chalk.red('✘');
  const secretStatus = secretCount === 0
    ? chalk.green('0 found')
    : chalk.red(`${secretCount} found`);
  const secretDeductStr = ctx.secretDeduction === 0
    ? chalk.gray('+0 deductions')
    : chalk.red(`−${ctx.secretDeduction} points`) + chalk.gray(` (${formatCounts(ctx.secretCounts)})`);

  console.log(
    `  ${secretIcon}  ${chalk.white.bold('Secrets       ')}  ${secretStatus.padEnd(18)}  ${secretDeductStr}`
  );

  // ── Row: Code Vulns ───────────────────────────────────────────────────────────
  const vulnCount = Object.values(ctx.vulnCounts).reduce((a, b) => a + b, 0);
  const vulnIcon = vulnCount === 0 ? chalk.green('✔') : chalk.yellow('✘');
  const vulnStatus = vulnCount === 0
    ? chalk.green('0 found')
    : chalk.yellow(`${vulnCount} found`);
  const vulnDeductStr = ctx.vulnDeduction === 0
    ? chalk.gray('+0 deductions')
    : chalk.yellow(`−${ctx.vulnDeduction} points`) + chalk.gray(` (${formatCounts(ctx.vulnCounts)})`);

  console.log(
    `  ${vulnIcon}  ${chalk.white.bold('Code Vulns    ')}  ${vulnStatus.padEnd(18)}  ${vulnDeductStr}`
  );

  // ── Row: Dependencies ─────────────────────────────────────────────────────────
  if (ctx.runDeps) {
    const depCount = Object.values(ctx.depCounts).reduce((a, b) => a + b, 0);
    const depIcon = depCount === 0 ? chalk.green('✔') : chalk.red('✘');
    const depLabel = ctx.pm ? `Dependencies  ` : 'Dependencies  ';

    let depStatus, depDeductStr;

    if (!ctx.pm) {
      depStatus  = chalk.gray('no manifest');
      depDeductStr = chalk.gray('+0 deductions');
    } else if (depCount === 0) {
      depStatus  = chalk.green('0 CVEs');
      depDeductStr = chalk.gray('+0 deductions');
    } else {
      depStatus  = chalk.red(`${depCount} CVEs`);
      depDeductStr = chalk.red(`−${ctx.depDeduction} points`) + chalk.gray(` (${formatCounts(ctx.depCounts)})`);
    }

    console.log(
      `  ${depIcon}  ${chalk.white.bold(depLabel)}  ${depStatus.padEnd(18)}  ${depDeductStr}`
    );
  } else {
    console.log(
      `  ${chalk.gray('–')}  ${chalk.gray('Dependencies    skipped (--no-deps)')}`
    );
  }

  console.log();
  console.log(chalk.cyan('  ' + '─'.repeat(58)));
  console.log(chalk.gray(`  Files scanned: ${ctx.filesScanned}`));

  // ── Next steps ────────────────────────────────────────────────────────────────
  if (score < 100) {
    console.log();
    const actions = [];
    if (Object.values(ctx.secretCounts).some(n => n > 0)) {
      actions.push(chalk.white('  npx ship-safe agent .') + chalk.gray('     # AI audit: classify + auto-fix secrets'));
    }
    if (Object.values(ctx.vulnCounts).some(n => n > 0)) {
      actions.push(chalk.white('  npx ship-safe agent .') + chalk.gray('     # AI audit: classify + fix suggestions'));
    }
    if (ctx.runDeps && Object.values(ctx.depCounts).some(n => n > 0) && ctx.pm) {
      actions.push(chalk.white(`  npx ship-safe deps .`) + chalk.gray('      # See full dependency CVE details'));
    }
    if (actions.length > 0) {
      console.log(chalk.gray('  Fix issues:'));
      // Deduplicate (agent appears for both secrets and vulns)
      const seen = new Set();
      for (const a of actions) {
        if (!seen.has(a)) { console.log(a); seen.add(a); }
      }
    }
  } else {
    console.log();
    console.log(chalk.green('  All clear — safe to ship!'));
  }

  console.log(chalk.cyan('='.repeat(60)));
  console.log(chalk.gray('  Share your score & track trends: ') + chalk.cyan('https://shipsafe.sh'));
  console.log();
}

function formatCounts(counts) {
  const SEV_ORDER = ['critical', 'high', 'moderate', 'medium', 'low'];
  return SEV_ORDER
    .filter(s => counts[s] > 0)
    .map(s => `${counts[s]} ${s}`)
    .join(', ');
}

// =============================================================================
// INTERNAL SCAN (no subprocess — import patterns directly)
// =============================================================================

const ALL_PATTERNS = [...SECRET_PATTERNS, ...SECURITY_PATTERNS];

/**
 * Find all scannable files (same logic as scan.js, without test-exclusion
 * and without .ship-safeignore loading — score is a quick overview).
 */
async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

  const files = await fg('**/*', {
    cwd: rootPath,
    absolute: true,
    onlyFiles: true,
    ignore: globIgnore,
    dot: true
  });

  const filtered = [];

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) continue;
    if (SKIP_FILENAMES.has(path.basename(file))) continue;

    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) continue;

    // Load and respect .ship-safeignore
    if (isIgnoredByFile(file, rootPath)) continue;

    try {
      const stats = fs.statSync(file);
      if (stats.size > MAX_FILE_SIZE) continue;
    } catch {
      continue;
    }

    filtered.push(file);
  }

  return filtered;
}

// Cache ignore patterns per root to avoid re-reading the file thousands of times
const _ignoreCache = new Map();

function loadIgnorePatterns(rootPath) {
  if (_ignoreCache.has(rootPath)) return _ignoreCache.get(rootPath);

  const ignorePath = path.join(rootPath, '.ship-safeignore');
  let patterns = [];

  if (fs.existsSync(ignorePath)) {
    try {
      patterns = fs.readFileSync(ignorePath, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
    } catch {
      // ignore read error
    }
  }

  _ignoreCache.set(rootPath, patterns);
  return patterns;
}

function isIgnoredByFile(filePath, rootPath) {
  const patterns = loadIgnorePatterns(rootPath);
  if (patterns.length === 0) return false;

  const relPath = path.relative(rootPath, filePath).replace(/\\/g, '/');

  return patterns.some(pattern => {
    if (pattern.endsWith('/')) {
      return relPath.startsWith(pattern) || relPath.includes('/' + pattern);
    }
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/]');
    return new RegExp(`(^|/)${escaped}($|/)`).test(relPath);
  });
}

/**
 * Scan a single file and return normalized findings.
 * Same algorithm as scan.js — inline here to avoid circular dependency
 * (scan.js has process.exit() side effects).
 */
function scanFile(filePath) {
  const findings = [];

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      if (/ship-safe-ignore/i.test(line)) continue;

      for (const pattern of ALL_PATTERNS) {
        pattern.pattern.lastIndex = 0;

        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) {
            continue;
          }

          findings.push({
            line: lineNum + 1,
            severity: pattern.severity,
            category: pattern.category || 'secret',
          });
        }
      }
    }
  } catch {
    // Skip unreadable files
  }

  // Deduplicate: same (line, severity, category)
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.line}:${f.severity}:${f.category}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
