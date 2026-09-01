/**
 * Diff Command
 * =============
 *
 * Scan only changed files (git diff) for security issues.
 * Much faster than a full audit — perfect for pre-commit hooks and PR reviews.
 *
 * USAGE:
 *   ship-safe diff              Scan uncommitted changes (staged + unstaged)
 *   ship-safe diff --staged     Scan only staged changes
 *   ship-safe diff HEAD~3       Scan changes in last 3 commits
 *   ship-safe diff main         Scan changes since branching from main
 */

import { execFileSync } from 'child_process';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { SECRET_PATTERNS, SECURITY_PATTERNS, SKIP_EXTENSIONS, SKIP_FILENAMES } from '../utils/patterns.js';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine, SCORE_VERSION } from '../agents/scoring-engine.js';

// =============================================================================
// DIFF COMMAND
// =============================================================================

export async function diffCommand(ref, options) {
  const targetPath = options.path || process.cwd();
  const absolutePath = path.resolve(targetPath);

  // ── Get changed files from git ────────────────────────────────────────────
  const spinner = ora(chalk.white('Getting changed files from git...')).start();

  let gitArgs;
  if (options.staged) {
    gitArgs = ['diff', '--cached', '--name-only', '--diff-filter=ACMR'];
  } else if (ref) {
    gitArgs = ['diff', '--name-only', '--diff-filter=ACMR', ref];
  } else {
    // Uncommitted changes: both staged and unstaged
    gitArgs = ['diff', '--name-only', '--diff-filter=ACMR', 'HEAD'];
  }

  let changedFiles;
  try {
    const output = execFileSync('git', gitArgs, {
      cwd: absolutePath,
      encoding: 'utf-8',
      timeout: 10_000,
    }).trim();

    if (!output) {
      spinner.succeed(chalk.green('No changed files detected'));
      console.log(chalk.gray('\n  Nothing to scan. Your working tree is clean.\n'));
      return;
    }

    changedFiles = output
      .split('\n')
      .map(f => f.trim())
      .filter(f => f.length > 0)
      .map(f => path.resolve(absolutePath, f))
      .filter(f => {
        const ext = path.extname(f).toLowerCase();
        if (SKIP_EXTENSIONS.has(ext)) return false;
        const basename = path.basename(f);
        if (SKIP_FILENAMES.has(basename)) return false;
        return true;
      });

    spinner.succeed(chalk.white(`${changedFiles.length} changed file(s) to scan`));
  } catch (err) {
    // Fallback for repos with no commits yet
    if (err.message?.includes('unknown revision')) {
      try {
        const output = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], {
          cwd: absolutePath,
          encoding: 'utf-8',
          timeout: 10_000,
        }).trim();

        changedFiles = output
          .split('\n')
          .map(f => f.trim())
          .filter(f => f.length > 0)
          .map(f => path.resolve(absolutePath, f))
          .filter(f => {
            const ext = path.extname(f).toLowerCase();
            if (SKIP_EXTENSIONS.has(ext)) return false;
            const basename = path.basename(f);
            if (SKIP_FILENAMES.has(basename)) return false;
            return true;
          });

        if (!changedFiles.length) {
          spinner.succeed(chalk.green('No changed files detected'));
          return;
        }
        spinner.succeed(chalk.white(`${changedFiles.length} changed file(s) to scan`));
      } catch {
        spinner.fail(chalk.red('Not a git repository or git not available'));
        process.exit(1);
      }
    } else {
      spinner.fail(chalk.red('Failed to get changed files from git'));
      console.error(chalk.gray(`  ${err.message}`));
      process.exit(1);
    }
  }

  if (changedFiles.length === 0) {
    console.log(chalk.gray('\n  No scannable files in the diff.\n'));
    return;
  }

  // ── Print header ──────────────────────────────────────────────────────────
  console.log();
  console.log(chalk.cyan('═'.repeat(60)));
  console.log(chalk.cyan.bold('  Ship Safe — Diff Scan'));
  console.log(chalk.cyan('═'.repeat(60)));
  console.log();
  console.log(chalk.gray(`  Scanning ${changedFiles.length} changed file(s):`));
  for (const f of changedFiles.slice(0, 10)) {
    console.log(chalk.gray(`    ${path.relative(absolutePath, f)}`));
  }
  if (changedFiles.length > 10) {
    console.log(chalk.gray(`    ... and ${changedFiles.length - 10} more`));
  }
  console.log();

  // ── Run agents on changed files only ──────────────────────────────────────
  const agentSpinner = ora(chalk.white('Running security agents on diff...')).start();

  const orchestrator = buildOrchestrator();
  const results = await orchestrator.runAll(absolutePath, {
    timeout: options.timeout || 30_000,
    changedFiles,
  });

  const findings = results.findings || [];
  agentSpinner.succeed(
    findings.length === 0
      ? chalk.green('No security issues in changed files')
      : chalk.yellow(`${findings.length} finding(s) in changed files`)
  );

  // ── Score ─────────────────────────────────────────────────────────────────
  if (findings.length > 0) {
    const scoringEngine = new ScoringEngine();
    const scoreResult = scoringEngine.compute(findings, []);
    scoreResult.score = Math.round(scoreResult.score * 10) / 10;

    const scoreColor = scoreResult.score >= 75 ? chalk.green.bold : scoreResult.score >= 60 ? chalk.yellow.bold : chalk.red.bold;

    console.log();
    console.log(chalk.cyan('  ' + '─'.repeat(56)));

    // Print findings
    let shown = 0;
    for (const f of findings) {
      if (shown >= 20) {
        console.log(chalk.gray(`\n  ... and ${findings.length - 20} more findings`));
        break;
      }
      const sevColor = f.severity === 'critical' ? chalk.red :
                        f.severity === 'high' ? chalk.yellow :
                        f.severity === 'medium' ? chalk.cyan : chalk.gray;
      const relPath = path.relative(absolutePath, f.file);
      console.log(`  ${sevColor(`[${f.severity.toUpperCase()}]`)} ${chalk.white(f.title)}`);
      console.log(chalk.gray(`    ${relPath}:${f.line} → ${f.fix || f.description}`));
      shown++;
    }

    console.log();
    console.log(chalk.cyan('  ' + '─'.repeat(56)));
    console.log(
      chalk.white.bold('  Changed-files risk score: ') +
      scoreColor(`${scoreResult.score}/100 ${scoreResult.grade.letter}`)
    );
    console.log(chalk.cyan('  ' + '─'.repeat(56)));
  }

  // ── JSON output ───────────────────────────────────────────────────────────
  if (options.json) {
    const output = {
      command: 'diff',
      analysisScope: 'changed-files',
      scoreVersion: SCORE_VERSION,
      repositoryPosture: null,
      ref: ref || (options.staged ? '--staged' : 'HEAD'),
      changedFiles: changedFiles.map(f => path.relative(absolutePath, f)),
      findings,
      totalFindings: findings.length,
    };
    console.log(JSON.stringify(output, null, 2));
  }

  console.log();
  console.log(chalk.cyan('═'.repeat(60)));
  console.log();

  process.exit(findings.length > 0 ? 1 : 0);
}
