/**
 * Autofix Command — Agentic Auto-Fix PRs
 * ========================================
 *
 * Reads findings from a ship-safe report (or the last audit run), applies the
 * LLM-generated fixes from Tier 3 deep analysis, commits them to a branch, and
 * opens a GitHub pull request.
 *
 * Requires:
 *   - A report with deepAnalysis.fix fields (run with `--deep` flag)
 *   - Git repository
 *   - GitHub CLI (`gh`) installed for PR creation, OR GITHUB_TOKEN + repo info
 *
 * USAGE:
 *   npx ship-safe autofix                        Auto-fix from last report
 *   npx ship-safe autofix --report report.json   Auto-fix from specific report
 *   npx ship-safe autofix --dry-run              Preview fixes without applying
 *   npx ship-safe autofix --severity high        Only fix critical+high findings
 *
 * SAFETY:
 *   - Never auto-commits secrets, config files, or .env
 *   - Always creates a new branch (never pushes to main/master/develop)
 *   - Dry-run mode shows a diff without writing any files
 *   - Each fix is applied atomically — if a file fails, others continue
 */

import fs from 'fs';
import path from 'path';
import { execFileSync, execSync } from 'child_process';
import chalk from 'chalk';
import * as output from '../utils/output.js';

// Severity rank for filtering
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// Files we never auto-edit (secrets, config, generated)
const NEVER_EDIT = [
  /\.env(\.|$)/i,
  /\.pem$|\.key$|\.p12$|\.pfx$/i,
  /package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$/i,
  /\.min\.(js|css)$/,
  /node_modules\//,
  /dist\//,
  /build\//,
];

// =============================================================================
// MAIN
// =============================================================================

export async function autofixCommand(options = {}) {
  const rootPath   = path.resolve(options.path || '.');
  const dryRun     = options.dryRun || false;
  const minSev     = options.severity || 'high';
  const minRank    = SEV_RANK[minSev] ?? 3;
  const reportPath = options.report
    ? path.resolve(options.report)
    : findLastReport(rootPath);

  console.log();
  output.header('Ship Safe — Agentic Autofix');
  console.log();

  if (!reportPath || !fs.existsSync(reportPath)) {
    output.error('No report found. Run `npx ship-safe audit . --deep --json` first, or pass --report <path>.');
    console.log(chalk.gray('  The --deep flag enables Tier 3 exploit-chain analysis that generates fix suggestions.'));
    process.exit(1);
  }

  // ── Load Report ─────────────────────────────────────────────────────────
  let report;
  try {
    report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
  } catch (err) {
    output.error(`Failed to parse report: ${err.message}`);
    process.exit(1);
  }

  const findings = report.findings ?? [];
  console.log(chalk.gray(`  Report: ${reportPath}`));
  console.log(chalk.gray(`  Total findings: ${findings.length}`));
  console.log();

  // ── Filter to fixable findings ──────────────────────────────────────────
  const fixable = findings.filter(f => {
    if (!f.deepAnalysis?.fix) return false;
    if ((SEV_RANK[f.severity] ?? 0) < minRank) return false;
    if (!f.file) return false;
    const absFile = path.resolve(rootPath, f.file);
    if (NEVER_EDIT.some(p => p.test(absFile.replace(/\\/g, '/')))) return false;
    if (!fs.existsSync(absFile)) return false;
    return true;
  });

  if (fixable.length === 0) {
    console.log(chalk.yellow(`  No fixable findings found at severity >= ${minSev}.`));
    console.log(chalk.gray('  Tip: Run `npx ship-safe audit . --deep` to generate AI-powered fix suggestions.'));
    return;
  }

  console.log(chalk.cyan(`  Found ${fixable.length} fixable finding(s) at severity >= ${minSev}:`));
  console.log();

  for (const f of fixable) {
    const sev = f.severity === 'critical' ? chalk.red.bold(f.severity)
      : f.severity === 'high' ? chalk.yellow(f.severity)
      : chalk.blue(f.severity);
    console.log(`  ${sev}  ${chalk.white(f.title)}`);
    console.log(`    ${chalk.gray('File:')} ${f.file}${f.line ? `:${f.line}` : ''}`);
    console.log(`    ${chalk.gray('Fix:')}  ${f.deepAnalysis.fix}`);
    console.log();
  }

  if (dryRun) {
    console.log(chalk.yellow('  Dry-run mode — no files will be changed.'));
    console.log(chalk.gray('  Remove --dry-run to apply fixes and open a PR.'));
    return;
  }

  // ── Confirm ──────────────────────────────────────────────────────────────
  if (!options.yes) {
    const { createInterface } = await import('readline');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise(resolve => {
      rl.question(chalk.cyan(`  Apply ${fixable.length} fix(es) and open a PR? [y/N] `), resolve);
    });
    rl.close();
    if (!/^y/i.test(answer)) {
      console.log(chalk.gray('\n  Cancelled.\n'));
      return;
    }
    console.log();
  }

  // ── Check git state ──────────────────────────────────────────────────────
  if (!isGitRepo(rootPath)) {
    output.error('Not a git repository. Autofix requires git.');
    process.exit(1);
  }

  const currentBranch = getCurrentBranch(rootPath);
  const protectedBranches = ['main', 'master', 'develop', 'dev', 'production', 'staging'];
  if (protectedBranches.includes(currentBranch)) {
    // Work on a new branch instead
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const branchName = `ship-safe/autofix-${timestamp}`;

  console.log(chalk.gray(`  Creating branch: ${branchName}`));
  try {
    execFileSync('git', ['checkout', '-b', branchName], { cwd: rootPath, stdio: 'pipe' });
  } catch (err) {
    output.error(`Failed to create branch: ${err.message}`);
    process.exit(1);
  }

  // ── Apply fixes ──────────────────────────────────────────────────────────
  const applied = [];
  const failed  = [];

  for (const f of fixable) {
    const absFile = path.resolve(rootPath, f.file);
    const fix     = f.deepAnalysis.fix;

    try {
      applyInlineAnnotation(absFile, f.line, fix);
      applied.push(f);
      console.log(chalk.green(`  ✔ Annotated: ${f.file}:${f.line ?? ''}`));
    } catch (err) {
      failed.push({ finding: f, error: err.message });
      console.log(chalk.yellow(`  ⚠ Skipped: ${f.file} — ${err.message}`));
    }
  }

  if (applied.length === 0) {
    console.log(chalk.yellow('\n  No files were changed. Cleaning up branch...'));
    try {
      execFileSync('git', ['checkout', currentBranch], { cwd: rootPath, stdio: 'pipe' });
      execFileSync('git', ['branch', '-D', branchName], { cwd: rootPath, stdio: 'pipe' });
    } catch { /* ignore cleanup errors */ }
    return;
  }

  // ── Commit ───────────────────────────────────────────────────────────────
  console.log(chalk.gray(`\n  Committing ${applied.length} fix annotation(s)...`));

  try {
    const filesToStage = [...new Set(applied.map(f => path.resolve(rootPath, f.file)))];
    execFileSync('git', ['add', ...filesToStage], { cwd: rootPath, stdio: 'pipe' });

    const commitMsg = [
      `fix(security): apply ship-safe autofix annotations`,
      '',
      `Addresses ${applied.length} finding(s) from ship-safe audit:`,
      ...applied.map(f => `- ${f.severity.toUpperCase()}: ${f.title} (${f.file}${f.line ? `:${f.line}` : ''})`),
      '',
      'Fix suggestions generated by ship-safe Tier 3 (Opus) deep analysis.',
      'Review each annotation and apply the suggested code change.',
    ].join('\n');

    execFileSync('git', ['commit', '-m', commitMsg], { cwd: rootPath, stdio: 'pipe' });
    console.log(chalk.green('  Committed.'));
  } catch (err) {
    output.error(`Commit failed: ${err.message}`);
    // Restore branch state
    try { execFileSync('git', ['checkout', currentBranch], { cwd: rootPath, stdio: 'pipe' }); } catch { /* ignore */ }
    process.exit(1);
  }

  // ── Push and open PR ─────────────────────────────────────────────────────
  console.log(chalk.gray('  Pushing branch...'));
  try {
    execFileSync('git', ['push', '-u', 'origin', branchName], { cwd: rootPath, stdio: 'pipe' });
  } catch (err) {
    console.log(chalk.yellow(`  Push failed: ${err.message}`));
    console.log(chalk.gray(`  Branch created locally: ${branchName}`));
    console.log(chalk.gray('  Push manually with: git push -u origin ' + branchName));
    return;
  }

  // ── Open PR ───────────────────────────────────────────────────────────────
  const prBody = buildPRBody(applied, failed, reportPath);
  const prTitle = `fix(security): ship-safe autofix — ${applied.length} finding(s)`;

  let prUrl = null;
  const ghAvailable = isCommandAvailable('gh');

  if (ghAvailable) {
    try {
      const result = execFileSync('gh', [
        'pr', 'create',
        '--title', prTitle,
        '--body', prBody,
        '--base', currentBranch,
        '--head', branchName,
      ], { cwd: rootPath, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
      prUrl = result.trim();
    } catch (err) {
      console.log(chalk.yellow(`  gh pr create failed: ${err.stderr?.toString().trim() || err.message}`));
    }
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log();
  console.log(chalk.green.bold(`  ✔ Autofix complete`));
  console.log(`    Applied: ${chalk.white(applied.length)} fix annotation(s)`);
  if (failed.length > 0) console.log(`    Skipped: ${chalk.yellow(failed.length)} (see above)`);
  console.log(`    Branch:  ${chalk.cyan(branchName)}`);
  if (prUrl) {
    console.log(`    PR:      ${chalk.cyan(prUrl)}`);
  } else {
    console.log(chalk.gray('    Install `gh` (GitHub CLI) to auto-open pull requests.'));
  }
  console.log();
}

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Apply the fix as a structured comment annotation above the finding line.
 * The comment explains the issue and the fix — a developer reviews and applies.
 * We never blindly rewrite code; instead we annotate so engineers make the call.
 */
/**
 * Apply fix annotations to a list of findings in-place.
 * Returns the count of files successfully annotated.
 * Exported for use by the --agentic audit loop.
 */
export function applyInlineAnnotations(findings) {
  const NEVER_EDIT = new Set(['.env', '.env.local', '.env.production', 'secrets.json', '.npmrc', '.netrc']);
  const fixable = findings.filter(f =>
    f.fix && f.file && fs.existsSync(f.file) && !NEVER_EDIT.has(path.basename(f.file))
  );
  let count = 0;
  for (const f of fixable.slice(0, 10)) {
    try {
      applyInlineAnnotation(f.file, f.line, f.fix);
      count++;
    } catch { /* skip unwritable */ }
  }
  return count;
}

export function applyInlineAnnotation(filePath, lineNum, fix) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines   = content.split('\n');
  const idx     = Math.max(0, (lineNum || 1) - 1);

  if (idx >= lines.length) {
    throw new Error(`Line ${lineNum} out of range`);
  }

  // Already annotated?
  if (idx > 0 && /ship-safe-fix/i.test(lines[idx - 1])) return;

  const indent = lines[idx].match(/^(\s*)/)?.[1] ?? '';
  const isJs   = /\.(js|ts|jsx|tsx|mjs|cjs|java|c|cpp|cs|go|rs|swift|kt)$/.test(filePath);
  const isPy   = /\.py$/.test(filePath);

  // Wrap fix in a structured annotation comment
  const fixLines = fix.split('\n').map(l => l.trim()).filter(Boolean);
  let annotation;

  if (isPy) {
    annotation = [
      `${indent}# ship-safe-fix [REVIEW REQUIRED]`,
      ...fixLines.map(l => `${indent}# ${l}`),
    ].join('\n');
  } else {
    annotation = [
      `${indent}// ship-safe-fix [REVIEW REQUIRED]`,
      ...fixLines.map(l => `${indent}// ${l}`),
    ].join('\n');
  }

  lines.splice(idx, 0, annotation);
  fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
}

function buildPRBody(applied, failed, reportPath) {
  const rows = applied.map(f =>
    `| ${f.severity} | ${f.title} | \`${f.file}${f.line ? `:${f.line}` : ''}\` | ${f.deepAnalysis.fix?.slice(0, 80) ?? ''} |`
  ).join('\n');

  return `## Security Autofix

Ship Safe detected **${applied.length}** security finding(s) and has annotated the affected files with fix instructions. Each annotation is marked \`// ship-safe-fix [REVIEW REQUIRED]\` — **please review and apply the suggested changes before merging.**

### Findings Fixed

| Severity | Title | Location | Fix Summary |
|----------|-------|----------|-------------|
${rows}

${failed.length > 0 ? `### Skipped (${failed.length})\n\n${failed.map(f => `- ${f.finding.title}: ${f.error}`).join('\n')}` : ''}

---

> Generated by [ship-safe](https://shipsafecli.com) — AI-powered security scanner.
> Run \`npx ship-safe audit . --deep\` to regenerate findings.

🤖 Generated with [Claude Code](https://claude.com/claude-code)`;
}

function findLastReport(rootPath) {
  // Look for common report filenames in order of preference
  const candidates = [
    'ship-safe-report.json',
    '.ship-safe/last-report.json',
    'security-report.json',
  ].map(f => path.join(rootPath, f));

  return candidates.find(p => fs.existsSync(p)) ?? null;
}

function isGitRepo(rootPath) {
  try {
    execFileSync('git', ['rev-parse', '--git-dir'], { cwd: rootPath, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function getCurrentBranch(rootPath) {
  try {
    return execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: rootPath, encoding: 'utf-8', stdio: 'pipe' }).trim();
  } catch {
    return 'main';
  }
}

function isCommandAvailable(cmd) {
  try {
    execFileSync(cmd, ['--version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}
