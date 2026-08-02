/**
 * Vibe Check Command
 * ==================
 *
 * Fun, emoji-rich security check with shareable results.
 * Same security scan as `audit`, but with personality.
 *
 * USAGE:
 *   npx ship-safe vibe-check [path]     Run a vibe check
 *   npx ship-safe vibe-check . --badge  Generate a markdown badge
 *
 * OUTPUT:
 *   Big ASCII art grade, emoji severity indicators,
 *   "vibes" rating, and a shareable one-liner.
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import { runDepsAudit } from './deps.js';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  SKIP_FILENAMES,
  MAX_FILE_SIZE,
  loadGitignorePatterns
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import fg from 'fast-glob';

// =============================================================================
// VIBES DATA
// =============================================================================

const VIBE_GRADES = {
  A: {
    emoji: '🛡️',
    vibe: 'immaculate',
    ascii: `
    ╔═══╗
    ║ A ║
    ╚═══╝`,
    message: 'Your security vibes are IMMACULATE. Ship it! 🚀',
    color: chalk.green.bold,
  },
  B: {
    emoji: '✅',
    vibe: 'solid',
    ascii: `
    ╔═══╗
    ║ B ║
    ╚═══╝`,
    message: 'Solid vibes. A few things to tighten up, but you\'re in good shape. 💪',
    color: chalk.cyan.bold,
  },
  C: {
    emoji: '⚠️',
    vibe: 'mid',
    ascii: `
    ╔═══╗
    ║ C ║
    ╚═══╝`,
    message: 'Mid vibes. Some security gaps need attention before you ship. 🔧',
    color: chalk.yellow.bold,
  },
  D: {
    emoji: '🚨',
    vibe: 'sketchy',
    ascii: `
    ╔═══╗
    ║ D ║
    ╚═══╝`,
    message: 'Sketchy vibes. Serious issues found — fix these before deploying. 🛑',
    color: chalk.red.bold,
  },
  F: {
    emoji: '💀',
    vibe: 'cooked',
    ascii: `
    ╔═══╗
    ║ F ║
    ╚═══╝`,
    message: 'You are cooked. Critical vulnerabilities everywhere. DO NOT SHIP. 🔥',
    color: chalk.red.bold,
  },
};

const SEV_EMOJI = {
  critical: '💀',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
};

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function vibeCheckCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    console.error(chalk.red(`Path does not exist: ${absolutePath}`));
    process.exit(1);
  }

  const projectName = path.basename(absolutePath);

  console.log();
  console.log(chalk.cyan.bold('  🎵 VIBE CHECK 🎵'));
  console.log(chalk.gray(`  Scanning ${projectName}...`));
  console.log();

  const startTime = Date.now();

  // ── Secret Scan ──────────────────────────────────────────────────────────
  const spinner = ora({ text: 'Checking the vibes...', color: 'magenta' }).start();

  const allFiles = await findFiles(absolutePath);
  const secretFindings = [];

  for (const file of allFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');
      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        if (/ship-safe-ignore/i.test(line)) continue;
        for (const pattern of SECRET_PATTERNS) {
          pattern.pattern.lastIndex = 0;
          let match;
          while ((match = pattern.pattern.exec(line)) !== null) {
            if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
            secretFindings.push({
              file, line: lineNum + 1, column: match.index + 1,
              matched: match[0], severity: pattern.severity,
              category: pattern.category || 'secrets',
              rule: pattern.name, title: pattern.name.replace(/_/g, ' '),
              description: pattern.description,
              confidence: getConfidence(pattern, match[0]),
            });
          }
        }
      }
    } catch { /* skip */ }
  }

  // ── Agent Scan ──────────────────────────────────────────────────────────
  const orchestrator = buildOrchestrator();
  const results = await orchestrator.runAll(absolutePath, { quiet: true });

  // ── Dependency Audit ─────────────────────────────────────────────────────
  let depVulns = [];
  try {
    const depResult = await runDepsAudit(absolutePath);
    depVulns = depResult.vulns || [];
  } catch { /* skip */ }

  spinner.stop();

  // ── Merge & Score ─────────────────────────────────────────────────────────
  const seen = new Set();
  const allFindings = [...secretFindings, ...results.findings].filter(f => {
    const key = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const scoringEngine = new ScoringEngine();
  const scoreResult = scoringEngine.compute(allFindings, depVulns);
  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  // ── Display ──────────────────────────────────────────────────────────────
  const grade = VIBE_GRADES[scoreResult.grade.letter] || VIBE_GRADES.F;
  const score = Math.round(scoreResult.score * 10) / 10;

  const critical = allFindings.filter(f => f.severity === 'critical').length;
  const high = allFindings.filter(f => f.severity === 'high').length;
  const medium = allFindings.filter(f => f.severity === 'medium').length;
  const low = allFindings.filter(f => f.severity === 'low').length;

  // Big grade display
  console.log(grade.color(grade.ascii));
  console.log();
  console.log(grade.color(`  ${grade.emoji}  Score: ${score}/100  |  Vibes: ${grade.vibe.toUpperCase()}`));
  console.log();
  console.log(grade.color(`  ${grade.message}`));
  console.log();

  // Severity breakdown
  console.log(chalk.white.bold('  Breakdown:'));
  if (critical > 0) console.log(`    ${SEV_EMOJI.critical} Critical: ${critical}`);
  if (high > 0) console.log(`    ${SEV_EMOJI.high} High: ${high}`);
  if (medium > 0) console.log(`    ${SEV_EMOJI.medium} Medium: ${medium}`);
  if (low > 0) console.log(`    ${SEV_EMOJI.low} Low: ${low}`);
  if (depVulns.length > 0) console.log(`    📦 Dep CVEs: ${depVulns.length}`);
  if (allFindings.length === 0 && depVulns.length === 0) {
    console.log(`    ✨ Zero issues found!`);
  }
  console.log(chalk.gray(`    ⏱️  ${duration}s`));
  console.log();

  // Top 3 issues
  if (allFindings.length > 0) {
    console.log(chalk.white.bold('  Top issues to fix:'));
    const top = allFindings
      .sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      })
      .slice(0, 3);
    for (const f of top) {
      const rel = path.relative(absolutePath, f.file).replace(/\\/g, '/');
      console.log(`    ${SEV_EMOJI[f.severity] || '⚪'} ${f.title || f.rule} ${chalk.gray(`(${rel}:${f.line})`)}`);
    }
    console.log();
  }

  // ── Shareable one-liner ──────────────────────────────────────────────────
  const shareLine = `${grade.emoji} ${projectName}: ${score}/100 (${scoreResult.grade.letter}) — ${grade.vibe} vibes | ${allFindings.length} findings | Scanned with Ship Safe`;
  console.log(chalk.gray('  Share your vibes:'));
  console.log(chalk.cyan(`  ${shareLine}`));
  console.log();

  // ── Badge ─────────────────────────────────────────────────────────────────
  if (options.badge) {
    const badgeColor = {
      A: 'brightgreen', B: 'blue', C: 'yellow', D: 'orange', F: 'red',
    }[scoreResult.grade.letter] || 'lightgrey';
    const badgeUrl = `https://img.shields.io/badge/ship--safe-${score}%2F100_${scoreResult.grade.letter}-${badgeColor}`;
    const badgeMd = `[![Ship Safe Score](${badgeUrl})](https://shipsafe.sh)`;

    console.log(chalk.white.bold('  Markdown badge:'));
    console.log(chalk.cyan(`  ${badgeMd}`));
    console.log();

    // Write badge to README if it exists and doesn't have one already
    const readmePath = path.join(absolutePath, 'README.md');
    if (fs.existsSync(readmePath)) {
      const readme = fs.readFileSync(readmePath, 'utf-8');
      if (!readme.includes('ship--safe')) {
        console.log(chalk.gray('  Add this badge to your README.md to show off your security score!'));
      }
    }
  }

  process.exit(allFindings.length > 0 || depVulns.length > 0 ? 1 : 0);
}

// =============================================================================
// FILE FINDER (reused from CI)
// =============================================================================

async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const gitignoreGlobs = loadGitignorePatterns(rootPath);
  globIgnore.push(...gitignoreGlobs);

  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true,
  });

  return files.filter(file => {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    if (SKIP_FILENAMES.has(path.basename(file))) return false;
    if (path.basename(file).endsWith('.min.js') || path.basename(file).endsWith('.min.css')) return false;
    try { if (fs.statSync(file).size > MAX_FILE_SIZE) return false; } catch { return false; }
    return true;
  });
}
