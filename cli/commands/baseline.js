/**
 * Baseline Command
 * =================
 *
 * Accept current findings as a baseline and only report new findings
 * on subsequent scans. This is how teams adopt security scanners:
 * baseline existing debt, focus on not making it worse.
 *
 * USAGE:
 *   ship-safe baseline .          Create a new baseline from current scan
 *   ship-safe baseline . --diff   Show what changed since baseline
 *   ship-safe baseline . --clear  Remove the baseline
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { buildOrchestrator } from '../agents/index.js';
import { SECRET_PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS, MAX_FILE_SIZE } from '../utils/patterns.js';
import { isHighEntropyMatch } from '../utils/entropy.js';
import fg from 'fast-glob';

const BASELINE_FILE = '.ship-safe/baseline.json';

/**
 * Generate a fingerprint for a finding that survives line-number shifts.
 * Uses rule + relative file path + first 40 chars of matched text.
 */
function fingerprint(finding, rootPath) {
  const relFile = path.relative(rootPath, finding.file || '').replace(/\\/g, '/');
  const matched = (finding.matched || '').slice(0, 40);
  return `${finding.rule}:${relFile}:${matched}`;
}

/**
 * Quick secret scan (same as audit Phase 1) to get current findings.
 */
async function quickScan(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true,
  });

  const filtered = files.filter(f => {
    const ext = path.extname(f).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    try { return fs.statSync(f).size <= MAX_FILE_SIZE; } catch { return false; }
  });

  const findings = [];
  for (const file of filtered) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/ship-safe-ignore/i.test(lines[i])) continue;
        for (const p of SECRET_PATTERNS) {
          p.pattern.lastIndex = 0;
          let m;
          while ((m = p.pattern.exec(lines[i])) !== null) {
            if (p.requiresEntropyCheck && !isHighEntropyMatch(m[0])) continue;
            findings.push({ file, line: i + 1, rule: p.name, matched: m[0], severity: p.severity });
          }
        }
      }
    } catch { /* skip */ }
  }

  return { findings, files: filtered };
}

/**
 * Run agents and combine with secret scan findings.
 */
async function fullScan(rootPath) {
  const { findings: secretFindings, files } = await quickScan(rootPath);

  const orchestrator = buildOrchestrator();
  const { findings: agentFindings } = await orchestrator.runAll(rootPath, { quiet: true });

  return [...secretFindings, ...agentFindings];
}

/**
 * Load existing baseline from disk.
 */
function loadBaseline(rootPath) {
  const baselinePath = path.join(rootPath, BASELINE_FILE);
  if (!fs.existsSync(baselinePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(baselinePath, 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * Save baseline to disk.
 */
function saveBaseline(rootPath, fingerprints, findingCount) {
  const baselinePath = path.join(rootPath, BASELINE_FILE);
  const dir = path.dirname(baselinePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const baseline = {
    version: '4.3.0',
    createdAt: new Date().toISOString(),
    fingerprints,
    findingCount,
  };

  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
  return baseline;
}

/**
 * Filter out baselined findings. Returns only new findings.
 */
export function filterBaseline(findings, rootPath) {
  const baseline = loadBaseline(rootPath);
  if (!baseline) return findings;

  const baseSet = new Set(baseline.fingerprints);
  return findings.filter(f => !baseSet.has(fingerprint(f, rootPath)));
}

/**
 * Main baseline command.
 */
export async function baselineCommand(targetPath = '.', options = {}) {
  const rootPath = path.resolve(targetPath);

  if (options.clear) {
    const baselinePath = path.join(rootPath, BASELINE_FILE);
    if (fs.existsSync(baselinePath)) {
      fs.unlinkSync(baselinePath);
      console.log(chalk.green('  Baseline removed.'));
    } else {
      console.log(chalk.gray('  No baseline found.'));
    }
    return;
  }

  if (options.diff) {
    const baseline = loadBaseline(rootPath);
    if (!baseline) {
      console.log(chalk.yellow('  No baseline found. Run `ship-safe baseline .` first.'));
      return;
    }

    const spinner = ora({ text: 'Scanning for comparison...', color: 'cyan' }).start();
    const findings = await fullScan(rootPath);
    spinner.stop();

    const currentFingerprints = new Set(findings.map(f => fingerprint(f, rootPath)));
    const baseSet = new Set(baseline.fingerprints);

    const newFindings = findings.filter(f => !baseSet.has(fingerprint(f, rootPath)));
    const resolvedCount = baseline.fingerprints.filter(fp => !currentFingerprints.has(fp)).length;

    console.log(chalk.cyan.bold('\n  Baseline Comparison'));
    console.log(chalk.gray(`  Baseline: ${baseline.findingCount} findings (${baseline.createdAt.slice(0, 10)})`));
    console.log(chalk.gray(`  Current:  ${findings.length} findings`));
    console.log();
    if (newFindings.length > 0) {
      console.log(chalk.red(`  + ${newFindings.length} new finding(s)`));
    }
    if (resolvedCount > 0) {
      console.log(chalk.green(`  - ${resolvedCount} resolved finding(s)`));
    }
    if (newFindings.length === 0 && resolvedCount === 0) {
      console.log(chalk.green('  No changes since baseline.'));
    }
    return;
  }

  // Default: create/update baseline
  const spinner = ora({ text: 'Running full scan for baseline...', color: 'cyan' }).start();
  const findings = await fullScan(rootPath);
  spinner.stop();

  const fingerprints = [...new Set(findings.map(f => fingerprint(f, rootPath)))];
  const baseline = saveBaseline(rootPath, fingerprints, findings.length);

  console.log(chalk.green.bold('\n  Baseline created'));
  console.log(chalk.gray(`  Findings baselined: ${findings.length}`));
  console.log(chalk.gray(`  Unique fingerprints: ${fingerprints.length}`));
  console.log(chalk.gray(`  Saved to: ${BASELINE_FILE}`));
  console.log();
  console.log(chalk.gray('  Run `ship-safe audit . --baseline` to only see new findings.'));
}
