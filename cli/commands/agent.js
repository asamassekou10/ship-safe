/**
 * Agent Command
 * =============
 *
 * AI-powered autonomous security audit.
 * Scans your codebase, classifies findings with Claude, remediates
 * confirmed secrets, then re-scans to verify the project is clean.
 *
 * USAGE:
 *   npx ship-safe agent [path]           Full AI-powered audit
 *   npx ship-safe agent . --dry-run      Preview without writing files
 *   npx ship-safe agent . --model sonnet Use a more capable model
 *
 * REQUIRES:
 *   ANTHROPIC_API_KEY in your environment or .env file.
 *   Falls back to pattern-only remediation if no key is found.
 *
 * FLOW:
 *   scan → classify (Claude) → remediate confirmed → verify clean
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import chalk from 'chalk';
import ora from 'ora';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  TEST_FILE_PATTERNS,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import { remediateCommand } from './remediate.js';
import * as output from '../utils/output.js';

const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';
const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function agentCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  const model = options.model || DEFAULT_MODEL;

  console.log();
  output.header('Ship Safe — AI Security Agent');
  console.log();

  // ── 1. Load API key ────────────────────────────────────────────────────────
  const apiKey = loadApiKey(absolutePath);

  // ── 2. Scan ────────────────────────────────────────────────────────────────
  const scanSpinner = ora({ text: 'Scanning for secrets...', color: 'cyan' }).start();
  const scanResults = await scanProject(absolutePath);
  const totalFindings = scanResults.reduce((n, r) => n + r.findings.length, 0);
  scanSpinner.stop();

  if (totalFindings === 0) {
    output.success('No secrets detected — your project is clean!');
    console.log();
    return;
  }

  console.log(chalk.yellow(`\n  Found ${totalFindings} potential secret(s) in ${scanResults.length} file(s)`));
  console.log();

  // ── 3. Fallback: no API key ────────────────────────────────────────────────
  if (!apiKey) {
    console.log(chalk.yellow('  ⚠  No ANTHROPIC_API_KEY found.'));
    console.log(chalk.gray('     Set it in your environment or .env to enable AI classification.'));
    console.log(chalk.gray('     Falling back to pattern-based remediation...\n'));
    await remediateCommand(targetPath, { yes: true, dryRun: options.dryRun });
    return;
  }

  // ── 4. Classify with Claude ────────────────────────────────────────────────
  const classifySpinner = ora({ text: `Classifying with ${model}...`, color: 'cyan' }).start();
  let classified;

  try {
    classified = await classifyWithClaude(scanResults, absolutePath, apiKey, model);
  } catch (err) {
    classifySpinner.stop();
    console.log(chalk.yellow(`  ⚠  Claude classification failed: ${err.message}`));
    console.log(chalk.gray('     Treating all findings as real secrets (safe fallback).\n'));
    classified = scanResults.map(({ file, findings }) => ({
      file,
      findings: findings.map(f => ({ ...f, classification: 'REAL', reason: 'Classification unavailable' }))
    }));
  }

  classifySpinner.stop();

  // ── 5. Print classification table ─────────────────────────────────────────
  printClassificationTable(classified, absolutePath);

  const realCount = classified.reduce(
    (n, { findings }) => n + findings.filter(f => f.classification === 'REAL').length, 0
  );
  const fpCount = totalFindings - realCount;

  console.log();
  if (realCount === 0) {
    output.success(`Claude classified all ${totalFindings} finding(s) as false positives — nothing to fix!`);
    if (fpCount > 0) {
      console.log(chalk.gray('  Tip: Add # ship-safe-ignore on those lines to suppress future warnings.'));
    }
    console.log();
    return;
  }

  console.log(chalk.cyan(`  ${realCount} confirmed secret(s) will be remediated. ${fpCount > 0 ? chalk.gray(`${fpCount} false positive(s) skipped.`) : ''}`));
  console.log();

  // ── 6. Remediate ──────────────────────────────────────────────────────────
  if (options.dryRun) {
    console.log(chalk.cyan('  Dry run — no files modified. Remove --dry-run to apply fixes.'));
    console.log();
    return;
  }

  await remediateCommand(targetPath, { yes: true });

  // ── 7. Verify ──────────────────────────────────────────────────────────────
  console.log();
  const verifySpinner = ora({ text: 'Re-scanning to verify...', color: 'cyan' }).start();
  const verifyResults = await scanProject(absolutePath);
  const remaining = verifyResults.reduce((n, r) => n + r.findings.length, 0);
  verifySpinner.stop();

  if (remaining === 0) {
    output.success('Verified clean — 0 secrets remain in your codebase!');
  } else {
    output.warning(`${remaining} finding(s) still remain. Review them manually or run npx ship-safe scan .`);
  }

  console.log();
  console.log(chalk.yellow.bold('  Next steps:'));
  console.log(chalk.white('  1.') + chalk.gray(' Rotate any exposed keys: ') + chalk.cyan('npx ship-safe rotate'));
  console.log(chalk.white('  2.') + chalk.gray(' Commit the fixes:        ') + chalk.cyan('git add . && git commit -m "fix: remove hardcoded secrets"'));
  console.log(chalk.white('  3.') + chalk.gray(' Fill in .env with fresh values from your providers'));
  console.log();
}

// =============================================================================
// API KEY LOADING
// =============================================================================

/**
 * Load ANTHROPIC_API_KEY from environment or .env file.
 * Returns the key string or null if not found.
 */
function loadApiKey(rootPath) {
  // 1. Check environment
  if (process.env.ANTHROPIC_API_KEY) {
    return process.env.ANTHROPIC_API_KEY;
  }

  // 2. Try .env file in the project root (simple KEY=value parser — no dotenv needed)
  const envPath = path.join(rootPath, '.env');
  if (fs.existsSync(envPath)) {
    try {
      const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;
        const eqIdx = trimmed.indexOf('=');
        const key = trimmed.slice(0, eqIdx).trim();
        if (key === 'ANTHROPIC_API_KEY') {
          const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
          if (val) return val;
        }
      }
    } catch {
      // ignore read errors
    }
  }

  return null;
}

// =============================================================================
// PROJECT SCANNING
// =============================================================================

/**
 * Scan a project directory for secrets.
 * Returns Array<{ file: string, findings: Finding[] }>
 */
async function scanProject(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

  const allFiles = await fg('**/*', {
    cwd: rootPath,
    absolute: true,
    onlyFiles: true,
    ignore: globIgnore,
    dot: true
  });

  const files = allFiles.filter(file => {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) return false;
    if (TEST_FILE_PATTERNS.some(p => p.test(file))) return false;
    try {
      const stats = fs.statSync(file);
      if (stats.size > MAX_FILE_SIZE) return false;
    } catch {
      return false;
    }
    return true;
  });

  const results = [];
  for (const file of files) {
    const findings = scanFile(file);
    if (findings.length > 0) {
      results.push({ file, findings });
    }
  }
  return results;
}

function scanFile(filePath) {
  const findings = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      if (/ship-safe-ignore/i.test(line)) continue;

      for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
          findings.push({
            line: lineNum + 1,
            column: match.index + 1,
            matched: match[0],
            patternName: pattern.name,
            severity: pattern.severity,
            confidence: getConfidence(pattern, match[0]),
            description: pattern.description
          });
        }
      }
    }
  } catch {
    // Skip unreadable files
  }

  // Deduplicate by (line, matched)
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.line}:${f.matched}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// =============================================================================
// CLAUDE CLASSIFICATION
// =============================================================================

/**
 * Send findings to Claude for classification.
 * Returns the same structure as scanResults but with classification added to each finding.
 */
async function classifyWithClaude(scanResults, rootPath, apiKey, model) {
  // Build items for the prompt — one per finding
  const items = [];
  for (const { file, findings } of scanResults) {
    let lines = [];
    try {
      lines = fs.readFileSync(file, 'utf-8').split('\n');
    } catch {
      // If file can't be read, include finding without context
    }

    for (const finding of findings) {
      const startLine = Math.max(0, finding.line - 3);
      const endLine = Math.min(lines.length - 1, finding.line + 1);
      const context = lines.slice(startLine, endLine + 1).join('\n');

      // Truncate matched value — don't send real secrets to the API
      const matchedPrefix = finding.matched.length > 12
        ? finding.matched.slice(0, 12) + '...'
        : finding.matched;

      items.push({
        id: `${path.relative(rootPath, file)}:${finding.line}`,
        file: path.relative(rootPath, file),
        line: finding.line,
        patternName: finding.patternName,
        severity: finding.severity,
        matchedPrefix,
        codeContext: context
      });
    }
  }

  const prompt = `You are a security expert reviewing potential secret leaks in source code.

For each finding below, classify it as REAL or FALSE_POSITIVE:
- REAL: a genuine hardcoded secret, credential, or API key that should be moved to environment variables
- FALSE_POSITIVE: a placeholder, example value, test fixture, documentation sample, or non-sensitive identifier

Respond with a JSON array ONLY — no markdown, no explanation, just the JSON:
[{"id":"<id>","classification":"REAL"|"FALSE_POSITIVE","reason":"<brief one-line reason>"}]

Findings to classify:
${JSON.stringify(items, null, 2)}`;

  const response = await fetch(ANTHROPIC_API_URL, {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model,
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Anthropic API error ${response.status}: ${body.slice(0, 200)}`);
  }

  const data = await response.json();
  const text = data.content?.[0]?.text || '[]';

  // Strip possible markdown code fences before parsing
  const jsonText = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
  let classifications;
  try {
    classifications = JSON.parse(jsonText);
  } catch {
    throw new Error('Claude returned non-JSON response');
  }

  // Merge classifications back into the scan results structure
  return scanResults.map(({ file, findings }) => ({
    file,
    findings: findings.map(f => {
      const id = `${path.relative(rootPath, file)}:${f.line}`;
      const cl = classifications.find(c => c.id === id);
      return {
        ...f,
        classification: cl?.classification ?? 'REAL', // safe default
        reason: cl?.reason ?? ''
      };
    })
  }));
}

// =============================================================================
// OUTPUT
// =============================================================================

function printClassificationTable(classified, rootPath) {
  const SEVERITY_COLOR = {
    critical: chalk.red.bold,
    high: chalk.yellow,
    medium: chalk.blue
  };

  console.log(chalk.cyan('  Classification Results'));
  console.log(chalk.cyan('  ' + '─'.repeat(58)));
  console.log();

  for (const { file, findings } of classified) {
    const relPath = path.relative(rootPath, file);
    for (const f of findings) {
      const isReal = f.classification === 'REAL';
      const icon = isReal ? chalk.red('✗') : chalk.gray('~');
      const label = isReal ? chalk.red('REAL') : chalk.gray('SKIP');
      const sevColor = SEVERITY_COLOR[f.severity] || chalk.white;
      const matchedShort = f.matched.length > 16 ? f.matched.slice(0, 16) + '…' : f.matched;

      console.log(
        `  ${icon}  ${label.padEnd(8)} ${chalk.white(`${relPath}:${f.line}`).padEnd(40)}  ` +
        `${sevColor(f.patternName.padEnd(24))}  ` +
        chalk.gray(`${matchedShort}`)
      );
      if (f.reason) {
        console.log(chalk.gray(`            → ${f.reason}`));
      }
    }
  }
}
