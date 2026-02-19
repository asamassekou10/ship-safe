/**
 * Agent Command
 * =============
 *
 * AI-powered autonomous security audit.
 * Scans for secrets AND code vulnerabilities, classifies findings with Claude,
 * remediates confirmed secrets, and provides specific fix suggestions for
 * confirmed code vulnerabilities.
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
 *   scan (secrets + vulns)
 *     → classify secrets (REAL/FP) → remediate confirmed secrets
 *     → classify vulns (REAL/FP + fix suggestion) → print fix table
 *     → re-scan to verify secrets clean
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

  // ── 2. Scan (secrets + vulnerabilities) ────────────────────────────────────
  const scanSpinner = ora({ text: 'Scanning for secrets and vulnerabilities...', color: 'cyan' }).start();
  const allResults = await scanProject(absolutePath);

  // Separate findings by category
  const secretResults = [];
  const vulnResults = [];
  for (const { file, findings } of allResults) {
    const secrets = findings.filter(f => f.category !== 'vulnerability');
    const vulns = findings.filter(f => f.category === 'vulnerability');
    if (secrets.length > 0) secretResults.push({ file, findings: secrets });
    if (vulns.length > 0) vulnResults.push({ file, findings: vulns });
  }

  const secretCount = secretResults.reduce((n, r) => n + r.findings.length, 0);
  const vulnCount = vulnResults.reduce((n, r) => n + r.findings.length, 0);
  scanSpinner.stop();

  // ── 3. Nothing found ───────────────────────────────────────────────────────
  if (secretCount === 0 && vulnCount === 0) {
    output.success('No secrets or vulnerabilities detected — your project is clean!');
    console.log();
    return;
  }

  if (secretCount > 0) {
    console.log(chalk.red(`\n  Found ${secretCount} potential secret(s) in ${secretResults.length} file(s)`));
  }
  if (vulnCount > 0) {
    console.log(chalk.yellow(`  Found ${vulnCount} code vulnerability/vulnerabilities in ${vulnResults.length} file(s)`));
  }
  console.log();

  // ── 4. Fallback: no API key ────────────────────────────────────────────────
  if (!apiKey) {
    console.log(chalk.yellow('  ⚠  No ANTHROPIC_API_KEY found.'));
    console.log(chalk.gray('     Set it in your environment or .env to enable AI classification.'));
    if (secretCount > 0) {
      console.log(chalk.gray('     Falling back to pattern-based remediation for secrets...\n'));
      await remediateCommand(targetPath, { yes: true, dryRun: options.dryRun });
    }
    if (vulnCount > 0) {
      console.log(chalk.gray('\n     Code vulnerabilities require manual review.'));
      console.log(chalk.gray('     Run: ') + chalk.cyan('npx ship-safe scan .') + chalk.gray(' to see details.'));
    }
    return;
  }

  // ── 5. Classify secrets ────────────────────────────────────────────────────
  if (secretCount > 0) {
    const classifySpinner = ora({ text: `Classifying ${secretCount} secret(s) with ${model}...`, color: 'cyan' }).start();
    let classifiedSecrets;

    try {
      classifiedSecrets = await classifyWithClaude(secretResults, absolutePath, apiKey, model);
    } catch (err) {
      classifySpinner.stop();
      console.log(chalk.yellow(`  ⚠  Claude secret classification failed: ${err.message}`));
      console.log(chalk.gray('     Treating all findings as real secrets (safe fallback).\n'));
      classifiedSecrets = secretResults.map(({ file, findings }) => ({
        file,
        findings: findings.map(f => ({ ...f, classification: 'REAL', reason: 'Classification unavailable' }))
      }));
    }

    classifySpinner.stop();

    // ── 6. Print secret classification table ──────────────────────────────
    printClassificationTable(classifiedSecrets, absolutePath);

    const realSecretCount = classifiedSecrets.reduce(
      (n, { findings }) => n + findings.filter(f => f.classification === 'REAL').length, 0
    );
    const fpCount = secretCount - realSecretCount;

    console.log();
    if (realSecretCount === 0) {
      output.success(`Claude classified all ${secretCount} secret finding(s) as false positives — nothing to fix!`);
      if (fpCount > 0) {
        console.log(chalk.gray('  Tip: Add # ship-safe-ignore on those lines to suppress future warnings.'));
      }
    } else {
      console.log(chalk.cyan(`  ${realSecretCount} confirmed secret(s) to remediate.${fpCount > 0 ? chalk.gray(` ${fpCount} false positive(s) skipped.`) : ''}`));
      console.log();

      // ── 7. Remediate confirmed secrets ──────────────────────────────────
      if (options.dryRun) {
        console.log(chalk.cyan('  Dry run — secrets not modified. Remove --dry-run to apply fixes.'));
      } else {
        await remediateCommand(targetPath, { yes: true });
      }
    }
  }

  // ── 8. Classify vulnerabilities ────────────────────────────────────────────
  if (vulnCount > 0) {
    console.log();
    const vulnSpinner = ora({
      text: `Analyzing ${vulnCount} vulnerability/vulnerabilities with ${model}...`,
      color: 'cyan'
    }).start();
    let classifiedVulns;

    try {
      classifiedVulns = await classifyVulnsWithClaude(vulnResults, absolutePath, apiKey, model);
    } catch (err) {
      vulnSpinner.stop();
      console.log(chalk.yellow(`  ⚠  Claude vulnerability analysis failed: ${err.message}`));
      console.log(chalk.gray('     Showing raw findings without AI fix suggestions.\n'));
      classifiedVulns = vulnResults.map(({ file, findings }) => ({
        file,
        findings: findings.map(f => ({ ...f, classification: 'REAL', reason: 'Analysis unavailable', fix: null }))
      }));
    }

    vulnSpinner.stop();

    // ── 9. Print vulnerability fix table ──────────────────────────────────
    printVulnFixTable(classifiedVulns, absolutePath);
  }

  // ── 10. Verify secrets clean ───────────────────────────────────────────────
  if (secretCount > 0 && !options.dryRun) {
    console.log();
    const verifySpinner = ora({ text: 'Re-scanning to verify secrets removed...', color: 'cyan' }).start();
    const verifyResults = await scanProject(absolutePath);
    const remainingSecrets = verifyResults.reduce(
      (n, r) => n + r.findings.filter(f => f.category !== 'vulnerability').length, 0
    );
    verifySpinner.stop();

    if (remainingSecrets === 0) {
      output.success('Secrets verified clean — 0 remain in your codebase!');
    } else {
      output.warning(`${remainingSecrets} secret(s) still remain. Review them manually or run npx ship-safe scan .`);
    }
  }

  // ── 11. Next steps ─────────────────────────────────────────────────────────
  console.log();
  console.log(chalk.yellow.bold('  Next steps:'));
  let step = 1;
  if (secretCount > 0) {
    console.log(chalk.white(`  ${step++}.`) + chalk.gray(' Rotate any exposed keys:   ') + chalk.cyan('npx ship-safe rotate'));
    console.log(chalk.white(`  ${step++}.`) + chalk.gray(' Commit the fixes:          ') + chalk.cyan('git add . && git commit -m "fix: remove hardcoded secrets"'));
    console.log(chalk.white(`  ${step++}.`) + chalk.gray(' Fill in .env with fresh values from your providers'));
  }
  if (vulnCount > 0) {
    console.log(chalk.white(`  ${step++}.`) + chalk.gray(' Apply the code fixes shown above, then re-run: ') + chalk.cyan('npx ship-safe agent .'));
  }
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
  if (process.env.ANTHROPIC_API_KEY) {
    return process.env.ANTHROPIC_API_KEY;
  }

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
// PROJECT SCANNING (secrets + vulnerabilities)
// =============================================================================

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

      for (const pattern of [...SECRET_PATTERNS, ...SECURITY_PATTERNS]) {
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
            description: pattern.description,
            category: pattern.category || 'secret'
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
// CLAUDE CLASSIFICATION — SECRETS
// =============================================================================

async function classifyWithClaude(scanResults, rootPath, apiKey, model) {
  const items = [];
  for (const { file, findings } of scanResults) {
    let lines = [];
    try {
      lines = fs.readFileSync(file, 'utf-8').split('\n');
    } catch {
      // include without context
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
  const jsonText = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
  let classifications;
  try {
    classifications = JSON.parse(jsonText);
  } catch {
    throw new Error('Claude returned non-JSON response');
  }

  return scanResults.map(({ file, findings }) => ({
    file,
    findings: findings.map(f => {
      const id = `${path.relative(rootPath, file)}:${f.line}`;
      const cl = classifications.find(c => c.id === id);
      return {
        ...f,
        classification: cl?.classification ?? 'REAL',
        reason: cl?.reason ?? ''
      };
    })
  }));
}

// =============================================================================
// CLAUDE CLASSIFICATION — VULNERABILITIES
// =============================================================================

/**
 * Send vulnerability findings to Claude for classification + specific fix suggestions.
 * Unlike secrets, code context is NOT masked — the pattern itself is the finding.
 */
async function classifyVulnsWithClaude(vulnResults, rootPath, apiKey, model) {
  const items = [];
  for (const { file, findings } of vulnResults) {
    let lines = [];
    try {
      lines = fs.readFileSync(file, 'utf-8').split('\n');
    } catch {
      // include without context
    }

    for (const finding of findings) {
      const startLine = Math.max(0, finding.line - 3);
      const endLine = Math.min(lines.length - 1, finding.line + 1);
      const context = lines.slice(startLine, endLine + 1).join('\n');

      items.push({
        id: `${path.relative(rootPath, file)}:${finding.line}`,
        file: path.relative(rootPath, file),
        line: finding.line,
        type: finding.patternName,
        severity: finding.severity,
        codeContext: context  // Not masked — it's a code pattern, not a secret
      });
    }
  }

  const prompt = `You are a security expert reviewing code vulnerabilities.

For each finding below, classify it and provide a specific fix if it's a real issue.

- REAL: genuinely exploitable as written (user-controlled input reaches a dangerous sink)
- FALSE_POSITIVE: safe in this context (static/hardcoded input, internal tool, test code, build script)

For REAL findings: provide a concise, specific 1-line code fix showing what to change.
For FALSE_POSITIVE: briefly explain why it's safe.

Respond with a JSON array ONLY — no markdown, no explanation:
[{"id":"<id>","classification":"REAL"|"FALSE_POSITIVE","reason":"<brief reason>","fix":"<specific fix code, or null>"}]

Vulnerabilities to analyze:
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
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Anthropic API error ${response.status}: ${body.slice(0, 200)}`);
  }

  const data = await response.json();
  const text = data.content?.[0]?.text || '[]';
  const jsonText = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
  let classifications;
  try {
    classifications = JSON.parse(jsonText);
  } catch {
    throw new Error('Claude returned non-JSON response');
  }

  return vulnResults.map(({ file, findings }) => ({
    file,
    findings: findings.map(f => {
      const id = `${path.relative(rootPath, file)}:${f.line}`;
      const cl = classifications.find(c => c.id === id);
      return {
        ...f,
        classification: cl?.classification ?? 'REAL',
        reason: cl?.reason ?? '',
        fix: cl?.fix ?? null
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

  console.log(chalk.cyan('  Secret Classification'));
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
        chalk.gray(matchedShort)
      );
      if (f.reason) {
        console.log(chalk.gray(`            → ${f.reason}`));
      }
    }
  }
}

function printVulnFixTable(classifiedVulns, rootPath) {
  const SEVERITY_COLOR = {
    critical: chalk.red.bold,
    high: chalk.yellow,
    medium: chalk.blue
  };

  const totalCount = classifiedVulns.reduce((n, { findings }) => n + findings.length, 0);
  const realCount = classifiedVulns.reduce(
    (n, { findings }) => n + findings.filter(f => f.classification === 'REAL').length, 0
  );
  const fpCount = totalCount - realCount;

  console.log(chalk.yellow('  Code Vulnerability Analysis'));
  console.log(chalk.yellow('  ' + '─'.repeat(58)));
  console.log();

  for (const { file, findings } of classifiedVulns) {
    const relPath = path.relative(rootPath, file);
    for (const f of findings) {
      const isReal = f.classification === 'REAL';
      const icon = isReal ? chalk.red('✗') : chalk.gray('~');
      const label = isReal ? chalk.red('REAL') : chalk.gray('SKIP');
      const sevColor = SEVERITY_COLOR[f.severity] || chalk.white;
      const snippet = f.matched.length > 55 ? f.matched.slice(0, 55) + '…' : f.matched;

      console.log(
        `  ${icon}  ${label.padEnd(8)} ${chalk.white(`${relPath}:${f.line}`).padEnd(38)}  ` +
        sevColor(`[${f.severity.toUpperCase()}]`)
      );
      console.log(chalk.gray(`            ${f.patternName}`));
      console.log(chalk.gray('     Code:   ') + chalk.cyan(snippet));
      if (f.reason) {
        console.log(chalk.gray(`     Reason: ${f.reason}`));
      }
      if (isReal && f.fix) {
        console.log(chalk.gray('     Fix:    ') + chalk.green(f.fix));
      }
      console.log();
    }
  }

  if (realCount === 0) {
    output.success(`Claude classified all ${totalCount} vulnerability/vulnerabilities as false positives!`);
    console.log(chalk.gray('  Tip: Add # ship-safe-ignore on those lines to suppress future warnings.'));
  } else {
    console.log(chalk.yellow(`  ${realCount} real vulnerability/vulnerabilities require manual fixes.${fpCount > 0 ? chalk.gray(` ${fpCount} false positive(s) skipped.`) : ''}`));
  }
}
