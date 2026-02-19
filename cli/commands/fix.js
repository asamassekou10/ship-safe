/**
 * Fix Command
 * ===========
 *
 * Scans for secrets and generates a .env.example file with placeholder values.
 * Also shows a summary of what to move to environment variables.
 *
 * USAGE:
 *   ship-safe fix             Scan and generate .env.example
 *   ship-safe fix --dry-run   Preview what would be generated (don't write file)
 */

import fs from 'fs';
import path from 'path';
import ora from 'ora';
import chalk from 'chalk';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  TEST_FILE_PATTERNS,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import { isHighEntropyMatch } from '../utils/entropy.js';
import fg from 'fast-glob';
import * as output from '../utils/output.js';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function fixCommand(options = {}) {
  const cwd = process.cwd();

  const spinner = ora({ text: 'Scanning for secrets...', color: 'cyan' }).start();

  try {
    const files = await findFiles(cwd);
    const results = [];

    for (const file of files) {
      const findings = await scanFile(file);
      if (findings.length > 0) {
        results.push({ file, findings });
      }
    }

    spinner.stop();

    if (results.length === 0) {
      output.success('No secrets found — nothing to fix!');
      console.log(chalk.gray('\nYour codebase looks clean. Keep it that way with:'));
      console.log(chalk.gray('  npx ship-safe guard   # Block pushes if secrets are found'));
      return;
    }

    // Build env var suggestions from findings
    const envVars = buildEnvVarSuggestions(results);

    output.header('Fix Report');
    printFindings(results, cwd);
    printEnvExample(envVars, options.dryRun);

  } catch (err) {
    spinner.fail('Fix scan failed');
    output.error(err.message);
    process.exit(1);
  }
}

// =============================================================================
// SCAN (same logic as scan command, reused here)
// =============================================================================

async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true
  });

  const filtered = [];
  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) continue;
    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) continue;
    if (TEST_FILE_PATTERNS.some(p => p.test(file))) continue;
    if (basename === '.env.example') continue; // Don't scan example files
    try {
      const stats = fs.statSync(file);
      if (stats.size > MAX_FILE_SIZE) continue;
    } catch { continue; }
    filtered.push(file);
  }
  return filtered;
}

async function scanFile(filePath) {
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
            matched: match[0],
            patternName: pattern.name,
            severity: pattern.severity,
          });
        }
      }
    }
  } catch {}
  return findings;
}

// =============================================================================
// ENV VAR GENERATION
// =============================================================================

function buildEnvVarSuggestions(results) {
  const seen = new Set();
  const vars = [];

  for (const { findings } of results) {
    for (const f of findings) {
      const varName = patternToEnvVar(f.patternName);
      if (!seen.has(varName)) {
        seen.add(varName);
        vars.push({ name: varName, comment: f.patternName });
      }
    }
  }

  return vars;
}

/**
 * Convert a pattern name to a sensible env var name.
 * e.g. "OpenAI API Key" → "OPENAI_API_KEY"
 */
function patternToEnvVar(patternName) {
  return patternName
    .toUpperCase()
    .replace(/[^A-Z0-9\s]/g, '')
    .trim()
    .replace(/\s+/g, '_');
}

// =============================================================================
// OUTPUT
// =============================================================================

function printFindings(results, rootPath) {
  const total = results.reduce((sum, r) => sum + r.findings.length, 0);
  console.log(chalk.red.bold(`\n  Found ${total} secret(s) across ${results.length} file(s)\n`));

  for (const { file, findings } of results) {
    const relPath = path.relative(rootPath, file);
    console.log(chalk.white.bold(`  ${relPath}`));
    for (const f of findings) {
      console.log(chalk.gray(`    Line ${f.line}: `) + chalk.yellow(f.patternName));
    }
  }
}

function printEnvExample(envVars, dryRun) {
  const lines = [
    '# .env.example',
    '# Generated by ship-safe — replace placeholder values with your actual secrets.',
    '# Copy this file to .env and fill in the values.',
    '# NEVER commit .env — only commit .env.example',
    '',
  ];

  for (const { name, comment } of envVars) {
    lines.push(`# ${comment}`);
    lines.push(`${name}=your_${name.toLowerCase()}_here`);
    lines.push('');
  }

  const content = lines.join('\n');

  output.header(dryRun ? '.env.example Preview (dry run)' : 'Generated .env.example');
  console.log();
  console.log(chalk.gray(content));

  if (!dryRun) {
    const envExamplePath = path.join(process.cwd(), '.env.example');

    if (fs.existsSync(envExamplePath)) {
      output.warning('.env.example already exists — skipping. Use --force to overwrite.');
    } else {
      fs.writeFileSync(envExamplePath, content);
      output.success('Created .env.example');
    }

    console.log();
    console.log(chalk.cyan.bold('Next steps:'));
    console.log(chalk.white('1.') + chalk.gray(' Copy .env.example to .env'));
    console.log(chalk.white('2.') + chalk.gray(' Replace placeholder values with your real secrets'));
    console.log(chalk.white('3.') + chalk.gray(' Remove the hardcoded values from your source code'));
    console.log(chalk.white('4.') + chalk.gray(' Verify .env is in your .gitignore'));
    console.log(chalk.white('5.') + chalk.gray(' Run npx ship-safe scan . to confirm clean'));
    console.log();
  }
}
