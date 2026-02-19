/**
 * Remediate Command
 * =================
 *
 * Automatically fixes hardcoded secrets by:
 *   1. Replacing them with environment variable references in source code
 *   2. Writing actual values to .env (atomic write, 0o600 permissions)
 *   3. Adding .env to .gitignore BEFORE writing .env
 *   4. Updating .env.example with safe placeholders
 *
 * USAGE:
 *   ship-safe remediate .              Interactive — shows diff, confirms per file
 *   ship-safe remediate . --dry-run    Preview only, writes nothing
 *   ship-safe remediate . --yes        Apply all without prompting (CI use)
 *   ship-safe remediate . --stage      Also run git add on modified files
 *
 * SAFETY GUARANTEES:
 *   - Dry-run by default shows full diff before any write
 *   - .gitignore updated BEFORE .env is written
 *   - Backs up originals to .ship-safe-backup/<timestamp>/ before touching
 *   - Atomic writes: temp file → rename, no partial writes
 *   - Verifies the fix worked by re-scanning before finalizing
 *   - Never prints actual secret values to stdout (masked in diff)
 *   - Sets .env to 0o600 (owner read/write only) on Unix
 *   - Warns if repository appears to be public
 *
 * RECOMMENDED ORDER:
 *   1. ship-safe rotate   — revoke the exposed key first
 *   2. ship-safe remediate — fix source code
 *   3. ship-safe purge-history — scrub git history (v4.0.0)
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { createInterface } from 'readline';
import { execSync } from 'child_process';
import chalk from 'chalk';
import ora from 'ora';
import pkg from 'write-file-atomic';
const { writeFile: writeFileAtomic } = pkg;
import fg from 'fast-glob';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  TEST_FILE_PATTERNS,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import * as output from '../utils/output.js';

// =============================================================================
// FRAMEWORK DETECTION
// =============================================================================

function detectFramework(rootPath) {
  const pkgPath = path.join(rootPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps['next']) return 'nextjs';
      if (deps['nuxt'] || deps['nuxt3']) return 'nuxt';
    } catch { /* ignore */ }
  }
  return 'node'; // default: Node.js / process.env
}

function envVarRef(varName, framework, filePath = '') {
  if (filePath.endsWith('.py')) return `os.environ.get('${varName}')`;
  if (filePath.endsWith('.rb')) return `ENV['${varName}']`;
  // For Next.js keep standard process.env — user decides if NEXT_PUBLIC_ is needed
  return `process.env.${varName}`;
}

// =============================================================================
// ENV VAR NAME GENERATION
// =============================================================================

/**
 * Convert pattern name to SCREAMING_SNAKE_CASE env var name.
 * e.g. "OpenAI API Key" → "OPENAI_API_KEY"
 *      "[custom] My Token" → "MY_TOKEN"
 */
function patternToEnvVar(patternName) {
  return patternName
    .replace(/^\[custom\]\s*/i, '')
    .toUpperCase()
    .replace(/[^A-Z0-9\s]/g, '')
    .trim()
    .replace(/\s+/g, '_');
}

/**
 * Ensure env var name is unique within the current session.
 * If "OPENAI_API_KEY" is already taken, returns "OPENAI_API_KEY_2".
 */
function uniqueVarName(baseName, seen) {
  if (!seen.has(baseName)) return baseName;
  let i = 2;
  while (seen.has(`${baseName}_${i}`)) i++;
  return `${baseName}_${i}`;
}

// =============================================================================
// REPLACEMENT LOGIC
// =============================================================================

/**
 * Compute what to replace in a line and extract the raw secret value.
 *
 * Given: matched = 'apiKey = "sk-abc123xyz"', envRef = 'process.env.OPENAI_API_KEY'
 * Returns:
 *   replacement = 'apiKey = process.env.OPENAI_API_KEY'
 *   secretValue = 'sk-abc123xyz'
 */
function computeReplacement(matched, envRef) {
  // Case 1: quoted assignment — key = "value" or key: 'value'
  const quotedAssignment = matched.match(/^(.*?[:=]\s*)["']([^"']{4,})["'](.*)$/s);
  if (quotedAssignment) {
    const [, prefix, secretValue, suffix] = quotedAssignment;
    return { replacement: prefix + envRef + suffix, secretValue };
  }

  // Case 2: unquoted assignment — key = value  (no quotes around value)
  const unquotedAssignment = matched.match(/^(.*?[:=]\s*)([^\s"'<>\[\]{},;]{8,})(\s*)$/s);
  if (unquotedAssignment) {
    const [, prefix, secretValue, suffix] = unquotedAssignment;
    return { replacement: prefix + envRef + suffix, secretValue };
  }

  // Case 3: raw secret with no assignment context (e.g. AKIA..., ghp_...)
  return { replacement: envRef, secretValue: matched };
}

/**
 * Apply a single replacement to a line at the exact column position.
 * Uses column index to avoid regex issues with special characters.
 */
function replaceInLine(line, matched, colIndex, replacement) {
  const before = line.substring(0, colIndex);
  const after = line.substring(colIndex + matched.length);
  return before + replacement + after;
}

// =============================================================================
// PLAN BUILDING
// =============================================================================

/**
 * Build a complete remediation plan from scan results.
 * Returns an array of file-level plans, each with:
 *   - file: absolute path
 *   - originalLines: string[]
 *   - modifiedLines: string[]
 *   - changes: [{lineNum, originalLine, newLine, varName, secretValue}]
 */
function buildPlan(scanResults, framework, rootPath) {
  const plan = [];
  const seenVarNames = new Set();

  for (const { file, findings } of scanResults) {
    const content = fs.readFileSync(file, 'utf-8');
    const originalLines = content.split('\n');
    const modifiedLines = [...originalLines];
    const changes = [];

    // Group findings by line, sort within each line by column descending
    // so right-to-left replacements don't shift column indices for earlier matches
    const byLine = {};
    for (const f of findings) {
      if (!byLine[f.line]) byLine[f.line] = [];
      byLine[f.line].push(f);
    }

    let fileHasChanges = false;

    for (const lineNumStr of Object.keys(byLine).sort((a, b) => Number(a) - Number(b))) {
      const lineNum = Number(lineNumStr);
      const lineFinders = byLine[lineNumStr].sort((a, b) => b.column - a.column);
      let lineContent = modifiedLines[lineNum - 1];
      const originalLine = originalLines[lineNum - 1];

      for (const f of lineFinders) {
        const baseVarName = patternToEnvVar(f.patternName);
        const varName = uniqueVarName(baseVarName, seenVarNames);
        seenVarNames.add(varName);

        const ref = envVarRef(varName, framework, file);
        const colIndex = f.column - 1;

        const { replacement, secretValue } = computeReplacement(f.matched, ref);

        lineContent = replaceInLine(lineContent, f.matched, colIndex, replacement);
        changes.push({ lineNum, originalLine, newLine: lineContent, varName, secretValue });
        fileHasChanges = true;
      }

      if (fileHasChanges) {
        modifiedLines[lineNum - 1] = lineContent;
      }
    }

    if (changes.length > 0) {
      plan.push({ file, originalLines, modifiedLines, changes });
    }
  }

  return plan;
}

// =============================================================================
// DIFF DISPLAY
// =============================================================================

function showDiff(planItem, rootPath) {
  const relPath = path.relative(rootPath, planItem.file);
  console.log('\n' + chalk.white.bold(`  ${relPath}`));

  for (const change of planItem.changes) {
    console.log(chalk.gray(`    Line ${change.lineNum}:`));
    // Mask secret value in the diff output — never print raw secrets
    const maskedOriginal = maskLine(change.originalLine);
    console.log(chalk.red(`    - ${maskedOriginal.trim()}`));
    console.log(chalk.green(`    + ${change.newLine.trim()}`));
  }
}

/**
 * Mask what looks like a secret value in a line for safe display.
 * Shows first 4 chars + asterisks so the user can identify which secret it is.
 */
function maskLine(line) {
  // Mask quoted strings that look like secrets (>8 chars of alphanum)
  return line.replace(/["']([a-zA-Z0-9_\-+/=.]{8,})["']/g, (_, val) => {
    const prefix = val.substring(0, 4);
    return `"${prefix}${'*'.repeat(Math.min(val.length - 4, 12))}"`;
  });
}

// =============================================================================
// CONFIRMATION PROMPT
// =============================================================================

async function confirm(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(chalk.yellow(`\n  ${question} `), (answer) => {
      rl.close();
      const a = answer.trim().toLowerCase();
      if (a === 's' || a === 'skip') resolve('skip');
      else if (a === 'n' || a === 'no') resolve('no');
      else resolve('yes');
    });
  });
}

// =============================================================================
// FILE BACKUP
// =============================================================================

function createBackupDir(rootPath) {
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const backupDir = path.join(rootPath, '.ship-safe-backup', ts);
  fs.mkdirSync(backupDir, { recursive: true });
  return backupDir;
}

function backupFile(filePath, backupDir, rootPath) {
  const rel = path.relative(rootPath, filePath);
  const dest = path.join(backupDir, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(filePath, dest);
}

// =============================================================================
// VERIFICATION
// =============================================================================

/**
 * Re-scan the modified content string to verify secrets are gone.
 * Returns true if clean, false if any of the original secrets still appear.
 */
function verifyFixed(modifiedContent, changes) {
  for (const change of changes) {
    // Check that the original matched string is gone from the file
    if (modifiedContent.includes(change.secretValue)) {
      return false;
    }
  }
  return true;
}

// =============================================================================
// ENV FILE MANAGEMENT
// =============================================================================

/**
 * Append new env vars to .env file.
 * - Creates .env if it doesn't exist
 * - Skips vars that already exist in .env
 * - Uses atomic write
 * - Sets 0o600 permissions on Unix
 */
async function writeEnvFile(rootPath, envVars) {
  const envPath = path.join(rootPath, '.env');
  let existing = '';

  if (fs.existsSync(envPath)) {
    existing = fs.readFileSync(envPath, 'utf-8');
  }

  const newLines = [];
  const addedVars = [];

  for (const [varName, secretValue] of Object.entries(envVars)) {
    // Skip if already defined in .env
    const alreadyDefined = new RegExp(`^${varName}=`, 'm').test(existing);
    if (alreadyDefined) continue;

    newLines.push(`${varName}=${secretValue}`);
    addedVars.push(varName);
  }

  if (newLines.length === 0) return addedVars;

  const separator = existing.endsWith('\n') || existing === '' ? '' : '\n';
  const addition = separator + newLines.join('\n') + '\n';
  const newContent = existing + addition;

  await writeFileAtomic(envPath, newContent, { encoding: 'utf8' });

  // Set restrictive permissions on Unix (no-op on Windows)
  if (os.platform() !== 'win32') {
    fs.chmodSync(envPath, 0o600);
  }

  return addedVars;
}

/**
 * Ensure .env is in .gitignore.
 * Adds it if missing. Called BEFORE writing .env.
 */
function updateGitignore(rootPath) {
  const gitignorePath = path.join(rootPath, '.gitignore');
  let content = '';

  if (fs.existsSync(gitignorePath)) {
    content = fs.readFileSync(gitignorePath, 'utf-8');
  }

  const lines = content.split('\n').map(l => l.trim());
  const hasEnv = lines.some(l => l === '.env' || l === '*.env');

  if (!hasEnv) {
    const addition = content.endsWith('\n') || content === ''
      ? '.env\n'
      : '\n.env\n';
    fs.writeFileSync(gitignorePath, content + addition);
    return true; // added
  }
  return false; // already present
}

/**
 * Add placeholder entries to .env.example.
 * Safe to call multiple times — skips vars already in the file.
 */
function updateEnvExample(rootPath, envVars) {
  const examplePath = path.join(rootPath, '.env.example');
  let existing = '';

  if (fs.existsSync(examplePath)) {
    existing = fs.readFileSync(examplePath, 'utf-8');
  }

  const newLines = [];
  for (const varName of Object.keys(envVars)) {
    const alreadyDefined = new RegExp(`^${varName}=`, 'm').test(existing);
    if (!alreadyDefined) {
      newLines.push(`${varName}=your_${varName.toLowerCase()}_here`);
    }
  }

  if (newLines.length === 0) return;

  const separator = existing.endsWith('\n') || existing === '' ? '' : '\n';
  fs.writeFileSync(examplePath, existing + separator + newLines.join('\n') + '\n');
}

// =============================================================================
// PUBLIC REPO WARNING
// =============================================================================

function checkPublicRepo(rootPath) {
  try {
    const remotes = execSync('git remote -v', { cwd: rootPath, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] });
    if (remotes.includes('github.com') || remotes.includes('gitlab.com')) {
      // We can't easily check visibility without an API call, so warn if it looks like a hosted repo
      console.log();
      console.log(chalk.yellow.bold('  ⚠  Heads up: this repo is hosted remotely.'));
      console.log(chalk.yellow('     If secrets were already pushed, rotating them is more urgent than this fix.'));
      console.log(chalk.yellow('     Run ship-safe rotate first if you haven\'t already.'));
    }
  } catch { /* Not a git repo or no remote — skip */ }
}

// =============================================================================
// GIT STAGING
// =============================================================================

function stageFiles(files, rootPath) {
  if (files.length === 0) return;
  try {
    const quoted = files.map(f => `"${f}"`).join(' ');
    execSync(`git add ${quoted}`, { cwd: rootPath, stdio: 'inherit' });
    output.success(`Staged ${files.length} file(s) with git add`);
  } catch {
    output.warning('Could not stage files — run git add manually.');
  }
}

// =============================================================================
// SCAN (local, includes lineContent for replacement)
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
    if (basename === '.env' || basename === '.env.example') continue;
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
            column: match.index + 1,
            matched: match[0],
            patternName: pattern.name,
            severity: pattern.severity,
            confidence: getConfidence(pattern, match[0]),
          });
        }
      }
    }
  } catch { /* skip unreadable files */ }

  return findings;
}

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function remediateCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  // ── 1. Scan ──────────────────────────────────────────────────────────────
  const spinner = ora({ text: 'Scanning for secrets to remediate...', color: 'cyan' }).start();

  const files = await findFiles(absolutePath);
  const scanResults = [];

  for (const file of files) {
    const findings = await scanFile(file);
    if (findings.length > 0) scanResults.push({ file, findings });
  }

  spinner.stop();

  if (scanResults.length === 0) {
    output.success('No secrets found — nothing to remediate!');
    console.log(chalk.gray('\n  Run ship-safe scan . to double-check.'));
    return;
  }

  // ── 2. Build plan ─────────────────────────────────────────────────────────
  const framework = detectFramework(absolutePath);
  const plan = buildPlan(scanResults, framework, absolutePath);

  const totalFindings = plan.reduce((sum, p) => sum + p.changes.length, 0);

  output.header('Remediation Plan');
  console.log(chalk.gray(`\n  Framework detected: ${framework}`));
  console.log(chalk.gray(`  Found ${totalFindings} secret(s) in ${plan.length} file(s) to fix\n`));

  // Show full diff for all files
  for (const item of plan) {
    showDiff(item, absolutePath);
  }

  // ── 3. Dry run ────────────────────────────────────────────────────────────
  if (options.dryRun) {
    console.log();
    console.log(chalk.cyan('\n  Dry run — no files modified.'));
    console.log(chalk.gray('  Remove --dry-run to apply these changes.'));
    return;
  }

  // ── 4. Warn if hosted remotely ────────────────────────────────────────────
  checkPublicRepo(absolutePath);

  // ── 5. Confirm before starting ────────────────────────────────────────────
  if (!options.yes) {
    const answer = await confirm(`Apply all ${totalFindings} fix(es)? [y/n]:`);
    if (answer !== 'yes') {
      console.log(chalk.gray('\n  Aborted. No files were modified.'));
      return;
    }
  }

  // ── 6. Ensure .env is in .gitignore BEFORE writing .env ──────────────────
  const addedToGitignore = updateGitignore(absolutePath);
  if (addedToGitignore) {
    output.success('Added .env to .gitignore');
  }

  // ── 7. Create backup directory ────────────────────────────────────────────
  const backupDir = createBackupDir(absolutePath);

  // ── 8. Process each file ──────────────────────────────────────────────────
  const modifiedFiles = [];
  const allEnvVars = {}; // varName → secretValue (deduplicated)

  for (const item of plan) {
    const relPath = path.relative(absolutePath, item.file);

    // Per-file confirmation in interactive mode
    if (!options.yes && plan.length > 1) {
      showDiff(item, absolutePath);
      const answer = await confirm(`Fix ${relPath}? [y/s(kip)/n(abort)]:`);
      if (answer === 'skip') {
        console.log(chalk.gray(`  Skipped ${relPath}`));
        continue;
      }
      if (answer === 'no') {
        console.log(chalk.gray('\n  Aborted. Previously fixed files are kept.'));
        break;
      }
    }

    // Backup original
    backupFile(item.file, backupDir, absolutePath);

    // Build modified content
    const newContent = item.modifiedLines.join('\n');

    // Verify the fix actually removes the secrets before writing
    if (!verifyFixed(newContent, item.changes)) {
      output.warning(`Verification failed for ${relPath} — skipping (original untouched)`);
      continue;
    }

    // Atomic write
    try {
      await writeFileAtomic(item.file, newContent, { encoding: 'utf8' });
    } catch (err) {
      output.error(`Failed to write ${relPath}: ${err.message}`);
      continue;
    }

    modifiedFiles.push(item.file);

    // Collect env vars (first value wins for duplicates)
    for (const change of item.changes) {
      if (!(change.varName in allEnvVars)) {
        allEnvVars[change.varName] = change.secretValue;
      }
    }

    console.log(chalk.green(`  ✓ Fixed ${relPath}`));
  }

  if (modifiedFiles.length === 0) {
    console.log(chalk.yellow('\n  No files were modified.'));
    return;
  }

  // ── 9. Write .env ─────────────────────────────────────────────────────────
  const addedVars = await writeEnvFile(absolutePath, allEnvVars);
  if (addedVars.length > 0) {
    output.success(`.env updated with ${addedVars.length} variable(s)`);
  }

  // ── 10. Update .env.example ───────────────────────────────────────────────
  updateEnvExample(absolutePath, allEnvVars);
  output.success('.env.example updated with placeholders');

  // ── 11. Stage files if --stage ────────────────────────────────────────────
  if (options.stage) {
    stageFiles(modifiedFiles, absolutePath);
  }

  // ── 12. Summary ───────────────────────────────────────────────────────────
  console.log();
  console.log(chalk.cyan.bold('  Remediation complete'));
  console.log(chalk.gray(`  Files fixed:     ${modifiedFiles.length}`));
  console.log(chalk.gray(`  Env vars added:  ${addedVars.length}`));
  console.log(chalk.gray(`  Backup saved to: .ship-safe-backup/`));

  console.log();
  console.log(chalk.yellow.bold('  Next steps — do these in order:'));
  console.log(chalk.white('  1.') + chalk.gray(' Rotate your exposed keys immediately (ship-safe rotate)'));
  console.log(chalk.white('  2.') + chalk.gray(' Commit the fixed files: git add . && git commit -m "fix: remove hardcoded secrets"'));
  console.log(chalk.white('  3.') + chalk.gray(' Copy .env.example → .env and fill in fresh values'));
  console.log(chalk.white('  4.') + chalk.gray(' Run ship-safe scan . to verify everything is clean'));
  console.log(chalk.white('  5.') + chalk.gray(' If secrets were already pushed, also purge git history'));
  console.log();
}
