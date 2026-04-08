/**
 * Env Audit Command
 * ==================
 *
 * Post-sync credential health check. Designed to run immediately after
 * `stripe projects env --pull` or any credential provisioning workflow.
 *
 * Checks:
 *   1. Every .env* file is covered by .gitignore
 *   2. No .env values appear hardcoded in source files
 *   3. Git history has no previously committed .env files
 *   4. Agent configs can't read credential files without restriction
 *
 * USAGE:
 *   ship-safe env-audit [path]
 *   ship-safe env-audit . --json
 *
 * EXIT CODES:
 *   0 — clean
 *   1 — issues found
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import chalk from 'chalk';
import ora from 'ora';
import { execFileSync } from 'child_process';
import { SECRET_PATTERNS, SKIP_DIRS } from '../utils/patterns.js';

// Minimum value length to cross-reference (skip short values like "true", "3000")
const MIN_VALUE_LENGTH = 8;

// Keys that are safe to appear in source (not secrets)
const SAFE_KEY_PATTERNS = /^(?:NEXT_PUBLIC_|REACT_APP_|VITE_|NUXT_PUBLIC_|NODE_ENV|PORT|HOST|HOSTNAME|LOG_LEVEL|DEBUG|TZ|LANG|APP_NAME|APP_URL|BASE_URL)/i;

// =============================================================================
// ENV AUDIT COMMAND
// =============================================================================

export async function envAuditCommand(targetPath = '.', options) {
  const absolutePath = path.resolve(targetPath);
  const spinner = ora('Auditing credential environment...').start();

  const findings = [];

  try {
    // ── Step 1: Find all .env files ──────────────────────────────────────────
    const envFiles = await findEnvFiles(absolutePath);
    spinner.text = `Found ${envFiles.length} .env file(s)`;

    if (envFiles.length === 0) {
      spinner.succeed('No .env files found — nothing to audit.');
      return;
    }

    // ── Step 2: Check .gitignore coverage ────────────────────────────────────
    spinner.text = 'Checking .gitignore coverage...';
    for (const envFile of envFiles) {
      const relPath = path.relative(absolutePath, envFile).replace(/\\/g, '/');
      const basename = path.basename(envFile);

      // Skip .env.example and .env.sample — these are meant to be committed
      if (/\.env\.(?:example|sample|template)$/i.test(basename)) continue;

      const isIgnored = checkGitignored(absolutePath, relPath);
      if (!isIgnored) {
        findings.push({
          type: 'gitignore',
          severity: 'critical',
          file: relPath,
          message: `${relPath} is NOT covered by .gitignore — credentials will be committed`,
          fix: `Add "${basename}" to your .gitignore file`,
        });
      }
    }

    // ── Step 3: Parse .env values and cross-reference against source ─────────
    spinner.text = 'Cross-referencing credentials against source files...';
    // Only cross-reference real .env files, not .env.example/.env.sample
    const realEnvFiles = envFiles.filter(f => !/\.env\.(?:example|sample|template)$/i.test(path.basename(f)));
    const envValues = parseEnvFiles(realEnvFiles);
    const sensitiveValues = envValues.filter(v =>
      v.value.length >= MIN_VALUE_LENGTH && !SAFE_KEY_PATTERNS.test(v.key)
    );

    if (sensitiveValues.length > 0) {
      const sourceFiles = await findSourceFiles(absolutePath);
      for (const { key, value, file: envFile } of sensitiveValues) {
        for (const srcFile of sourceFiles) {
          const relSrc = path.relative(absolutePath, srcFile).replace(/\\/g, '/');
          // Don't flag the .env file itself
          if (srcFile === envFile) continue;

          try {
            const content = fs.readFileSync(srcFile, 'utf-8');
            if (content.includes(value)) {
              findings.push({
                type: 'hardcoded',
                severity: 'critical',
                file: relSrc,
                message: `${key} value from ${path.basename(envFile)} is hardcoded in ${relSrc}`,
                fix: `Replace the hardcoded value with process.env.${key} or equivalent`,
              });
            }
          } catch {
            // skip unreadable files
          }
        }
      }
    }

    // ── Step 4: Check git history for committed .env files ───────────────────
    spinner.text = 'Checking git history for committed credentials...';
    const historyLeaks = checkGitHistory(absolutePath);
    for (const leak of historyLeaks) {
      findings.push({
        type: 'history',
        severity: 'high',
        file: leak,
        message: `${leak} was previously committed to git history — credentials may be in old commits`,
        fix: 'Rotate all credentials that were in this file. Use git filter-repo to remove from history if needed.',
      });
    }

    // ── Step 5: Check .projects manifest for credential leaks ────────────────
    spinner.text = 'Checking .projects manifest...';
    const projectsDir = path.join(absolutePath, '.projects');
    if (fs.existsSync(projectsDir)) {
      const projectsFiles = await fg(['**/*'], {
        cwd: projectsDir,
        absolute: true,
        onlyFiles: true,
      });

      for (const pFile of projectsFiles) {
        try {
          const content = fs.readFileSync(pFile, 'utf-8');
          for (const pattern of SECRET_PATTERNS) {
            pattern.pattern.lastIndex = 0;
            const match = pattern.pattern.exec(content);
            if (match) {
              const relPath = path.relative(absolutePath, pFile).replace(/\\/g, '/');
              findings.push({
                type: 'projects-manifest',
                severity: 'critical',
                file: relPath,
                message: `${pattern.name} found in .projects manifest — credentials should not be in the manifest`,
                fix: 'Remove credential values from .projects/ config. Stripe Projects stores credentials server-side.',
              });
            }
          }
        } catch {
          // skip unreadable
        }
      }
    }

    // ── Step 6: Check agent config access to .env files ──────────────────────
    spinner.text = 'Checking agent config access to credential files...';
    const agentConfigs = await fg([
      '.claude/settings.json',
      '.cursorrules',
      '.cursor/rules/*.mdc',
      '.windsurfrules',
      'CLAUDE.md',
      '.claw.json',
      '.claw/settings.json',
      'openclaw.json',
    ], {
      cwd: absolutePath,
      absolute: true,
      onlyFiles: true,
      dot: true,
    });

    for (const configFile of agentConfigs) {
      try {
        const content = fs.readFileSync(configFile, 'utf-8');
        const relPath = path.relative(absolutePath, configFile).replace(/\\/g, '/');

        // Check for danger modes that give agents full access
        if (/dangerouslySkipPermissions\s*["']?\s*[:=]\s*["']?true/i.test(content) ||
            /permissionMode\s*["']?\s*[:=]\s*["']?danger-full-access/i.test(content)) {
          findings.push({
            type: 'agent-access',
            severity: 'critical',
            file: relPath,
            message: `${relPath} grants unrestricted file access — agent can read all .env credentials`,
            fix: 'Remove dangerouslySkipPermissions / danger-full-access. Scope agent file access explicitly.',
          });
        }
      } catch {
        // skip
      }
    }

    // ── Output ───────────────────────────────────────────────────────────────
    spinner.stop();

    if (options.json) {
      console.log(JSON.stringify({ findings, envFiles: envFiles.length, clean: findings.length === 0 }, null, 2));
      process.exit(findings.length > 0 ? 1 : 0);
      return;
    }

    console.log();
    console.log(chalk.cyan.bold('  Ship Safe — Env Audit'));
    console.log(chalk.gray(`  Scanned ${envFiles.length} .env file(s), ${sensitiveValues.length} credential(s)`));
    console.log();

    if (findings.length === 0) {
      console.log(chalk.green('  ✔ Environment is clean. No credential leaks detected.\n'));
      console.log(chalk.gray('  Tip: run this after every `stripe projects env --pull` or credential sync.\n'));
      process.exit(0);
      return;
    }

    // Group by type
    const groups = {
      gitignore: { label: 'Missing .gitignore Coverage', icon: '🔓' },
      hardcoded: { label: 'Hardcoded Credentials in Source', icon: '🔑' },
      history: { label: 'Credentials in Git History', icon: '📜' },
      'projects-manifest': { label: 'Credentials in .projects Manifest', icon: '📁' },
      'agent-access': { label: 'Agent Config: Unrestricted Credential Access', icon: '🤖' },
    };

    for (const [type, meta] of Object.entries(groups)) {
      const typeFindings = findings.filter(f => f.type === type);
      if (typeFindings.length === 0) continue;

      console.log(chalk.yellow(`  ${meta.icon} ${meta.label} (${typeFindings.length})`));
      for (const f of typeFindings) {
        const sevColor = f.severity === 'critical' ? chalk.red : chalk.yellow;
        console.log(`    ${sevColor(f.severity.toUpperCase())} ${f.file}`);
        console.log(chalk.gray(`      ${f.message}`));
        console.log(chalk.gray(`      Fix: ${f.fix}`));
      }
      console.log();
    }

    const criticals = findings.filter(f => f.severity === 'critical').length;
    if (criticals > 0) {
      console.log(chalk.red.bold(`  ✘ ${criticals} critical issue(s). Fix before committing.\n`));
    } else {
      console.log(chalk.yellow(`  ⚠ ${findings.length} issue(s) found. Review before committing.\n`));
    }

    process.exit(1);

  } catch (err) {
    spinner.fail(`Env audit error: ${err.message}`);
    process.exit(1);
  }
}

// =============================================================================
// HELPERS
// =============================================================================

async function findEnvFiles(rootPath) {
  return fg(['.env', '.env.*', '**/.env', '**/.env.*'], {
    cwd: rootPath,
    absolute: true,
    onlyFiles: true,
    dot: true,
    ignore: Array.from(SKIP_DIRS).map(d => `**/${d}/**`),
  });
}

function parseEnvFiles(envFiles) {
  const values = [];
  for (const file of envFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx === -1) continue;
        const key = trimmed.slice(0, eqIdx).trim();
        let value = trimmed.slice(eqIdx + 1).trim();
        // Strip surrounding quotes
        if ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        if (value && value !== '' && !value.startsWith('${')) {
          values.push({ key, value, file });
        }
      }
    } catch {
      // skip unreadable
    }
  }
  return values;
}

async function findSourceFiles(rootPath) {
  return fg(['**/*.{js,jsx,ts,tsx,mjs,cjs,py,rb,go,rs,php,java,kt,swift,yaml,yml,json,toml,tf}'], {
    cwd: rootPath,
    absolute: true,
    onlyFiles: true,
    ignore: [
      ...Array.from(SKIP_DIRS).map(d => `**/${d}/**`),
      '**/.env*',
      '**/*.min.js',
      '**/__tests__/**',
      '**/*.test.*',
      '**/*.spec.*',
      '**/test/**',
      '**/tests/**',
      '**/fixtures/**',
      '**/snippets/**',
    ],
  });
}

function checkGitignored(rootPath, relPath) {
  try {
    execFileSync('git', ['check-ignore', '-q', relPath], { cwd: rootPath, stdio: 'pipe' });
    return true; // exit 0 means it IS ignored
  } catch {
    return false; // exit 1 means it is NOT ignored
  }
}

function checkGitHistory(rootPath) {
  try {
    const result = execFileSync('git', ['log', '--all', '--diff-filter=A', '--name-only', '--pretty=format:'], {
      cwd: rootPath,
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 5 * 1024 * 1024,
    }).toString();

    const envFilePattern = /^\.env(?:\.\w+)?$/;
    const safeEnvPattern = /\.env\.(?:example|sample|template)$/;
    const committed = new Set();
    for (const line of result.split('\n')) {
      const trimmed = line.trim();
      if (trimmed && envFilePattern.test(path.basename(trimmed)) && !safeEnvPattern.test(trimmed)) {
        committed.add(trimmed);
      }
    }
    return Array.from(committed);
  } catch {
    return [];
  }
}
