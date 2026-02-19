/**
 * Init Command
 * ============
 *
 * Initialize security configurations in the current project.
 * Copies pre-configured security files from ship-safe.
 *
 * USAGE:
 *   ship-safe init              Copy all security configs
 *   ship-safe init --gitignore  Only copy .gitignore
 *   ship-safe init --headers    Only copy security headers
 *   ship-safe init -f           Force overwrite existing files
 *
 * FILES COPIED:
 *   - .gitignore (merged with existing if present)
 *   - nextjs-security-headers.js (for Next.js projects)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import * as output from '../utils/output.js';

// Get the directory of this module (for finding config files)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PACKAGE_ROOT = path.resolve(__dirname, '..', '..');

// =============================================================================
// MAIN INIT FUNCTION
// =============================================================================

export async function initCommand(options = {}) {
  const targetDir = process.cwd();

  console.log();
  output.header('Initializing Security Configs');
  console.log();
  console.log(chalk.gray(`Target directory: ${targetDir}`));
  console.log();

  const results = {
    copied: [],
    skipped: [],
    merged: [],
    errors: []
  };

  // Determine which files to copy.
  // If a specific flag is set, only run that category.
  // With no flags, run everything.
  const hasSpecificFlag = options.gitignore || options.headers || options.agents;
  const copyGitignore = hasSpecificFlag ? !!options.gitignore : true;
  const copyHeaders   = hasSpecificFlag ? !!options.headers   : true;
  const copyAgents    = hasSpecificFlag ? !!options.agents    : true;

  // Copy .gitignore
  if (copyGitignore) {
    await handleGitignore(targetDir, options.force, results);
  }

  // Copy security headers
  if (copyHeaders) {
    await handleSecurityHeaders(targetDir, options.force, results);
  }

  // Append security rules to AI agent instruction files
  if (copyAgents) {
    await handleAgentFiles(targetDir, options.force, results);
  }

  // Print summary
  printSummary(results);
}

// =============================================================================
// GITIGNORE HANDLING
// =============================================================================

async function handleGitignore(targetDir, force, results) {
  // Note: We use 'gitignore-template' because npm excludes dotfiles from packages
  const sourcePath = path.join(PACKAGE_ROOT, 'configs', 'gitignore-template');
  const targetPath = path.join(targetDir, '.gitignore');

  // Check if source exists
  if (!fs.existsSync(sourcePath)) {
    results.errors.push({
      file: '.gitignore',
      error: 'Source file not found in ship-safe package'
    });
    return;
  }

  const sourceContent = fs.readFileSync(sourcePath, 'utf-8');

  // Check if target exists
  if (fs.existsSync(targetPath)) {
    if (force) {
      // Overwrite
      fs.writeFileSync(targetPath, sourceContent);
      results.copied.push('.gitignore (overwritten)');
    } else {
      // Merge: append ship-safe patterns to existing
      const existingContent = fs.readFileSync(targetPath, 'utf-8');

      // Check if already has ship-safe content
      if (existingContent.includes('# SHIP SAFE')) {
        results.skipped.push('.gitignore (already contains ship-safe patterns)');
        return;
      }

      // Append ship-safe section
      const mergedContent = existingContent.trim() + '\n\n' +
        '# =============================================================================\n' +
        '# SHIP SAFE ADDITIONS\n' +
        '# Added by: npx ship-safe init\n' +
        '# =============================================================================\n\n' +
        extractSecurityPatterns(sourceContent);

      fs.writeFileSync(targetPath, mergedContent);
      results.merged.push('.gitignore');
    }
  } else {
    // Create new
    fs.writeFileSync(targetPath, sourceContent);
    results.copied.push('.gitignore');
  }
}

/**
 * Extract the most important security patterns from our .gitignore
 */
function extractSecurityPatterns(fullGitignore) {
  // Extract key sections
  const patterns = `
# Environment files
.env
.env.local
.env*.local
*.env

# Private keys & certificates
*.pem
*.key
*.p12
*.pfx

# Credentials
*credentials*
*.secrets.json
secrets.yml
secrets.yaml

# Service accounts
**/service-account*.json
*-firebase-adminsdk-*.json

# AWS
.aws/credentials

# Database files
*.sqlite
*.sqlite3
*.db

# Logs (may contain sensitive data)
*.log
logs/
`;

  return patterns.trim();
}

// =============================================================================
// SECURITY HEADERS HANDLING
// =============================================================================

async function handleSecurityHeaders(targetDir, force, results) {
  const sourcePath = path.join(PACKAGE_ROOT, 'configs', 'nextjs-security-headers.js');
  const targetPath = path.join(targetDir, 'security-headers.config.js');

  // Check if source exists
  if (!fs.existsSync(sourcePath)) {
    results.errors.push({
      file: 'security-headers.config.js',
      error: 'Source file not found in ship-safe package'
    });
    return;
  }

  // Detect if this is a Next.js project
  const packageJsonPath = path.join(targetDir, 'package.json');
  let isNextProject = false;

  if (fs.existsSync(packageJsonPath)) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      isNextProject = !!(packageJson.dependencies?.next || packageJson.devDependencies?.next);
    } catch {
      // Ignore parse errors
    }
  }

  // Check if target exists
  if (fs.existsSync(targetPath) && !force) {
    results.skipped.push('security-headers.config.js (already exists, use -f to overwrite)');
    return;
  }

  // Copy the file
  const content = fs.readFileSync(sourcePath, 'utf-8');
  fs.writeFileSync(targetPath, content);
  results.copied.push('security-headers.config.js');

  // Show integration instructions
  if (isNextProject) {
    console.log(chalk.cyan('\nNext.js detected! Add to your next.config.js:\n'));
    console.log(chalk.gray('  const { securityHeadersConfig } = require(\'./security-headers.config.js\');'));
    console.log(chalk.gray('  module.exports = { ...securityHeadersConfig, /* your config */ };'));
    console.log();
  }
}

// =============================================================================
// AGENT FILE HANDLING
// =============================================================================

// Marker used for idempotency — if this string is present we already added our section.
const AGENT_MARKER = '<!-- ship-safe -->';

// The security rules block appended to existing agent instruction files.
const AGENT_SECTION = `
## Security (ship-safe)
${AGENT_MARKER}
- Always run \`npx ship-safe scan .\` before committing code
- Never hardcode API keys, tokens, or credentials in source files — use environment variables
- If hardcoded secrets are found or generated, run \`npx ship-safe remediate\` to auto-fix them
`;

// Standalone content for a new Cursor rules file.
const CURSOR_RULE_CONTENT = `---
description: Prevent API key leaks and credential exposure in generated code
alwaysApply: true
---

- Always run \`npx ship-safe scan .\` before committing code
- Never hardcode API keys, tokens, or credentials in source files — use environment variables
- If hardcoded secrets are found or generated, run \`npx ship-safe remediate\` to auto-fix them
`;

async function handleAgentFiles(targetDir, force, results) {
  // Files where we append a section if they already exist, or create if they don't.
  const appendTargets = [
    { file: 'CLAUDE.md',                          label: 'CLAUDE.md' },
    { file: '.windsurfrules',                      label: '.windsurfrules' },
    { file: path.join('.github', 'copilot-instructions.md'), label: '.github/copilot-instructions.md' },
  ];

  for (const { file, label } of appendTargets) {
    const targetPath = path.join(targetDir, file);

    if (fs.existsSync(targetPath)) {
      const existing = fs.readFileSync(targetPath, 'utf-8');
      if (existing.includes(AGENT_MARKER)) {
        results.skipped.push(`${label} (already contains ship-safe rules)`);
        continue;
      }
      if (force || true) { // always append unless already present
        fs.writeFileSync(targetPath, existing.trimEnd() + '\n' + AGENT_SECTION);
        results.merged.push(label);
      }
    } else {
      // Ensure parent directory exists (e.g. .github/)
      const parentDir = path.dirname(targetPath);
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true });
      }
      fs.writeFileSync(targetPath, AGENT_SECTION.trim() + '\n');
      results.copied.push(label);
    }
  }

  // Cursor rules — dedicated file, no merging needed.
  const cursorRulesDir  = path.join(targetDir, '.cursor', 'rules');
  const cursorRulesFile = path.join(cursorRulesDir, 'ship-safe.mdc');

  if (fs.existsSync(cursorRulesFile) && !force) {
    results.skipped.push('.cursor/rules/ship-safe.mdc (already exists, use -f to overwrite)');
  } else {
    if (!fs.existsSync(cursorRulesDir)) {
      fs.mkdirSync(cursorRulesDir, { recursive: true });
    }
    fs.writeFileSync(cursorRulesFile, CURSOR_RULE_CONTENT.trim() + '\n');
    results.copied.push('.cursor/rules/ship-safe.mdc');
  }
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(results) {
  console.log();
  console.log(chalk.cyan('='.repeat(60)));
  console.log(chalk.cyan.bold('  Summary'));
  console.log(chalk.cyan('='.repeat(60)));
  console.log();

  if (results.copied.length > 0) {
    console.log(chalk.green.bold('Created:'));
    for (const file of results.copied) {
      console.log(chalk.green(`  \u2714 ${file}`));
    }
    console.log();
  }

  if (results.merged.length > 0) {
    console.log(chalk.blue.bold('Merged:'));
    for (const file of results.merged) {
      console.log(chalk.blue(`  \u2194 ${file} (appended ship-safe patterns)`));
    }
    console.log();
  }

  if (results.skipped.length > 0) {
    console.log(chalk.yellow.bold('Skipped:'));
    for (const file of results.skipped) {
      console.log(chalk.yellow(`  \u2192 ${file}`));
    }
    console.log();
  }

  if (results.errors.length > 0) {
    console.log(chalk.red.bold('Errors:'));
    for (const { file, error } of results.errors) {
      console.log(chalk.red(`  \u2718 ${file}: ${error}`));
    }
    console.log();
  }

  // Next steps
  console.log(chalk.cyan('Next steps:'));
  console.log(chalk.white('  1.') + ' Review the copied files and customize for your project');
  console.log(chalk.white('  2.') + ' Run ' + chalk.cyan('npx ship-safe scan .') + ' to check for secrets');
  console.log(chalk.white('  3.') + ' Run ' + chalk.cyan('npx ship-safe checklist') + ' before launching');
  console.log();
  console.log(chalk.cyan('='.repeat(60)));
}
