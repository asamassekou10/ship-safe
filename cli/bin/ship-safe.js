#!/usr/bin/env node

/**
 * Ship Safe CLI
 * =============
 *
 * Security toolkit for vibe coders and indie hackers.
 *
 * USAGE:
 *   npx ship-safe scan [path]      Scan for secrets in your codebase
 *   npx ship-safe checklist        Run the launch-day security checklist
 *   npx ship-safe init             Initialize security configs in your project
 *   npx ship-safe fix              Generate .env.example from found secrets
 *   npx ship-safe guard            Install pre-push git hook
 *   npx ship-safe --help           Show all commands
 */

import { program } from 'commander';
import chalk from 'chalk';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { scanCommand } from '../commands/scan.js';
import { checklistCommand } from '../commands/checklist.js';
import { initCommand } from '../commands/init.js';
import { fixCommand } from '../commands/fix.js';
import { guardCommand } from '../commands/guard.js';
import { mcpCommand } from '../commands/mcp.js';
import { remediateCommand } from '../commands/remediate.js';
import { rotateCommand } from '../commands/rotate.js';

// =============================================================================
// CLI CONFIGURATION
// =============================================================================

// Read version from package.json
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
const VERSION = packageJson.version;

// Banner shown on help
const banner = `
${chalk.cyan('███████╗██╗  ██╗██╗██████╗     ███████╗ █████╗ ███████╗███████╗')}
${chalk.cyan('██╔════╝██║  ██║██║██╔══██╗    ██╔════╝██╔══██╗██╔════╝██╔════╝')}
${chalk.cyan('███████╗███████║██║██████╔╝    ███████╗███████║█████╗  █████╗  ')}
${chalk.cyan('╚════██║██╔══██║██║██╔═══╝     ╚════██║██╔══██║██╔══╝  ██╔══╝  ')}
${chalk.cyan('███████║██║  ██║██║██║         ███████║██║  ██║██║     ███████╗')}
${chalk.cyan('╚══════╝╚═╝  ╚═╝╚═╝╚═╝         ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝')}

${chalk.gray('Security toolkit for vibe coders. Secure your MVP in 5 minutes.')}
`;

// =============================================================================
// PROGRAM SETUP
// =============================================================================

program
  .name('ship-safe')
  .description('Security toolkit for vibe coders and indie hackers')
  .version(VERSION)
  .addHelpText('before', banner);

// -----------------------------------------------------------------------------
// SCAN COMMAND
// -----------------------------------------------------------------------------
program
  .command('scan [path]')
  .description('Scan your codebase for leaked secrets (API keys, passwords, etc.)')
  .option('-v, --verbose', 'Show all files being scanned')
  .option('--no-color', 'Disable colored output')
  .option('--json', 'Output results as JSON (useful for CI)')
  .option('--sarif', 'Output results in SARIF format (for GitHub Code Scanning)')
  .option('--include-tests', 'Also scan test files (excluded by default to reduce false positives)')
  .action(scanCommand);

// -----------------------------------------------------------------------------
// CHECKLIST COMMAND
// -----------------------------------------------------------------------------
program
  .command('checklist')
  .description('Run through the launch-day security checklist interactively')
  .option('--no-interactive', 'Print checklist without prompts')
  .action(checklistCommand);

// -----------------------------------------------------------------------------
// INIT COMMAND
// -----------------------------------------------------------------------------
program
  .command('init')
  .description('Initialize security configs in your project')
  .option('-f, --force', 'Overwrite existing files')
  .option('--gitignore', 'Only copy .gitignore')
  .option('--headers', 'Only copy security headers config')
  .option('--agents', 'Only add security rules to AI agent instruction files (CLAUDE.md, .cursor/rules/, .windsurfrules, copilot-instructions.md)')
  .action(initCommand);

// -----------------------------------------------------------------------------
// FIX COMMAND
// -----------------------------------------------------------------------------
program
  .command('fix')
  .description('Scan for secrets and generate a .env.example with placeholder values')
  .option('--dry-run', 'Preview generated .env.example without writing it')
  .action(fixCommand);

// -----------------------------------------------------------------------------
// GUARD COMMAND
// -----------------------------------------------------------------------------
program
  .command('guard [action]')
  .description('Install a git hook to block pushes if secrets are found')
  .option('--pre-commit', 'Install as pre-commit hook instead of pre-push')
  .action(guardCommand);

// -----------------------------------------------------------------------------
// MCP SERVER COMMAND
// -----------------------------------------------------------------------------
program
  .command('mcp')
  .description('Start ship-safe as an MCP server (for Claude Desktop, Cursor, Windsurf, etc.)')
  .action(mcpCommand);

// -----------------------------------------------------------------------------
// REMEDIATE COMMAND
// -----------------------------------------------------------------------------
program
  .command('remediate [path]')
  .description('Auto-fix hardcoded secrets: rewrite source code + write .env + update .gitignore')
  .option('--dry-run', 'Preview changes without writing any files')
  .option('--yes', 'Apply all fixes without prompting (for CI)')
  .option('--stage', 'Also run git add on modified files after fixing')
  .action(remediateCommand);

// -----------------------------------------------------------------------------
// ROTATE COMMAND
// -----------------------------------------------------------------------------
program
  .command('rotate [path]')
  .description('Revoke and rotate exposed secrets — opens provider dashboards with step-by-step guide')
  .option('--provider <name>', 'Only rotate secrets for a specific provider (e.g. github, stripe, openai)')
  .action(rotateCommand);

// -----------------------------------------------------------------------------
// PARSE AND RUN
// -----------------------------------------------------------------------------

// Show help if no command provided
if (process.argv.length === 2) {
  console.log(banner);
  console.log(chalk.yellow('\nQuick start:\n'));
  console.log(chalk.white('  npx ship-safe scan .        ') + chalk.gray('# Scan for secrets'));
  console.log(chalk.white('  npx ship-safe remediate .   ') + chalk.gray('# Auto-fix: rewrite code + write .env'));
  console.log(chalk.white('  npx ship-safe rotate .      ') + chalk.gray('# Revoke exposed keys (provider guides)'));
  console.log(chalk.white('  npx ship-safe fix           ') + chalk.gray('# Generate .env.example from secrets'));
  console.log(chalk.white('  npx ship-safe guard         ') + chalk.gray('# Block git push if secrets found'));
  console.log(chalk.white('  npx ship-safe checklist     ') + chalk.gray('# Run security checklist'));
  console.log(chalk.white('  npx ship-safe init          ') + chalk.gray('# Add security configs to your project'));
  console.log(chalk.white('\n  npx ship-safe --help        ') + chalk.gray('# Show all options'));
  console.log();
  process.exit(0);
}

program.parse();
