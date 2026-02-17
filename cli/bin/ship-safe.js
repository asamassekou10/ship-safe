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
  .action(initCommand);

// -----------------------------------------------------------------------------
// PARSE AND RUN
// -----------------------------------------------------------------------------

// Show help if no command provided
if (process.argv.length === 2) {
  console.log(banner);
  console.log(chalk.yellow('\nQuick start:\n'));
  console.log(chalk.white('  npx ship-safe scan .        ') + chalk.gray('# Scan current directory for secrets'));
  console.log(chalk.white('  npx ship-safe checklist     ') + chalk.gray('# Run security checklist'));
  console.log(chalk.white('  npx ship-safe init          ') + chalk.gray('# Add security configs to your project'));
  console.log(chalk.white('\n  npx ship-safe --help        ') + chalk.gray('# Show all options'));
  console.log();
  process.exit(0);
}

program.parse();
