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
import { agentCommand } from '../commands/agent.js';
import { depsCommand } from '../commands/deps.js';
import { scoreCommand } from '../commands/score.js';
import { redTeamCommand } from '../commands/red-team.js';
import { watchCommand } from '../commands/watch.js';
import { auditCommand } from '../commands/audit.js';
import { doctorCommand } from '../commands/doctor.js';
import { baselineCommand } from '../commands/baseline.js';
import { PolicyEngine } from '../agents/policy-engine.js';
import { SBOMGenerator } from '../agents/sbom-generator.js';

// =============================================================================
// CLI CONFIGURATION
// =============================================================================

const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';

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
  .option('--no-cache', 'Force full rescan (ignore cached results)')
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
  .option('--all', 'Also fix common agent findings (debug mode, TLS bypass, shell injection)')
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
// AGENT COMMAND
// -----------------------------------------------------------------------------
program
  .command('agent [path]')
  .description('AI-powered security audit: scan, classify with Claude, auto-remediate confirmed secrets')
  .option('--dry-run', 'Show classification and plan without writing any files')
  .option('--model <model>', `Claude model to use (default: ${DEFAULT_MODEL})`)
  .action(agentCommand);

// -----------------------------------------------------------------------------
// DEPS COMMAND
// -----------------------------------------------------------------------------
program
  .command('deps [path]')
  .description('Audit dependencies for known CVEs (npm, yarn, pnpm, pip-audit, bundler-audit)')
  .option('--fix', 'Run the package manager fix command after auditing')
  .action(depsCommand);

// -----------------------------------------------------------------------------
// SCORE COMMAND
// -----------------------------------------------------------------------------
program
  .command('score [path]')
  .description('Compute a 0-100 security health score for your project')
  .option('--no-deps', 'Skip dependency audit')
  .action(scoreCommand);

// -----------------------------------------------------------------------------
// AUDIT COMMAND (v4.0 — Full Security Audit)
// -----------------------------------------------------------------------------
program
  .command('audit [path]')
  .description('Full security audit: secrets + 12 agents + deps + score + remediation plan')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--csv', 'Output results as CSV')
  .option('--md', 'Output results as Markdown')
  .option('--html [file]', 'HTML report path (default: ship-safe-report.html)')
  .option('--compare', 'Show detailed comparison with last scan')
  .option('--timeout <ms>', 'Per-agent timeout in milliseconds (default: 30000)', parseInt)
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('--no-cache', 'Force full rescan (ignore cached results)')
  .option('--baseline', 'Only show findings not in the baseline')
  .option('--pdf [file]', 'Generate PDF report (requires Chrome/Chromium)')
  .option('-v, --verbose', 'Verbose output')
  .action(auditCommand);

// -----------------------------------------------------------------------------
// RED TEAM COMMAND (v4.0 — Multi-Agent Security Audit)
// -----------------------------------------------------------------------------
program
  .command('red-team [path]')
  .description('Multi-agent security audit: 12 agents scan for 50+ attack classes')
  .option('--agents <list>', 'Comma-separated list of agents to run')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--html [file]', 'Generate HTML security report')
  .option('--sbom [file]', 'Generate CycloneDX SBOM')
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('-v, --verbose', 'Verbose output')
  .action(redTeamCommand);

// -----------------------------------------------------------------------------
// WATCH COMMAND
// -----------------------------------------------------------------------------
program
  .command('watch [path]')
  .description('Continuous monitoring: watch files for security issues in real-time')
  .option('--poll', 'Use polling mode (for network drives)')
  .action(watchCommand);

// -----------------------------------------------------------------------------
// SBOM COMMAND
// -----------------------------------------------------------------------------
program
  .command('sbom [path]')
  .description('Generate Software Bill of Materials (CycloneDX SBOM)')
  .option('-o, --output <file>', 'Output file path', 'sbom.json')
  .action((targetPath = '.', options) => {
    const absolutePath = join(process.cwd(), targetPath);
    const sbom = new SBOMGenerator();
    sbom.generateToFile(absolutePath, options.output);
    console.log(chalk.green(`✔ SBOM saved to ${options.output}`));
  });

// -----------------------------------------------------------------------------
// POLICY COMMAND
// -----------------------------------------------------------------------------
program
  .command('policy <action>')
  .description('Manage security policies (init: create policy template)')
  .action((action) => {
    if (action === 'init') {
      const policyPath = PolicyEngine.generateTemplate(process.cwd());
      console.log(chalk.green(`✔ Policy template created: ${policyPath}`));
      console.log(chalk.gray('  Edit .ship-safe.policy.json to configure your security policy.'));
    } else {
      console.log(chalk.yellow(`Unknown policy action: ${action}. Use: policy init`));
    }
  });

// -----------------------------------------------------------------------------
// BASELINE COMMAND (v4.3)
// -----------------------------------------------------------------------------
program
  .command('baseline [path]')
  .description('Create/manage a findings baseline — only report new findings on subsequent scans')
  .option('--diff', 'Show what changed since baseline')
  .option('--clear', 'Remove the baseline')
  .action(baselineCommand);

// -----------------------------------------------------------------------------
// DOCTOR COMMAND
// -----------------------------------------------------------------------------
program
  .command('doctor')
  .description('Diagnose environment: check Node.js, git, API keys, cache, and dependencies')
  .action(doctorCommand);

// -----------------------------------------------------------------------------
// PARSE AND RUN
// -----------------------------------------------------------------------------

// Show help if no command provided
if (process.argv.length === 2) {
  console.log(banner);
  console.log(chalk.yellow('\nQuick start:\n'));
  console.log(chalk.cyan.bold('  v4.3 — Full Security Audit'));
  console.log(chalk.white('  npx ship-safe audit .       ') + chalk.gray('# Full audit: secrets + agents + deps + remediation plan'));
  console.log(chalk.white('  npx ship-safe red-team .    ') + chalk.gray('# 12-agent red team scan (50+ attack classes)'));
  console.log(chalk.white('  npx ship-safe watch .       ') + chalk.gray('# Continuous monitoring mode'));
  console.log(chalk.white('  npx ship-safe sbom .        ') + chalk.gray('# Generate CycloneDX SBOM'));
  console.log(chalk.white('  npx ship-safe policy init   ') + chalk.gray('# Create security policy template'));
  console.log(chalk.white('  npx ship-safe doctor        ') + chalk.gray('# Check environment and configuration'));
  console.log();
  console.log(chalk.gray('  Core commands:'));
  console.log(chalk.white('  npx ship-safe agent .       ') + chalk.gray('# AI audit: scan + classify + auto-fix'));
  console.log(chalk.white('  npx ship-safe scan .        ') + chalk.gray('# Scan for secrets'));
  console.log(chalk.white('  npx ship-safe remediate .   ') + chalk.gray('# Auto-fix: rewrite code + write .env'));
  console.log(chalk.white('  npx ship-safe rotate .      ') + chalk.gray('# Revoke exposed keys (provider guides)'));
  console.log(chalk.white('  npx ship-safe deps .        ') + chalk.gray('# Audit dependencies for CVEs'));
  console.log(chalk.white('  npx ship-safe score .       ') + chalk.gray('# Security health score (0-100)'));
  console.log(chalk.white('  npx ship-safe guard         ') + chalk.gray('# Block git push if secrets found'));
  console.log(chalk.white('  npx ship-safe init          ') + chalk.gray('# Add security configs to your project'));
  console.log(chalk.white('\n  npx ship-safe --help        ') + chalk.gray('# Show all options'));
  console.log();
  process.exit(0);
}

program.parse();
