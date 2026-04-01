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
import { ciCommand } from '../commands/ci.js';
import { diffCommand } from '../commands/diff.js';
import { vibeCheckCommand } from '../commands/vibe-check.js';
import { benchmarkCommand } from '../commands/benchmark.js';
import { openclawCommand } from '../commands/openclaw.js';
import { scanSkillCommand } from '../commands/scan-skill.js';
import { abomCommand } from '../commands/abom.js';
import { updateIntelCommand } from '../commands/update-intel.js';
import { hooksCommand } from '../commands/hooks.js';
import { legalCommand } from '../commands/legal.js';
import { ABOMGenerator } from '../agents/abom-generator.js';
import { PolicyEngine } from '../agents/policy-engine.js';
import { SBOMGenerator } from '../agents/sbom-generator.js';

// =============================================================================
// CLI CONFIGURATION
// =============================================================================

const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';

// Read version from package.json
const __filename = fileURLToPath(import.meta.url); // ship-safe-ignore — module's own path via import.meta.url, not user input
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
  .option('--openclaw', 'Generate a hardened openclaw.json template')
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
  .option('--generate-hooks', 'Generate defensive Claude Code hooks (.claude/settings.json)')
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
  .description('Full security audit: secrets + 18 agents + deps + score + deep analysis + remediation plan')
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
  .option('--deep', 'LLM-powered taint analysis for critical/high findings')
  .option('--local', 'Use local Ollama model for deep analysis (default: llama3.2)')
  .option('--model <model>', 'LLM model to use for deep/AI analysis')
  .option('--provider <name>', 'LLM provider: anthropic, openai, google, ollama, groq, together, mistral, cohere, deepseek, xai, lmstudio')
  .option('--base-url <url>', 'Custom OpenAI-compatible endpoint (e.g. http://localhost:1234/v1/chat/completions)')
  .option('--budget <cents>', 'Max spend in cents for deep analysis (default: 50)', parseInt)
  .option('--verify', 'Check if leaked secrets are still active (probes provider APIs)')
  .option('--include-legal', 'Also run the legal risk scan (DMCA, leaked source, IP disputes)')
  .option('-v, --verbose', 'Verbose output')
  .action(auditCommand);

// -----------------------------------------------------------------------------
// DIFF COMMAND (v6.0 — Scan only changed files)
// -----------------------------------------------------------------------------
program
  .command('diff [ref]')
  .description('Scan only changed files (git diff) — fast pre-commit & PR scanning')
  .option('--staged', 'Scan only staged changes')
  .option('--json', 'Output results as JSON')
  .option('-p, --path <path>', 'Project path (default: cwd)')
  .option('--timeout <ms>', 'Per-agent timeout in milliseconds (default: 30000)', parseInt)
  .action(diffCommand);

// -----------------------------------------------------------------------------
// RED TEAM COMMAND (v4.0 — Multi-Agent Security Audit)
// -----------------------------------------------------------------------------
program
  .command('red-team [path]')
  .description('Multi-agent security audit: 18 agents scan for 80+ attack classes')
  .option('--agents <list>', 'Comma-separated list of agents to run')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--html [file]', 'Generate HTML security report')
  .option('--sbom [file]', 'Generate CycloneDX SBOM')
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('--deep', 'LLM-powered taint analysis for critical/high findings')
  .option('--local', 'Use local Ollama model for deep analysis (default: llama3.2)')
  .option('--model <model>', 'LLM model for deep analysis')
  .option('--provider <name>', 'LLM provider: anthropic, openai, google, ollama, groq, together, mistral, cohere, deepseek, xai, lmstudio')
  .option('--base-url <url>', 'Custom OpenAI-compatible endpoint (e.g. http://localhost:1234/v1/chat/completions)')
  .option('--budget <cents>', 'Max spend in cents for deep analysis (default: 50)', parseInt)
  .option('-v, --verbose', 'Verbose output')
  .action(redTeamCommand);

// -----------------------------------------------------------------------------
// WATCH COMMAND
// -----------------------------------------------------------------------------
program
  .command('watch [path]')
  .description('Continuous monitoring: watch files for security issues in real-time')
  .option('--poll', 'Use polling mode (for network drives)')
  .option('--configs', 'Watch only agent config files (openclaw.json, .cursorrules, mcp.json, etc.)')
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
// CI COMMAND (v5.0 — CI/CD Pipeline Integration)
// -----------------------------------------------------------------------------
program
  .command('ci [path]')
  .description('CI/CD pipeline mode: scan, score, exit 1 on failure — optimized for automation')
  .option('--threshold <score>', 'Minimum passing score (default: 75)', parseInt)
  .option('--fail-on <severity>', 'Fail on findings at this severity or above (critical, high, medium)')
  .option('--sarif <file>', 'Write SARIF output for GitHub Code Scanning')
  .option('--json', 'JSON output')
  .option('--no-deps', 'Skip dependency audit')
  .option('--baseline', 'Only check new findings (not in baseline)')
  .option('--github-pr', 'Post findings as a GitHub PR comment (requires gh CLI)')
  .action(ciCommand);

// -----------------------------------------------------------------------------
// VIBE CHECK COMMAND
// -----------------------------------------------------------------------------
program
  .command('vibe-check [path]')
  .description('Fun security check with emoji output, shareable score, and badge generator')
  .option('--badge', 'Generate a shields.io markdown badge for your README')
  .action(vibeCheckCommand);

// -----------------------------------------------------------------------------
// BENCHMARK COMMAND
// -----------------------------------------------------------------------------
program
  .command('benchmark [path]')
  .description('Compare your security score against industry averages')
  .option('--json', 'Output results as JSON')
  .action(benchmarkCommand);

// -----------------------------------------------------------------------------
// OPENCLAW COMMAND
// -----------------------------------------------------------------------------
program
  .command('openclaw [path]')
  .description('OpenClaw security scan: agent configs, MCP servers, skills, hooks')
  .option('--fix', 'Auto-harden OpenClaw and agent configurations')
  .option('--preflight', 'Exit non-zero on critical findings (for CI)')
  .option('--red-team', 'Simulate adversarial attacks against agent configs')
  .option('--json', 'Output results as JSON')
  .action(openclawCommand);

// -----------------------------------------------------------------------------
// SCAN-SKILL COMMAND
// -----------------------------------------------------------------------------
program
  .command('scan-skill [target]')
  .description('Analyze an AI agent skill for security issues before installing it')
  .option('--all', 'Scan all skills defined in openclaw.json')
  .option('--json', 'Output results as JSON')
  .action(scanSkillCommand);

// -----------------------------------------------------------------------------
// ABOM COMMAND
// -----------------------------------------------------------------------------
program
  .command('abom [path]')
  .description('Generate Agent Bill of Materials (CycloneDX ABOM) — MCP servers, skills, configs, LLM providers')
  .option('-o, --output <file>', 'Output file path', 'abom.json')
  .option('--json', 'Output to stdout as JSON')
  .action(abomCommand);

// -----------------------------------------------------------------------------
// HOOKS COMMAND (Claude Code PreToolUse / PostToolUse integration)
// -----------------------------------------------------------------------------
program
  .command('hooks [action]')
  .description('Manage Claude Code hooks — real-time security gate on every Write, Edit, and Bash call')
  .addHelpText('after', `
Actions:
  install   Register ship-safe as PreToolUse + PostToolUse hooks in ~/.claude/settings.json
  remove    Unregister ship-safe hooks
  status    Show whether hooks are installed

How it works:
  PreToolUse  — blocks Write/Edit if critical secrets are in the new content;
                blocks dangerous Bash patterns (curl|bash, credential exfiltration)
  PostToolUse — scans the file after it is written; injects advisory findings
                into Claude's context so issues are caught immediately
`)
  .action(hooksCommand);

// -----------------------------------------------------------------------------
// LEGAL COMMAND
// -----------------------------------------------------------------------------
program
  .command('legal [path]')
  .description('Legal risk audit: DMCA notices, leaked-source derivatives, IP disputes in dependencies')
  .option('--json', 'Output results as JSON')
  .action(legalCommand);

// -----------------------------------------------------------------------------
// UPDATE-INTEL COMMAND
// -----------------------------------------------------------------------------
program
  .command('update-intel')
  .description('Update threat intelligence feed (malicious skill hashes, compromised MCP servers)')
  .option('--url <url>', 'Custom feed URL')
  .action(updateIntelCommand);

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
  console.log(chalk.cyan.bold('  v6.0 — Full Security Audit'));
  console.log(chalk.white('  npx ship-safe audit .       ') + chalk.gray('# Full audit: secrets + 18 agents + deps + remediation'));
  console.log(chalk.white('  npx ship-safe audit . --deep') + chalk.gray('# LLM-powered taint analysis (Anthropic/Ollama)'));
  console.log(chalk.white('  npx ship-safe red-team .    ') + chalk.gray('# 18-agent red team scan (80+ attack classes)'));
  console.log(chalk.white('  npx ship-safe vibe-check .  ') + chalk.gray('# Fun security check with emoji & shareable badge'));
  console.log(chalk.white('  npx ship-safe benchmark .   ') + chalk.gray('# Compare score against industry averages'));
  console.log(chalk.white('  npx ship-safe ci .          ') + chalk.gray('# CI/CD mode: scan, score, exit code'));
  console.log(chalk.white('  npx ship-safe diff          ') + chalk.gray('# Scan only changed files (fast pre-commit)'));
  console.log(chalk.white('  npx ship-safe watch .       ') + chalk.gray('# Continuous monitoring mode'));
  console.log(chalk.white('  npx ship-safe openclaw .    ') + chalk.gray('# OpenClaw & agent config security scan'));
  console.log(chalk.white('  npx ship-safe scan-skill <u>') + chalk.gray('# Vet a skill before installing'));
  console.log(chalk.white('  npx ship-safe abom .        ') + chalk.gray('# Agent Bill of Materials (CycloneDX)'));
  console.log(chalk.white('  npx ship-safe sbom .        ') + chalk.gray('# Generate CycloneDX SBOM (CRA-ready)'));
  console.log(chalk.white('  npx ship-safe legal .        ') + chalk.gray('# Legal risk audit: DMCA, leaked source, IP disputes'));
  console.log(chalk.white('  npx ship-safe update-intel  ') + chalk.gray('# Update threat intelligence feed'));
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
  console.log(chalk.white('  npx ship-safe hooks install ') + chalk.gray('# Real-time security gate inside Claude Code (PreToolUse/PostToolUse)'));
  console.log(chalk.white('  npx ship-safe guard         ') + chalk.gray('# Block git push if secrets found'));
  console.log(chalk.white('  npx ship-safe init          ') + chalk.gray('# Add security configs to your project'));
  console.log(chalk.white('\n  npx ship-safe --help        ') + chalk.gray('# Show all options'));
  console.log();
  process.exit(0);
}

program.parse();
