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
import { agentFixCommand } from '../commands/agent-fix.js';
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
import { scanMcpCommand } from '../commands/scan-mcp.js';
import { abomCommand } from '../commands/abom.js';
import { updateIntelCommand } from '../commands/update-intel.js';
import { hooksCommand } from '../commands/hooks.js';
import { legalCommand } from '../commands/legal.js';
import { runLiveAdvisories } from '../commands/live-advisories.js';
import { envAuditCommand } from '../commands/env-audit.js';
import { autofixCommand } from '../commands/autofix.js';
import { teamReportCommand } from '../commands/team-report.js';
import { memoryCommand } from '../utils/security-memory.js';
import { playbookCommand } from '../utils/scan-playbook.js';
import { listPluginFiles, scaffoldPlugin } from '../utils/plugin-loader.js';
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
  .option('--hermes', 'Bootstrap Hermes Agent security config (allowlist, integrity hashes, CI)')
  .option('--from <url>', 'Fetch a pre-built Hermes config bundle from a setup URL (used with --hermes)')
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
  .option('--plan <file>', 'Execute a rotation plan downloaded from shipsafecli.com/rotate')
  .action(rotateCommand);

// -----------------------------------------------------------------------------
// AGENT COMMAND
// -----------------------------------------------------------------------------
program
  .command('agent [path]')
  .description('Interactive security agent: scan, plan each fix, ask before changing, verify the fix worked')
  .option('--plan-only', 'Generate plans for review but never write changes')
  .option('--severity <level>', 'Minimum severity to fix (critical|high|medium|low)', 'low')
  .option('--provider <name>', 'LLM provider: deepseek-flash | deepseek | openai | kimi | anthropic')
  .option('--model <model>', 'Specific model name to use')
  .option('--think', 'Enable extended thinking (GPT-5.5 reasoning_effort:high, Claude extended thinking)')
  .option('--allow-dirty', 'Allow running with uncommitted changes in the working tree')
  .option('--legacy', 'Use the legacy non-interactive Claude-only agent')
  .action((targetPath, options) => {
    if (options.legacy) {
      return agentCommand(targetPath, options);
    }
    return agentFixCommand(targetPath, options);
  });

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
  .description('Full security audit: secrets + 22 agents + deps + score + deep analysis + remediation plan')
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
  .option('--think', 'Enable extended thinking mode (GPT-5.5 reasoning_effort:high, Claude extended thinking)')
  .option('--local', 'Use local Ollama model for deep analysis (default: llama3.2)')
  .option('--model <model>', 'LLM model to use for deep/AI analysis')
  .option('--provider <name>', 'LLM provider: anthropic, openai, google, ollama, groq, together, mistral, cohere, deepseek, xai, kimi, lmstudio')
  .option('--base-url <url>', 'Custom OpenAI-compatible endpoint (e.g. http://localhost:1234/v1/chat/completions)')
  .option('--budget <cents>', 'Max spend in cents for deep analysis (default: 50)', parseInt)
  .option('--verify', 'Check if leaked secrets are still active (probes provider APIs)')
  .option('--include-legal', 'Also run the legal risk scan (DMCA, leaked source, IP disputes)')
  .option('--agentic [iterations]', 'Agentic scan→fix→verify loop (default: 3 iterations, target score: 75)', (v) => v ? parseInt(v) : true)
  .option('--agentic-target <score>', 'Target security score for agentic loop (default: 75)', parseInt)
  .option('--hermes-only', 'Run only Hermes-relevant agents (llm + supply-chain categories) for fast CI')
  .option('--fail-below <threshold>', 'Exit 1 if score is below threshold (number or "baseline")')
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
  .description('Multi-agent security audit: 22 agents scan for 80+ attack classes')
  .option('--agents <list>', 'Comma-separated list of agents to run')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--html [file]', 'Generate HTML security report')
  .option('--sbom [file]', 'Generate CycloneDX SBOM')
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('--deep', 'LLM-powered taint analysis for critical/high findings')
  .option('--swarm', 'Use AI swarm mode — 23 parallel agents via DeepSeek V4 Flash or Kimi K2.6 (requires DEEPSEEK_API_KEY or MOONSHOT_API_KEY)')
  .option('--think', 'Enable extended thinking mode (GPT-5.5 reasoning_effort:high, Claude extended thinking)')
  .option('--local', 'Use local Ollama model for deep analysis (default: llama3.2)')
  .option('--model <model>', 'LLM model for deep analysis')
  .option('--provider <name>', 'LLM provider: anthropic, openai, google, ollama, groq, together, mistral, cohere, deepseek, xai, kimi, lmstudio')
  .option('--base-url <url>', 'Custom OpenAI-compatible endpoint (e.g. http://localhost:1234/v1/chat/completions)')
  .option('--budget <cents>', 'Max spend in cents for deep analysis (default: 50)', parseInt)
  .option('-v, --verbose', 'Verbose output')
  .action(redTeamCommand);

// -----------------------------------------------------------------------------
// TEAM REPORT COMMAND
// -----------------------------------------------------------------------------
program
  .command('team-report [file]')
  .description('Convert Hermes Agent team output into a professional Ship Safe report')
  .option('--html [path]', 'Save as HTML report (default: team-report.html)')
  .option('--json', 'JSON output')
  .action(teamReportCommand);

// -----------------------------------------------------------------------------
// WATCH COMMAND
// -----------------------------------------------------------------------------
program
  .command('watch [path]')
  .description('Continuous monitoring: watch files for security issues in real-time')
  .option('--poll', 'Use polling mode (for network drives)')
  .option('--configs', 'Watch only agent config files (openclaw.json, .cursorrules, mcp.json, etc.)')
  .option('--deep', 'Run full agent scanning on changes (not just pattern matching)')
  .option('--stateful', 'Keep Kimi K2.6 conversation context between scans for incremental analysis (requires MOONSHOT_API_KEY)')
  .option('--model <model>', 'LLM model for stateful watch (default: kimi-k2.6)')
  .option('--provider <name>', 'LLM provider for stateful watch (default: kimi)')
  .option('--status', 'Show current watch status and exit')
  .option('--threshold <score>', 'Alert when score drops below threshold', parseInt)
  .option('--debounce <ms>', 'Debounce interval in ms (default: 1500)', parseInt)
  .option('--slack [webhook]', 'Post findings to Slack webhook URL (or set SHIP_SAFE_SLACK_WEBHOOK env var)')
  .option('--pr-comment', 'Post inline findings as GitHub PR review comments (requires gh CLI)')
  .action(watchCommand);

// -----------------------------------------------------------------------------
// ADVISORIES COMMAND
// -----------------------------------------------------------------------------
program
  .command('advisories [path]')
  .description('Check dependencies against live advisory feeds (OSV.dev, GitHub Advisories)')
  .option('--ecosystem <type>', 'Filter by ecosystem (npm, PyPI)')
  .option('--json', 'Output as JSON')
  .action(async (targetPath = '.', options) => {
    const { resolve } = await import('path');
    const absolutePath = resolve(targetPath);
    try {
      const result = await runLiveAdvisories(absolutePath, options);
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }
      console.log();
      console.log(chalk.cyan.bold('  Ship Safe — Live Advisories'));
      console.log(chalk.gray(`  Checked ${result.checked} dependencies against OSV.dev`));
      console.log();
      if (result.advisories.length === 0) {
        console.log(chalk.green('  ✔ No known advisories for your current dependency versions.\n'));
      } else {
        const malware = result.advisories.filter(a => a.isMalware);
        const vulns = result.advisories.filter(a => !a.isMalware);
        if (malware.length > 0) {
          console.log(chalk.red.bold(`  !! ${malware.length} MALWARE ADVISORY(S) FOUND`));
          for (const a of malware) {
            console.log(chalk.red(`     ${a.package}@${a.version} — ${a.id}: ${a.summary.slice(0, 80)}`));
          }
          console.log();
        }
        if (vulns.length > 0) {
          console.log(chalk.yellow(`  ${vulns.length} vulnerability advisory(s):`));
          for (const a of vulns) {
            const sev = a.severity === 'critical' ? chalk.red.bold(a.severity) : a.severity === 'high' ? chalk.yellow(a.severity) : chalk.blue(a.severity);
            console.log(`    ${sev} ${a.package}@${a.version} — ${a.id}`);
          }
          console.log();
        }
      }
    } catch (err) {
      console.error(chalk.red(`  Error: ${err.message}\n`));
      process.exit(1);
    }
  });

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
// SCAN-MCP COMMAND
// -----------------------------------------------------------------------------
program
  .command('scan-mcp [target]')
  .description('Analyze an MCP server\'s tool manifest for security issues before connecting')
  .option('--json', 'Output results as JSON')
  .action(scanMcpCommand);

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
// ENV AUDIT COMMAND
// -----------------------------------------------------------------------------
program
  .command('env-audit [path]')
  .description('Credential health check: verify .env coverage, cross-reference source, check git history')
  .option('--json', 'Output results as JSON')
  .action(envAuditCommand);

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
// AUTOFIX COMMAND
// -----------------------------------------------------------------------------
program
  .command('autofix [path]')
  .description('Apply LLM-generated security fixes from a deep analysis report and open a GitHub PR')
  .option('--report <file>', 'Path to ship-safe JSON report (default: ship-safe-report.json)')
  .option('--severity <level>', 'Minimum severity to fix: critical, high, medium (default: high)')
  .option('--dry-run', 'Preview fixes without applying them or creating a branch')
  .option('--yes', 'Skip confirmation prompt')
  .action((targetPath, options) => autofixCommand({ ...options, path: targetPath }));

// -----------------------------------------------------------------------------
// MEMORY COMMAND
// -----------------------------------------------------------------------------
program
  .command('memory [subcommand]')
  .description('Manage security memory: false-positive learning that auto-suppresses known safe findings')
  .addHelpText('after', `
Subcommands:
  list           Show all suppressed findings in memory (default)
  forget <key>   Remove a specific entry by key
  clear          Wipe all memory entries

How it works:
  When --deep analysis confirms a finding is a false positive, it is added to
  .ship-safe/memory.json and suppressed automatically on all future scans.
`)
  .argument('[args...]')
  .action((subcommand, args, options) => memoryCommand(subcommand, args, options));

// -----------------------------------------------------------------------------
// PLAYBOOK COMMAND
// -----------------------------------------------------------------------------
program
  .command('playbook [subcommand]')
  .description('Manage scan playbooks: repo-specific context injected into every LLM analysis')
  .addHelpText('after', `
Subcommands:
  show                Show the current playbook (default)
  add-note "text"     Add a custom note to the playbook

How it works:
  After 2+ scans, a playbook is auto-generated in .ship-safe/playbook.md with
  your repo's tech stack, auth patterns, and score history. This is injected
  into the LLM system prompt so deep analysis is more accurate for your project.
`)
  .argument('[args...]')
  .action((subcommand, args, options) => playbookCommand(subcommand, args, options));

// -----------------------------------------------------------------------------
// PLUGINS COMMAND
// -----------------------------------------------------------------------------
program
  .command('plugins [action]')
  .description('Manage custom security agent plugins from .ship-safe/agents/')
  .addHelpText('after', `
Actions:
  list              List loaded plugins (default)
  new <name>        Scaffold a new plugin in .ship-safe/agents/<name>.js

How it works:
  Drop any .js file into .ship-safe/agents/ that exports a default class
  extending BaseAgent with an analyze() method. It will be loaded automatically
  on every audit or watch --deep run.
`)
  .action((action, options) => {
    const rootPath = path.resolve(process.cwd());
    if (action === 'new') {
      const pluginName = options.args?.[0] || options._name || 'my-rule';
      try {
        const filePath = scaffoldPlugin(rootPath, pluginName);
        console.log(chalk.green(`  ✔ Plugin scaffolded: ${filePath}`));
        console.log(chalk.gray('  Edit the file to implement your custom rule, then run ship-safe audit to activate it.'));
      } catch (err) {
        console.error(chalk.red(`  Error: ${err.message}`));
        process.exit(1);
      }
    } else {
      // list
      const plugins = listPluginFiles(rootPath);
      if (plugins.length === 0) {
        console.log('\n  No custom plugins found in .ship-safe/agents/');
        console.log(chalk.gray('  Create one with: npx ship-safe plugins new my-rule\n'));
      } else {
        console.log(`\n  ${chalk.cyan.bold('Custom Plugins')} — ${plugins.length} found\n`);
        for (const p of plugins) {
          console.log(`  ${chalk.white(p.name)}  ${chalk.gray(`(${(p.size / 1024).toFixed(1)} KB)  ${p.path}`)}`);
        }
        console.log();
      }
    }
  });

// -----------------------------------------------------------------------------
// PARSE AND RUN
// -----------------------------------------------------------------------------

// Show help if no command provided
if (process.argv.length === 2) {
  console.log(banner);
  console.log(chalk.yellow('\nQuick start:\n'));
  console.log(chalk.cyan.bold('  v9.0 — Agent Studio, Teams & Findings'));
  console.log(chalk.white('  npx ship-safe audit .       ') + chalk.gray('# Full audit: secrets + 22 agents + deps + remediation'));
  console.log(chalk.white('  npx ship-safe audit . --deep') + chalk.gray('# LLM-powered taint analysis (Anthropic/Ollama)'));
  console.log(chalk.white('  npx ship-safe red-team .    ') + chalk.gray('# 22-agent red team scan (80+ attack classes)'));
  console.log(chalk.white('  npx ship-safe vibe-check .  ') + chalk.gray('# Fun security check with emoji & shareable badge'));
  console.log(chalk.white('  npx ship-safe benchmark .   ') + chalk.gray('# Compare score against industry averages'));
  console.log(chalk.white('  npx ship-safe ci .          ') + chalk.gray('# CI/CD mode: scan, score, exit code'));
  console.log(chalk.white('  npx ship-safe diff          ') + chalk.gray('# Scan only changed files (fast pre-commit)'));
  console.log(chalk.white('  npx ship-safe watch .       ') + chalk.gray('# Continuous monitoring mode'));
  console.log(chalk.white('  npx ship-safe openclaw .    ') + chalk.gray('# OpenClaw & agent config security scan'));
  console.log(chalk.white('  npx ship-safe scan-skill <u>') + chalk.gray('# Vet a skill before installing'));
  console.log(chalk.white('  npx ship-safe scan-mcp <url> ') + chalk.gray('# Vet an MCP server before connecting'));
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
  console.log(chalk.white('  npx ship-safe env-audit .   ') + chalk.gray('# Credential health check (after stripe projects env --pull)'));
  console.log(chalk.white('  npx ship-safe hooks install ') + chalk.gray('# Real-time security gate inside Claude Code (PreToolUse/PostToolUse)'));
  console.log(chalk.white('  npx ship-safe guard         ') + chalk.gray('# Block git push if secrets found'));
  console.log(chalk.white('  npx ship-safe init          ') + chalk.gray('# Add security configs to your project'));
  console.log();
  console.log(chalk.gray('  Intelligence commands:'));
  console.log(chalk.white('  npx ship-safe autofix .     ') + chalk.gray('# Apply LLM fixes from --deep report, open PR'));
  console.log(chalk.white('  npx ship-safe memory list   ') + chalk.gray('# View / manage false-positive memory'));
  console.log(chalk.white('  npx ship-safe playbook show ') + chalk.gray('# View repo-specific LLM context playbook'));
  console.log(chalk.white('  npx ship-safe plugins list  ') + chalk.gray('# Manage custom agent plugins'));
  console.log(chalk.white('  npx ship-safe watch . --deep --slack ') + chalk.gray('# Guardian mode with Slack alerts + PR comments'));
  console.log(chalk.white('\n  npx ship-safe --help        ') + chalk.gray('# Show all options'));
  console.log();
  process.exit(0);
}

program.parse();
