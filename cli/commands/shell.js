/**
 * Shell Command — Interactive REPL
 * =================================
 *
 * `ship-safe shell` drops you into a persistent interactive session.
 *
 * Slash commands:
 *   /scan             Re-scan the project and show a summary
 *   /agent            Run the interactive agent fix loop
 *   /undo             Revert the last fix
 *   /findings         List findings from the last scan
 *   /show <n>         Show the full detail of finding number <n>
 *   /clear            Clear the screen
 *   /help             List commands
 *   /quit             Exit the shell
 *
 * Anything else is treated as a free-form prompt to the configured LLM,
 * with the last scan results provided as context.
 */

import { createInterface } from 'readline';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { auditCommand } from './audit.js';
import { agentFixCommand } from './agent-fix.js';
import { undoCommand } from './undo.js';
import * as output from '../utils/output.js';

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export async function shellCommand(targetPath = '.', options = {}) {
  const root = path.resolve(targetPath);

  // Session state — persists across commands within this REPL
  const state = {
    root,
    provider:    null,
    lastScan:    null,
    history:     [], // [{ role: 'user'|'assistant', content }]
  };

  // Try to load a provider eagerly (non-fatal if none available)
  state.provider = autoDetectProvider(root, {
    provider: options.provider,
    model:    options.model,
    think:    options.think || false,
  });

  console.log();
  output.header('Ship Safe — Interactive Shell');
  console.log(chalk.gray(`  cwd:      ${root}`));
  console.log(chalk.gray(`  provider: ${state.provider ? chalk.cyan(state.provider.name) : chalk.yellow('none — set DEEPSEEK_API_KEY or similar')}`));
  console.log();
  console.log(chalk.gray('  Type /help for commands, anything else to ask the agent.'));
  console.log(chalk.gray('  /quit or Ctrl-D to exit.'));
  console.log();

  const rl = createInterface({
    input:    process.stdin,
    output:   process.stdout,
    terminal: true,
  });

  const ask = (prompt) => new Promise(resolve => rl.question(prompt, resolve));

  // Graceful Ctrl-D
  rl.on('close', () => {
    console.log();
    process.exit(0);
  });

  let running = true;
  while (running) {
    const line = (await ask(chalk.cyan('shipsafe › '))).trim();
    if (!line) continue;

    if (line.startsWith('/')) {
      running = await handleSlashCommand(line, state, options);
    } else {
      await handlePrompt(line, state);
    }
  }

  rl.close();
}

// =============================================================================
// SLASH COMMANDS
// =============================================================================

async function handleSlashCommand(line, state, options) {
  const [raw, ...args] = line.slice(1).split(/\s+/);
  const cmd = raw.toLowerCase();

  switch (cmd) {
    case 'help':
    case '?':
      printHelp();
      return true;

    case 'quit':
    case 'exit':
    case 'bye':
      console.log(chalk.gray('  Bye.'));
      return false;

    case 'clear':
      process.stdout.write('\x1Bc');
      return true;

    case 'scan': {
      const spinner = ora({ text: 'Scanning...', color: 'cyan' }).start();
      try {
        const result = await auditCommand(state.root, { _agenticInner: true, deep: false, deps: false, noAi: true });
        state.lastScan = result;
        spinner.stop();
        printScanSummary(result);
      } catch (err) {
        spinner.fail(err.message);
      }
      return true;
    }

    case 'findings': {
      if (!state.lastScan) {
        console.log(chalk.yellow('  No scan results yet. Run /scan first.'));
        return true;
      }
      printFindingsList(state.lastScan.findings ?? []);
      return true;
    }

    case 'show': {
      if (!state.lastScan) {
        console.log(chalk.yellow('  No scan results yet. Run /scan first.'));
        return true;
      }
      const n = parseInt(args[0], 10);
      const findings = state.lastScan.findings ?? [];
      if (!Number.isInteger(n) || n < 1 || n > findings.length) {
        console.log(chalk.yellow(`  Usage: /show <n>  (1..${findings.length})`));
        return true;
      }
      printFindingDetail(findings[n - 1], n);
      return true;
    }

    case 'agent':
    case 'fix': {
      // Hand off to agent command. Pass through caller options + any inline flags.
      const opts = { ...options };
      for (const a of args) {
        if (a === '--plan-only')   opts.planOnly = true;
        if (a === '--allow-dirty') opts.allowDirty = true;
        if (a === '--branch')      opts.branch = true;
        if (a === '--pr')          opts.pr = true;
        if (a.startsWith('--severity=')) opts.severity = a.slice('--severity='.length);
      }
      try {
        await agentFixCommand(state.root, opts);
      } catch (err) {
        console.log(chalk.red(`  Agent failed: ${err.message}`));
      }
      return true;
    }

    case 'undo': {
      try {
        await undoCommand(state.root, { all: args.includes('--all'), dryRun: args.includes('--dry-run') });
      } catch (err) {
        console.log(chalk.red(`  Undo failed: ${err.message}`));
      }
      return true;
    }

    case 'provider': {
      const name = args[0];
      if (!name) {
        console.log(chalk.gray(`  Current: ${state.provider?.name ?? 'none'}`));
        console.log(chalk.gray('  Usage: /provider <deepseek-flash|openai|kimi|anthropic|deepseek>'));
        return true;
      }
      const next = autoDetectProvider(state.root, { provider: name });
      if (!next) {
        console.log(chalk.yellow(`  Could not load provider "${name}" — is the API key set?`));
      } else {
        state.provider = next;
        console.log(chalk.green(`  Provider switched to ${next.name}.`));
      }
      return true;
    }

    default:
      console.log(chalk.yellow(`  Unknown command: /${cmd}. Type /help for the list.`));
      return true;
  }
}

// =============================================================================
// FREE-FORM PROMPT
// =============================================================================

async function handlePrompt(text, state) {
  if (!state.provider) {
    console.log(chalk.yellow('  No LLM provider available. Set DEEPSEEK_API_KEY (or another supported key) and restart.'));
    return;
  }

  state.history.push({ role: 'user', content: text });

  const systemPrompt = buildSystemPrompt(state);
  const userPrompt   = buildConversationPrompt(state);

  const spinner = ora({ text: `Asking ${state.provider.name}...`, color: 'cyan' }).start();
  try {
    const response = await state.provider.complete(systemPrompt, userPrompt, { maxTokens: 1500 });
    spinner.stop();
    state.history.push({ role: 'assistant', content: response.trim() });
    console.log();
    console.log(formatAssistant(response.trim()));
    console.log();
  } catch (err) {
    spinner.fail(`Provider call failed: ${err.message}`);
  }
}

function buildSystemPrompt(state) {
  const scanSummary = state.lastScan
    ? `Latest scan: score ${state.lastScan.score ?? '?'}/100, ${state.lastScan.findings?.length ?? 0} finding(s).`
    : 'No scan has been run yet in this session.';

  return [
    'You are the Ship Safe security agent embedded in a developer\'s CLI.',
    'You give precise, security-focused answers. Prefer concrete fixes and references over abstract advice.',
    `Project root: ${state.root}`,
    scanSummary,
    'When findings are referenced, cite them by index (1-based, in the order shown by /findings).',
  ].join('\n');
}

function buildConversationPrompt(state) {
  // Keep last ~10 turns to bound context size
  const recent = state.history.slice(-10);

  let context = '';
  if (state.lastScan?.findings?.length) {
    const findings = state.lastScan.findings.slice(0, 25).map((f, i) =>
      `${i + 1}. [${f.severity}] ${f.title}${f.file ? ` — ${f.file}${f.line ? `:${f.line}` : ''}` : ''}`,
    ).join('\n');
    context = `\nKnown findings:\n${findings}\n\n`;
  }

  const turns = recent.map(t => `${t.role === 'user' ? 'USER' : 'ASSISTANT'}: ${t.content}`).join('\n\n');
  return `${context}${turns}\n\nASSISTANT:`;
}

function formatAssistant(text) {
  return text
    .split('\n')
    .map(line => chalk.white(`  ${line}`))
    .join('\n');
}

// =============================================================================
// PRINTING
// =============================================================================

function printHelp() {
  console.log();
  console.log(chalk.bold('  Commands:'));
  console.log('    /scan                 Re-scan the project');
  console.log('    /findings             List the latest scan\'s findings');
  console.log('    /show <n>             Show full detail of finding <n>');
  console.log('    /agent [--plan-only]  Run the interactive fix loop');
  console.log('    /undo [--all]         Revert the last fix (or all)');
  console.log('    /provider <name>      Switch LLM provider');
  console.log('    /clear                Clear the screen');
  console.log('    /quit                 Exit');
  console.log();
  console.log(chalk.gray('  Or just type a question — the agent will answer with scan context.'));
  console.log();
}

function printScanSummary(result) {
  const findings = result.findings ?? [];
  const counts   = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  console.log();
  console.log(chalk.bold(`  Score: ${gradeColor(result.score)(`${result.score ?? '?'}/100`)}`));
  console.log(`  Findings: ${chalk.red(counts.critical || 0)} critical, ${chalk.red(counts.high || 0)} high, ${chalk.yellow(counts.medium || 0)} medium, ${chalk.blue(counts.low || 0)} low`);
  console.log();
  console.log(chalk.gray('  /findings to list, /agent to fix.'));
  console.log();
}

function printFindingsList(findings) {
  if (findings.length === 0) {
    console.log(chalk.green('  No findings.'));
    return;
  }
  // Sort by severity desc
  const sorted = [...findings].sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0));
  console.log();
  for (let i = 0; i < sorted.length; i++) {
    const f = sorted[i];
    console.log(`  ${chalk.gray(`${i + 1}.`.padStart(4))} ${sevTag(f.severity)} ${f.title} ${chalk.gray(f.file ?? '')}${f.line ? chalk.gray(`:${f.line}`) : ''}`);
  }
  console.log();
}

function printFindingDetail(f, n) {
  console.log();
  console.log(chalk.bold(`  Finding ${n}: ${f.title}`));
  console.log(`  Severity:    ${sevTag(f.severity)}`);
  if (f.file) console.log(`  File:        ${f.file}${f.line ? `:${f.line}` : ''}`);
  if (f.rule) console.log(`  Rule:        ${f.rule}`);
  if (f.cwe)  console.log(`  CWE:         ${f.cwe}`);
  if (f.description) {
    console.log();
    console.log(chalk.gray('  Description:'));
    console.log(`    ${f.description}`);
  }
  if (f.fix) {
    console.log();
    console.log(chalk.gray('  Suggested fix:'));
    console.log(`    ${f.fix}`);
  }
  console.log();
}

function sevTag(sev) {
  switch (sev) {
    case 'critical': return chalk.red.bold('[CRITICAL]');
    case 'high':     return chalk.red('[HIGH]');
    case 'medium':   return chalk.yellow('[MEDIUM]');
    case 'low':      return chalk.blue('[LOW]');
    default:         return chalk.gray(`[${(sev || 'INFO').toUpperCase()}]`);
  }
}

function gradeColor(score) {
  if (score == null) return chalk.gray;
  if (score >= 80) return chalk.green;
  if (score >= 60) return chalk.yellow;
  return chalk.red;
}
