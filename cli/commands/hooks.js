/**
 * Hooks Command
 * =============
 *
 * Installs ship-safe as PreToolUse / PostToolUse hooks in Claude Code
 * (~/.claude/settings.json). Once installed, ship-safe runs automatically
 * on every Write, Edit, and Bash tool call — blocking secrets before they
 * land on disk and feeding advisory findings back into the conversation.
 *
 * USAGE:
 *   npx ship-safe hooks install     Install hooks into ~/.claude/settings.json
 *   npx ship-safe hooks remove      Remove ship-safe hooks
 *   npx ship-safe hooks status      Show whether hooks are installed
 *
 * HOOK BEHAVIOUR:
 *   PreToolUse  — blocks Write/Edit if critical secrets detected; blocks
 *                 dangerous Bash patterns (curl|bash, credential exfiltration)
 *   PostToolUse — scans the written file and injects advisory findings into
 *                 Claude's context (never blocks — just informs)
 *
 * STABLE PATH STRATEGY:
 *   npx caches packages in a volatile temp directory. Writing that temp path
 *   to ~/.claude/settings.json means hooks break silently as soon as npx
 *   clears or rotates its cache. Instead, we copy the three hook scripts to
 *   ~/.ship-safe/hooks/ (a stable, user-owned directory) and register those
 *   paths. They survive npx cache rotations and package updates.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Source: hook scripts shipped inside the package
const PKG_HOOK_DIR = path.resolve(__dirname, '../hooks');

// Stable destination: user-owned, survives npx cache rotations
const STABLE_HOOK_DIR = path.join(os.homedir(), '.ship-safe', 'hooks');
const PRE_HOOK_SCRIPT  = path.join(STABLE_HOOK_DIR, 'pre-tool-use.js');
const POST_HOOK_SCRIPT = path.join(STABLE_HOOK_DIR, 'post-tool-use.js');

// Claude Code settings.json location
const CLAUDE_SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');

// The command strings we register (use stable paths)
const PRE_COMMAND  = `node "${PRE_HOOK_SCRIPT}"`;
const POST_COMMAND = `node "${POST_HOOK_SCRIPT}"`;

// =============================================================================
// Public API
// =============================================================================

export async function hooksCommand(action = 'install', _options = {}) {
  switch (action) {
    case 'install': return install();
    case 'remove':  return remove();
    case 'status':  return status();
    default:
      console.error(chalk.red(`Unknown action: ${action}. Use: install | remove | status`));
      process.exit(1);
  }
}

// =============================================================================
// Install
// =============================================================================

function install() {
  // ── 1. Copy hook scripts to stable location ────────────────────────────────
  const scripts = ['pre-tool-use.js', 'post-tool-use.js', 'patterns.js'];

  for (const script of scripts) {
    const src = path.join(PKG_HOOK_DIR, script);
    if (!fs.existsSync(src)) {
      console.error(chalk.red(`Hook script not found: ${src}. Try reinstalling ship-safe.`));
      process.exit(1);
    }
  }

  try {
    fs.mkdirSync(STABLE_HOOK_DIR, { recursive: true });
    for (const script of scripts) {
      fs.copyFileSync(
        path.join(PKG_HOOK_DIR, script),
        path.join(STABLE_HOOK_DIR, script)
      );
    }
  } catch (err) {
    console.error(chalk.red(`Failed to copy hook scripts to ${STABLE_HOOK_DIR}: ${err.message}`));
    process.exit(1);
  }

  // ── 2. Register stable paths in ~/.claude/settings.json ───────────────────
  const settings = readSettings();
  ensureHooksStructure(settings);

  let changed = false;

  // PreToolUse: Write / Edit / MultiEdit / Bash
  const preEntry = buildEntry(
    ['Write', 'Edit', 'MultiEdit', 'Bash'],
    PRE_COMMAND,
    'ship-safe pre-tool-use: block secrets in writes, dangerous bash patterns'
  );
  if (!hasEntry(settings.hooks.PreToolUse, PRE_COMMAND)) {
    settings.hooks.PreToolUse.push(preEntry);
    changed = true;
  }

  // PostToolUse: Write / Edit / MultiEdit
  const postEntry = buildEntry(
    ['Write', 'Edit', 'MultiEdit'],
    POST_COMMAND,
    'ship-safe post-tool-use: advisory scan after file writes'
  );
  if (!hasEntry(settings.hooks.PostToolUse, POST_COMMAND)) {
    settings.hooks.PostToolUse.push(postEntry);
    changed = true;
  }

  if (!changed) {
    console.log(chalk.green('✔ ship-safe hooks are already installed.'));
    printStatus(settings);
    return;
  }

  writeSettings(settings);

  console.log(chalk.green.bold('\n✔ ship-safe hooks installed successfully.\n'));
  console.log(chalk.gray('  Hook scripts: ') + chalk.white(STABLE_HOOK_DIR));
  console.log(chalk.gray('  Settings file: ') + chalk.white(CLAUDE_SETTINGS_PATH));
  console.log();
  console.log(chalk.cyan('  What happens now:'));
  console.log(chalk.white('  Write / Edit    ') + chalk.gray('→ blocked if critical secrets detected in content'));
  console.log(chalk.white('  Bash            ') + chalk.gray('→ blocked on curl|bash, credential exfiltration patterns'));
  console.log(chalk.white('  Write / Edit    ') + chalk.gray('→ advisory scan after save (findings injected into context)'));
  console.log();
  console.log(chalk.gray('  To remove:  npx ship-safe hooks remove'));
  console.log(chalk.gray('  To verify:  npx ship-safe hooks status\n'));
}

// =============================================================================
// Remove
// =============================================================================

function remove() {
  const settings = readSettings();

  if (!settings.hooks) {
    console.log(chalk.yellow('No hooks configured in settings.json.'));
    return;
  }

  let removed = 0;

  for (const event of ['PreToolUse', 'PostToolUse']) {
    if (!Array.isArray(settings.hooks[event])) continue;
    const before = settings.hooks[event].length;
    settings.hooks[event] = settings.hooks[event].filter(entry => !isOurEntry(entry));
    removed += before - settings.hooks[event].length;
  }

  if (removed === 0) {
    console.log(chalk.yellow('No ship-safe hooks found in settings.json.'));
    return;
  }

  writeSettings(settings);
  console.log(chalk.green(`✔ Removed ${removed} ship-safe hook(s) from ${CLAUDE_SETTINGS_PATH}`));
  console.log(chalk.gray(`  Hook scripts kept at ${STABLE_HOOK_DIR} (safe to delete manually)`));
}

// =============================================================================
// Status
// =============================================================================

function status() {
  const settings = readSettings();
  printStatus(settings);
}

function printStatus(settings) {
  const preInstalled  = settings.hooks?.PreToolUse  && hasEntry(settings.hooks.PreToolUse,  PRE_COMMAND);
  const postInstalled = settings.hooks?.PostToolUse && hasEntry(settings.hooks.PostToolUse, POST_COMMAND);
  const scriptsExist  = fs.existsSync(PRE_HOOK_SCRIPT) && fs.existsSync(POST_HOOK_SCRIPT);

  console.log(chalk.bold('\nship-safe Claude Code hooks status:\n'));
  console.log(
    (preInstalled  ? chalk.green('  ✔') : chalk.red('  ✗')) +
    chalk.white(' PreToolUse  ') +
    chalk.gray('(block secrets in writes, dangerous bash commands)')
  );
  console.log(
    (postInstalled ? chalk.green('  ✔') : chalk.red('  ✗')) +
    chalk.white(' PostToolUse ') +
    chalk.gray('(advisory scan after file writes)')
  );
  console.log(
    (scriptsExist  ? chalk.green('  ✔') : chalk.yellow('  ✗')) +
    chalk.white(' Hook scripts') +
    chalk.gray(` (${STABLE_HOOK_DIR})`)
  );
  console.log();

  if (!preInstalled || !postInstalled) {
    console.log(chalk.gray('  Run: npx ship-safe hooks install'));
  }
  console.log();
}

// =============================================================================
// Settings helpers
// =============================================================================

function readSettings() {
  try {
    if (fs.existsSync(CLAUDE_SETTINGS_PATH)) {
      return JSON.parse(fs.readFileSync(CLAUDE_SETTINGS_PATH, 'utf8'));
    }
  } catch {
    // If the file exists but is malformed, back it up and start fresh
    const backup = CLAUDE_SETTINGS_PATH + '.bak';
    try { fs.copyFileSync(CLAUDE_SETTINGS_PATH, backup); } catch {}
    console.warn(chalk.yellow(`Warning: could not parse existing settings.json — backed up to ${backup}`));
  }
  return {};
}

function writeSettings(settings) {
  const dir = path.dirname(CLAUDE_SETTINGS_PATH);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2) + '\n', 'utf8');
}

function ensureHooksStructure(settings) {
  if (!settings.hooks) settings.hooks = {};
  if (!Array.isArray(settings.hooks.PreToolUse))  settings.hooks.PreToolUse  = [];
  if (!Array.isArray(settings.hooks.PostToolUse)) settings.hooks.PostToolUse = [];
}

function buildEntry(matchers, command, description) {
  return {
    matcher: matchers.join('|'),
    hooks: [
      {
        type: 'command',
        command,
        description,
      },
    ],
  };
}

function hasEntry(list, command) {
  if (!Array.isArray(list)) return false;
  return list.some(entry =>
    Array.isArray(entry.hooks) &&
    entry.hooks.some(h => h.command === command)
  );
}

function isOurEntry(entry) {
  if (!Array.isArray(entry.hooks)) return false;
  return entry.hooks.some(h => h.command === PRE_COMMAND || h.command === POST_COMMAND);
}
