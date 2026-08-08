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
const STATUS_LINE_SCRIPT = path.join(STABLE_HOOK_DIR, 'status-line.js');

// Claude Code settings.json location
const CLAUDE_SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');

// The command strings we register (use stable paths)
const PRE_COMMAND  = `node "${PRE_HOOK_SCRIPT}"`;
const POST_COMMAND = `node "${POST_HOOK_SCRIPT}"`;
const STATUS_LINE_COMMAND = `node "${STATUS_LINE_SCRIPT}"`;

export const HOOK_COMMANDS = { preToolUse: PRE_COMMAND, postToolUse: POST_COMMAND, statusLine: STATUS_LINE_COMMAND };

// =============================================================================
// Public API
// =============================================================================

export async function hooksCommand(action = 'install', options = {}) {
  switch (action) {
    case 'install': return install();
    case 'remove':  return remove();
    case 'status':  return status(options);
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
  const scripts = ['pre-tool-use.js', 'post-tool-use.js', 'patterns.js', 'status-line.js'];

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

  // Claude Code supports one statusLine command. Do not overwrite another
  // integration's status line; the hooks still install and status reports the
  // conflict explicitly.
  const hasOurStatusLine = settings.statusLine?.command === STATUS_LINE_COMMAND;
  const hasConflictingStatusLine = Boolean(settings.statusLine && !hasOurStatusLine);
  if (!settings.statusLine || hasOurStatusLine) {
    if (!hasOurStatusLine) {
      settings.statusLine = {
        type: 'command',
        command: STATUS_LINE_COMMAND,
        padding: 0,
      };
      changed = true;
    }
  } else if (hasConflictingStatusLine) {
    console.log(chalk.yellow('  Note: an existing Claude Code status line was preserved; Ship Safe did not overwrite it.'));
  }

  if (!changed) {
    console.log(chalk.green('✔ ship-safe hooks are already installed.'));
    printStatus(getHookStatus(settings, {
      preToolUse: fs.existsSync(PRE_HOOK_SCRIPT),
      postToolUse: fs.existsSync(POST_HOOK_SCRIPT),
      statusLine: fs.existsSync(STATUS_LINE_SCRIPT),
    }));
    return;
  }

  writeSettings(settings);

  console.log(chalk.green.bold('\n✔ ship-safe hooks installed successfully.\n'));
  console.log(chalk.gray('  Hook scripts: ') + chalk.white(STABLE_HOOK_DIR));
  console.log(chalk.gray('  Settings file: ') + chalk.white(CLAUDE_SETTINGS_PATH));
  console.log(chalk.gray('  Status line:    ') + chalk.white('Protected by Ship Safe (when hooks are ready)'));
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

  if (!settings.hooks && settings.statusLine?.command !== STATUS_LINE_COMMAND) {
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

  if (settings.statusLine?.command === STATUS_LINE_COMMAND) {
    delete settings.statusLine;
    removed += 1;
  }

  if (removed === 0) {
    console.log(chalk.yellow('No ship-safe hooks or status line found in settings.json.'));
    return;
  }

  writeSettings(settings);
  console.log(chalk.green(`✔ Removed ${removed} ship-safe hook(s) from ${CLAUDE_SETTINGS_PATH}`));
  console.log(chalk.gray(`  Hook scripts kept at ${STABLE_HOOK_DIR} (safe to delete manually)`));
}

// =============================================================================
// Status
// =============================================================================

function status(options = {}) {
  const settingsState = readSettingsState({ quiet: Boolean(options.json) });
  const hookStatus = getHookStatus(settingsState.settings, {
    preToolUse: fs.existsSync(PRE_HOOK_SCRIPT),
    postToolUse: fs.existsSync(POST_HOOK_SCRIPT),
    statusLine: fs.existsSync(STATUS_LINE_SCRIPT),
  }, settingsState.valid);

  if (options.json) {
    process.stdout.write(JSON.stringify(hookStatus, null, 2) + '\n');
  } else {
    printStatus(hookStatus);
  }

  process.exitCode = hookStatus.protected ? 0 : 1;
}

export function getHookStatus(settings, scripts, settingsValid = true) {
  const preRegistered = Boolean(settings.hooks?.PreToolUse && hasEntry(settings.hooks.PreToolUse, PRE_COMMAND));
  const postRegistered = Boolean(settings.hooks?.PostToolUse && hasEntry(settings.hooks.PostToolUse, POST_COMMAND));
  const preReady = preRegistered && scripts.preToolUse;
  const postReady = postRegistered && scripts.postToolUse;
  const protectedState = settingsValid && preReady && postReady;
  const hasPartialState = preRegistered || postRegistered || scripts.preToolUse || scripts.postToolUse;

  return {
    schemaVersion: 1,
    integration: 'claude-code',
    state: protectedState ? 'active' : hasPartialState ? 'partial' : 'inactive',
    protected: protectedState,
    settings: { valid: settingsValid, path: CLAUDE_SETTINGS_PATH },
    hooks: {
      preToolUse: { registered: preRegistered, scriptPresent: scripts.preToolUse, ready: preReady },
      postToolUse: { registered: postRegistered, scriptPresent: scripts.postToolUse, ready: postReady },
    },
    statusLine: {
      registered: settings.statusLine?.command === STATUS_LINE_COMMAND,
      scriptPresent: Boolean(scripts.statusLine),
      ready: settings.statusLine?.command === STATUS_LINE_COMMAND && Boolean(scripts.statusLine),
      conflict: Boolean(settings.statusLine && settings.statusLine.command !== STATUS_LINE_COMMAND),
    },
    scripts: { directory: STABLE_HOOK_DIR },
  };
}

function printStatus(hookStatus) {
  const preReady = hookStatus.hooks.preToolUse.ready;
  const postReady = hookStatus.hooks.postToolUse.ready;
  const scriptsExist = hookStatus.hooks.preToolUse.scriptPresent && hookStatus.hooks.postToolUse.scriptPresent;

  console.log(chalk.bold('\nship-safe Claude Code hooks status:\n'));
  console.log(
    (preReady  ? chalk.green('  ✔') : chalk.red('  ✗')) +
    chalk.white(' PreToolUse  ') +
    chalk.gray('(block secrets in writes, dangerous bash commands)')
  );
  console.log(
    (hookStatus.statusLine.ready ? chalk.green('  ✔') : chalk.yellow('  ○')) +
    chalk.white(' Status line ') +
    chalk.gray('(Protected by Ship Safe in Claude Code)')
  );
  console.log(
    (postReady ? chalk.green('  ✔') : chalk.red('  ✗')) +
    chalk.white(' PostToolUse ') +
    chalk.gray('(advisory scan after file writes)')
  );
  console.log(
    (scriptsExist  ? chalk.green('  ✔') : chalk.yellow('  ✗')) +
    chalk.white(' Hook scripts') +
    chalk.gray(` (${STABLE_HOOK_DIR})`)
  );
  console.log();

  if (!hookStatus.protected) {
    console.log(chalk.gray('  Run: npx ship-safe hooks install'));
  }
  console.log();
}

// =============================================================================
// Settings helpers
// =============================================================================

function readSettings() {
  return readSettingsState().settings;
}

function readSettingsState({ quiet = false } = {}) {
  try {
    if (fs.existsSync(CLAUDE_SETTINGS_PATH)) {
      return { settings: JSON.parse(fs.readFileSync(CLAUDE_SETTINGS_PATH, 'utf8')), valid: true };
    }
  } catch {
    // If the file exists but is malformed, back it up and start fresh
    const backup = CLAUDE_SETTINGS_PATH + '.bak';
    try { fs.copyFileSync(CLAUDE_SETTINGS_PATH, backup); } catch {}
    if (!quiet) console.warn(chalk.yellow(`Warning: could not parse existing settings.json — backed up to ${backup}`));
    return { settings: {}, valid: false };
  }
  return { settings: {}, valid: true };
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
