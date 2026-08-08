#!/usr/bin/env node
/**
 * Claude Code status line for Ship Safe.
 *
 * This is intentionally self-contained because hooks are copied to a stable
 * user-owned directory during installation.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

const stableDir = path.join(os.homedir(), '.ship-safe', 'hooks');
const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
const preCommand = `node "${path.join(stableDir, 'pre-tool-use.js')}"`;
const postCommand = `node "${path.join(stableDir, 'post-tool-use.js')}"`;
const statusLineCommand = `node "${path.join(stableDir, 'status-line.js')}"`;

function hasHook(settings, event, command) {
  return Array.isArray(settings?.hooks?.[event]) && settings.hooks[event].some(entry =>
    Array.isArray(entry.hooks) && entry.hooks.some(hook => hook.command === command)
  );
}

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  } catch {
    return null;
  }
}

function isProtected(settings) {
  return Boolean(
    settings &&
    hasHook(settings, 'PreToolUse', preCommand) &&
    hasHook(settings, 'PostToolUse', postCommand) &&
    settings.statusLine?.command === statusLineCommand &&
    fs.existsSync(path.join(stableDir, 'pre-tool-use.js')) &&
    fs.existsSync(path.join(stableDir, 'post-tool-use.js'))
  );
}

const settings = readSettings();
if (isProtected(settings)) {
  process.stdout.write('\u001b[33m● Protected by Ship Safe\u001b[0m');
} else {
  process.stdout.write('\u001b[90m○ Ship Safe inactive\u001b[0m');
}
