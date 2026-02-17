/**
 * Guard Command
 * =============
 *
 * Installs a git pre-push hook that runs ship-safe scan before every push.
 * If secrets are found, the push is blocked.
 *
 * USAGE:
 *   ship-safe guard                    Install pre-push hook
 *   ship-safe guard --pre-commit       Install pre-commit hook instead
 *   ship-safe guard remove             Remove installed hooks
 *
 * HUSKY SUPPORT:
 *   If a .husky/ directory is detected, the hook is added there instead.
 *   Otherwise it goes directly into .git/hooks/.
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import * as output from '../utils/output.js';

// =============================================================================
// HOOK SCRIPTS
// =============================================================================

const PRE_PUSH_HOOK = `#!/bin/sh
# ship-safe pre-push hook
# Scans for leaked secrets before every git push.
# Remove this hook with: npx ship-safe guard remove

echo ""
echo "🔍 ship-safe: Scanning for secrets before push..."

npx --yes ship-safe scan . --json > /tmp/ship-safe-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ ship-safe: Secrets detected! Push blocked."
  echo ""
  echo "Run 'npx ship-safe scan .' to see details."
  echo "Fix the issues, then push again."
  echo ""
  echo "To skip this check (not recommended):"
  echo "  git push --no-verify"
  echo ""
  rm -f /tmp/ship-safe-scan.json
  exit 1
fi

echo "✅ ship-safe: No secrets detected. Pushing..."
rm -f /tmp/ship-safe-scan.json
exit 0
`;

const PRE_COMMIT_HOOK = `#!/bin/sh
# ship-safe pre-commit hook
# Scans staged files for leaked secrets before every commit.
# Remove this hook with: npx ship-safe guard remove

echo ""
echo "🔍 ship-safe: Scanning for secrets before commit..."

npx --yes ship-safe scan . --json > /tmp/ship-safe-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ ship-safe: Secrets detected! Commit blocked."
  echo ""
  echo "Run 'npx ship-safe scan .' to see details."
  echo "Fix the issues, then commit again."
  echo ""
  echo "To skip this check (not recommended):"
  echo "  git commit --no-verify"
  echo ""
  rm -f /tmp/ship-safe-scan.json
  exit 1
fi

echo "✅ ship-safe: No secrets detected. Committing..."
rm -f /tmp/ship-safe-scan.json
exit 0
`;

const HUSKY_PRE_PUSH = `#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo ""
echo "🔍 ship-safe: Scanning for secrets before push..."

npx ship-safe scan . --json > /tmp/ship-safe-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ ship-safe: Secrets detected! Push blocked."
  echo "Run 'npx ship-safe scan .' to see details."
  rm -f /tmp/ship-safe-scan.json
  exit 1
fi

echo "✅ ship-safe: No secrets detected."
rm -f /tmp/ship-safe-scan.json
`;

const HUSKY_PRE_COMMIT = `#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo ""
echo "🔍 ship-safe: Scanning for secrets before commit..."

npx ship-safe scan . --json > /tmp/ship-safe-scan.json 2>/dev/null

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ ship-safe: Secrets detected! Commit blocked."
  echo "Run 'npx ship-safe scan .' to see details."
  rm -f /tmp/ship-safe-scan.json
  exit 1
fi

echo "✅ ship-safe: No secrets detected."
rm -f /tmp/ship-safe-scan.json
`;

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function guardCommand(action, options = {}) {
  const cwd = process.cwd();

  // Verify this is a git repo
  const gitDir = findGitDir(cwd);
  if (!gitDir) {
    output.error('Not a git repository. Run this from your project root.');
    process.exit(1);
  }

  if (action === 'remove') {
    return removeHooks(gitDir, cwd);
  }

  return installHook(gitDir, cwd, options);
}

// =============================================================================
// INSTALL
// =============================================================================

function installHook(gitDir, cwd, options) {
  const hookType = options.preCommit ? 'pre-commit' : 'pre-push';
  const hookScript = options.preCommit ? PRE_COMMIT_HOOK : PRE_PUSH_HOOK;
  const huskyScript = options.preCommit ? HUSKY_PRE_COMMIT : HUSKY_PRE_PUSH;

  output.header('Installing ship-safe Guard');

  // Check for Husky
  const huskyDir = path.join(cwd, '.husky');
  const useHusky = fs.existsSync(huskyDir);

  if (useHusky) {
    installHuskyHook(huskyDir, hookType, huskyScript);
  } else {
    installGitHook(gitDir, hookType, hookScript);
  }

  console.log();
  console.log(chalk.gray('What happens now:'));
  console.log(chalk.gray(`  Every git ${hookType === 'pre-push' ? 'push' : 'commit'} will run ship-safe scan`));
  console.log(chalk.gray('  If secrets are found, the operation is blocked'));
  console.log(chalk.gray('  Use --no-verify to skip (not recommended)'));
  console.log();
  console.log(chalk.gray('To remove: npx ship-safe guard remove'));
}

function installGitHook(gitDir, hookType, script) {
  const hooksDir = path.join(gitDir, 'hooks');
  const hookPath = path.join(hooksDir, hookType);

  // Ensure hooks directory exists
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  // Check if hook already exists (not from ship-safe)
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (!existing.includes('ship-safe')) {
      output.warning(`Existing ${hookType} hook found. Appending ship-safe check.`);
      fs.appendFileSync(hookPath, '\n' + script);
      output.success(`Appended to .git/hooks/${hookType}`);
      return;
    }
    output.warning(`ship-safe guard already installed in .git/hooks/${hookType}`);
    return;
  }

  fs.writeFileSync(hookPath, script);
  // Make executable (chmod +x)
  try {
    fs.chmodSync(hookPath, '755');
  } catch {
    // Windows doesn't support chmod, but hooks still run via git
  }

  output.success(`Hook installed at .git/hooks/${hookType}`);
}

function installHuskyHook(huskyDir, hookType, script) {
  const hookPath = path.join(huskyDir, hookType);

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (!existing.includes('ship-safe')) {
      output.warning(`Existing Husky ${hookType} found. Appending ship-safe check.`);
      fs.appendFileSync(hookPath, '\n# ship-safe\n' + script.split('\n').slice(3).join('\n'));
      output.success(`Appended to .husky/${hookType}`);
      return;
    }
    output.warning(`ship-safe guard already installed in .husky/${hookType}`);
    return;
  }

  fs.writeFileSync(hookPath, script);
  try {
    fs.chmodSync(hookPath, '755');
  } catch {}

  output.success(`Hook installed at .husky/${hookType} (Husky detected)`);
}

// =============================================================================
// REMOVE
// =============================================================================

function removeHooks(gitDir, cwd) {
  output.header('Removing ship-safe Guard');

  let removed = 0;

  // Check .git/hooks
  const hookTypes = ['pre-push', 'pre-commit'];
  for (const hookType of hookTypes) {
    const hookPath = path.join(gitDir, 'hooks', hookType);
    if (fs.existsSync(hookPath)) {
      const content = fs.readFileSync(hookPath, 'utf-8');
      if (content.includes('ship-safe')) {
        if (content.trim() === PRE_PUSH_HOOK.trim() || content.trim() === PRE_COMMIT_HOOK.trim()) {
          // Ship-safe is the only hook — delete the file
          fs.unlinkSync(hookPath);
          output.success(`Removed .git/hooks/${hookType}`);
        } else {
          // Other hooks exist — only remove ship-safe lines
          const cleaned = content
            .replace(/# ship-safe[\s\S]*?exit 0\n/g, '')
            .trimEnd() + '\n';
          fs.writeFileSync(hookPath, cleaned);
          output.success(`Removed ship-safe from .git/hooks/${hookType}`);
        }
        removed++;
      }
    }

    // Check .husky
    const huskyHookPath = path.join(cwd, '.husky', hookType);
    if (fs.existsSync(huskyHookPath)) {
      const content = fs.readFileSync(huskyHookPath, 'utf-8');
      if (content.includes('ship-safe')) {
        fs.unlinkSync(huskyHookPath);
        output.success(`Removed .husky/${hookType}`);
        removed++;
      }
    }
  }

  if (removed === 0) {
    output.warning('No ship-safe hooks found.');
  }
}

// =============================================================================
// UTILITIES
// =============================================================================

function findGitDir(startPath) {
  let current = startPath;

  while (true) {
    const gitPath = path.join(current, '.git');
    if (fs.existsSync(gitPath)) {
      return gitPath;
    }
    const parent = path.dirname(current);
    if (parent === current) return null; // Reached filesystem root
    current = parent;
  }
}
