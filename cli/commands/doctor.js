/**
 * Doctor Command — Environment Diagnostics
 * ==========================================
 *
 * Checks Node.js version, git, npm, API keys, ignore files,
 * cache directory, and package version.
 *
 * USAGE:
 *   npx ship-safe doctor
 */

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url); // ship-safe-ignore — module's own path via import.meta.url, not user input
const __dirname = dirname(__filename);
const PACKAGE_VERSION = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8')).version;

export async function doctorCommand() {
  console.log();
  console.log(chalk.cyan.bold('  Ship Safe Doctor'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log();

  let allGood = true;

  // 1. Node.js version
  const nodeVersion = process.version;
  const nodeMajor = parseInt(nodeVersion.slice(1), 10);
  if (nodeMajor >= 18) {
    pass(`Node.js ${nodeVersion} (requires ≥18)`);
  } else {
    fail(`Node.js ${nodeVersion} — requires ≥18`);
    allGood = false;
  }

  // 2. Git
  try {
    const gitVersion = execFileSync('git', ['--version'], { encoding: 'utf-8' }).trim();
    pass(gitVersion.replace('git version ', 'git v'));
  } catch {
    fail('git not found (needed for guard, git-history-scanner)');
    allGood = false;
  }

  // 3. Package manager
  const managers = ['npm', 'yarn', 'pnpm'];
  let foundPm = false;
  for (const pm of managers) {
    try {
      const ver = execFileSync(pm, ['--version'], { encoding: 'utf-8', shell: true }).trim();
      pass(`${pm} v${ver}`);
      foundPm = true;
      break;
    } catch { /* try next */ }
  }
  if (!foundPm) {
    fail('No package manager found (npm/yarn/pnpm)');
    allGood = false;
  }

  // 4. API keys
  const apiKeys = [
    { name: 'Anthropic API key', env: 'ANTHROPIC_API_KEY', required: false },
    { name: 'OpenAI API key', env: 'OPENAI_API_KEY', required: false },
    { name: 'Google AI API key', env: 'GOOGLE_API_KEY', required: false },
  ];
  for (const key of apiKeys) {
    if (process.env[key.env]) {
      pass(`${key.name} configured`);
    } else {
      info(`${key.name} not set (optional — for AI classification)`);
    }
  }

  // 5. .ship-safeignore
  const cwd = process.cwd();
  const ignorePath = path.join(cwd, '.ship-safeignore');
  if (fs.existsSync(ignorePath)) {
    try {
      const patterns = fs.readFileSync(ignorePath, 'utf-8')
        .split('\n').filter(l => l.trim() && !l.startsWith('#')).length;
      pass(`.ship-safeignore found (${patterns} patterns)`);
    } catch {
      pass('.ship-safeignore found');
    }
  } else {
    info('.ship-safeignore not found (run: ship-safe init)');
  }

  // 6. Cache directory
  const cacheDir = path.join(cwd, '.ship-safe');
  if (fs.existsSync(cacheDir)) {
    try {
      const testFile = path.join(cacheDir, '.doctor-test');
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      pass('Cache directory writable');
    } catch {
      fail('Cache directory not writable');
      allGood = false;
    }
  } else {
    info('Cache directory does not exist yet (created on first scan)');
  }

  // 7. Version check
  pass(`ship-safe v${PACKAGE_VERSION}`);
  try {
    const latest = execFileSync('npm', ['view', 'ship-safe', 'version'], {
      encoding: 'utf-8', timeout: 5000, shell: true,
    }).trim();
    if (latest && latest !== PACKAGE_VERSION) {
      const msg = ['v', latest, ' available (current: v', PACKAGE_VERSION, ')'].join('');
      info(msg);
    } else if (latest) {
      pass('Up to date');
    }
  } catch {
    // Skip version check if npm view fails
  }

  console.log();
  if (allGood) {
    console.log(chalk.green.bold('  All checks passed!'));
  } else {
    console.log(chalk.yellow.bold('  Some checks failed. See above for details.'));
  }
  console.log();
}

function pass(msg) {
  console.log(chalk.green('  ✔ ') + chalk.white(msg));
}

function fail(msg) {
  console.log(chalk.red('  ✗ ') + chalk.red(msg));
}

function info(msg) {
  console.log(chalk.gray('  ○ ') + chalk.gray(msg));
}

export default doctorCommand;
