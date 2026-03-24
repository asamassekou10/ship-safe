/**
 * Watch Command
 * ==============
 *
 * Continuous file monitoring mode. Watches for file changes
 * and incrementally scans modified files.
 *
 * USAGE:
 *   npx ship-safe watch [path]     Start watching for changes
 *   npx ship-safe watch . --poll   Use polling (for network drives)
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { SKIP_DIRS, SKIP_EXTENSIONS, SKIP_FILENAMES, SECRET_PATTERNS, SECURITY_PATTERNS } from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import * as output from '../utils/output.js';

// Agent config files to watch
const AGENT_CONFIG_PATTERNS = [
  '.cursorrules', '.windsurfrules', 'CLAUDE.md', 'AGENTS.md',
  '.github/copilot-instructions.md', '.aider.conf.yml',
  '.continue/config.json', 'openclaw.json', 'openclaw.config.json',
  'clawhub.json', 'mcp.json', '.claude/settings.json',
  '.cursor/mcp.json', '.vscode/mcp.json',
];

export async function watchCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  // Config-only watch mode
  if (options.configs) {
    return watchConfigs(absolutePath);
  }

  console.log();
  output.header('Ship Safe — Watch Mode');
  console.log();
  console.log(chalk.cyan('  Watching for file changes...'));
  console.log(chalk.gray('  Press Ctrl+C to stop'));
  console.log();

  const allPatterns = [...SECRET_PATTERNS, ...SECURITY_PATTERNS];
  const skipDirSet = SKIP_DIRS;
  let debounceTimer = null;
  const pendingFiles = new Set();

  // Use fs.watch recursively
  try {
    const watcher = fs.watch(absolutePath, { recursive: true }, (eventType, filename) => { // ship-safe-ignore — filename from fs.watch OS event, not user input
      if (!filename) return; // ship-safe-ignore

      const fullPath = path.join(absolutePath, filename); // ship-safe-ignore — filename from fs.watch, not user input
      const relPath = filename.replace(/\\/g, '/');

      // Skip directories we don't care about
      for (const skipDir of skipDirSet) {
        if (relPath.includes(`${skipDir}/`) || relPath.startsWith(`${skipDir}/`)) return;
      }

      // Skip non-code files
      const ext = path.extname(filename).toLowerCase(); // ship-safe-ignore — filename from fs.watch OS event
      if (SKIP_EXTENSIONS.has(ext)) return;
      if (SKIP_FILENAMES.has(path.basename(filename))) return; // ship-safe-ignore
      if (filename.endsWith('.min.js') || filename.endsWith('.min.css')) return;

      // Add to pending and debounce
      pendingFiles.add(fullPath);

      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const filesToScan = [...pendingFiles];
        pendingFiles.clear();
        scanChangedFiles(filesToScan, allPatterns, absolutePath);
      }, 300);
    });

    // Keep the process alive
    process.on('SIGINT', () => {
      watcher.close();
      console.log();
      output.info('Watch mode stopped.');
      process.exit(0);
    });

    // Prevent Node from exiting
    setInterval(() => {}, 1000 * 60 * 60);

  } catch (err) {
    output.error(`Watch failed: ${err.message}`);
    console.log(chalk.gray('  Try: npx ship-safe watch . --poll'));
    process.exit(1);
  }
}

function scanChangedFiles(files, patterns, rootPath) {
  const timestamp = new Date().toLocaleTimeString();
  let totalFindings = 0;

  for (const filePath of files) {
    if (!fs.existsSync(filePath)) continue;

    try {
      const stats = fs.statSync(filePath);
      if (stats.size > 1_000_000) continue;
    } catch {
      continue;
    }

    const findings = scanFile(filePath, patterns);
    if (findings.length > 0) {
      totalFindings += findings.length;
      const relPath = path.relative(rootPath, filePath);

      for (const f of findings) {
        const sevColor = f.severity === 'critical' ? chalk.red.bold
          : f.severity === 'high' ? chalk.yellow
          : chalk.blue;

        console.log(
          chalk.gray(`  [${timestamp}] `) +
          sevColor(`[${f.severity.toUpperCase()}]`) +
          chalk.white(` ${relPath}:${f.line} `) +
          chalk.gray(f.patternName)
        );
      }
    }
  }

  if (totalFindings === 0 && files.length > 0) {
    console.log(chalk.gray(`  [${timestamp}] ${files.length} file(s) scanned — clean`));
  }
}

function scanFile(filePath, patterns) {
  const findings = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/ship-safe-ignore/i.test(line)) continue;

      for (const pattern of patterns) {
        pattern.pattern.lastIndex = 0;
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
          findings.push({
            line: i + 1,
            patternName: pattern.name,
            severity: pattern.severity,
            matched: match[0],
            category: pattern.category || 'secret',
          });
        }
      }
    }
  } catch { /* skip */ }

  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.line}:${f.matched}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// =============================================================================
// CONFIG-ONLY WATCH MODE
// =============================================================================

async function watchConfigs(absolutePath) {
  console.log();
  output.header('Ship Safe — Agent Config Watch');
  console.log();
  console.log(chalk.cyan('  Watching agent config files for changes...'));
  console.log(chalk.gray('  Monitors: .cursorrules, CLAUDE.md, openclaw.json, mcp.json, .claude/settings.json, ...'));
  console.log(chalk.gray('  Press Ctrl+C to stop'));
  console.log();

  let debounceTimer = null;
  const pendingFiles = new Set();

  try {
    const watcher = fs.watch(absolutePath, { recursive: true }, (eventType, filename) => {
      if (!filename) return;

      // Check if this is an agent config file
      const relPath = filename.replace(/\\/g, '/');
      const isConfig = AGENT_CONFIG_PATTERNS.some(p => relPath === p || relPath.endsWith('/' + p));
      const isGlobMatch = relPath.match(/\.cursor\/rules\/.*\.mdc$/) ||
                          relPath.match(/\.openclaw\/.*\.json$/) ||
                          relPath.match(/\.claude\/commands\/.*\.md$/) ||
                          relPath.match(/\.claude\/memory\//);

      if (!isConfig && !isGlobMatch) return;

      const fullPath = path.join(absolutePath, filename);
      pendingFiles.add(fullPath);

      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(async () => {
        const filesToScan = [...pendingFiles];
        pendingFiles.clear();
        await scanConfigFiles(filesToScan, absolutePath);
      }, 300);
    });

    process.on('SIGINT', () => {
      watcher.close();
      console.log();
      output.info('Config watch stopped.');
      process.exit(0);
    });

    setInterval(() => {}, 1000 * 60 * 60);

  } catch (err) {
    output.error(`Watch failed: ${err.message}`);
    process.exit(1);
  }
}

async function scanConfigFiles(files, rootPath) {
  // Dynamic import to avoid circular dependency
  const { AgentConfigScanner } = await import('../agents/agent-config-scanner.js');
  const { MCPSecurityAgent } = await import('../agents/mcp-security-agent.js');

  const timestamp = new Date().toLocaleTimeString();
  const scanner = new AgentConfigScanner();
  const mcpScanner = new MCPSecurityAgent();

  for (const filePath of files) {
    if (!fs.existsSync(filePath)) {
      console.log(chalk.gray(`  [${timestamp}] ${path.relative(rootPath, filePath)} — deleted`));
      continue;
    }

    const relPath = path.relative(rootPath, filePath).replace(/\\/g, '/');
    console.log(chalk.cyan(`  [${timestamp}] Changed: ${relPath}`));

    // Git blame (best-effort)
    try {
      const { execSync } = await import('child_process');
      const blame = execSync(`git log -1 --format="%an (%ar)" -- "${filePath}"`, { cwd: rootPath, encoding: 'utf-8', timeout: 5000 }).trim();
      if (blame) console.log(chalk.gray(`    Last modified by: ${blame}`));
    } catch { /* not a git repo or git not available */ }

    // Run agent config scanner
    const context = { rootPath, files: [] };
    const [configFindings, mcpFindings] = await Promise.all([
      scanner.analyze(context),
      mcpScanner.analyze(context),
    ]);

    const findings = [...configFindings, ...mcpFindings].filter(f =>
      f.file && path.resolve(f.file) === path.resolve(filePath)
    );

    if (findings.length > 0) {
      for (const f of findings) {
        const sevColor = f.severity === 'critical' ? chalk.red.bold
          : f.severity === 'high' ? chalk.yellow
          : chalk.blue;
        console.log(`    ${sevColor(`[${f.severity.toUpperCase()}]`)} ${f.title || f.rule}`);
      }
    } else {
      console.log(chalk.green('    ✔ Clean'));
    }
    console.log();
  }
}
