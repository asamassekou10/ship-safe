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

export async function watchCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
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
