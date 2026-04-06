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
import { ScoringEngine } from '../agents/scoring-engine.js';

// Agent config files to watch
const AGENT_CONFIG_PATTERNS = [
  '.cursorrules', '.windsurfrules', 'CLAUDE.md', 'AGENTS.md',
  '.github/copilot-instructions.md', '.aider.conf.yml',
  '.continue/config.json', 'openclaw.json', 'openclaw.config.json',
  'clawhub.json', 'mcp.json', '.claude/settings.json',
  '.cursor/mcp.json', '.vscode/mcp.json',
];

// Watch state persistence
const WATCH_DB_DIR = '.ship-safe';
const WATCH_DB_FILE = 'watch.json';

export async function watchCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  // Status mode: print current watch state and exit
  if (options.status) {
    return showWatchStatus(absolutePath);
  }

  // Config-only watch mode
  if (options.configs) {
    return watchConfigs(absolutePath);
  }

  // Deep mode: run full orchestrator on changes
  if (options.deep) {
    return watchDeep(absolutePath, options);
  }

  console.log();
  output.header('Ship Safe — Watch Mode');
  console.log();
  console.log(chalk.cyan('  Watching for file changes...'));
  console.log(chalk.gray('  Use --deep for full agent scanning, --status for current findings'));
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

// =============================================================================
// STATUS MODE
// =============================================================================

function showWatchStatus(rootPath) {
  const dbFile = path.join(rootPath, WATCH_DB_DIR, WATCH_DB_FILE);
  if (!fs.existsSync(dbFile)) {
    console.log('\n  No watch data found. Run: ship-safe watch . --deep\n');
    return;
  }

  try {
    const data = JSON.parse(fs.readFileSync(dbFile, 'utf-8'));
    console.log(`\n  ${chalk.cyan.bold('Ship Safe Watch — Status')}`);
    console.log(`  ${'─'.repeat(40)}`);
    console.log(`  Last scan:  ${data.lastScan || 'never'}`);
    console.log(`  Scans run:  ${data.scanCount || 0}`);
    console.log(`  Score:      ${data.score?.score ?? '?'}/100 ${data.score?.grade ?? ''}`);
    console.log(`  Findings:   ${data.score?.totalFindings ?? 0}`);

    if (data.agentic) {
      console.log(`  Agentic:    ${data.agentic.flagged}/${data.agentic.total} OWASP Agentic risks flagged`);
    }

    // Severity breakdown
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of (data.findings || [])) {
      sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
    }
    console.log(`    Critical: ${sevCounts.critical}`);
    console.log(`    High:     ${sevCounts.high}`);
    console.log(`    Medium:   ${sevCounts.medium}`);
    console.log(`    Low:      ${sevCounts.low}\n`);
  } catch {
    console.log('\n  Failed to read watch data. File may be corrupted.\n');
  }
}

// =============================================================================
// DEEP WATCH MODE (full orchestrator)
// =============================================================================

async function watchDeep(absolutePath, options = {}) {
  const { buildOrchestrator } = await import('../agents/index.js');
  const { ReconAgent } = await import('../agents/recon-agent.js');

  const debounceMs = options.debounce || 1500;
  const threshold = options.threshold || null;
  const scoringEngine = new ScoringEngine();

  console.log();
  output.header('Ship Safe — Deep Watch Mode');
  console.log();
  console.log(chalk.cyan('  Running full agent scans on file changes'));
  console.log(chalk.gray(`  Debounce: ${debounceMs}ms`));
  if (threshold) console.log(chalk.gray(`  Threshold: ${threshold}/100`));
  console.log(chalk.gray('  Press Ctrl+C to stop'));
  console.log();

  // Initial recon
  const reconAgent = new ReconAgent();
  console.log(chalk.gray('  Running initial recon...'));
  let recon;
  try {
    const reconResults = await reconAgent.analyze({ rootPath: absolutePath });
    recon = Array.isArray(reconResults) ? {} : reconResults;
  } catch { recon = {}; }
  console.log(chalk.gray('  Recon complete. Watching...\n'));

  let pendingFiles = new Set();
  let debounceTimer = null;
  let scanCount = 0;

  const dbDir = path.join(absolutePath, WATCH_DB_DIR);
  const dbFile = path.join(dbDir, WATCH_DB_FILE);

  const processChanges = async () => {
    const files = [...pendingFiles];
    pendingFiles.clear();
    if (files.length === 0) return;

    scanCount++;
    const timestamp = new Date().toLocaleTimeString();
    console.log(chalk.gray(`  [${timestamp}] ${files.length} file(s) changed — deep scanning...`));

    try {
      const orchestrator = buildOrchestrator();
      const context = {
        rootPath: absolutePath,
        files,
        changedFiles: files,
        recon,
        options: { incremental: true },
      };

      const findings = await orchestrator.run(context);
      const scoreResult = scoringEngine.compute(findings);

      // Persist results
      try {
        if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
        fs.writeFileSync(dbFile, JSON.stringify({
          lastScan: new Date().toISOString(),
          scanCount,
          score: {
            score: scoreResult.score,
            grade: scoreResult.grade?.letter,
            totalFindings: scoreResult.totalFindings,
          },
          agentic: scoreResult.agenticSummary
            ? { flagged: scoreResult.agenticSummary.flagged, total: scoreResult.agenticSummary.total }
            : null,
          findings: findings.map(f => ({
            file: path.relative(absolutePath, f.file || ''),
            line: f.line,
            severity: f.severity,
            rule: f.rule,
            title: f.title,
            agenticRisk: f.agenticRisk || null,
          })),
        }, null, 2));
      } catch { /* non-fatal */ }

      // Output
      const criticals = findings.filter(f => f.severity === 'critical').length;
      const highs = findings.filter(f => f.severity === 'high').length;

      if (findings.length === 0) {
        console.log(chalk.green(`  [${timestamp}] ✔ Clean — Score: ${scoreResult.score}/100 ${scoreResult.grade?.letter}\n`));
      } else {
        const scoreColor = scoreResult.score >= 75 ? chalk.cyan : scoreResult.score >= 50 ? chalk.yellow : chalk.red;
        console.log(`  [${timestamp}] ${chalk.white(`${findings.length} finding(s)`)}: ${criticals ? chalk.red.bold(`${criticals} critical`) : ''}${criticals && highs ? ', ' : ''}${highs ? chalk.yellow(`${highs} high`) : ''}. Score: ${scoreColor(`${scoreResult.score}/100 ${scoreResult.grade?.letter}`)}`);

        for (const f of findings.filter(f => f.severity === 'critical' || f.severity === 'high')) {
          const relFile = path.relative(absolutePath, f.file || '');
          const sev = f.severity === 'critical' ? chalk.red.bold('!!') : chalk.yellow(' !');
          const agentic = f.agenticRisk ? chalk.gray(` [${f.agenticRisk.id}]`) : '';
          console.log(`    ${sev} ${f.title} — ${relFile}:${f.line}${agentic}`);
        }
        console.log('');
      }

      if (threshold && scoreResult.score < threshold) {
        console.log(chalk.red.bold(`  ⚠ Score ${scoreResult.score} below threshold ${threshold}\n`));
      }
    } catch (err) {
      console.log(chalk.red(`  [${timestamp}] Scan error: ${err.message}\n`));
    }
  };

  try {
    const watcher = fs.watch(absolutePath, { recursive: true }, (eventType, filename) => {
      if (!filename) return;

      // Skip non-scannable
      const relPath = filename.replace(/\\/g, '/');
      for (const skipDir of SKIP_DIRS) {
        if (relPath.includes(`${skipDir}/`)) return;
      }
      const ext = path.extname(filename).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) return;
      if (SKIP_FILENAMES.has(path.basename(filename))) return;
      if (filename.endsWith('.min.js') || filename.endsWith('.min.css')) return;

      const fullPath = path.join(absolutePath, filename);
      if (!fs.existsSync(fullPath)) return;

      pendingFiles.add(fullPath);
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(processChanges, debounceMs);
    });

    process.on('SIGINT', () => {
      watcher.close();
      console.log(`\n  Watch stopped. ${scanCount} scan(s) completed.\n`);
      process.exit(0);
    });

    setInterval(() => {}, 1000 * 60 * 60);
  } catch (err) {
    output.error(`Watch failed: ${err.message}`);
    process.exit(1);
  }
}

// =============================================================================
// CONFIG WATCH — scanConfigFiles
// =============================================================================

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
      const { execFileSync } = await import('child_process');
      const blame = execFileSync('git', ['log', '-1', '--format=%an (%ar)', '--', filePath], { cwd: rootPath, encoding: 'utf-8', timeout: 5000 }).trim();
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
