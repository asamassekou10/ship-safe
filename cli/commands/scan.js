/**
 * Scan Command
 * ============
 *
 * Scans a directory for leaked secrets using pattern matching.
 *
 * USAGE:
 *   ship-safe scan [path]     Scan specified path (default: current directory)
 *   ship-safe scan . -v       Verbose mode (show files being scanned)
 *   ship-safe scan . --json   Output as JSON (for CI integration)
 *
 * EXIT CODES:
 *   0 - No secrets found
 *   1 - Secrets found (or error)
 *
 * This allows CI pipelines to fail builds when secrets are detected.
 */

import fs from 'fs';
import path from 'path';
import { glob } from 'glob';
import ora from 'ora';
import chalk from 'chalk';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import * as output from '../utils/output.js';

// =============================================================================
// MAIN SCAN FUNCTION
// =============================================================================

export async function scanCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  // Validate path exists
  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  // Start spinner
  const spinner = ora({
    text: 'Scanning for secrets...',
    color: 'cyan'
  }).start();

  try {
    // Find all files
    const files = await findFiles(absolutePath, options.verbose);
    spinner.text = `Scanning ${files.length} files...`;

    // Scan each file
    const results = [];
    let scannedCount = 0;

    for (const file of files) {
      const findings = await scanFile(file);
      if (findings.length > 0) {
        results.push({ file, findings });
      }

      scannedCount++;
      if (options.verbose) {
        spinner.text = `Scanned ${scannedCount}/${files.length}: ${path.relative(absolutePath, file)}`;
      }
    }

    spinner.stop();

    // Output results
    if (options.json) {
      outputJSON(results, files.length);
    } else {
      outputPretty(results, files.length, absolutePath);
    }

    // Exit with appropriate code
    const hasFindings = results.length > 0;
    process.exit(hasFindings ? 1 : 0);

  } catch (err) {
    spinner.fail('Scan failed');
    output.error(err.message);
    process.exit(1);
  }
}

// =============================================================================
// FILE DISCOVERY
// =============================================================================

async function findFiles(rootPath, verbose = false) {
  // Build ignore patterns from SKIP_DIRS
  const ignorePatterns = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

  // Find all files
  const files = await glob('**/*', {
    cwd: rootPath,
    absolute: true,
    nodir: true,
    ignore: ignorePatterns,
    dot: true  // Include dotfiles (but not .git which is ignored)
  });

  // Filter by extension and size
  const filtered = [];

  for (const file of files) {
    // Skip by extension
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) {
      continue;
    }

    // Handle compound extensions like .min.js
    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) {
      continue;
    }

    // Skip by size
    try {
      const stats = fs.statSync(file);
      if (stats.size > MAX_FILE_SIZE) {
        if (verbose) {
          console.log(chalk.gray(`  Skipping (too large): ${file}`));
        }
        continue;
      }
    } catch {
      continue;
    }

    filtered.push(file);
  }

  return filtered;
}

// =============================================================================
// FILE SCANNING
// =============================================================================

async function scanFile(filePath) {
  const findings = [];

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    // Check each pattern against each line
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      for (const pattern of SECRET_PATTERNS) {
        // Reset regex state (important for global regexes)
        pattern.pattern.lastIndex = 0;

        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          findings.push({
            line: lineNum + 1,
            column: match.index + 1,
            matched: match[0],
            patternName: pattern.name,
            severity: pattern.severity,
            description: pattern.description
          });
        }
      }
    }
  } catch (err) {
    // Skip files that can't be read (binary, permissions, etc.)
  }

  return findings;
}

// =============================================================================
// OUTPUT FORMATTING
// =============================================================================

function outputPretty(results, filesScanned, rootPath) {
  // Calculate stats
  const stats = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    filesScanned
  };

  for (const { findings } of results) {
    for (const f of findings) {
      stats.total++;
      stats[f.severity]++;
    }
  }

  // Print header
  output.header('Scan Results');

  if (results.length === 0) {
    output.success('No secrets detected in your codebase!');
    console.log();
    console.log(chalk.gray('Note: This scanner uses pattern matching and may miss some secrets.'));
    console.log(chalk.gray('Consider also using: gitleaks, trufflehog, or detect-secrets'));
  } else {
    // Print findings grouped by file
    for (const { file, findings } of results) {
      const relPath = path.relative(rootPath, file);

      for (const f of findings) {
        output.finding(
          relPath,
          f.line,
          f.patternName,
          f.severity,
          f.matched,
          f.description
        );
      }
    }

    // Print recommendations
    output.recommendations();
  }

  // Print summary
  output.summary(stats);
}

function outputJSON(results, filesScanned) {
  const jsonOutput = {
    success: results.length === 0,
    filesScanned,
    totalFindings: 0,
    findings: []
  };

  for (const { file, findings } of results) {
    for (const f of findings) {
      jsonOutput.totalFindings++;
      jsonOutput.findings.push({
        file,
        line: f.line,
        column: f.column,
        severity: f.severity,
        type: f.patternName,
        matched: output.maskSecret(f.matched),
        description: f.description
      });
    }
  }

  console.log(JSON.stringify(jsonOutput, null, 2));
}
