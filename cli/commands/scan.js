/**
 * Scan Command
 * ============
 *
 * Scans a directory for leaked secrets using pattern matching + entropy scoring.
 *
 * USAGE:
 *   ship-safe scan [path]            Scan specified path (default: current directory)
 *   ship-safe scan . -v              Verbose mode (show files being scanned)
 *   ship-safe scan . --json          Output as JSON (for CI integration)
 *   ship-safe scan . --include-tests Also scan test files (excluded by default)
 *
 * SUPPRESSING FALSE POSITIVES:
 *   Add  # ship-safe-ignore  as a comment on the same line to suppress a finding.
 *   Create a .ship-safeignore file (same syntax as .gitignore) to exclude paths.
 *
 * EXIT CODES:
 *   0 - No secrets found
 *   1 - Secrets found (or error)
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import ora from 'ora';
import chalk from 'chalk';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  TEST_FILE_PATTERNS,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import * as output from '../utils/output.js';

// =============================================================================
// CUSTOM PATTERNS (.ship-safe.json)
// =============================================================================

/**
 * Load custom patterns from .ship-safe.json in the project root.
 *
 * Format:
 *   {
 *     "patterns": [
 *       {
 *         "name": "My Internal Key",
 *         "pattern": "MYAPP_[A-Z0-9]{32}",
 *         "severity": "high",
 *         "description": "Internal API key for myapp services."
 *       }
 *     ]
 *   }
 */
function loadCustomPatterns(rootPath) {
  const configPath = path.join(rootPath, '.ship-safe.json');
  if (!fs.existsSync(configPath)) return [];

  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    if (!Array.isArray(config.patterns)) return [];

    return config.patterns
      .filter(p => p.name && p.pattern)
      .map(p => ({
        name: `[custom] ${p.name}`,
        pattern: new RegExp(p.pattern, 'g'),
        severity: p.severity || 'high',
        description: p.description || `Custom pattern: ${p.name}`,
        custom: true,
      }));
  } catch (err) {
    output.warning(`.ship-safe.json parse error: ${err.message}`);
    return [];
  }
}

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

  // Load .ship-safeignore patterns
  const ignorePatterns = loadIgnoreFile(absolutePath);

  // Load custom patterns from .ship-safe.json
  const customPatterns = loadCustomPatterns(absolutePath);
  const allPatterns = [...SECRET_PATTERNS, ...customPatterns];

  if (customPatterns.length > 0 && options.verbose) {
    output.info(`Loaded ${customPatterns.length} custom pattern(s) from .ship-safe.json`);
  }

  // Start spinner
  const spinner = ora({
    text: 'Scanning for secrets...',
    color: 'cyan'
  }).start();

  try {
    // Find all files
    const files = await findFiles(absolutePath, ignorePatterns, options);
    spinner.text = `Scanning ${files.length} files...`;

    // Scan each file
    const results = [];
    let scannedCount = 0;

    for (const file of files) {
      const findings = await scanFile(file, allPatterns);
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
    if (options.sarif) {
      outputSARIF(results, absolutePath);
    } else if (options.json) {
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
// .SHIP-SAFEIGNORE LOADING
// =============================================================================

/**
 * Load ignore patterns from .ship-safeignore file.
 * Same syntax as .gitignore — glob patterns, one per line, # for comments.
 */
function loadIgnoreFile(rootPath) {
  const ignorePath = path.join(rootPath, '.ship-safeignore');

  if (!fs.existsSync(ignorePath)) return [];

  try {
    return fs.readFileSync(ignorePath, 'utf-8')
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch {
    return [];
  }
}

/**
 * Check if a file path matches any ignore pattern.
 * Supports: exact paths, glob patterns, and directory prefixes.
 */
function isIgnoredByFile(filePath, rootPath, ignorePatterns) {
  if (ignorePatterns.length === 0) return false;

  const relPath = path.relative(rootPath, filePath).replace(/\\/g, '/');

  return ignorePatterns.some(pattern => {
    // Directory prefix match: "tests/" ignores everything under tests/
    if (pattern.endsWith('/')) {
      return relPath.startsWith(pattern) || relPath.includes('/' + pattern);
    }
    // Simple glob: "**/fixtures/**" or "src/secrets.js"
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/]');
    return new RegExp(`(^|/)${escaped}($|/)`).test(relPath);
  });
}

// =============================================================================
// FILE DISCOVERY
// =============================================================================

async function findFiles(rootPath, ignorePatterns, options = {}) {
  // Build ignore patterns from SKIP_DIRS
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

  // Find all files
  const files = await fg('**/*', {
    cwd: rootPath,
    absolute: true,
    onlyFiles: true,
    ignore: globIgnore,
    dot: true
  });

  const filtered = [];

  for (const file of files) {
    // Skip by extension
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) continue;

    // Handle compound extensions like .min.js
    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) continue;

    // Skip test files by default (--include-tests to override)
    if (!options.includeTests && isTestFile(file)) continue;

    // Skip files matching .ship-safeignore
    if (isIgnoredByFile(file, rootPath, ignorePatterns)) continue;

    // Skip by size
    try {
      const stats = fs.statSync(file);
      if (stats.size > MAX_FILE_SIZE) continue;
    } catch {
      continue;
    }

    filtered.push(file);
  }

  return filtered;
}

function isTestFile(filePath) {
  return TEST_FILE_PATTERNS.some(pattern => pattern.test(filePath));
}

// =============================================================================
// FILE SCANNING
// =============================================================================

async function scanFile(filePath, patterns = SECRET_PATTERNS) {
  const findings = [];

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      // Inline suppression: # ship-safe-ignore on the same line
      if (/ship-safe-ignore/i.test(line)) continue;

      for (const pattern of patterns) {
        // Reset regex state (important for global regexes)
        pattern.pattern.lastIndex = 0;

        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          // For generic patterns, apply entropy check to filter placeholders
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) {
            continue;
          }

          const confidence = getConfidence(pattern, match[0]);

          findings.push({
            line: lineNum + 1,
            column: match.index + 1,
            matched: match[0],
            patternName: pattern.name,
            severity: pattern.severity,
            confidence,
            description: pattern.description
          });
        }
      }
    }
  } catch {
    // Skip files that can't be read (binary, permissions, etc.)
  }

  return findings;
}

// =============================================================================
// OUTPUT FORMATTING
// =============================================================================

function outputPretty(results, filesScanned, rootPath) {
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
      stats[f.severity] = (stats[f.severity] || 0) + 1;
    }
  }

  output.header('Scan Results');

  if (results.length === 0) {
    output.success('No secrets detected in your codebase!');
    console.log();
    console.log(chalk.gray('Note: Uses pattern matching + entropy scoring. Test files excluded by default.'));
    console.log(chalk.gray('Tip:  Run with --include-tests to also scan test files.'));
    console.log(chalk.gray('Tip:  Add a .ship-safeignore file to exclude paths.'));
  } else {
    for (const { file, findings } of results) {
      const relPath = path.relative(rootPath, file);

      for (const f of findings) {
        output.finding(
          relPath,
          f.line,
          f.patternName,
          f.severity,
          f.matched,
          f.description,
          f.confidence
        );
      }
    }

    // Remind about suppressions
    console.log();
    console.log(chalk.gray('Suppress a finding: add  # ship-safe-ignore  as a comment on that line'));
    console.log(chalk.gray('Exclude a path:     add it to .ship-safeignore'));

    output.recommendations();
  }

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
        confidence: f.confidence,
        type: f.patternName,
        matched: output.maskSecret(f.matched),
        description: f.description
      });
    }
  }

  console.log(JSON.stringify(jsonOutput, null, 2));
}

// =============================================================================
// SARIF OUTPUT (GitHub Code Scanning compatible)
// =============================================================================

/**
 * Output findings in SARIF 2.1.0 format.
 * Feed this into GitHub's Security tab:
 *   npx ship-safe scan . --sarif > results.sarif
 *
 * Then upload via:
 *   github/codeql-action/upload-sarif@v3
 */
function outputSARIF(results, rootPath) {
  const rules = {};

  // Build rules from findings
  for (const { findings } of results) {
    for (const f of findings) {
      if (!rules[f.patternName]) {
        rules[f.patternName] = {
          id: f.patternName.replace(/\s+/g, '-').toLowerCase(),
          name: f.patternName,
          shortDescription: { text: f.patternName },
          fullDescription: { text: f.description },
          defaultConfiguration: {
            level: f.severity === 'critical' ? 'error'
              : f.severity === 'high' ? 'error'
              : f.severity === 'medium' ? 'warning'
              : 'note'
          },
          helpUri: 'https://github.com/asamassekou10/ship-safe',
        };
      }
    }
  }

  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ship-safe',
          version: '2.1.0',
          informationUri: 'https://github.com/asamassekou10/ship-safe',
          rules: Object.values(rules),
        }
      },
      results: results.flatMap(({ file, findings }) =>
        findings.map(f => ({
          ruleId: f.patternName.replace(/\s+/g, '-').toLowerCase(),
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          message: { text: f.description },
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: path.relative(rootPath, file).replace(/\\/g, '/'),
                uriBaseId: '%SRCROOT%'
              },
              region: {
                startLine: f.line,
                startColumn: f.column,
              }
            }
          }]
        }))
      )
    }]
  };

  console.log(JSON.stringify(sarif, null, 2));
}
