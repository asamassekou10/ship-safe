/**
 * CI Command — Optimized for CI/CD Pipelines
 * =============================================
 *
 * Single command for CI pipelines with:
 *   - Exit code 1 if score < threshold (default 75)
 *   - SARIF output for GitHub Code Scanning upload
 *   - JSON output for custom integrations
 *   - Compact summary for CI logs
 *   - --fail-on flag for severity-based gating
 *
 * USAGE:
 *   npx ship-safe ci .                         Default: fail if score < 75
 *   npx ship-safe ci . --threshold 60          Custom score threshold
 *   npx ship-safe ci . --fail-on critical      Only fail on critical findings
 *   npx ship-safe ci . --sarif results.sarif   SARIF for GitHub Code Scanning
 *   npx ship-safe ci . --baseline              Only check new findings
 */

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import { PolicyEngine } from '../agents/policy-engine.js';
import { runDepsAudit } from './deps.js';
import { filterBaseline } from './baseline.js';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  SKIP_FILENAMES,
  MAX_FILE_SIZE,
  loadGitignorePatterns,
  loadShipSafeIgnorePatterns,
  isTestFile,
  isExampleFile
} from '../utils/patterns.js';
import { projectFindings } from '../agents/base-agent.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import fg from 'fast-glob';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function ciCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  // `?? 75`, not `|| 75`: `--threshold 0` is a legitimate request to report
  // without gating, and `||` silently turned it back into the default.
  const threshold = Number(options.threshold ?? 75);
  const failOn = options.failOn || null;
  const sarifPath = options.sarif || null;

  if (!fs.existsSync(absolutePath)) {
    console.error(`[ship-safe] Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  const startTime = Date.now();

  // ── Secret Scan ──────────────────────────────────────────────────────────
  // A pipeline cannot act on the runner's home directory, so environment
  // checks are off unless explicitly requested.
  const checkGlobalAgents = options.checkGlobalAgents === true;

  const allFiles = await findFiles(absolutePath, { includeTests: options.includeTests });
  const secretFindings = [];

  for (const file of allFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');
      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        if (/ship-safe-ignore/i.test(line)) continue;
        for (const pattern of SECRET_PATTERNS) {
          pattern.pattern.lastIndex = 0;
          let match;
          while ((match = pattern.pattern.exec(line)) !== null) {
            if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
            secretFindings.push({
              file, line: lineNum + 1, column: match.index + 1,
              matched: match[0], severity: pattern.severity,
              category: pattern.category || 'secrets',
              rule: pattern.name, title: pattern.name.replace(/_/g, ' '),
              description: pattern.description,
              confidence: getConfidence(pattern, match[0]),
              fix: 'Move to environment variable or secrets manager',
            });
          }
        }
      }
    } catch { /* skip */ }
  }

  // ── Agent Scan ───────────────────────────────────────────────────────────
  const orchestrator = buildOrchestrator();
  const results = await orchestrator.runAll(absolutePath, { quiet: true, includeTests: options.includeTests, checkGlobalAgents }); // ship-safe-ignore — orchestrator result, not LLM output triggering actions
  const agentFindings = results.findings;

  // ── Dependency Audit ─────────────────────────────────────────────────────
  let depVulns = [];
  if (options.deps !== false) {
    try {
      const depResult = await runDepsAudit(absolutePath);
      depVulns = depResult.vulns || [];
    } catch { /* skip */ }
  }

  // ── Merge & Deduplicate ──────────────────────────────────────────────────
  const seen = new Set();
  let allFindings = [...secretFindings, ...agentFindings].filter(f => {
    const key = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Apply policy
  const policy = PolicyEngine.load(absolutePath);
  allFindings = policy.applyPolicy(allFindings);

  // Apply baseline filter
  if (options.baseline) {
    allFindings = filterBaseline(allFindings, absolutePath);
  }

  // ── Score ────────────────────────────────────────────────────────────────
  const scoringEngine = new ScoringEngine();
  const scoreResult = scoringEngine.compute(allFindings, depVulns, { includeEnvironment: checkGlobalAgents });
  // Round like audit does; without this the JSON emitted 29.900000000000006.
  scoreResult.score = Math.round(scoreResult.score * 10) / 10;
  scoringEngine.saveToHistory(absolutePath, scoreResult);

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  // ── SARIF Output ─────────────────────────────────────────────────────────
  if (sarifPath) {
    // Environment findings describe the developer's machine. Publishing the
    // names of someone's globally configured agent servers into a repository's
    // security tab is not acceptable, so machine output carries project only —
    // unless --check-global-agents was passed, which is the caller declaring
    // the environment in scope. A flag that ran a check and then discarded its
    // result would be worse than no flag.
    const sarif = buildSARIF(checkGlobalAgents ? allFindings : projectFindings(allFindings), absolutePath);
    fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2));
  }

  // ── JSON Output ──────────────────────────────────────────────────────────
  if (options.json) {
    console.log(JSON.stringify({
      score: scoreResult.score,
      grade: scoreResult.grade.letter,
      totalFindings: allFindings.length,
      totalDepVulns: depVulns.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      threshold,
      pass: determinePass(scoreResult, allFindings, threshold, failOn),
      duration: `${duration}s`,
    }, null, 2));
  } else {
    // ── Compact CI Summary ───────────────────────────────────────────────
    const critical = allFindings.filter(f => f.severity === 'critical').length;
    const high = allFindings.filter(f => f.severity === 'high').length;
    const medium = allFindings.filter(f => f.severity === 'medium').length;

    console.log(`[ship-safe] Score: ${scoreResult.score}/100 (${scoreResult.grade.letter}) | Findings: ${allFindings.length} (${critical}C ${high}H ${medium}M) | CVEs: ${depVulns.length} | ${duration}s`);

    if (critical > 0) {
      console.log(`[ship-safe] Critical findings:`);
      for (const f of allFindings.filter(f => f.severity === 'critical').slice(0, 5)) {
        const rel = path.relative(absolutePath, f.file).replace(/\\/g, '/');
        console.log(`  - ${f.rule} at ${rel}:${f.line}`);
      }
    }

    if (sarifPath) {
      console.log(`[ship-safe] SARIF: ${sarifPath}`);
    }
  }

  // ── GitHub PR Comment ──────────────────────────────────────────────────
  if (options.githubPr) {
    try {
      postPRComment(scoreResult, allFindings, depVulns, absolutePath, duration);
    } catch (err) {
      console.log(`[ship-safe] Warning: Could not post PR comment: ${err.message}`);
    }
  }

  // ── Exit Code ────────────────────────────────────────────────────────────
  const pass = determinePass(scoreResult, allFindings, threshold, failOn);
  if (!pass) {
    if (!options.json) {
      if (failOn) {
        console.log(`[ship-safe] FAIL: Found ${failOn}-severity findings`);
      } else {
        console.log(`[ship-safe] FAIL: Score ${scoreResult.score} < threshold ${threshold}`);
      }
    }
    process.exit(1);
  } else {
    if (!options.json) {
      console.log(`[ship-safe] PASS`);
    }
    process.exit(0);
  }
}

// =============================================================================
// HELPERS
// =============================================================================

function determinePass(scoreResult, findings, threshold, failOn) {
  if (failOn) {
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    const failIndex = sevOrder.indexOf(failOn);
    if (failIndex === -1) return scoreResult.score >= threshold;
    const blockingSevs = sevOrder.slice(0, failIndex + 1);
    return !findings.some(f => blockingSevs.includes(f.severity));
  }
  return scoreResult.score >= threshold;
}

function buildSARIF(findings, rootPath) {
  const rules = {};
  for (const f of findings) {
    if (!rules[f.rule]) {
      rules[f.rule] = {
        id: f.rule, name: f.title || f.rule,
        shortDescription: { text: f.title || f.rule },
        fullDescription: { text: f.description || '' },
        defaultConfiguration: {
          level: ['critical', 'high'].includes(f.severity) ? 'error' : 'warning',
        },
      };
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ship-safe', version: '5.0.0',
          informationUri: 'https://github.com/asamassekou10/ship-safe',
          rules: Object.values(rules),
        },
      },
      results: findings.map(f => ({
        ruleId: f.rule,
        level: ['critical', 'high'].includes(f.severity) ? 'error' : 'warning',
        message: { text: `${f.title}: ${f.description}` },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: path.relative(rootPath, f.file).replace(/\\/g, '/').replace(/\[/g, '%5B').replace(/\]/g, '%5D'),
              uriBaseId: '%SRCROOT%',
            },
            region: { startLine: Math.max(1, f.line || 1), startColumn: f.column || 1 },
          },
        }],
      })),
    }],
  };
}

/**
 * Post a summary comment on the current GitHub PR using the `gh` CLI.
 * Requires: `gh` installed and authenticated, running in a PR context.
 */
function postPRComment(scoreResult, findings, depVulns, rootPath, duration) {
  // Detect PR number from environment (GitHub Actions sets GITHUB_REF)
  let prNumber = process.env.GITHUB_PR_NUMBER || '';

  if (!prNumber) {
    // Try to detect from GITHUB_REF (refs/pull/123/merge)
    const ref = process.env.GITHUB_REF || '';
    const match = ref.match(/refs\/pull\/(\d+)\//);
    if (match) prNumber = match[1];
  }

  if (!prNumber) {
    // Try gh pr view to get current PR
    try {
      const prJson = execFileSync('gh', ['pr', 'view', '--json', 'number'], { // ship-safe-ignore — execFileSync, not MCP
        cwd: rootPath, stdio: ['pipe', 'pipe', 'pipe'], // ship-safe-ignore
      }).toString();
      const parsed = JSON.parse(prJson);
      prNumber = String(parsed.number);
    } catch {
      console.log('[ship-safe] No PR detected — skipping PR comment');
      return;
    }
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;

  const gradeEmoji = { A: '🟢', B: '🔵', C: '🟡', D: '🟠', F: '🔴' };
  const emoji = gradeEmoji[scoreResult.grade.letter] || '⚪';

  // Build markdown body
  let body = `## ${emoji} Ship Safe Security Report\n\n`;
  body += `| Metric | Value |\n|--------|-------|\n`;
  body += `| **Score** | ${scoreResult.score}/100 (${scoreResult.grade.letter}) |\n`;
  body += `| **Findings** | ${findings.length} total (${critical}C ${high}H ${medium}M ${low}L) |\n`;
  body += `| **Dep CVEs** | ${depVulns.length} |\n`;
  body += `| **Duration** | ${duration}s |\n\n`;

  if (critical > 0 || high > 0) {
    body += `### Critical & High Findings\n\n`;
    body += `| Severity | File | Issue |\n|----------|------|-------|\n`;
    for (const f of findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 20)) {
      const rel = path.relative(rootPath, f.file).replace(/\\/g, '/');
      body += `| ${f.severity.toUpperCase()} | \`${rel}:${f.line}\` | ${(f.title || f.rule).slice(0, 60)} |\n`;
    }
    body += '\n';
  }

  if (findings.length === 0 && depVulns.length === 0) {
    body += '> No security issues found — looking good! 🎉\n\n';
  }

  body += `\n---\n<sub>Generated by <a href="https://shipsafe.sh">Ship Safe</a> · <a href="https://shipsafe.sh/app">View full report in dashboard</a></sub>`;

  // Post comment via gh CLI
  execFileSync('gh', ['pr', 'comment', prNumber, '--body', body], { // ship-safe-ignore — execFileSync, not MCP
    cwd: rootPath,
    stdio: ['pipe', 'pipe', 'pipe'], // ship-safe-ignore
  });

  console.log(`[ship-safe] PR comment posted on #${prNumber}`);
}

async function findFiles(rootPath, { includeTests = false } = {}) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const gitignoreGlobs = loadGitignorePatterns(rootPath);
  globIgnore.push(...gitignoreGlobs);
  // Honor .ship-safeignore. Without this, `ci` was the only command that
  // ignored the user's own suppression config, which is exactly backwards for
  // the command that gates their pipeline.
  globIgnore.push(...loadShipSafeIgnorePatterns(rootPath));

  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true,
  });

  return files.filter(file => {
    // Same reasoning as audit: test and example code is illustrative, and
    // scoring a pipeline on it produces failures nobody can act on.
    if (!includeTests && (isTestFile(file) || isExampleFile(file))) return false;
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    if (SKIP_FILENAMES.has(path.basename(file))) return false;
    if (path.basename(file).endsWith('.min.js') || path.basename(file).endsWith('.min.css')) return false;
    try { if (fs.statSync(file).size > MAX_FILE_SIZE) return false; } catch { return false; }
    return true;
  });
}
