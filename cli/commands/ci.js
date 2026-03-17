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
  loadGitignorePatterns
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import fg from 'fast-glob';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function ciCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  const threshold = options.threshold || 75;
  const failOn = options.failOn || null;
  const sarifPath = options.sarif || null;

  if (!fs.existsSync(absolutePath)) {
    console.error(`[ship-safe] Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  const startTime = Date.now();

  // ── Secret Scan ──────────────────────────────────────────────────────────
  const allFiles = await findFiles(absolutePath);
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
  const results = await orchestrator.runAll(absolutePath, { quiet: true });
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
  const scoreResult = scoringEngine.compute(allFindings, depVulns);
  scoringEngine.saveToHistory(absolutePath, scoreResult);

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  // ── SARIF Output ─────────────────────────────────────────────────────────
  if (sarifPath) {
    const sarif = buildSARIF(allFindings, absolutePath);
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
              uri: path.relative(rootPath, f.file).replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: { startLine: f.line, startColumn: f.column || 1 },
          },
        }],
      })),
    }],
  };
}

async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const gitignoreGlobs = loadGitignorePatterns(rootPath);
  globIgnore.push(...gitignoreGlobs);

  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true,
  });

  return files.filter(file => {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    if (SKIP_FILENAMES.has(path.basename(file))) return false;
    if (path.basename(file).endsWith('.min.js') || path.basename(file).endsWith('.min.css')) return false;
    try { if (fs.statSync(file).size > MAX_FILE_SIZE) return false; } catch { return false; }
    return true;
  });
}
