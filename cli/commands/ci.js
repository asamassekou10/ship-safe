/**
 * CI Command — Optimized for CI/CD Pipelines
 * =============================================
 *
 * Single command for CI pipelines with:
 *   - Exit code 1 if any finding meets the failure severity (default: critical)
 *   - SARIF output for GitHub Code Scanning upload
 *   - JSON output for custom integrations
 *   - Compact summary for CI logs
 *   - --threshold for score-based gating, for pipelines that already use it
 *
 * USAGE:
 *   npx ship-safe ci .                         Default: fail on any critical
 *   npx ship-safe ci . --fail-on high          Fail on critical or high
 *   npx ship-safe ci . --fail-on none          Report only, never fail
 *   npx ship-safe ci . --threshold 60          Gate on score instead
 *   npx ship-safe ci . --sarif results.sarif   SARIF for GitHub Code Scanning
 *   npx ship-safe ci . --baseline              Only check new findings
 *
 * WHY SEVERITY AND NOT SCORE:
 *   The gate used to be `score < 75`. A composite score is a poor gate and
 *   every comparable tool avoids it — Snyk gates on --severity-threshold,
 *   Trivy on --severity, SonarQube rates on the worst finding rather than the
 *   volume of findings. Our own score could not tell 30 findings from 7,000
 *   (see the scoring engine), so a pipeline gating on it was gating on noise.
 *
 *   `--threshold` still works and still takes precedence when set explicitly,
 *   so pipelines that pinned a number keep their behaviour.
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
import { normalizeFindingMetadata, postureFindings, projectFindings, resolveCodeScopes } from '../agents/base-agent.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import { postPRComments } from './watch.js';
import { compareFindingSets, snapshotFinding } from '../utils/finding-delta.js';
import fg from 'fast-glob';
import { STDOUT_WRITE_TIMEOUT_MS, writeStdout } from '../utils/stdout.js';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function ciCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  // Score gating is now opt-in. `--threshold 0` remains a legitimate request
  // to report without gating, which is why this stays `??` and not `||`.
  const thresholdSet = options.threshold !== undefined && options.threshold !== null;
  const threshold = Number(options.threshold ?? 75);

  // Severity is the default gate. An explicit --threshold wins, so pipelines
  // that already pinned a score keep the behaviour they configured.
  const failOn = options.failOn || (thresholdSet ? null : 'critical');
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
  const results = await orchestrator.runAll(absolutePath, { quiet: true, includeTests: options.includeTests, includeDocExamples: options.includeDocExamples, checkGlobalAgents }); // ship-safe-ignore — orchestrator result, not LLM output triggering actions
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
  allFindings = resolveCodeScopes(allFindings.map(normalizeFindingMetadata), absolutePath);

  // A base report turns a repository scan into a true PR comparison. Reports
  // carry hashed snapshots, so this does not require storing raw secret matches.
  let prDelta = null;
  if (options.baseReport) {
    try {
      const reportPath = path.resolve(options.baseReport);
      const baseReport = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
      const baseFindings = baseReport.findingSnapshots || baseReport.findings;
      if (!Array.isArray(baseFindings)) {
        throw new Error('report has no findingSnapshots or findings array');
      }
      prDelta = compareFindingSets(baseFindings, allFindings, { headRoot: absolutePath });
    } catch (error) {
      console.error(`[ship-safe] Could not load base report: ${error.message}`);
      process.exit(1);
    }
  }

  // ── Score ────────────────────────────────────────────────────────────────
  const scoringEngine = new ScoringEngine();
  const scoreResult = scoringEngine.compute(allFindings, depVulns, {
    includeEnvironment: checkGlobalAgents,
    includeNonProduction: options.includeTests,
  });
  const posture = postureFindings(allFindings, { includeNonProduction: options.includeTests });
  const findingSnapshots = allFindings.map(finding => snapshotFinding(finding, absolutePath));
  const introducedFindings = prDelta
    ? prDelta.introduced.map(entry => entry.finding)
    : allFindings;
  const gateScoreResult = prDelta
    ? scoringEngine.compute(introducedFindings, [], { includeNonProduction: options.includeTests })
    : scoreResult;
  // Round like audit does; without this the JSON emitted 29.900000000000006.
  scoreResult.score = Math.round(scoreResult.score * 10) / 10;
  scoringEngine.saveToHistory(absolutePath, scoreResult);

  if (options.writeBaselineReport) {
    const baselineReportPath = path.resolve(options.writeBaselineReport);
    const baselineReport = {
      schemaVersion: 1,
      scoreVersion: scoreResult.scoreVersion,
      createdAt: new Date().toISOString(),
      findingSnapshots,
    };
    fs.mkdirSync(path.dirname(baselineReportPath), { recursive: true });
    fs.writeFileSync(baselineReportPath, `${JSON.stringify(baselineReport, null, 2)}\n`);
  }

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
    // A large report can be buffered by stdout. Wait for the write callback
    // before the command's forced exit, otherwise CI consumers may receive a
    // truncated JSON document.
    try {
      await writeStdout(`${JSON.stringify({
        scoreVersion: scoreResult.scoreVersion,
        score: scoreResult.score,
        postureScore: scoreResult.postureScore,
        grade: scoreResult.grade.letter,
        totalFindings: allFindings.length,
        postureFindings: scoreResult.postureFindings,
        excludedFromPosture: scoreResult.excludedFromPosture,
        excludedByCodeScope: scoreResult.excludedByCodeScope,
        aiAffectsScore: scoreResult.aiAffectsScore,
        findingSnapshots,
        prDelta,
        prRiskScore: prDelta ? gateScoreResult.postureScore : null,
        prRiskGrade: prDelta ? gateScoreResult.grade.letter : null,
        totalDepVulns: depVulns.length,
        critical: allFindings.filter(f => f.severity === 'critical').length,
        high: allFindings.filter(f => f.severity === 'high').length,
        medium: allFindings.filter(f => f.severity === 'medium').length,
        low: allFindings.filter(f => f.severity === 'low').length,
        postureCritical: posture.filter(f => f.severity === 'critical').length,
        postureHigh: posture.filter(f => f.severity === 'high').length,
        postureMedium: posture.filter(f => f.severity === 'medium').length,
        postureLow: posture.filter(f => f.severity === 'low').length,
        // What the investigation layer concluded, so a pipeline can act on
        // evidence rather than on a severity label alone.
        verdicts: countVerdicts(allFindings),
        findings: projectFindings(allFindings),
        threshold,
        pass: determinePass(gateScoreResult, introducedFindings, threshold, failOn, options.includeTests, options),
        duration: `${duration}s`,
        })}\n`);
    } catch (error) {
      const message = error.code === 'SHIP_SAFE_STDOUT_TIMEOUT'
        ? `Timed out writing JSON output to stdout after ${STDOUT_WRITE_TIMEOUT_MS}ms; the downstream consumer may not be reading.`
        : `Could not write JSON output to stdout: ${error.message}`;
      console.error(`[ship-safe] ${message}`);
      // The report cannot be delivered once stdout is stalled or broken. Exit
      // immediately so a blocked stream cannot keep the CI process alive.
      process.exit(1);
    }
  } else {
    // ── Compact CI Summary ───────────────────────────────────────────────
    const gatePosture = prDelta
      ? postureFindings(introducedFindings, { includeNonProduction: options.includeTests })
      : posture;
    const critical = posture.filter(f => f.severity === 'critical').length;
    const high = posture.filter(f => f.severity === 'high').length;
    const medium = posture.filter(f => f.severity === 'medium').length;

    const deltaSummary = prDelta
      ? ` | PR delta: +${prDelta.counts.introduced} -${prDelta.counts.resolved} ?${prDelta.counts.uncertain}`
      : '';
    console.log(`[ship-safe] Posture: ${scoreResult.score}/100 (${scoreResult.grade.letter}) | Findings: ${posture.length} (${critical}C ${high}H ${medium}M) | Observed: ${allFindings.length}${deltaSummary} | CVEs: ${depVulns.length} | ${duration}s`);

    const gateCritical = gatePosture.filter(f => f.severity === 'critical');
    if (gateCritical.length > 0) {
      console.log(`[ship-safe] ${prDelta ? 'Introduced critical findings' : 'Critical findings'}:`);
      for (const f of gateCritical.slice(0, 5)) {
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
      postPRComment(scoreResult, allFindings, depVulns, absolutePath, duration, options.includeTests, prDelta, gateScoreResult);
    } catch (err) {
      console.log(`[ship-safe] Warning: Could not post PR comment: ${err.message}`);
    }
  }

  // Inline comments are opt-in because they require pull request write
  // permission and should never be enabled accidentally on untrusted events.
  if (options.githubInline) {
    try {
      const inlineFindings = prDelta ? introducedFindings : projectFindings(allFindings);
      await postPRComments(projectFindings(inlineFindings), absolutePath, 'ci');
    } catch (err) {
      console.log(`[ship-safe] Warning: Could not post inline PR comments: ${err.message}`);
    }
  }

  // ── Exit Code ────────────────────────────────────────────────────────────
  const pass = determinePass(gateScoreResult, introducedFindings, threshold, failOn, options.includeTests, options);
  if (!pass) {
    if (!options.json) {
      if (options.failOnVerdict && options.failOnVerdict !== 'none') {
        const blocking = VERDICT_ORDER.slice(0, VERDICT_ORDER.indexOf(options.failOnVerdict) + 1);
        const n = postureFindings(introducedFindings, { includeNonProduction: options.includeTests })
          .filter(f => blocking.includes(f.evidence?.verdict)).length;
        console.log(`[ship-safe] FAIL: ${n} finding(s) at verdict ${options.failOnVerdict} or stronger`);
      } else if (failOn) {
        const order = ['critical', 'high', 'medium', 'low'];
        const blocking = order.slice(0, order.indexOf(failOn) + 1);
        const gatePosture = postureFindings(introducedFindings, { includeNonProduction: options.includeTests });
        const n = gatePosture.filter(f => blocking.includes(f.severity)).length;
        const label = prDelta ? 'introduced finding(s)' : 'finding(s)';
        console.log(`[ship-safe] FAIL: ${n} ${label} at ${failOn} severity or above`);
      } else {
        const label = prDelta ? 'PR risk score' : 'Score';
        console.log(`[ship-safe] FAIL: ${label} ${gateScoreResult.score} < threshold ${threshold}`);
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

/**
 * Verdicts, from strongest evidence to weakest. A gate set at one level blocks
 * on it and everything above it.
 */
const VERDICT_ORDER = ['confirmed', 'likely'];

export function determinePass(scoreResult, findings, threshold, failOn, includeNonProduction = false, options = {}) {
  let gateFindings = postureFindings(findings, { includeNonProduction });

  // A finding the investigation layer argued away, with a citation, is not a
  // reason to stop a build -- but only when asked. Refutation is a judgement,
  // and a wrong one silently lets a real issue through, so it never changes
  // what blocks a pipeline unless the pipeline opts in.
  if (options.ignoreRefuted) {
    gateFindings = gateFindings.filter(f => f.evidence?.verdict !== 'refuted');
  }

  // Gating on evidence rather than severity: block what was actually
  // established, whatever its severity label says.
  if (options.failOnVerdict) {
    if (options.failOnVerdict === 'none') return true;
    const index = VERDICT_ORDER.indexOf(options.failOnVerdict);
    if (index !== -1) {
      const blocking = VERDICT_ORDER.slice(0, index + 1);
      return !gateFindings.some(f => blocking.includes(f.evidence?.verdict));
    }
  }

  if (failOn === 'none') return true;
  if (failOn) {
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    const failIndex = sevOrder.indexOf(failOn);
    if (failIndex === -1) return scoreResult.score >= threshold;
    const blockingSevs = sevOrder.slice(0, failIndex + 1);
    return !gateFindings.some(f => blockingSevs.includes(f.severity));
  }
  return scoreResult.score >= threshold;
}

function countVerdicts(findings) {
  const counts = { confirmed: 0, likely: 0, unknown: 0, refuted: 0 };
  for (const finding of findings) {
    const verdict = finding.evidence?.verdict || 'unknown';
    if (verdict in counts) counts[verdict] += 1;
  }
  return counts;
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
        ...((f.hermesBoundary?.evidence?.slice(1) || f.hermesCronLifecycle?.evidence || f.hermesCredentialFlow?.evidence)?.length > 0 ? {
          relatedLocations: (f.hermesBoundary?.evidence?.slice(1) || f.hermesCronLifecycle?.evidence || f.hermesCredentialFlow.evidence).map((item, index) => ({
            id: index + 1,
            physicalLocation: {
              artifactLocation: {
                uri: path.relative(rootPath, item.file).replace(/\\/g, '/').replace(/\[/g, '%5B').replace(/\]/g, '%5D'),
                uriBaseId: '%SRCROOT%',
              },
              region: { startLine: Math.max(1, item.line || 1) },
            },
            message: { text: item.role },
          })),
        } : {}),
        // Carried into SARIF so a policy-aware consumer can filter on it. Only
        // findings whose target publishes a trust model have one today, so the
        // key is omitted rather than defaulted when absent.
        // The verdict travels into code scanning, where a severity label is
        // otherwise the only thing distinguishing a traced finding from an
        // unexamined one.
        ...((f.posture || f.evidence?.verdict || f.hermesBoundary || f.hermesCronLifecycle || f.hermesCredentialFlow) ? {
          properties: {
            ...(f.posture ? { posture: f.posture } : {}),
            ...(f.hermesBoundary ? {
              hermesBackend: f.hermesBoundary.backend,
              hermesSurface: f.hermesBoundary.surface,
              caller: f.hermesBoundary.caller,
              transport: f.hermesBoundary.transport,
              authentication: f.hermesBoundary.authentication,
              bindScope: f.hermesBoundary.bindScope,
              handler: f.hermesBoundary.handler,
              reachableTool: f.hermesBoundary.tool,
              permission: f.hermesBoundary.permission,
              claimedBoundary: f.hermesBoundary.claimedBoundary,
              reachableOperation: f.hermesBoundary.reachableOperation,
              effect: f.hermesBoundary.effect,
              executesIn: f.hermesBoundary.executesIn,
              reachabilityBasis: f.hermesBoundary.reachabilityBasis,
            } : {}),
            ...(f.hermesCronLifecycle ? {
              hermesCronStage: f.hermesCronLifecycle.stage,
              retainedAuthority: f.hermesCronLifecycle.retainedAuthority,
              errorAndRetryImpact: f.hermesCronLifecycle.errorAndRetryImpact,
            } : {}),
            ...(f.hermesCredentialFlow ? {
              credential: f.hermesCredentialFlow.credential,
              credentialScope: f.hermesCredentialFlow.scope,
              credentialRecipient: f.hermesCredentialFlow.recipient,
              reachableOperation: f.hermesCredentialFlow.reachableOperation,
              externalEffect: f.hermesCredentialFlow.externalEffect,
              reachabilityBasis: f.hermesCredentialFlow.reachabilityBasis,
            } : {}),
            ...(f.evidence?.verdict ? {
              verdict: f.evidence.verdict,
              ...(f.evidence.decidedBy ? { decidedBy: f.evidence.decidedBy.join(', ') } : {}),
            } : {}),
          },
        } : {}),
      })),
    }],
  };
}

/**
 * Post a summary comment on the current GitHub PR using the `gh` CLI.
 * Requires: `gh` installed and authenticated, running in a PR context.
 */
function postPRComment(scoreResult, findings, depVulns, rootPath, duration, includeNonProduction = false, prDelta = null, gateScoreResult = scoreResult) {
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

  const posture = postureFindings(findings, { includeNonProduction });
  const critical = posture.filter(f => f.severity === 'critical').length;
  const high = posture.filter(f => f.severity === 'high').length;
  const medium = posture.filter(f => f.severity === 'medium').length;
  const low = posture.filter(f => f.severity === 'low').length;

  const gradeEmoji = { A: '🟢', B: '🔵', C: '🟡', D: '🟠', F: '🔴' };
  const emoji = gradeEmoji[scoreResult.grade.letter] || '⚪';

  // Build markdown body
  let body = `## ${emoji} Ship Safe Security Report\n\n`;
  body += `| Metric | Value |\n|--------|-------|\n`;
  body += `| **Score** | ${scoreResult.score}/100 (${scoreResult.grade.letter}) |\n`;
  body += `| **Posture findings** | ${scoreResult.postureFindings} |\n`;
  if (scoreResult.excludedFromPosture > 0) {
    body += `| **Non-production evidence** | ${scoreResult.excludedFromPosture} excluded from posture score |\n`;
  }
  body += `| **Posture severity** | ${critical}C ${high}H ${medium}M ${low}L |\n`;
  body += `| **Observed findings** | ${findings.length} total |\n`;
  body += `| **Dep CVEs** | ${depVulns.length} |\n`;
  body += `| **Duration** | ${duration}s |\n\n`;

  if (prDelta) {
    body += `### Pull request risk\n\n`;
    body += `| Introduced | Resolved | Unchanged | Uncertain | Risk score |\n`;
    body += `|------------|----------|-----------|-----------|------------|\n`;
    body += `| ${prDelta.counts.introduced} | ${prDelta.counts.resolved} | ${prDelta.counts.unchanged} | ${prDelta.counts.uncertain} | ${gateScoreResult.score}/100 (${gateScoreResult.grade.letter}) |\n\n`;
    if (prDelta.counts.uncertain > 0) {
      body += `> Ambiguous matches are reported as uncertain and do not block this pull request.\n\n`;
    }
  }

  const detailedFindings = prDelta
    ? prDelta.introduced.map(entry => entry.finding)
    : posture;
  const detailedCritical = detailedFindings.filter(f => f.severity === 'critical').length;
  const detailedHigh = detailedFindings.filter(f => f.severity === 'high').length;

  if (detailedCritical > 0 || detailedHigh > 0) {
    body += `### Critical & High Findings\n\n`;
    body += `| Severity | File | Issue |\n|----------|------|-------|\n`;
    for (const f of detailedFindings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 20)) {
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
    if (!includeTests && (isTestFile(file, rootPath) || isExampleFile(file, rootPath))) return false;
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    if (SKIP_FILENAMES.has(path.basename(file))) return false;
    if (path.basename(file).endsWith('.min.js') || path.basename(file).endsWith('.min.css')) return false;
    try { if (fs.statSync(file).size > MAX_FILE_SIZE) return false; } catch { return false; }
    return true;
  });
}
