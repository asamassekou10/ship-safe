/**
 * Audit Command — Full Security Audit
 * =====================================
 *
 * One command to run everything: secrets, agents, deps, score, and
 * generate a comprehensive report with a prioritized remediation plan.
 *
 * USAGE:
 *   npx ship-safe audit [path]                 Full audit with HTML report
 *   npx ship-safe audit . --json               JSON output
 *   npx ship-safe audit . --html report.html   Custom report path
 *   npx ship-safe audit . --no-deps            Skip dependency audit
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import fg from 'fast-glob';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import { PolicyEngine } from '../agents/policy-engine.js';
import { HTMLReporter } from '../agents/html-reporter.js';
import { SBOMGenerator } from '../agents/sbom-generator.js';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { runDepsAudit } from './deps.js';
import {
  SECRET_PATTERNS,
  SECURITY_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  SKIP_FILENAMES,
  MAX_FILE_SIZE,
  loadGitignorePatterns
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence } from '../utils/entropy.js';
import { CacheManager } from '../utils/cache-manager.js';
import { filterBaseline } from './baseline.js';
import { generatePDF, generatePrintHTML, isChromeAvailable } from '../utils/pdf-generator.js';
import { SecretsVerifier } from '../utils/secrets-verifier.js';

// =============================================================================
// CONSTANTS
// =============================================================================

const ALL_PATTERNS = [...SECRET_PATTERNS, ...SECURITY_PATTERNS];

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

const CATEGORY_LABELS = {
  secrets: 'Secrets',
  injection: 'Code Vulnerabilities',
  deps: 'Dependencies',
  auth: 'Auth & Access Control',
  config: 'Configuration',
  'supply-chain': 'Supply Chain',
  api: 'API Security',
  llm: 'AI/LLM Security',
};

const EFFORT_MAP = {
  secrets: 'low',
  config: 'low',
  deps: 'medium',
  injection: 'medium',
  auth: 'medium',
  'supply-chain': 'medium',
  api: 'medium',
  llm: 'high',
};

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function auditCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  const machineOutput = options.json || options.sarif || options.csv || options.md;

  if (!fs.existsSync(absolutePath)) {
    console.error(chalk.red(`  Path does not exist: ${absolutePath}`));
    process.exit(1);
  }

  if (!machineOutput) {
    console.log();
    console.log(chalk.cyan('═'.repeat(60)));
    console.log(chalk.cyan.bold('  Ship Safe — Full Security Audit'));
    console.log(chalk.cyan('═'.repeat(60)));
    console.log();
  }

  // ── Cache Layer ──────────────────────────────────────────────────────────
  const useCache = options.cache !== false;
  const cache = new CacheManager(absolutePath);
  let cacheData = useCache ? cache.load() : null;
  let cacheDiff = null;
  let allFiles = [];

  // ── Phase 1: Secret Scan ──────────────────────────────────────────────────
  const secretSpinner = machineOutput ? null : ora({ text: chalk.white('[Phase 1/4] Scanning for secrets...'), color: 'cyan' }).start();
  let secretFindings = [];
  let filesScanned = 0;

  try {
    allFiles = await findFiles(absolutePath);
    filesScanned = allFiles.length;

    // Determine which files need scanning (incremental if cache exists)
    let filesToScan = allFiles;
    let cachedSecretFindings = [];

    if (cacheData) {
      cacheDiff = cache.diff(allFiles);
      filesToScan = cacheDiff.changedFiles;
      // Reuse cached findings for unchanged files (secrets only)
      cachedSecretFindings = cacheDiff.cachedFindings.filter(
        f => f.category === 'secrets' || f.category === 'secret'
      );
    }

    for (const file of filesToScan) {
      const fileResults = scanFileForSecrets(file);
      for (const f of fileResults) {
        secretFindings.push({
          file,
          line: f.line,
          column: f.column,
          severity: f.severity,
          category: f.category || 'secrets',
          rule: f.patternName,
          title: f.patternName.replace(/_/g, ' '),
          description: f.description,
          matched: f.matched,
          confidence: f.confidence,
          fix: file.match(/\.env(\..*)?$/)
            ? `Ensure .env is in .gitignore and use a secrets manager for production`
            : `Move to environment variable or secrets manager`,
        });
      }
    }

    // Downgrade .env findings if the file is gitignored (properly managed)
    const gitignoreContent = (() => {
      try { return fs.readFileSync(path.join(absolutePath, '.gitignore'), 'utf-8'); } catch { return ''; }
    })();
    const envIsGitignored = gitignoreContent.split('\n')
      .map(l => l.trim())
      .some(l => /^\.env(\s|$)/.test(l) || l === '*.env' || l === '.env*' || l === '.env.local' || l === '.env.production');

    if (envIsGitignored) {
      for (const f of secretFindings) {
        if (f.file.match(/\.env(\..*)?$/) && !f.file.includes('node_modules')) {
          f.severity = 'low';
          f.confidence = 'low';
          f.fix = 'Already gitignored — ensure secrets manager is used for production deploys';
        }
      }
    }

    // Merge with cached findings for unchanged files
    secretFindings = [...secretFindings, ...cachedSecretFindings];

    const cacheNote = cacheDiff && cacheDiff.changedFiles.length < allFiles.length
      ? ` (${cacheDiff.changedFiles.length} changed, ${cacheDiff.unchangedCount} cached)`
      : '';

    if (secretSpinner) secretSpinner.succeed(
      secretFindings.length === 0
        ? chalk.green(`[Phase 1/4] Secrets: clean${cacheNote}`)
        : chalk.red(`[Phase 1/4] Secrets: ${secretFindings.length} found${cacheNote}`)
    );
  } catch (err) {
    if (secretSpinner) secretSpinner.fail(chalk.red(`[Phase 1/4] Secret scan failed: ${err.message}`));
  }

  // ── Phase 2: Agent Scan ───────────────────────────────────────────────────
  const agentSpinner = machineOutput ? null : ora({ text: chalk.white('[Phase 2/4] Running 12 security agents...'), color: 'cyan' }).start();
  let agentFindings = [];
  let recon = null;
  let agentResults = [];

  try {
    const orchestrator = buildOrchestrator();
    // Suppress individual agent spinners by using quiet mode
    // Pass changedFiles for incremental scanning if cache is valid
    const orchestratorOpts = { quiet: true };
    if (options.deep) orchestratorOpts.deep = true;
    if (options.local) orchestratorOpts.local = true;
    if (options.model) orchestratorOpts.model = options.model;
    if (options.budget) orchestratorOpts.budget = options.budget;
    if (options.verbose) orchestratorOpts.verbose = true;
    if (cacheDiff && cacheDiff.changedFiles.length < allFiles.length) {
      orchestratorOpts.changedFiles = cacheDiff.changedFiles;
    }
    const results = await orchestrator.runAll(absolutePath, orchestratorOpts);
    recon = results.recon;
    agentFindings = results.findings;
    agentResults = results.agentResults;

    const totalAgentFindings = agentFindings.length;
    const agentCount = agentResults.filter(a => a.success).length;
    if (agentSpinner) agentSpinner.succeed(
      totalAgentFindings === 0
        ? chalk.green(`[Phase 2/4] ${agentCount} agents: clean`)
        : chalk.yellow(`[Phase 2/4] ${agentCount} agents: ${totalAgentFindings} finding(s)`)
    );
  } catch (err) {
    if (agentSpinner) agentSpinner.fail(chalk.red(`[Phase 2/4] Agent scan failed: ${err.message}`));
  }

  // ── Phase 3: Dependency Audit ─────────────────────────────────────────────
  let depVulns = [];
  if (options.deps !== false) {
    const depSpinner = machineOutput ? null : ora({ text: chalk.white('[Phase 3/4] Auditing dependencies...'), color: 'cyan' }).start();
    try {
      const depResult = await runDepsAudit(absolutePath);
      depVulns = depResult.vulns || [];
      if (depSpinner) depSpinner.succeed(
        depVulns.length === 0
          ? chalk.green('[Phase 3/4] Dependencies: clean')
          : chalk.red(`[Phase 3/4] Dependencies: ${depVulns.length} CVE(s)`)
      );
    } catch {
      if (depSpinner) depSpinner.succeed(chalk.gray('[Phase 3/4] Dependencies: skipped (no manifest)'));
    }
  } else if (!machineOutput) {
    console.log(chalk.gray('  [Phase 3/4] Dependencies: skipped (--no-deps)'));
  }

  // ── Phase 4: Merge, Score, and Build Plan ─────────────────────────────────
  const scoreSpinner = machineOutput ? null : ora({ text: chalk.white('[Phase 4/4] Computing security score...'), color: 'cyan' }).start();

  // Merge secret findings + agent findings, deduplicate
  const allFindings = deduplicateFindings([...secretFindings, ...agentFindings]);

  // Apply policy
  const policy = PolicyEngine.load(absolutePath);
  let filteredFindings = policy.applyPolicy(allFindings);

  // Apply baseline filter (only show new findings)
  if (options.baseline) {
    const beforeCount = filteredFindings.length;
    filteredFindings = filterBaseline(filteredFindings, absolutePath);
    if (!machineOutput && beforeCount !== filteredFindings.length) {
      console.log(chalk.gray(`  Baseline: ${beforeCount - filteredFindings.length} known finding(s) filtered, ${filteredFindings.length} new`));
    }
  }

  // Count suppressions (ship-safe-ignore comments)
  const suppressions = countSuppressions(allFiles);

  // Score
  const scoringEngine = new ScoringEngine();
  const scoreResult = scoringEngine.compute(filteredFindings, depVulns);
  scoringEngine.saveToHistory(absolutePath, scoreResult, suppressions);

  const gradeColor = scoreResult.score >= 75 ? chalk.green.bold : scoreResult.score >= 60 ? chalk.yellow.bold : chalk.red.bold;
  if (scoreSpinner) scoreSpinner.succeed(
    chalk.white('[Phase 4/4] Score: ') + gradeColor(`${scoreResult.score}/100 ${scoreResult.grade.letter}`)
  );

  // ── AI Classification (optional, with LLM cache) ───────────────────────
  if (options.ai !== false) {
    const provider = autoDetectProvider(absolutePath);
    if (provider && filteredFindings.length > 0 && filteredFindings.length <= 50) {
      const aiSpinner = machineOutput ? null : ora({ text: `Classifying with ${provider.name}...`, color: 'cyan' }).start();
      try {
        // Check LLM cache for existing classifications
        const llmCache = cache.loadLLMClassifications();
        const uncachedFindings = [];
        let cachedCount = 0;

        for (const finding of filteredFindings) {
          const key = cache.getLLMCacheKey(finding);
          const cached = llmCache[key];
          if (cached) {
            finding.aiClassification = cached.classification;
            finding.aiReason = cached.reason;
            finding.aiFix = cached.fix;
            cachedCount++;
          } else {
            uncachedFindings.push(finding);
          }
        }

        // Only send uncached findings to LLM
        if (uncachedFindings.length > 0) {
          const classifications = await provider.classify(uncachedFindings);
          const newCacheEntries = {};
          for (const cl of classifications) {
            const finding = filteredFindings.find(f => `${f.file}:${f.line}` === cl.id);
            if (finding) {
              finding.aiClassification = cl.classification;
              finding.aiReason = cl.reason;
              finding.aiFix = cl.fix;
              const key = cache.getLLMCacheKey(finding);
              newCacheEntries[key] = {
                classification: cl.classification,
                reason: cl.reason,
                fix: cl.fix,
                cachedAt: new Date().toISOString(),
              };
            }
          }
          cache.saveLLMClassifications(newCacheEntries);
        }

        const cacheNote = cachedCount > 0 ? `, ${cachedCount} cached` : '';
        if (aiSpinner) aiSpinner.succeed(chalk.green(`AI classification complete (${provider.name}${cacheNote})`));
      } catch (err) {
        if (aiSpinner) aiSpinner.fail(chalk.yellow(`AI classification failed: ${err.message}`));
      }
    }
  }

  // ── Secrets Verification (optional, --verify flag) ─────────────────────
  if (options.verify) {
    const verifySpinner = machineOutput ? null : ora({ text: 'Verifying leaked secrets against provider APIs...', color: 'cyan' }).start();
    try {
      const verifier = new SecretsVerifier();
      const verifyResults = await verifier.verify(filteredFindings);
      const activeCount = verifyResults.filter(r => r.result.active === true).length;
      const inactiveCount = verifyResults.filter(r => r.result.active === false).length;
      if (verifySpinner) {
        verifySpinner.succeed(chalk.green(
          `Secrets verified: ${activeCount} active, ${inactiveCount} inactive, ${verifyResults.length - activeCount - inactiveCount} unknown`
        ));
      }
      // Show active secrets warning
      if (activeCount > 0 && !machineOutput) {
        console.log(chalk.red.bold('  ⚠ ACTIVE SECRETS DETECTED — rotate immediately:'));
        for (const r of verifyResults.filter(r => r.result.active === true)) {
          const rel = path.relative(absolutePath, r.finding.file).replace(/\\/g, '/');
          console.log(chalk.red(`    ${r.result.provider}: ${rel}:${r.finding.line} — ${r.result.info}`));
        }
      }
    } catch (err) {
      if (verifySpinner) verifySpinner.fail(chalk.yellow(`Secrets verification failed: ${err.message}`));
    }
  }

  // ── Save Cache ──────────────────────────────────────────────────────────
  if (useCache) {
    try {
      // Merge agent findings back for cache (secret + agent findings from changed files)
      // plus cached findings from unchanged files
      const cachedAgentFindings = cacheData && cacheDiff
        ? cacheDiff.cachedFindings.filter(f => f.category !== 'secrets' && f.category !== 'secret')
        : [];
      const allFindingsForCache = [...secretFindings, ...agentFindings, ...cachedAgentFindings];
      cache.save(allFiles, deduplicateFindings(allFindingsForCache), recon, scoreResult);
    } catch {
      // Silent — caching should never break a scan
    }
  }

  // ── Build Remediation Plan ────────────────────────────────────────────────
  const remediationPlan = buildRemediationPlan(filteredFindings, depVulns, absolutePath);

  // ── Output ────────────────────────────────────────────────────────────────
  console.log();

  if (options.csv) {
    outputCSV(filteredFindings, depVulns, scoreResult, absolutePath);
  } else if (options.md) {
    outputMarkdown(scoreResult, filteredFindings, depVulns, remediationPlan, absolutePath);
  } else if (options.json) {
    outputJSON(scoreResult, filteredFindings, depVulns, recon, agentResults, remediationPlan, suppressions, options.compare ? scoringEngine.loadHistory(absolutePath) : null);
  } else if (options.sarif) {
    outputSARIF(filteredFindings, absolutePath);
  } else {
    printReport(scoreResult, filteredFindings, depVulns, recon, remediationPlan, absolutePath, filesScanned);
  }

  // ── HTML Report (always generate unless machine output) ───────────────────
  if (!options.json && !options.sarif && !options.csv && !options.md) {
    const htmlPath = typeof options.html === 'string' ? options.html : 'ship-safe-report.html';
    const reporter = new HTMLReporter();
    reporter.generateFullReport(scoreResult, filteredFindings, depVulns, recon, remediationPlan, absolutePath, htmlPath);
    console.log();
    console.log(chalk.cyan(`  Full report: ${chalk.white.bold(htmlPath)}`));

    // PDF export
    if (options.pdf) {
      const pdfPath = typeof options.pdf === 'string' ? options.pdf : 'ship-safe-report.pdf';
      const result = generatePDF(path.resolve(htmlPath), path.resolve(pdfPath));
      if (result) {
        console.log(chalk.cyan(`  PDF report:  ${chalk.white.bold(pdfPath)}`));
      } else {
        // Fallback: print-optimized HTML
        const fallbackPath = pdfPath.replace(/\.pdf$/, '.print.html');
        generatePrintHTML(path.resolve(htmlPath), path.resolve(fallbackPath));
        console.log(chalk.yellow(`  Chrome not found — saved print-optimized HTML: ${fallbackPath}`));
        console.log(chalk.gray('  Open in a browser and Print → Save as PDF'));
      }
    }
  }

  if (!machineOutput && !options.csv && !options.md) {
    // ── Policy Violations ──────────────────────────────────────────────────
    const violations = policy.evaluate(scoreResult, filteredFindings);
    if (violations.length > 0) {
      console.log();
      console.log(chalk.red.bold('  Policy Violations:'));
      for (const v of violations.slice(0, 5)) {
        console.log(chalk.red(`    ✗ ${v.message}`));
      }
    }

    // ── Trend ───────────────────────────────────────────────────────────────
    const trend = scoringEngine.getTrend(absolutePath, scoreResult.score);
    if (trend) {
      const arrow = trend.diff > 0 ? chalk.green('↑') : trend.diff < 0 ? chalk.red('↓') : chalk.gray('→');
      console.log(chalk.gray(`  Trend: ${trend.previousScore} → ${trend.currentScore} ${arrow} (${trend.diff > 0 ? '+' : ''}${trend.diff})`));
    }

    // ── Detailed Comparison ────────────────────────────────────────────────
    if (options.compare) {
      printComparison(scoringEngine, absolutePath, scoreResult);
    }

    console.log();
    console.log(chalk.cyan('═'.repeat(60)));
    console.log();
  }

  process.exit(scoreResult.score >= 75 ? 0 : 1);
}

// =============================================================================
// REMEDIATION PLAN BUILDER
// =============================================================================

function buildRemediationPlan(findings, depVulns, rootPath) {
  const plan = [];
  let priority = 1;

  // Priority order: secrets first, then by severity
  const secretFindings = findings.filter(f => f.category === 'secrets' || f.category === 'secret');
  const otherFindings = findings.filter(f => f.category !== 'secrets' && f.category !== 'secret');

  // Group and sort
  for (const sev of SEV_ORDER) {
    // Secrets at this severity — group .env findings by file
    const sevSecrets = secretFindings.filter(s => s.severity === sev);
    const envGroups = new Map();
    const nonEnvSecrets = [];

    for (const f of sevSecrets) {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      if (f.file.match(/\.env(\..*)?$/)) {
        if (!envGroups.has(relFile)) envGroups.set(relFile, []);
        envGroups.get(relFile).push(f);
      } else {
        nonEnvSecrets.push(f);
      }
    }

    // One plan item per .env file
    for (const [relFile, envFindings] of envGroups) {
      const names = envFindings.map(f => f.title || f.rule).join(', ');
      plan.push({
        priority: priority++,
        severity: sev,
        category: 'secrets',
        categoryLabel: 'SECRETS',
        title: `${envFindings.length} secret${envFindings.length > 1 ? 's' : ''} in ${relFile} (${names})`,
        file: relFile,
        action: envFindings[0].fix || 'Ensure .env is in .gitignore and use a secrets manager for production',
        effort: 'low',
      });
    }

    // Individual items for non-.env secrets
    for (const f of nonEnvSecrets) {
      plan.push({
        priority: priority++,
        severity: sev,
        category: 'secrets',
        categoryLabel: 'SECRETS',
        title: f.title || f.rule,
        file: `${path.relative(rootPath, f.file).replace(/\\/g, '/')}:${f.line}`,
        action: f.aiFix || f.fix || f.description,
        effort: 'low',
      });
    }

    // Other findings at this severity
    for (const f of otherFindings.filter(s => s.severity === sev)) {
      plan.push({
        priority: priority++,
        severity: sev,
        category: f.category,
        categoryLabel: (CATEGORY_LABELS[f.category] || f.category).toUpperCase(),
        title: f.title || f.rule,
        file: `${path.relative(rootPath, f.file).replace(/\\/g, '/')}:${f.line}`,
        action: f.aiFix || f.fix || f.description,
        effort: EFFORT_MAP[f.category] || 'medium',
      });
    }

    // Dep vulns at this severity
    for (const d of depVulns.filter(v => v.severity === sev || (sev === 'medium' && v.severity === 'moderate'))) {
      plan.push({
        priority: priority++,
        severity: sev,
        category: 'deps',
        categoryLabel: 'DEPENDENCIES',
        title: `Vulnerable: ${d.package || d.id}`,
        file: 'package.json',
        action: d.description ? `${d.description.slice(0, 80)}` : 'Update to patched version',
        effort: 'medium',
      });
    }
  }

  return plan;
}

// =============================================================================
// CONSOLE OUTPUT
// =============================================================================

function printReport(scoreResult, findings, depVulns, recon, plan, rootPath, filesScanned) {
  const GRADE_COLOR = { A: chalk.green.bold, B: chalk.cyan.bold, C: chalk.yellow.bold, D: chalk.red, F: chalk.red.bold };
  const SEV_ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
  const SEV_LABEL = { critical: 'CRITICAL — fix immediately', high: 'HIGH — fix before deploy', medium: 'MEDIUM — fix soon', low: 'LOW — review when possible' };

  // ── Score ─────────────────────────────────────────────────────────────────
  const gradeColor = GRADE_COLOR[scoreResult.grade.letter] || chalk.white;
  const scoreColor = scoreResult.score >= 75 ? chalk.green.bold : scoreResult.score >= 60 ? chalk.yellow.bold : chalk.red.bold;

  console.log(chalk.cyan('  ' + '═'.repeat(56)));
  console.log(
    chalk.white.bold('  Security Score: ') +
    scoreColor(`${scoreResult.score}/100 `) +
    gradeColor(scoreResult.grade.letter) +
    chalk.gray(` — ${scoreResult.grade.label}`)
  );
  console.log(chalk.cyan('  ' + '═'.repeat(56)));
  console.log();

  // ── Category Breakdown ────────────────────────────────────────────────────
  console.log(chalk.white.bold('  Category Breakdown'));
  console.log(chalk.gray('  ' + '─'.repeat(56)));

  for (const [key, cat] of Object.entries(scoreResult.categories)) {
    const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
    const icon = count === 0 ? chalk.green('✔') : chalk.red('✘');
    const status = count === 0 ? chalk.green('clean') : chalk.red(`${count} issue(s)`);
    const deduction = cat.deduction > 0 ? chalk.red(`-${cat.deduction} pts`) : chalk.gray('+0');
    console.log(`  ${icon}  ${chalk.white(cat.label.padEnd(22))} ${status.padEnd(25)} ${deduction}`);
  }

  // Deps row
  const depIcon = depVulns.length === 0 ? chalk.green('✔') : chalk.red('✘');
  const depStatus = depVulns.length === 0 ? chalk.green('clean') : chalk.red(`${depVulns.length} CVE(s)`);
  console.log(`  ${depIcon}  ${chalk.white('Dependencies'.padEnd(22))} ${depStatus}`);

  console.log(chalk.gray(`\n  Files scanned: ${filesScanned} | Findings: ${findings.length} | CVEs: ${depVulns.length}`));

  // ── Remediation Plan ──────────────────────────────────────────────────────
  if (plan.length > 0) {
    console.log();
    console.log(chalk.cyan('  ' + '═'.repeat(56)));
    console.log(chalk.cyan.bold('  Remediation Plan'));
    console.log(chalk.cyan('  ' + '═'.repeat(56)));

    let currentSev = null;
    let shown = 0;
    const maxItems = 30;

    for (const item of plan) {
      if (shown >= maxItems) {
        console.log(chalk.gray(`\n  ... and ${plan.length - maxItems} more items in the full report`));
        break;
      }

      if (item.severity !== currentSev) {
        currentSev = item.severity;
        console.log();
        console.log(chalk.white.bold(`  ${SEV_ICON[currentSev] || '⚪'} ${SEV_LABEL[currentSev] || currentSev.toUpperCase()}`));
        console.log(chalk.gray('  ' + '─'.repeat(56)));
      }

      console.log(
        chalk.white(`  ${String(item.priority).padStart(2)}.`) +
        chalk.gray(` [${item.categoryLabel}] `) +
        chalk.white(item.title)
      );
      console.log(
        chalk.gray(`      ${item.file}`) +
        chalk.gray(' → ') +
        chalk.green((item.action || '').slice(0, 70))
      );
      shown++;
    }
  } else {
    console.log();
    console.log(chalk.green.bold('  All clear — safe to ship!'));
  }

  // ── Attack Surface ────────────────────────────────────────────────────────
  if (recon) {
    console.log();
    console.log(chalk.gray('  Attack Surface:'));
    if (recon.frameworks?.length) console.log(chalk.gray(`    Frameworks:  ${recon.frameworks.join(', ')}`));
    if (recon.databases?.length) console.log(chalk.gray(`    Databases:   ${recon.databases.join(', ')}`));
    if (recon.authPatterns?.length) console.log(chalk.gray(`    Auth:        ${recon.authPatterns.join(', ')}`));
    if (recon.apiRoutes?.length) console.log(chalk.gray(`    API Routes:  ${recon.apiRoutes.length} discovered`));
  }
}

// =============================================================================
// JSON OUTPUT
// =============================================================================

function outputJSON(scoreResult, findings, depVulns, recon, agentResults, remediationPlan, suppressions, history) {
  const output = {
    score: scoreResult.score,
    grade: scoreResult.grade.letter,
    gradeLabel: scoreResult.grade.label,
    totalFindings: findings.length,
    totalDepVulns: depVulns.length,
    categories: Object.fromEntries(
      Object.entries(scoreResult.categories).map(([k, v]) => [k, {
        label: v.label,
        findingCount: Object.values(v.counts).reduce((a, b) => a + b, 0),
        deduction: v.deduction,
        counts: v.counts,
      }])
    ),
    findings: findings.map(f => ({
      file: f.file, line: f.line, severity: f.severity, category: f.category,
      rule: f.rule, title: f.title, description: f.description, fix: f.fix,
      cwe: f.cwe, owasp: f.owasp,
    })),
    depVulns: depVulns.map(d => ({
      severity: d.severity, package: d.package || d.id, description: d.description,
    })),
    remediationPlan,
    recon,
    agents: agentResults,
  };
  if (suppressions) output.suppressions = suppressions;
  if (history && history.length >= 2) {
    const prev = history[history.length - 2];
    output.comparison = {
      previousScore: prev.score,
      previousGrade: prev.grade,
      previousDate: prev.timestamp,
      diff: scoreResult.score - prev.score,
      categoryComparison: Object.fromEntries(
        Object.entries(scoreResult.categories).map(([k, v]) => {
          const prevCat = prev.categoryScores?.[k];
          return [k, {
            label: v.label,
            current: -v.deduction,
            previous: prevCat ? -prevCat.deduction : 0,
            delta: prevCat ? prevCat.deduction - v.deduction : 0,
          }];
        })
      ),
    };
  }
  console.log(JSON.stringify(output, null, 2));
}

// =============================================================================
// SARIF OUTPUT
// =============================================================================

function outputSARIF(findings, rootPath) {
  const rules = {};
  for (const f of findings) {
    if (!rules[f.rule]) {
      rules[f.rule] = {
        id: f.rule,
        name: f.title || f.rule,
        shortDescription: { text: f.title || f.rule },
        fullDescription: { text: f.description || '' },
        defaultConfiguration: {
          level: ['critical', 'high'].includes(f.severity) ? 'error' : 'warning',
        },
      };
    }
  }

  console.log(JSON.stringify({
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ship-safe',
          version: '4.0.0',
          informationUri: 'https://github.com/asamassekou10/ship-safe',
          rules: Object.values(rules),
        }
      },
      results: findings.map(f => ({
        ruleId: f.rule,
        level: ['critical', 'high'].includes(f.severity) ? 'error' : 'warning',
        message: { text: `${f.title}: ${f.description}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: path.relative(rootPath, f.file).replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' },
            region: { startLine: f.line, startColumn: f.column || 1 },
          }
        }],
      })),
    }],
  }, null, 2));
}

// =============================================================================
// FILE SCANNING (inline from scan.js to avoid circular deps)
// =============================================================================

async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

  // Respect .gitignore patterns
  const gitignoreGlobs = loadGitignorePatterns(rootPath);
  globIgnore.push(...gitignoreGlobs);

  // Load .ship-safeignore
  const ignorePath = path.join(rootPath, '.ship-safeignore');
  if (fs.existsSync(ignorePath)) {
    try {
      const patterns = fs.readFileSync(ignorePath, 'utf-8')
        .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      for (const p of patterns) {
        if (p.endsWith('/')) { globIgnore.push(`**/${p}**`); }
        else { globIgnore.push(`**/${p}`); globIgnore.push(p); }
      }
    } catch { /* skip */ }
  }

  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true
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

function scanFileForSecrets(filePath) {
  const findings = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      if (/ship-safe-ignore/i.test(line)) continue;
      for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
          findings.push({
            line: lineNum + 1, column: match.index + 1, matched: match[0],
            patternName: pattern.name, severity: pattern.severity,
            confidence: getConfidence(pattern, match[0]),
            description: pattern.description, category: pattern.category || 'secret'
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

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// =============================================================================
// SUPPRESSION COUNTING
// =============================================================================

function countSuppressions(files) {
  const suppressions = {};
  let total = 0;
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');
      for (const line of lines) {
        if (/ship-safe-ignore/i.test(line)) {
          total++;
          // Try to extract rule name from comment: ship-safe-ignore RULE_NAME
          const match = line.match(/ship-safe-ignore\s+(\w+)/i);
          const rule = match ? match[1] : '_unspecified';
          suppressions[rule] = (suppressions[rule] || 0) + 1;
        }
      }
    } catch { /* skip */ }
  }
  return total > 0 ? { total, rules: suppressions } : null;
}

// =============================================================================
// CSV OUTPUT
// =============================================================================

function outputCSV(findings, depVulns, scoreResult, rootPath) {
  const escape = (s) => {
    if (!s) return '';
    const str = String(s).replace(/"/g, '""');
    return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str}"` : str;
  };

  console.log('severity,category,rule,file,line,title,description,fix');
  for (const f of findings) {
    const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
    console.log([
      escape(f.severity), escape(f.category), escape(f.rule),
      escape(relFile), f.line || '', escape(f.title),
      escape(f.description), escape(f.fix),
    ].join(','));
  }
  for (const d of depVulns) {
    console.log([
      escape(d.severity), 'deps', escape(d.id || d.package),
      'package.json', '', escape(`Vulnerable: ${d.package || d.id}`),
      escape(d.description), escape('Update to patched version'),
    ].join(','));
  }
}

// =============================================================================
// MARKDOWN OUTPUT
// =============================================================================

function outputMarkdown(scoreResult, findings, depVulns, remediationPlan, rootPath) {
  const lines = [];
  lines.push('# Ship Safe Security Report');
  lines.push('');
  lines.push(`**Score: ${scoreResult.score}/100 (${scoreResult.grade.letter})** — ${scoreResult.grade.label}`);
  lines.push('');
  lines.push(`> Generated: ${new Date().toISOString()}`);
  lines.push('');

  // Category breakdown
  lines.push('## Category Breakdown');
  lines.push('');
  lines.push('| Category | Issues | Deduction |');
  lines.push('|----------|--------|-----------|');
  for (const [, cat] of Object.entries(scoreResult.categories)) {
    const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
    lines.push(`| ${cat.label} | ${count} | -${cat.deduction} |`);
  }
  lines.push('');

  // Findings by severity
  for (const sev of SEV_ORDER) {
    const sevFindings = findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    lines.push(`## ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${sevFindings.length})`);
    lines.push('');
    lines.push('| File | Rule | Description | Fix |');
    lines.push('|------|------|-------------|-----|');
    for (const f of sevFindings) {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      lines.push(`| ${relFile}:${f.line} | ${f.rule} | ${(f.description || '').slice(0, 80)} | ${(f.fix || '').slice(0, 60)} |`);
    }
    lines.push('');
  }

  // Dep vulns
  if (depVulns.length > 0) {
    lines.push('## Dependency Vulnerabilities');
    lines.push('');
    lines.push('| Severity | Package | Description |');
    lines.push('|----------|---------|-------------|');
    for (const d of depVulns) {
      lines.push(`| ${d.severity} | ${d.package || d.id} | ${(d.description || '').slice(0, 80)} |`);
    }
    lines.push('');
  }

  console.log(lines.join('\n'));
}

// =============================================================================
// COMPARISON OUTPUT
// =============================================================================

function printComparison(scoringEngine, rootPath, scoreResult) {
  const history = scoringEngine.loadHistory(rootPath);
  if (history.length < 2) {
    console.log(chalk.gray('\n  No previous scan to compare against.'));
    return;
  }

  const prev = history[history.length - 2];
  console.log();
  console.log(chalk.cyan.bold('  Detailed Comparison'));
  console.log(chalk.gray('  ' + '─'.repeat(56)));
  console.log(chalk.gray(`  Previous scan: ${new Date(prev.timestamp).toLocaleString()}`));
  console.log();
  console.log(chalk.white('  Category'.padEnd(26)) + chalk.white('Previous'.padEnd(12)) + chalk.white('Current'.padEnd(12)) + chalk.white('Delta'));
  console.log(chalk.gray('  ' + '─'.repeat(56)));

  for (const [key, cat] of Object.entries(scoreResult.categories)) {
    const prevCat = prev.categoryScores?.[key];
    const prevDed = prevCat ? prevCat.deduction : 0;
    const curDed = cat.deduction;
    const delta = prevDed - curDed;

    let deltaStr;
    if (delta > 0) deltaStr = chalk.green(`+${delta} improved`);
    else if (delta < 0) deltaStr = chalk.red(`${delta} regressed`);
    else deltaStr = chalk.gray('→ unchanged');

    console.log(
      `  ${chalk.white(cat.label.padEnd(24))}` +
      `${chalk.gray(String(-prevDed).padEnd(12))}` +
      `${chalk.gray(String(-curDed).padEnd(12))}` +
      deltaStr
    );
  }

  const overallDiff = scoreResult.score - prev.score;
  let overallDelta;
  if (overallDiff > 0) overallDelta = chalk.green(`+${overallDiff} improved`);
  else if (overallDiff < 0) overallDelta = chalk.red(`${overallDiff} regressed`);
  else overallDelta = chalk.gray('→ unchanged');

  console.log(chalk.gray('  ' + '─'.repeat(56)));
  console.log(
    `  ${chalk.white.bold('Overall'.padEnd(24))}` +
    `${chalk.gray(`${prev.score}/100 ${prev.grade}`.padEnd(12))}` +
    `${chalk.gray(`${scoreResult.score}/100 ${scoreResult.grade.letter}`.padEnd(12))}` +
    overallDelta
  );
}
