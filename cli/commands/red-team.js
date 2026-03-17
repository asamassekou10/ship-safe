/**
 * Red Team Command
 * =================
 *
 * Run all security agents against the codebase.
 * This is the main entry point for the multi-agent security audit.
 *
 * USAGE:
 *   npx ship-safe red-team [path]           Full multi-agent audit
 *   npx ship-safe red-team . --agents injection,auth  Run specific agents
 *   npx ship-safe red-team . --json         JSON output
 *   npx ship-safe red-team . --html report.html  Generate HTML report
 *   npx ship-safe red-team . --sarif        SARIF output
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import { PolicyEngine } from '../agents/policy-engine.js';
import { HTMLReporter } from '../agents/html-reporter.js';
import { SBOMGenerator } from '../agents/sbom-generator.js';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { runDepsAudit } from './deps.js';
import * as output from '../utils/output.js';

export async function redTeamCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  console.log();
  output.header('Ship Safe v4.0 — Multi-Agent Security Audit');
  console.log();

  // ── 1. Run orchestrator ─────────────────────────────────────────────────────
  const orchestrator = buildOrchestrator();

  const agentFilter = options.agents
    ? options.agents.split(',').map(a => a.trim())
    : null;

  const orchestratorOpts = {
    verbose: options.verbose,
    agents: agentFilter,
  };
  if (options.deep) orchestratorOpts.deep = true;
  if (options.local) orchestratorOpts.local = true;
  if (options.model) orchestratorOpts.model = options.model;
  if (options.budget) orchestratorOpts.budget = options.budget;

  const results = await orchestrator.runAll(absolutePath, orchestratorOpts);

  const { recon, findings, agentResults } = results;

  // ── 2. Dependency audit ─────────────────────────────────────────────────────
  let depVulns = [];
  if (!options.noDeps) {
    const depSpinner = ora({ text: 'Auditing dependencies...', color: 'cyan' }).start();
    try {
      const depResult = await runDepsAudit(absolutePath);
      depVulns = depResult.vulns || [];
      depSpinner.succeed(
        depVulns.length === 0
          ? chalk.green('Dependencies: clean')
          : chalk.yellow(`Dependencies: ${depVulns.length} CVE(s)`)
      );
    } catch {
      depSpinner.succeed(chalk.gray('Dependencies: skipped'));
    }
  }

  // ── 3. Apply policy ─────────────────────────────────────────────────────────
  const policy = PolicyEngine.load(absolutePath);
  const filteredFindings = policy.applyPolicy(findings);

  // ── 4. Score ────────────────────────────────────────────────────────────────
  const scoringEngine = new ScoringEngine();
  const scoreResult = scoringEngine.compute(filteredFindings, depVulns);
  scoringEngine.saveToHistory(absolutePath, scoreResult);

  // ── 5. AI classification (if provider available) ────────────────────────────
  if (options.ai !== false) {
    const provider = autoDetectProvider(absolutePath);
    if (provider && filteredFindings.length > 0 && filteredFindings.length <= 50) {
      const aiSpinner = ora({ text: `Classifying ${filteredFindings.length} finding(s) with ${provider.name}...`, color: 'cyan' }).start();
      try {
        const classifications = await provider.classify(filteredFindings);
        // Merge classifications back into findings
        for (const cl of classifications) {
          const finding = filteredFindings.find(f => `${f.file}:${f.line}` === cl.id);
          if (finding) {
            finding.aiClassification = cl.classification;
            finding.aiReason = cl.reason;
            finding.aiFix = cl.fix;
          }
        }
        aiSpinner.succeed(chalk.green(`AI classification complete (${provider.name})`));
      } catch (err) {
        aiSpinner.fail(chalk.yellow(`AI classification failed: ${err.message}`));
      }
    }
  }

  // ── 6. Output ───────────────────────────────────────────────────────────────
  if (options.json) {
    outputJSON(scoreResult, filteredFindings, recon, agentResults);
  } else if (options.sarif) {
    outputSARIF(filteredFindings, absolutePath);
  } else if (options.html) {
    const reporter = new HTMLReporter();
    const htmlPath = typeof options.html === 'string' ? options.html : 'ship-safe-report.html';
    reporter.generateToFile(scoreResult, filteredFindings, recon, absolutePath, htmlPath);
    output.success(`HTML report saved to ${htmlPath}`);
  } else {
    printResults(scoreResult, filteredFindings, recon, agentResults, depVulns, absolutePath);
  }

  // ── 7. SBOM (if requested) ──────────────────────────────────────────────────
  if (options.sbom) {
    const sbomGen = new SBOMGenerator();
    const sbomPath = typeof options.sbom === 'string' ? options.sbom : 'sbom.json';
    sbomGen.generateToFile(absolutePath, sbomPath);
    output.success(`SBOM saved to ${sbomPath}`);
  }

  // ── 8. Policy evaluation ────────────────────────────────────────────────────
  const violations = policy.evaluate(scoreResult, filteredFindings);
  if (violations.length > 0) {
    console.log();
    console.log(chalk.red.bold('  Policy Violations:'));
    for (const v of violations.slice(0, 10)) {
      console.log(chalk.red(`    ✗ ${v.message}`));
    }
    if (violations.length > 10) {
      console.log(chalk.gray(`    ... and ${violations.length - 10} more`));
    }
  }

  // ── 9. Trend ────────────────────────────────────────────────────────────────
  const trend = scoringEngine.getTrend(absolutePath, scoreResult.score);
  if (trend) {
    const arrow = trend.diff > 0 ? chalk.green('↑') : trend.diff < 0 ? chalk.red('↓') : chalk.gray('→');
    console.log();
    console.log(chalk.gray(`  Trend: ${trend.previousScore} → ${trend.currentScore} ${arrow} (${trend.diff > 0 ? '+' : ''}${trend.diff})`));
  }

  console.log();

  // Exit code
  process.exit(scoreResult.score >= 75 ? 0 : 1);
}

// =============================================================================
// OUTPUT FORMATTERS
// =============================================================================

function printResults(scoreResult, findings, recon, agentResults, depVulns, rootPath) {
  const GRADE_COLOR = { A: chalk.green.bold, B: chalk.cyan.bold, C: chalk.yellow.bold, D: chalk.red, F: chalk.red.bold };
  const SEV_COLOR = { critical: chalk.red.bold, high: chalk.yellow, medium: chalk.blue, low: chalk.gray };

  // ── Score ───────────────────────────────────────────────────────────────────
  console.log();
  const gradeColor = GRADE_COLOR[scoreResult.grade.letter] || chalk.white;
  const scoreColor = scoreResult.score >= 75 ? chalk.green.bold : scoreResult.score >= 60 ? chalk.yellow.bold : chalk.red.bold;

  console.log(
    chalk.white.bold('  Security Score: ') +
    scoreColor(`${scoreResult.score}/100 `) +
    gradeColor(scoreResult.grade.letter) +
    chalk.gray(` — ${scoreResult.grade.label}`)
  );
  console.log(chalk.cyan('  ' + '─'.repeat(58)));
  console.log();

  // ── Category breakdown ──────────────────────────────────────────────────────
  for (const [key, cat] of Object.entries(scoreResult.categories)) {
    const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
    const icon = count === 0 ? chalk.green('✔') : chalk.red('✘');
    const status = count === 0 ? chalk.green('clean') : chalk.red(`${count} issue(s)`);
    const deduction = cat.deduction > 0 ? chalk.red(`-${cat.deduction} pts`) : chalk.gray('+0');
    console.log(`  ${icon}  ${chalk.white.bold(cat.label.padEnd(22))} ${status.padEnd(25)} ${deduction}`);
  }

  // Dependencies row
  const depCount = depVulns.length;
  const depIcon = depCount === 0 ? chalk.green('✔') : chalk.red('✘');
  const depDeduction = scoreResult.categories.deps?.deduction || 0;
  console.log(`  ${depIcon}  ${chalk.white.bold('Dependencies'.padEnd(22))} ${depCount === 0 ? chalk.green('clean') : chalk.red(`${depCount} CVE(s)`)}`);

  // ── Top findings ────────────────────────────────────────────────────────────
  if (findings.length > 0) {
    console.log();
    console.log(chalk.yellow.bold(`  Top Findings (${Math.min(findings.length, 20)} of ${findings.length})`));
    console.log(chalk.yellow('  ' + '─'.repeat(58)));

    for (const f of findings.slice(0, 20)) {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      const sevColor = SEV_COLOR[f.severity] || chalk.white;
      const aiTag = f.aiClassification === 'FALSE_POSITIVE'
        ? chalk.gray(' [FP]')
        : f.aiClassification === 'REAL' ? chalk.red(' [REAL]') : '';

      console.log(`  ${sevColor(`[${f.severity.toUpperCase()}]`.padEnd(12))} ${chalk.white(`${relFile}:${f.line}`)}${aiTag}`);
      console.log(`  ${chalk.gray('           ')} ${f.title || f.rule}`);
      if (f.aiFix || f.fix) {
        console.log(`  ${chalk.gray('     Fix:')} ${chalk.green((f.aiFix || f.fix).slice(0, 80))}`);
      }
    }
  }

  // ── Attack surface summary ──────────────────────────────────────────────────
  if (recon) {
    console.log();
    console.log(chalk.cyan('  Attack Surface:'));
    if (recon.frameworks?.length) console.log(chalk.gray(`    Frameworks:  ${recon.frameworks.join(', ')}`));
    if (recon.databases?.length) console.log(chalk.gray(`    Databases:   ${recon.databases.join(', ')}`));
    if (recon.authPatterns?.length) console.log(chalk.gray(`    Auth:        ${recon.authPatterns.join(', ')}`));
    if (recon.apiRoutes?.length) console.log(chalk.gray(`    API Routes:  ${recon.apiRoutes.length} discovered`));
  }

  // ── Next steps ──────────────────────────────────────────────────────────────
  if (findings.length > 0) {
    console.log();
    console.log(chalk.yellow.bold('  Next steps:'));
    console.log(chalk.gray('    1. Review and fix findings above'));
    console.log(chalk.gray('    2. Run again: ') + chalk.cyan('npx ship-safe red-team .'));
    console.log(chalk.gray('    3. Generate report: ') + chalk.cyan('npx ship-safe red-team . --html report.html'));
    console.log(chalk.gray('    4. Set policy: ') + chalk.cyan('npx ship-safe policy init'));
  } else {
    console.log();
    output.success('All agents report clean — safe to ship!');
  }

  console.log(chalk.cyan('  ' + '═'.repeat(58)));
}

function outputJSON(scoreResult, findings, recon, agentResults) {
  console.log(JSON.stringify({
    score: scoreResult.score,
    grade: scoreResult.grade.letter,
    gradeLabel: scoreResult.grade.label,
    totalFindings: findings.length,
    categories: Object.fromEntries(
      Object.entries(scoreResult.categories).map(([k, v]) => [k, {
        label: v.label,
        findingCount: Object.values(v.counts).reduce((a, b) => a + b, 0),
        deduction: v.deduction,
        counts: v.counts,
      }])
    ),
    findings: findings.map(f => ({
      file: f.file,
      line: f.line,
      severity: f.severity,
      category: f.category,
      rule: f.rule,
      title: f.title,
      description: f.description,
      fix: f.fix,
      aiClassification: f.aiClassification,
      aiFix: f.aiFix,
    })),
    recon,
    agents: agentResults,
  }, null, 2));
}

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
        helpUri: 'https://github.com/asamassekou10/ship-safe',
      };
    }
  }

  const sarif = {
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
            artifactLocation: {
              uri: path.relative(rootPath, f.file).replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: { startLine: f.line, startColumn: f.column || 1 },
          }
        }],
      })),
    }],
  };

  console.log(JSON.stringify(sarif, null, 2));
}
