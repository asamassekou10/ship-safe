/**
 * Legal Command
 * =============
 *
 * Scans dependency manifests for packages that carry legal risk:
 * active DMCA takedowns, leaked-source derivatives, IP disputes,
 * and license violations.
 *
 * USAGE:
 *   ship-safe legal [path]        Scan for legally risky dependencies
 *   ship-safe legal . --json      JSON output
 *
 * EXIT CODES:
 *   0  Clean — no legally risky packages found
 *   1  Findings — one or more legally risky packages detected
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { LegalRiskAgent } from '../agents/legal-risk-agent.js';
import * as output from '../utils/output.js';

// =============================================================================
// RISK LABELS & COLORS
// =============================================================================

const RISK_COLORS = {
  dmca:              chalk.red.bold,
  'ip-dispute':      chalk.red,
  'leaked-source':   chalk.yellow.bold,
  'license-violation': chalk.yellow,
};

const RISK_LABELS = {
  dmca:              'DMCA Takedown',
  'ip-dispute':      'IP Dispute',
  'leaked-source':   'Leaked Source',
  'license-violation': 'License Violation',
};

const SEVERITY_COLORS = {
  critical: chalk.bgRed.white.bold,
  high:     chalk.red.bold,
  medium:   chalk.yellow,
  low:      chalk.blue,
};

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function legalCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  if (!options.json) {
    console.log();
    output.header('Legal Risk Audit');
    console.log(chalk.gray('  Scanning for DMCA notices, leaked-source derivatives, and IP disputes'));
    console.log();
  }

  // ── Run the agent ──────────────────────────────────────────────────────────
  const spinner = options.json
    ? null
    : ora({ text: 'Scanning dependency manifests…', color: 'cyan' }).start();

  const agent = new LegalRiskAgent();
  let findings = [];

  try {
    findings = await agent.analyze({ rootPath: absolutePath, files: [] });
    if (spinner) spinner.stop();
  } catch (err) {
    if (spinner) spinner.stop();
    output.error(`Legal scan failed: ${err.message}`);
    process.exit(1);
  }

  // ── JSON output ────────────────────────────────────────────────────────────
  if (options.json) {
    console.log(JSON.stringify({ findings, total: findings.length }, null, 2));
    process.exit(findings.length > 0 ? 1 : 0);
  }

  // ── Human-readable output ──────────────────────────────────────────────────
  if (findings.length === 0) {
    output.success('No legally risky packages found.');
    console.log();
    console.log(chalk.gray('  Scanned: package.json, requirements.txt, Cargo.toml, go.mod'));
    console.log();
    return;
  }

  // Group by severity
  const bySeverity = { critical: [], high: [], medium: [], low: [] };
  for (const f of findings) {
    (bySeverity[f.severity] || bySeverity.medium).push(f);
  }

  const total = findings.length;
  const critCount = bySeverity.critical.length;
  const highCount = bySeverity.high.length;

  // Summary line
  console.log(
    chalk.red.bold(`  ${total} legal risk finding${total === 1 ? '' : 's'}`),
    chalk.gray('—'),
    critCount > 0 ? chalk.red.bold(`${critCount} critical`) + chalk.gray(', ') : '',
    highCount > 0 ? chalk.red(`${highCount} high`) : '',
  );
  console.log();

  // Print findings
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const group = bySeverity[severity];
    if (group.length === 0) continue;

    for (const f of group) {
      const sevBadge = SEVERITY_COLORS[severity]
        ? SEVERITY_COLORS[severity](` ${severity.toUpperCase()} `)
        : chalk.gray(` ${severity.toUpperCase()} `);

      // Extract risk type from rule: LEGAL_RISK_DMCA → dmca
      const riskKey = f.rule
        .replace('LEGAL_RISK_', '')
        .toLowerCase()
        .replace(/_/g, '-');
      const riskColor = RISK_COLORS[riskKey] || chalk.white;
      const riskLabel = RISK_LABELS[riskKey] || riskKey;

      console.log(`  ${sevBadge}  ${chalk.white.bold(f.title)}`);
      console.log(`          ${riskColor(`[${riskLabel}]`)}  ${chalk.gray(path.relative(absolutePath, f.file) || f.file)}`);
      console.log();
      console.log(`          ${chalk.gray(f.description)}`);
      console.log();
      if (f.fix) {
        console.log(`          ${chalk.cyan('Fix:')} ${chalk.gray(f.fix)}`);
      }
      console.log();
      console.log(chalk.gray('  ' + '─'.repeat(56)));
      console.log();
    }
  }

  // Footer
  console.log(chalk.yellow.bold('  ⚠  Shipping legally risky packages can expose your project to IP liability.'));
  console.log(chalk.gray('     Review each finding and remove the affected dependency before releasing.'));
  console.log();

  process.exit(1);
}
