/**
 * Investigate Command
 * ===================
 *
 * The scanner answers "what looks wrong here". This answers the question after
 * it: of the things that look wrong, which ones are real, how would they be
 * reached, and what did we actually establish rather than assume.
 *
 * It runs the same sensors as `audit` and then reports on the evidence rather
 * than the score. Findings are grouped by verdict, each one showing the pass
 * that decided it, the path the value took, and the lines that were read to
 * conclude it — so a reader can disagree with a specific step instead of
 * with a severity label.
 *
 * USAGE:
 *   ship-safe investigate [path]           Scan, investigate, report by verdict
 *   ship-safe investigate . --deep         Add the LLM pass
 *   ship-safe investigate . --all          Show unresolved and refuted too
 *   ship-safe investigate . --json         Machine-readable evidence
 *
 * Exits 1 when anything is confirmed.
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { buildOrchestratorAsync } from '../agents/index.js';
import { summarizeEvidence, decidingClaim } from '../utils/evidence.js';
import * as output from '../utils/output.js';

const VERDICT_ORDER = ['confirmed', 'likely', 'unknown', 'refuted'];

const VERDICT_STYLE = {
  confirmed: { color: chalk.red,    label: 'CONFIRMED', blurb: 'traced end to end' },
  likely:    { color: chalk.yellow, label: 'LIKELY',    blurb: 'plausible, no mitigation found' },
  unknown:   { color: chalk.gray,   label: 'UNRESOLVED', blurb: 'nothing established either way' },
  refuted:   { color: chalk.green,  label: 'REFUTED',   blurb: 'a mitigating control was found' },
};

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export async function investigateCommand(targetPath = '.', options = {}) {
  const rootPath = path.resolve(targetPath);

  if (!fs.existsSync(rootPath)) {
    output.error(`Path does not exist: ${rootPath}`);
    process.exit(1);
  }

  const quiet = Boolean(options.json);
  const orchestrator = await buildOrchestratorAsync(rootPath, { quiet: true });

  const spinner = quiet ? null : ora({ text: 'Scanning and investigating...', color: 'cyan' }).start();
  let findings = [];

  try {
    const results = await orchestrator.runAll(rootPath, {
      quiet: true,
      includeTests: Boolean(options.includeTests),
      deep: Boolean(options.deep),
      local: options.local,
      model: options.model,
      provider: options.provider,
      budget: options.budget,
    });
    findings = results.findings;
  } catch (error) {
    if (spinner) spinner.fail(chalk.red(`Investigation failed: ${error.message}`));
    else output.error(error.message);
    process.exit(1);
  }

  // Environment-scope findings describe the operator's machine. They are useful
  // locally but they are not findings about this repository, and an evidence
  // report about a repository should not be padded with them.
  const subjects = findings.filter((f) => f.scope !== 'environment');
  const grouped = groupByVerdict(subjects);

  if (spinner) {
    const counts = VERDICT_ORDER.map((v) => `${grouped[v].length} ${v}`).join(', ');
    spinner.succeed(chalk.green(
      `Investigated ${subjects.length} finding(s) across ${VERDICT_ORDER.reduce((n, v) => n + grouped[v].length, 0)} location(s): ${counts}`
    ));
  }

  if (options.json) {
    console.log(JSON.stringify({
      root: rootPath,
      // Locations are what a reader acts on; findings are what the rules
      // produced. Both are reported because they differ, often by a lot.
      findingCount: subjects.length,
      locationCounts: Object.fromEntries(VERDICT_ORDER.map((v) => [v, grouped[v].length])),
      findings: subjects.map((finding) => ({
        file: path.relative(rootPath, finding.file),
        line: finding.line,
        rule: finding.rule,
        title: finding.title,
        severity: finding.severity,
        verdict: finding.evidence?.verdict || 'unknown',
        evidence: summarizeEvidence(finding, rootPath),
      })),
    }, null, 2));
    process.exitCode = grouped.confirmed.length ? 1 : 0;
    return;
  }

  render(grouped, rootPath, options);
  process.exitCode = grouped.confirmed.length ? 1 : 0;
}

/**
 * Collapse findings that describe the same line.
 *
 * Three rules firing on one `eval(req.body.x)` is three findings and one
 * vulnerability. A score can absorb that; an evidence report cannot, because
 * "15 confirmed" when five lines are at fault is a claim about the world that
 * is wrong. Locations are the unit a reader acts on, so they are the unit
 * counted here — with the rules that fired listed underneath.
 */
export function groupByLocation(findings) {
  const locations = new Map();

  for (const finding of findings) {
    const key = `${finding.file}:${finding.line}`;
    if (!locations.has(key)) locations.set(key, { primary: finding, rules: [], findings: [] });
    const group = locations.get(key);
    group.findings.push(finding);
    if (!group.rules.includes(finding.rule)) group.rules.push(finding.rule);

    // Keep the most severe finding as the one whose title and fix are shown.
    if ((SEVERITY_RANK[finding.severity] ?? 9) < (SEVERITY_RANK[group.primary.severity] ?? 9)) {
      group.primary = finding;
    }
  }

  return [...locations.values()]
    .sort((a, b) => (SEVERITY_RANK[a.primary.severity] ?? 9) - (SEVERITY_RANK[b.primary.severity] ?? 9));
}

export function groupByVerdict(findings) {
  const grouped = Object.fromEntries(VERDICT_ORDER.map((v) => [v, []]));

  for (const finding of findings) {
    const verdict = finding.evidence?.verdict || 'unknown';
    (grouped[verdict] || grouped.unknown).push(finding);
  }

  return Object.fromEntries(VERDICT_ORDER.map((v) => [v, groupByLocation(grouped[v])]));
}

function render(grouped, rootPath, options) {
  output.header('Investigation');

  const total = VERDICT_ORDER.reduce((n, v) => n + grouped[v].length, 0);
  if (total === 0) {
    output.success('Nothing to investigate — the scanners found no findings.');
    return;
  }

  // Unresolved and refuted are reported but not detailed by default. A refuted
  // finding is still shown as a count rather than hidden: this pass downgrades
  // findings, it does not delete them, and a reader deserves to know how many
  // were argued away and by what.
  const detailed = options.all ? VERDICT_ORDER : ['confirmed', 'likely'];

  for (const verdict of VERDICT_ORDER) {
    const bucket = grouped[verdict];
    if (!bucket.length) continue;

    const style = VERDICT_STYLE[verdict];
    console.log(`\n${style.color.bold(`  ${style.label}`)} ${chalk.dim(`— ${style.blurb} (${bucket.length})`)}\n`);

    if (!detailed.includes(verdict)) {
      console.log(chalk.dim(`    ${bucket.length} finding(s). Re-run with --all to see them.\n`));
      continue;
    }

    for (const location of bucket) renderLocation(location, rootPath);
  }

  console.log('');
  if (grouped.confirmed.length) {
    output.error(`${grouped.confirmed.length} confirmed location(s) — do not ship.`);
  } else if (grouped.likely.length) {
    output.warning(`${grouped.likely.length} likely location(s) — review before shipping.`);
  } else {
    output.success('Nothing confirmed or likely.');
  }

  if (grouped.unknown.length && !options.all) {
    console.log(chalk.dim(`  ${grouped.unknown.length} location(s) could not be resolved either way.`));
  }
  console.log('');
}

function renderLocation(location, rootPath) {
  const finding = location.primary;
  const relative = path.relative(rootPath, finding.file) || finding.file;
  const alsoCount = location.rules.length - 1;

  console.log(`    ${chalk.bold(finding.title)} ${chalk.dim(`[${finding.severity}]`)}`);
  console.log(chalk.dim(
    `    ${relative}:${finding.line}  ${location.rules[0]}${alsoCount > 0 ? ` (+${alsoCount} more rule${alsoCount > 1 ? 's' : ''}: ${location.rules.slice(1).join(', ')})` : ''}`
  ));

  const claim = decidingClaim(finding);
  if (claim) {
    console.log(`    ${chalk.dim('why:')} ${claim.rationale || '(no rationale recorded)'}`);
    console.log(chalk.dim(`    decided by: ${claim.source}`));

    if (claim.attackPath.length > 1) {
      claim.attackPath.forEach((step, index) => {
        const citation = claim.citations[index];
        const where = citation ? chalk.dim(`  ${path.relative(rootPath, citation.file)}:${citation.line}`) : '';
        console.log(`      ${chalk.dim(`${index + 1}.`)} ${step}${where}`);
      });
    }

    if (finding.evidence.conflict) {
      console.log(chalk.yellow('    passes disagreed at equal standing — treat as unresolved'));
    }
  }

  if (finding.fix) console.log(`    ${chalk.dim('fix:')} ${finding.fix}`);
  console.log('');
}
