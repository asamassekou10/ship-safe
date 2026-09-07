/**
 * Trust Command
 * =============
 *
 * Answers one question: is it safe to point an agent at this folder?
 *
 * A folder that arrives whole — a zip, a shared drive, a take-home, a synced
 * directory — can carry configuration that executes when an agent gathers
 * context, before any trust dialog appears. `.git/config` decides what git
 * runs when it refreshes the index. `.vscode/tasks.json` can run a task on
 * folder open. A devcontainer can run a command on the host before the
 * container exists. Repository-scoped agent hook config runs on a lifecycle
 * event nobody approved.
 *
 * This is deliberately a pre-flight check and not a scan. It reads
 * configuration, never source. It writes nothing. It makes no network request.
 * The whole point is that it is safe to run on a directory you do not trust
 * yet, which means it must not do any of the things a scan does.
 *
 * USAGE:
 *   ship-safe trust [path]
 *   ship-safe trust ~/Downloads/take-home --json
 *
 * EXIT CODES:
 *   0 — no execution sinks found
 *   1 — sinks found
 *   2 — the path could not be read
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { WorkspaceTrustAgent } from '../agents/workspace-trust-agent.js';
import { loadAdvisoryTable, resolveReachability, tableAgeDays } from '../utils/agent-advisories.js';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEVERITY_COLOR = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

export async function trustCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  const json = Boolean(options.json);

  let stat;
  try {
    stat = fs.statSync(absolutePath);
  } catch {
    return fail(json, `Path not found: ${absolutePath}`, absolutePath);
  }

  if (!stat.isDirectory()) {
    return fail(json, `Not a directory: ${absolutePath}`, absolutePath);
  }

  let findings;
  try {
    findings = await new WorkspaceTrustAgent().analyze({
      rootPath: absolutePath,
      files: [],
      recon: {},
      options: {},
    });
  } catch (error) {
    return fail(json, `Could not inspect the folder: ${error.message}`, absolutePath);
  }

  findings.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      String(a.rule).localeCompare(String(b.rule))
  );

  // Reachability is resolved once per rule, not once per finding: the question
  // "is an affected agent installed" has the same answer for every finding of
  // the same rule, and asking a binary for its version repeatedly would be
  // both slower and no more informative.
  const table = loadAdvisoryTable();
  const reachability = new Map();
  for (const finding of findings) {
    if (reachability.has(finding.rule)) continue;
    reachability.set(finding.rule, resolveReachability(finding.rule, { table, excludeRoot: absolutePath }));
  }

  if (json) {
    process.stdout.write(`${JSON.stringify(buildReport(absolutePath, findings, table, reachability), null, 2)}\n`);
  } else {
    renderHuman(absolutePath, findings, table, reachability);
  }

  process.exitCode = findings.length > 0 ? 1 : 0;
  return findings;
}

// =============================================================================
// OUTPUT
// =============================================================================

/**
 * The machine-readable report.
 *
 * `checked` names what was actually inspected rather than leaving the reader
 * to infer it from an empty findings array. "We looked at these five things
 * and found nothing" and "we did not look" are different results, and a clean
 * run has to be able to say which one it is.
 */
function buildReport(rootPath, findings, table, reachability) {
  const counts = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }

  const age = tableAgeDays(table);

  return {
    version: 1,
    command: 'trust',
    path: rootPath,
    generatedAt: new Date().toISOString(),
    // The table lags disclosure. A reader who cannot see how old it is cannot
    // discount it, so its version and age travel with every report.
    advisoryTable: {
      version: table.tableVersion,
      recordedAt: table.recordedAt,
      ageDays: age,
      entries: (table.entries ?? []).length,
    },
    checked: [
      '.git/config',
      '.git/hooks/',
      '.vscode/tasks.json',
      '.devcontainer/',
      '.envrc',
      'repository-scoped agent hook config',
    ],
    summary: {
      total: findings.length,
      bySeverity: counts,
      verdict: findings.length === 0 ? 'no-sinks-found' : 'sinks-found',
    },
    findings: findings.map((f) => ({
      rule: f.rule,
      severity: f.severity,
      confidence: f.confidence,
      title: f.title,
      description: f.description,
      file: path.relative(rootPath, f.file) || path.basename(f.file),
      line: f.line,
      matched: f.matched,
      cwe: f.cwe,
      owasp: f.owasp,
      fix: f.fix,
      evidenceLevel: f.evidenceLevel,
      reachability: reachability.get(f.rule)?.state ?? 'configured',
      reachabilityReason: reachability.get(f.rule)?.reason ?? null,
      installedAgents: reachability.get(f.rule)?.installed ?? [],
    })),
  };
}

function renderHuman(rootPath, findings, table, reachability) {
  const out = process.stdout;

  out.write(`\n${chalk.bold('Workspace trust')} ${chalk.gray(rootPath)}\n\n`);

  if (findings.length === 0) {
    out.write(`${chalk.green('✓')} No execution sinks found.\n\n`);
    out.write(
      `${chalk.gray('  Checked: .git/config, .git/hooks, .vscode/tasks.json, .devcontainer, .envrc,')}\n` +
        `${chalk.gray('  and repository-scoped agent hook config.')}\n\n`
    );
    // Saying what was not checked is the difference between a useful pre-flight
    // and false assurance. This command reads configuration; it has not looked
    // at a single line of source.
    out.write(
      `${chalk.gray('  This checks configuration that runs on open. It does not scan source code —')}\n` +
        `${chalk.gray('  run `ship-safe scan` for that.')}\n\n`
    );
    out.write(`${chalk.gray(`  ${tableFooter(table)}`)}\n\n`);
    return;
  }

  for (const finding of findings) {
    const color = SEVERITY_COLOR[finding.severity] ?? chalk.white;
    const where = path.relative(rootPath, finding.file) || path.basename(finding.file);

    const reach = reachability.get(finding.rule);

    out.write(`${color(`[${finding.severity.toUpperCase()}]`)} ${chalk.bold(finding.title)}\n`);
    out.write(`  ${chalk.gray(`${where}:${finding.line}`)}  ${chalk.gray(finding.rule)}`);
    if (reach) out.write(`  ${reachLabel(reach.state)}`);
    out.write('\n\n');
    out.write(`  ${wrap(finding.description)}\n\n`);
    if (reach) out.write(`  ${chalk.gray(wrap(reach.reason))}\n\n`);
    if (finding.matched) out.write(`  ${chalk.bold('Found:')} ${finding.matched}\n\n`);
    if (finding.fix) out.write(`  ${chalk.bold('Fix:')} ${wrap(finding.fix, 8)}\n\n`);
  }

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const summary = `${findings.length} execution ${findings.length === 1 ? 'sink' : 'sinks'} found`;

  out.write(`${chalk.bold(critical > 0 ? chalk.red(summary) : summary)}\n`);
  out.write(
    `${chalk.gray('Do not open this folder with a coding agent or editor until these are resolved.')}\n`
  );
  out.write(`${chalk.gray(tableFooter(table))}\n\n`);
}

/** A short badge for a reachability state. */
function reachLabel(state) {
  if (state === 'reachable') return chalk.red('reachable');
  if (state === 'unresolved') return chalk.yellow('unresolved');
  return chalk.gray('configured');
}

/**
 * How stale the advisory table is.
 *
 * Printed on every run with findings. A reachability verdict is only as good
 * as the table behind it, and the reader is the one who has to decide whether
 * a table this old still means anything.
 */
function tableFooter(table) {
  const age = tableAgeDays(table);
  if (table.tableVersion === 'unavailable') {
    return 'Advisory table unavailable, so reachability was not assessed.';
  }
  const staleness = age === null ? '' : age === 0 ? ', recorded today' : `, ${age} day${age === 1 ? '' : 's'} old`;
  return `Advisory table ${table.tableVersion}${staleness}. It lags disclosure; an agent absent from it is undocumented, not safe.`;
}

/** Wrap prose to a readable width, indenting continuation lines. */
function wrap(text, indent = 2) {
  const width = 76 - indent;
  const pad = ' '.repeat(indent);
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';

  for (const word of words) {
    if (line.length + word.length + 1 > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);

  return lines.join(`\n${pad}`);
}

function fail(json, message, rootPath) {
  if (json) {
    process.stdout.write(
      `${JSON.stringify({ version: 1, command: 'trust', path: rootPath, error: message }, null, 2)}\n`
    );
  } else {
    process.stderr.write(`${chalk.red('Error:')} ${message}\n`);
  }
  process.exitCode = 2;
  return null;
}

export default trustCommand;
