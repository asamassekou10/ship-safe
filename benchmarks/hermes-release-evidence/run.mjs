/**
 * Hermes 10.0 release evidence.
 *
 * This runner executes the public CLI and checks rendered JSON, SARIF, and
 * verdict-gate output, then validates every cited location in each evidence
 * chain.
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const cli = path.join(repoRoot, 'cli', 'bin', 'ship-safe.js');
const baseline = JSON.parse(fs.readFileSync(path.join(repoRoot, 'cli/data/hermes-baseline.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(here, 'scenarios.json'), 'utf8'));
const write = process.argv.includes('--write');
const asJson = process.argv.includes('--json');
const validBases = new Set(['configured', 'inferred', 'traced', 'reproduced']);

function fail(message) {
  throw new Error(message);
}

if (
  manifest.release !== baseline.release
  || manifest.tag !== baseline.tag
  || manifest.commit !== baseline.commit
) {
  fail('Hermes release-evidence manifest is not pinned to cli/data/hermes-baseline.json');
}

function runCli(command, args) {
  const result = spawnSync(process.execPath, [cli, command, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1' },
  });
  if (result.error) fail(command + ' failed to start: ' + result.error.message);
  return result;
}

function parseOutput(result, label) {
  if (!result.stdout) fail(label + ' produced no stdout');
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    fail(label + ' produced incomplete or invalid JSON: ' + error.message);
  }
}

function evidenceContainer(finding) {
  return finding.hermesBoundary
    || finding.hermesCronLifecycle
    || finding.hermesCredentialFlow
    || null;
}

function validateCitations(rootPath, finding, label) {
  const container = evidenceContainer(finding);
  if (!container?.evidence?.length) fail(label + ' has no structured evidence citations');
  if (!validBases.has(container.reachabilityBasis)) {
    fail(label + ' has no valid reachability basis');
  }

  for (const citation of container.evidence) {
    const absolute = path.isAbsolute(citation.file)
      ? citation.file
      : path.resolve(rootPath, citation.file);
    const relative = path.relative(rootPath, absolute);
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      fail(label + ' cites a file outside its fixture: ' + citation.file);
    }
    let lines;
    try {
      lines = fs.readFileSync(absolute, 'utf8').split('\n');
    } catch {
      fail(label + ' cites a missing file: ' + citation.file);
    }
    if (!Number.isInteger(citation.line) || citation.line < 1 || citation.line > lines.length) {
      fail(label + ' cites an invalid line: ' + citation.file + ':' + citation.line);
    }
  }

  return {
    basis: container.reachabilityBasis,
    citations: container.evidence.map((item) => ({
      file: path.relative(rootPath, path.isAbsolute(item.file) ? item.file : path.resolve(rootPath, item.file)).replace(/\\/g, '/'),
      line: item.line,
      role: item.role,
    })),
  };
}

function findSarifResult(report, rule) {
  return (report.runs || [])
    .flatMap((run) => run.results || [])
    .find((result) => result.ruleId === rule);
}

function inspectSide(scenario, side, expected) {
  const relativeFixture = scenario[side + 'Fixture'];
  const rootPath = path.resolve(repoRoot, relativeFixture);
  if (!fs.existsSync(rootPath)) fail(scenario.id + ' ' + side + ' fixture is missing: ' + relativeFixture);

  const auditJsonResult = runCli('audit', [
    rootPath, '--hermes-only', '--no-deps', '--no-ai', '--no-cache', '--json',
  ]);
  if (auditJsonResult.status !== 0) fail(scenario.id + ' ' + side + ' audit JSON exited ' + auditJsonResult.status);
  const auditJson = parseOutput(auditJsonResult, scenario.id + ' ' + side + ' audit JSON');
  const finding = (auditJson.findings || []).find((item) => item.rule === scenario.rule);
  if (Boolean(finding) !== expected) {
    fail(scenario.id + ' ' + side + ' expected target finding=' + expected + ', got ' + Boolean(finding));
  }

  const auditSarifResult = runCli('audit', [
    rootPath, '--hermes-only', '--no-deps', '--no-ai', '--no-cache', '--sarif',
  ]);
  if (auditSarifResult.status !== 0) fail(scenario.id + ' ' + side + ' audit SARIF exited ' + auditSarifResult.status);
  const auditSarif = parseOutput(auditSarifResult, scenario.id + ' ' + side + ' audit SARIF');
  const sarifFinding = findSarifResult(auditSarif, scenario.rule);
  if (Boolean(sarifFinding) !== expected) {
    fail(scenario.id + ' ' + side + ' SARIF expected target finding=' + expected + ', got ' + Boolean(sarifFinding));
  }

  const ciResult = runCli('ci', [
    rootPath, '--no-deps', '--fail-on-verdict', 'confirmed', '--json',
  ]);
  const ciJson = parseOutput(ciResult, scenario.id + ' ' + side + ' ci verdict gate');
  if (ciResult.status !== 0) {
    fail(scenario.id + ' ' + side + ' verdict gate blocked a static fixture with exit ' + ciResult.status);
  }

  if (!finding) {
    return {
      fixture: relativeFixture,
      targetFinding: false,
      auditJsonFindings: (auditJson.findings || []).length,
      auditSarifResults: ((auditSarif.runs || [])[0]?.results || []).length,
      ciStatus: ciResult.status,
      ciFindings: (ciJson.findings || []).length,
    };
  }

  const evidence = validateCitations(rootPath, finding, scenario.id + ' ' + side);
  if (evidence.basis !== scenario.reachabilityBasis) {
    fail(scenario.id + ' ' + side + ' basis ' + evidence.basis + ' != ' + scenario.reachabilityBasis);
  }
  if (sarifFinding?.properties?.reachabilityBasis !== scenario.reachabilityBasis) {
    fail(scenario.id + ' ' + side + ' SARIF did not preserve reachability basis');
  }

  return {
    fixture: relativeFixture,
    targetFinding: true,
    evidence,
    verdict: finding.evidence?.verdict || 'unknown',
    auditJsonFindings: (auditJson.findings || []).length,
    auditSarifResults: ((auditSarif.runs || [])[0]?.results || []).length,
    ciStatus: ciResult.status,
    ciFindings: (ciJson.findings || []).length,
  };
}

const scenarios = manifest.scenarios.map((scenario) => ({
  id: scenario.id,
  question: scenario.question,
  rule: scenario.rule,
  reachabilityBasis: scenario.reachabilityBasis,
  evidenceLabels: {
    configured: scenario.reachabilityBasis === 'configured',
    inferred: scenario.reachabilityBasis === 'inferred',
    traced: false,
    reproduced: false,
  },
  vulnerable: inspectSide(scenario, 'vulnerable', true),
  safe: inspectSide(scenario, 'safe', false),
  humanReview: scenario.humanReview,
}));

const report = {
  schemaVersion: 1,
  release: manifest.release,
  tag: manifest.tag,
  commit: manifest.commit,
  methodology: 'Four paired Hermes boundary fixtures. The runner checks actual CLI JSON, SARIF, and ci --fail-on-verdict confirmed output, then resolves every cited location. Static fixtures do not claim traced or reproduced runtime evidence.',
  scenarios,
  summary: {
    scenarios: scenarios.length,
    vulnerableTargetFindings: scenarios.filter((item) => item.vulnerable.targetFinding).length,
    safeTargetFindings: scenarios.filter((item) => item.safe.targetFinding).length,
    humanReviewed: scenarios.filter((item) => item.humanReview.reviewed).length,
    confirmationsSurvived: scenarios.filter((item) => item.humanReview.survives).length,
    traced: 0,
    reproduced: 0,
  },
};

if (write) {
  const destination = path.join(here, 'results', 'latest.json');
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, JSON.stringify(report, null, 2) + '\n');
  process.stderr.write('wrote ' + path.relative(repoRoot, destination) + '\n');
}

if (asJson) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  for (const scenario of scenarios) {
    process.stdout.write(
      scenario.id + ': vulnerable=' + scenario.vulnerable.targetFinding
      + ' safe=' + scenario.safe.targetFinding
      + ' basis=' + scenario.reachabilityBasis
      + ' human_review=' + scenario.humanReview.survives + '\n',
    );
  }
  process.stdout.write(
    'Hermes ' + manifest.release + ' release evidence passed: '
    + report.summary.confirmationsSurvived + '/' + report.summary.scenarios
    + ' fixture confirmations survived review; traced=0 reproduced=0\n',
  );
}
