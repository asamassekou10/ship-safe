/**
 * False-positive benchmark
 * ========================
 *
 * Recall is the easy half. A scanner that flags everything has perfect recall
 * and is useless, so this measures the other half: what does Ship Safe say
 * about code that is almost certainly fine?
 *
 * The clean corpus is four mature, heavily reviewed projects with no known
 * active vulnerabilities. Findings against them are the triage burden a user
 * inherits on a healthy codebase. The vulnerable corpus is two deliberately
 * insecure applications, present so a drop in noise cannot be mistaken for
 * progress when it is really lost detection.
 *
 * Everything is pinned by commit. An unpinned benchmark reports a different
 * number every week and cannot be argued with.
 *
 *   node benchmarks/false-positives/run.mjs            # uses ./corpus-src
 *   node benchmarks/false-positives/run.mjs --write    # refresh results/latest.json
 *   node benchmarks/false-positives/run.mjs --clone    # fetch the corpus first
 *
 * Honest limits, repeated in the README because they matter more than the
 * numbers: "no known active vulnerabilities" is not the same as "no
 * vulnerabilities". These counts are a proxy for a false-positive rate, not a
 * verified one. Verifying every finding by hand is the work that would turn
 * this into a rate.
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const corpus = JSON.parse(fs.readFileSync(path.join(here, 'corpus.json'), 'utf8'));
const srcDir = path.join(here, 'corpus-src');
const cli = path.join(repoRoot, 'cli', 'bin', 'ship-safe.js');

const write = process.argv.includes('--write');
const clone = process.argv.includes('--clone');

function cloneCorpus() {
  fs.mkdirSync(srcDir, { recursive: true });
  for (const entry of [...corpus.clean, ...corpus.vulnerable]) {
    const dest = path.join(srcDir, entry.id);
    if (fs.existsSync(dest)) continue;
    process.stderr.write(`cloning ${entry.repo}\n`);
    // Fetch the single pinned commit rather than a branch, so the corpus does
    // not drift when upstream moves.
    fs.mkdirSync(dest, { recursive: true });
    execFileSync('git', ['init', '-q'], { cwd: dest });
    execFileSync('git', ['remote', 'add', 'origin', `https://github.com/${entry.repo}.git`], { cwd: dest });
    execFileSync('git', ['fetch', '-q', '--depth', '1', 'origin', entry.commit], { cwd: dest });
    execFileSync('git', ['checkout', '-q', 'FETCH_HEAD'], { cwd: dest });
  }
}

/** Run `ship-safe ci` against one checkout and return its summary. */
function scan(dir) {
  const out = execFileSync(
    process.execPath,
    [cli, 'ci', dir, '--json', '--threshold', '0', '--no-deps'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, NO_COLOR: '1' } },
  );
  return JSON.parse(out);
}

/**
 * What the investigation layer concluded about the same checkout.
 *
 * Counting findings measures the sensor layer alone, and on a clean project the
 * number a user actually inherits is not how many rules fired but how many
 * survived investigation. A finding refuted with a citation costs a reader far
 * less than one left unresolved, and neither is visible in a total.
 *
 * `investigate` exits 1 when something is confirmed, which is not a failure of
 * the harness — on the deliberately vulnerable corpus it is the expected result.
 */
function investigate(dir) {
  try {
    const out = execFileSync(
      process.execPath,
      [cli, 'investigate', dir, '--json'],
      { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, NO_COLOR: '1' } },
    );
    return JSON.parse(out);
  } catch (error) {
    if (error.stdout) {
      try { return JSON.parse(error.stdout); } catch { /* fall through */ }
    }
    return null;
  }
}

if (clone) cloneCorpus();

const missing = [...corpus.clean, ...corpus.vulnerable]
  .filter((e) => !fs.existsSync(path.join(srcDir, e.id)))
  .map((e) => e.id);

if (missing.length > 0) {
  process.stderr.write(`missing corpus checkouts: ${missing.join(', ')}\nrun with --clone to fetch them\n`);
  process.exit(1);
}

const clean = corpus.clean.map((entry) => {
  const dir = path.join(srcDir, entry.id);
  const r = scan(dir);
  const i = investigate(dir);
  return {
    id: entry.id,
    repo: entry.repo,
    commit: entry.commit,
    findings: r.totalFindings,
    critical: r.critical,
    high: r.high,
    score: r.score,
    grade: r.grade,
    verdicts: i ? i.locationCounts : null,
  };
});

/**
 * Rules that must still fire on a deliberately vulnerable application.
 *
 * Counting findings measures noise, and a change that quietly stops detecting
 * something looks exactly like a change that reduced it. That is how a guard
 * added to cut false positives on XSS_DOCUMENT_WRITE took the true positives
 * with it, in every page with an inline script, while every number here moved
 * in the direction that reads as an improvement.
 *
 * A floor is not a recall measurement. It is a small set of things known to be
 * present, whose disappearance is always a regression and never a win.
 */
function checkFloor(entry, result) {
  const required = entry.mustDetect || [];
  if (!required.length) return { required: [], missing: [] };

  const found = new Set((result.findings || []).map((f) => f.rule));
  return { required, missing: required.filter((rule) => !found.has(rule)) };
}

const vulnerable = corpus.vulnerable.map((entry) => {
  const dir = path.join(srcDir, entry.id);
  const r = scan(dir);
  const i = investigate(dir);
  const floor = checkFloor(entry, r);
  return {
    id: entry.id,
    repo: entry.repo,
    commit: entry.commit,
    findings: r.totalFindings,
    critical: r.critical,
    high: r.high,
    verdicts: i ? i.locationCounts : null,
    mustDetect: floor.required,
    missingFromFloor: floor.missing,
  };
});

function sumVerdict(rows, verdict) {
  return rows.reduce((n, r) => n + (r.verdicts?.[verdict] || 0), 0);
}

const totalClean = clean.reduce((n, r) => n + r.findings, 0);
const criticalClean = clean.reduce((n, r) => n + r.critical, 0);

const result = {
  tool: 'ship-safe',
  version: JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version,
  methodology:
    'Findings reported by `ship-safe ci --no-deps` against pinned checkouts, plus what `ship-safe investigate` concluded about them. Clean corpus: mature projects with no known active vulnerabilities, where every finding is triage a user inherits. Vulnerable corpus: deliberately insecure applications, present so a reduction in noise cannot be mistaken for lost detection. Counts are a proxy for a false-positive rate, not a verified one.',
  clean,
  vulnerable,
  summary: {
    cleanProjects: clean.length,
    cleanFindings: totalClean,
    cleanCriticalFindings: criticalClean,
    vulnerableProjects: vulnerable.length,
    vulnerableFindings: vulnerable.reduce((n, r) => n + r.findings, 0),
    // The asymmetry is the point: confirmations should concentrate in the
    // deliberately vulnerable corpus, and refutations in the mature one.
    cleanConfirmed: sumVerdict(clean, 'confirmed'),
    cleanRefuted: sumVerdict(clean, 'refuted'),
    vulnerableConfirmed: sumVerdict(vulnerable, 'confirmed'),
  },
};

const outPath = path.join(here, 'results', 'latest.json');
if (write) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`);
  process.stderr.write(`wrote ${path.relative(repoRoot, outPath)}\n`);
}

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

// A missing floor rule is a detection regression. It is the only thing in this
// harness that fails the run: every other number here is descriptive, and this
// one is a fact about the corpus that stopped being true.
const breached = vulnerable.filter((entry) => entry.missingFromFloor.length > 0);
for (const entry of breached) {
  process.stderr.write(
    `detection floor: ${entry.id} no longer reports ${entry.missingFromFloor.join(', ')}\n`,
  );
}
if (breached.length > 0) process.exitCode = 1;
