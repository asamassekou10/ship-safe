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

if (clone) cloneCorpus();

const missing = [...corpus.clean, ...corpus.vulnerable]
  .filter((e) => !fs.existsSync(path.join(srcDir, e.id)))
  .map((e) => e.id);

if (missing.length > 0) {
  process.stderr.write(`missing corpus checkouts: ${missing.join(', ')}\nrun with --clone to fetch them\n`);
  process.exit(1);
}

const clean = corpus.clean.map((entry) => {
  const r = scan(path.join(srcDir, entry.id));
  return {
    id: entry.id,
    repo: entry.repo,
    commit: entry.commit,
    findings: r.totalFindings,
    critical: r.critical,
    high: r.high,
    score: r.score,
    grade: r.grade,
  };
});

const vulnerable = corpus.vulnerable.map((entry) => {
  const r = scan(path.join(srcDir, entry.id));
  return {
    id: entry.id,
    repo: entry.repo,
    commit: entry.commit,
    findings: r.totalFindings,
    critical: r.critical,
    high: r.high,
  };
});

const totalClean = clean.reduce((n, r) => n + r.findings, 0);
const criticalClean = clean.reduce((n, r) => n + r.critical, 0);

const result = {
  tool: 'ship-safe',
  version: JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version,
  methodology:
    'Findings reported by `ship-safe ci --no-deps` against pinned checkouts. Clean corpus: mature projects with no known active vulnerabilities, where every finding is triage a user inherits. Vulnerable corpus: deliberately insecure applications, present so a reduction in noise cannot be mistaken for lost detection. Counts are a proxy for a false-positive rate, not a verified one.',
  clean,
  vulnerable,
  summary: {
    cleanProjects: clean.length,
    cleanFindings: totalClean,
    cleanCriticalFindings: criticalClean,
    vulnerableProjects: vulnerable.length,
    vulnerableFindings: vulnerable.reduce((n, r) => n + r.findings, 0),
  },
};

const outPath = path.join(here, 'results', 'latest.json');
if (write) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`);
  process.stderr.write(`wrote ${path.relative(repoRoot, outPath)}\n`);
}

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
