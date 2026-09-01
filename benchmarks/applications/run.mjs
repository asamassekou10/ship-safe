/**
 * Application corpus — list confirmations for a person to read
 * =============================================================
 *
 * The other two benchmarks gate. This one does not, deliberately.
 *
 * A confirmation is the strongest thing this tool says: traced end to end,
 * ranked above everything a model or a heuristic concluded. There is no
 * automatic way to check one. Either someone opens the cited lines and agrees,
 * or the claim stands unexamined.
 *
 * So the output here is a list of confirmations with their paths and citations,
 * shaped for reading. The audit is the product; the exit code is always zero.
 *
 *   node benchmarks/applications/run.mjs --clone   fetch the pinned checkouts
 *   node benchmarks/applications/run.mjs           list confirmations
 *   node benchmarks/applications/run.mjs --json    the same, machine-readable
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

const asJson = process.argv.includes('--json');
const clone = process.argv.includes('--clone');

function cloneCorpus() {
  fs.mkdirSync(srcDir, { recursive: true });
  for (const entry of corpus.applications) {
    const dest = path.join(srcDir, entry.id);
    if (fs.existsSync(dest)) continue;
    process.stderr.write(`cloning ${entry.repo}\n`);
    // The single pinned commit, so the corpus does not drift when upstream moves.
    fs.mkdirSync(dest, { recursive: true });
    execFileSync('git', ['init', '-q'], { cwd: dest });
    execFileSync('git', ['remote', 'add', 'origin', `https://github.com/${entry.repo}.git`], { cwd: dest });
    execFileSync('git', ['fetch', '-q', '--depth', '1', 'origin', entry.commit], { cwd: dest });
    execFileSync('git', ['checkout', '-q', 'FETCH_HEAD'], { cwd: dest });
  }
}

/** `investigate` exits 1 when anything is confirmed, which is the normal case here. */
function investigate(dir) {
  try {
    return JSON.parse(execFileSync(process.execPath, [cli, 'investigate', dir, '--json'], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, NO_COLOR: '1' },
    }));
  } catch (error) {
    if (error.stdout) {
      try { return JSON.parse(error.stdout); } catch { /* fall through */ }
    }
    return null;
  }
}

if (clone) cloneCorpus();

const missing = corpus.applications
  .filter((e) => !fs.existsSync(path.join(srcDir, e.id)))
  .map((e) => e.id);

if (missing.length > 0) {
  process.stderr.write(`missing checkouts: ${missing.join(', ')}\nrun with --clone to fetch them\n`);
  process.exit(1);
}

const applications = corpus.applications.map((entry) => {
  const result = investigate(path.join(srcDir, entry.id));
  if (!result) return { ...entry, error: 'investigate produced no output' };

  const confirmed = result.findings
    .filter((f) => f.verdict === 'confirmed')
    .map((f) => ({
      rule: f.rule,
      file: f.file,
      line: f.line,
      severity: f.severity,
      why: f.evidence?.claims?.at(-1)?.rationale || null,
      decidedBy: f.evidence?.decidedBy || null,
      path: (f.evidence?.claims?.at(-1)?.attackPath || []).map((step, i) => {
        const citation = f.evidence.claims.at(-1).citations[i];
        return citation ? `${step} — ${citation.file}:${citation.line}` : step;
      }),
    }));

  return {
    id: entry.id, repo: entry.repo, commit: entry.commit, shape: entry.shape,
    counts: result.locationCounts,
    findings: result.findingCount,
    confirmed,
  };
});

const report = {
  schemaVersion: 1,
  corpusVersion: corpus.version,
  methodology: 'Confirmations from `ship-safe investigate` against pinned real applications. There is no gate: a confirmation can only be checked by reading the code it cites, so this lists them for that purpose.',
  applications,
};

if (asJson) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  for (const app of applications) {
    process.stdout.write(`\n${app.id}  (${app.shape})\n`);
    process.stdout.write(`  ${app.findings} findings  ${JSON.stringify(app.counts)}\n`);
    if (!app.confirmed?.length) {
      process.stdout.write('  no confirmations to audit\n');
      continue;
    }
    for (const c of app.confirmed) {
      process.stdout.write(`\n  CONFIRMED  ${c.rule}  [${c.severity}]\n`);
      process.stdout.write(`    ${c.file}:${c.line}   decided by ${c.decidedBy?.join(', ')}\n`);
      process.stdout.write(`    why: ${c.why}\n`);
      for (const step of c.path) process.stdout.write(`      - ${step}\n`);
    }
  }
  process.stdout.write('\nRead the cited lines. A confirmation nobody has checked is a claim, not a finding.\n');
}
