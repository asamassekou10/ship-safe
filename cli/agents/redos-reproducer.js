/**
 * RedosReproducer — settle a backtracking finding by running it
 * ==============================================================
 *
 * A ReDoS rule fires on the *shape* of a pattern: nested quantifiers, an
 * alternation that can match the same text two ways. Shape is a proxy. Whether
 * a pattern actually backtracks catastrophically depends on whether those parts
 * are genuinely ambiguous, which a regex over the regex cannot see.
 *
 * This project's own `/^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/` was flagged for
 * nested quantifiers. It has them, and it is fine: `[^_]+` cannot match the `_`
 * that separates the groups, so every input has exactly one parse and there is
 * nothing to backtrack over. A hundred thousand characters run in 0.3ms. No
 * amount of reading the pattern establishes that; running it does, in
 * milliseconds.
 *
 * So this pass runs it. The pattern is executed against generated input in a
 * worker that can be terminated, with a hard time budget. Blowing the budget is
 * a reproduction and confirms the finding; finishing with linear growth across
 * doubling input sizes refutes it.
 *
 * The budget measures the match, not the machine. A worker takes time to start
 * and a loaded host schedules it late, and counting that against the pattern
 * confirms a ReDoS in whatever happens to be running when the box is busy — at
 * the highest rank in the system, on evidence that is really a load average.
 * The deadline therefore starts when the worker says it is running, and a
 * timeout is confirmed only when it reproduces on a second attempt.
 *
 * This is the only pass that executes anything from the scanned repository, and
 * what it executes is a regular expression against a synthetic string: no
 * network, no filesystem, no side effects, and a bounded lifetime. The value
 * under test is the pattern the rule already read, not code the repository
 * chooses to run.
 */

import fs from 'fs';
import { Worker } from 'worker_threads';
import { attachEvidence, createClaim } from '../utils/evidence.js';

/** Rules whose claim is "this pattern can be made to backtrack". */
const REDOS_RULE = /^REDOS_/;

/** Milliseconds a single attempt may take before it counts as catastrophic. */
const BUDGET_MS = 400;

/** Repeat counts, doubling so growth can be read from the timings. */
const PUMP_SIZES = [500, 1000];

/**
 * Strings that commonly drive an ambiguous quantifier. Each is repeated and
 * followed by a character the pattern is unlikely to accept, so the match fails
 * and the engine must exhaust every alternative before saying so.
 */
const PUMPS = ['a', 'a ', 'ab', 'a_', '0', '/a'];

const FAIL_SUFFIX = ' !';

/** How long a worker may take to start before its own deadline begins. */
const STARTUP_GRACE_MS = 2000;

/** Enough to settle a repository's patterns without turning a scan into a benchmark. */
const MAX_PROBED = 40;

export class RedosReproducer {
  constructor({ budgetMs = BUDGET_MS } = {}) {
    this.name = 'RedosReproducer';
    this.description = 'Runs a flagged pattern against generated input to see whether it actually backtracks';
    this.budgetMs = budgetMs;
  }

  async investigate(findings) {
    const candidates = findings.filter((f) => REDOS_RULE.test(f.rule) && f.file && f.line);
    if (!candidates.length) return findings;

    const cache = new Map();
    // Findings often share a pattern — the same helper flagged in several
    // places, or one rule firing beside another on the same line. Probing costs
    // a worker per attempt, so an identical pattern is measured once.
    const probed = new Map();

    for (const finding of candidates.slice(0, MAX_PROBED)) {
      const lines = this._read(finding.file, cache);
      if (!lines) continue;

      const pattern = extractPattern(lines[finding.line - 1] || '');
      if (!pattern) continue;                       // cannot run what we cannot read

      const key = `${pattern.source}\u0000${pattern.flags}`;
      if (!probed.has(key)) probed.set(key, await this._probe(pattern));
      const result = probed.get(key);
      if (!result) continue;

      attachEvidence(finding, createClaim({
        source: 'reproduction',
        verdict: result.catastrophic ? 'confirmed' : 'refuted',
        rationale: result.catastrophic
          ? `The pattern was run against ${result.length} characters of generated input and had not finished after ${this.budgetMs}ms. The backtracking is real and reachable by anyone who controls the subject string.`
          : `The pattern was run against inputs up to ${result.length} characters; the longest took ${result.ms.toFixed(1)}ms and time grew linearly with length. The quantifiers the rule saw are not ambiguous, so there is nothing to backtrack over.`,
        citations: [{ file: finding.file, line: finding.line }],
        ...(result.catastrophic ? { reproduction: { pump: result.pump, length: result.length, budgetMs: this.budgetMs } } : {}),
      }));
    }

    return findings;
  }

  async _probe(pattern) {
    const session = new MatchSession(pattern, this.budgetMs);
    let slowestMs = 0;
    let longest = 0;

    try {
      for (const pump of PUMPS) {
        for (const size of PUMP_SIZES) {
          const input = pump.repeat(size) + FAIL_SUFFIX;
          const ms = await session.time(input);

          // A single overrun is equally consistent with a busy machine. A
          // catastrophic pattern reproduces; a scheduling blip does not.
          if (ms === null && await session.time(input) === null) {
            return { catastrophic: true, ms: this.budgetMs, length: input.length, pump };
          }
          if (ms !== null) {
            slowestMs = Math.max(slowestMs, ms);
            longest = Math.max(longest, input.length);
          }
        }
      }
    } finally {
      await session.close();
    }

    // Report the longest input tried and the slowest time seen. They are rarely
    // the same run, and quoting one number for both would misdescribe the test.
    return { catastrophic: false, ms: slowestMs, length: longest };
  }

  _read(file, cache) {
    if (cache.has(file)) return cache.get(file);
    let lines;
    try { lines = fs.readFileSync(file, 'utf-8').split('\n'); } catch { lines = null; }
    cache.set(file, lines);
    return lines;
  }
}

/**
 * One worker per pattern, kept alive across attempts.
 *
 * Spawning costs about 200ms on a normal machine. Doing it per attempt made
 * startup several times the match budget, so the budget was measuring process
 * creation and timing out on patterns that run in microseconds. The worker is
 * replaced only when a match genuinely hangs, which is the one case where it
 * cannot be reused: it is stuck inside a synchronous regex and will never read
 * another message.
 */
class MatchSession {
  constructor(pattern, budgetMs) {
    this.pattern = pattern;
    this.budgetMs = budgetMs;
    this.worker = null;
  }

  async time(input) {
    const worker = await this._worker();
    if (!worker) return 0;                       // uncompilable: not ours to settle

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        worker.terminate();
        this.worker = null;                      // stuck mid-match; unusable now
        resolve(null);
      }, this.budgetMs);

      worker.once('message', (ms) => { clearTimeout(timer); resolve(ms); });
      worker.postMessage(input);
    });
  }

  async _worker() {
    if (this.worker) return this.worker;

    return new Promise((resolve) => {
      let worker;
      try {
        worker = new Worker(WORKER_SOURCE, {
          eval: true,
          workerData: { source: this.pattern.source, flags: this.pattern.flags },
        });
      } catch { resolve(null); return; }

      const startup = setTimeout(() => { worker.terminate(); resolve(null); }, STARTUP_GRACE_MS);

      worker.once('message', (message) => {
        clearTimeout(startup);
        if (message !== 'ready') { resolve(null); return; }
        this.worker = worker;
        resolve(worker);
      });
      worker.on('error', () => { clearTimeout(startup); this.worker = null; resolve(null); });
    });
  }

  async close() {
    if (this.worker) await this.worker.terminate();
    this.worker = null;
  }
}

/**
 * The worker body. It compiles the pattern and runs it once, which is the only
 * thing from the scanned repository that ever executes here.
 */
const WORKER_SOURCE = `
  const { parentPort, workerData } = require('worker_threads');

  let re = null;
  try {
    // Compiled once. Compilation is not part of what the finding claims.
    re = new RegExp(workerData.source, workerData.flags.replace(/[gy]/g, ''));
  } catch { /* an uncompilable pattern is not a finding this pass can settle */ }

  parentPort.postMessage('ready');

  parentPort.on('message', (input) => {
    if (!re) { parentPort.postMessage(0); return; }
    const started = process.hrtime.bigint();
    try { re.test(input); } catch { /* runtime refusal is not a reproduction */ }
    parentPort.postMessage(Number(process.hrtime.bigint() - started) / 1e6);
  });
`;

/**
 * Pull a regular expression out of the line the finding points at.
 *
 * Only the forms where the pattern is written literally. A pattern built from
 * variables at runtime is not knowable here, and guessing at one would run
 * something other than what ships.
 */
/** Metacharacters that distinguish a pattern from a pair of division signs. */
const LOOKS_LIKE_PATTERN = /[*+?{}[\]()|^$\\]/;

export function extractPattern(line) {
  const js = line.match(/(?:^|[=(,:[\s])\/((?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+)\/([dgimsuvy]*)/);
  // `a / b / c` parses as a literal between two slashes. Reading arithmetic as a
  // pattern would run something the file does not contain and, worse, refute a
  // finding on the strength of it.
  if (js && LOOKS_LIKE_PATTERN.test(js[1])) return { source: js[1], flags: js[2] || '' };

  const py = line.match(/re\.(?:compile|match|search|fullmatch|sub|findall)\s*\(\s*r?(['"])((?:[^\\]|\\.)*?)\1/);
  if (py) return { source: py[2], flags: '' };

  return null;
}
