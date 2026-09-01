/**
 * Fix verification — did the path close, not just the pattern
 * ============================================================
 *
 * A fix used to be judged by whether the rule stopped firing. That is the
 * weakest available claim and it rewards the wrong edit: renaming a variable,
 * splitting a template, or moving a call to the next line all silence a
 * detector without changing what an attacker can do. It also misses the
 * opposite case, where the right fix leaves the pattern in place — adding
 * validation upstream does not remove the `db.raw(...)` the rule matched, so a
 * genuinely fixed finding looks unfixed.
 *
 * With evidence attached to findings both readings become available, and they
 * disagree often enough to be worth separating:
 *
 *   resolved     the detector no longer fires. The code that matched is gone.
 *   neutralised  it still fires, and the investigation now refutes it. The
 *                pattern remains and the path is closed — usually the better
 *                fix, and the one the old check called a failure.
 *   weakened     it still fires and nothing is established any more. Something
 *                changed; whether it was the right thing is not known.
 *   unchanged    it still fires and the evidence still stands.
 *   introduced   a confirmed finding that was not there before.
 *
 * The last one exists because a fix is an edit like any other, and the only
 * thing worse than an unfixed finding is a new one nobody looked for.
 */

const ESTABLISHED = new Set(['confirmed', 'likely']);

/** How far a finding may move before it is considered a different finding. */
const LINE_DRIFT = 3;

const verdictOf = (finding) => finding?.evidence?.verdict || 'unknown';

function sameFinding(a, b) {
  return a.rule === b.rule
    && a.file === b.file
    && Math.abs((a.line ?? 0) - (b.line ?? 0)) <= LINE_DRIFT;
}

/**
 * Compare the findings for a fix's target before and after applying it.
 *
 * @param {object[]} before — findings as investigated before the edit
 * @param {object[]} after  — findings as investigated after it
 * @returns {{outcomes: object[], introduced: object[], summary: object}}
 */
export function classifyFixOutcome(before = [], after = []) {
  const matched = new Set();

  const outcomes = before.map((original) => {
    const survivor = after.find((candidate) => !matched.has(candidate) && sameFinding(original, candidate));
    if (survivor) matched.add(survivor);

    return {
      rule: original.rule,
      file: original.file,
      line: original.line,
      before: verdictOf(original),
      after: survivor ? verdictOf(survivor) : null,
      outcome: outcomeFor(verdictOf(original), survivor ? verdictOf(survivor) : null),
      // The reason the survivor is now refuted is the proof the fix worked, so
      // it travels with the outcome rather than being summarised away.
      evidence: survivor?.evidence?.claims?.at(-1)?.rationale || null,
    };
  });

  // A finding the edit created. Only confirmed ones are reported: an edit that
  // makes a scanner newly uncertain about something is not a regression worth
  // stopping a person for.
  const introduced = after
    .filter((candidate) => !matched.has(candidate) && verdictOf(candidate) === 'confirmed')
    .map((candidate) => ({
      rule: candidate.rule,
      file: candidate.file,
      line: candidate.line,
      evidence: candidate.evidence?.claims?.at(-1)?.rationale || null,
    }));

  return { outcomes, introduced, summary: summarize(outcomes, introduced) };
}

function outcomeFor(before, after) {
  if (after === null) return 'resolved';
  if (after === 'refuted') return before === 'refuted' ? 'unchanged' : 'neutralised';

  // Nothing was established before, so nothing can be said to have closed.
  if (!ESTABLISHED.has(before)) return 'unchanged';

  if (!ESTABLISHED.has(after)) return 'weakened';
  return 'unchanged';
}

function summarize(outcomes, introduced) {
  const counts = { resolved: 0, neutralised: 0, weakened: 0, unchanged: 0 };
  for (const outcome of outcomes) counts[outcome.outcome] += 1;

  return {
    ...counts,
    introduced: introduced.length,
    // What a person actually wants to know: is every finding this fix targeted
    // either gone or demonstrably closed, and did it cost anything.
    verified: counts.resolved + counts.neutralised === outcomes.length && introduced.length === 0,
    total: outcomes.length,
  };
}

/** One line a person can read without unpacking the object. */
export function describeFixOutcome({ summary }) {
  if (!summary.total) return 'Nothing to verify.';

  const parts = [];
  if (summary.resolved) parts.push(`${summary.resolved} no longer detected`);
  if (summary.neutralised) parts.push(`${summary.neutralised} still detected but now refuted`);
  if (summary.weakened) parts.push(`${summary.weakened} weakened without proof`);
  if (summary.unchanged) parts.push(`${summary.unchanged} unchanged`);

  const tail = summary.introduced ? `, and ${summary.introduced} new confirmed finding(s)` : '';
  return `${parts.join(', ')}${tail}.`;
}
