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
 *   resolved     no matching detector result remains; closure is not established.
 *   neutralised  it still fires, and the investigation now refutes it. The
 *                pattern remains and static analysis refutes the path, not a replay.
 *   weakened     it still fires and nothing is established any more. Something
 *                changed; whether it was the right thing is not known.
 *   unchanged    it still fires and the evidence still stands.
 *   introduced   a confirmed or likely finding absent from the baseline.
 *
 * Disappearance is not proof of remediation. This comparator never executes
 * an independent security retest, so it cannot set summary.verified to true.
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
 * @param {{baseline?: object[]}} options full pre-edit scan, for regression scope
 * @returns {{schemaVersion: number, outcomes: object[], introduced: object[], summary: object}}
 */
export function classifyFixOutcome(before = [], after = [], { baseline = before } = {}) {
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
      // Preserve the static rationale without treating it as independent proof.
      evidence: survivor?.evidence?.claims?.at(-1)?.rationale || null,
    };
  });

  // Compare against the complete baseline, not just the target file. Preserve
  // one-to-one matching so existing debt does not hide a newly added duplicate.
  const baselineMatches = new Set();
  const baselineGroups = new Map();
  for (const item of baseline) {
    const key = JSON.stringify([item.file, item.rule]);
    const group = baselineGroups.get(key) ?? [];
    group.push(item);
    baselineGroups.set(key, group);
  }
  const introduced = after
    .filter((candidate) => {
      const group = baselineGroups.get(JSON.stringify([candidate.file, candidate.rule])) ?? [];
      const existing = group.find(item => !baselineMatches.has(item) && sameFinding(item, candidate));
      if (existing) baselineMatches.add(existing);
      return !existing && ESTABLISHED.has(verdictOf(candidate));
    })
    .map((candidate) => ({
      rule: candidate.rule,
      file: candidate.file,
      line: candidate.line,
      verdict: verdictOf(candidate),
      evidence: candidate.evidence?.claims?.at(-1)?.rationale || null,
    }));

  return { schemaVersion: 2, outcomes, introduced, summary: summarize(outcomes, introduced) };
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

  const staticallyRefuted = outcomes.length > 0
    && counts.neutralised === outcomes.length && introduced.length === 0;
  return {
    ...counts,
    introduced: introduced.length,
    status: introduced.length ? 'regression_detected'
      : !outcomes.length ? 'not_applicable'
      : staticallyRefuted ? 'statically_refuted' : 'inconclusive',
    staticallyRefuted,
    // Retained for JSON consumers, but v2 reserves this for independent retests.
    // A static comparison cannot establish that guarantee.
    verified: false,
    total: outcomes.length,
  };
}

/** One line a person can read without unpacking the object. */
export function describeFixOutcome({ summary }) {
  if (!summary.total && !summary.introduced) return 'Nothing to verify. No independent retest performed.';

  const parts = [];
  if (summary.resolved) parts.push(`${summary.resolved} no longer detected`);
  if (summary.neutralised) parts.push(`${summary.neutralised} still detected but now refuted by static analysis`);
  if (summary.weakened) parts.push(`${summary.weakened} weakened without proof`);
  if (summary.unchanged) parts.push(`${summary.unchanged} unchanged`);
  if (!summary.total) parts.push('No original target findings');

  const tail = summary.introduced ? `, and ${summary.introduced} new confirmed or likely finding(s)` : '';
  return `${parts.join(', ')}${tail}. No independent retest performed.`;
}
