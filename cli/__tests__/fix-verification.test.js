/**
 * Judging a fix on evidence rather than on whether the rule stopped firing.
 *
 * The two readings disagree in both directions, and both disagreements matter:
 * renaming a variable silences a detector and changes nothing an attacker can
 * do, while adding validation upstream leaves the matched line exactly where it
 * was and closes the path.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { classifyFixOutcome, describeFixOutcome } from '../utils/fix-verification.js';
import { createFinding } from '../agents/base-agent.js';
import { attachEvidence, createClaim } from '../utils/evidence.js';

const finding = (verdict, overrides = {}) => {
  const f = createFinding({
    file: '/repo/src/app.js', line: 10, rule: 'SQL_INJECTION_TEMPLATE_LITERAL',
    title: 'SQL injection', category: 'injection', severity: 'critical', ...overrides,
  });
  if (verdict) attachEvidence(f, createClaim({ source: 'dataflow', verdict, rationale: `${verdict} by trace` }));
  return f;
};

const only = (result) => result.outcomes[0];

describe('what counts as fixed', () => {
  it('calls a finding resolved when the detector stops firing', () => {
    const result = classifyFixOutcome([finding('confirmed')], []);
    assert.equal(only(result).outcome, 'resolved');
    assert.equal(result.summary.verified, true);
  });

  it('calls it neutralised when the pattern remains and the path is closed', () => {
    // Adding validation upstream does not remove the line the rule matched.
    // The old check called this a failure.
    const result = classifyFixOutcome([finding('confirmed')], [finding('refuted')]);

    assert.equal(only(result).outcome, 'neutralised');
    assert.equal(result.summary.verified, true, 'a closed path is a fix');
    assert.match(only(result).evidence, /refuted by trace/, 'the reason travels with the outcome');
  });

  it('does not call it fixed when the evidence still stands', () => {
    const result = classifyFixOutcome([finding('confirmed')], [finding('confirmed')]);
    assert.equal(only(result).outcome, 'unchanged');
    assert.equal(result.summary.verified, false);
  });

  it('separates a weakened finding from a closed one', () => {
    // The detector still fires and nothing is established any more. Something
    // changed; whether it was the right thing is not known.
    const result = classifyFixOutcome([finding('confirmed')], [finding(null)]);
    assert.equal(only(result).outcome, 'weakened');
    assert.equal(result.summary.verified, false, 'not knowing is not proof');
  });

  it('does not credit a fix for closing what was never open', () => {
    const result = classifyFixOutcome([finding('unknown')], [finding('unknown')]);
    assert.equal(only(result).outcome, 'unchanged');
  });
});

describe('what the fix cost', () => {
  it('reports a confirmed finding the edit introduced', () => {
    const before = [finding('confirmed')];
    const after = [finding('refuted'), finding('confirmed', { line: 40, rule: 'CMD_INJECTION_EXEC_TEMPLATE' })];
    const result = classifyFixOutcome(before, after);

    assert.equal(result.introduced.length, 1);
    assert.equal(result.introduced[0].rule, 'CMD_INJECTION_EXEC_TEMPLATE');
    assert.equal(result.summary.verified, false, 'a fix that adds a confirmed finding is not verified');
  });

  it('does not report a merely uncertain new finding as a regression', () => {
    const result = classifyFixOutcome([finding('confirmed')], [finding('refuted'), finding(null, { line: 40, rule: 'OTHER' })]);
    assert.equal(result.introduced.length, 0);
    assert.equal(result.summary.verified, true);
  });
});

describe('matching findings across the edit', () => {
  it('follows a finding that moved a couple of lines', () => {
    const result = classifyFixOutcome([finding('confirmed')], [finding('refuted', { line: 12 })]);
    assert.equal(only(result).outcome, 'neutralised');
  });

  it('treats a finding that moved far as a different one', () => {
    const result = classifyFixOutcome([finding('confirmed')], [finding('confirmed', { line: 90 })]);
    assert.equal(only(result).outcome, 'resolved', 'the original is gone');
    assert.equal(result.introduced.length, 1, 'and the far one is new');
  });

  it('does not match one survivor to two originals', () => {
    const before = [finding('confirmed', { line: 10 }), finding('confirmed', { line: 11 })];
    const result = classifyFixOutcome(before, [finding('refuted', { line: 10 })]);
    const outcomes = result.outcomes.map((o) => o.outcome).sort();
    assert.deepEqual(outcomes, ['neutralised', 'resolved']);
  });
});

describe('saying it in one line', () => {
  it('names the closed path rather than counting silence', () => {
    const result = classifyFixOutcome([finding('confirmed'), finding('confirmed', { line: 20 })], [finding('refuted')]);
    assert.match(describeFixOutcome(result), /1 no longer detected/);
    assert.match(describeFixOutcome(result), /1 still detected but now refuted/);
  });

  it('handles having nothing to verify', () => {
    assert.match(describeFixOutcome(classifyFixOutcome([], [])), /Nothing to verify/);
  });
});
