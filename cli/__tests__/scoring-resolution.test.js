/**
 * Scoring resolution
 * ==================
 *
 * The score has to stay responsive across the whole range of finding counts a
 * real repository can produce. It previously did not: category deductions were
 * clamped with Math.min, every category's weight is worth only 3 to 5
 * medium-severity findings, and the eight weights sum to 100 — so about thirty
 * findings spread across categories bottomed the score out. hermes-agent
 * scored 13/F at 6,948 findings and 13/F at 799, an 89% reduction the number
 * could not see.
 *
 * These are invariants, not fixed values: they assert how two scans must relate
 * to each other, so they survive re-cut grade bands and re-weighted categories.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ScoringEngine, CATEGORIES } from '../agents/scoring-engine.js';

const cats = Object.keys(CATEGORIES);

function findings(n) {
  return Array.from({ length: n }, (_, i) => ({
    category: cats[i % cats.length],
    severity: ['critical', 'high', 'medium'][i % 3],
    confidence: 'medium',
    rule: 'TEST_RULE',
    title: 'test',
    file: `f${i}.js`,
    line: 1,
  }));
}

const scoreOf = (n) => new ScoringEngine().compute(findings(n), []).score;

describe('scoring stays responsive as findings grow', () => {
  it('is strictly decreasing across four orders of magnitude', () => {
    const counts = [5, 15, 30, 60, 120, 300, 800, 2000, 7000];
    const scores = counts.map(scoreOf);

    for (let i = 1; i < scores.length; i++) {
      assert.ok(
        scores[i] < scores[i - 1],
        `${counts[i]} findings scored ${scores[i]}, not below ${counts[i - 1]} findings at ${scores[i - 1]}`
      );
    }
  });

  it('separates a noisy repository from a catastrophic one', () => {
    // The case that motivated this: an 89% reduction in findings has to move
    // the number. Under the old hard cap both of these scored 0.
    assert.ok(scoreOf(800) < scoreOf(90), '800 findings must score below 90');
    assert.ok(scoreOf(7000) < scoreOf(800), '7000 findings must score below 800');
  });

  it('still charges the first finding in a category the most', () => {
    const first = 100 - scoreOf(8);        // one per category
    const second = 100 - scoreOf(16) - first;
    assert.ok(first > second, 'marginal cost must fall as findings accumulate');
  });

  it('never goes negative or above 100', () => {
    for (const n of [0, 1, 50, 5000]) {
      const s = scoreOf(n);
      assert.ok(s >= 0 && s <= 100, `score ${s} out of range for ${n} findings`);
    }
  });
});

describe('quality findings are reported but never scored', async () => {
  const { ScoringEngine } = await import('../agents/scoring-engine.js');

  it('does not let a maintainability finding move the score', () => {
    const engine = new ScoringEngine();
    const clean = engine.compute([], []);
    const withQuality = engine.compute(
      Array(50).fill({ severity: 'medium', category: 'quality', confidence: 'high' }), []);

    assert.equal(withQuality.score, clean.score,
      'code-quality findings must not affect a security score');
  });

  it('still counts them so they show up in the report', () => {
    const engine = new ScoringEngine();
    const result = engine.compute(
      [{ severity: 'medium', category: 'quality', confidence: 'high' }], []);

    assert.equal(result.categories.quality.counts.medium, 1);
  });

  it('keeps scoring real security findings alongside them', () => {
    const engine = new ScoringEngine();
    const mixed = engine.compute([
      { severity: 'critical', category: 'secrets', confidence: 'high' },
      ...Array(20).fill({ severity: 'medium', category: 'quality', confidence: 'high' }),
    ], []);
    assert.ok(mixed.score < 100, 'a critical secret must still cost');
  });
});
