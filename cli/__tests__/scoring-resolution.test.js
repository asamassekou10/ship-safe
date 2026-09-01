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
import { ScoringEngine, CATEGORIES, SCORE_VERSION } from '../agents/scoring-engine.js';
import { createFinding, inferCodeScope, normalizeFindingMetadata } from '../agents/base-agent.js';

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

describe('the grade cannot contradict the gate', () => {
  const engine = () => new ScoringEngine();
  const finding = (severity, category = 'injection') => ({
    severity, category, confidence: 'high', rule: 'R', file: 'f.js', line: 1,
  });

  it('never grades a repository with a critical finding as A or B', () => {
    // `ci` fails on any critical by default. A grade of "A — Ship it!" on the
    // same code would be the tool contradicting itself, and the friendlier
    // answer would be the wrong one.
    const r = engine().compute([finding('critical')], []);
    assert.ok(['D', 'F'].includes(r.grade.letter),
      `one critical graded ${r.grade.letter}`);
  });

  it('caps on the worst finding, not on how many there are', () => {
    const one = engine().compute([finding('critical')], []);
    const many = engine().compute(Array(20).fill(finding('critical')), []);
    // Both are ungradeable-for-shipping. The score still separates them.
    assert.ok(['D', 'F'].includes(one.grade.letter));
    assert.ok(['D', 'F'].includes(many.grade.letter));
    assert.ok(many.score < one.score, 'score must still distinguish volume');
  });

  it('leaves a clean repository alone', () => {
    assert.equal(engine().compute([], []).grade.letter, 'A');
  });

  it('does not cap on high or medium', () => {
    // Deliberately narrow. Highs are confidence-weighted and noisier, so
    // capping on them would move most of the corpus for less reason.
    for (const sev of ['high', 'medium']) {
      const r = engine().compute([finding(sev)], []);
      assert.equal(r.grade.letter, 'A', `a single ${sev} should not cap`);
    }
  });
});

describe('score v2 posture contract', () => {
  const engine = new ScoringEngine();

  it('classifies common non-production paths without overloading scope', () => {
    assert.equal(inferCodeScope('/repo/src/auth.js'), 'production');
    assert.equal(inferCodeScope('/repo/test/auth.test.js'), 'test');
    assert.equal(inferCodeScope('/repo/fixtures/malicious.js'), 'fixture');
    assert.equal(inferCodeScope('/repo/examples/insecure.js'), 'fixture');
    assert.equal(inferCodeScope('/repo/benchmarks/corpus.js'), 'benchmark');
    assert.equal(inferCodeScope('/repo/docs/security.md'), 'docs');

    const finding = createFinding({ file: '/repo/test/auth.test.js', rule: 'R', title: 'test' });
    assert.equal(finding.scope, 'project');
    assert.equal(finding.codeScope, 'test');

    const legacy = normalizeFindingMetadata({ file: '/repo/docs/example.md', confidence: 'medium' });
    assert.equal(legacy.codeScope, 'docs');
    assert.equal(legacy.evidenceLevel, 'heuristic');
    assert.equal(legacy.reachability, 'unknown');
  });

  it('excludes non-production evidence from posture while retaining observation counts', () => {
    const fixture = {
      file: '/repo/fixtures/malicious.js', line: 1, rule: 'R', title: 'fixture',
      severity: 'critical', category: 'injection', confidence: 'high',
    };
    const result = engine.compute([fixture], []);

    assert.equal(result.scoreVersion, SCORE_VERSION);
    assert.equal(result.postureScore, 100);
    assert.equal(result.totalObservedFindings, 1);
    assert.equal(result.postureFindings, 0);
    assert.equal(result.excludedFromPosture, 1);
    assert.deepEqual(result.excludedByCodeScope, { fixture: 1 });
  });

  it('can explicitly include non-production findings', () => {
    const result = engine.compute([{
      file: '/repo/tests/injection.test.js', line: 1, rule: 'R', title: 'test',
      severity: 'critical', category: 'injection', confidence: 'high',
    }], [], { includeNonProduction: true });

    assert.ok(result.score < 100);
    assert.equal(result.postureFindings, 1);
  });

  it('does not let an AI classification silently alter deterministic posture', () => {
    const base = {
      file: '/repo/src/query.js', line: 1, rule: 'R', title: 'query',
      severity: 'high', category: 'injection', confidence: 'high',
    };
    const real = engine.compute([{ ...base, aiClassification: 'REAL' }], []);
    const falsePositive = engine.compute([{ ...base, aiClassification: 'FALSE_POSITIVE' }], []);

    assert.equal(real.score, falsePositive.score);
    assert.equal(real.aiAffectsScore, false);
  });

  it('uses preserved deterministic evidence when deep analysis changes confidence', () => {
    const base = {
      file: '/repo/src/handler.js', line: 12, rule: 'COMMAND_INJECTION', title: 'command injection',
      severity: 'critical', category: 'injection', confidence: 'high',
    };
    const withoutDeep = engine.compute([{ ...base }], []);
    const afterDeep = engine.compute([{
      ...base,
      deterministicConfidence: 'high',
      deterministicSeverity: 'critical',
      confidence: 'low',
      deepAnalysis: { exploitability: 'false_positive' },
    }], []);

    assert.equal(afterDeep.score, withoutDeep.score);
    assert.equal(afterDeep.grade.letter, withoutDeep.grade.letter);
  });
});
