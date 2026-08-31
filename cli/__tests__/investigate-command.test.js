/**
 * Investigate command — how findings are grouped and counted for a reader.
 *
 * The counting is the part with a claim in it. Three rules firing on one line
 * is three findings and one thing to fix, and a report that says "15 confirmed"
 * about five lines is wrong in a way a severity label never is.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import { execFileSync } from 'child_process';

import { groupByVerdict, groupByLocation } from '../commands/investigate.js';
import { createFinding } from '../agents/base-agent.js';
import { attachEvidence, createClaim } from '../utils/evidence.js';

const CLI = path.resolve(import.meta.dirname, '../bin/ship-safe.js');

const finding = (overrides = {}) => createFinding({
  file: '/repo/src/app.js', line: 10, rule: 'RULE_A', title: 'Injection',
  category: 'injection', severity: 'critical', ...overrides,
});

const withVerdict = (verdict, overrides = {}) => {
  const f = finding(overrides);
  attachEvidence(f, createClaim({ source: 'dataflow', verdict, rationale: 'traced' }));
  return f;
};

describe('grouping by location', () => {
  it('collapses several rules firing on one line into one entry', () => {
    const groups = groupByLocation([
      finding({ rule: 'CODE_INJECTION_EVAL' }),
      finding({ rule: 'VIBE_EVAL_INPUT' }),
      finding({ rule: 'CODE_INJECTION_EVAL_GENERIC' }),
    ]);

    assert.equal(groups.length, 1, 'one line is one thing to fix');
    assert.deepEqual(groups[0].rules, ['CODE_INJECTION_EVAL', 'VIBE_EVAL_INPUT', 'CODE_INJECTION_EVAL_GENERIC']);
    assert.equal(groups[0].findings.length, 3, 'the individual findings are still carried');
  });

  it('keeps separate lines separate', () => {
    assert.equal(groupByLocation([finding({ line: 10 }), finding({ line: 11 })]).length, 2);
  });

  it('keeps the same line in different files separate', () => {
    const groups = groupByLocation([finding({ file: '/repo/a.js' }), finding({ file: '/repo/b.js' })]);
    assert.equal(groups.length, 2);
  });

  it('shows the most severe finding at a shared location', () => {
    const groups = groupByLocation([
      finding({ rule: 'LOW_RULE', severity: 'low', title: 'Minor' }),
      finding({ rule: 'CRIT_RULE', severity: 'critical', title: 'Serious' }),
    ]);
    assert.equal(groups[0].primary.title, 'Serious');
  });

  it('orders locations by severity', () => {
    const groups = groupByLocation([
      finding({ line: 1, severity: 'low' }),
      finding({ line: 2, severity: 'critical' }),
      finding({ line: 3, severity: 'medium' }),
    ]);
    assert.deepEqual(groups.map((g) => g.primary.severity), ['critical', 'medium', 'low']);
  });
});

describe('grouping by verdict', () => {
  it('files each location under the verdict its evidence resolved to', () => {
    const grouped = groupByVerdict([
      withVerdict('confirmed', { line: 1 }),
      withVerdict('refuted', { line: 2 }),
      withVerdict('likely', { line: 3 }),
      finding({ line: 4 }),
    ]);

    assert.equal(grouped.confirmed.length, 1);
    assert.equal(grouped.refuted.length, 1);
    assert.equal(grouped.likely.length, 1);
    assert.equal(grouped.unknown.length, 1, 'a finding nothing investigated is unresolved, not clean');
  });

  it('counts a multi-rule location once within its verdict', () => {
    const grouped = groupByVerdict([
      withVerdict('confirmed', { rule: 'A' }),
      withVerdict('confirmed', { rule: 'B' }),
      withVerdict('confirmed', { rule: 'C' }),
    ]);
    assert.equal(grouped.confirmed.length, 1);
  });

  it('returns every bucket even when empty, so a report can say zero', () => {
    const grouped = groupByVerdict([]);
    assert.deepEqual(Object.keys(grouped).sort(), ['confirmed', 'likely', 'refuted', 'unknown']);
  });
});

describe('command surface', () => {
  it('is registered with its documented options', () => {
    const help = execFileSync(process.execPath, [CLI, 'investigate', '--help'], { encoding: 'utf8' });
    assert.match(help, /--all/);
    assert.match(help, /--deep/);
    assert.match(help, /--json/);
  });
});
