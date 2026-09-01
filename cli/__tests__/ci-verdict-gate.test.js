/**
 * Gating a pipeline on evidence rather than on a severity label.
 *
 * The original premise of the investigation layer was that a build should stop
 * for what was established, not for what a rule was willing to call critical.
 * These pin the two ways that changes a gate, and — more importantly — that
 * neither changes it unless a pipeline asks.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import { execFileSync } from 'child_process';

import { createFinding } from '../agents/base-agent.js';
import { attachEvidence, createClaim } from '../utils/evidence.js';
import { determinePass } from '../commands/ci.js';

const CLI = path.resolve(import.meta.dirname, '../bin/ship-safe.js');
const SCORE = { score: 90, grade: { letter: 'A' } };

const finding = (verdict, overrides = {}) => {
  const f = createFinding({
    file: '/repo/src/app.js', line: 3, rule: 'R', title: 'Injection',
    category: 'injection', severity: 'critical', ...overrides,
  });
  if (verdict) attachEvidence(f, createClaim({ source: 'dataflow', verdict, rationale: 'traced' }));
  return f;
};

describe('gating on evidence', () => {
  it('blocks a confirmed finding', () => {
    const pass = determinePass(SCORE, [finding('confirmed')], 75, 'critical', false, { failOnVerdict: 'confirmed' });
    assert.equal(pass, false);
  });

  it('lets a likely finding through when the gate is set to confirmed', () => {
    const pass = determinePass(SCORE, [finding('likely')], 75, 'critical', false, { failOnVerdict: 'confirmed' });
    assert.equal(pass, true, 'plausible is not established');
  });

  it('blocks both when the gate is set to likely', () => {
    for (const verdict of ['confirmed', 'likely']) {
      assert.equal(
        determinePass(SCORE, [finding(verdict)], 75, 'critical', false, { failOnVerdict: 'likely' }),
        false,
        `${verdict} should block`,
      );
    }
  });

  it('lets an unresolved critical through, which severity gating would not', () => {
    const findings = [finding(null)];
    assert.equal(determinePass(SCORE, findings, 75, 'critical', false, {}), false, 'severity blocks it');
    assert.equal(
      determinePass(SCORE, findings, 75, 'critical', false, { failOnVerdict: 'confirmed' }),
      true,
      'evidence does not',
    );
  });

  it('passes everything at verdict none', () => {
    assert.equal(determinePass(SCORE, [finding('confirmed')], 75, 'critical', false, { failOnVerdict: 'none' }), true);
  });
});

describe('refuted findings', () => {
  it('still blocks a refuted critical by default', () => {
    // Refutation is a judgement, and a wrong one lets a real issue through
    // silently. It must never change what stops a build on its own.
    assert.equal(determinePass(SCORE, [finding('refuted')], 75, 'critical', false, {}), false);
  });

  it('stops blocking only when the pipeline opts in', () => {
    assert.equal(
      determinePass(SCORE, [finding('refuted')], 75, 'critical', false, { ignoreRefuted: true }),
      true,
    );
  });

  it('does not drop an unresolved finding along with the refuted one', () => {
    const pass = determinePass(SCORE, [finding('refuted'), finding(null)], 75, 'critical', false, { ignoreRefuted: true });
    assert.equal(pass, false, 'only the refuted one is excused');
  });
});

describe('command surface', () => {
  it('documents both flags', () => {
    const help = execFileSync(process.execPath, [CLI, 'ci', '--help'], { encoding: 'utf8' });
    assert.match(help, /--fail-on-verdict/);
    assert.match(help, /--ignore-refuted/);
  });
});
