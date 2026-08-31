/**
 * VerifierAgent dead-code check — regressions from NodeGoat.
 *
 * This pass may return `verified: false`, which now resolves to a 'refuted'
 * verdict, so a wrong dead-code judgement drops a real vulnerability quietly.
 * Both cases below were found refuting live, exploitable code.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { VerifierAgent } from '../agents/verifier-agent.js';
import { createFinding } from '../agents/base-agent.js';

let ROOT;
before(() => { ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-verifier-')); });
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));

const verify = (name, lines, line) => {
  const file = path.join(ROOT, name);
  fs.writeFileSync(file, lines.join('\n'));
  const finding = createFinding({
    file, line, rule: 'NOSQL_INJECTION_WHERE', title: 'NoSQL injection',
    category: 'injection', severity: 'critical', matched: '$where',
  });
  new VerifierAgent().verify([finding]);
  return finding;
};

describe('dead code', () => {
  it('does not treat a throw inside a block comment as real control flow', () => {
    const finding = verify('commented.js', [
      'export function search(threshold, db) {',
      '  /*',
      '  const parsed = parseInt(threshold, 10);',
      '  throw `invalid: ${parsed}`;',
      '  */',
      '  return db.raw({ $where: `n > \'${threshold}\'` });',
      '}',
    ], 6);

    assert.notEqual(finding.verified, false, 'the commented-out fix does not make the live line unreachable');
    assert.notEqual(finding.evidence.verdict, 'refuted');
  });

  it('does not treat the statement a finding sits inside as preceding it', () => {
    const finding = verify('multiline.js', [
      'export function search(threshold, db) {',
      '  return {',
      '    $where: `n > \'${threshold}\'`,',
      '  };',
      '}',
    ], 3);

    assert.notEqual(finding.verified, false, 'the `return {` opens the statement the finding is in');
  });

  it('still recognises genuinely unreachable code', () => {
    const finding = verify('unreachable.js', [
      'export function search(threshold, db) {',
      '  return null;',
      '  db.raw({ $where: `n > \'${threshold}\'` });',
      '}',
    ], 3);

    assert.equal(finding.verified, false, 'a completed return above the finding still ends the flow');
  });
});
