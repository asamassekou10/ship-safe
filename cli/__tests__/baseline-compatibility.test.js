import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { filterBaseline } from '../commands/baseline.js';
import { findingFingerprint } from '../utils/finding-fingerprint.js';

function writeBaseline(root, baseline) {
  const directory = path.join(root, '.ship-safe');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'baseline.json'), JSON.stringify(baseline));
}

describe('baseline fingerprint compatibility', () => {
  it('matches v2 hashed identities across line-number changes', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-baseline-v2-'));
    const finding = {
      file: path.join(root, 'src/app.js'),
      line: 5,
      rule: 'SHELL_INJECTION',
      matched: 'exec(userInput)',
    };

    try {
      writeBaseline(root, { version: 2, fingerprints: [findingFingerprint(finding, root)] });
      assert.deepEqual(filterBaseline([{ ...finding, line: 200 }], root), []);
      assert.equal(filterBaseline([{ ...finding, matched: 'exec(otherInput)' }], root).length, 1);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('continues to honor legacy readable identities', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-baseline-v1-'));
    const finding = {
      file: path.join(root, 'src/app.js'),
      line: 5,
      rule: 'SHELL_INJECTION',
      matched: 'exec(userInput)',
    };
    const legacy = 'SHELL_INJECTION:src/app.js:exec(userInput)';

    try {
      writeBaseline(root, { version: '4.3.0', fingerprints: [legacy] });
      assert.deepEqual(filterBaseline([finding], root), []);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
