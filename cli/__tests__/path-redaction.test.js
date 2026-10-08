import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { redactLocalPaths } from '../utils/path-redaction.js';

test('redacts checkout and home paths recursively in machine reports', () => {
  const root = path.join(os.tmpdir(), 'ship-safe-private-checkout');
  const home = os.homedir();
  const report = {
    root,
    findings: [{
      file: path.join(root, 'src', 'index.js'),
      evidence: `read ${path.join(home, '.config', 'private.json')}`,
    }],
  };

  const sanitized = redactLocalPaths(report, root);
  const serialized = JSON.stringify(sanitized);

  assert.equal(sanitized.root, '.');
  assert.equal(sanitized.findings[0].file, './src/index.js');
  assert.match(sanitized.findings[0].evidence, /~[\\/]\.config/);
  assert.equal(serialized.includes(root), false);
  assert.equal(serialized.includes(home), false);
  assert.equal(report.root, root, 'redaction returns a copy instead of mutating the caller report');
});
