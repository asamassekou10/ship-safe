/**
 * CI JSON transport regression.
 *
 * `ci --json` is consumed by benchmark runners and automation, so the child
 * process must not exit while a large stdout write is still buffered.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

describe('ci JSON output', () => {
  it('emits parseable JSON for a large finding set', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-ci-json-'));
    const file = path.join(dir, 'generated-findings.js');
    const cli = path.resolve('cli/bin/ship-safe.js');

    try {
      // Spread findings across files so the scanner exercises a large report
      // without making one file's context analysis quadratic.
      fs.rmSync(file, { force: true });
      for (let i = 0; i < 180; i++) {
        fs.writeFileSync(path.join(dir, `generated-${i}.js`),
          Array.from({ length: 10 }, (_, line) => `eval(userInput${i}_${line});`).join('\n'));
      }

      const result = spawnSync(process.execPath, [
        cli, 'ci', dir, '--json', '--threshold', '0', '--no-deps',
      ], {
        cwd: path.resolve('.'),
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1' },
      });

      assert.equal(result.error, undefined, result.error?.message);
      assert.equal(result.status, 0, result.stderr);
      assert.ok(result.stdout.length > 1024 * 1024,
        `expected a large JSON payload, got ${result.stdout.length} bytes`);

      const report = JSON.parse(result.stdout);
      assert.equal(report.totalFindings, report.findings.length);
      assert.ok(report.totalFindings >= 1800,
        `expected all generated findings, got ${report.totalFindings}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
