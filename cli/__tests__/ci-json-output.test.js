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
import { spawn, spawnSync } from 'node:child_process';

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

  it('fails instead of hanging when stdout is not drained', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-ci-json-stalled-'));
    const cli = path.resolve('cli/bin/ship-safe.js');

    try {
      for (let i = 0; i < 180; i++) {
        fs.writeFileSync(path.join(dir, `generated-${i}.js`),
          Array.from({ length: 10 }, (_, line) => `eval(userInput${i}_${line});`).join('\n'));
      }

      const child = spawn(process.execPath, [
        cli, 'ci', dir, '--json', '--threshold', '0', '--no-deps',
      ], {
        cwd: path.resolve('.'),
        env: {
          ...process.env,
          NO_COLOR: '1',
          SHIP_SAFE_STDOUT_TIMEOUT_MS: '100',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      // Intentionally leave child.stdout unread to model a stalled CI collector.
      const stderr = [];
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk) => stderr.push(chunk));

      const result = await new Promise((resolve, reject) => {
        // Generous, because the assertion is "does not hang", not "finishes
        // quickly". The scan itself takes about three seconds, `node --test`
        // runs files in parallel, and a budget only slightly above the
        // measured time turns every added test elsewhere in the suite into a
        // failure here. A genuine hang is still caught, just later.
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error('ci command hung with a stalled stdout consumer'));
        }, 30_000);

        child.once('error', reject);
        child.once('exit', (code, signal) => {
          clearTimeout(timer);
          resolve({ code, signal });
        });
      });

      assert.equal(result.signal, null);
      assert.equal(result.code, 1);
      assert.match(stderr.join(''), /Timed out writing JSON output to stdout/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
