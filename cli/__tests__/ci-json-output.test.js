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
      // Spread enough findings across files to exceed a pipe buffer without
      // making one file's context analysis quadratic or turning this transport
      // regression into a long-running corpus benchmark.
      fs.rmSync(file, { force: true });
      for (let i = 0; i < 40; i++) {
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
      assert.ok(result.stdout.length > 128 * 1024,
        `expected a large JSON payload, got ${result.stdout.length} bytes`);

      const report = JSON.parse(result.stdout);
      assert.equal(report.schemaVersion, 1);
      assert.equal(report.tool.name, 'ship-safe');
      assert.match(report.tool.version, /^\d+\.\d+\.\d+$/);
      assert.match(report.generatedAt, /^\d{4}-\d{2}-\d{2}T/);
      assert.equal(report.totalFindings, report.findings.length);
      assert.ok(report.findings.every(finding => !path.isAbsolute(finding.file)));
      assert.ok(report.totalFindings >= 400,
        `expected all generated findings, got ${report.totalFindings}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails instead of hanging when stdout is not drained', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-ci-json-stalled-'));
    const cli = path.resolve('cli/bin/ship-safe.js');

    try {
      for (let i = 0; i < 40; i++) {
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
        // quickly". Scanner startup and fixture analysis can take much longer
        // on constrained runners; a genuine blocked stdout write is still
        // caught once the CLI reaches report emission.
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error('ci command hung with a stalled stdout consumer'));
        }, 120_000);

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
