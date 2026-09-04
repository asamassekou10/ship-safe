import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';

const directories = [];

afterEach(() => {
  for (const dir of directories.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function largeAudit(format) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-audit-json-'));
  directories.push(dir);
  const cli = path.resolve('cli/bin/ship-safe.js');
  const source = Array.from(
    { length: 800 },
    (_, index) => `const key${index} = "AKIA${String(index).padStart(16, '0')}";`,
  ).join('\n');
  fs.writeFileSync(path.join(dir, 'secrets.js'), source);

  return spawnSync(process.execPath, [
    cli,
    'audit',
    dir,
    '--hermes-only',
    '--no-deps',
    '--no-ai',
    '--no-cache',
    format,
  ], {
    cwd: path.resolve('.'),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1' },
  });
}

test('audit emits complete JSON when the report exceeds a pipe buffer', () => {
  const result = largeAudit('--json');
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.length > 64 * 1024, `expected more than 64 KiB, got ${result.stdout.length}`);

  let report;
  assert.doesNotThrow(() => { report = JSON.parse(result.stdout); });
  assert.equal(report.findings.length, 800);
});

test('audit emits complete SARIF when the report exceeds a pipe buffer', () => {
  const result = largeAudit('--sarif');
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.length > 64 * 1024, `expected more than 64 KiB, got ${result.stdout.length}`);

  let report;
  assert.doesNotThrow(() => { report = JSON.parse(result.stdout); });
  assert.equal(report.version, '2.1.0');
  assert.equal(report.runs[0].results.length, 800);
});
