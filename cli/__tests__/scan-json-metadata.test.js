import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

test('scan JSON is portable and records scanner provenance', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-scan-json-'));
  const cli = path.resolve('cli/bin/ship-safe.js');
  const source = path.join(dir, 'src', 'config.js');

  try {
    fs.mkdirSync(path.dirname(source), { recursive: true });
    fs.writeFileSync(source, 'const key = "AKIA0000000000000000";\n');

    const result = spawnSync(process.execPath, [
      cli, 'scan', dir, '--json', '--no-cache',
    ], {
      cwd: path.resolve('.'),
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1' },
    });

    assert.equal(result.status, 1, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.tool.name, 'ship-safe');
    assert.match(report.tool.version, /^\d+\.\d+\.\d+$/);
    assert.match(report.generatedAt, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(report.findings[0].file, 'src/config.js');
    assert.doesNotMatch(report.findings[0].file, new RegExp(os.homedir().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

    const absolute = spawnSync(process.execPath, [
      cli, 'scan', dir, '--json', '--absolute-paths', '--no-cache',
    ], {
      cwd: path.resolve('.'),
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1' },
    });
    const absoluteReport = JSON.parse(absolute.stdout);
    assert.equal(absoluteReport.findings[0].file, source);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
