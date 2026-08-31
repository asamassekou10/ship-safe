import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve('cli/bin/ship-safe.js');

function runCi(directory, args = []) {
  return spawnSync(process.execPath, [CLI, 'ci', directory, '--json', '--no-deps', ...args], {
    cwd: path.resolve('.'),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1' },
  });
}

describe('ci pull request delta', () => {
  it('gates on introduced posture findings instead of existing repository debt', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-pr-delta-'));
    const baselinePath = path.join(directory, '.ship-safe', 'base-report.json');

    try {
      fs.writeFileSync(path.join(directory, 'existing.js'), 'eval(request.body.code);\n');
      const baseline = runCi(directory, ['--fail-on', 'none', '--write-baseline-report', baselinePath]);
      assert.equal(baseline.status, 0, baseline.stderr);

      const saved = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
      assert.ok(saved.findingSnapshots.length > 0);
      assert.doesNotMatch(JSON.stringify(saved), /request\.body\.code/);

      const unchanged = runCi(directory, ['--fail-on', 'critical', '--base-report', baselinePath]);
      assert.equal(unchanged.status, 0, unchanged.stderr);
      const unchangedReport = JSON.parse(unchanged.stdout);
      assert.equal(unchangedReport.prDelta.counts.introduced, 0);
      assert.ok(unchangedReport.prDelta.counts.unchanged > 0);
      assert.equal(unchangedReport.pass, true);

      fs.writeFileSync(path.join(directory, 'introduced.js'), 'eval(req.query.payload);\n');
      const changed = runCi(directory, ['--fail-on', 'critical', '--base-report', baselinePath]);
      assert.equal(changed.status, 1, changed.stderr);
      const changedReport = JSON.parse(changed.stdout);
      assert.ok(changedReport.prDelta.counts.introduced > 0);
      assert.equal(changedReport.pass, false);
      assert.equal(changedReport.postureScore < 100, true);
      assert.equal(changedReport.prRiskScore < 100, true);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
