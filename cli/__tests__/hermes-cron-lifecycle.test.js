import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  HermesSecurityAgent,
  HERMES_CRON_LIFECYCLE,
} from '../agents/hermes-security-agent.js';

const FIXTURES = path.resolve('cli/__tests__/fixtures/hermes-cron');

async function scanFixture(name) {
  const rootPath = path.join(FIXTURES, name);
  const files = fs.readdirSync(rootPath).map((file) => path.join(rootPath, file));
  return new HermesSecurityAgent().analyze({ rootPath, files, recon: {}, options: {} });
}

describe('Hermes v0.21.0 cron lifecycle and retained authority', () => {
  it('maps definition, persistence, identity, cancellation, and cleanup', () => {
    assert.match(HERMES_CRON_LIFECYCLE.definition, /create_job.*update_job/);
    assert.match(HERMES_CRON_LIFECYCLE.persistence, /jobs\.json/);
    assert.match(HERMES_CRON_LIFECYCLE.executionIdentity, /execution id.*secret scope/);
    assert.match(HERMES_CRON_LIFECYCLE.cancellation, /fire-claim/);
    assert.match(HERMES_CRON_LIFECYCLE.cleanup, /finally/);
  });

  it('detects a persisted update that bypasses the creation guard', async () => {
    const findings = await scanFixture('update-vulnerable');
    const finding = findings.find((item) => item.rule === 'HERMES_CRON_UPDATE_LIFECYCLE_GUARD_BYPASS');
    assert.ok(finding);
    assert.equal(finding.posture, 'hygiene');
    assert.equal(finding.hermesCronLifecycle.stage, 'update');
    assert.equal(finding.hermesCronLifecycle.evidence.length, 4);
    assert.match(finding.hermesCronLifecycle.evidence[0].role, /schedule definition/);
    assert.match(finding.hermesCronLifecycle.evidence[3].role, /privileged action/);
    assert.match(finding.hermesCronLifecycle.evidence[3].file.replace(/\\/g, '/'), /\/scheduler\.py$/);
  });

  it('accepts a guard applied to the effective payload before persistence', async () => {
    const findings = await scanFixture('update-safe');
    assert.ok(!findings.some((item) => item.rule === 'HERMES_CRON_UPDATE_LIFECYCLE_GUARD_BYPASS'));
  });

  it('detects authority retained across an exception and retry path', async () => {
    const findings = await scanFixture('authority-vulnerable');
    const finding = findings.find((item) => item.rule === 'HERMES_CRON_RETAINED_AUTHORITY');
    assert.ok(finding);
    assert.equal(finding.hermesCronLifecycle.stage, 'cleanup');
    assert.match(finding.description, /Exceptions, cancellation, or retry/);
    assert.ok(finding.hermesCronLifecycle.evidence.some((item) => /retry/.test(item.role)));
  });

  it('accepts authority revoked in a function-level finally block', async () => {
    const findings = await scanFixture('authority-safe');
    assert.ok(!findings.some((item) => item.rule === 'HERMES_CRON_RETAINED_AUTHORITY'));
  });

  it('does not treat JavaScript-shaped scheduler text in Python as cron evidence', async () => {
    const rootPath = path.join(FIXTURES, 'language-scope');
    fs.mkdirSync(rootPath, { recursive: true });
    const file = path.join(rootPath, 'hermes_cron.py');
    fs.writeFileSync(file, `example = "cron.schedule('0 9 * * *', lambda: fs.readFileSync('.hermes/skills/a.md'))"\n`);
    try {
      const findings = await new HermesSecurityAgent().analyze({ rootPath, files: [file], recon: {}, options: {} });
      assert.ok(!findings.some((item) => item.rule === 'HERMES_CRON_SKILL_INJECTION'));
    } finally {
      fs.rmSync(rootPath, { recursive: true, force: true });
    }
  });

  it('does not build lifecycle evidence from Python comments or docstrings', async () => {
    const findings = await scanFixture('comment-only');
    assert.ok(!findings.some((item) => item.rule.startsWith('HERMES_CRON_')));
  });

  for (const format of ['--json', '--sarif']) {
    it(`renders the complete cron chain in audit ${format.slice(2).toUpperCase()} output`, () => {
      const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-cron-'));
      const rootPath = path.join(tempRoot, 'update-vulnerable');
      fs.cpSync(path.join(FIXTURES, 'update-vulnerable'), rootPath, { recursive: true });
      try {
        const result = spawnSync(process.execPath, [
          path.resolve('cli/bin/ship-safe.js'),
          'audit',
          rootPath,
          '--hermes-only',
          '--no-deps',
          '--no-ai',
          '--no-cache',
          format,
        ], {
          cwd: path.resolve('.'),
          encoding: 'utf8',
          maxBuffer: 8 * 1024 * 1024,
          env: { ...process.env, NO_COLOR: '1' },
        });
        assert.equal(result.status, 0, result.stderr);
        const report = JSON.parse(result.stdout);

        if (format === '--json') {
          const finding = report.findings.find((item) => item.rule === 'HERMES_CRON_UPDATE_LIFECYCLE_GUARD_BYPASS');
          assert.ok(finding);
          assert.equal(finding.hermesCronLifecycle.stage, 'update');
          assert.equal(finding.hermesCronLifecycle.evidence.length, 4);
        } else {
          const finding = report.runs[0].results.find((item) => item.ruleId === 'HERMES_CRON_UPDATE_LIFECYCLE_GUARD_BYPASS');
          assert.ok(finding);
          assert.equal(finding.properties.hermesCronStage, 'update');
          assert.match(finding.properties.retainedAuthority, /stored schedule/);
          assert.equal(finding.relatedLocations.length, 4);
          assert.match(finding.relatedLocations[0].message.text, /schedule definition/);
          assert.match(finding.relatedLocations[3].physicalLocation.artifactLocation.uri, /scheduler\.py$/);
        }
      } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
      }
    });
  }

  it('carries the complete cron chain into CI SARIF output', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-ci-'));
    const rootPath = path.join(tempRoot, 'update-vulnerable');
    const sarifPath = path.join(tempRoot, 'results.sarif');
    fs.cpSync(path.join(FIXTURES, 'update-vulnerable'), rootPath, { recursive: true });
    try {
      const result = spawnSync(process.execPath, [
        path.resolve('cli/bin/ship-safe.js'),
        'ci',
        rootPath,
        '--no-deps',
        '--fail-on',
        'none',
        '--sarif',
        sarifPath,
      ], {
        cwd: path.resolve('.'),
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1' },
      });
      assert.equal(result.status, 0, result.stderr);
      const report = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
      const finding = report.runs[0].results.find((item) => item.ruleId === 'HERMES_CRON_UPDATE_LIFECYCLE_GUARD_BYPASS');
      assert.ok(finding);
      assert.equal(finding.properties.hermesCronStage, 'update');
      assert.equal(finding.relatedLocations.length, 4);
      assert.match(finding.relatedLocations[0].message.text, /schedule definition/);
      assert.match(finding.relatedLocations[3].physicalLocation.artifactLocation.uri, /scheduler\.py$/);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
});
