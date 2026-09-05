import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  HermesSecurityAgent,
  HERMES_CREDENTIAL_FLOW,
} from '../agents/hermes-security-agent.js';

const FIXTURES = path.resolve('cli/__tests__/fixtures/hermes-credentials');

function fixtureFiles(root) {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const item = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(item);
      else files.push(item);
    }
  };
  visit(root);
  return files;
}

async function scanFixture(name) {
  const rootPath = path.join(FIXTURES, name);
  return scanRoot(rootPath);
}

async function scanRoot(rootPath) {
  return new HermesSecurityAgent().analyze({
    rootPath,
    files: fixtureFiles(rootPath),
    recon: {},
    options: {},
  });
}

function credentialFindings(findings) {
  return findings.filter((item) => item.rule === 'HERMES_CREDENTIAL_REACHABLE_EFFECT');
}

describe('Hermes credential reachability', () => {
  it('requires source, scope, recipient, operation, and effect evidence', () => {
    assert.deepEqual(HERMES_CREDENTIAL_FLOW, [
      'source',
      'scope',
      'recipient',
      'reachableOperation',
      'externalEffect',
    ]);
  });

  it('traces an enabled project plugin credential to its network effect', async () => {
    const findings = credentialFindings(await scanFixture('plugin-vulnerable'));
    assert.equal(findings.length, 1);
    assert.match(findings[0].hermesCredentialFlow.recipient, /plugin deploy-reporter/);
    assert.equal(findings[0].hermesCredentialFlow.reachabilityBasis, 'configured');
    assert.equal(findings[0].hermesCredentialFlow.evidence.length, 6);
  });

  it('does not elevate a declared but unused plugin credential', async () => {
    assert.equal(credentialFindings(await scanFixture('plugin-safe')).length, 0);
  });

  it('does not treat an unregistered helper as reachable plugin code', async () => {
    assert.equal(credentialFindings(await scanFixture('plugin-unregistered')).length, 0);
  });

  it('does not treat project-plugin opt-in prose as executable configuration', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-plugin-prose-'));
    fs.cpSync(path.join(FIXTURES, 'plugin-vulnerable'), tempRoot, { recursive: true });
    fs.rmSync(path.join(tempRoot, 'compose.yaml'));
    fs.writeFileSync(path.join(tempRoot, 'README.md'), 'Set HERMES_ENABLE_PROJECT_PLUGINS=true to opt in.\n');
    try {
      assert.equal(credentialFindings(await scanRoot(tempRoot)).length, 0);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('traces a platform adapter credential to its network effect', async () => {
    const findings = credentialFindings(await scanFixture('adapter-vulnerable'));
    assert.equal(findings.length, 1);
    assert.match(findings[0].hermesCredentialFlow.recipient, /adapter incident-platform/);
  });

  it('does not elevate an adapter credential that never reaches its network call', async () => {
    assert.equal(credentialFindings(await scanFixture('adapter-safe')).length, 0);
  });

  it('does not use Python comments or strings as credential-flow edges', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-plugin-prose-code-'));
    fs.cpSync(path.join(FIXTURES, 'plugin-vulnerable'), tempRoot, { recursive: true });
    const sourcePath = path.join(tempRoot, '.hermes/plugins/deploy-reporter/__init__.py');
    fs.writeFileSync(sourcePath, [
      'import httpx',
      '',
      'def report(payload):',
      '    example = """token = get_secret("DEPLOY_TOKEN")"""',
      '    return httpx.post("https://deploy.example.test/report", json=payload)',
      '',
      '# register_tool("report", report)',
      '',
    ].join('\n'));
    try {
      assert.equal(credentialFindings(await scanRoot(tempRoot)).length, 0);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('traces terminal passthrough only when a skill consumes it externally', async () => {
    const vulnerable = credentialFindings(await scanFixture('terminal-vulnerable'));
    const safe = credentialFindings(await scanFixture('terminal-safe'));
    assert.equal(vulnerable.length, 1);
    assert.match(vulnerable[0].hermesCredentialFlow.scope, /env_passthrough/);
    assert.equal(safe.length, 0);
  });

  it('does not join a credential reference to an unrelated nearby network command', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-terminal-proximity-'));
    fs.cpSync(path.join(FIXTURES, 'terminal-vulnerable'), tempRoot, { recursive: true });
    fs.writeFileSync(path.join(tempRoot, '.hermes/skills/deploy.md'), [
      '---',
      'name: deploy',
      'required_environment_variables:',
      '  - DEPLOY_TOKEN',
      '---',
      '',
      'Print `$DEPLOY_TOKEN` for a local diagnostic.',
      'Run `curl https://status.example.test` separately.',
      '',
    ].join('\n'));
    try {
      assert.equal(credentialFindings(await scanRoot(tempRoot)).length, 0);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('traces an enabled cron credential effect and ignores a disabled job', async () => {
    const vulnerable = credentialFindings(await scanFixture('cron-vulnerable'));
    const safe = credentialFindings(await scanFixture('cron-safe'));
    assert.equal(vulnerable.length, 1);
    assert.match(vulnerable[0].hermesCredentialFlow.recipient, /cron job nightly deploy/);
    assert.match(vulnerable[0].hermesCredentialFlow.externalEffect, /unattended/);
    assert.equal(safe.length, 0);
  });

  it('reports names and evidence locations without credential values', async () => {
    const [finding] = credentialFindings(await scanFixture('plugin-vulnerable'));
    assert.equal(finding.hermesCredentialFlow.credential, 'DEPLOY_TOKEN');
    assert.ok(!JSON.stringify(finding).includes('super-secret-value'));
    for (const item of finding.hermesCredentialFlow.evidence) {
      assert.ok(item.file);
      assert.ok(item.line > 0);
      assert.ok(item.role);
    }
  });

  for (const format of ['--json', '--sarif']) {
    it(`renders credential-chain evidence in audit ${format.slice(2).toUpperCase()} output`, () => {
      const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-credential-'));
      const rootPath = path.join(tempRoot, 'plugin-vulnerable');
      fs.cpSync(path.join(FIXTURES, 'plugin-vulnerable'), rootPath, { recursive: true });
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
          const finding = report.findings.find((item) => item.rule === 'HERMES_CREDENTIAL_REACHABLE_EFFECT');
          assert.ok(finding);
          assert.equal(finding.hermesCredentialFlow.credential, 'DEPLOY_TOKEN');
          assert.equal(finding.hermesCredentialFlow.evidence.length, 6);
        } else {
          const finding = report.runs[0].results.find((item) => item.ruleId === 'HERMES_CREDENTIAL_REACHABLE_EFFECT');
          assert.ok(finding);
          assert.equal(finding.properties.credential, 'DEPLOY_TOKEN');
          assert.equal(finding.properties.reachabilityBasis, 'configured');
          assert.equal(finding.relatedLocations.length, 6);
        }
      } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
      }
    });
  }

  it('carries credential-chain evidence into CI SARIF output', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-hermes-credential-ci-'));
    const rootPath = path.join(tempRoot, 'plugin-vulnerable');
    const sarifPath = path.join(tempRoot, 'results.sarif');
    fs.cpSync(path.join(FIXTURES, 'plugin-vulnerable'), rootPath, { recursive: true });
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
      const finding = report.runs[0].results.find((item) => item.ruleId === 'HERMES_CREDENTIAL_REACHABLE_EFFECT');
      assert.ok(finding);
      assert.equal(finding.properties.credentialRecipient, 'plugin deploy-reporter');
      assert.equal(finding.relatedLocations.length, 6);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
});
