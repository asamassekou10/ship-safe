import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  HermesSecurityAgent,
  HERMES_OPERATION_BOUNDARIES,
  HERMES_TERMINAL_BACKENDS,
  postureFor,
} from '../agents/hermes-security-agent.js';

const EXPECTED_BACKENDS = [
  'local',
  'docker',
  'modal',
  'ssh',
  'daytona',
  'vercel_sandbox',
  'singularity',
];

function fixture(config, extraFiles = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-hermes-terminal-'));
  const configFile = path.join(dir, '.hermes', 'config.yaml');
  fs.mkdirSync(path.dirname(configFile), { recursive: true });
  fs.writeFileSync(configFile, config);
  const files = [configFile];

  for (const [relative, content] of Object.entries(extraFiles)) {
    const file = path.join(dir, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
    files.push(file);
  }
  return { dir, configFile, files };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

async function scan(config, extraFiles = {}) {
  const project = fixture(config, extraFiles);
  try {
    return await new HermesSecurityAgent().analyze({
      rootPath: project.dir,
      files: project.files,
      recon: {},
      options: {},
    });
  } finally {
    cleanup(project.dir);
  }
}

async function scanCheckedFixture(name) {
  const rootPath = path.resolve('cli/__tests__/fixtures/hermes-terminal-posture', name);
  const files = [path.join(rootPath, '.hermes', 'config.yaml')];
  const dockerfile = path.join(rootPath, 'Dockerfile');
  if (fs.existsSync(dockerfile)) files.push(dockerfile);
  return await new HermesSecurityAgent().analyze({ rootPath, files, recon: {}, options: {} });
}

function untrustedMcpConfig(backend) {
  return `
model: openrouter/test
terminal:
  backend: ${backend}
mcp_servers:
  contributor-tools:
    command: "npx"
    args: ["untrusted-mcp"]
    trust: untrusted
`;
}

describe('Hermes v0.21.0 terminal-backend posture', () => {
  it('enumerates every backend from the pinned release', () => {
    assert.deepEqual(Object.keys(HERMES_TERMINAL_BACKENDS), EXPECTED_BACKENDS);
    assert.equal(HERMES_TERMINAL_BACKENDS.local.terminal, 'host');
    for (const backend of EXPECTED_BACKENDS.slice(1)) {
      assert.equal(HERMES_TERMINAL_BACKENDS[backend].terminal, 'backend');
      assert.equal(HERMES_TERMINAL_BACKENDS[backend].file, 'backend');
    }
    assert.equal(HERMES_OPERATION_BOUNDARIES.executeCode.local, 'host child process');
    assert.equal(HERMES_OPERATION_BOUNDARIES.executeCode.nonLocal, 'terminal backend');
    for (const operation of ['mcp', 'plugin', 'hook', 'skill']) {
      assert.equal(HERMES_OPERATION_BOUNDARIES[operation].local, 'Hermes agent process');
      assert.equal(HERMES_OPERATION_BOUNDARIES[operation].nonLocal, 'Hermes agent process');
    }
  });

  it('does not report an explicitly selected local backend by itself', async () => {
    const findings = await scan(`
model: openrouter/test
terminal:
  backend: local
toolsets:
  - hermes-cli
`);
    assert.equal(findings.filter((finding) => finding.rule.startsWith('HERMES_')).length, 0);
  });

  it('reports local only when an enabled untrusted input path also reaches the host', async () => {
    const findings = await scan(untrustedMcpConfig('local'));
    const finding = findings.find((item) => item.rule === 'HERMES_LOCAL_BACKEND_UNTRUSTED_INPUT');
    assert.ok(finding);
    assert.equal(finding.posture, 'hygiene');
    assert.equal(finding.hermesBoundary.backend, 'local');
    assert.match(finding.hermesBoundary.claimedBoundary, /no OS isolation/);
    assert.equal(finding.hermesBoundary.reachableOperation, 'MCP subprocess "contributor-tools"');
    assert.equal(finding.hermesBoundary.evidence.length, 2);
  });

  for (const backend of EXPECTED_BACKENDS.slice(1)) {
    it(`reports the MCP host-process gap for ${backend}`, async () => {
      const findings = await scan(untrustedMcpConfig(backend));
      const finding = findings.find((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP');
      assert.ok(finding, `expected a scope-gap finding for ${backend}`);
      assert.equal(finding.posture, 'hygiene');
      assert.equal(finding.hermesBoundary.backend, backend);
      assert.match(finding.hermesBoundary.executesIn, /agent process/);
      assert.equal(finding.reachability, 'reachable');
      assert.equal(finding.exposure, 'external');
    });
  }

  it('does not report a trusted MCP server', async () => {
    const findings = await scan(`
model: openrouter/test
terminal:
  backend: docker
mcp_servers:
  internal:
    command: "internal-mcp"
    trust: full
`);
    assert.ok(!findings.some((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP'));
  });

  it('does not report a disabled untrusted MCP server', async () => {
    const findings = await scan(`
model: openrouter/test
terminal:
  backend: docker
mcp_servers:
  retired:
    command: "retired-mcp"
    trust: untrusted
    enabled: false
`);
    assert.ok(!findings.some((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP'));
  });

  it('parses comments and non-default YAML indentation without guessing', async () => {
    const findings = await scan(`
model: openrouter/test
terminal:
    # Keep commands off the workstation.
    backend: ssh
mcp_servers:
    "review-tools":
        command: "review-mcp"
        trust: untrusted
`);
    const finding = findings.find((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP');
    assert.ok(finding);
    assert.equal(finding.hermesBoundary.backend, 'ssh');
    assert.match(finding.hermesBoundary.input, /review-tools/);
  });

  it('accepts whole-process Docker wrapping as the safely constrained counterpart', async () => {
    const vulnerable = await scanCheckedFixture('vulnerable');
    const findings = await scanCheckedFixture('safe');
    assert.ok(vulnerable.some((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP'));
    assert.ok(!findings.some((item) =>
      item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP' ||
      item.rule === 'HERMES_LOCAL_BACKEND_UNTRUSTED_INPUT'
    ));
  });

  it('does not let an unrelated Hermes Dockerfile hide a direct deployment gap', async () => {
    const findings = await scan(untrustedMcpConfig('docker'), {
      Dockerfile: 'FROM python:3.12-slim\nRUN pip install hermes-agent==0.21.0\nENTRYPOINT ["hermes", "gateway"]\n',
    });
    assert.ok(findings.some((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP'));
  });

  it('keeps both posture rules out of the boundary-vulnerability set', () => {
    assert.equal(postureFor('HERMES_LOCAL_BACKEND_UNTRUSTED_INPUT'), 'hygiene');
    assert.equal(postureFor('HERMES_TERMINAL_BACKEND_SCOPE_GAP'), 'hygiene');
  });

  for (const format of ['--json', '--sarif']) {
    it(`renders boundary evidence in audit ${format.slice(2).toUpperCase()} output`, () => {
      const project = fixture(untrustedMcpConfig('docker'));
      try {
        const cli = path.resolve('cli/bin/ship-safe.js');
        const result = spawnSync(process.execPath, [
          cli,
          'audit',
          project.dir,
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
        assert.equal(result.error, undefined, result.error?.message);
        assert.equal(result.status, 0, result.stderr);
        const report = JSON.parse(result.stdout);

        if (format === '--json') {
          const finding = report.findings.find((item) => item.rule === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP');
          assert.ok(finding);
          assert.equal(finding.posture, 'hygiene');
          assert.equal(finding.hermesBoundary.backend, 'docker');
          assert.match(finding.hermesBoundary.reachableOperation, /MCP subprocess/);
        } else {
          const finding = report.runs[0].results.find((item) => item.ruleId === 'HERMES_TERMINAL_BACKEND_SCOPE_GAP');
          assert.ok(finding);
          assert.equal(finding.properties.posture, 'hygiene');
          assert.equal(finding.properties.hermesBackend, 'docker');
          assert.match(finding.properties.reachableOperation, /MCP subprocess/);
        }
      } finally {
        cleanup(project.dir);
      }
    });
  }
});
