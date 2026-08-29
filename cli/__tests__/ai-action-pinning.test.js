import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, test } from 'node:test';

import { CICDScanner } from '../agents/cicd-scanner.js';

const FIXTURES = new URL('./fixtures/ai-actions/', import.meta.url);

function fixture(name) {
  return fs.readFileSync(new URL(name, FIXTURES), 'utf8');
}

async function scanWorkflow(content) {
  const rootPath = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-ai-action-'));
  try {
    const workflowDir = path.join(rootPath, '.github', 'workflows');
    fs.mkdirSync(workflowDir, { recursive: true });
    const file = path.join(workflowDir, 'ai-review.yml');
    fs.writeFileSync(file, content, 'utf8');

    const scanner = new CICDScanner();
    return await scanner.analyze({ rootPath, files: [file] });
  } finally {
    fs.rmSync(rootPath, { recursive: true, force: true });
  }
}

function aiActionFindings(findings) {
  return findings.filter(finding => finding.rule === 'CICD_AI_ACTION_UNPINNED');
}

describe('CICDScanner: AI action pinning', () => {
  test('flags an unpinned AI action with broad permissions as critical', async () => {
    const findings = await scanWorkflow(fixture('unsafe-unpinned.yml'));

    const [finding] = aiActionFindings(findings);
    assert.ok(finding, 'expected the AI-specific pinning rule to fire');
    assert.strictEqual(finding.severity, 'critical');
    assert.strictEqual(finding.line, 9);
    assert.strictEqual(finding.matched, 'vendor/ai-review@main');
  });

  test('uses the step name to recognize an AI action on pull_request_target', async () => {
    const findings = await scanWorkflow(`
on: pull_request_target
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: AI review
        uses: vendor/general-action@master
`);

    const [finding] = aiActionFindings(findings);
    assert.ok(finding, 'expected an AI-named step to be recognized');
    assert.strictEqual(finding.severity, 'critical');
  });

  test('flags an unpinned AI action even with read-only permissions', async () => {
    const findings = await scanWorkflow(`
on: [push]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/agent-review@v1
`);

    const [finding] = aiActionFindings(findings);
    assert.ok(finding, 'an unpinned AI action is still a supply-chain risk');
    assert.strictEqual(finding.severity, 'high');
  });

  test('stays quiet for a pinned AI action with read-only permissions', async () => {
    const findings = await scanWorkflow(fixture('safe-pinned.yml'));

    assert.strictEqual(aiActionFindings(findings).length, 0);
  });

  test('does not inherit broad permissions from a different job', async () => {
    const findings = await scanWorkflow(`
on: [push]
jobs:
  release:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
  review:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/ai-review@main
`);

    const [finding] = aiActionFindings(findings);
    assert.ok(finding);
    assert.strictEqual(finding.severity, 'high');
  });

  test('does not classify a non-AI action or a comment as an AI step', async () => {
    const findings = await scanWorkflow(`
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # AI review uses: vendor/ai-review@main
      - uses: actions/checkout@v4
`);

    assert.strictEqual(aiActionFindings(findings).length, 0);
  });
});
