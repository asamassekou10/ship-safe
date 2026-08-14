/**
 * cli/__tests__/ai-action-unpinned.test.js
 * =========================================
 *
 * Tests for the CICD_AI_ACTION_UNPINNED check in CICDScanner: an AI/agent
 * GitHub Action that floats on a mutable ref (@main, @v1, etc.) combined
 * with either broad write permissions or an unguarded pull_request_target
 * trigger.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { CICDScanner } from '../agents/cicd-scanner.js';

// ── Fixtures ─────────────────────────────────────────────────────────────

// UNSAFE: unpinned AI review action, job grants contents/pull-requests write.
const UNSAFE_BROAD_WRITE = `
name: AI PR Review
on:
  pull_request:
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/ai-pr-reviewer@main
        env:
          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
`;

// UNSAFE: unpinned AI action, pull_request_target trigger with no
// permissions block at all narrowing the default token.
const UNSAFE_PR_TARGET_UNGUARDED = `
name: AI Autofix
on:
  pull_request_target:
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/autofix-agent@v1
`;

// SAFE: same AI action, but pinned to a full commit SHA.
const SAFE_PINNED_SHA = `
name: AI PR Review
on:
  pull_request:
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/ai-pr-reviewer@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678
        env:
          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
`;

// SAFE: unpinned AI action, but permissions are read-only and there is no
// pull_request_target trigger.
const SAFE_READ_ONLY = `
name: AI PR Review
on:
  pull_request:
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/ai-pr-reviewer@main
`;

// SAFE: unpinned AI action on pull_request_target, but the job explicitly
// scopes the token down to contents: read.
const SAFE_PR_TARGET_SCOPED = `
name: AI Autofix
on:
  pull_request_target:
jobs:
  autofix:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/autofix-agent@v1
`;

// SAFE: unpinned action with broad write, but nothing AI/agent related.
const SAFE_NON_AI_ACTION = `
name: Deploy
on:
  push:
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/deploy-tool@main
`;

// ── Test harness ─────────────────────────────────────────────────────────

function writeFixture(dir, filename, content) {
  const workflowsDir = path.join(dir, '.github', 'workflows');
  fs.mkdirSync(workflowsDir, { recursive: true });
  const filePath = path.join(workflowsDir, filename);
  fs.writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

async function scanFixture(content, filename = 'ai-review.yml') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-ai-action-'));
  try {
    fs.mkdirSync(path.join(tmpDir, '.git'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, '.git', 'config'),
      '[remote "origin"]\n\turl = https://github.com/example-org/example-repo.git\n',
      'utf-8'
    );

    const filePath = writeFixture(tmpDir, filename, content);
    const scanner = new CICDScanner();
    const findings = await scanner.analyze({ rootPath: tmpDir, files: [filePath] });
    return findings;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ── Tests ────────────────────────────────────────────────────────────────

describe('CICDScanner: unpinned AI action with broad access', () => {
  test('flags an unpinned AI action with broad write permissions', async () => {
    const findings = await scanFixture(UNSAFE_BROAD_WRITE);
    const rule = findings.find(f => f.rule === 'CICD_AI_ACTION_UNPINNED');

    assert.ok(rule, 'expected CICD_AI_ACTION_UNPINNED to fire');
    assert.strictEqual(rule.severity, 'critical');
  });

  test('flags an unpinned AI action on unguarded pull_request_target', async () => {
    const findings = await scanFixture(UNSAFE_PR_TARGET_UNGUARDED);
    const rule = findings.find(f => f.rule === 'CICD_AI_ACTION_UNPINNED');

    assert.ok(rule, 'expected CICD_AI_ACTION_UNPINNED to fire');
  });

  test('does not flag a pinned AI action even with broad write permissions', async () => {
    const findings = await scanFixture(SAFE_PINNED_SHA);
    const rule = findings.find(f => f.rule === 'CICD_AI_ACTION_UNPINNED');

    assert.strictEqual(rule, undefined);
  });

  test('does not flag an unpinned AI action with read-only permissions', async () => {
    const findings = await scanFixture(SAFE_READ_ONLY);
    const rule = findings.find(f => f.rule === 'CICD_AI_ACTION_UNPINNED');

    assert.strictEqual(rule, undefined);
  });

  test('does not flag pull_request_target when permissions are explicitly scoped to read', async () => {
    const findings = await scanFixture(SAFE_PR_TARGET_SCOPED);
    const rule = findings.find(f => f.rule === 'CICD_AI_ACTION_UNPINNED');

    assert.strictEqual(rule, undefined);
  });

  test('does not flag a non-AI action even when unpinned with broad write', async () => {
    const findings = await scanFixture(SAFE_NON_AI_ACTION);
    const rule = findings.find(f => f.rule === 'CICD_AI_ACTION_UNPINNED');

    assert.strictEqual(rule, undefined);
  });
});
