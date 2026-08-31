/**
 * cli/__tests__/npm-publish-provenance.test.js
 * =============================================
 *
 * Tests for the npm publish provenance checks in CICDScanner:
 *   - CICD_NPM_PUBLISH_PROVENANCE_DISABLED
 *   - CICD_NPM_PUBLISH_NO_PROVENANCE
 *   - CICD_NPM_PUBLISH_MISSING_ID_TOKEN
 *
 * Adjust the import path below to match where CICDScanner actually lives
 * relative to this test file (it should mirror the other test files in
 * cli/__tests__/, e.g. upstream-ingestion.test.js).
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { CICDScanner } from '../agents/cicd-scanner.js';

// ── Fixtures ─────────────────────────────────────────────────────────────

// UNSAFE: publishes with a long-lived NPM_TOKEN, no provenance mentioned
// anywhere in the file. Should trigger CICD_NPM_PUBLISH_NO_PROVENANCE.
const UNSAFE_NO_PROVENANCE = `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: \${{ secrets.NPM_TOKEN }}
`;

// UNSAFE: provenance explicitly turned off. Should trigger
// CICD_NPM_PUBLISH_PROVENANCE_DISABLED.
const UNSAFE_PROVENANCE_DISABLED = `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f
        with:
          node-version: '20'
      - run: npm ci
      - run: npm publish --provenance=false
        env:
          NODE_AUTH_TOKEN: \${{ secrets.NPM_TOKEN }}
`;

// UNSAFE: provenance/trusted publishing is referenced, but the job never
// requests id-token: write, so the OIDC token needed for provenance can't
// actually be minted. Should trigger CICD_NPM_PUBLISH_MISSING_ID_TOKEN.
const UNSAFE_MISSING_ID_TOKEN = `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f
        with:
          node-version: '20'
      - run: npm ci
      # Trusted publishing is intended here, but the OIDC permission is
      # not requested anywhere in this job.
      - run: npm publish --provenance
`;

// SAFE: provenance intended, id-token: write present, no disabling flag,
// no bare NPM_TOKEN reliance. Should be quiet.
const SAFE_PROVENANCE_AWARE = `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm publish --provenance
`;

// UNSAFE: a comment merely discusses provenance/id-token, but the actual
// config still uses a bare NPM_TOKEN with no id-token permission anywhere.
// A naive regex match against raw file text (comments included) would be
// fooled into silence by this. Should still trigger both
// CICD_NPM_PUBLISH_NO_PROVENANCE... actually since the comment mentions
// "trusted publishing", NO_PROVENANCE would be masked by design (the
// mention could be genuine intent) — but MISSING_ID_TOKEN must still fire,
// since intent without id-token: write is unsafe regardless of whether
// the mention was in a comment or a real setting.
const UNSAFE_PROVENANCE_MENTIONED_ONLY_IN_COMMENT = `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f
        with:
          node-version: '20'
      - run: npm ci
      # We should eventually set up trusted publishing here, and add
      # id-token: write once we do.
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: \${{ secrets.NPM_TOKEN }}
`;

// SAFE: no npm publish step at all — the rule should not fire on unrelated
// workflows just because NPM_TOKEN or id-token appear elsewhere.
const SAFE_NO_PUBLISH_STEP = `
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f
      - run: npm ci
      - run: npm test
`;

const CLOUD_OIDC_WITHOUT_SUBJECT = `
name: Deploy
on: [push]
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
      - run: ./deploy.sh
`;

const CLOUD_OIDC_SCOPED = CLOUD_OIDC_WITHOUT_SUBJECT.replace(
  'role-to-assume: arn:aws:iam::123456789012:role/deploy',
  'role-to-assume: arn:aws:iam::123456789012:role/deploy\n          subject: repo:example-org/example-repo:ref:refs/heads/main'
);

const CLOUD_OIDC_BROAD = CLOUD_OIDC_WITHOUT_SUBJECT.replace(
  'role-to-assume: arn:aws:iam::123456789012:role/deploy',
  'role-to-assume: arn:aws:iam::123456789012:role/deploy\n          subject: repo:*'
);

// ── Test harness ─────────────────────────────────────────────────────────

function writeFixture(dir, filename, content) {
  const workflowsDir = path.join(dir, '.github', 'workflows');
  fs.mkdirSync(workflowsDir, { recursive: true });
  const filePath = path.join(workflowsDir, filename);
  fs.writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

async function scanFixture(content, filename = 'publish.yml') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-npm-publish-'));
  try {
    // Minimal fake git config so selfOwner() resolution doesn't blow up —
    // mirrors what a real cloned repo would have.
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

describe('CICDScanner: npm publish provenance', () => {
  test('flags npm publish with NPM_TOKEN and no provenance mention', async () => {
    const findings = await scanFixture(UNSAFE_NO_PROVENANCE);
    const rule = findings.find(f => f.rule === 'CICD_NPM_PUBLISH_NO_PROVENANCE');

    assert.ok(rule, 'expected CICD_NPM_PUBLISH_NO_PROVENANCE to fire');
    assert.strictEqual(rule.severity, 'medium');
  });

  test('flags npm publish --provenance=false', async () => {
    const findings = await scanFixture(UNSAFE_PROVENANCE_DISABLED);
    const rule = findings.find(f => f.rule === 'CICD_NPM_PUBLISH_PROVENANCE_DISABLED');

    assert.ok(rule, 'expected CICD_NPM_PUBLISH_PROVENANCE_DISABLED to fire');
    assert.strictEqual(rule.severity, 'high');
  });

  test('flags provenance intent without id-token: write', async () => {
    const findings = await scanFixture(UNSAFE_MISSING_ID_TOKEN);
    const rule = findings.find(f => f.rule === 'CICD_NPM_PUBLISH_MISSING_ID_TOKEN');

    assert.ok(rule, 'expected CICD_NPM_PUBLISH_MISSING_ID_TOKEN to fire');
    assert.strictEqual(rule.severity, 'medium');
  });

  test('stays quiet on a provenance-aware publish workflow', async () => {
    const findings = await scanFixture(SAFE_PROVENANCE_AWARE);
    const npmRules = findings.filter(f => f.rule.startsWith('CICD_NPM_PUBLISH_'));

    assert.strictEqual(npmRules.length, 0);
  });

  test('does not fire when there is no npm publish step', async () => {
    const findings = await scanFixture(SAFE_NO_PUBLISH_STEP);
    const npmRules = findings.filter(f => f.rule.startsWith('CICD_NPM_PUBLISH_'));

    assert.strictEqual(npmRules.length, 0);
  });

  test('does not let a comment-only mention of provenance mask NO_PROVENANCE', async () => {
    // The word "trusted publishing" only appears inside a YAML comment here.
    // Comments are stripped before matching, so this must be treated the
    // same as if provenance were never mentioned at all.
    const findings = await scanFixture(UNSAFE_PROVENANCE_MENTIONED_ONLY_IN_COMMENT);
    const rule = findings.find(f => f.rule === 'CICD_NPM_PUBLISH_NO_PROVENANCE');

    assert.ok(rule, 'a comment mentioning provenance must not silence the NO_PROVENANCE finding');
  });

  test('does not duplicate the existing write-all permission finding', async () => {
    // A publish workflow with permissions: write-all should still be
    // caught by the existing generic CICD_EXCESSIVE_PERMISSIONS rule,
    // not by a second npm-specific rule.
    const content = UNSAFE_NO_PROVENANCE.replace(
      'runs-on: ubuntu-latest',
      'runs-on: ubuntu-latest\n    permissions: write-all'
    );
    const findings = await scanFixture(content);

    const generic = findings.filter(f => f.rule === 'CICD_EXCESSIVE_PERMISSIONS');
    const npmSpecificWriteAll = findings.filter(f => f.rule === 'CICD_NPM_PUBLISH_WRITE_ALL');

    assert.ok(generic.length > 0, 'expected the existing generic permission rule to still fire');
    assert.strictEqual(npmSpecificWriteAll.length, 0);
  });

  test('scopes OIDC subject checks to cloud-provider workflows', async () => {
    const unrelated = await scanFixture(SAFE_PROVENANCE_AWARE);
    assert.strictEqual(
      unrelated.filter(f => f.rule.startsWith('CICD_OIDC_')).length,
      0,
      'npm provenance alone must not create a cloud OIDC finding'
    );

    const missing = await scanFixture(CLOUD_OIDC_WITHOUT_SUBJECT, 'deploy.yml');
    assert.ok(missing.some(f => f.rule === 'CICD_OIDC_MISSING_SUBJECT'));

    const scoped = await scanFixture(CLOUD_OIDC_SCOPED, 'deploy.yml');
    assert.strictEqual(scoped.filter(f => f.rule.startsWith('CICD_OIDC_')).length, 0);

    const broad = await scanFixture(CLOUD_OIDC_BROAD, 'deploy.yml');
    const broadRule = broad.find(f => f.rule === 'CICD_OIDC_BROAD_SUBJECT');
    assert.ok(broadRule);
    assert.strictEqual(broadRule.severity, 'critical');
  });
});
