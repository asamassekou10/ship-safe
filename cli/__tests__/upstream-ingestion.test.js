/**
 * Ungoverned continuous ingestion tests
 * =====================================
 *
 * A pipeline that resolves a mutable third-party reference, builds it, and
 * deploys it with no human gate hands upstream control of production. No line
 * of such a workflow is dangerous alone, so the line-by-line CI rules cannot
 * see it — these cover the whole-file chain analysis that can.
 *
 * The positive fixtures are this repository's own `update-hermes-image.yml`,
 * before and after it was fixed. Real files rather than invented ones: the
 * first draft of these rules passed on synthetic YAML and missed both real
 * cases, because the actual workflow builds its API URL from a shell variable
 * and wraps its deploy command across lines.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

import { CICDScanner } from '../agents/cicd-scanner.js';

// Not `import.meta.dirname` — that landed in Node 20.11 and this package
// supports >=18, so it is undefined on the oldest version CI runs.
const HERE = path.dirname(fileURLToPath(import.meta.url));

const CHAIN_RULES = /^(CICD_UNATTENDED_UPSTREAM_DEPLOY|CICD_UNPINNED_UPSTREAM_BUILD|CICD_NO_DEPLOY_APPROVAL)$/;
const HANDOFF_RULES = /^(CICD_PR_TARGET_UNSAFE_CHECKOUT|CICD_PR_TARGET_EXECUTES_UNTRUSTED_CODE|CICD_WORKFLOW_RUN_UNVERIFIED_ARTIFACT_EXEC)$/;

/** Build a throwaway repo containing one workflow, owned by `owner`. */
function workspace(yaml, owner = 'someone-else') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-ingest-'));
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, '.git', 'config'),
    `[remote "origin"]\n\turl = https://github.com/${owner}/its-repo.git\n`,
  );
  const file = path.join(dir, '.github', 'workflows', 'w.yml');
  fs.writeFileSync(file, yaml);
  return { dir, file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

async function chainFindings(yaml, owner) {
  const ws = workspace(yaml, owner);
  try {
    const findings = await new CICDScanner().analyze({ rootPath: ws.dir, files: [ws.file] });
    return findings.filter(f => CHAIN_RULES.test(f.rule));
  } finally {
    ws.cleanup();
  }
}

async function handoffFindings(yaml, owner) {
  const ws = workspace(yaml, owner);
  try {
    const findings = await new CICDScanner().analyze({ rootPath: ws.dir, files: [ws.file] });
    return findings.filter(f => HANDOFF_RULES.test(f.rule));
  } finally {
    ws.cleanup();
  }
}

function readFixture(name) {
  return fs.readFileSync(path.join(HERE, 'fixtures', name), 'utf-8');
}

describe('ungoverned continuous ingestion — real workflows', () => {
  it('flags tracking an upstream branch straight to production as critical', async () => {
    const found = await chainFindings(readFixture('hermes-workflow-before.yml'));
    const deploy = found.find(f => f.rule === 'CICD_UNATTENDED_UPSTREAM_DEPLOY');
    assert.ok(deploy, 'the full chain should be reported');
    assert.equal(deploy.severity, 'critical');
    assert.match(deploy.matched, /commits\/main/);
  });

  it('still flags tracking an upstream release, one band lower', async () => {
    // The remediated workflow tracks a published release instead of a branch.
    // That is better, not safe: it still deploys unattended with no approval,
    // so it must not come back clean.
    const found = await chainFindings(readFixture('hermes-workflow-after.yml'));
    const deploy = found.find(f => f.rule === 'CICD_UNATTENDED_UPSTREAM_DEPLOY');
    assert.ok(deploy, 'release tracking is still ungoverned ingestion');
    assert.equal(deploy.severity, 'high');
    assert.match(deploy.matched, /releases\/latest/);
  });

  it('reports the missing approval gate independently', async () => {
    const found = await chainFindings(readFixture('hermes-workflow-before.yml'));
    assert.ok(found.some(f => f.rule === 'CICD_NO_DEPLOY_APPROVAL'));
  });
});

describe('ungoverned continuous ingestion — must not fire', () => {
  it('ignores a workflow building its own repository', async () => {
    const yaml = `
on:
  schedule:
    - cron: '0 3 * * *'
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          SHA=$(curl -s https://api.github.com/repos/acme/its-repo/commits/main | jq -r .sha)
          docker build --build-arg SHA=$SHA .
      - uses: docker/build-push-action@v6
        with:
          push: true
`;
    assert.deepEqual(await chainFindings(yaml, 'acme'), []);
  });

  it('ignores an auto-update job that opens a pull request', async () => {
    // Opening a PR *is* the human gate.
    const yaml = `
on:
  schedule:
    - cron: '0 3 * * *'
jobs:
  bump:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://api.github.com/repos/upstream/dep/releases/latest
      - uses: peter-evans/create-pull-request@v6
`;
    assert.deepEqual(await chainFindings(yaml), []);
  });

  it('downgrades a deploy to a non-production environment', async () => {
    const yaml = `
on:
  schedule:
    - cron: '0 3 * * *'
jobs:
  ship:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - run: curl -s https://api.github.com/repos/upstream/dep/commits/main
      - run: kubectl rollout restart deploy/api
`;
    const found = await chainFindings(yaml);
    assert.ok(!found.some(f => f.severity === 'critical'), 'staging must not be critical');
  });

  it('ignores a pinned upstream reference', async () => {
    const yaml = `
on:
  schedule:
    - cron: '0 3 * * *'
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: git clone --branch v1.4.2 https://github.com/upstream/dep
      - uses: docker/build-push-action@v6
        with:
          push: true
`;
    assert.deepEqual(await chainFindings(yaml), []);
  });

  it('ignores an ordinary test workflow', async () => {
    const yaml = `
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
`;
    assert.deepEqual(await chainFindings(yaml), []);
  });

  it('ignores a manually triggered deploy', async () => {
    // No schedule means a human started it.
    const yaml = `
on:
  workflow_dispatch:
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://api.github.com/repos/upstream/dep/commits/main
      - run: kubectl rollout restart deploy/api
`;
    const found = await chainFindings(yaml);
    assert.ok(!found.some(f => f.rule === 'CICD_UNATTENDED_UPSTREAM_DEPLOY'));
  });
});

describe('privileged PR and artifact handoffs', () => {
  it('flags pull_request_target when it checks out and runs PR-controlled code', async () => {
    const yaml = `
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: write
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: \${{ github.event.pull_request.head.repo.full_name }}
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
`;
    const found = await handoffFindings(yaml);
    assert.ok(found.some(f => f.rule === 'CICD_PR_TARGET_UNSAFE_CHECKOUT'));
    assert.ok(found.some(f => f.rule === 'CICD_PR_TARGET_EXECUTES_UNTRUSTED_CODE'));
    assert.ok(found.every(f => f.severity === 'critical'));
  });

  it('flags workflow_run when it executes an artifact without verification', async () => {
    const yaml = `
on:
  workflow_run:
    workflows: ["PR build"]
    types: [completed]
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: pr-build
      - run: |
          chmod +x ./dist/release.sh
          ./dist/release.sh
`;
    const found = await handoffFindings(yaml);
    const artifact = found.find(f => f.rule === 'CICD_WORKFLOW_RUN_UNVERIFIED_ARTIFACT_EXEC');
    assert.ok(artifact);
    assert.equal(artifact.severity, 'critical');
  });

  it('does not flag workflow_run artifact execution when the artifact is verified first', async () => {
    const yaml = `
on:
  workflow_run:
    workflows: ["PR build"]
    types: [completed]
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: pr-build
      - run: |
          echo "$EXPECTED_SHA  dist/release.sh" | sha256sum -c -
          bash ./dist/release.sh
`;
    const found = await handoffFindings(yaml);
    assert.ok(!found.some(f => f.rule === 'CICD_WORKFLOW_RUN_UNVERIFIED_ARTIFACT_EXEC'));
  });

  it('does not flag pull_request_target workflows that only touch metadata', async () => {
    const yaml = `
on:
  pull_request_target:
    types: [opened]
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
`;
    assert.deepEqual(await handoffFindings(yaml), []);
  });
});
