/**
 * Ship Safe — interactive shell
 * =============================
 *
 * Regression coverage for issue #34:
 * `/scan` followed by `/findings` must remain inside the Ship Safe REPL.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { createShellState, handleSlashCommand } from '../commands/shell.js';

function tempDir(prefix = 'ship-safe-shell-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
}

async function captureConsole(fn) {
  const logs = [];
  const originalLog = console.log;
  console.log = (...args) => {
    logs.push(args.join(' '));
  };

  try {
    const result = await fn();
    return { result, output: logs.join('\n') };
  } finally {
    console.log = originalLog;
  }
}

describe('interactive shell slash commands', () => {
  it('keeps running after /scan and shows /findings from the last scan', async () => {
    const dir = tempDir();
    try {
      const state = createShellState(dir);
      let receivedOptions = null;
      const fakeAudit = async (_root, options) => {
        receivedOptions = options;
        return {
          score: 42,
          findings: [
            {
              severity: 'high',
              title: 'Hardcoded API key',
              file: path.join(dir, 'app.js'),
              line: 7,
            },
          ],
        };
      };

      const scan = await captureConsole(() =>
        handleSlashCommand('/scan', state, { _auditCommand: fakeAudit }),
      );
      assert.equal(scan.result, true, '/scan should keep the shell running');
      assert.equal(state.lastScan?.findings?.length, 1);
      assert.equal(receivedOptions?._agenticInner, true, '/scan must not let auditCommand call process.exit');

      const findings = await captureConsole(() =>
        handleSlashCommand('/findings', state, { _auditCommand: fakeAudit }),
      );
      assert.equal(findings.result, true, '/findings should keep the shell running');
      assert.match(findings.output, /Hardcoded API key/);
      assert.match(findings.output, /\[HIGH\]/);
    } finally {
      cleanup(dir);
    }
  });
});
