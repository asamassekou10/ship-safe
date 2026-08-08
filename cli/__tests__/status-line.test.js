import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const statusLine = path.resolve('cli/hooks/status-line.js');

function runStatusLine(home) {
  return execFileSync(process.execPath, [statusLine], {
    env: { ...process.env, HOME: home, USERPROFILE: home },
    encoding: 'utf8',
  });
}

test('Claude status line stays inactive until both hooks are registered', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-statusline-'));

  try {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.mkdirSync(path.join(home, '.ship-safe', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({
      hooks: { PreToolUse: [], PostToolUse: [] },
      statusLine: { command: `node "${path.join(home, '.ship-safe', 'hooks', 'status-line.js')}"` },
    }));

    assert.match(runStatusLine(home), /Ship Safe inactive/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('Claude status line shows protection only for a complete hook installation', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-statusline-'));
  const hookDir = path.join(home, '.ship-safe', 'hooks');

  try {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.mkdirSync(hookDir, { recursive: true });
    const pre = path.join(hookDir, 'pre-tool-use.js');
    const post = path.join(hookDir, 'post-tool-use.js');
    const status = path.join(hookDir, 'status-line.js');
    fs.writeFileSync(pre, '');
    fs.writeFileSync(post, '');
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({
      hooks: {
        PreToolUse: [{ hooks: [{ command: `node "${pre}"` }] }],
        PostToolUse: [{ hooks: [{ command: `node "${post}"` }] }],
      },
      statusLine: { command: `node "${status}"` },
    }));

    assert.match(runStatusLine(home), /Protected by Ship Safe/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
