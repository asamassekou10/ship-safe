import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { scanRepo } from '../commands/mcp.js';

test('MCP scan_repo returns a scored report', async () => {
  const rootPath = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-mcp-'));

  try {
    fs.writeFileSync(path.join(rootPath, 'package.json'), JSON.stringify({ name: 'mcp-fixture' }));
    fs.writeFileSync(path.join(rootPath, 'app.js'), 'export const ready = true;\n');

    const report = await scanRepo({ path: rootPath, agents: [] });

    assert.equal(report.error, undefined);
    assert.equal(typeof report.score, 'number');
    assert.match(report.grade, /^[A-F]$/);
    assert.equal(typeof report.totalFindings, 'number');
    assert.match(report.summary, /Score: \d+(?:\.\d+)?\/100/);
  } finally {
    fs.rmSync(rootPath, { recursive: true, force: true });
  }
});
