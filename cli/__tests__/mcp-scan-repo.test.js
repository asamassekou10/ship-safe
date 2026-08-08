import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { scanRepo, suppressFinding } from '../commands/mcp.js';

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

test('MCP suppress_finding refuses paths outside the workspace', () => {
  const outsidePath = path.join(os.tmpdir(), `ship-safe-outside-${Date.now()}.js`);
  const original = 'const value = true;\n';
  fs.writeFileSync(outsidePath, original);

  try {
    const result = suppressFinding({ file: outsidePath, line: 1, reason: 'test' });

    assert.match(result.error, /within the MCP workspace/);
    assert.equal(fs.readFileSync(outsidePath, 'utf8'), original);
  } finally {
    fs.rmSync(outsidePath, { force: true });
  }
});

test('MCP suppress_finding refuses symlinked paths outside the workspace', () => {
  const linkPath = path.join(process.cwd(), `.ship-safe-test-link-${Date.now()}`);
  fs.symlinkSync(os.tmpdir(), linkPath, 'dir');

  try {
    const result = suppressFinding({
      file: path.join(linkPath, 'target.js'),
      line: 1,
      reason: 'test',
    });

    assert.match(result.error, /resolve within the MCP workspace/);
  } finally {
    fs.rmSync(linkPath, { force: true });
  }
});
