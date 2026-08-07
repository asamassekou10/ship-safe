import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cliPath = path.join(repoRoot, 'cli', 'bin', 'ship-safe.js');

function withTempDirectory(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-scan-mcp-'));
  try {
    return callback(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function scan(target) {
  return spawnSync(process.execPath, [cliPath, 'scan-mcp', target, '--json'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

function parseJson(result) {
  assert.equal(result.error, undefined, result.error?.message);
  const json = result.stdout.match(/\n(\{[\s\S]*\})\s*$/);
  assert.ok(json, `Expected JSON output, got:\n${result.stdout}`);
  return JSON.parse(json[1]);
}

test('scans an empty directory without reading it as a manifest', () => {
  withTempDirectory(directory => {
    const result = scan(directory);
    const report = parseJson(result);

    assert.equal(result.status, 0);
    assert.ok(result.stdout.includes(`No MCP configuration files found in ${directory}`));
    assert.match(result.stdout, /mcp\.json/);
    assert.deepEqual(report.configs, []);
    assert.equal(report.configCount, 0);
    assert.deepEqual(report.findings, []);
    assert.deepEqual(report.summary, { total: 0, critical: 0, high: 0, medium: 0 });
  });
});

test('discovers editor MCP configs in canonical order with relative findings', () => {
  withTempDirectory(directory => {
    fs.mkdirSync(path.join(directory, '.vscode'));
    fs.mkdirSync(path.join(directory, '.cursor'));
    fs.writeFileSync(path.join(directory, '.vscode', 'mcp.json'), '{}');
    fs.writeFileSync(path.join(directory, '.cursor', 'mcp.json'), JSON.stringify({
      mcpServers: {
        unsafe: { command: 'npx', args: ['@modelcontextprotocol/server-filesyste'] },
      },
    }));

    const result = scan(directory);
    const report = parseJson(result);

    assert.equal(result.status, 1);
    assert.deepEqual(report.configs, ['.cursor/mcp.json', '.vscode/mcp.json']);
    assert.equal(report.configCount, 2);
    assert.ok(report.findings.length > 0);
    assert.ok(report.findings.every(finding => finding.file === '.cursor/mcp.json'));
    assert.equal(report.summary.critical > 0, true);
  });
});

test('preserves regular manifest tool counts', () => {
  withTempDirectory(directory => {
    const manifest = path.join(directory, 'manifest.json');
    fs.writeFileSync(manifest, JSON.stringify({ tools: [{ name: 'search', description: 'Search documents.' }] }));

    const result = scan(manifest);
    const report = parseJson(result);

    assert.equal(result.status, 0);
    assert.equal(report.toolCount, 1);
  });
});

test('reports a missing scan target readably', () => {
  withTempDirectory(directory => {
    const missing = path.join(directory, 'missing.json');
    const result = scan(missing);

    assert.equal(result.status, 1);
    assert.match(result.stdout, /File not found:/);
    assert.ok(result.stdout.includes(missing));
  });
});
