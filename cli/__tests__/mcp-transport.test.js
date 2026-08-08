import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawn } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

test('MCP stdio waits for an asynchronous scan response before exiting', async () => {
  const cliPath = path.resolve('cli/bin/ship-safe.js');
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-mcp-transport-'));
  fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({ name: 'mcp-transport-fixture' }));
  fs.writeFileSync(path.join(fixture, 'app.js'), 'export const ready = true;\n');
  const request = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'scan_repo', arguments: { path: '.', agents: [] } },
  });

  try {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [cliPath, 'mcp'], { cwd: fixture });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error('MCP scan response timed out'));
      }, 60000);

      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', code => {
        clearTimeout(timer);
        resolve({ code, stdout, stderr });
      });
      child.stdin.end(`${request}\n`);
    });

    assert.equal(result.code, 0, result.stderr);
    const response = JSON.parse(result.stdout.trim());
    assert.equal(response.id, 1);
    assert.equal(response.error, undefined, response.error?.message);
    assert.equal(typeof response.result?.content?.[0]?.text, 'string');
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(typeof report.score, 'number');
    assert.match(report.grade, /^[A-F]$/);
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
