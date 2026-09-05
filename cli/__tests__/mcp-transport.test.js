import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawn } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { PACKAGE_VERSION } from '../utils/package-version.js';

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

test('MCP initialize negotiates a supported protocol version', async () => {
  const cliPath = path.resolve('cli/bin/ship-safe.js');

  const initialize = (id, protocolVersion) => JSON.stringify({
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: 'fixture-client', version: '1.0.0' },
    },
  });

  const request = `${initialize(2, '2025-11-25')}\n${initialize(3, '2026-07-28')}`;

  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, 'mcp'], { cwd: process.cwd() });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('MCP initialize response timed out'));
    }, 10000);

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
  const responses = result.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(responses.map(item => item.id), [2, 3]);
  assert.deepEqual(
    responses.map(item => item.result.protocolVersion),
    ['2025-11-25', '2025-11-25'],
  );
});

test('MCP modern discovery and result envelopes stay separate from legacy output', async () => {
  const cliPath = path.resolve('cli/bin/ship-safe.js');
  const modernMeta = {
    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'fixture-client', version: '1.0.0' },
  };
  const requests = [
    { jsonrpc: '2.0', id: 10, method: 'server/discover' },
    { jsonrpc: '2.0', id: 11, method: 'tools/list', params: { _meta: modernMeta } },
    {
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/call',
      params: { name: 'get_checklist', arguments: {}, _meta: modernMeta },
    },
    {
      jsonrpc: '2.0',
      id: 13,
      method: 'tools/list',
      params: {
        _meta: { ...modernMeta, 'io.modelcontextprotocol/protocolVersion': '1999-01-01' },
      },
    },
    {
      jsonrpc: '2.0',
      id: 14,
      method: 'tools/list',
      params: { _meta: { ...modernMeta, 'io.modelcontextprotocol/protocolVersion': '2025-11-25' } },
    },
  ];

  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, 'mcp'], { cwd: process.cwd() });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('MCP modern protocol response timed out'));
    }, 10000);

    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(`${requests.map(request => JSON.stringify(request)).join('\n')}\n`);
  });

  assert.equal(result.code, 0, result.stderr);
  const responses = result.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(responses.map(response => response.id), [10, 11, 12, 13, 14]);

  const discovery = responses[0].result;
  assert.deepEqual(discovery.supportedVersions, ['2026-07-28', '2025-11-25', '2024-11-05']);
  assert.equal(discovery.resultType, 'complete');
  assert.equal(discovery.ttlMs, 300000);
  assert.equal(discovery.cacheScope, 'public');
  assert.deepEqual(discovery._meta['io.modelcontextprotocol/serverInfo'], {
    name: 'ship-safe',
    version: PACKAGE_VERSION,
  });

  const modernList = responses[1].result;
  assert.equal(modernList.resultType, 'complete');
  assert.equal(modernList.ttlMs, 300000);
  assert.equal(modernList.cacheScope, 'public');
  assert.ok(Array.isArray(modernList.tools));
  assert.equal(modernList._meta['io.modelcontextprotocol/serverInfo'].name, 'ship-safe');

  const modernCall = responses[2].result;
  assert.equal(modernCall.resultType, 'complete');
  assert.ok(Array.isArray(modernCall.content));
  assert.equal(modernCall._meta['io.modelcontextprotocol/serverInfo'].name, 'ship-safe');

  assert.equal(responses[3].error.code, -32022);
  assert.deepEqual(responses[3].error.data.supported, ['2026-07-28', '2025-11-25', '2024-11-05']);
  assert.equal(responses[3].error.data.requested, '1999-01-01');

  const legacyList = responses[4].result;
  assert.ok(Array.isArray(legacyList.tools));
  assert.equal(legacyList.resultType, undefined);
  assert.equal(legacyList.ttlMs, undefined);
  assert.equal(legacyList.cacheScope, undefined);
  assert.equal(legacyList._meta, undefined);
});
