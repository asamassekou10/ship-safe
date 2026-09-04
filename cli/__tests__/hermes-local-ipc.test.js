import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  HermesSecurityAgent,
  HERMES_IPC_SURFACES,
  HERMES_REACHABILITY_BASES,
  postureFor,
} from '../agents/hermes-security-agent.js';

const FIXTURES = path.resolve('cli/__tests__/fixtures/hermes-local-ipc');

async function scanFixture(name) {
  const rootPath = path.join(FIXTURES, name);
  const files = fs.readdirSync(rootPath).map((file) => path.join(rootPath, file));
  return new HermesSecurityAgent().analyze({ rootPath, files, recon: {}, options: {} });
}

async function scanSource(content) {
  const rootPath = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-hermes-ipc-'));
  const file = path.join(rootPath, 'app.py');
  fs.writeFileSync(file, content);
  try {
    return await new HermesSecurityAgent().analyze({ rootPath, files: [file], recon: {}, options: {} });
  } finally {
    fs.rmSync(rootPath, { recursive: true, force: true });
  }
}

describe('Hermes v0.21.0 ACP and TUI gateway boundaries', () => {
  it('records callers, transports, auth, bind scope, permissions, and effects', () => {
    assert.deepEqual(HERMES_REACHABILITY_BASES, ['configured', 'inferred', 'reproduced']);
    assert.match(HERMES_IPC_SURFACES.acp.transport, /stdio/);
    assert.match(HERMES_IPC_SURFACES.acp.authentication, /host-user/);
    assert.match(HERMES_IPC_SURFACES.acp.tool, /agent tool registry/);
    assert.match(HERMES_IPC_SURFACES.acp.permission, /not containment/);
    assert.match(HERMES_IPC_SURFACES.tui.transport, /stdio|socket/);
    assert.match(HERMES_IPC_SURFACES.tui.effect, /terminal actions/);
  });

  it('traces an unauthenticated non-loopback ACP route to agent effects', async () => {
    const findings = await scanFixture('acp-vulnerable');
    const finding = findings.find((item) => item.rule === 'HERMES_ACP_GATEWAY_EXPOSED');
    assert.ok(finding);
    assert.equal(finding.posture, 'boundary');
    assert.equal(finding.hermesBoundary.surface, 'acp');
    assert.equal(finding.hermesBoundary.caller, 'unauthenticated network peer');
    assert.equal(finding.hermesBoundary.handler, 'acp_gateway');
    assert.equal(finding.hermesBoundary.reachabilityBasis, 'configured');
    assert.match(finding.hermesBoundary.bindScope, /0\.0\.0\.0/);
    assert.match(finding.hermesBoundary.reachableOperation, /agent tool execution/);
    assert.equal(finding.hermesBoundary.tool, 'session agent tool registry');
    assert.equal(finding.hermesBoundary.evidence.length, 3);
  });

  it('keeps the ACP stdio/loopback counterpart quiet', async () => {
    const findings = await scanFixture('acp-safe');
    assert.ok(!findings.some((item) => item.rule === 'HERMES_ACP_GATEWAY_EXPOSED'));
  });

  it('traces an unauthenticated non-loopback TUI route to gateway actions', async () => {
    const findings = await scanFixture('tui-vulnerable');
    const finding = findings.find((item) => item.rule === 'HERMES_TUI_GATEWAY_EXPOSED');
    assert.ok(finding);
    assert.equal(finding.posture, 'boundary');
    assert.equal(finding.hermesBoundary.surface, 'tui');
    assert.equal(finding.hermesBoundary.handler, 'gateway_ws');
    assert.match(finding.hermesBoundary.permission, /not containment/);
    assert.match(finding.hermesBoundary.tool, /command\.dispatch/);
    assert.match(finding.hermesBoundary.effect, /plugin, MCP, and terminal/);
  });

  it('accepts fail-closed upgrade authentication on a non-loopback TUI route', async () => {
    const findings = await scanFixture('tui-safe');
    assert.ok(!findings.some((item) => item.rule === 'HERMES_TUI_GATEWAY_EXPOSED'));
  });

  it('does not combine a route with another application object\'s public bind', async () => {
    const findings = await scanSource(`
from fastapi import FastAPI, WebSocket
from tui_gateway.ws import handle_ws
import uvicorn
public_app = FastAPI()
local_app = FastAPI()
@local_app.websocket("/api/ws")
async def gateway_ws(ws: WebSocket):
    await handle_ws(ws)
uvicorn.run(public_app, host="0.0.0.0", port=9119)
`);
    assert.ok(!findings.some((item) => item.rule === 'HERMES_TUI_GATEWAY_EXPOSED'));
  });

  it('does not let authentication after dispatch hide the reachable path', async () => {
    const findings = await scanSource(`
from fastapi import FastAPI, WebSocket
from tui_gateway.ws import handle_ws
import uvicorn
app = FastAPI()
@app.websocket("/api/ws")
async def gateway_ws(ws: WebSocket):
    await handle_ws(ws)
    if not verify_ticket(ws):
        await ws.close(code=4401)
        return
uvicorn.run(app, host="0.0.0.0", port=9119)
`);
    assert.ok(findings.some((item) => item.rule === 'HERMES_TUI_GATEWAY_EXPOSED'));
  });

  it('classifies unauthenticated network re-exports as boundary findings', () => {
    assert.equal(postureFor('HERMES_ACP_GATEWAY_EXPOSED'), 'boundary');
    assert.equal(postureFor('HERMES_TUI_GATEWAY_EXPOSED'), 'boundary');
  });

  for (const format of ['--json', '--sarif']) {
    it(`renders the complete IPC chain in audit ${format.slice(2).toUpperCase()} output`, () => {
      const rootPath = path.join(FIXTURES, 'tui-vulnerable');
      const result = spawnSync(process.execPath, [
        path.resolve('cli/bin/ship-safe.js'),
        'audit',
        rootPath,
        '--hermes-only',
        '--no-deps',
        '--no-ai',
        '--no-cache',
        format,
      ], {
        cwd: path.resolve('.'),
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1' },
      });
      assert.equal(result.status, 0, result.stderr);
      const report = JSON.parse(result.stdout);

      if (format === '--json') {
        const finding = report.findings.find((item) => item.rule === 'HERMES_TUI_GATEWAY_EXPOSED');
        assert.ok(finding);
        assert.equal(finding.hermesBoundary.caller, 'unauthenticated network peer');
        assert.equal(finding.hermesBoundary.authentication, 'none before gateway dispatch');
        assert.equal(finding.hermesBoundary.reachabilityBasis, 'configured');
        assert.equal(finding.hermesBoundary.evidence.length, 3);
      } else {
        const finding = report.runs[0].results.find((item) => item.ruleId === 'HERMES_TUI_GATEWAY_EXPOSED');
        assert.ok(finding);
        assert.equal(finding.properties.hermesSurface, 'tui');
        assert.equal(finding.properties.caller, 'unauthenticated network peer');
        assert.equal(finding.properties.bindScope, 'non-loopback (0.0.0.0)');
        assert.match(finding.properties.reachableTool, /prompt\.submit/);
        assert.equal(finding.properties.reachabilityBasis, 'configured');
        assert.equal(finding.relatedLocations.length, 2);
      }
    });
  }
});
