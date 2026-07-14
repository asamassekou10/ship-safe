/**
 * Ship Safe — MCPSecurityAgent auto-launch-on-trust
 * ==================================================
 *
 * Verifies MCP_AUTO_LAUNCH_ON_TRUST fires on repo-local project MCP configs
 * with a stdio command server, and not on remote-only or global configs.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { MCPSecurityAgent } from '../agents/mcp-security-agent.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-mcp-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

async function scan(dir, relFiles) {
  const files = relFiles.map((r) => path.join(dir, r));
  return new MCPSecurityAgent().analyze({ rootPath: dir, files, recon: {}, options: {} });
}

describe('MCPSecurityAgent — auto-launch on trust', () => {
  it('flags a project-local .mcp.json stdio command server', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
        mcpServers: { evil: { command: 'node', args: ['./.tools/server.js'] } },
      }));
      const f = await scan(dir, ['.mcp.json']);
      assert.ok(f.some((x) => x.rule === 'MCP_AUTO_LAUNCH_ON_TRUST' && x.severity === 'high'));
    } finally { cleanup(dir); }
  });

  it('flags a .cursor/mcp.json command server', async () => {
    const dir = tmp();
    try {
      fs.mkdirSync(path.join(dir, '.cursor'), { recursive: true });
      fs.writeFileSync(path.join(dir, '.cursor', 'mcp.json'), JSON.stringify({
        servers: { x: { command: 'python', args: ['run.py'] } },
      }));
      const f = await scan(dir, ['.cursor/mcp.json']);
      assert.ok(f.some((x) => x.rule === 'MCP_AUTO_LAUNCH_ON_TRUST'));
    } finally { cleanup(dir); }
  });

  it('does not flag a remote (url-only) server', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
        mcpServers: { remote: { url: 'https://mcp.example.com/sse' } },
      }));
      const f = await scan(dir, ['.mcp.json']);
      assert.equal(f.filter((x) => x.rule === 'MCP_AUTO_LAUNCH_ON_TRUST').length, 0);
    } finally { cleanup(dir); }
  });

  it('does not flag the global claude_desktop_config.json', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'claude_desktop_config.json'), JSON.stringify({
        mcpServers: { local: { command: 'node', args: ['server.js'] } },
      }));
      const f = await scan(dir, ['claude_desktop_config.json']);
      assert.equal(f.filter((x) => x.rule === 'MCP_AUTO_LAUNCH_ON_TRUST').length, 0);
    } finally { cleanup(dir); }
  });
});
