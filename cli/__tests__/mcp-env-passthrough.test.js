/**
 * Ship Safe — MCPSecurityAgent env secret passthrough
 * ===================================================
 *
 * Verifies MCP_ENV_SECRET_PASSTHROUGH fires on repo-local project MCP configs
 * that pass secret-like env vars into tool processes.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { MCPSecurityAgent } from '../agents/mcp-security-agent.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-mcp-env-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

async function scan(dir, relFiles) {
  const files = relFiles.map((r) => path.join(dir, r));
  return new MCPSecurityAgent().analyze({ rootPath: dir, files, recon: {}, options: {} });
}

describe('MCPSecurityAgent — env secret passthrough', () => {
  it('flags secret-like env vars in a project-local .mcp.json', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
        mcpServers: {
          example: {
            command: 'node',
            args: ['server.js'],
            env: {
              OPENAI_API_KEY: '${OPENAI_API_KEY}',
              AWS_SECRET_ACCESS_KEY: '${AWS_SECRET_ACCESS_KEY}',
            },
          },
        },
      }));
      const f = await scan(dir, ['.mcp.json']);
      const hits = f.filter((x) => x.rule === 'MCP_ENV_SECRET_PASSTHROUGH');
      assert.equal(hits.length, 2);
      assert.ok(hits.every((x) => x.severity === 'high'));
      assert.ok(hits.some((x) => x.matched === 'OPENAI_API_KEY'));
      assert.ok(hits.some((x) => x.matched === 'AWS_SECRET_ACCESS_KEY'));
    } finally { cleanup(dir); }
  });

  it('does not flag benign operational env vars', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
        mcpServers: {
          example: {
            command: 'node',
            args: ['server.js'],
            env: { LOG_LEVEL: 'info', NODE_ENV: 'production' },
          },
        },
      }));
      const f = await scan(dir, ['.mcp.json']);
      assert.equal(f.filter((x) => x.rule === 'MCP_ENV_SECRET_PASSTHROUGH').length, 0);
    } finally { cleanup(dir); }
  });

  it('does not flag tokenizer or token-limit env names', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
        mcpServers: {
          example: {
            command: 'node',
            args: ['server.js'],
            env: { MAX_TOKENS: '4096', TOKENIZER_MODEL: 'gpt-4' },
          },
        },
      }));
      const f = await scan(dir, ['.mcp.json']);
      assert.equal(f.filter((x) => x.rule === 'MCP_ENV_SECRET_PASSTHROUGH').length, 0);
    } finally { cleanup(dir); }
  });

  it('flags secret env vars in .cursor/mcp.json', async () => {
    const dir = tmp();
    try {
      fs.mkdirSync(path.join(dir, '.cursor'), { recursive: true });
      fs.writeFileSync(path.join(dir, '.cursor', 'mcp.json'), JSON.stringify({
        servers: {
          example: {
            command: 'node',
            args: ['server.js'],
            env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' },
          },
        },
      }));
      const f = await scan(dir, ['.cursor/mcp.json']);
      assert.ok(f.some((x) => x.rule === 'MCP_ENV_SECRET_PASSTHROUGH' && x.matched === 'GITHUB_TOKEN'));
    } finally { cleanup(dir); }
  });

  it('does not flag the global claude_desktop_config.json', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'claude_desktop_config.json'), JSON.stringify({
        mcpServers: {
          example: {
            command: 'node',
            args: ['server.js'],
            env: { OPENAI_API_KEY: '${OPENAI_API_KEY}' },
          },
        },
      }));
      const f = await scan(dir, ['claude_desktop_config.json']);
      assert.equal(f.filter((x) => x.rule === 'MCP_ENV_SECRET_PASSTHROUGH').length, 0);
    } finally { cleanup(dir); }
  });

  it('does not flag remote servers without an env block', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
        mcpServers: { remote: { url: 'https://mcp.example.com/sse' } },
      }));
      const f = await scan(dir, ['.mcp.json']);
      assert.equal(f.filter((x) => x.rule === 'MCP_ENV_SECRET_PASSTHROUGH').length, 0);
    } finally { cleanup(dir); }
  });
});
