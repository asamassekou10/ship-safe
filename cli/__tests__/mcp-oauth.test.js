/**
 * Ship Safe — MCPSecurityAgent OAuth and token-boundary fixtures
 * ===============================================================
 *
 * Regression coverage for issue #104.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { MCPSecurityAgent } from '../agents/mcp-security-agent.js';

function fixture(content, ext = '.js') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-mcp-oauth-'));
  const file = path.join(dir, `server${ext}`);
  fs.writeFileSync(file, content);
  return { dir, file };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

async function scan(content, ext = '.js') {
  const { dir, file } = fixture(content, ext);
  try {
    return await new MCPSecurityAgent().analyze({
      rootPath: dir,
      files: [file],
      recon: {},
      options: {},
    });
  } finally {
    cleanup(dir);
  }
}

describe('MCPSecurityAgent — OAuth security rules', () => {
  it('flags an MCP tool that forwards an inbound bearer token downstream', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('search', async (request) => {
        const authorization = request.headers.authorization;
        return fetch('https://api.example.com/search', {
          headers: { Authorization: authorization },
        });
      });
    `);

    const hits = findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'high');
    assert.match(hits[0].matched, /fetch/i);
    assert.match(hits[0].description, /audience/i);
  });

  it('flags a direct inbound authorization header passed to fetch', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('search', async (request) => fetch('https://api.example.com/search', {
        headers: { Authorization: request.headers.authorization },
      }));
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 1);
    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('flags an inbound MCP token that is accepted without audience validation', async () => {
    const findings = await scan(`
      import jwt from 'jsonwebtoken';
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const token = request.headers.authorization?.replace(/^Bearer\\s+/i, '');
        const claims = jwt.verify(token, process.env.MCP_PUBLIC_KEY);
        return claims.sub;
      });
    `);

    const hits = findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'high');
    assert.match(hits[0].description, /audience/i);
  });

  it('flags a static OAuth client id combined with dynamic registration', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        client_id: 'mcp-proxy-production',
        dynamic_client_registration: true,
      };
    `);

    const hits = findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'high');
    assert.match(hits[0].description, /confused deputy/i);
  });

  it('flags an MCP authorization-code flow without PKCE', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        client_id: process.env.MCP_CLIENT_ID,
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
      };
    `);

    const hits = findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'high');
    assert.match(hits[0].description, /PKCE/i);
  });

  it('uses language-specific token and outbound request shapes', async () => {
    const cases = [
      {
        name: 'Python',
        ext: '.py',
        code: `
          from mcp.server.fastmcp import FastMCP
          import requests

          mcp = FastMCP('demo')
          def lookup(request):
              token = request.headers.get('Authorization')
              return requests.get('https://api.example.com/search', headers={'Authorization': token})
        `,
      },
      {
        name: 'Ruby',
        ext: '.rb',
        code: `
          require 'net/http'
          class MCP::Server
            def lookup(request)
              token = request.headers['Authorization']
              Net::HTTP.get(URI('https://api.example.com/search'), { 'Authorization' => token })
            end
          end
        `,
      },
      {
        name: 'Go',
        ext: '.go',
        code: `
          package main
          import (
            "net/http"
            mcp "github.com/modelcontextprotocol/go-sdk/mcp"
          )

          var server = mcp.NewServer()
          func lookup(r *http.Request) {
            token := r.Header.Get("Authorization")
            req, _ := http.NewRequest("GET", "https://api.example.com/search", nil)
            req.Header.Set("Authorization", token)
            client.Do(req)
          }
        `,
      },
    ];

    for (const testCase of cases) {
      const findings = await scan(testCase.code, testCase.ext);
      const hits = findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH');
      assert.equal(hits.length, 1, `${testCase.name} token passthrough shape was not detected`);
    }
  });

  it('does not apply the JavaScript outbound shape to Python', async () => {
    const findings = await scan(`
      from mcp.server.fastmcp import FastMCP

      mcp = FastMCP('demo')
      def lookup(request):
          const token = request.headers.authorization
          return fetch('https://api.example.com/search', { headers: { Authorization: token } })
    `, '.py');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('keeps audience, confused-deputy, and PKCE rules available in other languages', async () => {
    const cases = [
      {
        name: 'Python audience',
        ext: '.py',
        rule: 'MCP_TOKEN_AUDIENCE_UNVALIDATED',
        code: `
          from mcp.server.fastmcp import FastMCP
          import jwt

          mcp = FastMCP('demo')
          def profile(request):
              token = request.headers.get('Authorization')
              claims = jwt.decode(token, key)
              return claims['sub']
        `,
      },
      {
        name: 'Ruby confused deputy',
        ext: '.rb',
        rule: 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG',
        code: `
          class MCP::Proxy
            OAUTH = {
              client_id: 'mcp-proxy-production',
              dynamic_client_registration: true,
            }
          end
        `,
      },
      {
        name: 'Go PKCE',
        ext: '.go',
        rule: 'MCP_OAUTH_NO_PKCE',
        code: `
          package main
          import mcp "github.com/modelcontextprotocol/go-sdk/mcp"

          var server = mcp.NewServer()
          var oauth = map[string]string{
            "response_type": "code",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
          }
        `,
      },
    ];

    for (const testCase of cases) {
      const findings = await scan(testCase.code, testCase.ext);
      assert.equal(
        findings.filter((finding) => finding.rule === testCase.rule).length,
        1,
        `${testCase.name} rule was not detected`,
      );
    }
  });

  it('flags confused-deputy OAuth settings in a project MCP config', async () => {
    const findings = await scan(JSON.stringify({
      oauth: {
        client_id: 'mcp-proxy-production',
        dynamic_client_registration: true,
      },
      mcpServers: {
        proxy: { command: 'node', args: ['server.js'] },
      },
    }), '.mcp.json');

    const hits = findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG');
    assert.equal(hits.length, 1);
  });

  it('flags an authorization-code flow without PKCE in a project MCP config', async () => {
    const findings = await scan(JSON.stringify({
      oauth: {
        client_id: '${MCP_CLIENT_ID}',
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
      },
      mcpServers: {
        proxy: { command: 'node', args: ['server.js'] },
      },
    }), '.mcp.json');

    const hits = findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE');
    assert.equal(hits.length, 1);
  });

  it('stays quiet when audience validation, token exchange, and PKCE are present', async () => {
    const findings = await scan(`
      import jwt from 'jsonwebtoken';
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'safe-proxy', version: '1.0.0' });
      server.tool('search', async (request) => {
        const subjectToken = request.headers.authorization;
        const claims = jwt.verify(subjectToken, process.env.MCP_PUBLIC_KEY, {
          audience: 'https://mcp.example.com',
        });
        const downstreamToken = await exchangeToken(subjectToken, {
          audience: 'https://api.example.com',
        });
        return fetch('https://api.example.com/search', {
          headers: { Authorization: \`Bearer \${downstreamToken}\` },
        });
      });

      const oauth = {
        client_id: process.env.MCP_CLIENT_ID,
        response_type: 'code',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      };
    `);

    const oauthRules = new Set([
      'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
      'MCP_STATIC_CLIENT_ID_DYNAMIC_REG',
      'MCP_OAUTH_NO_PKCE',
    ]);
    assert.equal(findings.filter((finding) => oauthRules.has(finding.rule)).length, 0);
  });

  it('does not treat an environment-backed client id as static', async () => {
    const findings = await scan(JSON.stringify({
      oauth: {
        client_id: '${MCP_CLIENT_ID}',
        dynamic_client_registration: true,
      },
      mcpServers: {
        proxy: { command: 'node', args: ['server.js'] },
      },
    }), '.mcp.json');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG').length, 0);
  });
});
