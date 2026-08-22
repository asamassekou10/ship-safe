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

  it('recognizes direct MCP callbacks after an object configuration argument', async () => {
    const cases = [
      `server.tool('search', { description: 'Search', inputSchema: { query: z.string() } }, async (request) => {`,
      `server.registerTool('search', { description: 'Search', inputSchema: { query: z.string() } }, async (request) => {`,
    ];

    for (const registration of cases) {
      const findings = await scan(`
        import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

        const server = new McpServer({ name: 'demo', version: '1.0.0' });
        ${registration}
          const token = request.headers.authorization;
          return fetch('https://api.example.com/search', {
            headers: { Authorization: token },
          });
        });
      `);

      assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 1, registration);
      assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1, registration);
    }
  });

  it('does not attribute a following MCP tool registration to a preceding helper', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });

      function helper(request) {
        const token = request.headers.authorization;
        jwt.verify(token, key);
        return fetch('https://api.example.com', {
          headers: { Authorization: token },
        });
      }

      server.tool('real', async (request) => 'ok');
    `);

    const oauthRules = new Set([
      'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
    ]);
    assert.equal(findings.filter((finding) => oauthRules.has(finding.rule)).length, 0);
  });

  it('does not attribute a preceding MCP tool registration to a following helper', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });

      server.tool('real', async (request) => {
        return 'ok';
      });

      function helper(request) {
        const token = request.headers.authorization;
        jwt.verify(token, key);
        return fetch('https://api.example.com', {
          headers: { Authorization: token },
        });
      }
    `);

    const oauthRules = new Set([
      'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
    ]);
    assert.equal(findings.filter((finding) => oauthRules.has(finding.rule)).length, 0);
  });

  it('ignores downstream request examples inside strings', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('search', async (request) => {
        const token = request.headers.authorization;
        const example = "fetch(url, { headers: { Authorization: token } })";
        return example;
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('tracks JavaScript token identifiers containing dollar signs', async () => {
    for (const tokenName of ['$token', 'access$token']) {
      const findings = await scan(`
        import jwt from 'jsonwebtoken';
        import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

        const server = new McpServer({ name: 'demo', version: '1.0.0' });
        server.tool('search', async (request) => {
          const ${tokenName} = request.headers.authorization;
          jwt.verify(${tokenName}, key, { audience: 'mcp-server' });
          return fetch('https://api.example.com/search', {
            headers: { Authorization: ${tokenName} },
          });
        });
      `);

      assert.equal(
        findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length,
        1,
        tokenName,
      );
      assert.equal(
        findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length,
        0,
        tokenName,
      );
    }
  });

  it('does not treat a custom request id header as an OAuth token', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('search', async (request) => {
        const requestId = request.headers['X-Request-ID'];
        return fetch('https://api.example.com/search', {
          headers: { 'X-Request-ID': requestId },
        });
      });
    `);

    const oauthRules = new Set([
      'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
    ]);
    assert.equal(findings.filter((finding) => oauthRules.has(finding.rule)).length, 0);
  });

  it('does not treat an API-key variable as a bearer token', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('search', async (request) => {
        const apiKey = request.headers.authorization;
        return fetch('https://api.example.com/search', {
          headers: { Authorization: apiKey },
        });
      });
    `);

    const oauthRules = new Set([
      'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
    ]);
    assert.equal(findings.filter((finding) => oauthRules.has(finding.rule)).length, 0);
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

  it('does not let a safe handler hide an unsafe handler audience check', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('safe', async (request) => {
        const safeToken = request.headers.authorization;
        return jwt.verify(safeToken, key, { audience: 'https://mcp.example.com' });
      });

      server.tool('unsafe', async (request) => {
        const unsafeToken = request.headers.authorization;
        return jwt.verify(unsafeToken, key);
      });
    `);

    const hits = findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED');
    assert.equal(hits.length, 1);
    assert.match(hits[0].matched, /unsafeToken|authorization/i);
  });

  it('does not treat an OAuth header expression stored in a string as an inbound token', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async () => {
        const token = 'request.headers.authorization';
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 0);
  });

  it('does not treat an audience comment as validation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const token = request.headers.authorization;
        // audience: this is UI metadata, not token validation
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not treat an unrelated audience string as validation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const note = 'verify audience';
        const token = request.headers.authorization;
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not treat an unrelated token-exchange string as mitigation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const note = 'token_exchange RFC 8693';
        const token = request.headers.authorization;
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not treat an unrelated audience property as validation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const token = request.headers.authorization;
        const ui = { audience: 'admin-dashboard' };
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not let unrelated credential audience validation hide the inbound token finding', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const token = request.headers.authorization;
        validate(serviceCredential, { audience: 'internal-api' });
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not let unrelated audience validation hide a direct inbound authorization finding', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        validate(serviceCredential, { audience: 'internal-api' });
        return jwt.verify(request.headers.authorization, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('accepts audience validation applied to a direct inbound authorization value', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => (
        jwt.verify(request.headers.authorization, key, { audience: 'https://mcp.example.com' })
      ));
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 0);
  });

  it('accepts audience validation applied to a direct authorization header getter', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => (
        jwt.verify(request.headers.get('Authorization'), key, { audience: 'https://mcp.example.com' })
      ));
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 0);
  });

  it('keeps quoted audience keys visible in token validation calls', async () => {
    const cases = [
      {
        name: 'JavaScript',
        ext: '.js',
        code: `
          import jwt from 'jsonwebtoken';
          import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
          const server = new McpServer({ name: 'demo' });
          server.tool('profile', async (request) => {
            const token = request.headers.authorization;
            return jwt.verify(token, key, { "audience": 'mcp-server' });
          });
        `,
      },
      {
        name: 'Python',
        ext: '.py',
        code: `
          from mcp.server.fastmcp import FastMCP
          mcp = FastMCP('demo')
          def profile(request):
              token = request.headers.get('Authorization')
              return jwt.decode(token, key, **{"audience": 'mcp-server'})
        `,
      },
      {
        name: 'Ruby',
        ext: '.rb',
        code: `
          MCPServer.new
          def profile(request)
            token = request['authorization']
            jwt.verify(token, key, 'audience' => 'mcp-server')
          end
        `,
      },
    ];

    for (const testCase of cases) {
      const findings = await scan(testCase.code, testCase.ext);
      assert.equal(
        findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length,
        0,
        testCase.name,
      );
    }
  });

  it('does not let unrelated credential exchange hide the inbound token finding', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const token = request.headers.authorization;
        const exchanged = await exchangeToken(serviceCredential);
        return jwt.verify(token, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not let unrelated token exchange hide a direct inbound authorization finding', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import jwt from 'jsonwebtoken';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => {
        const exchanged = await exchangeToken(serviceCredential);
        return jwt.verify(request.headers.authorization, key);
      });
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('accepts token exchange applied to a direct inbound authorization value', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      server.tool('profile', async (request) => (
        exchangeToken(request.headers.authorization)
      ));
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 0);
  });

  it('does not pair an unused helper token with another helper request', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      function readToken(request) {
        const token = request.headers.authorization;
        return token;
      }
      function unrelated(token) {
        return fetch('https://api.example.com/search', {
          headers: { Authorization: token },
        });
      }
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('does not flag an unrelated helper that forwards a token outside an MCP tool handler', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      function unrelatedHttpProxy(request) {
        const token = request.headers.authorization;
        return fetch('https://api.example.com', {
          headers: { Authorization: token },
        });
      }
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('does not report unrelated OAuth helpers in an MCP-containing source file', async () => {
    const cases = [
      {
        name: 'JavaScript',
        ext: '.js',
        code: `
          import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
          const server = new McpServer({ name: 'demo', version: '1.0.0' });

          function unrelatedOAuth(request) {
            const token = request.headers.authorization;
            jwt.verify(token, key);
            const oauth = {
              response_type: 'code',
              authorization_endpoint: 'https://idp.example.com/authorize',
              token_endpoint: 'https://idp.example.com/token',
            };
            return fetch('https://api.example.com', {
              headers: { Authorization: token },
            });
          }
        `,
      },
      {
        name: 'Python',
        ext: '.py',
        code: `
          from mcp.server.fastmcp import FastMCP
          import jwt
          import requests

          mcp = FastMCP('demo')

          def unrelated_oauth(request):
              token = request.headers.get('Authorization')
              jwt.decode(token, key)
              oauth = {'response_type': 'code', 'authorization_endpoint': 'https://idp.example.com/authorize', 'token_endpoint': 'https://idp.example.com/token'}
              return requests.get('https://api.example.com', headers={'Authorization': token})
        `,
      },
      {
        name: 'Ruby',
        ext: '.rb',
        code: `
          require 'mcp'
          require 'net/http'
          MCPServer.new

          def unrelated_oauth(request)
            token = request['authorization']
            JWT.decode(token, key)
            oauth = { response_type: 'code', authorization_endpoint: 'https://idp.example.com/authorize', token_endpoint: 'https://idp.example.com/token' }
            Net::HTTP.get(URI('https://api.example.com'))
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

          func unrelatedOAuth(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            jwt.Verify(token, key)
            oauth := map[string]string{"response_type": "code", "authorization_endpoint": "https://idp.example.com/authorize", "token_endpoint": "https://idp.example.com/token"}
            http.Get("https://api.example.com")
          }
        `,
      },
    ];

    for (const testCase of cases) {
      const findings = await scan(testCase.code, testCase.ext);
      const oauthRules = new Set([
        'MCP_TOKEN_AUDIENCE_UNVALIDATED',
        'MCP_OAUTH_NO_PKCE',
      ]);
      assert.equal(
        findings.filter((finding) => oauthRules.has(finding.rule)).length,
        0,
        testCase.name,
      );
    }
  });

  it('does not report an unrelated top-level JavaScript OAuth object', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      const server = new McpServer({ name: 'demo', version: '1.0.0' });

      const unrelatedOAuth = {
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
      };
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 0);
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

  it('keeps static client and dynamic registration in scope despite a brace in a string', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        note: '{',
        client_id: 'mcp-proxy-production',
        dynamic_client_registration: true,
      };
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG').length, 1);
  });

  it('does not pair static client id and dynamic registration from separate objects', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const clientConfig = { client_id: 'mcp-proxy-production' };
      const registrationConfig = { dynamic_client_registration: true };
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG').length, 0);
  });

  it('ignores OAuth config examples inside ordinary strings', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const docs = {
        staticExample: "client_id: 'mcp-prod', dynamic_client_registration: true",
        flowExample: "response_type: 'code'",
      };
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG').length, 0);
    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 0);
  });

  it('keeps JavaScript escaped quotes and template text out of structural matching', async () => {
    const backtick = String.fromCharCode(96);
    const findings = await scan([
      "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';",
      "const server = new McpServer({ name: 'oauth-proxy' });",
      'const escaped = "example \\" // { client_id: \'fake\', dynamic_client_registration: true";',
      `const template = ${backtick}# } response_type: 'code'; code_challenge: true${backtick};`,
      'const oauth = {',
      "  response_type: 'code',",
      "  authorization_endpoint: 'https://idp.example.com/authorize',",
      "  token_endpoint: 'https://idp.example.com/token',",
      '};',
      "server.tool('oauth', () => oauth);",
    ].join('\n'));

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG').length, 0);
    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
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
      server.tool('oauth', () => oauth);
    `);

    const hits = findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'high');
    assert.match(hits[0].description, /PKCE/i);
  });

  it('keeps a missing-PKCE flow in scope despite a brace in a string', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        note: '}',
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
      };
      server.tool('oauth', () => oauth);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('reports a missing PKCE flow when another flow is PKCE-safe', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const safeFlow = { response_type: 'code', code_challenge: challenge };
      const unsafeFlow = {
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
      };
      server.tool('safe', () => safeFlow);
      server.tool('unsafe', () => unsafeFlow);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('does not treat a PKCE comment as a mitigation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = { response_type: 'code' }; // PKCE will be added later
      server.tool('oauth', () => oauth);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('does not treat an unrelated PKCE string as a mitigation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
        note: 'code_challenge will be added',
      };
      server.tool('oauth', () => oauth);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('does not treat a PKCE marker inside a note string as a mitigation', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
        note: 'pkce: true',
      };
      server.tool('oauth', () => oauth);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('does not treat a PKCE marker inside a note string as an explicit disable', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = {
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
        note: 'pkce: false',
      };
      server.tool('oauth', () => oauth);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('flags an authorization-code flow with PKCE explicitly disabled', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

      const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
      const oauth = { response_type: 'code', use_pkce: false };
      server.tool('oauth', () => oauth);
    `);

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('flags null and disabled PKCE settings', async () => {
    for (const setting of ['pkce: null', "pkce: 'disabled'"]) {
      const findings = await scan(`
        import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

        const server = new McpServer({ name: 'oauth-proxy', version: '1.0.0' });
        const oauth = { response_type: 'code', ${setting} };
        server.tool('oauth', () => oauth);
      `);

      assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1, setting);
    }
  });

  it('ignores OAuth-shaped code inside Python triple-quoted docstrings', async () => {
    for (const delimiter of ['"""', "'''"]) {
      const findings = await scan([
        'from mcp.server.fastmcp import FastMCP',
        'mcp = FastMCP("demo")',
        'def documented_handler(request):',
        `    ${delimiter}Example # { } " ' response_type: code`,
        "    token = request.headers.get('Authorization')",
        "    return httpx.get(url, headers={'Authorization': token})",
        '    validate(token, { audience: "mcp-server" })',
        '    code_challenge = "example"',
        `    ${delimiter}`,
        '    return None',
      ].join('\n'), '.py');

      const oauthRules = new Set([
        'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
        'MCP_TOKEN_AUDIENCE_UNVALIDATED',
        'MCP_OAUTH_NO_PKCE',
      ]);
      assert.equal(
        findings.filter((finding) => oauthRules.has(finding.rule)).length,
        0,
        delimiter,
      );
    }
  });

  it('does not let Python docstring mitigations hide real unsafe OAuth code', async () => {
    for (const delimiter of ['"""', "'''"]) {
      const findings = await scan([
        'from mcp.server.fastmcp import FastMCP',
        'mcp = FastMCP("demo")',
        '@mcp.tool()',
        'def profile(request):',
        `    ${delimiter}validate(token, { audience: "mcp-server" })`,
        '    exchangeToken(token) # { }',
        '    code_challenge = "example"',
        `    ${delimiter}`,
        "    token = request.headers.get('Authorization')",
        '    claims = jwt.decode(token, key)',
        "    oauth = {'response_type': 'code'}",
        '    return claims',
      ].join('\n'), '.py');

      assert.equal(
        findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length,
        1,
        delimiter,
      );
      assert.equal(
        findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length,
        1,
        delimiter,
      );
    }
  });

  it('uses the Python MCP tool token and outbound request shapes', async () => {
    const cases = [
      {
        name: 'Python',
        ext: '.py',
        code: `
          from mcp.server.fastmcp import FastMCP
          import requests

          mcp = FastMCP('demo')
          @mcp.tool()
          def lookup(request):
              token = request.headers.get('Authorization')
              return requests.get('https://api.example.com/search', headers={'Authorization': token})
        `,
      },
    ];

    for (const testCase of cases) {
      const findings = await scan(testCase.code, testCase.ext);
      const hits = findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH');
      assert.equal(hits.length, 1, `${testCase.name} token passthrough shape was not detected`);
    }
  });

  it('does not flag an unrelated Python helper in an MCP-containing file', async () => {
    const findings = await scan(`
      from mcp.server.fastmcp import FastMCP
      import requests

      mcp = FastMCP('demo')

      def unrelated_proxy(request):
          token = request.headers.get('Authorization')
          return requests.get('https://api.example.com/search', headers={'Authorization': token})
    `, '.py');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('flags a passthrough from an async decorated Python MCP tool', async () => {
    const findings = await scan(`
      from mcp.server.fastmcp import FastMCP
      import requests

      mcp = FastMCP('demo')

      @mcp.tool()
      async def lookup(request):
          token = request.headers.get('Authorization')
          return await requests.get('https://api.example.com/search', headers={'Authorization': token})
    `, '.py');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 1);
  });

  it('recognizes a multiline FastMCP tool decorator', async () => {
    const findings = await scan(`
      from mcp.server.fastmcp import FastMCP
      import requests

      mcp = FastMCP('demo')

      @mcp.tool(
          name='lookup',
          description='Search the catalog',
      )
      async def lookup(request):
          token = request.headers.get('Authorization')
          return await requests.get('https://api.example.com/search', headers={'Authorization': token})
    `, '.py');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 1);
    assert.equal(findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length, 1);
  });

  it('does not treat a generic Python tool decorator as an MCP handler', async () => {
    const findings = await scan(`
      from mcp.server.fastmcp import FastMCP
      import requests

      mcp = FastMCP('demo')

      @tool
      def lookup(request):
          token = request.headers.get('Authorization')
          return requests.get('https://api.example.com/search', headers={'Authorization': token})
    `, '.py');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('does not flag an unrelated Ruby helper in an MCP-containing file', async () => {
    const findings = await scan(`
      require 'mcp'
      require 'net/http'

      server = MCP::Server.new(name: 'demo')

      def unrelated_proxy(request)
        token = request.headers['Authorization']
        Net::HTTP.get(URI('https://api.example.com/search'), { 'Authorization' => token })
      end
    `, '.rb');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('keeps Ruby audience validation inside methods with nested end blocks', async () => {
    const blocks = {
      if: "if request\n    puts 'nested'\n  end",
      unless: "unless request.nil?\n    puts 'nested'\n  end",
      case: "case request.path\n  when '/profile'\n    puts 'nested'\n  end",
      begin: "begin\n    puts 'nested'\n  rescue StandardError\n    puts 'handled'\n  end",
      do: "[request].each do |item|\n    puts item\n  end",
      while: "while request.pending?\n    break\n  end",
      until: "until request.ready?\n    break\n  end",
      for: "for item in [request]\n    puts item\n  end",
    };

    for (const [name, block] of Object.entries(blocks)) {
      const findings = await scan(`
        MCPServer.new

        def handle(request)
          token = request['authorization']
          ${block}
          jwt.verify(token, key, audience: 'mcp-server')
        end
      `, '.rb');

      assert.equal(
        findings.filter((finding) => finding.rule === 'MCP_TOKEN_AUDIENCE_UNVALIDATED').length,
        0,
        name,
      );
    }
  });

  it('does not flag an unrelated Go helper in an MCP-containing file', async () => {
    const findings = await scan(`
      package main

      import (
        "net/http"
        mcp "github.com/modelcontextprotocol/go-sdk/mcp"
      )

      var server = mcp.NewServer()

      func unrelatedProxy(r *http.Request) {
        token := r.Header.Get("Authorization")
        req, _ := http.NewRequest("GET", "https://api.example.com/search", nil)
        req.Header.Set("Authorization", token)
        http.DefaultClient.Do(req)
      }
    `, '.go');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_UPSTREAM_TOKEN_PASSTHROUGH').length, 0);
  });

  it('does not let Go raw string markers hide a following OAuth object', async () => {
    const rawDelimiter = String.fromCharCode(96);
    const findings = await scan([
      'package main',
      'import mcp "github.com/modelcontextprotocol/go-sdk/mcp"',
      'var server = mcp.NewServer()',
      `var raw = ${rawDelimiter}first // literal`,
      '/* literal */ # { }',
      `path\\${rawDelimiter}`,
      'var oauth = map[string]string{',
      '  "response_type": "code",',
      '  "authorization_endpoint": "https://idp.example.com/authorize",',
      '  "token_endpoint": "https://idp.example.com/token",',
      '}',
    ].join('\n'), '.go');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('does not let Ruby backtick content hide a following OAuth object', async () => {
    const rawDelimiter = String.fromCharCode(96);
    const findings = await scan([
      "require 'mcp'",
      'server = MCP::Server.new',
      `note = ${rawDelimiter}echo "# { / } // /* literal */"${rawDelimiter}`,
      "oauth = { 'response_type' => 'code', 'authorization_endpoint' => 'https://idp.example.com/authorize', 'token_endpoint' => 'https://idp.example.com/token' }",
    ].join('\n'), '.rb');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
  });

  it('ignores OAuth source candidates inside Go raw and Ruby command strings', async () => {
    const backtick = String.fromCharCode(96);
    const cases = [
      {
        ext: '.go',
        code: [
          'package main',
          'import mcp "github.com/modelcontextprotocol/go-sdk/mcp"',
          'var server = mcp.NewServer()',
          `var docs = ${backtick}token := request.Header.Get("Authorization")`,
          'client_id: "mcp-prod", dynamic_client_registration: true',
          `response_type: "code" # { } // /* */${backtick}`,
        ].join('\n'),
      },
      {
        ext: '.rb',
        code: [
          "require 'mcp'",
          'server = MCP::Server.new',
          `docs = ${backtick}token = request.headers['Authorization']`,
          "client_id: 'mcp-prod', dynamic_client_registration: true",
          `response_type: 'code' # { } // /* */${backtick}`,
        ].join('\n'),
      },
    ];

    const oauthRules = new Set([
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
      'MCP_STATIC_CLIENT_ID_DYNAMIC_REG',
      'MCP_OAUTH_NO_PKCE',
    ]);
    for (const testCase of cases) {
      const findings = await scan(testCase.code, testCase.ext);
      assert.equal(
        findings.filter((finding) => oauthRules.has(finding.rule)).length,
        0,
        testCase.ext,
      );
    }
  });

  it('fails closed on OAuth-shaped text in an unterminated string', async () => {
    const findings = await scan(`
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      const server = new McpServer({ name: 'demo', version: '1.0.0' });
      const docs = "token = request.headers.authorization;
      fetch(url, { headers: { Authorization: token } });
      client_id: 'mcp-prod'; dynamic_client_registration: true;
      response_type: 'code';
    `);

    const oauthRules = new Set([
      'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
      'MCP_TOKEN_AUDIENCE_UNVALIDATED',
      'MCP_STATIC_CLIENT_ID_DYNAMIC_REG',
      'MCP_OAUTH_NO_PKCE',
    ]);
    assert.equal(findings.filter((finding) => oauthRules.has(finding.rule)).length, 0);
  });

  it('keeps Ruby hash-rocket PKCE keys visible to mitigation detection', async () => {
    const findings = await scan(`
      require 'mcp'

      class MCP::Proxy
        OAUTH = { 'response_type' => 'code', 'authorization_endpoint' => 'https://idp.example.com/authorize', 'token_endpoint' => 'https://idp.example.com/token', 'code_challenge' => challenge, 'code_verifier' => verifier, 'pkce' => true }
      end
    `, '.rb');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 0);
  });

  it('reports an unsafe Ruby hash-rocket authorization-code flow without PKCE', async () => {
    const findings = await scan(`
      require 'mcp'

      class MCP::Proxy
        OAUTH = { 'response_type' => 'code', 'authorization_endpoint' => 'https://idp.example.com/authorize', 'token_endpoint' => 'https://idp.example.com/token' }
      end
    `, '.rb');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 1);
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
          @mcp.tool()
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

  it('does not pair static client id and registration from separate config objects', async () => {
    const findings = await scan(JSON.stringify({
      client: { client_id: 'mcp-proxy-production' },
      registration: { dynamic_client_registration: true },
      mcpServers: {
        proxy: { command: 'node', args: ['server.js'] },
      },
    }), '.mcp.json');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG').length, 0);
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

  it('keeps quoted PKCE config keys visible to mitigation detection', async () => {
    const findings = await scan(JSON.stringify({
      oauth: {
        client_id: '${MCP_CLIENT_ID}',
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
        code_challenge: 'challenge',
        code_challenge_method: 'S256',
      },
      mcpServers: {
        proxy: { command: 'node', args: ['server.js'] },
      },
    }), '.mcp.json');

    assert.equal(findings.filter((finding) => finding.rule === 'MCP_OAUTH_NO_PKCE').length, 0);
  });

  it('reports confused deputy and missing PKCE independently in one config', async () => {
    const findings = await scan(JSON.stringify({
      oauth: {
        client_id: 'mcp-proxy-production',
        dynamic_client_registration: true,
        response_type: 'code',
        authorization_endpoint: 'https://idp.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
      },
      mcpServers: {
        proxy: { command: 'node', args: ['server.js'] },
      },
    }), '.mcp.json');

    const rules = new Set(findings.map((finding) => finding.rule));
    assert.equal(rules.has('MCP_STATIC_CLIENT_ID_DYNAMIC_REG'), true);
    assert.equal(rules.has('MCP_OAUTH_NO_PKCE'), true);
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
