/**
 * MCP Security Agent
 * ===================
 *
 * Detects security vulnerabilities in MCP (Model Context Protocol)
 * server implementations. MCP servers are the new attack surface
 * for AI-powered applications.
 *
 * In 2026, 30+ CVEs were filed against MCP servers in 60 days.
 * 82% of implementations are prone to path traversal.
 *
 * Checks: tool poisoning, unauthenticated endpoints, overprivileged
 * tools, input injection, missing rate limiting, credential exposure,
 * unsafe transport.
 *
 * Maps to: OWASP Agentic AI ASI02 (Tool Misuse), ASI03 (Privilege Abuse)
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { BaseAgent, createFinding, languageOf } from './base-agent.js';

// =============================================================================
// MCP SECURITY PATTERNS
// =============================================================================

const PATTERNS = [
  // ── Tool Poisoning & Validation ──────────────────────────────────────────
  // MCP_NO_TOOL_VALIDATION is emitted by _checkToolValidation, not from here.
  // As a line pattern it matched every `callTool(` site and never looked for
  // the validation whose absence it was reporting, so it fired 95 times on
  // hermes-agent — once per call site, in files that do validate.
  {
    rule: 'MCP_DYNAMIC_TOOL_REGISTRATION',
    title: 'MCP: Dynamic Tool Registration from External Source',
    regex: /(?:registerTool|addTool|server\.tool)\s*\(\s*(?:req\.|request\.|body\.|data\.|input\.|params\.)/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    cves: ['CVE-2026-26118'],
    description: 'Pattern exploited by CVE-2026-26118 (Microsoft MCP tool hijacking). Tool registration from external/user input allows attackers to inject malicious tool definitions (tool poisoning attack).',
    fix: 'Only register tools from trusted, hardcoded definitions. Never accept tool definitions from user input.',
  },

  // ── Authentication & Access Control ──────────────────────────────────────
  {
    rule: 'MCP_NO_AUTH_TRANSPORT',
    title: 'MCP: Server Without Authentication',
    regex: /(?:McpServer|Server|createServer)\s*\(\s*\{(?:(?!auth|token|apiKey|bearer|jwt|session|credential).)*\}\s*\)/gs,
    severity: 'critical',
    cwe: 'CWE-306',
    owasp: 'A07:2021',
    cves: ['CVE-2026-33032'],
    confidence: 'medium',
    description: 'Pattern exploited by CVE-2026-33032 (nginx-ui MCP unauthenticated RCE, CVSS 9.8 — 2,600+ exposed instances). MCP server created without any authentication configuration. Any client can connect and invoke tools.',
    fix: 'Add authentication to MCP server transport: API key validation, JWT verification, or OAuth',
  },
  {
    rule: 'MCP_STDIO_NO_SANDBOX',
    title: 'MCP: stdio Transport Without Sandbox',
    regex: /(?:StdioServerTransport|new\s+StdioTransport|transport\s*[:=]\s*['"]stdio['"]|StdioClientTransport)/g,
    severity: 'medium',
    cwe: 'CWE-269',
    owasp: 'A04:2021',
    confidence: 'medium',
    description: 'MCP server using stdio transport runs in the same process context. Consider sandboxing for untrusted tools.',
    fix: 'Run MCP servers in sandboxed containers or separate processes with limited permissions',
  },

  // ── Overprivileged Tools ─────────────────────────────────────────────────
  {
    rule: 'MCP_TOOL_SHELL_EXEC',
    title: 'MCP: Tool Executes Shell Commands',
    regex: /(?:server\.tool|registerTool|addTool)[\s\S]{0,500}(?:exec|execSync|spawn|spawnSync|execFile|child_process|subprocess|os\.system|os\.popen)/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    cves: ['CVE-2026-30615'],
    description: 'Pattern exploited by CVE-2026-30615 (Windsurf prompt-injection → local RCE, zero user interaction). MCP tool handler executes shell commands. If tool arguments are user-influenced via prompt injection, this enables RCE.',
    fix: 'Avoid shell execution in MCP tools. If necessary, use strict allowlists for commands and validate all arguments.',
  },
  {
    rule: 'MCP_TOOL_FS_WRITE',
    title: 'MCP: Tool Has File System Write Access',
    regex: /(?:server\.tool|registerTool|addTool)[\s\S]{0,500}(?:writeFile|writeFileSync|appendFile|createWriteStream|fs\.write|unlink|rmdir|mkdir)/g,
    severity: 'high',
    cwe: 'CWE-732',
    owasp: 'A01:2021',
    description: 'MCP tool can write to the file system. Prompt injection could lead to arbitrary file writes or deletions.',
    fix: 'Restrict file operations to a sandboxed directory. Validate all paths against an allowlist.',
  },
  {
    rule: 'MCP_TOOL_DB_MUTATION',
    title: 'MCP: Tool Has Database Write Access',
    regex: /(?:server\.tool|registerTool|addTool)[\s\S]{0,500}(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|\.create\(|\.update\(|\.delete\(|\.destroy\(|\.remove\()/g,
    severity: 'high',
    cwe: 'CWE-284',
    owasp: 'A01:2021',
    description: 'MCP tool can mutate database records. Without confirmation gates, prompt injection can modify or delete data.',
    fix: 'Add human-in-the-loop confirmation for destructive database operations in MCP tools.',
  },
  {
    rule: 'MCP_TOOL_NETWORK_REQUEST',
    title: 'MCP: Tool Makes External Network Requests',
    regex: /(?:server\.tool|registerTool|addTool)[\s\S]{0,500}(?:fetch\(|axios\.|got\(|http\.get|https\.get|request\(|urllib|requests\.)/g,
    severity: 'medium',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    cves: ['CVE-2026-44284'],
    confidence: 'medium',
    description: 'Pattern exploited by CVE-2026-44284 (FastGPT MCP SSRF in tool URL handling). MCP tool makes external HTTP requests. Prompt injection could trigger SSRF via tool arguments.',
    fix: 'Validate URLs against allowlist. Block internal/private IP ranges (169.254.169.254, 100.100.100.200, metadata.google.internal).',
  },

  // ── Input Injection ──────────────────────────────────────────────────────
  {
    rule: 'MCP_TOOL_ARGS_TO_SQL',
    title: 'MCP: Tool Arguments in SQL Query',
    regex: /(?:server\.tool|registerTool)[\s\S]{0,500}(?:`SELECT|`INSERT|`UPDATE|`DELETE|\.query\s*\(\s*`|\.raw\s*\()/g,
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    description: 'MCP tool constructs SQL queries that may include tool arguments from LLM output. This enables SQL injection via prompt injection.',
    fix: 'Use parameterized queries in all MCP tool handlers. Never interpolate tool arguments into SQL.',
  },
  {
    rule: 'MCP_TOOL_ARGS_TO_EVAL',
    title: 'MCP: Tool Arguments Passed to eval()',
    regex: /(?:server\.tool|registerTool)[\s\S]{0,500}eval\s*\(/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'MCP tool passes arguments to eval(). Prompt injection can achieve arbitrary code execution.',
    fix: 'Never use eval() in MCP tool handlers. Use structured data parsing instead.',
  },
  {
    rule: 'MCP_TOOL_PATH_TRAVERSAL',
    title: 'MCP: Tool Arguments in File Path',
    regex: /(?:server\.tool|registerTool)[\s\S]{0,500}(?:path\.join|path\.resolve|readFile|readFileSync)\s*\(\s*(?!__dirname)/g,
    severity: 'high',
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'MCP tool constructs file paths from arguments. Path traversal via prompt injection can read arbitrary files.',
    fix: 'Validate file paths against an allowed directory. Use path.resolve() and check the result starts with the allowed base.',
  },

  // ── Credential Exposure ──────────────────────────────────────────────────
  {
    rule: 'MCP_HARDCODED_CREDENTIALS',
    title: 'MCP: Credentials in Server Config',
    regex: /(?:mcpServers|mcp_server|server\.json)[\s\S]{0,300}(?:password|secret|token|apiKey|api_key|credential)\s*[:=]\s*["'][^"']+["']/gi,
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    description: 'Hardcoded credentials in MCP server configuration. These are exposed to anyone with access to the config.',
    fix: 'Use environment variables or a secrets manager for MCP server credentials.',
  },
  {
    rule: 'MCP_ENV_IN_TOOL_RESPONSE',
    title: 'MCP: Environment Variables Exposed in Tool Response',
    regex: /(?:server\.tool|registerTool)[\s\S]{0,500}(?:process\.env|os\.environ)/g,
    severity: 'high',
    cwe: 'CWE-200',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'MCP tool accesses environment variables. If returned in tool responses, secrets may leak to the LLM and user.',
    fix: 'Never return raw environment variables in tool responses. Filter sensitive values.',
  },

  // ── Remote/Untrusted Connections ─────────────────────────────────────────
  {
    rule: 'MCP_REMOTE_UNPINNED',
    title: 'MCP: Remote Server Without Version Pinning',
    regex: /(?:mcpServers|mcp_servers)[\s\S]{0,200}(?:url|command)\s*[:=]\s*["'][^"']*["'](?![\s\S]{0,100}(?:hash|integrity|version|sha|pin|digest))/g,
    severity: 'medium',
    cwe: 'CWE-494',
    owasp: 'A08:2021',
    confidence: 'medium',
    description: 'MCP server reference without version pinning or integrity hash. Vulnerable to rug-pull attacks.',
    fix: 'Pin MCP server versions and validate integrity hashes to prevent supply chain attacks.',
  },
  {
    rule: 'MCP_HTTP_NO_TLS',
    title: 'MCP: HTTP Transport Without TLS',
    regex: /(?:SSEServerTransport|StreamableHTTPServerTransport|mcpServers)[\s\S]{0,200}http:\/\/(?!localhost|127\.0\.0\.1)/g,
    severity: 'high',
    cwe: 'CWE-319',
    owasp: 'A02:2021',
    description: 'MCP server using HTTP (not HTTPS) for non-localhost connections. Tool calls and responses are sent in plaintext.',
    fix: 'Use HTTPS for all remote MCP server connections.',
  },

  // ── Missing Rate Limiting ────────────────────────────────────────────────
  {
    rule: 'MCP_NO_RATE_LIMIT',
    title: 'MCP: No Rate Limiting on Tool Calls',
    regex: /(?:McpServer|Server|createServer)\s*\(\s*\{(?:(?!rateLimit|rateLimiter|throttle|limit|maxRequests).)*\}\s*\)/gs,
    severity: 'medium',
    cwe: 'CWE-770',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'MCP server without rate limiting. Enables unbounded consumption attacks (denial of wallet).',
    fix: 'Add rate limiting to MCP server: limit tool calls per client per time window.',
  },

  // ── Tool Result Injection ────────────────────────────────────────────────
  {
    rule: 'MCP_TOOL_RESULT_UNESCAPED',
    title: 'MCP: Tool Result Injected Into Prompt Without Escaping',
    regex: /(?:tool_result|toolResult|function_result)[\s\S]{0,200}(?:content|messages|prompt)\s*(?:\.push|\.append|\+=|\.concat)/g,
    severity: 'high',
    cwe: 'CWE-74',
    owasp: 'A03:2021',
    confidence: 'medium',
    description: 'Raw tool results injected back into LLM prompt context. Enables tool-to-prompt injection attacks.',
    fix: 'Sanitize and escape tool results before including them in LLM context. Strip any instruction-like content.',
  },
];

// =============================================================================
// STRUCTURAL CHECKS (beyond line-by-line regex)
// =============================================================================

export const MCP_CONFIG_FILES = [
  'mcp.json',
  '.mcp.json',
  'mcp-config.json',
  'claude_desktop_config.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
];

// Well-known official MCP server packages
const OFFICIAL_MCP_SERVERS = new Set([
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
]);

// OAuth request shapes are deliberately language-scoped. These rules inspect
// source code rather than MCP JSON, so a JS header expression must not be
// allowed to report on a Python, Ruby, or Go file by accident.
const MCP_TOOL_REGISTRATION = /(?:\.\s*tool|\b(?:registerTool|addTool))\s*\(/gi;
const MCP_OAUTH_STATIC_CLIENT_ID = /["']?\bclient[_-]?id\b["']?\s*(?:=>|:=|[:=])\s*(["'])(.*?)\1/gi;
const MCP_OAUTH_CODE_FLOW = /(?:["']?\bresponse[_-]?type\b["']?\s*[:=]\s*["']code["']|["']?\bgrant[_-]?type\b["']?\s*[:=]\s*["']authorization[_-]?code["']|\bauthorization[_-]?code\b|["']?\bauthorization[_-]?endpoint\b["']?[^\n]{0,240}["']?\btoken[_-]?endpoint\b["']?)/i;
const MCP_OAUTH_SHAPES = {
  js: {
    inboundToken: /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*\b(?:req|request|ctx|event)\b[^;\n]*(?:\.(?:authorization|bearer)\b|\[\s*['"](?:authorization|bearer|http_authorization)['"]\s*\]|(?:get|header)\s*\(\s*['"](?:authorization|bearer)['"])/gi,
    directToken: /\b(?:req|request|ctx|event)\b[^;\n]*(?:\.(?:authorization|bearer)\b|\[\s*['"](?:authorization|bearer|http_authorization)['"]\s*\]|(?:get|header)\s*\(\s*['"](?:authorization|bearer)['"])/gi,
    outboundRequest: /\b(?:fetch|axios(?:\.[A-Za-z_$][\w$]*)?|got|https?\.request)\s*\(/i,
    audienceValidation: /(?:\b(?:verify|decode|validate|check|assert)\w*[^\n;]{0,180}\baud(?:ience)?\b|\b(?:claims?|payload)\b[^\n;]{0,120}\baud\b\s*(?:===|!==|==|!=|=))/i,
    staticClientId: MCP_OAUTH_STATIC_CLIENT_ID,
    codeFlow: /(?:["']?\bresponse[_-]?type\b["']?\s*[:=]\s*["']code["']|["']?\bgrant[_-]?type\b["']?\s*[:=]\s*["']authorization[_-]?code["']|\bauthorization[_-]?code\b|["']?\bauthorization[_-]?endpoint\b["']?[^\n;]{0,240}["']?\btoken[_-]?endpoint\b["']?)/i,
  },
  python: {
    inboundToken: /\b([A-Za-z_]\w*)\s*=\s*(?:request|req|ctx|context)\b[^\n]*(?:\.(?:authorization|bearer)\b|\[\s*['"](?:authorization|bearer|http_authorization)['"]\s*\]|\.get\s*\(\s*['"](?:authorization|bearer)['"])/gi,
    directToken: /\b(?:request|req|ctx|context)\b[^\n]*(?:\.(?:authorization|bearer)\b|\[\s*['"](?:authorization|bearer|http_authorization)['"]\s*\]|\.get\s*\(\s*['"](?:authorization|bearer)['"])/gi,
    outboundRequest: /\b(?:requests|httpx)\.(?:get|post|put|patch|delete|request)\s*\(|\b(?:urllib\.request\.)?urlopen\s*\(/i,
    audienceValidation: /(?:\b(?:verify|decode|validate|check|assert)\w*[^\n]{0,180}\baud(?:ience)?\b|\b(?:claims?|payload)\b[^\n]{0,120}\b(?:aud|audience)\b\s*(?:==|!=|in\b|=))/i,
    staticClientId: MCP_OAUTH_STATIC_CLIENT_ID,
    codeFlow: MCP_OAUTH_CODE_FLOW,
  },
  ruby: {
    inboundToken: /\b([A-Za-z_]\w*)\s*=\s*(?:request|req|context|env|headers)\b[^\n]*(?:\.(?:authorization|bearer)\b|\[\s*['"](?:authorization|bearer|http_authorization)['"]\s*\])/gi,
    directToken: /\b(?:request|req|context|env|headers)\b[^\n]*(?:\.(?:authorization|bearer)\b|\[\s*['"](?:authorization|bearer|http_authorization)['"]\s*\])/gi,
    outboundRequest: /\b(?:Net::HTTP|Faraday|HTTParty|RestClient)\b[\s\S]{0,120}\b(?:get|post|put|delete|request|call)\b\s*[.(]/i,
    audienceValidation: /(?:\b(?:verify|decode|validate|check|assert)\w*[^\n]{0,180}\baud(?:ience)?\b|\b(?:claims?|payload)\b[^\n]{0,120}\b(?:aud|audience)\b\s*(?:==|!=|=~|=>))/i,
    staticClientId: MCP_OAUTH_STATIC_CLIENT_ID,
    codeFlow: MCP_OAUTH_CODE_FLOW,
  },
  go: {
    inboundToken: /\b([A-Za-z_]\w*)\s*:?=\s*(?:r|req|request)\.Header\.Get\(\s*["']Authorization["']\s*\)/gi,
    directToken: /\b(?:r|req|request)\.Header\.Get\(\s*["']Authorization["']\s*\)/gi,
    outboundRequest: /\b(?:http\.(?:NewRequest|Get|Post|PostForm)|[A-Za-z_]\w*\.Do)\s*\(/i,
    audienceValidation: /(?:\b(?:VerifyAudience|ValidateAudience|ParseWithClaims)\b|\b(?:claims?|payload)\b[\s\S]{0,120}\baud(?:ience)?\b\s*(?:==|!=))/i,
    staticClientId: /["']?\b(?:client[_-]?id|clientID)\b["']?\s*(?:=>|:=|[:=])\s*(["'])(.*?)\1/gi,
    codeFlow: /(?:["']?\bresponse[_-]?type\b["']?\s*[:=]\s*["']code["']|["']?\bgrant[_-]?type\b["']?\s*[:=]\s*["']authorization[_-]?code["']|\bauthorization[_-]?code\b|["']?\bauthorization[_-]?endpoint\b["']?[\s\S]{0,240}["']?\btoken[_-]?endpoint\b["']?)/i,
  },
};

const MCP_OAUTH_DYNAMIC_REGISTRATION = /["']?(?:dynamic[_-]?client[_-]?registration|dynamicClientRegistration|allow[_-]?dynamic[_-]?registration|enable[_-]?dynamic[_-]?client[_-]?registration|dynamicRegistration|registerClients|RegisterClient)["']?\s*(?:=>|:=|[:=])\s*(?:true|["']?enabled["']?)/i;
const MCP_OAUTH_TOKEN_EXCHANGE = /(?:exchangeToken|token[_-]?exchange|subject_token|RFC\s*8693|urn:ietf:params:oauth:grant-type:token-exchange)/i;
const MCP_OAUTH_PKCE = /(?:\bcode[_-]?challenge\b|\bcode[_-]?verifier\b|\b(?:use[_-]?pkce|pkce)\b\s*[:=]|\b(?:generate|create|build)\w*code[_-]?(?:challenge|verifier)\b)/i;
const MCP_OAUTH_EXPLICIT_NO_PKCE = /(?:["']?\b(?:use[_-]?pkce|pkce)\b["']?\s*[:=]\s*(?:false|null|["']?disabled["']?)|["']?\bcode[_-]?challenge\b["']?\s*[:=]\s*null)/i;
const MCP_OAUTH_MARKER = /(?:\bMCP(?:::|[-_.])?(?:Server|Proxy)\b|@modelcontextprotocol|\bmcp[._-](?:server|proxy)\b|mcp\.NewServer)/i;

function isOAuthTokenName(name) {
  const normalized = String(name || '').toLowerCase();
  return normalized.includes('token')
    || normalized.includes('bearer')
    || normalized.includes('authorization')
    || normalized === 'auth'
    || normalized.startsWith('auth_')
    || normalized === 'accesstoken';
}

function sourceLineHelpers(content) {
  const lines = content.split('\n');
  const lineNumber = (index) => content.slice(0, index).split('\n').length;
  const lineText = (index) => (lines[lineNumber(index) - 1] || '').trim().slice(0, 180);
  return { lineNumber, lineText };
}

function createStaticClientIdDynamicRegFinding({ file, line, category, matched }) {
  return createFinding({
    file,
    line,
    column: 1,
    severity: 'high',
    category,
    rule: 'MCP_STATIC_CLIENT_ID_DYNAMIC_REG',
    title: 'MCP: Static OAuth Client ID With Dynamic Registration',
    description: 'An MCP proxy combines a fixed third-party OAuth client_id with dynamic client registration. This can enable a confused deputy attack that reuses consent for an attacker-controlled client.',
    matched,
    confidence: 'medium',
    cwe: 'CWE-441',
    owasp: 'A07:2021',
    fix: 'Use per-client consent and validate registered client_id and redirect_uri values before starting the third-party authorization flow.',
  });
}

function createOAuthNoPkceFinding({ file, line, category, matched }) {
  return createFinding({
    file,
    line,
    column: 1,
    severity: 'high',
    category,
    rule: 'MCP_OAUTH_NO_PKCE',
    title: 'MCP: OAuth Authorization-Code Flow Without PKCE',
    description: 'An MCP OAuth authorization-code flow does not use PKCE. An intercepted authorization code can then be redeemed by an attacker.',
    matched,
    confidence: 'medium',
    cwe: 'CWE-352',
    owasp: 'A07:2021',
    fix: 'Use a cryptographically random code_verifier and send its S256 code_challenge with every authorization-code request.',
  });
}

function stripComments(content, language) {
  const supportsLineSlashComments = language === 'js' || language === 'go';
  const output = [...content];
  let state = 'code';
  let quote = '';

  const blank = (index) => {
    if (output[index] !== '\n' && output[index] !== '\r') output[index] = ' ';
  };

  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    const next = content[index + 1];

    if (state === 'line-comment') {
      if (char === '\n' || char === '\r') state = 'code';
      else blank(index);
      continue;
    }

    if (state === 'block-comment') {
      if (char === '*' && next === '/') {
        blank(index);
        blank(index + 1);
        index += 1;
        state = 'code';
      } else {
        blank(index);
      }
      continue;
    }

    if (state === 'string') {
      const isGoRawString = language === 'go' && quote === '`';
      if (char === '\\' && !isGoRawString) {
        index += 1;
      } else if (char === quote) {
        state = 'code';
        quote = '';
      }
      continue;
    }

    if (supportsLineSlashComments && char === '/' && next === '/') {
      blank(index);
      blank(index + 1);
      index += 1;
      state = 'line-comment';
      continue;
    }

    if (supportsLineSlashComments && char === '/' && next === '*') {
      blank(index);
      blank(index + 1);
      index += 1;
      state = 'block-comment';
      continue;
    }

    if ((language === 'python' || language === 'ruby') && char === '#') {
      blank(index);
      state = 'line-comment';
      continue;
    }

    if (char === '\'' || char === '"' || ((language === 'js' || language === 'go' || language === 'ruby') && char === '`')) {
      quote = char;
      state = 'string';
    }
  }

  return output.join('');
}

function maskStrings(content, preserveObjectKeys = false, language = 'js') {
  const output = [...content];
  let state = 'code';
  let quote = '';
  let stringStart = -1;

  const blank = (index) => {
    if (output[index] !== '\n' && output[index] !== '\r') output[index] = ' ';
  };
  const blankRange = (start, end) => {
    for (let index = start; index <= end; index += 1) blank(index);
  };

  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    if (state === 'string') {
      const isGoRawString = language === 'go' && quote === '`';
      if (char === '\\' && !isGoRawString) {
        index += 1;
      } else if (char === quote) {
        let next = index + 1;
        while (next < content.length && /\s/.test(content[next])) next += 1;
        const isRubyHashKey = language === 'ruby' && content[next] === '=' && content[next + 1] === '>';
        if (!preserveObjectKeys || (content[next] !== ':' && !isRubyHashKey)) blankRange(stringStart, index);
        blank(index);
        state = 'code';
        quote = '';
        stringStart = -1;
      } else {
        continue;
      }
      continue;
    }

    if (char === '\'' || char === '"' || char === '`') {
      quote = char;
      state = 'string';
      stringStart = index;
    }
  }

  if (state === 'string' && stringStart !== -1) blankRange(stringStart, content.length - 1);

  return output.join('');
}

function findBracePairs(content, language) {
  const code = maskStrings(stripComments(content, language), false, language);
  const stack = [];
  const pairs = [];

  for (let index = 0; index < code.length; index += 1) {
    if (code[index] === '{') {
      stack.push(index);
    } else if (code[index] === '}' && stack.length) {
      pairs.push({ start: stack.pop(), end: index + 1 });
    }
  }

  return pairs;
}

function sourceFunctionScopes(content, language) {
  if (language === 'python' || language === 'ruby') {
    const lines = content.split('\n');
    const offsets = [];
    let offset = 0;
    for (const line of lines) {
      offsets.push(offset);
      offset += line.length + 1;
    }

    const scopes = [];
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      const line = lines[lineIndex];
      const match = language === 'python'
        ? line.match(/^(\s*)(?:async\s+)?def\s+/)
        : line.match(/^(\s*)def\s+/);
      if (!match) continue;

      const indent = match[1].replace(/\t/g, '    ').length;
      let endLine = lines.length;
      if (language === 'python') {
        for (let nextLine = lineIndex + 1; nextLine < lines.length; nextLine += 1) {
          if (!lines[nextLine].trim()) continue;
          const nextIndent = lines[nextLine].match(/^\s*/)[0].replace(/\t/g, '    ').length;
          if (nextIndent <= indent) {
            endLine = nextLine;
            break;
          }
        }
      } else {
        let depth = 1;
        for (let nextLine = lineIndex + 1; nextLine < lines.length; nextLine += 1) {
          if (/^\s*def\b/.test(lines[nextLine])) depth += 1;
          if (/^\s*end\b/.test(lines[nextLine])) depth -= 1;
          if (depth === 0) {
            endLine = nextLine + 1;
            break;
          }
        }
      }

      scopes.push({ start: offsets[lineIndex], end: offsets[endLine] ?? content.length });
    }
    return scopes;
  }

  const code = maskStrings(stripComments(content, language), false, language);
  return findBracePairs(content, language)
    .filter(({ start }) => isFunctionBrace(code, start, language));
}

function isFunctionBrace(code, start, language) {
  const prefix = code.slice(Math.max(0, start - 180), start);
  if (language === 'go') return /\bfunc\b[\s\S]{0,160}$/.test(prefix);
  return language === 'js' && /\bfunction\b[\s\S]{0,160}$|=>\s*$/.test(prefix);
}

function sourceObjectScopes(content, language) {
  const code = maskStrings(stripComments(content, language), false, language);
  return findBracePairs(content, language)
    .filter(({ start }) => !isFunctionBrace(code, start, language));
}

function braceDepthAt(code, scope, index) {
  let depth = 0;
  for (let position = scope.start; position < index; position += 1) {
    if (code[position] === '{') depth += 1;
    if (code[position] === '}') depth -= 1;
  }
  return depth;
}

function objectScopeContaining(code, scopes, firstIndex, secondIndex, language = 'js') {
  const structuralCode = maskStrings(code, false, language);
  return scopes
    .filter((scope) => (
      scope.start <= firstIndex
      && firstIndex < scope.end
      && scope.start <= secondIndex
      && secondIndex < scope.end
      && braceDepthAt(structuralCode, scope, firstIndex) === 1
      && braceDepthAt(structuralCode, scope, secondIndex) === 1
    ))
    .sort((left, right) => (left.end - left.start) - (right.end - right.start))[0] || null;
}

function scopeContaining(scopes, start, end = start + 1) {
  return scopes
    .filter((scope) => scope.start <= start && end <= scope.end)
    .sort((left, right) => (left.end - left.start) - (right.end - right.start))[0] || null;
}

function sourceScopeContaining(content, code, language, scopes, start, end = start + 1) {
  const scope = scopeContaining(scopes, start, end);
  if (scope || language !== 'js') return scope;

  const arrow = code.lastIndexOf('=>', start);
  if (arrow === -1) return null;

  const lineStart = code.lastIndexOf('\n', arrow - 1) + 1;
  const statementEnd = code.indexOf(');', start);
  const lineEndIndex = code.indexOf('\n', start);
  const lineEnd = lineEndIndex === -1 ? content.length : lineEndIndex + 1;
  return {
    start: lineStart,
    end: statementEnd === -1 ? lineEnd : statementEnd + 2,
  };
}

function isMcpToolHandlerScope(code, scope, language) {
  if (language === 'python') {
    const precedingLines = code.slice(0, scope.start).split('\n');
    const previousLine = precedingLines.at(-2)?.trim() || '';
    const decorator = previousLine.match(/^@([A-Za-z_]\w*)\.tool(?:\([^)]*\))?$/);
    if (!decorator) return false;

    const receiver = decorator[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b${receiver}\\s*=\\s*FastMCP\\s*\\(`).test(code);
  }

  if (language !== 'js') return false;

  const prefix = code.slice(Math.max(0, scope.start - 320), scope.start);
  const registrations = allRegexMatches(MCP_TOOL_REGISTRATION, prefix);
  if (registrations.length) {
    const registration = registrations.at(-1);
    const callbackHeader = prefix.slice(registration.index);
    const callback = callbackHeader.search(/=>|\bfunction\b/);
    return callback !== -1 && !/[{};]/.test(callbackHeader.slice(0, callback));
  }

  const localHeader = code.slice(scope.start, Math.min(code.length, scope.start + 320));
  const localRegistration = allRegexMatches(MCP_TOOL_REGISTRATION, localHeader)[0];
  if (!localRegistration) return false;

  const callbackHeader = localHeader.slice(localRegistration.index);
  const callback = callbackHeader.search(/=>|\bfunction\b/);
  return callback !== -1 && !/[{};]/.test(callbackHeader.slice(0, callback));
}

function allRegexMatches(regex, content) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const scanner = new RegExp(regex.source, flags);
  const matches = [];
  let match;
  while ((match = scanner.exec(content)) !== null) {
    matches.push(match);
    if (!match[0]) scanner.lastIndex += 1;
  }
  return matches;
}

function isQuotedObjectKeyAt(content, index, language = 'js') {
  const quote = content[index];
  if (quote !== '\'' && quote !== '"') return false;

  let end = index + 1;
  while (end < content.length) {
    if (content[end] === '\\') {
      end += 2;
      continue;
    }
    if (content[end] === quote) break;
    end += 1;
  }
  if (end >= content.length) return false;

  let next = end + 1;
  while (next < content.length && /\s/.test(content[next])) next += 1;
  return content[next] === ':'
    || (language === 'ruby' && content[next] === '=' && content[next + 1] === '>');
}

function hasExplicitNoPkce(content, language = 'js') {
  const masked = maskStrings(content, false, language);
  return allRegexMatches(MCP_OAUTH_EXPLICIT_NO_PKCE, content).some((match) => (
    masked[match.index] === content[match.index]
    || isQuotedObjectKeyAt(content, match.index, language)
  ));
}

function hasTokenRelatedMitigation(scopeContent, tokenName, mitigation, directTokenReference) {
  const tokenReference = tokenName
    ? new RegExp(`\\b${tokenName.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}\\b`)
    : directTokenReference ? maskStrings(directTokenReference) : null;
  if (!tokenReference) return false;

  const referencesToken = (content) => tokenName
    ? tokenReference.test(content)
    : content.includes(tokenReference);
  return allRegexMatches(mitigation, scopeContent).some((match) => {
    if (referencesToken(match[0])) return true;

    const callEnd = scopeContent.indexOf(')', match.index);
    const end = callEnd === -1 ? Math.min(scopeContent.length, match.index + 280) : callEnd + 1;
    return referencesToken(scopeContent.slice(match.index, end));
  });
}

// =============================================================================
// MCP SECURITY AGENT
// =============================================================================

export class MCPSecurityAgent extends BaseAgent {
  constructor() {
    super(
      'MCPSecurityAgent',
      'Detect MCP server security vulnerabilities — tool poisoning, auth gaps, privilege escalation',
      'llm'
    );
  }

  async analyze(context) {
    const { files, rootPath } = context;
    let findings = [];

    // ── 1. Scan code files for MCP patterns ──────────────────────────────
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.go'].includes(ext);
    });

    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      findings = findings.concat(this._checkOAuthTokenPassthrough(file));
      findings = findings.concat(this._checkOAuthAudienceValidation(file));
      findings = findings.concat(this._checkOAuthConfusedDeputy(file));
      findings = findings.concat(this._checkOAuthPkce(file));
    }

    // ── 2. Scan MCP config files ─────────────────────────────────────────
    const configFiles = files.filter(f => {
      const basename = path.basename(f);
      const rel = path.relative(rootPath, f).replace(/\\/g, '/');
      return MCP_CONFIG_FILES.some(cfg => rel.endsWith(cfg) || basename === cfg);
    });

    for (const file of configFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      findings = findings.concat(this._checkConfigFile(file));
      findings = findings.concat(this._checkOAuthConfig(file));
    }

    // ── 3. Check for MCP server files without auth patterns ──────────────
    const mcpServerFiles = codeFiles.filter(f => {
      const content = this.readFile(f);
      return content && /(?:McpServer|@modelcontextprotocol|mcp-server|from\s+mcp)/i.test(content);
    });

    for (const file of mcpServerFiles) {
      findings = findings.concat(this._checkServerAuth(file));
      findings = findings.concat(this._checkToolValidation(file));
    }

    // ── 4. Check MCP configs for typosquatting & over-permissioned servers ─
    for (const file of configFiles) {
      findings = findings.concat(this._checkMcpTyposquatting(file));
      findings = findings.concat(this._checkOverPermissioned(file));
      findings = findings.concat(this._checkAutoLaunchOnTrust(file, rootPath));
      findings = findings.concat(this._checkEnvSecretPassthrough(file, rootPath));
      findings = findings.concat(this._checkAllowlistBypass(file, rootPath));
    }

    // ── 5. Detect shadow MCP configs (not in version control) ───────────
    // Reads the developer's home directory, which is useful locally and
    // meaningless to a pipeline whose runner is ephemeral. `ci` opts out by
    // default; --check-global-agents forces it on for persistent self-hosted
    // runners where a poisoned global config is a real concern.
    if (context.options?.checkGlobalAgents !== false) {
      findings = findings.concat(this._detectShadowMcpConfigs(rootPath));
    }

    return findings;
  }

  /**
   * Detect an inbound MCP bearer token copied into a downstream request.
   *
   * Request/header syntax is language-specific. Each supported language gets
   * its own shape so a JavaScript expression cannot report on Python, Ruby,
   * or Go by accident (issue #105).
   */
  _checkOAuthTokenPassthrough(filePath) {
    const language = languageOf(filePath);
    const shape = MCP_OAUTH_SHAPES[language];
    if (!shape) return [];

    const content = this.readFile(filePath);
    const code = content && stripComments(content, language);
    if (!code || !MCP_OAUTH_MARKER.test(code)) {
      return [];
    }

    const scopes = sourceFunctionScopes(content, language);
    const inboundCandidates = allRegexMatches(shape.inboundToken, code);
    const directCandidates = allRegexMatches(shape.directToken, code)
      .filter((direct) => !inboundCandidates.some((inbound) => (
        inbound.index <= direct.index && direct.index < inbound.index + inbound[0].length
      )));
    const outbound = shape.outboundRequest;
    const { lineNumber, lineText } = sourceLineHelpers(content);
    const makeFinding = (requestIndex) => {
      if (this.isSuppressed(lineText(requestIndex), 'high')) return null;

      return createFinding({
        file: filePath,
        line: lineNumber(requestIndex),
        column: 1,
        severity: 'high',
        category: this.category,
        rule: 'MCP_UPSTREAM_TOKEN_PASSTHROUGH',
        title: 'MCP: Inbound OAuth Token Passed Through Downstream',
        description: 'An MCP tool reads an inbound authorization token and forwards it unchanged to a downstream request. This can bypass audience validation and downstream trust boundaries.',
        matched: lineText(requestIndex),
        confidence: 'high',
        cwe: 'CWE-345',
        owasp: 'ASI03:2026',
        fix: 'Validate the inbound token for the MCP server and use RFC 8693 token exchange to mint a downstream-audience token instead of forwarding it unchanged.',
      });
    };

    for (const incoming of inboundCandidates) {
      const tokenName = incoming[1];
      if (!isOAuthTokenName(tokenName)) continue;
      const scope = sourceScopeContaining(content, code, language, scopes, incoming.index, incoming.index + incoming[0].length);
      if (!scope || !isMcpToolHandlerScope(code, scope, language)) continue;
      const searchStart = incoming.index + incoming[0].length;
      const searchWindow = code.slice(searchStart, Math.min(scope.end, searchStart + 1200));
      const requestMatch = searchWindow.match(outbound);
      if (!requestMatch) continue;

      const requestIndex = searchStart + requestMatch.index;
      const requestContext = code.slice(requestIndex, Math.min(scope.end, requestIndex + 600));
      const tokenReference = new RegExp(`\\b${tokenName}\\b`);
      if (!/(?:authorization|bearer|headers)/i.test(requestContext) || !tokenReference.test(requestContext)) {
        continue;
      }

      const finding = makeFinding(requestIndex);
      if (finding) return [finding];
    }

    for (const directMatch of directCandidates) {
      const directIndex = directMatch.index;
      const scope = sourceScopeContaining(content, code, language, scopes, directIndex, directIndex + directMatch[0].length);
      if (!scope || !isMcpToolHandlerScope(code, scope, language)) continue;
      const beforeStart = Math.max(scope.start, directIndex - 200);
      const beforeWindow = code.slice(beforeStart, directIndex);
      const beforeRequest = beforeWindow.match(outbound);
      if (!beforeRequest) continue;
      const requestIndex = beforeStart + beforeRequest.index;

      const requestContext = code.slice(requestIndex, Math.min(scope.end, Math.max(requestIndex + 600, directIndex + directMatch[0].length)));
      if (!/(?:authorization|bearer|headers)/i.test(requestContext)) continue;

      const finding = makeFinding(requestIndex);
      if (finding) return [finding];
    }

    return [];
  }

  /**
   * Detect an inbound MCP token that is accepted without an audience check.
   *
   * The MCP authorization guidance requires tokens to be issued for the MCP
   * server itself. Token exchange is a valid alternative because it mints a
   * new token for the downstream audience.
   */
  _checkOAuthAudienceValidation(filePath) {
    const shape = MCP_OAUTH_SHAPES[languageOf(filePath)];
    if (!shape) return [];

    const content = this.readFile(filePath);
    const language = languageOf(filePath);
    const code = content && stripComments(content, language);
    if (!code || !MCP_OAUTH_MARKER.test(code)) {
      return [];
    }

    const scopes = sourceFunctionScopes(content, language);
    const inboundCandidates = allRegexMatches(shape.inboundToken, code);
    const directCandidates = allRegexMatches(shape.directToken, code)
      .filter((direct) => !inboundCandidates.some((inbound) => (
        inbound.index <= direct.index && direct.index < inbound.index + inbound[0].length
      )));
    const candidates = [...inboundCandidates, ...directCandidates]
      .sort((left, right) => left.index - right.index);
    const audienceValidation = shape.audienceValidation;
    const tokenExchange = MCP_OAUTH_TOKEN_EXCHANGE;
    const { lineNumber, lineText } = sourceLineHelpers(content);
    const findings = [];
    const seenScopes = new Set();

    for (const incoming of candidates) {
      if (incoming[1] && !isOAuthTokenName(incoming[1])) continue;
      const scope = sourceScopeContaining(content, code, language, scopes, incoming.index, incoming.index + incoming[0].length);
      if (!scope || seenScopes.has(scope.start)) continue;

      const scopeContent = code.slice(scope.start, scope.end);
      const mitigationContent = maskStrings(scopeContent, false, language);
      const hasAudienceValidation = hasTokenRelatedMitigation(
        mitigationContent,
        incoming[1],
        audienceValidation,
        incoming[0],
      );
      const hasTokenExchange = hasTokenRelatedMitigation(
        mitigationContent,
        incoming[1],
        tokenExchange,
        incoming[0],
      );
      if (hasAudienceValidation || hasTokenExchange) continue;
      if (this.isSuppressed(lineText(incoming.index), 'high')) continue;

      seenScopes.add(scope.start);
      findings.push(createFinding({
        file: filePath,
        line: lineNumber(incoming.index),
        column: 1,
        severity: 'high',
        category: this.category,
        rule: 'MCP_TOKEN_AUDIENCE_UNVALIDATED',
        title: 'MCP: Inbound OAuth Token Audience Not Validated',
        description: 'An MCP server accepts an inbound authorization token without checking that its audience is the MCP server. Tokens issued for another resource can then cross the MCP trust boundary.',
        matched: lineText(incoming.index),
        confidence: 'medium',
        cwe: 'CWE-287',
        owasp: 'A07:2021',
        fix: 'Validate the token audience against the MCP server resource before accepting it, or use RFC 8693 token exchange to mint a token for the target audience.',
      }));
    }

    return findings;
  }

  /**
   * Detect a static OAuth client id used alongside dynamic client
   * registration in an MCP proxy.
   */
  _checkOAuthConfusedDeputy(filePath) {
    const language = languageOf(filePath);
    const shape = MCP_OAUTH_SHAPES[language];
    if (!shape) return [];

    const content = this.readFile(filePath);
    const code = content && stripComments(content, language);
    if (!code || !MCP_OAUTH_MARKER.test(code)) {
      return [];
    }

    const objectScopes = sourceObjectScopes(content, language);
    const clients = allRegexMatches(shape.staticClientId, code);
    const registrations = allRegexMatches(MCP_OAUTH_DYNAMIC_REGISTRATION, code);
    const { lineNumber, lineText } = sourceLineHelpers(content);

    for (const client of clients) {
      if (/\$\{|\b(?:process\.env|os\.environ|getenv|ENV\[|os\.Getenv)\b/i.test(client[2])) continue;
      for (const registration of registrations) {
        const scope = objectScopeContaining(code, objectScopes, client.index, registration.index, language);
        if (!scope || this.isSuppressed(lineText(client.index), 'high')) continue;

        return [createStaticClientIdDynamicRegFinding({
          file: filePath,
          line: lineNumber(client.index),
          category: this.category,
          matched: lineText(client.index),
        })];
      }
    }

    return [];
  }

  /**
   * Detect an OAuth authorization-code flow that does not use PKCE.
   */
  _checkOAuthPkce(filePath) {
    const language = languageOf(filePath);
    const shape = MCP_OAUTH_SHAPES[language];
    if (!shape) return [];

    const content = this.readFile(filePath);
    const code = content && stripComments(content, language);
    if (!code || !MCP_OAUTH_MARKER.test(code)) {
      return [];
    }

    const objectScopes = sourceObjectScopes(content, language);
    const functionScopes = sourceFunctionScopes(content, language);
    const codeFlows = allRegexMatches(shape.codeFlow, code);
    const pkce = MCP_OAUTH_PKCE;
    const { lineNumber, lineText } = sourceLineHelpers(content);
    const findings = [];
    const reportedScopes = new Set();

    for (const flowMatch of codeFlows) {
      const scope = objectScopeContaining(code, objectScopes, flowMatch.index, flowMatch.index, language)
        || sourceScopeContaining(content, code, language, functionScopes, flowMatch.index, flowMatch.index + flowMatch[0].length);
      if (!scope) continue;

      const scopeContent = code.slice(scope.start, scope.end);
      const mitigationContent = maskStrings(scopeContent, true, language);
      if (pkce.test(mitigationContent) && !hasExplicitNoPkce(scopeContent, language)) continue;
      if (reportedScopes.has(scope.start)) continue;
      if (this.isSuppressed(lineText(flowMatch.index), 'high')) continue;
      reportedScopes.add(scope.start);

      findings.push(createOAuthNoPkceFinding({
        file: filePath,
        line: lineNumber(flowMatch.index),
        category: this.category,
        matched: lineText(flowMatch.index),
      }));
    }

    return findings;
  }

  /**
   * Check project MCP JSON for OAuth proxy settings. JSON configs have no
   * source-language extension, so they use their own key/value shapes.
   */
  _checkOAuthConfig(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const code = stripComments(content, 'js');
    const objectScopes = sourceObjectScopes(content, 'js');
    const staticClientId = /["']?\bclient[_-]?id\b["']?\s*[:=]\s*(["'])(.*?)\1/gi;
    const clients = allRegexMatches(staticClientId, code);
    const registrations = allRegexMatches(MCP_OAUTH_DYNAMIC_REGISTRATION, code);
    const { lineNumber, lineText } = sourceLineHelpers(content);
    const findings = [];

    for (const client of clients) {
      if (/\$\{|\b(?:process\.env|os\.environ|getenv|ENV\[|os\.Getenv)\b/i.test(client[2])) continue;
      const registration = registrations.find((candidate) => (
        objectScopeContaining(code, objectScopes, client.index, candidate.index, 'js')
      ));
      if (!registration || this.isSuppressed(lineText(client.index), 'high')) continue;

      findings.push(createStaticClientIdDynamicRegFinding({
        file: filePath,
        line: lineNumber(client.index),
        category: this.category,
        matched: lineText(client.index),
      }));
      break;
    }

    const reportedScopes = new Set();
    for (const flowMatch of allRegexMatches(MCP_OAUTH_SHAPES.js.codeFlow, code)) {
      const scope = objectScopeContaining(code, objectScopes, flowMatch.index, flowMatch.index, 'js');
      if (!scope || reportedScopes.has(scope.start)) continue;

      const scopeContent = code.slice(scope.start, scope.end);
      const mitigationContent = maskStrings(scopeContent, true, 'js');
      if (MCP_OAUTH_PKCE.test(mitigationContent) && !hasExplicitNoPkce(scopeContent, 'js')) continue;
      if (this.isSuppressed(lineText(flowMatch.index), 'high')) continue;
      reportedScopes.add(scope.start);

      findings.push(createOAuthNoPkceFinding({
        file: filePath,
        line: lineNumber(flowMatch.index),
        category: this.category,
        matched: lineText(flowMatch.index),
      }));
    }

    return findings;
  }

  /**
   * Check MCP config files for misconfigurations.
   */
  _checkConfigFile(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const findings = [];

    // Check for hardcoded secrets in config
    const secretPatterns = /(?:password|secret|token|apiKey|api_key)\s*[:=]\s*["'][^"']{8,}["']/gi;
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (this.isSuppressed(lines[i], 'critical')) continue;
      secretPatterns.lastIndex = 0;
      if (secretPatterns.test(lines[i])) {
        findings.push({
          file: filePath,
          line: i + 1,
          column: 0,
          severity: 'critical',
          category: this.category,
          rule: 'MCP_CONFIG_HARDCODED_SECRET',
          title: 'MCP: Hardcoded Secret in Config',
          description: 'MCP configuration contains a hardcoded secret. Use environment variables instead.',
          matched: lines[i].trim().substring(0, 100),
          confidence: 'high',
          cwe: 'CWE-798',
          owasp: 'A07:2021',
          fix: 'Replace hardcoded values with environment variable references: {"env": "MY_SECRET"}',
        });
      }
    }

    return findings;
  }

  /**
   * Check if MCP server files have authentication.
   */
  _checkToolValidation(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const dispatches = /(?:tools\/call|tool_call|callTool|executeTool)\s*\(/.test(content);
    if (!dispatches) return [];

    // Any allowlist, schema check, or membership test in the file refutes the
    // claim that names go unvalidated. Deliberately generous: the finding says
    // "nothing here validates," and one check is enough to disprove it.
    const validates =
      /(?:allow_?list|allowedTools|ALLOWED_TOOLS|SAFE_TOOLS|permitted_?tools|tool_?schema|validate\w*\s*\(|zod|pydantic|jsonschema|BaseModel)/i.test(content)
      || /\b(?:in|includes|has|hasOwnProperty|get)\s*\(?\s*(?:ALLOWED|allowed|registry|REGISTRY|_tools|TOOLS)\b/.test(content);
    if (validates) return [];

    const lines = content.split('\n');
    const idx = lines.findIndex(l => /(?:tools\/call|tool_call|callTool|executeTool)\s*\(/.test(l));
    const line = idx === -1 ? 1 : idx + 1;
    const matched = (lines[line - 1] || '').trim().slice(0, 180);
    if (this.isSuppressed(matched, 'high')) return [];

    return [createFinding({
      file: filePath,
      line,
      column: 1,
      severity: 'high',
      category: this.category,
      rule: 'MCP_NO_TOOL_VALIDATION',
      title: 'MCP: Tool Call Without Validation',
      description: 'This file dispatches MCP tool invocations but contains no tool-name allowlist or argument schema check. Tool poisoning can then invoke whatever the server exposes.',
      matched,
      confidence: 'medium',
      cwe: 'CWE-20',
      owasp: 'A03:2021',
      fix: 'Validate tool names against an explicit allowlist, and tool arguments against a schema, before execution.',
    })];
  }

  _checkServerAuth(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const findings = [];

    // Check if server file has any auth patterns
    const hasAuth = /(?:auth|authenticate|authorization|bearer|jwt|token|apiKey|session|passport|middleware)/i.test(content);

    if (!hasAuth) {
      findings.push({
        file: filePath,
        line: 1,
        column: 0,
        severity: 'high',
        category: this.category,
        rule: 'MCP_SERVER_NO_AUTH',
        title: 'MCP: Server Implementation Without Authentication',
        description: 'MCP server implementation has no visible authentication mechanism. Any client can connect and invoke tools.',
        matched: 'No auth pattern found in MCP server file',
        confidence: 'medium',
        cwe: 'CWE-306',
        owasp: 'A07:2021',
        fix: 'Add authentication middleware to your MCP server. Validate client identity before allowing tool invocations.',
      });
    }

    return findings;
  }

  /**
   * Detect repo-local MCP configs that auto-launch a local process when the
   * developer accepts the editor's folder-trust prompt. A malicious repo can
   * ship such a config so a stdio server (command) runs the moment the folder
   * is trusted in Claude Code / Cursor / VS Code — the shared weak default
   * across agentic CLI tools (Adversa, 2026).
   */
  _checkAutoLaunchOnTrust(filePath, rootPath) {
    // Only project-local configs auto-load on trust; skip global user configs.
    const rel = path.relative(rootPath, filePath).replace(/\\/g, '/');
    const base = path.basename(filePath);
    const isProjectLocal = base === '.mcp.json' || base === 'mcp.json'
      || rel.endsWith('.cursor/mcp.json') || rel.endsWith('.vscode/mcp.json');
    if (!isProjectLocal) return [];

    const content = this.readFile(filePath);
    if (!content) return [];
    let config;
    try { config = JSON.parse(content); } catch { return []; }
    const servers = config.mcpServers || config.servers || (config.mcp && config.mcp.servers) || {};
    const findings = [];

    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object' || typeof server.command !== 'string') continue;
      const invocation = `${server.command} ${(server.args || []).join(' ')}`.trim();
      findings.push({
        file: filePath, line: 1, column: 0,
        severity: 'high',
        category: this.category,
        rule: 'MCP_AUTO_LAUNCH_ON_TRUST',
        title: `MCP: Server "${name}" auto-launches on folder trust`,
        description: `Project-local ${base} defines a stdio server ("${name}") that runs \`${invocation.slice(0, 80)}\`. If this repo is opened and trusted in an agentic editor (Claude Code, Cursor, VS Code), the command executes automatically — a malicious repo weaponizes this to run code the moment you accept the trust prompt.`,
        matched: invocation.slice(0, 100),
        confidence: 'high',
        cwe: 'CWE-829',
        owasp: 'ASI06:2026',
        fix: 'Do not ship auto-launching MCP servers in a repo. Review the command, require explicit per-server approval, and never trust a repo-supplied server definition without inspecting what it runs.',
      });
    }
    return findings;
  }

  /**
   * Detect project-local MCP configs that pass secret-like environment variables
   * into a tool process. A malicious or compromised server can read credentials
   * that were never meant for it.
   */
  _checkEnvSecretPassthrough(filePath, rootPath) {
    const rel = path.relative(rootPath, filePath).replace(/\\/g, '/');
    const base = path.basename(filePath);
    const isProjectLocal = base === '.mcp.json' || base === 'mcp.json'
      || rel.endsWith('.cursor/mcp.json') || rel.endsWith('.vscode/mcp.json');
    if (!isProjectLocal) return [];

    const content = this.readFile(filePath);
    if (!content) return [];
    let config;
    try { config = JSON.parse(content); } catch { return []; }

    const servers = config.mcpServers || config.servers || (config.mcp && config.mcp.servers) || {};
    const findings = [];
    const operationalEnvNames = new Set([
      'LOG_LEVEL', 'NODE_ENV', 'PORT', 'DEBUG', 'PATH', 'HOME', 'LANG', 'TZ',
      'CI', 'TERM', 'SHELL', 'USER', 'TMPDIR', 'TMP', 'TEMP',
    ]);
    const secretEnvNameRe = /(?:^|_)(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?ACCESS[_-]?KEY|AUTH[_-]?TOKEN|ACCESS[_-]?TOKEN|CLIENT[_-]?SECRET|PRIVATE[_-]?KEY|PASSWORD|PASSWD|CREDENTIAL|CREDENTIALS|PAT|GH_PAT|SECRET|TOKEN|PASSWORD|CREDENTIAL)(?:_|$)/i;
    const connectionStringEnvNameRe = /(?:^|_)(?:DATABASE|POSTGRES(?:_PRISMA)?|REDIS|MONGODB|MYSQL|SUPABASE_DB|NEON_DATABASE|VERCEL_POSTGRES)_(?:URL|URI)$/i;

    for (const [name, server] of Object.entries(servers)) {
      const env = server?.env;
      if (!env || typeof env !== 'object' || Array.isArray(env)) continue;

      for (const key of Object.keys(env)) {
        if (operationalEnvNames.has(key)) continue;
        const isSecretName = secretEnvNameRe.test(key);
        const isConnectionStringName = connectionStringEnvNameRe.test(key);
        if (!isSecretName && !isConnectionStringName) continue;

        const rule = isSecretName
          ? 'MCP_ENV_SECRET_PASSTHROUGH'
          : 'MCP_ENV_CONNECTION_STRING_PASSTHROUGH';
        const secretKind = isConnectionStringName ? 'credential-bearing connection' : 'secret';

        findings.push({
          file: filePath, line: 1, column: 0,
          severity: 'high',
          category: this.category,
          rule,
          title: `MCP: Server "${name}" passes ${secretKind} env "${key}"`,
          description: `Project-local ${base} passes "${key}" into the "${name}" MCP server process. A malicious or compromised server can read credentials that were never meant for the tool.`,
          matched: key,
          confidence: 'high',
          cwe: 'CWE-200',
          owasp: 'ASI06:2026',
          fix: 'Remove secret env vars from MCP server config. Pass only operational settings (e.g. LOG_LEVEL). Use scoped, server-specific credentials if absolutely required.',
        });
      }
    }

    return findings;
  }

  /**
   * Detect MCP configs that weaken or bypass tool-call allowlists via wildcards,
   * tool aliases, or nested permission blocks that expand access.
   */
  _checkAllowlistBypass(filePath, rootPath) {
    const rel = path.relative(rootPath, filePath).replace(/\\/g, '/');
    const base = path.basename(filePath);
    const isProjectLocal = base === '.mcp.json' || base === 'mcp.json'
      || rel.endsWith('.cursor/mcp.json') || rel.endsWith('.vscode/mcp.json');
    if (!isProjectLocal) return [];

    const content = this.readFile(filePath);
    if (!content) return [];
    let config;
    try { config = JSON.parse(content); } catch { return []; }

    const findings = [];
    const allowlistKeys = new Set([
      'allowedTools', 'toolAllowlist', 'allowedToolNames', 'permittedTools',
      'toolPermissions', 'permissions', 'allowed_tools', 'tool_allowlist',
    ]);
    const aliasKeys = new Set(['toolAliases', 'aliases', 'tool_aliases']);
    const denyKeys = new Set([
      'deny', 'denied', 'denyTools', 'blockedTools', 'disallowedTools', 'disallow', 'blocked',
    ]);
    const hasWildcard = (obj) => {
      if (obj === '*' || obj === 'all' || obj === 'any') return true;
      if (Array.isArray(obj)) return obj.some(hasWildcard);
      if (obj && typeof obj === 'object') return Object.values(obj).some(hasWildcard);
      return false;
    };
    const hasDenyValue = (value) => {
      if (value === true || hasWildcard(value)) return true;
      if (typeof value === 'string') return value.trim().length > 0;
      if (Array.isArray(value)) return value.some(hasDenyValue);
      if (value && typeof value === 'object') return Object.values(value).some(hasDenyValue);
      return false;
    };
    const denyTokens = (value) => {
      if (value === true || hasWildcard(value)) return ['*'];
      if (typeof value === 'string') return [value];
      if (Array.isArray(value)) return value.flatMap(denyTokens);
      if (value && typeof value === 'object') {
        return Object.entries(value).flatMap(([key, nestedValue]) =>
          nestedValue === true ? [key] : denyTokens(nestedValue));
      }
      return [];
    };
    const matchingRegrant = (key, value, pathParts, denials) => {
      const isAllowField = key === 'allow' || key === 'allowed';
      const isWildcardAllowlist = allowlistKeys.has(key) && hasWildcard(value);
      if ((!isAllowField || (value !== true && !hasWildcard(value))) && !isWildcardAllowlist) {
        return null;
      }

      const overrideIndex = Math.max(
        pathParts.lastIndexOf('overrides'),
        pathParts.lastIndexOf('override'),
      );
      const overrideTarget = overrideIndex >= 0 ? pathParts[overrideIndex + 1] : null;
      const scopeTarget = overrideTarget || pathParts[pathParts.length - 1];

      return denials.find((denial) => {
        const denialScope = denial.path.slice(0, -1);
        const sameScope = denialScope.length === pathParts.length
          && denialScope.every((part, index) => part === pathParts[index]);
        const deniedTokens = denial.tokens.map((token) => token.toLowerCase());
        const targetMatches = scopeTarget && deniedTokens.includes(String(scopeTarget).toLowerCase());
        return sameScope || deniedTokens.includes('*') || targetMatches;
      }) || null;
    };

    const walk = (node, pathParts = [], serverPath = null, inheritedDenials = []) => {
      if (node === null || typeof node !== 'object') return;

      if (Array.isArray(node)) {
        const hasWildcard = node.some(v => v === '*' || v === 'all' || v === 'any');
        const parentKey = pathParts[pathParts.length - 1] || '';
        if (hasWildcard && allowlistKeys.has(parentKey)) {
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'high',
            category: this.category,
            rule: 'MCP_ALLOWLIST_WILDCARD',
            title: `MCP: Wildcard tool allowlist at ${pathParts.join('.')}`,
            description: `Project-local ${base} sets "${parentKey}" to a wildcard (${JSON.stringify(node)}). Any tool the server exposes becomes callable, defeating allowlist-based tool restrictions.`,
            matched: `${parentKey}: ${JSON.stringify(node)}`,
            confidence: 'high',
            cwe: 'CWE-269',
            owasp: 'ASI03:2026',
            fix: 'Replace the wildcard with an explicit list of required tool names. Never use "*" in tool allowlists.',
          });
        }
        node.forEach((item, i) => walk(item, pathParts.concat(String(i)), serverPath, inheritedDenials));
        return;
      }

      const localDenials = serverPath
        ? Object.entries(node)
          .filter(([key, value]) => denyKeys.has(key) && hasDenyValue(value))
          .map(([key, value]) => ({ path: pathParts.concat(key), tokens: denyTokens(value) }))
        : [];
      const activeDenials = inheritedDenials.concat(localDenials);

      for (const [key, value] of Object.entries(node)) {
        const nextPath = pathParts.concat(key);
        const entersServerEntry = !serverPath
          && (pathParts[pathParts.length - 1] === 'mcpServers'
            || pathParts[pathParts.length - 1] === 'servers');
        const nextServerPath = serverPath || (entersServerEntry ? nextPath : null);

        // Only report an explicit deny/re-grant relationship within one server entry.
        const matchingDenial = nextServerPath
          ? matchingRegrant(key, value, pathParts, activeDenials)
          : null;
        if (matchingDenial) {
          const denialPath = matchingDenial.path;
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'medium',
            category: this.category,
            rule: 'MCP_NESTED_PERMISSION_OVERRIDE',
            title: `MCP: Nested permission re-grant at ${nextPath.join('.')}`,
            description: `Project-local ${base} denies access at "${denialPath.join('.')}" but re-grants it at "${nextPath.join('.')}", which can silently broaden tool access for that server.`,
            matched: `${denialPath.join('.')} -> ${nextPath.join('.')}: ${JSON.stringify(value).slice(0, 120)}`,
            confidence: 'medium',
            cwe: 'CWE-863',
            owasp: 'ASI03:2026',
            fix: 'Keep deny and allow rules consistent within each server entry. Do not nest wildcard or allow=true permission blocks beneath a denied scope.',
          });
        }

        if (allowlistKeys.has(key)) {
          if (value === '*' || value === 'all' || value === 'any') {
            findings.push({
              file: filePath, line: 1, column: 0,
              severity: 'high',
              category: this.category,
              rule: 'MCP_ALLOWLIST_WILDCARD',
              title: `MCP: Wildcard tool allowlist at ${nextPath.join('.')}`,
              description: `Project-local ${base} sets "${key}" to "${value}". Any tool the server exposes becomes callable, defeating allowlist-based tool restrictions.`,
              matched: `${key}: ${JSON.stringify(value)}`,
              confidence: 'high',
              cwe: 'CWE-269',
              owasp: 'ASI03:2026',
              fix: 'Replace the wildcard with an explicit list of required tool names. Never use "*" in tool allowlists.',
            });
          }
        }

        if (aliasKeys.has(key) && value && typeof value === 'object' && !Array.isArray(value)) {
          const mappings = Object.entries(value).slice(0, 3).map(([from, to]) => `${from}→${to}`).join(', ');
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'high',
            category: this.category,
            rule: 'MCP_TOOL_ALIAS_BYPASS',
            title: `MCP: Tool alias mapping at ${nextPath.join('.')}`,
            description: `Project-local ${base} defines tool aliases (${mappings}${Object.keys(value).length > 3 ? ', …' : ''}). Aliases can route an allowlisted name to a different, more privileged tool and bypass name-based restrictions.`,
            matched: mappings || key,
            confidence: 'high',
            cwe: 'CWE-863',
            owasp: 'ASI03:2026',
            fix: 'Remove tool aliases from MCP config. Validate the resolved tool name against an explicit allowlist at dispatch time.',
          });
        }

        // Nested permission block inside a server entry that re-expands access.
        if ((key === 'toolPolicy' || key === 'toolAccess')
            && value && typeof value === 'object'
            && pathParts.some(p => p === 'mcpServers' || p === 'servers')) {
          const hasNestedWildcard = (obj) => {
            if (obj === '*' || obj === 'all' || obj === 'any') return true;
            if (Array.isArray(obj)) return obj.some(hasNestedWildcard);
            if (obj && typeof obj === 'object') {
              return Object.entries(obj).some(([nestedKey, nestedValue]) =>
                allowlistKeys.has(nestedKey) ? hasNestedWildcard(nestedValue) : false);
            }
            return false;
          };
          if (hasNestedWildcard(value)) {
            findings.push({
              file: filePath, line: 1, column: 0,
              severity: 'medium',
              category: this.category,
              rule: 'MCP_NESTED_PERMISSION_OVERRIDE',
              title: `MCP: Nested permission override at ${nextPath.join('.')}`,
              description: `Project-local ${base} nests a "${key}" block under a server entry with wildcard or "all" permissions. Nested blocks can override a parent allowlist and silently broaden tool access.`,
              matched: `${key}: ${JSON.stringify(value).slice(0, 120)}`,
              confidence: 'medium',
              cwe: 'CWE-863',
              owasp: 'ASI03:2026',
              fix: 'Keep tool permissions at the top level with an explicit allowlist. Do not nest wildcard permission blocks inside individual server entries.',
            });
          }
        }

        const childDenials = denyKeys.has(key) ? inheritedDenials : activeDenials;
        walk(value, nextPath, nextServerPath, childDenials);
      }
    };

    walk(config);
    return findings;
  }

  /**
   * Detect possible typosquatted MCP server names in config.
   */
  _checkMcpTyposquatting(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    try {
      const config = JSON.parse(content);
      const servers = config.mcpServers || config.servers || {};

      for (const [name, server] of Object.entries(servers)) {
        const cmd = server.command || '';
        const args = (server.args || []).join(' ');
        const fullCmd = `${cmd} ${args}`;

        // Check if server uses an npx package that looks like a typosquat of official ones
        const npxMatch = fullCmd.match(/npx\s+(?:-[^\s]+\s+)*([^\s]+)/);
        if (npxMatch) {
          const pkg = npxMatch[1];
          for (const official of OFFICIAL_MCP_SERVERS) {
            const distance = this._levenshtein(pkg, official);
            if (distance > 0 && distance <= 3 && pkg !== official) {
              findings.push({
                file: filePath, line: 1, column: 0,
                severity: 'critical',
                category: this.category,
                rule: 'MCP_TYPOSQUAT_SERVER',
                title: `MCP: Possible Typosquatted Server "${pkg}"`,
                description: `MCP server package "${pkg}" is ${distance} char(s) from official "${official}". Could be a supply chain attack.`,
                matched: pkg,
                confidence: 'medium',
                cwe: 'CWE-494',
                owasp: 'A08:2021',
                fix: `Verify this is the correct package. Did you mean "${official}"?`,
              });
            }
          }
        }
      }
    } catch { /* not valid JSON */ }

    return findings;
  }

  /**
   * Check for over-permissioned MCP servers (filesystem access to / or ~).
   */
  _checkOverPermissioned(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    try {
      const config = JSON.parse(content);
      const servers = config.mcpServers || config.servers || {};

      for (const [name, server] of Object.entries(servers)) {
        const args = server.args || [];
        const argsStr = args.join(' ');

        // Check for root/home filesystem access
        if (/(?:^\/\s|['" ]\/['"]?\s|\/Users\/|\/home\/|\\Users\\|C:\\)/.test(argsStr)) {
          const hasWideAccess = args.some(a =>
            a === '/' || a === '~' || a === '%USERPROFILE%' ||
            /^\/(?:Users|home)\/[^/]+$/.test(a) ||
            /^[A-Z]:\\(?:Users\\)?[^\\]*$/.test(a)
          );
          if (hasWideAccess) {
            findings.push({
              file: filePath, line: 1, column: 0,
              severity: 'high',
              category: this.category,
              rule: 'MCP_OVER_PERMISSIONED',
              title: `MCP: Server "${name}" Has Broad Filesystem Access`,
              description: `MCP server "${name}" has access to a wide directory scope. A prompt injection attack could read or modify sensitive files.`,
              matched: argsStr.slice(0, 200),
              confidence: 'high',
              cwe: 'CWE-269',
              owasp: 'A01:2021',
              fix: 'Restrict filesystem access to the minimum required directory: e.g., the project folder only.',
            });
          }
        }
      }
    } catch { /* not valid JSON */ }

    return findings;
  }

  /**
   * Detect shadow MCP configs that exist but aren't in .gitignore or git.
   */
  _detectShadowMcpConfigs(rootPath) {
    const findings = [];
    const home = os.homedir();

    // Check common locations for MCP configs outside version control
    const homeConfigs = [
      path.join(home, '.cursor', 'mcp.json'),
      path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      path.join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'),
    ];

    for (const configPath of homeConfigs) {
      try {
        if (fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf-8');
          const config = JSON.parse(content);
          const servers = config.mcpServers || config.servers || {};
          const serverCount = Object.keys(servers).length;

          if (serverCount > 0) {
            findings.push({
              file: configPath, line: 1, column: 0,
              severity: 'medium',
              category: this.category,
              rule: 'MCP_SHADOW_CONFIG',
              // About the machine, not the repository: a pipeline cannot fix a
              // developer's home directory, and these server names must not
              // reach machine output. See createFinding in base-agent.js.
              scope: 'environment',
              title: `MCP: ${serverCount} Shadow Server(s) in User Config`,
              description: `Found ${serverCount} MCP server(s) configured outside the project in ${configPath}. These operate outside your project's security controls.`,
              matched: Object.keys(servers).join(', '),
              confidence: 'medium',
              cwe: 'CWE-269',
              owasp: 'A05:2021',
              fix: 'Review shadow MCP servers. Move project-specific servers to the project mcp.json and track in version control.',
            });
          }
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Simple Levenshtein distance for typosquatting detection.
   */
  _levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i-1] === b[j-1]
          ? dp[i-1][j-1]
          : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
      }
    }
    return dp[m][n];
  }
}

export default MCPSecurityAgent;
