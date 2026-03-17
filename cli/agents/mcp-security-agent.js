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

import path from 'path';
import { BaseAgent } from './base-agent.js';

// =============================================================================
// MCP SECURITY PATTERNS
// =============================================================================

const PATTERNS = [
  // ── Tool Poisoning & Validation ──────────────────────────────────────────
  {
    rule: 'MCP_NO_TOOL_VALIDATION',
    title: 'MCP: Tool Call Without Validation',
    regex: /(?:tools\/call|tool_call|callTool|executeTool)\s*\(/g,
    severity: 'high',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    confidence: 'medium',
    description: 'MCP tool invocation without visible tool-name validation or allowlisting. Attackers can invoke arbitrary tools via tool poisoning.',
    fix: 'Validate tool names against an explicit allowlist before execution',
  },
  {
    rule: 'MCP_DYNAMIC_TOOL_REGISTRATION',
    title: 'MCP: Dynamic Tool Registration from External Source',
    regex: /(?:registerTool|addTool|server\.tool)\s*\(\s*(?:req\.|request\.|body\.|data\.|input\.|params\.)/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'Tool registration from external/user input allows attackers to inject malicious tool definitions (tool poisoning attack).',
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
    confidence: 'medium',
    description: 'MCP server created without any authentication configuration. Any client can connect and invoke tools.',
    fix: 'Add authentication to MCP server transport: API key validation, JWT verification, or OAuth',
  },
  {
    rule: 'MCP_STDIO_NO_SANDBOX',
    title: 'MCP: stdio Transport Without Sandbox',
    regex: /(?:StdioServerTransport|stdio|transport.*stdio)/g,
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
    description: 'MCP tool handler executes shell commands. If tool arguments are user-influenced via prompt injection, this enables RCE.',
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
    confidence: 'medium',
    description: 'MCP tool makes external HTTP requests. Prompt injection could trigger SSRF via tool arguments.',
    fix: 'Validate URLs against allowlist. Block internal/private IP ranges.',
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

const MCP_CONFIG_FILES = [
  'mcp.json',
  '.mcp.json',
  'mcp-config.json',
  'claude_desktop_config.json',
  '.cursor/mcp.json',
];

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
    }

    // ── 3. Check for MCP server files without auth patterns ──────────────
    const mcpServerFiles = codeFiles.filter(f => {
      const content = this.readFile(f);
      return content && /(?:McpServer|@modelcontextprotocol|mcp-server|from\s+mcp)/i.test(content);
    });

    for (const file of mcpServerFiles) {
      findings = findings.concat(this._checkServerAuth(file));
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
      if (this.isSuppressed(lines[i])) continue;
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
}

export default MCPSecurityAgent;
