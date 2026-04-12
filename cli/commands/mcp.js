/**
 * MCP Server
 * ==========
 *
 * Exposes ship-safe as a Model Context Protocol (MCP) server.
 * Allows AI editors (Claude Desktop, Cursor, Windsurf, Zed) to call
 * ship-safe's security tools directly during conversations.
 *
 * USAGE:
 *   npx ship-safe mcp       Start the MCP server (stdio transport)
 *
 * SETUP (Claude Desktop):
 *   Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
 *   {
 *     "mcpServers": {
 *       "ship-safe": {
 *         "command": "npx",
 *         "args": ["ship-safe", "mcp"]
 *       }
 *     }
 *   }
 *
 * AVAILABLE TOOLS:
 *   scan_secrets    - Scan a directory for leaked secrets
 *   get_checklist   - Return the launch-day security checklist
 *   analyze_file    - Analyze a single file for security issues
 *   scan_repo       - Run a full multi-agent security scan on a repo
 *   get_findings    - Read findings from a saved ship-safe report file
 *   suppress_finding - Add a ship-safe-ignore comment to suppress a finding
 *
 * PROTOCOL:
 *   JSON-RPC 2.0 over stdio (MCP spec: https://modelcontextprotocol.io)
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import { SECRET_PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS, SKIP_FILENAMES, TEST_FILE_PATTERNS, MAX_FILE_SIZE } from '../utils/patterns.js';
import { isHighEntropyMatch } from '../utils/entropy.js';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { DeepAnalyzer } from '../agents/deep-analyzer.js';

// =============================================================================
// MCP TOOL DEFINITIONS
// =============================================================================

const TOOLS = [
  {
    name: 'scan_secrets',
    description: 'Scan a directory or file for leaked secrets, API keys, and credentials. Returns structured findings with severity, file location, and remediation advice.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'The directory or file path to scan. Use "." for the current directory.',
        },
        includeTests: {
          type: 'boolean',
          description: 'Whether to include test files in the scan (default: false)',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'get_checklist',
    description: 'Return the ship-safe launch-day security checklist as structured data. Use this to guide users through pre-launch security checks.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'analyze_file',
    description: 'Analyze a single file for security issues including secrets, hardcoded credentials, and dangerous patterns.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'The absolute or relative path to the file to analyze.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'scan_repo',
    description: 'Run a full multi-agent security scan on a repository or directory. Runs all 20+ ship-safe security agents (injection, auth bypass, secrets, supply chain, LLM security, etc.) and returns a structured findings report with severity ratings and remediation advice. Use this when the user asks to audit, scan, or check the security of their project.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'The directory path to scan. Use "." for current directory.',
        },
        agents: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific agent names to run (optional). Omit to run all agents.',
        },
        llm: {
          type: 'boolean',
          description: 'Enable LLM-powered deep analysis for critical/high findings (default: false). Requires ANTHROPIC_API_KEY or similar env var.',
        },
        outputFile: {
          type: 'string',
          description: 'Optional path to save the JSON report for later retrieval with get_findings.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'get_findings',
    description: 'Read and return findings from a ship-safe JSON report file previously saved by scan_repo or the ship-safe CLI (npx ship-safe audit --json). Useful for reviewing or referencing a prior scan without re-running it.',
    inputSchema: {
      type: 'object',
      properties: {
        reportPath: {
          type: 'string',
          description: 'Path to the ship-safe JSON report file (e.g. ship-safe-report.json).',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Filter findings by minimum severity (optional).',
        },
      },
      required: ['reportPath'],
    },
  },
  {
    name: 'suppress_finding',
    description: 'Add a ship-safe-ignore comment to a specific line in a file to suppress a false-positive security finding. The comment tells ship-safe\'s scanner to skip that line in future scans. Always explain why the suppression is safe.',
    inputSchema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          description: 'Path to the file containing the false-positive finding.',
        },
        line: {
          type: 'number',
          description: 'Line number of the finding to suppress (1-indexed).',
        },
        reason: {
          type: 'string',
          description: 'Brief explanation of why this finding is a false positive (appended to the ignore comment).',
        },
      },
      required: ['file', 'line', 'reason'],
    },
  },
];

// =============================================================================
// TOOL IMPLEMENTATIONS
// =============================================================================

async function scanSecrets({ path: targetPath, includeTests = false }) {
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    return { error: `Path does not exist: ${absolutePath}` };
  }

  const stat = fs.statSync(absolutePath);
  const files = stat.isFile()
    ? [absolutePath]
    : await findFiles(absolutePath, includeTests);

  const results = [];

  for (const file of files) {
    const findings = scanFile(file);
    if (findings.length > 0) {
      results.push({ file: path.relative(process.cwd(), file), findings });
    }
  }

  return {
    filesScanned: files.length,
    totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
    clean: results.length === 0,
    findings: results,
    summary: results.length === 0
      ? 'No secrets detected.'
      : `Found ${results.reduce((s, r) => s + r.findings.length, 0)} secret(s) across ${results.length} file(s).`,
    remediation: results.length > 0
      ? 'Move secrets to environment variables. Add .env to .gitignore. Rotate any already-committed credentials.'
      : null,
  };
}

function getChecklist() {
  return {
    title: 'Ship Safe Launch-Day Security Checklist',
    items: [
      { id: 1, category: 'Secrets', check: 'No API keys hardcoded in source code', command: 'npx ship-safe scan .' },
      { id: 2, category: 'Secrets', check: '.env file is in .gitignore', command: null },
      { id: 3, category: 'Secrets', check: '.env.example exists with placeholder values', command: 'npx ship-safe fix' },
      { id: 4, category: 'Database', check: 'Row Level Security (RLS) enabled on all Supabase tables', command: null },
      { id: 5, category: 'Database', check: 'Service role key is server-side only (never in frontend)', command: null },
      { id: 6, category: 'Auth', check: 'Authentication required on all sensitive API routes', command: null },
      { id: 7, category: 'Auth', check: 'JWT tokens expire within 24 hours', command: null },
      { id: 8, category: 'Headers', check: 'Security headers configured (CSP, X-Frame-Options, HSTS)', command: 'npx ship-safe init --headers' },
      { id: 9, category: 'API', check: 'Rate limiting implemented on auth and AI endpoints', command: null },
      { id: 10, category: 'API', check: 'Input validation on all API endpoints', command: null },
      { id: 11, category: 'AI', check: 'Token limits set on all LLM API calls', command: null },
      { id: 12, category: 'AI', check: 'Budget caps configured in AI provider dashboard', command: null },
      { id: 13, category: 'CI/CD', check: 'ship-safe scan runs in CI pipeline', command: null },
      { id: 14, category: 'CI/CD', check: 'Pre-push hook installed', command: 'npx ship-safe guard' },
    ],
  };
}

async function analyzeFile({ path: filePath }) {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    return { error: `File does not exist: ${absolutePath}` };
  }

  const findings = scanFile(absolutePath);

  return {
    file: filePath,
    totalFindings: findings.length,
    clean: findings.length === 0,
    findings,
    summary: findings.length === 0
      ? `No secrets detected in ${path.basename(filePath)}.`
      : `Found ${findings.length} potential secret(s) in ${path.basename(filePath)}.`,
  };
}

async function scanRepo({ path: targetPath, agents: agentFilter, llm = false, outputFile }) {
  const rootPath = path.resolve(targetPath);

  if (!fs.existsSync(rootPath)) {
    return { error: `Path does not exist: ${rootPath}` };
  }

  // MCP communicates over stdout as JSON-RPC. Suppress all console output during
  // the scan so spinner text and log lines don't pollute the transport stream.
  const noop = () => {};
  const savedLog   = console.log;
  const savedWarn  = console.warn;
  const savedError = console.error;
  const savedInfo  = console.info;
  console.log = console.warn = console.error = console.info = noop;

  try {
    const orchestrator = buildOrchestrator();
    const context = { rootPath };

    // Run all agents (quiet:true suppresses ora spinners; console is already nulled)
    const { findings, recon } = await orchestrator.runAll(rootPath, {
      agents: agentFilter,
      timeout: 30000,
      concurrency: 6,
      quiet: true,
    });

    // Optional: LLM deep analysis
    let deepStats = null;
    if (llm) {
      const provider = autoDetectProvider(rootPath, {});
      if (provider) {
        const analyzer = new DeepAnalyzer({ provider, budgetCents: 50, verbose: false });
        await analyzer.analyze(findings, { rootPath, recon });
        deepStats = analyzer.getStats();
      }
    }

    // Score
    const scorer = new ScoringEngine();
    const { score, grade } = scorer.score(findings);

    const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
    const bySeverity = {};
    for (const sev of SEV_ORDER) {
      bySeverity[sev] = findings.filter(f => f.severity === sev).length;
    }

    const report = {
      scannedAt: new Date().toISOString(),
      rootPath,
      score,
      grade,
      totalFindings: findings.length,
      bySeverity,
      findings: findings.map(f => ({
        title:         f.title,
        severity:      f.severity,
        category:      f.category,
        rule:          f.rule,
        file:          f.file ? path.relative(rootPath, f.file) : null,
        line:          f.line,
        description:   f.description,
        remediation:   f.remediation,
        confidence:    f.confidence,
        ...(f.deepAnalysis ? { deepAnalysis: f.deepAnalysis } : {}),
      })),
      ...(deepStats ? { deepAnalysis: deepStats } : {}),
      summary: `Score: ${score}/100 (${grade}) — ${findings.length} finding(s): ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low.`,
    };

    if (outputFile) {
      const outPath = path.resolve(outputFile);
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2), 'utf-8');
      report.savedTo = outPath;
    }

    return report;
  } catch (err) {
    return { error: `Scan failed: ${err.message}` };
  } finally {
    // Always restore console so other tool calls are not affected
    console.log   = savedLog;
    console.warn  = savedWarn;
    console.error = savedError;
    console.info  = savedInfo;
  }
}

function getFindings({ reportPath, severity }) {
  const absPath = path.resolve(reportPath);

  if (!fs.existsSync(absPath)) {
    return { error: `Report file not found: ${absPath}` };
  }

  let report;
  try {
    report = JSON.parse(fs.readFileSync(absPath, 'utf-8'));
  } catch (err) {
    return { error: `Failed to parse report: ${err.message}` };
  }

  const findings = report.findings ?? [];
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  const filtered = severity
    ? findings.filter(f => (SEV_RANK[f.severity] ?? 0) >= (SEV_RANK[severity] ?? 0))
    : findings;

  return {
    reportPath:    absPath,
    scannedAt:     report.scannedAt,
    score:         report.score,
    grade:         report.grade,
    totalFindings: filtered.length,
    bySeverity:    report.bySeverity,
    findings:      filtered,
    summary:       report.summary,
    ...(severity ? { filter: `severity >= ${severity}` } : {}),
  };
}

function suppressFinding({ file, line, reason }) {
  const absPath = path.resolve(file);

  if (!fs.existsSync(absPath)) {
    return { error: `File not found: ${absPath}` };
  }

  let content;
  try {
    content = fs.readFileSync(absPath, 'utf-8');
  } catch (err) {
    return { error: `Cannot read file: ${err.message}` };
  }

  const lines = content.split('\n');
  const lineIdx = line - 1; // Convert to 0-indexed

  if (lineIdx < 0 || lineIdx >= lines.length) {
    return { error: `Line ${line} is out of range (file has ${lines.length} lines)` };
  }

  const targetLine = lines[lineIdx];

  // Already suppressed?
  if (/ship-safe-ignore/i.test(targetLine)) {
    return { alreadySuppressed: true, file: absPath, line, message: 'Line already has a ship-safe-ignore comment.' };
  }

  // Detect indentation and comment style
  const indent = targetLine.match(/^(\s*)/)?.[1] ?? '';
  const isJs   = /\.(js|ts|jsx|tsx|mjs|cjs|java|c|cpp|cs|go|rs|swift|kt)$/.test(file);
  const isPy   = /\.py$/.test(file);
  const isRb   = /\.rb$/.test(file);
  const isHtml = /\.(html?|vue|svelte)$/.test(file);

  let ignoreComment;
  if (isHtml) {
    ignoreComment = `${indent}<!-- ship-safe-ignore — ${reason} -->`;
  } else if (isPy || isRb) {
    ignoreComment = `${indent}# ship-safe-ignore — ${reason}`;
  } else {
    ignoreComment = `${indent}// ship-safe-ignore — ${reason}`;
  }

  // Insert ignore comment on the line BEFORE the finding
  lines.splice(lineIdx, 0, ignoreComment);

  try {
    fs.writeFileSync(absPath, lines.join('\n'), 'utf-8');
  } catch (err) {
    return { error: `Cannot write file: ${err.message}` };
  }

  return {
    suppressed:    true,
    file:          absPath,
    originalLine:  line,
    insertedLine:  line, // The ignore comment is now on this line, original moved to line+1
    comment:       ignoreComment,
    message:       `Added ship-safe-ignore comment before line ${line} in ${path.basename(file)}.`,
  };
}

// =============================================================================
// SCAN UTILITIES (shared with scan command)
// =============================================================================

async function findFiles(rootPath, includeTests) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const files = await fg('**/*', { cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true });

  return files.filter(file => {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    if (SKIP_FILENAMES.has(path.basename(file))) return false;
    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) return false;
    if (!includeTests && TEST_FILE_PATTERNS.some(p => p.test(file))) return false;
    try {
      return fs.statSync(file).size <= MAX_FILE_SIZE;
    } catch { return false; }
  });
}

function scanFile(filePath) {
  const findings = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      if (/ship-safe-ignore/i.test(line)) continue;

      for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
          findings.push({
            line: lineNum + 1,
            type: pattern.name,
            severity: pattern.severity,
            description: pattern.description,
            fix: 'Move to environment variable. Never commit to source control.',
          });
        }
      }
    }
  } catch {}
  return findings;
}

// =============================================================================
// MCP STDIO SERVER
// =============================================================================

export async function mcpCommand() {
  // MCP uses JSON-RPC 2.0 over stdio
  process.stdin.setEncoding('utf-8');

  let buffer = '';

  process.stdin.on('data', async (chunk) => {
    buffer += chunk;

    // MCP messages are newline-delimited JSON
    const lines = buffer.split('\n');
    buffer = lines.pop(); // Keep incomplete line in buffer

    for (const line of lines) {
      if (!line.trim()) continue;

      try {
        const request = JSON.parse(line);
        const response = await handleRequest(request);
        process.stdout.write(JSON.stringify(response) + '\n');
      } catch (err) {
        const errorResponse = {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error', data: err.message },
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
      }
    }
  });

  process.stdin.on('end', () => process.exit(0));
}

async function handleRequest(request) {
  const { jsonrpc, id, method, params } = request;

  const respond = (result) => ({ jsonrpc: '2.0', id, result });
  const respondError = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'initialize':
      return respond({
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'ship-safe', version: '3.0.0' },
      });

    case 'tools/list':
      return respond({ tools: TOOLS });

    case 'tools/call': {
      const { name, arguments: args } = params;

      try {
        let result;
        switch (name) {
          case 'scan_secrets':
            result = await scanSecrets(args);
            break;
          case 'get_checklist':
            result = getChecklist();
            break;
          case 'analyze_file':
            result = await analyzeFile(args);
            break;
          case 'scan_repo':
            result = await scanRepo(args);
            break;
          case 'get_findings':
            result = getFindings(args);
            break;
          case 'suppress_finding':
            result = suppressFinding(args);
            break;
          default:
            return respondError(-32601, `Unknown tool: ${name}`);
        }

        return respond({
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
      } catch (err) {
        return respondError(-32603, err.message);
      }
    }

    case 'notifications/initialized':
      return null; // No response needed for notifications

    default:
      return respondError(-32601, `Method not found: ${method}`);
  }
}
