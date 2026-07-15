/**
 * SwarmOrchestrator — K2.6-Powered Parallel Security Swarm
 * ==========================================================
 *
 * Instead of running the local agent pool in Node.js (chunks of 6),
 * --swarm sends the entire task to Kimi K2.6 and lets its native
 * 300-agent swarm handle parallel analysis.
 *
 * Each of Ship Safe's AI security attack classes is assigned as an explicit
 * sub-agent role. K2.6 fans out, each sub-agent scans for its class,
 * and results are returned as a consolidated findings array.
 *
 * Output is mapped back to Ship Safe's Finding format so SARIF,
 * HTML reports, and CI exit codes work unchanged.
 *
 * USAGE:
 *   npx ship-safe red-team . --swarm
 *   npx ship-safe red-team . --swarm --provider kimi
 */

import fs from 'fs';
import path from 'path';
import { createProvider, autoDetectProvider } from '../providers/llm-provider.js';
import { ReconAgent } from './recon-agent.js';
import { createFinding } from './base-agent.js';

// =============================================================================
// AGENT ROLE DEFINITIONS — maps Ship Safe's attack classes to swarm roles
// =============================================================================

const SWARM_ROLES = [
  { id: 'injection',           name: 'Injection Tester',            desc: 'SQL injection, command injection, LDAP injection, XPath injection, template injection' },
  { id: 'auth-bypass',         name: 'Auth Bypass Agent',           desc: 'Authentication bypass, authorization flaws, privilege escalation, JWT weaknesses' },
  { id: 'ssrf',                name: 'SSRF Prober',                 desc: 'Server-side request forgery, SSRF via redirects, internal service exposure' },
  { id: 'supply-chain',        name: 'Supply Chain Auditor',        desc: 'Dependency confusion, typosquatting, malicious packages, outdated deps with CVEs' },
  { id: 'config',              name: 'Config Auditor',              desc: 'Hardcoded secrets, insecure defaults, exposed debug endpoints, misconfigured CORS' },
  { id: 'llm-redteam',         name: 'LLM Red Team',               desc: 'Prompt injection, jailbreaks, unsafe LLM output rendering, model inversion' },
  { id: 'mobile',              name: 'Mobile Scanner',             desc: 'Insecure data storage, weak crypto, insecure communication, exported components' },
  { id: 'git-history',         name: 'Git History Scanner',        desc: 'Secrets committed in git history, deleted files with sensitive data' },
  { id: 'cicd',                name: 'CI/CD Scanner',              desc: 'Insecure GitHub Actions, exposed secrets in workflows, artifact poisoning' },
  { id: 'api-fuzzer',          name: 'API Fuzzer',                 desc: 'Missing input validation, mass assignment, insecure direct object references (IDOR)' },
  { id: 'supabase-rls',        name: 'Supabase RLS Agent',         desc: 'Missing row-level security, exposed Supabase service keys, insecure RLS policies' },
  { id: 'mcp-security',        name: 'MCP Security Agent',         desc: 'Tool poisoning, MCP server misconfiguration, unsafe tool definitions' },
  { id: 'agentic-security',    name: 'Agentic Security Agent',     desc: 'Agentic loop vulnerabilities, unsafe tool use, context window attacks' },
  { id: 'rag-security',        name: 'RAG Security Agent',         desc: 'Prompt injection via retrieved documents, data poisoning, retrieval manipulation' },
  { id: 'pii-compliance',      name: 'PII Compliance Agent',       desc: 'PII exposure, GDPR/CCPA violations, unencrypted personal data' },
  { id: 'vibe-coding',         name: 'Vibe Coding Agent',          desc: 'AI-generated code security issues, hardcoded values from iterative prompting' },
  { id: 'exception-handler',   name: 'Exception Handler Agent',    desc: 'Stack traces in responses, error information disclosure, unhandled exceptions' },
  { id: 'agent-config',        name: 'Agent Config Scanner',       desc: 'Insecure agent config files (.cursorrules, CLAUDE.md, MCP configs)' },
  { id: 'memory-poisoning',    name: 'Memory Poisoning Agent',     desc: 'Malicious content in AI memory stores, embedding poisoning' },
  { id: 'managed-agent',       name: 'Managed Agent Scanner',      desc: 'Insecure managed agent platforms, overprivileged agents' },
  { id: 'hermes-security',     name: 'Hermes Security Agent',      desc: 'Hermes CLI security, agent tool permissions, orchestrator misconfiguration' },
  { id: 'agent-attestation',   name: 'Agent Attestation Agent',    desc: 'Missing agent identity verification, unauthenticated agent-to-agent calls' },
  { id: 'agentic-supply-chain', name: 'Agentic Supply Chain Agent', desc: 'Compromised AI integrations, OAuth scope creep, MCP server supply chain' },
  { id: 'roblox-security',     name: 'Roblox Security Agent',      desc: 'Malicious Roblox/Luau assets, runtime asset injection, hidden payload loaders' },
  { id: 'model-scan',          name: 'Model Scan Agent',           desc: 'Executable ML model weights, pickle payloads, unsafe torch.load usage' },
  { id: 'trust-boundary',      name: 'Trust Boundary Agent',       desc: 'GhostApproval symlinks, repo trust-boundary escapes, run-on-review instructions' },
  { id: 'slopsquat',           name: 'SlopSquat Agent',            desc: 'Hallucinated package imports, phantom dependencies, slopsquatting risk' },
  { id: 'clickfix',            name: 'ClickFix Agent',             desc: 'Fake CAPTCHA paste-and-run lures, fake installer scripts, command cradles' },
  { id: 'install-guard',       name: 'Install Guard Agent',        desc: 'npm worm lifecycle behavior, credential harvesting, destructive install scripts' },
];

// Max file content to include in the swarm prompt (cost control)
const MAX_FILE_CHARS = 200_000;
const MAX_FILES = 100;

// =============================================================================
// SWARM ORCHESTRATOR
// =============================================================================

export class SwarmOrchestrator {
  /**
   * @param {object} options
   * @param {object}  options.provider    — LLM provider (must be Kimi or OpenAI-compatible with tool use)
   * @param {boolean} options.verbose
   * @param {number}  options.budgetCents
   */
  constructor(options = {}) {
    this.provider = options.provider;
    this.verbose = options.verbose || false;
    this.budgetCents = options.budgetCents ?? 200;
  }

  static create(rootPath, options = {}) {
    if (typeof options.provider === 'string') {
      // Explicit provider requested
      const provider = autoDetectProvider(rootPath, { provider: options.provider, model: options.model });
      if (!provider) return null;
      return new SwarmOrchestrator({ provider, verbose: options.verbose, budgetCents: options.budgetCents });
    }

    // Auto-select: prefer deepseek-flash (1M ctx, cheap) then kimi as fallback
    for (const [providerName, swarmModel] of [
      ['deepseek-flash', 'deepseek-v4-flash'],
      ['kimi',           'moonshot-v1-128k'],
    ]) {
      const provider = autoDetectProvider(rootPath, { provider: providerName, model: swarmModel });
      if (provider) return new SwarmOrchestrator({ provider, verbose: options.verbose, budgetCents: options.budgetCents });
    }

    return null;
  }

  /**
   * Run the swarm scan against a codebase.
   *
   * @param {string} rootPath
   * @param {object} reconData — Output from ReconAgent
   * @param {string[]} files   — All scannable files
   * @returns {Promise<object[]>} — findings[]
   */
  async run(rootPath, reconData, files) {
    const codeBundle = this._bundleCode(rootPath, files);
    const prompt = this._buildSwarmPrompt(reconData, codeBundle, rootPath);

    const systemPrompt = `You are a security swarm coordinator. You MUST respond with ONLY a valid JSON object — no prose, no markdown, no explanation, no code fences. Your response must start with { and end with }. Deploy all ${SWARM_ROLES.length} sub-agents, each scanning for their attack class, then output the consolidated JSON findings.`;

    const jsonInstruction = '\n\nOutput a JSON object with exactly these keys: {"findings":[{"agentId":"<agent-id>","file":"<relative-path>","line":<number>,"severity":"critical|high|medium|low","rule":"<rule-id>","title":"<title>","description":"<description>","remediation":"<fix>"}],"agentSummary":[{"agentId":"<agent-id>","findingCount":<number>,"status":"clean|findings"}]}';

    const text = await this.provider.complete(systemPrompt, prompt + jsonInstruction, { maxTokens: 8192, jsonMode: true });
    let raw;
    try {
      raw = JSON.parse(text || '{}');
    } catch {
      if (this.verbose) console.log('  [Swarm] JSON parse failed. Preview:', text?.slice(0, 200));
      raw = null;
    }

    return this._mapFindings(raw?.findings ?? [], rootPath);
  }

  _bundleCode(rootPath, files) {
    let bundle = '';
    let totalChars = 0;
    const selected = files.slice(0, MAX_FILES);

    for (const filePath of selected) {
      if (totalChars >= MAX_FILE_CHARS) break;
      try {
        const relPath = path.relative(rootPath, filePath);
        const content = fs.readFileSync(filePath, 'utf-8');
        const snippet = content.slice(0, Math.min(8000, MAX_FILE_CHARS - totalChars));
        bundle += `\n\n### ${relPath}\n\`\`\`\n${snippet}\n\`\`\``;
        totalChars += snippet.length;
      } catch { /* skip unreadable */ }
    }

    return bundle;
  }

  _buildSwarmPrompt(recon, codeBundle, rootPath) {
    const projectName = path.basename(rootPath);
    const reconSummary = recon
      ? [
          recon.frameworks?.length ? `Frameworks: ${recon.frameworks.join(', ')}` : '',
          recon.databases?.length  ? `Databases: ${recon.databases.join(', ')}`   : '',
          recon.authPatterns?.length ? `Auth patterns: ${recon.authPatterns.join(', ')}` : '',
          recon.languages?.length  ? `Languages: ${recon.languages.join(', ')}`   : '',
        ].filter(Boolean).join('\n')
      : '';

    const agentList = SWARM_ROLES.map((r, i) =>
      `  Sub-agent ${String(i + 1).padStart(2, '0')} [${r.id}] — ${r.name}: ${r.desc}`
    ).join('\n');

    return `# Security Swarm Task: ${projectName}

## Project Context
${reconSummary || 'No recon data available.'}

## Sub-Agent Assignments
Deploy all ${SWARM_ROLES.length} sub-agents in parallel. Each scans for exactly their assigned attack class:

${agentList}

## Instructions
1. Each sub-agent independently analyzes the full codebase for its attack class.
2. For each finding, record: agentId (the sub-agent's id), file path, line number, severity, a rule identifier, title, description, the matched snippet, and remediation advice.
3. Severity scale: critical (exploitable now), high (likely exploitable), medium (potential issue), low (best practice), info (note).
4. Report all findings from all sub-agents in the tool call, even if the list is long.
5. If a sub-agent finds nothing, include it in agentSummary with status "clean" and findingCount 0.

## Codebase
${codeBundle}`;
  }

  _mapFindings(rawFindings, rootPath) {
    return rawFindings.map(r => {
      const role = SWARM_ROLES.find(a => a.id === r.agentId) || { name: 'SwarmAgent', id: r.agentId };
      return createFinding({
        file: r.file ? path.resolve(rootPath, r.file) : null,
        line: r.line || 0,
        severity: r.severity || 'medium',
        confidence: 'medium',
        rule: r.rule || `swarm:${role.id}`,
        title: r.title,
        description: r.description,
        matched: r.matched || '',
        remediation: r.remediation || '',
        category: role.name,
      });
    });
  }
}

export default SwarmOrchestrator;
