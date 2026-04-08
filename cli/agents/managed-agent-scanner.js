/**
 * ManagedAgentScanner
 * ====================
 *
 * Detect security misconfigurations in Claude Managed Agents definitions.
 *
 * Claude Managed Agents (beta, April 2026) introduces a hosted agent
 * infrastructure with Agents, Environments, Sessions, and Vaults.
 * Misconfigurations in these definitions — unrestricted networking,
 * always_allow permission policies, all tools enabled by default —
 * map directly to OWASP Agentic AI Top 10 risks (ASI-03, ASI-04, ASI-05).
 *
 * Scans: Python, TypeScript, JavaScript, JSON, YAML, shell scripts, and
 *        any file containing Managed Agents API calls or SDK usage.
 *
 * Maps to: OWASP Agentic AI ASI-03 (Excessive Agency),
 *          ASI-04 (Inadequate Sandboxing), ASI-05 (Improper Tool Use),
 *          ASI-07 (Lack of Human Oversight)
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// SINGLE-LINE REGEX PATTERNS
// =============================================================================

const PATTERNS = [
  // ── ASI-03: Excessive Agency — Permission Policies ─────────────────────────
  {
    rule: 'MANAGED_AGENT_ALWAYS_ALLOW',
    title: 'Managed Agent: All Tools Set to always_allow',
    regex: /permission_policy['":\s]*\{?\s*['"]?type['"]?\s*[:=]\s*['"]always_allow['"]/g,
    severity: 'critical',
    cwe: 'CWE-269',
    owasp: 'ASI03',
    description: 'Claude Managed Agent permission policy is set to always_allow. All tools — including bash and file write — execute without human confirmation. Any prompt injection in the session can run arbitrary commands ungateed.',
    fix: 'Set permission_policy to {type: "always_ask"} for the agent toolset, or at minimum require confirmation for bash and write tools using per-tool configs.',
  },

  // ── ASI-04: Inadequate Sandboxing — Networking ─────────────────────────────
  {
    rule: 'MANAGED_AGENT_UNRESTRICTED_NET',
    title: 'Managed Agent: Unrestricted Network Access',
    regex: /networking['":\s]*\{?\s*['"]?type['"]?\s*[:=]\s*['"]unrestricted['"]/g,
    severity: 'high',
    cwe: 'CWE-284',
    owasp: 'ASI04',
    description: 'Managed Agent environment has unrestricted outbound networking. An agent with bash and web_fetch tools can exfiltrate code, secrets, or PII to any external endpoint.',
    fix: 'Use networking: {type: "limited", allowed_hosts: ["api.example.com"]} with an explicit allowlist. Only grant allow_mcp_servers and allow_package_managers if needed.',
  },

  // ── ASI-05: Improper Tool Use — Full Toolset Default ───────────────────────
  {
    rule: 'MANAGED_AGENT_ALL_TOOLS_DEFAULT',
    title: 'Managed Agent: Full Toolset Enabled With No Restrictions',
    regex: /['"]?type['"]?\s*[:=]\s*['"]agent_toolset_20260401['"]/g,
    severity: 'high',
    cwe: 'CWE-250',
    owasp: 'ASI05',
    confidence: 'medium',
    description: 'agent_toolset_20260401 enables all 8 built-in tools (bash, read, write, edit, glob, grep, web_fetch, web_search) by default. Without a configs array or default_config, the agent has maximum tool access.',
    fix: 'Use default_config: {enabled: false} and explicitly enable only the tools your agent needs. Disable web_fetch and web_search if the agent does not need internet access.',
  },

  // ── ASI-05: MCP Toolset Permission Override ────────────────────────────────
  {
    rule: 'MANAGED_AGENT_MCP_ALWAYS_ALLOW',
    title: 'Managed Agent: MCP Toolset Set to always_allow',
    regex: /mcp_toolset['",\s]*[\s\S]{0,200}permission_policy['":\s]*\{?\s*['"]?type['"]?\s*[:=]\s*['"]always_allow['"]/g,
    severity: 'high',
    cwe: 'CWE-269',
    owasp: 'ASI05',
    description: 'MCP toolset permission policy overridden from the safe default (always_ask) to always_allow. Third-party MCP server tools will execute without human confirmation — if the MCP server adds new tools, they auto-execute too.',
    fix: 'Keep MCP toolset at the default always_ask policy, or audit the MCP server tools before setting always_allow.',
  },

  // ── ASI-04: MCP Server Over HTTP ───────────────────────────────────────────
  {
    rule: 'MANAGED_AGENT_MCP_HTTP',
    title: 'Managed Agent: MCP Server URL Uses Plain HTTP',
    regex: /mcp_server(?:_url|s)?['":\s]*[\s\S]{0,100}['"]http:\/\/(?!localhost|127\.0\.0\.1|::1)/g,
    severity: 'critical',
    cwe: 'CWE-319',
    owasp: 'ASI04',
    description: 'MCP server URL uses unencrypted HTTP for a non-localhost endpoint. All tool calls, results, and credentials are transmitted in cleartext.',
    fix: 'Use https:// for all MCP server URLs. Only http://localhost is acceptable for local development.',
  },

  // ── ASI-03: Callable Agents (Multi-Agent Escalation) ───────────────────────
  {
    rule: 'MANAGED_AGENT_CALLABLE_AGENTS',
    title: 'Managed Agent: Multi-Agent Orchestration Enabled',
    regex: /callable_agents\s*[:=]/g,
    severity: 'medium',
    cwe: 'CWE-269',
    owasp: 'ASI03',
    confidence: 'medium',
    description: 'Agent has callable_agents configured, enabling multi-agent orchestration. A compromised child agent can escalate privileges through the parent if tool access is not scoped per-agent.',
    fix: 'Apply least-privilege tool access to each callable agent independently. Do not grant child agents broader tool access than their parent.',
  },

  // ── ASI-07: No System Prompt ───────────────────────────────────────────────
  {
    rule: 'MANAGED_AGENT_NO_SYSTEM_PROMPT',
    title: 'Managed Agent: No System Prompt Defined',
    regex: /(?:agents\.create|\/v1\/agents)\s*\([^)]*\)/g,
    severity: 'low',
    cwe: 'CWE-1188',
    owasp: 'ASI07',
    confidence: 'low',
    description: 'Agent created without a system prompt. Without behavioral constraints, the agent is more susceptible to prompt injection and goal hijacking.',
    fix: 'Add a system prompt that defines the agent\'s role, boundaries, and what it must refuse to do.',
  },

  // ── Credential Exposure — Hardcoded Tokens ─────────────────────────────────
  {
    rule: 'MANAGED_AGENT_HARDCODED_TOKEN',
    title: 'Managed Agent: Hardcoded Credential in Config',
    regex: /(?:access_token|refresh_token|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-/.]{20,}['"]/g,
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'ASI04',
    description: 'Vault credential (access_token, refresh_token, or client_secret) appears hardcoded in source code. These should be injected from environment variables or a secrets manager, not committed to the repository.',
    fix: 'Move tokens to environment variables or a secrets manager. Use vault_ids at session creation to inject credentials at runtime.',
  },

  // ── ASI-04: Static Bearer Token in Source ──────────────────────────────────
  {
    rule: 'MANAGED_AGENT_STATIC_BEARER_INLINE',
    title: 'Managed Agent: Static Bearer Token in Source',
    regex: /['"]?type['"]?\s*[:=]\s*['"]static_bearer['"][\s\S]{0,150}['"]?token['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-/.]{20,}['"]/g,
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'ASI04',
    description: 'A static_bearer credential with an inline token is defined in source code. This token is visible to anyone with repository access.',
    fix: 'Store the token in a secrets manager or environment variable. Reference it at runtime: token: process.env.LINEAR_API_KEY.',
  },
];

// =============================================================================
// MULTI-LINE / STRUCTURAL PATTERNS (checked via content analysis)
// =============================================================================

/**
 * Check for environment configs missing network restrictions entirely.
 * Pattern: environment creation with no networking field → defaults to unrestricted.
 */
function checkMissingNetworkConfig(content, filePath, agent) {
  const findings = [];
  // Match environment creation calls that have a config block but no networking field
  const envCreateRe = /(?:environments\.create|\/v1\/environments)\s*\(/g;
  let match;
  while ((match = envCreateRe.exec(content)) !== null) {
    // Look ahead up to 500 chars for a config block
    const snippet = content.slice(match.index, match.index + 500);
    if (snippet.includes('config') && !snippet.includes('networking')) {
      const line = content.slice(0, match.index).split('\n').length;
      findings.push(createFinding({
        file: filePath,
        line,
        severity: 'medium',
        category: agent.category,
        rule: 'MANAGED_AGENT_NO_NETWORK_LIMIT',
        title: 'Managed Agent: Environment Created Without Network Config',
        description: 'Environment created without a networking field. Defaults to unrestricted outbound access. For production, explicitly set networking: {type: "limited"} with an allowed_hosts list.',
        matched: snippet.slice(0, 120),
        confidence: 'medium',
        cwe: 'CWE-284',
        owasp: 'ASI04',
        fix: 'Add networking: {type: "limited", allowed_hosts: ["your-api.example.com"]} to the environment config.',
      }));
    }
  }
  return findings;
}

/**
 * Check for bash + web tools enabled with always_allow — exfiltration combo.
 */
function checkExfilCombo(content, filePath, agent) {
  const findings = [];
  // Only flag if we see the toolset AND always_allow AND no bash restriction
  const hasToolset = /agent_toolset_20260401/.test(content);
  const hasAlwaysAllow = /always_allow/.test(content);
  const hasBashRestriction = /['"]bash['"][\s\S]{0,100}always_ask/.test(content);
  const disablesBash = /['"]bash['"][\s\S]{0,50}enabled['"]?\s*[:=]\s*false/.test(content);

  if (hasToolset && hasAlwaysAllow && !hasBashRestriction && !disablesBash) {
    // Find the line of always_allow for positioning
    const idx = content.indexOf('always_allow');
    const line = idx >= 0 ? content.slice(0, idx).split('\n').length : 1;
    findings.push(createFinding({
      file: filePath,
      line,
      severity: 'critical',
      category: agent.category,
      rule: 'MANAGED_AGENT_BASH_NO_CONFIRM',
      title: 'Managed Agent: Bash Executes Without Human Confirmation',
      description: 'Agent toolset uses always_allow and bash is not restricted to always_ask. Any prompt injection can execute shell commands without confirmation. This is equivalent to --dangerously-skip-permissions in Claude Code.',
      matched: 'permission_policy: always_allow (bash unrestricted)',
      confidence: 'high',
      cwe: 'CWE-78',
      owasp: 'ASI03',
      fix: 'Add a per-tool override: configs: [{name: "bash", permission_policy: {type: "always_ask"}}].',
    }));
  }
  return findings;
}

/**
 * Check for unpinned packages in environment config.
 */
function checkUnpinnedPackages(content, filePath, agent) {
  const findings = [];
  // Look for packages blocks with items that lack version pins
  const packagesRe = /packages['":\s]*\{[\s\S]{0,500}\}/g;
  let match;
  while ((match = packagesRe.exec(content)) !== null) {
    const block = match[0];
    // Check for pip packages without ==, npm without @, etc.
    const unpinnedPip = /pip['":\s]*\[([^\]]+)\]/.exec(block);
    const unpinnedNpm = /npm['":\s]*\[([^\]]+)\]/.exec(block);

    const checkList = (listMatch, manager) => {
      if (!listMatch) return;
      const items = listMatch[1].match(/['"][^'"]+['"]/g) || [];
      const unpinned = items.filter(item => {
        const clean = item.replace(/['"]/g, '');
        if (manager === 'pip') return !clean.includes('==') && !clean.includes('>=');
        return !clean.includes('@');
      });
      if (unpinned.length > 0) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push(createFinding({
          file: filePath,
          line,
          severity: 'medium',
          category: agent.category,
          rule: 'MANAGED_AGENT_UNPINNED_PACKAGE',
          title: `Managed Agent: Unpinned ${manager} Packages in Environment`,
          description: `Environment installs ${manager} packages without version pins: ${unpinned.join(', ')}. Unpinned packages can be hijacked via supply chain attacks.`,
          matched: unpinned.join(', '),
          confidence: 'medium',
          cwe: 'CWE-829',
          owasp: 'ASI04',
          fix: `Pin package versions: ${manager === 'pip' ? '"pandas==2.2.0"' : '"express@4.18.0"'}.`,
        }));
      }
    };

    checkList(unpinnedPip, 'pip');
    checkList(unpinnedNpm, 'npm');
  }
  return findings;
}

// =============================================================================
// AGENT CLASS
// =============================================================================

export class ManagedAgentScanner extends BaseAgent {
  constructor() {
    super(
      'ManagedAgentScanner',
      'Detect security misconfigurations in Claude Managed Agents (environments, tools, permissions, networking)',
      'agentic',
    );
  }

  /**
   * Only run if the codebase references Managed Agents API/SDK.
   */
  shouldRun(recon) {
    return true; // Lightweight patterns — always run, regex will short-circuit on non-matching files
  }

  async analyze(context) {
    const { rootPath, files } = context;

    // Filter to files likely containing Managed Agent configs
    const targetFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      const basename = path.basename(f).toLowerCase();
      return (
        ['.js', '.ts', '.mjs', '.mts', '.py', '.json', '.yaml', '.yml', '.sh', '.bash', '.go', '.java', '.cs', '.php', '.rb'].includes(ext) ||
        basename === 'dockerfile' ||
        basename === 'docker-compose.yml' ||
        basename === 'docker-compose.yaml'
      );
    });

    if (targetFiles.length === 0) return [];

    let findings = [];

    for (const file of targetFiles) {
      const content = this.readFile(file);
      if (!content) continue;

      // Quick relevance check — skip files with no Managed Agent signals
      const hasSignal =
        content.includes('agent_toolset_20260401') ||
        content.includes('managed-agents') ||
        content.includes('/v1/agents') ||
        content.includes('/v1/environments') ||
        content.includes('/v1/sessions') ||
        content.includes('/v1/vaults') ||
        content.includes('beta.agents') ||
        content.includes('beta.environments') ||
        content.includes('beta.sessions') ||
        content.includes('beta.vaults') ||
        content.includes('callable_agents') ||
        content.includes('mcp_toolset') ||
        content.includes('static_bearer') ||
        content.includes('mcp_oauth');

      if (!hasSignal) continue;

      // Run single-line patterns
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));

      // Run structural checks
      findings = findings.concat(checkMissingNetworkConfig(content, file, this));
      findings = findings.concat(checkExfilCombo(content, file, this));
      findings = findings.concat(checkUnpinnedPackages(content, file, this));
    }

    return findings;
  }
}

export default ManagedAgentScanner;
