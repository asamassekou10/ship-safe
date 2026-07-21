export type AgentTemplateIcon = 'shield' | 'network' | 'target' | 'key' | 'package' | 'api';

export interface AgentTemplate {
  id: string;
  name: string;
  description: string;
  icon: AgentTemplateIcon;
  tools: string[];
  memoryProvider: string;
  maxDepth: number;
  promptHint: string;
}

const TEMPLATES: AgentTemplate[] = [
  {
    id: 'repository-auditor',
    name: 'Repository Auditor',
    description: 'Reviews application code and configuration for exploitable security issues.',
    icon: 'shield',
    tools: ['read_file', 'list_files', 'grep_codebase', 'terminal', 'web_search'],
    memoryProvider: 'builtin',
    maxDepth: 2,
    promptHint: 'Audit this repository, prioritize exploitable findings, and provide concrete fixes.',
  },
  {
    id: 'mcp-guard',
    name: 'MCP Tool-Call Guard',
    description: 'Reviews MCP servers, tool permissions, transports, and agent trust boundaries.',
    icon: 'network',
    tools: ['read_file', 'list_files', 'grep_codebase', 'terminal'],
    memoryProvider: 'builtin',
    maxDepth: 2,
    promptHint: 'Inspect every MCP tool and transport for unsafe permissions, injection, and data exposure.',
  },
  {
    id: 'red-team',
    name: 'AI Red-Team Agent',
    description: 'Challenges an AI application with adaptive attacks and verifies guardrail behavior.',
    icon: 'target',
    tools: ['browser', 'terminal', 'web_search', 'delegate_task'],
    memoryProvider: 'builtin',
    maxDepth: 2,
    promptHint: 'Red-team this AI system, adapt attacks to observed behavior, and preserve reproducible evidence.',
  },
  {
    id: 'secrets-scanner',
    name: 'Secrets Monitor',
    description: 'Finds exposed API keys, credentials, tokens, and unsafe secret handling.',
    icon: 'key',
    tools: ['read_file', 'list_files', 'grep_codebase'],
    memoryProvider: 'builtin',
    maxDepth: 1,
    promptHint: 'Scan the codebase for exposed secrets and report safe rotation steps without revealing values.',
  },
  {
    id: 'dependency-auditor',
    name: 'Dependency Auditor',
    description: 'Investigates vulnerable packages, reachable CVEs, and safer upgrade paths.',
    icon: 'package',
    tools: ['read_file', 'list_files', 'terminal', 'web_search'],
    memoryProvider: 'builtin',
    maxDepth: 1,
    promptHint: 'Audit dependencies, confirm exploitability, and recommend the lowest-risk upgrade path.',
  },
  {
    id: 'api-security',
    name: 'API Security Tester',
    description: 'Tests authentication, authorization, rate limits, data exposure, and IDOR risks.',
    icon: 'api',
    tools: ['read_file', 'list_files', 'terminal', 'web_search', 'browser'],
    memoryProvider: 'builtin',
    maxDepth: 2,
    promptHint: 'Test the API for practical abuse paths and return reproducible requests with remediation guidance.',
  },
];

export default TEMPLATES;
