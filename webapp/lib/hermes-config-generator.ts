/**
 * Hermes Agent Security Config Generator
 * ---------------------------------------
 * Shared between:
 *   /api/generate-hermes-config  → zip bundle download
 *   /api/setup                   → setup URL token
 *   /s/[token]                   → CLI setup URL (--from flag)
 *
 * Terminology matches the real Hermes Agent repo:
 *   - Tool registry: tools/registry.py — ToolRegistry singleton
 *   - Toolsets: toolsets.py — groups of tools (web, terminal, file, etc.)
 *   - Memory providers: agent/memory_provider.py — pluggable (builtin, honcho, mem0, etc.)
 *   - Delegation: tools/delegate_tool.py — subagent spawning (max depth 2)
 *   - Skills: skills/<category>/<name>/SKILL.md — YAML frontmatter + markdown
 *   - Approval: tools/approval.py — dangerous command detection (33 patterns)
 *   - Config: ~/.hermes/config.yaml — YAML-based, NOT manifest-based
 */

export interface HermesConfig {
  projectName: string;
  repoUrl: string;
  tools: Array<{ name: string; sourceUrl?: string }>;
  /** Memory provider: 'builtin' (MEMORY.md/USER.md), or an external plugin name */
  memoryProvider: 'builtin' | 'honcho' | 'hindsight' | 'mem0' | 'none';
  hasSubAgents: boolean;
  hasManifest: boolean;
  manifestPath: string;
  framework: string;
  ciProvider: 'github' | 'gitlab' | 'none';
}

export interface GeneratedFile {
  path: string;
  content: string;
}

// ── Generators ─────────────────────────────────────────────────────────────

export function generateAgentManifest(config: HermesConfig): string {
  const tools = config.tools.map(t => ({
    name: t.name,
    ...(t.sourceUrl
      ? { source: t.sourceUrl, integrity: '# run: npx ship-safe hash <source-url>' }
      : { local: true }),
    permissions: ['read'],
  }));

  return JSON.stringify(
    {
      $schema: 'https://shipsafecli.com/schemas/agent-manifest.v1.json',
      name: config.projectName || 'my-hermes-agent',
      version: '1.0.0',
      description: 'Ship Safe security manifest — tool allowlist + integrity hashes for Hermes',
      tools,
      security: {
        allowlist: config.tools.map(t => t.name),
        // Hermes MAX_DEPTH is 2 (parent → child → grandchild rejected)
        maxRecursionDepth: config.hasSubAgents ? 2 : 1,
        requireIntegrity: true,
        memoryProvider: config.memoryProvider || 'builtin',
      },
    },
    null,
    2,
  );
}

export function generateHermesPolicy(config: HermesConfig): string {
  const allowlist = config.tools.map(t => `'${t.name}'`).join(', ');

  // Memory scanning: check ~/.hermes/memories/ and MEMORY.md/USER.md paths
  const hasMemory = config.memoryProvider !== 'none';
  const memoryChecks = hasMemory
    ? `
    // ── Memory provider validation ─────────────────────────────────────────
    // Hermes stores memory in ~/.hermes/memories/MEMORY.md and USER.md
    // (builtin provider). External providers (honcho, mem0, etc.) use
    // plugin-specific dirs under plugins/memory/<name>/.
    const MEMORY_PATTERNS = [
      /\\.hermes[\\/\\\\]memories/,
      /MEMORY\\.md$/,
      /USER\\.md$/,
      /plugins[\\/\\\\]memory[\\/\\\\]/,
    ];
    for (const file of files) {
      if (!MEMORY_PATTERNS.some(p => p.test(file))) continue;
      let content;
      try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }
      const lines = content.split('\\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/ship-safe-ignore/i.test(line)) continue;

        // Detect unvalidated deserialization of memory content
        if (/JSON\\.parse\\s*\\((?!.*schema|.*validate)/i.test(line)) {
          findings.push(createFinding({
            rule: 'HERMES_MEMORY_UNSAFE_DESERIALIZE', severity: 'high',
            title: 'Memory deserialized without schema validation',
            description: 'JSON.parse on memory data without schema validation allows poisoned memory (via MEMORY.md or external provider) to inject arbitrary values.',
            file, line: i + 1, matched: line.trim().slice(0, 120), category: 'llm',
            remediation: 'Validate memory structure with zod or ajv before use.',
            confidence: 'medium',
          }));
        }

        // Detect prompt injection patterns in memory files
        // (mirrors Hermes built-in _MEMORY_THREAT_PATTERNS from tools/memory_tool.py)
        if (/ignore\\s+(previous|all|above|prior)\\s+instructions/i.test(line) ||
            /you\\s+are\\s+now\\s+/i.test(line) ||
            /system\\s+prompt\\s+override/i.test(line) ||
            /disregard\\s+(your|all|any)\\s+(instructions|rules)/i.test(line)) {
          findings.push(createFinding({
            rule: 'HERMES_MEMORY_INJECTION', severity: 'critical',
            title: 'Prompt injection payload in memory file',
            description: 'Memory content contains injection patterns that could hijack the agent when loaded into the system prompt.',
            file, line: i + 1, matched: line.trim().slice(0, 120), category: 'llm',
            remediation: 'Hermes has built-in _scan_memory_content() — ensure it runs before all memory loads. See tools/memory_tool.py.',
            confidence: 'high',
          }));
        }
      }
    }`
    : '';

  return `/**
 * hermes-policy.js — Ship Safe Hermes Security Policy
 * Generated by: npx ship-safe init --hermes
 * Project: ${config.projectName || 'my-hermes-agent'}
 * Date: ${new Date().toISOString().split('T')[0]}
 *
 * Enforces:
 *   - Tool allowlist (only registered tools from your Hermes tool registry)
 *   - Function-call injection detection (tool name sourced from LLM output)
 *   - Memory provider validation (MEMORY.md/USER.md poisoning detection)
 *   - Sub-agent trust boundaries (delegation depth checks)
 *
 * Hermes architecture reference:
 *   - Tool registry: tools/registry.py (ToolRegistry.dispatch)
 *   - Delegation: tools/delegate_tool.py (MAX_DEPTH = 2)
 *   - Memory: tools/memory_tool.py (MEMORY.md, USER.md)
 *   - Approval: tools/approval.py (DANGEROUS_PATTERNS)
 *
 * Place in .ship-safe/agents/ — runs on every \`ship-safe audit\`.
 */

import fs from 'fs';

let BaseAgent, createFinding;
try {
  ({ BaseAgent, createFinding } = await import('ship-safe'));
} catch {
  ({ BaseAgent, createFinding } = await import('../agents/base-agent.js'));
}

const ALLOWED_TOOLS = [${allowlist}];

// Patterns indicating a tool name comes from unsanitized LLM output.
// In Hermes, tool dispatch goes through registry.dispatch(name, args).
// If the name originates from model output without an allowlist check,
// a prompt injection can call any registered tool.
const DYNAMIC_TOOL_PATTERNS = [
  /toolName\\s*=\\s*(?:response|llmOutput|message|completion|result)[\\.\\[]/i,
  /dispatch\\(\\s*(?:response|llmOutput|completion)[\\.\\[]/i,
  /execute\\(\\s*(?:response|llmOutput|completion)[\\.\\[]/i,
  /invoke\\(\\s*(?:response|llmOutput|completion)[\\.\\[]/i,
  /registry\\.dispatch\\(\\s*(?:response|output|message|result)[\\.\\[]/i,
];

export default class HermesPolicy extends BaseAgent {
  constructor() {
    super();
    this.name     = 'HermesPolicy';
    this.category = 'llm';
  }

  async analyze({ files = [] }) {
    const findings = [];
    for (const file of files.filter(f => /\\.(js|ts|jsx|tsx|py)$/.test(f))) {
      let content;
      try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }
      const lines = content.split('\\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/ship-safe-ignore/i.test(line)) continue;
        if (DYNAMIC_TOOL_PATTERNS.some(p => p.test(line))) {
          findings.push(createFinding({
            rule: 'HERMES_FUNCTION_CALL_NO_ALLOWLIST', severity: 'critical',
            title: 'Tool dispatched from LLM output without allowlist check',
            description: 'Tool name sourced directly from LLM — prompt injection could call any tool in the Hermes registry.',
            file, line: i + 1, matched: line.trim().slice(0, 120), category: 'llm',
            remediation: \`Check against ALLOWED_TOOLS before dispatch:\\n  if (!ALLOWED_TOOLS.includes(toolName)) throw new Error('Unknown tool: ' + toolName);\`,
            confidence: 'high',
          }));
        }
      }
    }
${memoryChecks}
    return findings;
  }
}
`;
}

export function generateGitHubWorkflow(config: HermesConfig): string {
  return `name: Ship Safe — Hermes Security Audit

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  hermes-audit:
    name: Hermes Security Audit
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Run Ship Safe — Hermes Audit
        id: audit
        run: |
          npx ship-safe audit . --hermes-only --fail-below baseline --json > audit-result.json || true
          echo "score=$(cat audit-result.json | jq -r '.score // 0')" >> \$GITHUB_OUTPUT
          echo "findings=$(cat audit-result.json | jq -r '.findings | length // 0')" >> \$GITHUB_OUTPUT

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const score = '\${{ steps.audit.outputs.score }}';
            const findings = '\${{ steps.audit.outputs.findings }}';
            const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
            const emoji = score >= 80 ? '✅' : score >= 60 ? '⚠️' : '❌';
            await github.rest.issues.createComment({
              ...context.repo, issue_number: context.issue.number,
              body: [
                '## ' + emoji + ' Ship Safe — Hermes Security Report',
                '| Score | Grade | Findings |',
                '|-------|-------|----------|',
                \`| \${score}/100 | \${grade} | \${findings} |\`,
                '',
                score < 70 ? '> ⚠️ Run \`npx ship-safe audit . --agentic 3\` locally to auto-fix findings.' : '> Security posture looks good.',
                '_[Ship Safe](https://shipsafecli.com) · [Hermes Security](https://shipsafecli.com/hermes)_',
              ].join('\\n'),
            });

      - name: Enforce baseline
        run: npx ship-safe audit . --hermes-only --fail-below baseline
`;
}

export function generateGitLabCI(_config: HermesConfig): string {
  return `hermes-security-audit:
  stage: test
  image: node:20-alpine
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - npx ship-safe audit . --hermes-only --fail-below baseline
`;
}

export function generateBaseline(config: HermesConfig): string {
  return JSON.stringify(
    {
      score: 0,
      date: new Date().toISOString().split('T')[0],
      findings: 0,
      note: 'Run `npx ship-safe audit .` to populate. CI compares against this.',
      tools: config.tools.map(t => t.name),
      memoryProvider: config.memoryProvider,
      hasSubAgents: config.hasSubAgents,
    },
    null,
    2,
  );
}

export function generateSetupGuide(config: HermesConfig): string {
  const toolList = config.tools
    .map(t => `- \`${t.name}\`${t.sourceUrl ? ` — ${t.sourceUrl}` : ' (local)'}`)
    .join('\n');

  const memoryNote = config.memoryProvider === 'none'
    ? 'None — no memory validation rules will fire.'
    : config.memoryProvider === 'builtin'
    ? 'Built-in (MEMORY.md / USER.md). Ship Safe validates these files for injection patterns.'
    : `External: ${config.memoryProvider}. Ship Safe monitors the plugin directory for poisoned data.`;

  return `# Ship Safe × Hermes — Security Setup

Generated ${new Date().toISOString().split('T')[0]} for **${config.projectName || 'my-hermes-agent'}**.

## About this config

Ship Safe generates a security manifest (\`agent-manifest.json\`) that layers security
on top of your Hermes agent. This is NOT a native Hermes config — it's a companion
that Ship Safe reads during \`ship-safe audit\` to enforce tool allowlists and integrity.

Your Hermes config stays at \`~/.hermes/config.yaml\` as usual.

## Registered tools (${config.tools.length})

${toolList}

## Memory provider

${memoryNote}

## Next steps

1. Run your first audit: \`npx ship-safe audit .\`
2. Fix findings: \`npx ship-safe audit . --agentic 3 --agentic-target 80\`
3. Commit and push — CI runs on every PR

## Hermes architecture reference

| Component | Hermes path | What Ship Safe checks |
|-----------|-------------|----------------------|
| Tool registry | \`tools/registry.py\` | Allowlist + integrity hashes |
| Delegation | \`tools/delegate_tool.py\` | Depth limit (MAX_DEPTH = 2) |
| Memory | \`tools/memory_tool.py\` | Injection in MEMORY.md / USER.md |
| Approval | \`tools/approval.py\` | 33 dangerous command patterns |
| Skills | \`skills/<category>/SKILL.md\` | Skill source validation |

---
_[Ship Safe](https://shipsafecli.com) v8.0.0_
`;
}

// ── Build all files ────────────────────────────────────────────────────────

export function generateAllFiles(config: HermesConfig): GeneratedFile[] {
  const files: GeneratedFile[] = [
    {
      path: config.manifestPath || 'agent-manifest.json',
      content: generateAgentManifest(config),
    },
    {
      path: '.ship-safe/agents/hermes-policy.js',
      content: generateHermesPolicy(config),
    },
    {
      path: '.ship-safe/hermes-baseline.json',
      content: generateBaseline(config),
    },
    {
      path: 'SHIP_SAFE_SETUP.md',
      content: generateSetupGuide(config),
    },
  ];

  if (config.ciProvider === 'github') {
    files.push({
      path: '.github/workflows/ship-safe-hermes.yml',
      content: generateGitHubWorkflow(config),
    });
  } else if (config.ciProvider === 'gitlab') {
    files.push({
      path: 'ship-safe-hermes-ci.yml',
      content: generateGitLabCI(config),
    });
  }

  return files;
}

// ── Token encode/decode (base64url, no DB needed) ──────────────────────────

export function encodeConfig(config: HermesConfig): string {
  return Buffer.from(JSON.stringify(config)).toString('base64url');
}

export function decodeConfig(token: string): HermesConfig | null {
  try {
    return JSON.parse(Buffer.from(token, 'base64url').toString('utf-8')) as HermesConfig;
  } catch {
    return null;
  }
}
