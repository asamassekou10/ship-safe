/**
 * Hermes Tool Registry — Ship Safe × Hermes Agent
 * =================================================
 *
 * Declares Ship Safe's five security tools in the Hermes Agent tool-registry
 * format. Import this module in your Hermes agent bootstrap to register
 * Ship Safe as a first-class citizen in the tool registry.
 *
 * USAGE:
 *   import { HERMES_TOOLS, registerWithHermes } from './hermes-tool-registry.js';
 *
 *   // Option A — register all tools at once
 *   await registerWithHermes(agent.toolRegistry);
 *
 *   // Option B — use the raw definitions
 *   for (const tool of HERMES_TOOLS) agent.toolRegistry.register(tool);
 *
 * SECURITY NOTE:
 *   These definitions are pinned, hardcoded, and integrity-verified at load
 *   time. They are never fetched from a remote URL. Do not replace the
 *   INTEGRITY_HASH values without auditing the updated definitions.
 */

import { createHash } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// =============================================================================
// TOOL DEFINITIONS (Hermes function-call schema format)
// =============================================================================

export const HERMES_TOOLS = [
  {
    name: 'ship_safe_audit',
    description:
      'Run a Ship Safe security audit on a local codebase directory. ' +
      'Returns a findings report with severity-graded issues, CWE/OWASP mappings, ' +
      'and remediation guidance. Use before deploying any code or merging PRs.',
    parameters: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project root directory to scan.',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Minimum severity threshold for reported findings.',
          default: 'medium',
        },
        deep: {
          type: 'boolean',
          description: 'Enable deep LLM-powered taint analysis (Haiku→Sonnet→Opus pipeline). Slower but more accurate.',
          default: false,
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
    handler: async ({ path: scanPath, severity = 'medium', deep = false }) => {
      const { auditCommand } = await import('../commands/audit.js');
      return auditCommand(scanPath, { severity, deep, json: true, quiet: true });
    },
  },

  {
    name: 'ship_safe_scan_mcp',
    description:
      'Analyze an MCP server manifest (URL or local file path) for security issues ' +
      'before connecting. Checks for prompt injection in tool descriptions, credential ' +
      'harvesting patterns, Hermes function-call poisoning, schema bypass (additionalProperties: true), ' +
      'and known-malicious server hashes. Returns per-tool findings.',
    parameters: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'URL (https://...) or absolute local file path to the MCP manifest JSON.',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
    handler: async ({ target }) => {
      const { scanMcpCommand } = await import('../commands/scan-mcp.js');
      return scanMcpCommand(target, { json: true });
    },
  },

  {
    name: 'ship_safe_get_findings',
    description:
      'Retrieve findings from the last saved Ship Safe scan report for a project. ' +
      'Optionally filter by minimum severity. Returns an array of findings with rule, ' +
      'title, severity, file, line, and remediation guidance.',
    parameters: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project root (used to locate the saved report).',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Minimum severity to include in results.',
          default: 'medium',
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
    handler: async ({ path: projectPath, severity = 'medium' }) => {
      const { mcpGetFindings } = await import('../commands/mcp.js');
      return mcpGetFindings({ projectPath, severity });
    },
  },

  {
    name: 'ship_safe_suppress_finding',
    description:
      'Suppress a known-safe finding by inserting an inline ship-safe-ignore comment ' +
      'in the source file before the flagged line. Use only when the finding is a ' +
      'confirmed false positive and you can document why it is safe.',
    parameters: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          description: 'Absolute path to the source file containing the finding.',
        },
        line: {
          type: 'number',
          description: 'Line number of the finding (1-based).',
        },
        reason: {
          type: 'string',
          description: 'Human-readable explanation of why this finding is safe to suppress.',
        },
      },
      required: ['file', 'line', 'reason'],
      additionalProperties: false,
    },
    handler: async ({ file, line, reason }) => {
      const { mcpSuppressFinding } = await import('../commands/mcp.js');
      return mcpSuppressFinding({ file, line, reason });
    },
  },

  {
    name: 'ship_safe_memory_list',
    description:
      'List all entries in the Ship Safe security memory for a project. ' +
      'The memory stores learned false positives that are automatically filtered ' +
      'from future scans. Returns each entry with its rule, file pattern, and ' +
      'the snippet that was suppressed.',
    parameters: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project root.',
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
    handler: async ({ path: projectPath }) => {
      const { SecurityMemory } = await import('./security-memory.js');
      const mem = new SecurityMemory(projectPath);
      return mem.list();
    },
  },
];

// =============================================================================
// INTEGRITY VERIFICATION
// Each tool definition is hashed at module load time. If the registry is
// tampered with (e.g. supply-chain attack), the hash check will fail.
// Run `node -e "import('./hermes-tool-registry.js').then(m => m.printHashes())"` to regenerate.
// =============================================================================

const KNOWN_HASHES = {
  ship_safe_audit:             '4d282d29e44fcc01',
  ship_safe_scan_mcp:          'f967aea9626ca840',
  ship_safe_get_findings:      'c09c9447efd574b3',
  ship_safe_suppress_finding:  '3b7339419fe52ac7',
  ship_safe_memory_list:       'c71c996716d1805b',
};

function toolHash(tool) {
  // Hash name + description + parameter schema only (not handler function)
  const canonical = JSON.stringify({ name: tool.name, description: tool.description, parameters: tool.parameters });
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

export function verifyIntegrity() {
  const mismatches = [];
  for (const tool of HERMES_TOOLS) {
    const actual = toolHash(tool);
    const expected = KNOWN_HASHES[tool.name];
    if (expected && actual !== expected) {
      mismatches.push({ tool: tool.name, expected, actual });
    }
  }
  return mismatches;
}

export function printHashes() {
  console.log('// Current tool definition hashes — paste into KNOWN_HASHES:');
  for (const tool of HERMES_TOOLS) {
    console.log(`  ${tool.name}: '${toolHash(tool)}',`);
  }
}

// =============================================================================
// REGISTRATION HELPER
// =============================================================================

/**
 * Register all Ship Safe tools with a Hermes tool registry instance.
 *
 * @param {object} toolRegistry — Hermes ToolRegistry instance with a .register() method
 * @param {object} options
 * @param {boolean} [options.skipVerification=false] — bypass hash verification (not recommended)
 * @param {boolean} [options.quiet=false] — suppress registration log lines
 */
export async function registerWithHermes(toolRegistry, options = {}) {
  if (!options.skipVerification) { // ship-safe-ignore — this is the integrity-check implementation, not a bypass
    const mismatches = verifyIntegrity();
    if (mismatches.length > 0) {
      const msg = mismatches.map(m => `  ${m.tool}: expected ${m.expected}, got ${m.actual}`).join('\n');
      throw new Error(`Ship Safe tool registry integrity check failed:\n${msg}\n\nThis may indicate a supply-chain attack. Run ship-safe --version to verify your installation.`);
    }
  }

  for (const tool of HERMES_TOOLS) {
    if (typeof toolRegistry.register === 'function') {
      toolRegistry.register(tool);
    } else if (typeof toolRegistry.registerTool === 'function') {
      toolRegistry.registerTool(tool);
    } else {
      throw new Error('toolRegistry must have a .register() or .registerTool() method');
    }
    if (!options.quiet) {
      console.log(`  [ship-safe] Registered tool: ${tool.name}`);
    }
  }
}
