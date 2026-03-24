/**
 * Agent Bill of Materials (ABOM) Generator
 * ==========================================
 *
 * Generates an Agent-focused BOM in CycloneDX 1.5 format.
 * Lists all AI agent components: MCP servers, OpenClaw skills,
 * agent config files, LLM providers.
 *
 * This complements the SBOMGenerator (software dependencies)
 * with agent-specific component inventory for compliance and
 * supply chain visibility.
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';

// Agent config files to discover (from AgentConfigScanner)
const AGENT_CONFIG_FILES = [
  '.cursorrules', '.windsurfrules', 'CLAUDE.md', 'AGENTS.md',
  '.github/copilot-instructions.md', '.aider.conf.yml', '.continue/config.json',
];

const MCP_CONFIG_FILES = [
  'mcp.json', '.cursor/mcp.json', '.vscode/mcp.json',
  'claude_desktop_config.json', '.claude/settings.json',
];

const OPENCLAW_FILES = ['openclaw.json', 'openclaw.config.json', 'clawhub.json'];

const LLM_ENV_VARS = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_AI_API_KEY',
  'AZURE_OPENAI_API_KEY', 'OLLAMA_HOST', 'GROQ_API_KEY',
  'MISTRAL_API_KEY', 'COHERE_API_KEY',
];

export class ABOMGenerator {
  /**
   * Generate a CycloneDX 1.5 ABOM.
   * @param {string} rootPath — Project root directory
   * @returns {object} — CycloneDX JSON with agent components
   */
  generate(rootPath) {
    const components = [];
    let componentIndex = 0;

    // ── MCP Servers ──────────────────────────────────────────────────────────
    for (const rel of MCP_CONFIG_FILES) {
      const full = path.join(rootPath, rel);
      if (!fs.existsSync(full)) continue;
      try {
        const data = JSON.parse(fs.readFileSync(full, 'utf-8'));
        const servers = data.mcpServers || data.servers || {};
        for (const [name, config] of Object.entries(servers)) {
          components.push({
            'bom-ref': `agent-${componentIndex++}`,
            type: 'framework',
            name,
            version: config.version || 'unknown',
            description: `MCP server from ${rel}`,
            purl: config.command ? `pkg:mcp/${encodeURIComponent(name)}` : undefined,
            properties: [
              { name: 'agent:type', value: 'mcp-server' },
              { name: 'agent:source', value: rel },
              { name: 'agent:command', value: config.command || 'N/A' },
              { name: 'agent:transport', value: config.transport || 'stdio' },
            ],
          });
        }
      } catch { /* skip */ }
    }

    // ── OpenClaw Skills ──────────────────────────────────────────────────────
    for (const rel of OPENCLAW_FILES) {
      const full = path.join(rootPath, rel);
      if (!fs.existsSync(full)) continue;
      try {
        const data = JSON.parse(fs.readFileSync(full, 'utf-8'));
        const skills = data.skills || [];
        for (const skill of skills) {
          const skillName = typeof skill === 'string' ? skill : skill.name || skill.id || 'unnamed';
          const skillSource = typeof skill === 'object' ? (skill.source || skill.url || 'local') : 'config';
          components.push({
            'bom-ref': `agent-${componentIndex++}`,
            type: 'library',
            name: skillName,
            version: (typeof skill === 'object' ? skill.version : null) || 'unknown',
            description: `OpenClaw skill from ${rel}`,
            purl: `pkg:openclaw/${encodeURIComponent(skillName)}`,
            properties: [
              { name: 'agent:type', value: 'openclaw-skill' },
              { name: 'agent:source', value: skillSource },
              { name: 'agent:verified', value: String(typeof skill === 'object' ? !!skill.verified : false) },
            ],
          });
        }

        // Record OpenClaw config itself
        components.push({
          'bom-ref': `agent-${componentIndex++}`,
          type: 'data',
          name: `openclaw-config:${rel}`,
          version: data.version || '1.0.0',
          description: `OpenClaw gateway configuration`,
          properties: [
            { name: 'agent:type', value: 'openclaw-config' },
            { name: 'agent:host', value: data.host || 'localhost' },
            { name: 'agent:auth', value: data.auth ? 'enabled' : 'disabled' },
          ],
        });
      } catch { /* skip */ }
    }

    // ── Agent Config Files ───────────────────────────────────────────────────
    for (const rel of AGENT_CONFIG_FILES) {
      const full = path.join(rootPath, rel);
      if (!fs.existsSync(full)) continue;
      try {
        const stat = fs.statSync(full);
        components.push({
          'bom-ref': `agent-${componentIndex++}`,
          type: 'data',
          name: `agent-config:${rel}`,
          version: stat.mtime.toISOString().split('T')[0],
          description: `AI agent instruction file`,
          properties: [
            { name: 'agent:type', value: 'agent-rules' },
            { name: 'agent:file', value: rel },
            { name: 'agent:size', value: String(stat.size) },
          ],
        });
      } catch { /* skip */ }
    }

    // ── Glob-based config files ──────────────────────────────────────────────
    try {
      const globs = ['.cursor/rules/*.mdc', '.openclaw/**/*.json', '.claude/commands/*.md'];
      const found = fg.sync(globs, { cwd: rootPath, absolute: true, dot: true });
      for (const full of found) {
        const rel = path.relative(rootPath, full).replace(/\\/g, '/');
        try {
          const stat = fs.statSync(full);
          components.push({
            'bom-ref': `agent-${componentIndex++}`,
            type: 'data',
            name: `agent-config:${rel}`,
            version: stat.mtime.toISOString().split('T')[0],
            description: `AI agent configuration file`,
            properties: [
              { name: 'agent:type', value: 'agent-config' },
              { name: 'agent:file', value: rel },
            ],
          });
        } catch { /* skip */ }
      }
    } catch { /* skip */ }

    // ── LLM Providers ────────────────────────────────────────────────────────
    for (const envVar of LLM_ENV_VARS) {
      if (process.env[envVar]) {
        const provider = envVar.replace(/_API_KEY$/, '').replace(/_HOST$/, '').toLowerCase();
        components.push({
          'bom-ref': `agent-${componentIndex++}`,
          type: 'service',
          name: `llm-provider:${provider}`,
          version: 'detected',
          description: `LLM provider detected via ${envVar} environment variable`,
          properties: [
            { name: 'agent:type', value: 'llm-provider' },
            { name: 'agent:env-var', value: envVar },
            { name: 'agent:key-present', value: 'true' },
          ],
        });
      }
    }

    // ── Build CycloneDX BOM ──────────────────────────────────────────────────
    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${this._uuid()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: 'ship-safe', name: 'ship-safe-abom', version: '6.1.0' }],
        component: this._getProjectMeta(rootPath),
        lifecycles: [{ phase: 'build' }],
      },
      components,
      compositions: [{
        aggregate: 'incomplete',
        assemblies: components.map(c => c['bom-ref']),
      }],
    };
  }

  /**
   * Generate ABOM and write to file.
   */
  generateToFile(rootPath, outputPath) {
    const bom = this.generate(rootPath);
    fs.writeFileSync(outputPath, JSON.stringify(bom, null, 2));
    return outputPath;
  }

  _getProjectMeta(rootPath) {
    try {
      const pkgPath = path.join(rootPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        return { type: 'application', name: pkg.name || path.basename(rootPath), version: pkg.version || '0.0.0' };
      }
    } catch { /* skip */ }
    return { type: 'application', name: path.basename(rootPath), version: '0.0.0' };
  }

  _uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }
}

export default ABOMGenerator;
