/**
 * AIBOMGenerator — AI Bill of Materials + EU AI Act readiness
 * ===========================================================
 *
 * An AIBOM inventories the AI supply chain of a project: model weights, LLM/ML
 * SDKs and providers, MCP servers, and agent instruction files — the artifacts
 * an SBOM misses. It also produces a heuristic EU AI Act high-risk readiness
 * report, timed to the Aug 2 2026 obligations deadline (Articles 9–17 / 26),
 * where ~78% of organizations are unprepared.
 *
 * The readiness report is an engineering indicator (presence of governance
 * artifacts + AI usage signals), not legal advice.
 *
 * Output: CycloneDX 1.5-style JSON. Class: Compliance / Supply Chain.
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import { SKIP_DIRS } from '../utils/patterns.js';

const MODEL_EXTS = new Set(['.pkl', '.pt', '.pth', '.ckpt', '.bin', '.safetensors', '.gguf', '.onnx', '.h5', '.joblib']);
const UNSAFE_MODEL_EXTS = new Set(['.pkl', '.pt', '.pth', '.ckpt', '.bin', '.joblib']);
const MCP_CONFIG_FILES = ['mcp.json', '.mcp.json', 'mcp-config.json', 'claude_desktop_config.json', '.cursor/mcp.json', '.vscode/mcp.json'];
const AGENT_CONFIG_FILES = ['CLAUDE.md', 'AGENTS.md', '.cursorrules', '.windsurfrules', '.github/copilot-instructions.md'];

// Known LLM/ML SDKs and providers (npm + pypi).
const AI_SDKS = {
  openai: 'OpenAI', '@anthropic-ai/sdk': 'Anthropic', anthropic: 'Anthropic',
  '@google/generative-ai': 'Google Gemini', 'google-generativeai': 'Google Gemini',
  'cohere-ai': 'Cohere', cohere: 'Cohere', mistralai: 'Mistral', '@mistralai/mistralai': 'Mistral',
  langchain: 'LangChain', '@langchain/core': 'LangChain', llamaindex: 'LlamaIndex', 'llama-index': 'LlamaIndex',
  ollama: 'Ollama', replicate: 'Replicate', 'groq-sdk': 'Groq', groq: 'Groq',
  '@huggingface/inference': 'Hugging Face', transformers: 'Hugging Face Transformers',
  torch: 'PyTorch', tensorflow: 'TensorFlow', 'onnxruntime': 'ONNX Runtime', 'vllm': 'vLLM',
};

export class AIBOMGenerator {
  generate(rootPath) {
    const components = [];
    let idx = 0;
    const ref = () => `ai-${idx++}`;

    // ── Model weights ────────────────────────────────────────────────────────
    const modelFiles = fg.sync(['**/*.{pkl,pt,pth,ckpt,bin,safetensors,gguf,onnx,h5,joblib}'], {
      cwd: rootPath, absolute: true, onlyFiles: true,
      ignore: Array.from(SKIP_DIRS).map((d) => `**/${d}/**`),
    });
    for (const file of modelFiles) {
      const ext = path.extname(file).toLowerCase();
      if (!MODEL_EXTS.has(ext)) continue;
      const unsafe = UNSAFE_MODEL_EXTS.has(ext);
      components.push({
        'bom-ref': ref(), type: 'machine-learning-model',
        name: path.basename(file),
        version: 'unknown',
        description: `ML model weights (${ext})`,
        properties: [
          { name: 'ai:type', value: 'model' },
          { name: 'ai:format', value: ext.slice(1) },
          { name: 'ai:serialization', value: unsafe ? 'pickle-based (executes on load)' : 'safe' },
          { name: 'ai:path', value: path.relative(rootPath, file) },
        ],
      });
    }

    // ── AI SDKs / providers ──────────────────────────────────────────────────
    for (const [dep, provider] of Object.entries(this._detectDeps(rootPath))) {
      components.push({
        'bom-ref': ref(), type: 'library',
        name: dep, version: provider.version || 'unknown',
        description: `AI SDK / provider: ${provider.label}`,
        purl: `pkg:${provider.ecosystem}/${encodeURIComponent(dep)}`,
        properties: [
          { name: 'ai:type', value: 'sdk' },
          { name: 'ai:provider', value: provider.label },
        ],
      });
    }

    // ── MCP servers ──────────────────────────────────────────────────────────
    for (const rel of MCP_CONFIG_FILES) {
      const full = path.join(rootPath, rel);
      if (!fs.existsSync(full)) continue;
      try {
        const data = JSON.parse(fs.readFileSync(full, 'utf-8'));
        const servers = data.mcpServers || data.servers || {};
        for (const [name, cfg] of Object.entries(servers)) {
          components.push({
            'bom-ref': ref(), type: 'application',
            name, version: cfg.version || 'unknown',
            description: `MCP server from ${rel}`,
            properties: [
              { name: 'ai:type', value: 'mcp-server' },
              { name: 'ai:source', value: rel },
              { name: 'ai:transport', value: cfg.command ? 'stdio' : (cfg.url ? 'remote' : 'unknown') },
            ],
          });
        }
      } catch { /* skip */ }
    }

    // ── Agent instruction files ──────────────────────────────────────────────
    for (const rel of AGENT_CONFIG_FILES) {
      const full = path.join(rootPath, rel);
      if (!fs.existsSync(full)) continue;
      components.push({
        'bom-ref': ref(), type: 'data',
        name: rel, version: this._mtime(full),
        description: 'AI agent instruction / rules file',
        properties: [{ name: 'ai:type', value: 'agent-config' }],
      });
    }

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: { type: 'application', name: path.basename(path.resolve(rootPath)) },
        tools: [{ name: 'ship-safe', description: 'AIBOM generator' }],
      },
      components,
    };
  }

  generateToFile(rootPath, outputPath) {
    const bom = this.generate(rootPath);
    fs.writeFileSync(outputPath, JSON.stringify(bom, null, 2));
    return bom;
  }

  /**
   * Heuristic EU AI Act high-risk readiness. Engineering indicator, not legal
   * advice. Maps loosely to Articles 9–17 provider obligations.
   */
  generateAIActReadiness(rootPath) {
    const bom = this.generate(rootPath);
    const aiComponents = bom.components.length;
    const has = (globs) => fg.sync(globs, { cwd: rootPath, ignore: Array.from(SKIP_DIRS).map((d) => `**/${d}/**`), caseSensitiveMatch: false }).length > 0;
    const grepAny = (globs, re) => {
      for (const f of fg.sync(globs, { cwd: rootPath, absolute: true, ignore: Array.from(SKIP_DIRS).map((d) => `**/${d}/**`) }).slice(0, 200)) {
        try { if (re.test(fs.readFileSync(f, 'utf-8'))) return true; } catch { /* */ }
      }
      return false;
    };

    const checks = [
      { id: 'art9-risk-mgmt', name: 'Risk management documentation (Art. 9)', pass: has(['**/{RISK,risk,risk-management}*.md', '**/docs/**/risk*.md']) },
      { id: 'art10-data-gov', name: 'Data governance / dataset documentation (Art. 10)', pass: has(['**/{DATA,DATASET,data-governance,MODEL_CARD,model-card,model_card}*.{md,json}', '**/model-card*']) },
      { id: 'art11-tech-doc', name: 'Technical documentation (Art. 11)', pass: has(['**/README*', '**/docs/**/*.md']) },
      { id: 'art12-logging', name: 'Record-keeping / logging (Art. 12)', pass: grepAny(['**/*.{js,ts,py}'], /audit[_-]?log|winston|pino|logging\.getLogger|structlog|opentelemetry/i) },
      { id: 'art13-transparency', name: 'Transparency / AI disclosure to users (Art. 13)', pass: has(['**/{AI_DISCLOSURE,ai-disclosure,TRANSPARENCY,transparency}*']) || grepAny(['**/*.{md,tsx,jsx,html}'], /AI[- ]generated|powered by (?:AI|GPT|an? LLM)|this (?:assistant|response) (?:is|was) generated/i) },
      { id: 'art14-human-oversight', name: 'Human oversight / approval gate (Art. 14)', pass: grepAny(['**/*.{js,ts,py,json,md}'], /require[_-]?approval|human[- ]?in[- ]?the[- ]?loop|human[- ]?review|dry[- ]?run|confirm(?:ation)?\s+before/i) },
      { id: 'art15-accuracy', name: 'Accuracy / robustness testing (Art. 15)', pass: has(['**/*.{test,spec}.{js,ts,py}', '**/tests/**', '**/__tests__/**', '**/eval*/**', '**/benchmark*/**']) },
      { id: 'art15-cybersecurity', name: 'AI-specific security scanning (Art. 15)', pass: has(['**/.ship-safe*', '**/ship-safe*']) || grepAny(['**/.github/workflows/*.{yml,yaml}'], /ship-safe|semgrep|codeql|trivy/i) },
    ];

    const passed = checks.filter((c) => c.pass).length;
    const score = Math.round((passed / checks.length) * 100);
    const level = score >= 80 ? 'strong' : score >= 50 ? 'partial' : 'weak';

    return {
      timestamp: new Date().toISOString(),
      project: bom.metadata.component.name,
      aiComponents,
      isLikelyAISystem: aiComponents > 0,
      score,
      level,
      passed,
      total: checks.length,
      checks,
      gaps: checks.filter((c) => !c.pass).map((c) => c.name),
      disclaimer: 'Heuristic readiness indicator based on repository signals — not legal advice. EU AI Act high-risk obligations (Art. 9–17, 26) bind Aug 2 2026.',
    };
  }

  // ── helpers ──────────────────────────────────────────────────────────────────

  _detectDeps(rootPath) {
    const found = {};
    const pkgPath = path.join(rootPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(deps)) {
          if (AI_SDKS[name]) found[name] = { label: AI_SDKS[name], version: String(version).replace(/^[^\d]*/, '') || 'unknown', ecosystem: 'npm' };
        }
      } catch { /* */ }
    }
    for (const reqName of ['requirements.txt', 'pyproject.toml', 'Pipfile']) {
      const reqPath = path.join(rootPath, reqName);
      if (!fs.existsSync(reqPath)) continue;
      let text;
      try { text = fs.readFileSync(reqPath, 'utf-8'); } catch { continue; }
      for (const name of Object.keys(AI_SDKS)) {
        const re = new RegExp(`(^|[\\s"'\\[])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'im');
        if (re.test(text)) found[name] = { label: AI_SDKS[name], version: 'unknown', ecosystem: 'pypi' };
      }
    }
    return found;
  }

  _mtime(file) {
    try { return fs.statSync(file).mtime.toISOString().split('T')[0]; } catch { return 'unknown'; }
  }
}

export default AIBOMGenerator;
