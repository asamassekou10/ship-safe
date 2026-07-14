/**
 * Ship Safe — AIBOMGenerator
 * ===========================
 *
 * Verifies AI component inventory (models, SDKs, MCP, agent configs) and the
 * EU AI Act readiness scoring.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { AIBOMGenerator } from '../agents/aibom-generator.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-aibom-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

describe('AIBOMGenerator — inventory', () => {
  it('inventories models, SDKs, MCP servers and agent configs', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'model.safetensors'), 'x');
      fs.writeFileSync(path.join(dir, 'weights.pkl'), 'x');
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'app', dependencies: { openai: '^4', '@anthropic-ai/sdk': '^0.30' } }));
      fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { fs: { command: 'node', args: ['s.js'] } } }));
      fs.writeFileSync(path.join(dir, 'CLAUDE.md'), '# rules');

      const bom = new AIBOMGenerator().generate(dir);
      const typeVals = bom.components.flatMap((c) => c.properties.filter((p) => p.name === 'ai:type').map((p) => p.value));
      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.ok(typeVals.includes('model'));
      assert.ok(typeVals.includes('sdk'));
      assert.ok(typeVals.includes('mcp-server'));
      assert.ok(typeVals.includes('agent-config'));
      // pickle model flagged as unsafe serialization
      const pkl = bom.components.find((c) => c.name === 'weights.pkl');
      assert.ok(pkl.properties.some((p) => p.name === 'ai:serialization' && /pickle/.test(p.value)));
    } finally { cleanup(dir); }
  });

  it('detects Python AI SDKs from requirements.txt', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'requirements.txt'), 'torch==2.3\ntransformers>=4.40\nnumpy\n');
      const bom = new AIBOMGenerator().generate(dir);
      const names = bom.components.map((c) => c.name);
      assert.ok(names.includes('torch'));
      assert.ok(names.includes('transformers'));
    } finally { cleanup(dir); }
  });
});

describe('AIBOMGenerator — EU AI Act readiness', () => {
  it('scores higher for a governed project than a bare one', async () => {
    const bare = tmp();
    const governed = tmp();
    try {
      fs.writeFileSync(path.join(bare, 'package.json'), JSON.stringify({ name: 'bare', dependencies: { openai: '^4' } }));

      fs.writeFileSync(path.join(governed, 'package.json'), JSON.stringify({ name: 'gov', dependencies: { openai: '^4' } }));
      fs.writeFileSync(path.join(governed, 'README.md'), '# Project');
      fs.writeFileSync(path.join(governed, 'RISK.md'), '# Risk management');
      fs.writeFileSync(path.join(governed, 'MODEL_CARD.md'), '# Model card / data governance');
      fs.mkdirSync(path.join(governed, 'tests'));
      fs.writeFileSync(path.join(governed, 'tests', 'a.test.js'), 'test');
      fs.writeFileSync(path.join(governed, 'app.js'), 'const logger = require("winston"); // require_approval human-in-the-loop');

      const gen = new AIBOMGenerator();
      const rBare = gen.generateAIActReadiness(bare);
      const rGov = gen.generateAIActReadiness(governed);

      assert.ok(rGov.score > rBare.score, `governed (${rGov.score}) should exceed bare (${rBare.score})`);
      assert.equal(rGov.total, 8);
      assert.ok(Array.isArray(rGov.gaps));
      assert.ok(rBare.isLikelyAISystem);
    } finally { cleanup(bare); cleanup(governed); }
  });
});
