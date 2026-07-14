/**
 * Ship Safe — ModelScanAgent
 * ===========================
 *
 * Verifies pickle code-execution detection, unsafe-format flagging, safetensors
 * safety, source-level loaders, and archive-evasion — without unpickling.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { ModelScanAgent } from '../agents/model-scan-agent.js';

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-model-'));
}
function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
}

async function scan(dir, files) {
  const agent = new ModelScanAgent();
  return agent.analyze({ rootPath: dir, files, recon: {}, options: {} });
}

describe('ModelScanAgent — model files', () => {
  it('flags a code-execution payload (os.system) in a pickle', async () => {
    const dir = tmp();
    try {
      // pickle proto-4 header + a GLOBAL reference to os.system
      const buf = Buffer.concat([Buffer.from([0x80, 0x04]), Buffer.from('c__main__\n_x\nq\x00cos\nsystem\nq\x01.')]);
      fs.writeFileSync(path.join(dir, 'model.pkl'), buf);
      const f = await scan(dir, []);
      assert.ok(f.some((x) => x.rule === 'MODEL_PICKLE_CODE_EXECUTION' && x.severity === 'critical'));
    } finally { cleanup(dir); }
  });

  it('flags a pickle-format model even without a dangerous global', async () => {
    const dir = tmp();
    try {
      const buf = Buffer.concat([Buffer.from([0x80, 0x04]), Buffer.from('}q\x00.')]); // empty dict, benign
      fs.writeFileSync(path.join(dir, 'weights.pth'), buf);
      const f = await scan(dir, []);
      assert.ok(f.some((x) => x.rule === 'MODEL_UNSAFE_PICKLE_FORMAT'));
      assert.ok(!f.some((x) => x.rule === 'MODEL_PICKLE_CODE_EXECUTION'));
    } finally { cleanup(dir); }
  });

  it('does not flag a .safetensors file', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'model.safetensors'), Buffer.from('anything at all'));
      const f = await scan(dir, []);
      assert.equal(f.length, 0);
    } finally { cleanup(dir); }
  });

  it('ignores a .bin with no pickle signature (avoids false positives)', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'blob.bin'), Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04]));
      const f = await scan(dir, []);
      assert.equal(f.length, 0);
    } finally { cleanup(dir); }
  });

  it('flags a model wrapped in a 7z archive (scanner evasion)', async () => {
    const dir = tmp();
    try {
      const buf = Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), Buffer.from('payload')]);
      fs.writeFileSync(path.join(dir, 'model.pkl'), buf);
      const f = await scan(dir, []);
      assert.ok(f.some((x) => x.rule === 'MODEL_EVASION_ARCHIVE'));
    } finally { cleanup(dir); }
  });
});

describe('ModelScanAgent — source loaders', () => {
  it('flags torch.load without weights_only=True', async () => {
    const dir = tmp();
    const file = path.join(dir, 'load.py');
    try {
      fs.writeFileSync(file, 'import torch\nm = torch.load("model.pt")\n');
      const f = await scan(dir, [file]);
      assert.ok(f.some((x) => x.rule === 'MODEL_TORCH_LOAD_UNSAFE'));
    } finally { cleanup(dir); }
  });

  it('does not flag torch.load with weights_only=True', async () => {
    const dir = tmp();
    const file = path.join(dir, 'safe.py');
    try {
      fs.writeFileSync(file, 'import torch\nm = torch.load("model.pt", weights_only=True)\n');
      const f = await scan(dir, [file]);
      assert.equal(f.filter((x) => x.rule === 'MODEL_TORCH_LOAD_UNSAFE').length, 0);
    } finally { cleanup(dir); }
  });
});
