/**
 * Ship Safe — SlopSquatAgent
 * ===========================
 *
 * Verifies phantom-import detection, known-hallucination flagging, and
 * false-positive guards (declared deps, installed deps, builtins, relative).
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { SlopSquatAgent } from '../agents/slopsquat-agent.js';

function project(pkgJson, sources) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-slop-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkgJson));
  const files = [];
  for (const [name, content] of Object.entries(sources)) {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content);
    files.push(p);
  }
  return { dir, files };
}
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

async function scan(dir, files) {
  return new SlopSquatAgent().analyze({ rootPath: dir, files, recon: {}, options: {} });
}

describe('SlopSquatAgent', () => {
  it('flags a phantom import (not declared, not installed, not builtin)', async () => {
    const { dir, files } = project({ dependencies: { react: '^18' } }, {
      'a.js': "import react from 'react';\nimport helper from 'totally-not-real-pkg-xyz';\n",
    });
    try {
      const f = await scan(dir, files);
      assert.ok(f.some((x) => x.rule === 'SLOPSQUAT_PHANTOM_IMPORT' && x.matched === 'totally-not-real-pkg-xyz'));
    } finally { cleanup(dir); }
  });

  it('raises a known hallucination to high', async () => {
    const { dir, files } = project({ dependencies: {} }, {
      'b.ts': "import { transform } from 'react-codeshift';\n",
    });
    try {
      const f = await scan(dir, files);
      assert.ok(f.some((x) => x.rule === 'SLOPSQUAT_KNOWN_HALLUCINATION' && x.severity === 'high'));
    } finally { cleanup(dir); }
  });

  it('does not flag a declared dependency', async () => {
    const { dir, files } = project({ dependencies: { lodash: '^4' } }, {
      'c.js': "const _ = require('lodash');\n",
    });
    try {
      const f = await scan(dir, files);
      assert.equal(f.length, 0);
    } finally { cleanup(dir); }
  });

  it('does not flag a dependency present in node_modules', async () => {
    const { dir, files } = project({ dependencies: {} }, { 'd.js': "import x from 'installed-pkg';\n" });
    try {
      fs.mkdirSync(path.join(dir, 'node_modules', 'installed-pkg'), { recursive: true });
      const f = await scan(dir, files);
      assert.equal(f.length, 0);
    } finally { cleanup(dir); }
  });

  it('does not flag Node builtins or relative imports', async () => {
    const { dir, files } = project({ dependencies: {} }, {
      'e.js': "import fs from 'node:fs';\nimport path from 'path';\nimport './local.js';\n",
    });
    try {
      const f = await scan(dir, files);
      assert.equal(f.length, 0);
    } finally { cleanup(dir); }
  });

  it('resolves scoped package names correctly', async () => {
    const { dir, files } = project({ dependencies: { '@scope/real': '^1' } }, {
      'f.js': "import a from '@scope/real';\nimport b from '@scope/fake-hallucinated';\n",
    });
    try {
      const f = await scan(dir, files);
      const names = f.map((x) => x.matched);
      assert.ok(names.includes('@scope/fake-hallucinated'));
      assert.ok(!names.includes('@scope/real'));
    } finally { cleanup(dir); }
  });
});
