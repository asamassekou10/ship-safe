/**
 * CI gate behaviour
 * =================
 *
 * `ci` used to gate on `score < 75`. A composite score is a poor gate — ours
 * could not distinguish 30 findings from 7,000 — and no comparable tool uses
 * one: Snyk gates on `--severity-threshold`, Trivy on `--severity`, SonarQube
 * rates on the worst finding rather than the volume of findings.
 *
 * The gate is now severity-based by default. `--threshold` still works and
 * still wins when set, so pipelines that pinned a score keep their behaviour.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = path.join(ROOT, 'cli', 'bin', 'ship-safe.js');

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-gate-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}
const cleanup = (dir) => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } };

const run = (dir, ...args) => spawnSync(
  process.execPath,
  [BIN, 'ci', dir, '--no-deps', ...args],
  { encoding: 'utf8', timeout: 120_000 },
);

// A critical finding: user input straight into a shell.
const CRITICAL = { 'app.js': 'const { execSync } = require("child_process");\nexecSync(`ls ${req.body.dir}`);\n' };
// Nothing any rule fires on.
const CLEAN = { 'index.js': 'export function add(a, b) {\n  return a + b;\n}\n' };
// One medium finding and nothing worse: the severity default passes it, a
// score gate does not. That difference is what proves precedence.
const MEDIUM_ONLY = {
  'hash.js': 'const crypto = require("crypto");\nconst h = crypto.createHash("md5").update(x).digest("hex");\n',
};

describe('ci gate', () => {
  it('fails by default when a critical finding is present', () => {
    const dir = project(CRITICAL);
    try {
      const res = run(dir);
      assert.equal(res.status, 1, `expected failure\n${res.stdout}${res.stderr}`);
      assert.match(res.stdout, /critical severity or above/);
    } finally { cleanup(dir); }
  });

  it('passes clean code without needing a score threshold', () => {
    const dir = project(CLEAN);
    try {
      const res = run(dir);
      assert.equal(res.status, 0, `expected pass\n${res.stdout}${res.stderr}`);
    } finally { cleanup(dir); }
  });

  it('--fail-on none reports without ever failing', () => {
    const dir = project(CRITICAL);
    try {
      const res = run(dir, '--fail-on', 'none');
      assert.equal(res.status, 0, `expected pass\n${res.stdout}${res.stderr}`);
    } finally { cleanup(dir); }
  });

  it('an explicit --threshold still gates on score', () => {
    const dir = project(MEDIUM_ONLY);
    try {
      // No critical finding, so the severity default would pass this.
      assert.equal(run(dir).status, 0, 'severity default should pass a medium-only project');

      // The same project under a score gate it cannot meet must fail, which
      // is only possible if --threshold took precedence.
      const res = run(dir, '--threshold', '99');
      assert.equal(res.status, 1, `expected score gate to apply\n${res.stdout}${res.stderr}`);
      assert.match(res.stdout, /threshold/);
    } finally { cleanup(dir); }
  });
});
