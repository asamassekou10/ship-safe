/**
 * Canonical detection
 * ===================
 *
 * The false-positive benchmark measures noise. Nothing measured the other
 * direction, and that asymmetry is how two real gaps sat undetected: CORS
 * wildcard set through `res.setHeader` was invisible because the rule required
 * `:` or `=` before the wildcard, and prototype pollution via computed key
 * assignment was never covered at all.
 *
 * This is the floor. Each case is a vulnerability a security scanner is
 * expected to find, written the way people actually write it. A change that
 * silences one of these has lost detection, whatever the benchmark says about
 * noise.
 *
 * Add a case whenever a false-negative turns up in the wild. Do not delete one
 * to make a change pass.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { buildOrchestrator } from '../agents/index.js';

const orchestrator = buildOrchestrator();

async function detects(filename, source) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-canon-'));
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, filename), source);
  // A second, boring file so recon sees a normal project rather than one file.
  fs.writeFileSync(path.join(dir, 'src', 'index.js'), 'export const x = 1;\n');
  try {
    const res = await orchestrator.runAll(dir, { quiet: true, includeTests: true });
    return (res.findings || []).filter(f => f.file && f.file.endsWith(filename));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
  }
}

const cases = [
  ['command injection, template',  'a.js', 'const {execSync}=require("child_process");\nexecSync(`ls ${req.body.dir}`);\n'],
  ['SQL injection, template',      'b.js', 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\n'],
  ['eval of request input',        'c.js', 'eval(req.body.code);\n'],
  ['SSRF via fetch',               'd.js', 'await fetch(req.query.url);\n'],
  ['XSS via innerHTML',            'e.js', 'el.innerHTML = req.query.name;\n'],
  ['JWT alg none',                 'f.js', 'jwt.verify(t, k, { algorithms: ["none"] });\n'],
  ['weak crypto MD5',              'g.js', 'crypto.createHash("md5").update(pw).digest("hex");\n'],
  ['SQL injection, f-string',      'h.py', 'cursor.execute(f"SELECT * FROM users WHERE name = {name}")\n'],
  ['subprocess shell=True',        'i.py', 'subprocess.run(cmd, shell=True)\n'],
  ['pickle of untrusted data',     'j.py', 'import pickle\ndata = pickle.loads(untrusted)\n'],
  ['yaml.load without SafeLoader', 'k.py', 'import yaml\ncfg = yaml.load(f)\n'],
  ['SSRF via requests',            'l.py', 'import requests\nrequests.get(request.args["u"])\n'],
  ['cloud metadata endpoint',      'm.py', 'import requests\nrequests.get("http://169.254.169.254/latest/meta-data/")\n'],
  ['torch.load without weights_only', 'n.py', 'import torch\nm = torch.load("model.pt")\n'],
  ['MCP wildcard tool allowlist',  '.mcp.json', '{"mcpServers":{"fs":{"command":"x","allowedTools":["*"]}}}\n'],

  // The two gaps this file was written for.
  ['CORS wildcard via setHeader',  'o.js', 'res.setHeader("Access-Control-Allow-Origin", "*");\n'],
  ['CORS wildcard via header',     'p.js', 'res.header("Access-Control-Allow-Origin", "*");\n'],
  ['prototype pollution, computed key', 'q.js', 'obj[req.body.key] = req.body.value;\n'],
  ['prototype pollution, wrapped source', 'r.js', 'Object.assign(target, JSON.parse(req.body.raw));\n'],
];

describe('canonical vulnerabilities are still detected', () => {
  for (const [label, filename, source] of cases) {
    it(label, async () => {
      const findings = await detects(filename, source);
      assert.ok(
        findings.length > 0,
        `no finding for ${label}. If this is intentional, the case is wrong or detection was lost.`
      );
    });
  }
});

describe('the safe form of each stays quiet', () => {
  it('specific CORS origin with credentials is fine', async () => {
    const findings = await detects('s.js',
      'res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");\n' +
      'res.setHeader("Access-Control-Allow-Credentials", "true");\n');
    assert.equal(findings.filter(f => f.rule.startsWith('CORS')).length, 0);
  });

  it('assignment through a non-request key is fine', async () => {
    const findings = await detects('t.js', 'const safe = allowlist[key];\nobj[safe] = value;\n');
    assert.equal(findings.filter(f => f.rule === 'PROTOTYPE_POLLUTION').length, 0);
  });
});
