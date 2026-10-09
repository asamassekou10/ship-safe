import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const cli = fileURLToPath(new URL('../bin/ship-safe.js', import.meta.url));

for (const [command, options] of [
  ['red-team', ['--agents', 'A2ASecurityAgent', '--no-ai']],
  ['audit', ['--no-ai', '--no-cache']],
  ['ci', ['--threshold', '0']],
]) {
  test(`${command} JSON preserves A2A signature states without trusting signatures`, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-a2a-output-'));
    try {
      for (const signed of [false, true]) {
        const target = path.join(dir, signed ? 'signed' : 'unsigned', '.well-known');
        fs.mkdirSync(target, { recursive: true });
        fs.writeFileSync(path.join(target, 'agent-card.json'), JSON.stringify({
          name: 'Example', description: 'Summarizes text.', skills: [],
          url: 'http://agent.example.com/a2a',
          securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } },
          security: [{ bearer: [] }],
          ...(signed ? { signatures: [{ protected: 'broken', signature: 'broken' }] } : {}),
        }));
      }
      const result = spawnSync(process.execPath, [cli, command, dir, '--json', '--no-deps', ...options], {
        encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
        env: { ...process.env, HOME: dir, USERPROFILE: dir, NO_COLOR: '1' },
        timeout: 30_000,
      });
      assert.equal(result.error, undefined, result.error?.message);
      assert.equal(result.status, 0, result.stderr);
      const report = JSON.parse(result.stdout);
      const findings = report.findings.filter(f => f.rule === 'A2A_CARD_HTTP_ENDPOINT');
      assert.equal(findings.length, 2);
      for (const finding of findings) {
        const expected = finding.file.startsWith('unsigned/') ? 'absent' : 'present but unverified';
        assert.equal(finding.signatureState, expected);
        assert.ok(!path.isAbsolute(finding.file));
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
