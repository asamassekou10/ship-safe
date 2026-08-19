/**
 * Hermes posture
 * ==============
 *
 * Hermes publishes a security policy that names OS-level isolation as the only
 * boundary and states that in-process heuristics are not boundaries. Its §3.1
 * lists what it treats as in scope and §3.2 what it does not, and both halves
 * are worth reporting but not worth reporting identically.
 *
 * These assert the classification holds its shape rather than freezing a list,
 * so adding a rule does not break them but forgetting the field does.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { HermesSecurityAgent, postureFor } from '../agents/hermes-security-agent.js';

function project(content, name = 'agent.js') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-posture-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  return { dir, file };
}
const cleanup = (dir) => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } };

describe('postureFor', () => {
  it('classifies credential exfiltration as a boundary class', () => {
    // §3.1: "leakage of operator credentials ... to a destination outside the
    // trust envelope, via a mechanism that should have prevented it".
    for (const rule of [
      'HERMES_SUB_AGENT_CREDENTIAL_FORWARD',
      'HERMES_XURL_TOKEN_STORE_EXPOSURE',
      'HERMES_MEMORY_EXFIL_PATTERN',
      'HERMES_BROWSER_CLOUD_METADATA_SSRF',
      'HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN',
    ]) {
      assert.equal(postureFor(rule), 'boundary', rule);
    }
  });

  it('classifies in-process heuristics as hygiene', () => {
    // §2.4 and §3.2: a tool allowlist is not a boundary, and prompt injection
    // on its own is not a vulnerability under their policy.
    for (const rule of [
      'HERMES_FUNCTION_CALL_NO_ALLOWLIST',
      'HERMES_GOAL_PROMPT_INJECTION',
      'HERMES_PLAN_USER_INPUT',
      'HERMES_MANIFEST_NO_VERSION_PIN',
    ]) {
      assert.equal(postureFor(rule), 'hygiene', rule);
    }
  });

  it('defaults an unknown rule to hygiene', () => {
    // §3.2 is the larger set. Defaulting the other way would silently inflate
    // every rule nobody has classified yet.
    assert.equal(postureFor('HERMES_SOMETHING_NOT_YET_CLASSIFIED'), 'hygiene');
  });
});

describe('HermesSecurityAgent tags every finding', () => {
  it('sets a posture on all findings it emits', async () => {
    const { dir, file } = project(`
      const hermes = require('hermes-agent');
      const registry = loadRegistry(await fetch(process.env.REGISTRY_URL));
      subAgent.invoke({ credentials: parentCreds, goal: req.body.goal });
    `);
    try {
      const findings = await new HermesSecurityAgent()
        .analyze({ rootPath: dir, files: [file], recon: {}, options: {} });

      assert.ok(findings.length > 0, 'fixture should produce findings');
      for (const f of findings) {
        assert.ok(
          f.posture === 'boundary' || f.posture === 'hygiene',
          `${f.rule} has no posture`
        );
      }
    } finally { cleanup(dir); }
  });
});
