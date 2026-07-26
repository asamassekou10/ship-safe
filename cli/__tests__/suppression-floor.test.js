/**
 * Suppression floor tests
 * =======================
 *
 * `ship-safe-ignore` was designed for a human deciding a finding is a false
 * positive. The code under scan is now often written by an AI agent, and an
 * agent that can emit a line of source can emit the suppression comment on the
 * line that matters — including through our own `ship_safe_suppress_finding`
 * tool. So critical findings are reported regardless, and every suppression is
 * counted so a silenced scan can't read as a clean one.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { BaseAgent, isSuppressible, SUPPRESSION_FLOOR_SEVERITIES } from '../agents/base-agent.js';

const IGNORE = 'ship-safe' + '-ignore'; // split so our own self-scan stays clean

function tempFile(lines) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-suppress-'));
  const file = path.join(dir, 'sample.js');
  fs.writeFileSync(file, lines.join('\n'));
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

class ProbeAgent extends BaseAgent {
  constructor() {
    super('ProbeAgent', 'test probe', 'test');
  }
}

const PATTERNS = [
  { rule: 'CRIT_SECRET', title: 'Hardcoded key', severity: 'critical', regex: /AKIA[0-9A-Z]{16}/g },
  { rule: 'HIGH_THING', title: 'High thing', severity: 'high', regex: /highRisk\(/g },
  { rule: 'LOW_THING', title: 'Low thing', severity: 'low', regex: /lowRisk\(/g },
];

describe('suppression floor', () => {
  it('critical severity is not suppressible', () => {
    assert.equal(isSuppressible('critical'), false);
    assert.equal(isSuppressible('CRITICAL'), false);
    assert.ok(SUPPRESSION_FLOOR_SEVERITIES.has('critical'));
  });

  it('everything below critical stays suppressible', () => {
    for (const sev of ['high', 'medium', 'low', 'info']) {
      assert.equal(isSuppressible(sev), true, sev);
    }
  });

  it('reports a critical finding even on a suppressed line', () => {
    const { file, cleanup } = tempFile([`const k = "AKIAIOSFODNN7EXAMPLE"; // ${IGNORE}`]);
    try {
      const agent = new ProbeAgent();
      const findings = agent.scanFileWithPatterns(file, PATTERNS);
      assert.deepEqual(findings.map(f => f.rule), ['CRIT_SECRET']);
      assert.equal(agent.floorSuppressionAttempts, 1);
      assert.equal(agent.suppressedCount, 0);
    } finally {
      cleanup();
    }
  });

  it('still suppresses non-critical findings (no behaviour change)', () => {
    const { file, cleanup } = tempFile([
      `lowRisk(); // ${IGNORE}`,
      `highRisk(); // ${IGNORE}`,
    ]);
    try {
      const agent = new ProbeAgent();
      const findings = agent.scanFileWithPatterns(file, PATTERNS);
      assert.deepEqual(findings, []);
      assert.equal(agent.suppressedCount, 2);
      assert.equal(agent.floorSuppressionAttempts, 0);
    } finally {
      cleanup();
    }
  });

  it('an unsuppressed line is unaffected', () => {
    const { file, cleanup } = tempFile(['lowRisk();', 'const k = "AKIAIOSFODNN7EXAMPLE";']);
    try {
      const agent = new ProbeAgent();
      const findings = agent.scanFileWithPatterns(file, PATTERNS);
      assert.deepEqual(findings.map(f => f.rule).sort(), ['CRIT_SECRET', 'LOW_THING']);
      assert.equal(agent.suppressedCount, 0);
      assert.equal(agent.floorSuppressionAttempts, 0);
    } finally {
      cleanup();
    }
  });

  it('counts once per silenced rule, not per pattern checked', () => {
    // Three patterns are evaluated against this line but only one matches, so
    // exactly one suppression is recorded.
    const { file, cleanup } = tempFile([`lowRisk(); // ${IGNORE}`]);
    try {
      const agent = new ProbeAgent();
      agent.scanFileWithPatterns(file, PATTERNS);
      assert.equal(agent.suppressedCount, 1);
      assert.equal(agent.floorSuppressionAttempts, 0);
    } finally {
      cleanup();
    }
  });

  it('isSuppressed without a severity keeps the pre-floor behaviour', () => {
    const agent = new ProbeAgent();
    assert.equal(agent.isSuppressed(`x = 1; // ${IGNORE}`), true);
    assert.equal(agent.isSuppressed('x = 1;'), false);
  });

  it('a clean line is never counted as suppressed', () => {
    const agent = new ProbeAgent();
    assert.equal(agent.isSuppressed('const safe = 1;', 'critical'), false);
    assert.equal(agent.floorSuppressionAttempts, 0);
    assert.equal(agent.suppressedCount, 0);
  });
});

describe('agent tool registry', () => {
  it('exposes no suppression tool to agents', async () => {
    // An agent holding a suppression tool can silence the findings that cover
    // its own output. The removed tool was also non-functional (its handler
    // called an export that never existed).
    const { HERMES_TOOLS } = await import('../utils/hermes-tool-registry.js');
    const names = HERMES_TOOLS.map(t => t.name);
    assert.ok(!names.includes('ship_safe_suppress_finding'), names.join(', '));
  });

  it('every registered tool matches its integrity hash', async () => {
    const mod = await import('../utils/hermes-tool-registry.js');
    const verify = mod.verifyIntegrity || mod.verifyToolIntegrity;
    if (typeof verify === 'function') {
      assert.deepEqual(verify(), [], 'tool registry hashes drifted');
    }
  });
});
