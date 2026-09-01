/**
 * SecretsVerifier — the only pass that observes rather than reads.
 *
 * Its claims carry the 'reproduction' rank, which outranks everything else, so
 * what it files and what it declines to file both matter. It also handles live
 * credentials, and the tests below pin that none of that material reaches a
 * claim, a rationale, or a citation.
 *
 * No probe here touches the network: the probe table is injected.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { SecretsVerifier } from '../utils/secrets-verifier.js';
import { createFinding } from '../agents/base-agent.js';
import { attachEvidence, createClaim, summarizeEvidence } from '../utils/evidence.js';

const SECRET = 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

const secretFinding = () => createFinding({
  file: '/repo/config.js',
  line: 12,
  rule: 'GITHUB_TOKEN',
  title: 'GitHub token committed',
  category: 'secrets',
  severity: 'critical',
  matched: `GITHUB_TOKEN="${SECRET}"`,
});

const probes = (active, info) => ({
  GITHUB_TOKEN: { label: 'GitHub', test: async () => ({ active, info }) },
});

const claimOf = (finding) => finding.evidence.claims.find((c) => c.source === 'reproduction') || null;

describe('what the probe establishes', () => {
  it('confirms a key that authenticates', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: probes(true) }).verify([finding]);

    const claim = claimOf(finding);
    assert.equal(claim.verdict, 'confirmed');
    assert.equal(finding.evidence.verdict, 'confirmed');
    assert.match(claim.rationale, /working credential/);
  });

  it('refutes a key the provider rejects, without pretending it is not committed', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: probes(false) }).verify([finding]);

    const claim = claimOf(finding);
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /still committed/);
  });

  it('files nothing when the probe cannot tell', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: probes(null, 'needs a key pair') }).verify([finding]);

    assert.equal(claimOf(finding), null, '"we could not tell" would outrank every pass that did real work');
    assert.equal(finding.evidence.verdict, 'unknown');
  });

  it('files nothing when no probe exists for the rule', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: {} }).verify([finding]);
    assert.equal(claimOf(finding), null);
  });

  it('outranks a cheaper pass that concluded otherwise', async () => {
    const finding = secretFinding();
    attachEvidence(finding, createClaim({
      source: 'heuristic', verdict: 'refuted', rationale: 'looks like a placeholder',
    }));
    await new SecretsVerifier({ probes: probes(true) }).verify([finding]);

    assert.equal(finding.evidence.verdict, 'confirmed');
    assert.deepEqual(finding.evidence.decidedBy, ['reproduction']);
  });
});

describe('handling live credentials', () => {
  it('never puts key material in the claim', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: probes(true, `Authenticated as: octocat`) }).verify([finding]);

    const serialized = JSON.stringify(claimOf(finding));
    assert.equal(serialized.includes(SECRET), false, 'a report is not a place a live key may reach');
  });

  it('keeps key material out of machine output', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: probes(true) }).verify([finding]);

    const summary = JSON.stringify(summarizeEvidence(finding, '/repo'));
    assert.equal(summary.includes(SECRET), false);
    assert.equal(summary.includes('ghp_'), false);
  });

  it('cites the location without quoting the line', async () => {
    const finding = secretFinding();
    await new SecretsVerifier({ probes: probes(true) }).verify([finding]);

    const [citation] = claimOf(finding).citations;
    assert.equal(citation.line, 12);
    assert.equal(citation.excerpt, undefined, 'the excerpt would be the secret itself');
  });
});

describe('scope', () => {
  it('leaves findings that are not secrets alone', async () => {
    const finding = createFinding({
      file: '/repo/app.js', line: 3, rule: 'SQL_INJECTION_TEMPLATE_LITERAL',
      title: 'SQL injection', category: 'injection', severity: 'critical',
    });
    await new SecretsVerifier({ probes: probes(true) }).verify([finding]);
    assert.equal(finding.evidence.claims.length, 0);
  });
});
