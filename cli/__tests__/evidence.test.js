/**
 * Evidence schema — claims, citation validation, and verdict precedence.
 *
 * The invariants under test are the ones the rest of the investigation layer
 * will rely on: a cheap pass never overturns an expensive one, a claim whose
 * citations do not resolve decides nothing, and a genuine disagreement between
 * equals resolves to 'unknown' rather than to whichever verdict is scarier.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  CLAIM_SOURCES,
  VERDICTS,
  attachEvidence,
  createClaim,
  decidingClaim,
  emptyEvidence,
  hasEvidence,
  resolveVerdict,
  summarizeEvidence,
  validateCitations,
} from '../utils/evidence.js';
import { createFinding, normalizeFindingMetadata } from '../agents/base-agent.js';

let ROOT;
const SOURCE = [
  'export async function proxy(req, res) {',
  '  const target = req.query.url;',
  '  const body = await fetch(target);',
  '  res.send(await body.text());',
  '}',
  '',
].join('\n');

before(() => {
  ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-evidence-'));
  fs.mkdirSync(path.join(ROOT, 'src'));
  fs.writeFileSync(path.join(ROOT, 'src/proxy.js'), SOURCE);
});

after(() => {
  fs.rmSync(ROOT, { recursive: true, force: true });
});

const claim = (overrides = {}) => createClaim({
  source: 'heuristic',
  verdict: 'likely',
  rationale: 'user input reaches the sink',
  ...overrides,
});

describe('claim construction', () => {
  it('rejects an unknown source instead of ranking it zero', () => {
    assert.throws(() => claim({ source: 'vibes' }), /Unknown evidence source/);
  });

  it('rejects a verdict outside the vocabulary', () => {
    assert.throws(() => claim({ verdict: 'probably-fine' }), /Unknown verdict/);
  });

  it('drops citations with no file and defaults endLine to line', () => {
    const c = claim({ citations: [{ file: 'src/proxy.js', line: 3 }, { line: 9 }, null] });
    assert.equal(c.citations.length, 1);
    assert.deepEqual(c.citations[0], { file: 'src/proxy.js', line: 3, endLine: 3 });
  });

  it('ranks reproduction above dataflow above analysis above heuristic', () => {
    assert.ok(CLAIM_SOURCES.reproduction > CLAIM_SOURCES.dataflow);
    assert.ok(CLAIM_SOURCES.dataflow > CLAIM_SOURCES.analysis);
    assert.ok(CLAIM_SOURCES.analysis > CLAIM_SOURCES.heuristic);
  });
});

describe('citation validation', () => {
  it('accepts a citation that resolves to a real line', () => {
    const c = claim({ citations: [{ file: 'src/proxy.js', line: 3 }] });
    const result = validateCitations(c, { rootPath: ROOT });
    assert.equal(result.status, 'valid');
    assert.equal(c.citationStatus, 'valid');
  });

  it('rejects a citation to a file that does not exist', () => {
    const c = claim({ citations: [{ file: 'src/imagined.js', line: 3 }] });
    const { status, invalid } = validateCitations(c, { rootPath: ROOT });
    assert.equal(status, 'invalid');
    assert.match(invalid[0].reason, /file not found/);
  });

  it('rejects a citation past the end of a real file', () => {
    const c = claim({ citations: [{ file: 'src/proxy.js', line: 400 }] });
    const { status, invalid } = validateCitations(c, { rootPath: ROOT });
    assert.equal(status, 'invalid');
    assert.match(invalid[0].reason, /outside file/);
  });

  it('rejects an excerpt that is not present at the cited line', () => {
    const c = claim({ citations: [{ file: 'src/proxy.js', line: 2, excerpt: 'validateHost(target)' }] });
    assert.equal(validateCitations(c, { rootPath: ROOT }).status, 'invalid');
  });

  it('accepts an excerpt regardless of surrounding whitespace', () => {
    const c = claim({ citations: [{ file: 'src/proxy.js', line: 3, excerpt: 'await   fetch(target)' }] });
    assert.equal(validateCitations(c, { rootPath: ROOT }).status, 'valid');
  });

  it('leaves an uncited claim unchecked rather than invalid', () => {
    const c = claim({ citations: [] });
    assert.equal(validateCitations(c, { rootPath: ROOT }).status, 'unchecked');
  });

  it('resolves absolute citation paths without a root', () => {
    const c = claim({ citations: [{ file: path.join(ROOT, 'src/proxy.js'), line: 1 }] });
    assert.equal(validateCitations(c, { rootPath: '/nonexistent' }).status, 'valid');
  });
});

describe('verdict precedence', () => {
  it('is unknown with no claims', () => {
    assert.deepEqual(resolveVerdict(emptyEvidence()), { verdict: 'unknown', conflict: false, decidedBy: null });
  });

  it('lets a higher-ranked source overturn a lower one', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({ source: 'heuristic', verdict: 'likely' }));
    attachEvidence(finding, claim({ source: 'reproduction', verdict: 'refuted' }));

    assert.equal(finding.evidence.verdict, 'refuted');
    assert.deepEqual(finding.evidence.decidedBy, ['reproduction']);
    assert.equal(finding.evidence.conflict, false);
  });

  it('does not let a lower-ranked source overturn a higher one', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({ source: 'reproduction', verdict: 'confirmed' }));
    attachEvidence(finding, claim({ source: 'analysis', verdict: 'refuted' }));

    assert.equal(finding.evidence.verdict, 'confirmed');
  });

  it('reports a conflict as unknown when equals disagree', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({ source: 'dataflow', verdict: 'confirmed' }));
    attachEvidence(finding, claim({ source: 'chain', verdict: 'refuted' }));

    assert.equal(finding.evidence.verdict, 'unknown');
    assert.equal(finding.evidence.conflict, true);
  });

  it('treats an equal-ranked unknown as silence, not disagreement', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({ source: 'dataflow', verdict: 'confirmed' }));
    attachEvidence(finding, claim({ source: 'chain', verdict: 'unknown' }));

    assert.equal(finding.evidence.verdict, 'confirmed');
    assert.equal(finding.evidence.conflict, false);
  });

  it('ignores a claim whose citations did not resolve', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({ source: 'heuristic', verdict: 'likely' }));

    const fabricated = claim({ source: 'reproduction', verdict: 'refuted', citations: [{ file: 'src/imagined.js', line: 1 }] });
    validateCitations(fabricated, { rootPath: ROOT });
    attachEvidence(finding, fabricated);

    assert.equal(finding.evidence.verdict, 'likely', 'an uncheckable claim must not decide the verdict');
    assert.equal(finding.evidence.claims.length, 2, 'but it is still recorded');
  });

  it('takes the most recent claim when equals agree', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({ source: 'dataflow', verdict: 'confirmed', rationale: 'first' }));
    attachEvidence(finding, claim({ source: 'dataflow', verdict: 'confirmed', rationale: 'second' }));

    assert.equal(decidingClaim(finding).rationale, 'second');
  });
});

describe('finding integration', () => {
  it('gives every finding an evidence container from birth', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    assert.deepEqual(finding.evidence, { verdict: 'unknown', claims: [], conflict: false });
    assert.equal(hasEvidence(finding), false);
  });

  it('backfills the container for findings built outside the factory', () => {
    const legacy = normalizeFindingMetadata({ file: 'src/proxy.js', rule: 'SSRF', confidence: 'medium' });
    assert.equal(legacy.evidence.verdict, 'unknown');
  });

  it('moves evidenceLevel only for verdicts that settle the question', () => {
    const confirmed = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF', confidence: 'medium' });
    attachEvidence(confirmed, claim({ source: 'reproduction', verdict: 'confirmed' }));
    assert.equal(confirmed.evidenceLevel, 'strong');

    const refuted = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    attachEvidence(refuted, claim({ source: 'dataflow', verdict: 'refuted' }));
    assert.equal(refuted.evidenceLevel, 'advisory');

    const undecided = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF', confidence: 'medium' });
    attachEvidence(undecided, claim({ source: 'analysis', verdict: 'likely' }));
    assert.equal(undecided.evidenceLevel, 'heuristic', 'an unsettled verdict leaves the detector assessment standing');
  });

  it('never emits a verdict outside the vocabulary', () => {
    const finding = createFinding({ file: 'src/proxy.js', rule: 'SSRF', title: 'SSRF' });
    for (const verdict of VERDICTS) {
      attachEvidence(finding, claim({ source: 'analysis', verdict }));
      assert.ok(VERDICTS.includes(finding.evidence.verdict));
    }
  });
});

describe('report summary', () => {
  it('relativizes absolute citation paths for machine output', () => {
    const finding = createFinding({ file: path.join(ROOT, 'src/proxy.js'), rule: 'SSRF', title: 'SSRF' });
    attachEvidence(finding, claim({
      source: 'dataflow',
      verdict: 'confirmed',
      citations: [{ file: path.join(ROOT, 'src/proxy.js'), line: 2 }],
      attackPath: ['req.query.url', 'fetch(target)'],
    }));

    const summary = summarizeEvidence(finding, ROOT);
    assert.equal(summary.verdict, 'confirmed');
    assert.equal(summary.claims[0].citations[0].file, 'src/proxy.js');
    assert.deepEqual(summary.claims[0].attackPath, ['req.query.url', 'fetch(target)']);
    assert.equal(JSON.stringify(summary).includes(ROOT), false, 'no workstation paths in machine output');
  });
});
