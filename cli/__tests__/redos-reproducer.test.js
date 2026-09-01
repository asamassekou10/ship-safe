import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { RedosReproducer, extractPattern } from '../agents/redos-reproducer.js';
import { createFinding } from '../agents/base-agent.js';

let ROOT;
before(() => { ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-redos-')); });
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));

const probe = async (name, line, { budgetMs = 300 } = {}) => {
  const file = path.join(ROOT, name);
  fs.writeFileSync(file, `${line}\n`);
  const finding = createFinding({
    file, line: 1, rule: 'REDOS_NESTED_QUANTIFIER', title: 'ReDoS',
    category: 'vulnerability', severity: 'high',
  });
  await new RedosReproducer({ budgetMs }).investigate([finding]);
  return finding.evidence.claims.find((c) => c.source === 'reproduction') || null;
};

describe('running the pattern', () => {
  it('confirms a pattern that actually backtracks', async () => {
    const claim = await probe('bad.js', 'export const re = /^(a+)+$/;');
    assert.equal(claim.verdict, 'confirmed');
    assert.ok(claim.reproduction.length > 0, 'the input that did it is recorded');
  });

  it('refutes nested quantifiers that are not ambiguous', async () => {
    // This project's own pattern. `[^_]+` cannot match the separator, so every
    // input has one parse and there is nothing to backtrack over.
    const claim = await probe('ok.js', 'const t = spec.match(/^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/);');
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /grew linearly/);
  });

  it('files a reproduction-rank claim, which outranks a reading of the pattern', async () => {
    const claim = await probe('rank.js', 'export const re = /^(a+)+$/;');
    assert.equal(claim.source, 'reproduction');
  });
});

describe('what it declines to run', () => {
  it('says nothing when the pattern is built at runtime', async () => {
    assert.equal(await probe('dyn.js', 'const re = new RegExp(userSupplied + "+$");'), null);
  });

  it('does not read arithmetic as a pattern', () => {
    assert.equal(extractPattern('const ratio = total / count / 2;'), null);
  });

  it('reads a Python pattern', () => {
    assert.deepEqual(extractPattern('PAT = re.compile(r"(a+)+$")'), { source: '(a+)+$', flags: '' });
  });
});
