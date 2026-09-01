import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compareFindingSets, snapshotFinding } from '../utils/finding-delta.js';

const ROOT = '/tmp/project';
const finding = (overrides = {}) => ({
  file: `${ROOT}/src/app.js`,
  line: 4,
  rule: 'SHELL_INJECTION',
  title: 'Shell injection',
  matched: 'exec(userInput)',
  severity: 'critical',
  codeScope: 'production',
  evidenceLevel: 'confirmed',
  ...overrides,
});

describe('finding delta comparison', () => {
  it('classifies introduced, resolved, and unchanged findings', () => {
    const stable = finding();
    const removed = finding({ rule: 'OLD_RULE', matched: 'old(value)' });
    const added = finding({ rule: 'NEW_RULE', matched: 'new(value)' });
    const delta = compareFindingSets([stable, removed], [{ ...stable, line: 90 }, added], { rootPath: ROOT });

    assert.deepEqual(delta.counts, { introduced: 1, resolved: 1, unchanged: 1, uncertain: 0 });
    assert.equal(delta.introduced[0].finding.rule, 'NEW_RULE');
    assert.equal(delta.resolved[0].finding.rule, 'OLD_RULE');
  });

  it('recognizes a unique finding moved to another file', () => {
    const delta = compareFindingSets(
      [finding()],
      [finding({ file: `${ROOT}/src/commands/run.js`, line: 22 })],
      { rootPath: ROOT },
    );

    assert.deepEqual(delta.counts, { introduced: 0, resolved: 0, unchanged: 1, uncertain: 0 });
    assert.equal(delta.unchanged[0].relocated, true);
  });

  it('treats a severity increase as an introduced regression', () => {
    const delta = compareFindingSets(
      [finding({ severity: 'medium' })],
      [finding({ severity: 'critical', line: 90 })],
      { rootPath: ROOT },
    );

    assert.deepEqual(delta.counts, { introduced: 1, resolved: 0, unchanged: 0, uncertain: 0 });
    assert.equal(delta.introduced[0].reason, 'severity-increased');
    assert.equal(delta.introduced[0].previous.severity, 'medium');
    assert.equal(delta.introduced[0].finding.severity, 'critical');
  });

  it('does not guess when duplicate relocation candidates are ambiguous', () => {
    const base = [
      finding({ file: `${ROOT}/src/a.js` }),
      finding({ file: `${ROOT}/src/b.js` }),
    ];
    const head = [
      finding({ file: `${ROOT}/src/c.js` }),
      finding({ file: `${ROOT}/src/d.js` }),
    ];
    const delta = compareFindingSets(base, head, { rootPath: ROOT });

    assert.deepEqual(delta.counts, { introduced: 0, resolved: 0, unchanged: 0, uncertain: 2 });
    assert.equal(delta.uncertain.length, 1);
  });

  it('stores no raw evidence or absolute path in report snapshots', () => {
    const snapshot = snapshotFinding(finding({ matched: 'ghp_super_secret_value' }), ROOT);
    const serialized = JSON.stringify(snapshot);

    assert.equal(snapshot.file, 'src/app.js');
    assert.doesNotMatch(serialized, /ghp_super_secret_value/);
    assert.doesNotMatch(serialized, /\/tmp\/project/);
  });
});
