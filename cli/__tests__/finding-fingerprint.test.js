import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { findingFingerprint, fingerprintMarker, extractFingerprint } from '../utils/finding-fingerprint.js';

const ROOT = '/tmp/project';

describe('finding fingerprints', () => {
  it('stays stable when line numbers change', () => {
    const base = { file: '/tmp/project/src/app.js', line: 4, rule: 'SHELL_INJECTION', title: 'Shell injection', matched: 'exec(userInput)' };
    assert.equal(
      findingFingerprint(base, ROOT),
      findingFingerprint({ ...base, line: 88 }, ROOT),
    );
  });

  it('changes when the rule, file, or matched code changes', () => {
    const base = { file: '/tmp/project/src/app.js', rule: 'RULE_A', title: 'Issue', matched: 'value' };
    const fingerprint = findingFingerprint(base, ROOT);
    assert.notEqual(fingerprint, findingFingerprint({ ...base, rule: 'RULE_B' }, ROOT));
    assert.notEqual(fingerprint, findingFingerprint({ ...base, file: '/tmp/project/src/other.js' }, ROOT));
    assert.notEqual(fingerprint, findingFingerprint({ ...base, matched: 'other' }, ROOT));
  });

  it('round-trips the hidden GitHub comment marker', () => {
    const fingerprint = 'v1-0123456789abcdef';
    const body = `${fingerprintMarker(fingerprint)}\n**Finding**`;
    assert.equal(extractFingerprint(body), fingerprint);
    assert.equal(extractFingerprint('ordinary comment'), null);
  });
});
