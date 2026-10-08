import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRoadmap } from '../../scripts/check-roadmap.mjs';

test('roadmap check keeps an unreleased candidate in Now, not Just shipped', () => {
  const changelog = '## [11.0.0] - Unreleased\n';
  const roadmap = '## Just shipped — 10.1.0\n\n## Now — 11.0, Untrusted Inputs\n';

  assert.equal(validateRoadmap('11.0.0', changelog, roadmap), null);
});

test('roadmap check requires a released package version in Just shipped', () => {
  const changelog = '## [11.0.0] - 2026-10-08\n';
  const roadmap = '## Just shipped — 11.0.0\n\n## Now — 11.1\n';

  assert.equal(validateRoadmap('11.0.0', changelog, roadmap), null);
});

test('roadmap check rejects a stale Now milestone for an unreleased candidate', () => {
  const changelog = '## [11.0.0] - Unreleased\n';
  const roadmap = '## Just shipped — 10.1.0\n\n## Now — 10.1\n';

  assert.match(validateRoadmap('11.0.0', changelog, roadmap), /unreleased package/);
});

test('roadmap check rejects package and changelog version drift', () => {
  const changelog = '## [11.0.0] - Unreleased\n';
  const roadmap = '## Just shipped — 10.1.0\n\n## Now — 11.0\n';

  assert.match(validateRoadmap('11.0.1', changelog, roadmap), /CHANGELOG.md starts at/);
});
