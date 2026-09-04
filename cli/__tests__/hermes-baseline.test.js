import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const baselinePath = path.join(root, 'cli/data/hermes-baseline.json');
const fixturePath = path.join(root, 'cli/__tests__/fixtures/hermes-v0.21.0-baseline.json');
const matrixPath = path.join(root, 'docs/hermes-coverage-matrix.md');
const agentPath = path.join(root, 'cli/agents/hermes-security-agent.js');

const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const matrix = fs.readFileSync(matrixPath, 'utf8');
const agent = fs.readFileSync(agentPath, 'utf8');

test('Hermes baseline pins an immutable upstream release', () => {
  assert.equal(baseline.project, 'NousResearch/hermes-agent');
  assert.equal(baseline.release, 'v0.21.0');
  assert.equal(baseline.tag, 'v2026.8.31');
  assert.match(baseline.commit, /^[a-f0-9]{40}$/);
  assert.match(baseline.releasedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.doesNotMatch(baseline.commit, /^(?:main|master|latest)$/);
});

test('coverage matrix accounts for every 10.0 Hermes surface', () => {
  const expected = [
    'plugin-manifests',
    'network-adapters',
    'terminal-backends',
    'acp',
    'tui-gateway',
    'cron',
    'credential-scoping',
  ];
  assert.deepEqual(baseline.surfaces.map((surface) => surface.id), expected);

  for (const surface of baseline.surfaces) {
    assert.match(surface.status, /^(?:covered|partial|uncovered)$/);
    assert.ok(surface.upstreamPaths.length > 0, `${surface.id} needs upstream paths`);
    assert.ok(surface.boundary.length > 0, `${surface.id} needs a boundary`);
    assert.ok(surface.limitations.length > 0, `${surface.id} needs limitations`);
  }
});

test('baseline only claims rules that exist and documentation pins the same snapshot', () => {
  for (const rule of baseline.surfaces.flatMap((surface) => surface.rules)) {
    assert.match(agent, new RegExp(`['\\"]${rule}['\\"]`), `${rule} must exist`);
  }

  for (const value of [baseline.release, baseline.tag, baseline.commit]) {
    assert.ok(matrix.includes(value), `matrix must include ${value}`);
  }
  assert.match(matrix, /never automatic tag following/i);
});

test('the upstream fixture and published baseline cannot drift apart', () => {
  for (const field of ['release', 'tag', 'commit']) {
    assert.equal(fixture[field], baseline[field]);
  }

  assert.deepEqual(
    Object.keys(fixture.representativePaths),
    baseline.surfaces.map((surface) => surface.id),
  );
  for (const representativePath of Object.values(fixture.representativePaths)) {
    assert.ok(representativePath.length > 0);
    assert.doesNotMatch(representativePath, /^(?:main|latest)(?:\/|$)/);
  }
});
