import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  changedFiles,
  matchesPattern,
  newerReleases,
  readBaseline,
  renderReport,
  run,
  securityRelevantPaths,
  surfacesTouched,
  unmatchedSecurityFiles,
} from '../../scripts/hermes-baseline-drift.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const baseline = readBaseline();

// A fake GitHub API, so these tests never touch the network and the drift
// report is asserted against known input rather than whatever upstream did
// this week.
function fakeApi({ releases = [], files = [] } = {}) {
  return async (url) => {
    if (url.includes('/releases')) return releases;
    if (url.includes('/compare/')) return { files: files.map((filename) => ({ filename })) };
    throw new Error(`unexpected URL ${url}`);
  };
}

const PINNED = { tag_name: baseline.tag, name: baseline.release, sha: baseline.commit };

test('the workflow that runs the script exists and is scheduled', () => {
  const workflow = fs.readFileSync(
    path.join(root, '.github/workflows/hermes-baseline-drift.yml'),
    'utf8',
  );
  assert.match(workflow, /schedule:/);
  assert.match(workflow, /scripts\/hermes-baseline-drift\.mjs/);
  // #205: a human merges. The workflow must not be able to merge itself.
  assert.doesNotMatch(workflow, /gh pr merge/);
  assert.doesNotMatch(workflow, /--auto/);
});

test('the workflow never edits the baseline or the matrix', () => {
  // The whole point of the pin is that it moves under review. A workflow that
  // could rewrite either file would defeat that regardless of intent.
  const workflow = fs.readFileSync(
    path.join(root, '.github/workflows/hermes-baseline-drift.yml'),
    'utf8',
  );
  assert.doesNotMatch(workflow, /hermes-baseline\.json/);
  assert.doesNotMatch(workflow, /hermes-coverage-matrix\.md/);
});

test('security-relevant paths come from the baseline, not a second list', () => {
  const patterns = securityRelevantPaths(baseline);
  assert.ok(patterns.length > 0);
  const declared = baseline.surfaces.flatMap((surface) => surface.upstreamPaths);
  assert.equal(patterns.length, declared.length);
  for (const { pattern } of patterns) assert.ok(declared.includes(pattern));
});

test('glob matching does not over-match', () => {
  // `*` must not cross a separator, or a single pattern would silently claim
  // to watch a whole tree it was never calibrated against.
  assert.ok(matchesPattern('cron/scheduler.py', 'cron/**'));
  assert.ok(matchesPattern('acp_adapter/a/b/c.py', 'acp_adapter/**'));
  assert.ok(matchesPattern('plugins/x/plugin.yaml', 'plugins/**/plugin.yaml'));
  assert.ok(matchesPattern('hermes_cli/plugins.py', 'hermes_cli/plugins.py'));

  assert.ok(!matchesPattern('cronjobs/other.py', 'cron/**'));
  assert.ok(!matchesPattern('hermes_cli/other.py', 'hermes_cli/plugins.py'));
  assert.ok(!matchesPattern('tools/environments/x/y.py', 'tools/terminal_tool.py'));
});

test('a changed file maps to the surface that declares it', () => {
  const touched = surfacesTouched(baseline, ['cron/scheduler.py', 'acp_adapter/server.py']);
  assert.ok(touched.has('cron'));
  assert.ok(touched.has('acp'));
  assert.deepEqual(touched.get('cron'), ['cron/scheduler.py']);
});

test('a change outside every declared path touches nothing', () => {
  assert.equal(surfacesTouched(baseline, ['README.md', 'docs/x.md']).size, 0);
});

test('a new area under a watched root is reported as uncovered', () => {
  // #205: the workflow never widens a claim. A file upstream added under a
  // directory we watch, that no pattern names, has to surface as uncovered
  // rather than be passed over.
  const unmatched = unmatchedSecurityFiles(baseline, [
    'tools/brand_new_sink.py',
    'cron/scheduler.py',
    'README.md',
  ]);
  assert.deepEqual(unmatched, ['tools/brand_new_sink.py']);
});

test('no newer releases means no drift', async () => {
  const { unknownPinnedTag, releases } = await newerReleases(baseline, {
    fetchJson: fakeApi({ releases: [PINNED, { tag_name: 'v2026.8.1' }] }),
  });
  assert.equal(unknownPinnedTag, false);
  assert.deepEqual(releases, []);
});

test('releases published after the pin are reported', async () => {
  const newer = { tag_name: 'v2026.9.5', name: 'v0.22.0', sha: 'a'.repeat(40) };
  const { releases } = await newerReleases(baseline, {
    fetchJson: fakeApi({ releases: [newer, PINNED] }),
  });
  assert.equal(releases.length, 1);
  assert.equal(releases[0].tag_name, 'v2026.9.5');
});

test('a pinned tag upstream no longer lists is itself drift', async () => {
  const { unknownPinnedTag } = await newerReleases(baseline, {
    fetchJson: fakeApi({ releases: [{ tag_name: 'v2026.9.5' }] }),
  });
  assert.equal(unknownPinnedTag, true);
});

test('changed files are read from the compare endpoint', async () => {
  const files = await changedFiles(baseline, 'b'.repeat(40), {
    fetchJson: fakeApi({ files: ['cron/scheduler.py'] }),
  });
  assert.deepEqual(files, ['cron/scheduler.py']);
});

test('the report names the surfaces to re-check and refuses to widen', async () => {
  const { baseline: b, result } = await run({
    fetchJson: fakeApi({
      releases: [{ tag_name: 'v2026.9.5', name: 'v0.22.0', sha: 'a'.repeat(40) }, PINNED],
      files: ['cron/scheduler.py', 'tools/brand_new_sink.py'],
    }),
  });
  const report = renderReport(b, result);

  assert.match(report, /Hermes baseline drift/);
  assert.match(report, /v2026\.9\.5/);
  assert.match(report, /\*\*cron\*\*/);
  assert.match(report, /UNCOVERED/);
  assert.match(report, /brand_new_sink\.py/);
  // The two promises #205 makes, stated in the body a reviewer reads.
  assert.match(report, /No status may move to covered/);
  assert.match(report, /Nothing is updated/);
});

test('a quiet report says so rather than inventing findings', async () => {
  const { baseline: b, result } = await run({
    fetchJson: fakeApi({ releases: [PINNED] }),
  });
  const report = renderReport(b, result);
  assert.match(report, /No releases newer than the pinned tag/);
  assert.equal(result.releases.length, 0);
});

test('the report never contains a credential-shaped value', () => {
  // The body is posted to a public pull request.
  const report = renderReport(baseline, { unknownPinnedTag: false, releases: [] });
  assert.doesNotMatch(report, /gh[pousr]_[A-Za-z0-9]{16,}/);
  assert.doesNotMatch(report, /Bearer\s+\S+/);
});
