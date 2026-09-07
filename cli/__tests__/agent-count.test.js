/**
 * Ship Safe — user-facing agent count stays true
 * ===============================================
 *
 * The number of scanning agents appears in six user-facing strings across the
 * CLI, the banner, and the README. Nothing connected those strings to the
 * registry, so adding an agent left six claims quietly overstating or
 * understating what runs.
 *
 * This is a small claim to get wrong, which is exactly why it is worth a test:
 * a security tool that is casually inaccurate about its own size invites the
 * reader to wonder what else is approximate.
 *
 * Run: node --test cli/__tests__/agent-count.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { buildOrchestrator } from '../agents/index.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Files whose copy quotes the agent count. */
const COPY_FILES = [
  'cli/bin/ship-safe.js',
  'cli/utils/output.js',
  'cli/agents/index.js',
  'README.md',
];

/** Every "<number> agents" or "<number> scanning agents" claim in a file. */
function claimedCounts(source) {
  const counts = [];
  const pattern = /(\d+)\s+(?:scanning\s+)?agents\b/g;
  let match;
  while ((match = pattern.exec(source)) !== null) counts.push(Number(match[1]));
  return counts;
}

describe('user-facing agent count', () => {
  it('matches the number of agents actually registered in the scanning pool', () => {
    const actual = buildOrchestrator().agents.length;

    for (const relative of COPY_FILES) {
      const source = fs.readFileSync(path.join(repoRoot, relative), 'utf8');

      for (const claimed of claimedCounts(source)) {
        assert.equal(
          claimed,
          actual,
          `${relative} claims ${claimed} agents but the scanning pool holds ${actual}. `
            + 'Update the copy, or the claim ships wrong.',
        );
      }
    }
  });

  it('is claimed somewhere, so the check cannot pass by finding nothing', () => {
    const total = COPY_FILES.reduce((sum, relative) => {
      const source = fs.readFileSync(path.join(repoRoot, relative), 'utf8');
      return sum + claimedCounts(source).length;
    }, 0);

    assert.ok(total > 0, 'no agent-count claim was found; the regex or the copy has moved');
  });

  it('counts only the scanning pool, not every file in cli/agents/', () => {
    // The directory holds post-processors, generators, and reporters that never
    // enter the pool. Asserting the difference keeps a future reader from
    // "fixing" the count to the file total.
    const files = fs
      .readdirSync(path.join(repoRoot, 'cli', 'agents'))
      .filter((name) => name.endsWith('.js'));

    assert.ok(
      files.length > buildOrchestrator().agents.length,
      'expected more agent files than pooled agents; if these are equal the distinction has gone',
    );
  });
});
