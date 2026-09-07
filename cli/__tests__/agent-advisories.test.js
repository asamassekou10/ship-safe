/**
 * Ship Safe — pinned agent advisory table
 * ========================================
 *
 * Issue #204. The table decides when a configured execution sink is promoted
 * to `reachable`, so what these tests mostly guard is the table's refusal to
 * over-claim: an unreadable version stays unresolved, an untested version
 * around a tested one is not covered, and no path through this code turns
 * "we could not tell" into "you are fine".
 *
 * Run: node --test cli/__tests__/agent-advisories.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  loadAdvisoryTable,
  resolveReachability,
  detectAgentVersion,
  compareVersions,
  isAffected,
  tableAgeDays,
} from '../utils/agent-advisories.js';

/** A table with one entry, for tests that should not depend on the real one. */
const TABLE = {
  schemaVersion: 1,
  tableVersion: 'test',
  recordedAt: '2026-09-01',
  entries: [{
    id: 'demo',
    agent: 'demo',
    displayName: 'Demo Agent',
    binaries: ['demo'],
    sinks: ['WORKSPACE_GIT_FSMONITOR_EXEC'],
    affected: { lt: '2.0.0' },
    patchedIn: '2.0.0',
    cve: 'CVE-TEST-0001',
    source: 'https://example.invalid/advisory',
    recordedAt: '2026-09-01',
  }],
};

/** A stub for the version detector, so tests never depend on what is installed. */
const detector = (versions) => (binary) =>
  versions[binary] ? { binary: `/usr/local/bin/${binary}`, version: versions[binary] } : null;

// =============================================================================
// VERSION COMPARISON
// =============================================================================

describe('compareVersions', () => {
  it('orders dotted numeric versions', () => {
    assert.equal(compareVersions('1.2.3', '1.2.4'), -1);
    assert.equal(compareVersions('1.10.0', '1.9.0'), 1);
    assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
  });

  it('treats a missing segment as zero', () => {
    assert.equal(compareVersions('1.2', '1.2.0'), 0);
    assert.equal(compareVersions('1.2', '1.2.1'), -1);
  });

  it('tolerates a v prefix and build metadata', () => {
    assert.equal(compareVersions('v1.44.0', '1.44.0'), 0);
    assert.equal(compareVersions('1.44.0-beta.1', '1.44.0'), 0);
  });

  it('returns null rather than guessing at something unparseable', () => {
    assert.equal(compareVersions('nightly', '1.0.0'), null);
    assert.equal(compareVersions('1.0.0', ''), null);
  });
});

describe('isAffected', () => {
  it('handles an upper bound', () => {
    assert.equal(isAffected('1.43.9', { lt: '1.44.0' }), true);
    assert.equal(isAffected('1.44.0', { lt: '1.44.0' }), false);
  });

  it('handles a closed range', () => {
    const range = { gte: '0.102.0', lte: '0.130.0' };
    assert.equal(isAffected('0.110.0', range), true);
    assert.equal(isAffected('0.131.0', range), false);
    assert.equal(isAffected('0.101.0', range), false);
  });

  it('covers only the versions an exact list names', () => {
    const exact = { exact: ['0.18.2', '0.21.0'] };
    assert.equal(isAffected('0.21.0', exact), true);
    assert.equal(isAffected('0.20.0', exact), false,
      'a version between two tested ones was not tested and is not claimed');
  });

  it('returns null when the version cannot be compared', () => {
    assert.equal(isAffected('nightly-build', { lt: '1.44.0' }), null);
    assert.equal(isAffected(null, { lt: '1.0.0' }), null);
  });
});

// =============================================================================
// RESOLUTION
// =============================================================================

describe('resolveReachability', () => {
  it('promotes to reachable when an affected version is installed', () => {
    const r = resolveReachability('WORKSPACE_GIT_FSMONITOR_EXEC', {
      table: TABLE,
      detect: detector({ demo: '1.9.0' }),
    });

    assert.equal(r.state, 'reachable');
    assert.match(r.reason, /Demo Agent 1\.9\.0/);
    assert.match(r.reason, /CVE-TEST-0001/);
  });

  it('stays unresolved when the version cannot be read', () => {
    const r = resolveReachability('WORKSPACE_GIT_FSMONITOR_EXEC', {
      table: TABLE,
      detect: detector({ demo: 'nightly' }),
    });

    assert.equal(r.state, 'unresolved', 'an unreadable version is never reachable');
  });

  it('stays unresolved when no covered agent is installed', () => {
    const r = resolveReachability('WORKSPACE_GIT_FSMONITOR_EXEC', {
      table: TABLE,
      detect: () => null,
    });

    assert.equal(r.state, 'unresolved');
    assert.match(r.reason, /not evidence the folder is safe/);
  });

  it('does not claim safety when the installed version is patched', () => {
    const r = resolveReachability('WORKSPACE_GIT_FSMONITOR_EXEC', {
      table: TABLE,
      detect: detector({ demo: '2.5.0' }),
    });

    assert.equal(r.state, 'configured');
    assert.match(r.reason, /Other agents may still reach this sink/);
  });

  it('does not assess a sink no advisory covers', () => {
    const r = resolveReachability('WORKSPACE_ENVRC_EXEC', {
      table: TABLE,
      detect: detector({ demo: '1.0.0' }),
    });

    assert.equal(r.state, 'configured');
    assert.match(r.reason, /No pinned advisory covers this sink/);
    assert.deepEqual(r.candidates, []);
  });

  it('never reports reachable from an empty or unavailable table', () => {
    const r = resolveReachability('WORKSPACE_GIT_FSMONITOR_EXEC', {
      table: { tableVersion: 'unavailable', entries: [] },
      detect: detector({ demo: '1.0.0' }),
    });

    assert.equal(r.state, 'configured',
      'a table that failed to load must not behave like one that cleared the finding');
  });
});

// =============================================================================
// DETECTION SAFETY
// =============================================================================

describe('detectAgentVersion — safety', () => {
  it('will not run a binary from inside the folder being inspected', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-adv-'));
    const originalPath = process.env.PATH;

    try {
      // A repository that ships an executable named after an agent, and a
      // PATH that would otherwise find it. Running this is the exact attack
      // `ship-safe trust` warns about.
      const planted = path.join(dir, 'demo');
      fs.writeFileSync(planted, '#!/bin/sh\ntouch "$(dirname "$0")/executed"\necho 1.0.0\n');
      fs.chmodSync(planted, 0o755);

      process.env.PATH = `${dir}${path.delimiter}${originalPath}`;

      const found = detectAgentVersion('demo', { excludeRoot: dir });

      assert.equal(found, null, 'the scanned folder must never supply the binary');
      assert.equal(fs.existsSync(path.join(dir, 'executed')), false, 'and it must not have run');
    } finally {
      process.env.PATH = originalPath;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('ignores relative and empty PATH entries', () => {
    const originalPath = process.env.PATH;
    try {
      // An empty entry is the current directory to POSIX, which would let the
      // cwd decide what gets executed.
      process.env.PATH = `:.:relative/bin`;
      assert.equal(detectAgentVersion('demo', {}), null);
    } finally {
      process.env.PATH = originalPath;
    }
  });

  it('returns null for an agent that is not installed', () => {
    assert.equal(detectAgentVersion('definitely-not-a-real-agent-binary', {}), null);
  });
});

// =============================================================================
// THE SHIPPED TABLE
// =============================================================================

describe('the shipped advisory table', () => {
  const table = loadAdvisoryTable();

  it('is versioned and dated', () => {
    assert.equal(table.schemaVersion, 1);
    assert.match(table.tableVersion, /^\d{4}\.\d{2}\.\d{2}$/);
    assert.match(table.recordedAt, /^\d{4}-\d{2}-\d{2}$/);
  });

  it('cites a source and a date for every entry', () => {
    for (const entry of table.entries) {
      assert.ok(entry.source, `${entry.id} must cite where the claim came from`);
      assert.match(entry.source, /^https:\/\//, `${entry.id} source must be a URL`);
      assert.match(entry.recordedAt, /^\d{4}-\d{2}-\d{2}$/, `${entry.id} must record when`);
      assert.ok(entry.sinks?.length, `${entry.id} must name the sinks it covers`);
      assert.ok(entry.binaries?.length, `${entry.id} must name how to detect it`);
      assert.ok(entry.affected, `${entry.id} must state which versions are affected`);
    }
  });

  it('names sinks that correspond to real rules', () => {
    const known = new Set([
      'WORKSPACE_GIT_FSMONITOR_EXEC',
      'WORKSPACE_GIT_HOOKS_PATH',
      'WORKSPACE_GIT_ATTR_TREE',
      'WORKSPACE_GIT_FILTER_PROCESS',
      'WORKSPACE_GIT_HOOK_PRESENT',
      'WORKSPACE_TASK_AUTORUN',
      'WORKSPACE_DEVCONTAINER_INIT',
      'WORKSPACE_ENVRC_EXEC',
      'WORKSPACE_AGENT_HOOK_CONFIG',
    ]);

    for (const entry of table.entries) {
      for (const sink of entry.sinks) {
        assert.ok(known.has(sink), `${entry.id} names an unknown sink: ${sink}`);
      }
    }
  });

  it('records the GitSpawn and CVE-2026-48124 entries', () => {
    const ids = table.entries.map((e) => e.id);
    assert.ok(ids.includes('goose-fsmonitor'));
    assert.ok(ids.includes('hermes-agent-fsmonitor'));
    assert.ok(ids.includes('cursor-agent-hook-config'));

    const hermes = table.entries.find((e) => e.id === 'hermes-agent-fsmonitor');
    assert.equal(hermes.patchedIn, null, 'Hermes was unpatched at publication');
    assert.equal(hermes.cve, 'CVE-2026-71963');
  });
});

describe('tableAgeDays', () => {
  it('reports how stale the table is', () => {
    assert.equal(tableAgeDays({ recordedAt: '2026-09-01' }, new Date('2026-09-08T00:00:00Z')), 7);
    assert.equal(tableAgeDays({ recordedAt: '2026-09-01' }, new Date('2026-09-01T12:00:00Z')), 0);
  });

  it('returns null when there is no date to work from', () => {
    assert.equal(tableAgeDays({ tableVersion: 'unavailable', recordedAt: null }), null);
  });
});
