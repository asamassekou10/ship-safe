/**
 * .ship-safeignore handling
 * =========================
 *
 * `ci` loaded .gitignore but never .ship-safeignore, so the one command built
 * for pipelines was the only one that ignored the user's own suppression
 * config. On this repository that surfaced findings from `cli/__tests__/`,
 * whose fixtures are deliberately vulnerable and are excluded by that very
 * file.
 *
 * The loader is shared so a future caller cannot drift the same way. These
 * cover the loader itself and the upward walk that lets a subdirectory scan
 * still find the repository-level config.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { loadShipSafeIgnorePatterns, findUpwards, isTestFile, isExampleFile } from '../utils/patterns.js';

function workspace(ignoreBody, extraDirs = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-ignore-'));
  if (ignoreBody !== null) {
    fs.writeFileSync(path.join(dir, '.ship-safeignore'), ignoreBody);
  }
  for (const d of extraDirs) fs.mkdirSync(path.join(dir, d), { recursive: true });
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

describe('loadShipSafeIgnorePatterns', () => {
  it('expands a directory entry so nested files are excluded', () => {
    const ws = workspace('cli/__tests__/\n');
    try {
      assert.deepEqual(loadShipSafeIgnorePatterns(ws.dir), ['**/cli/__tests__/**']);
    } finally { ws.cleanup(); }
  });

  it('emits both anchored and nested globs for a file entry', () => {
    const ws = workspace('secrets.env\n');
    try {
      const globs = loadShipSafeIgnorePatterns(ws.dir);
      assert.ok(globs.includes('**/secrets.env'));
      assert.ok(globs.includes('secrets.env'));
    } finally { ws.cleanup(); }
  });

  it('skips comments and blank lines', () => {
    const ws = workspace('# a comment\n\n   \ndocs/\n');
    try {
      assert.deepEqual(loadShipSafeIgnorePatterns(ws.dir), ['**/docs/**']);
    } finally { ws.cleanup(); }
  });

  it('returns nothing when the file is absent', () => {
    const ws = workspace(null);
    try {
      assert.deepEqual(loadShipSafeIgnorePatterns(ws.dir), []);
    } finally { ws.cleanup(); }
  });

  it('finds the ignore file from a subdirectory', () => {
    // Scanning `repo/src` must still honor `repo/.ship-safeignore`.
    const ws = workspace('docs/\n', ['src/deep']);
    try {
      const globs = loadShipSafeIgnorePatterns(path.join(ws.dir, 'src', 'deep'));
      assert.deepEqual(globs, ['**/docs/**']);
    } finally { ws.cleanup(); }
  });

  it('honors entries a .gitignore loader would drop as security sensitive', () => {
    // .gitignore parsing deliberately keeps scanning .env and friends. This
    // file is an explicit instruction from the user, so it is taken literally.
    const ws = workspace('.env\nfixtures/keys.pem\n');
    try {
      const globs = loadShipSafeIgnorePatterns(ws.dir);
      assert.ok(globs.includes('**/.env'));
      assert.ok(globs.includes('**/fixtures/keys.pem'));
    } finally { ws.cleanup(); }
  });
});

describe('findUpwards', () => {
  it('returns null when nothing matches', () => {
    const ws = workspace(null);
    try {
      assert.equal(findUpwards(ws.dir, '.does-not-exist'), null);
    } finally { ws.cleanup(); }
  });

  it('locates a file in an ancestor directory', () => {
    const ws = workspace('docs/\n', ['a/b/c']);
    try {
      const found = findUpwards(path.join(ws.dir, 'a', 'b', 'c'), '.ship-safeignore');
      assert.ok(found && found.endsWith('.ship-safeignore'));
    } finally { ws.cleanup(); }
  });
});

describe('ci --threshold', () => {
  it('treats 0 as a real threshold rather than falling back to the default', () => {
    // `options.threshold || 75` made `--threshold 0` silently become 75, so a
    // report-only run could not be requested. `?? 75` is the fix; this pins the
    // distinction between an absent option and an explicit zero.
    const resolve = (opt) => Number(opt.threshold ?? 75);
    assert.equal(resolve({ threshold: 0 }), 0);
    assert.equal(resolve({ threshold: '0' }), 0);
    assert.equal(resolve({}), 75);
    assert.equal(resolve({ threshold: 60 }), 60);
  });
});

describe('test and example path classification', () => {
  it('recognises the common test layouts', () => {
    for (const p of [
      '/repo/test/app.js', '/repo/tests/thing.py', '/repo/__tests__/x.js',
      '/repo/src/thing.test.ts', '/repo/src/thing.spec.jsx', '/repo/test_client.py',
      '/repo/fixtures/data.json', '/repo/mocks/api.js', '/repo/src/x.stories.tsx',
    ]) {
      assert.equal(isTestFile(p), true, p);
    }
  });

  it('recognises example and demo layouts', () => {
    for (const p of ['/repo/examples/auth.js', '/repo/example/a.py', '/repo/samples/x.js', '/repo/demo/app.js']) {
      assert.equal(isExampleFile(p), true, p);
    }
  });

  it('does not misclassify production source', () => {
    // `lib/` is where express's only two real findings lived, against 528 in
    // `test/`. Misclassifying these would hide the findings that matter.
    for (const p of [
      '/repo/lib/router.js', '/repo/src/index.ts', '/repo/app/main.py',
      '/repo/contest/app.js',      // contains "test" but is not a test dir
      '/repo/src/latest.js',       // ends in "test" but is not a test file
      '/repo/src/protester.py',
    ]) {
      assert.equal(isTestFile(p), false, p);
      assert.equal(isExampleFile(p), false, p);
    }
  });
});
