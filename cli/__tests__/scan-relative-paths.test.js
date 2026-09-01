/**
 * Test and example exclusion is about a file's role *within* a project.
 *
 * Matching those patterns against an absolute path asks a different question —
 * whether anything in the machine's directory structure resembles a fixture —
 * and answers it wrongly for any repository that happens to live under a
 * directory named test, fixtures, examples, or benchmarks.
 *
 * The concrete failure: the false-positive harness scans vendored checkouts
 * under benchmarks/**\/corpus-src/, which a rule excludes so those vulnerable
 * applications do not lower this repository's own score. Correct when scanning
 * Ship Safe; wrong when the corpus is the target, which is what that harness
 * does. Express reported 1 finding in place and 20 elsewhere, at one commit.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';

import { isTestFile, isExampleFile } from '../utils/patterns.js';

describe('paths relative to the scan root', () => {
  it('does not treat a project as a fixture because of where it is checked out', () => {
    const root = '/home/dev/fixtures/my-api';
    const file = path.join(root, 'src/server.js');

    assert.equal(isTestFile(file), true, 'the absolute path looks like a fixture');
    assert.equal(isTestFile(file, root), false, 'but nothing inside the project is one');
  });

  it('still excludes test code inside the project', () => {
    const root = '/home/dev/my-api';
    assert.equal(isTestFile(path.join(root, 'test/server.test.js'), root), true);
    assert.equal(isTestFile(path.join(root, 'src/__tests__/x.js'), root), true);
    assert.equal(isExampleFile(path.join(root, 'examples/basic.js'), root), true);
  });

  it('still excludes a vendored corpus when the repository around it is scanned', () => {
    const root = '/home/dev/ship-safe';
    const vendored = path.join(root, 'benchmarks/false-positives/corpus-src/DVWA/login.php');
    assert.equal(isTestFile(vendored, root), true, 'DVWA must not lower this repo\'s score');
  });

  it('scans the same corpus normally when it is itself the target', () => {
    const root = '/home/dev/ship-safe/benchmarks/false-positives/corpus-src/express';
    const file = path.join(root, 'lib/application.js');
    assert.equal(isTestFile(file, root), false, 'the harness must be able to measure what it vendored');
  });

  it('matches a first-segment directory, which has no leading separator', () => {
    const root = '/home/dev/my-api';
    assert.equal(isTestFile(path.join(root, 'fixtures/data.js'), root), true);
  });

  it('falls back to the absolute path for files outside the root', () => {
    const outside = '/elsewhere/test/helper.js';
    assert.equal(isTestFile(outside, '/home/dev/my-api'), true);
  });

  it('behaves as before when no root is given', () => {
    assert.equal(isTestFile('/home/dev/my-api/test/x.js'), true);
    assert.equal(isTestFile('/home/dev/my-api/src/x.js'), false);
  });
});
