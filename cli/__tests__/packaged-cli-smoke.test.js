/**
 * Ship Safe — packaged CLI smoke test
 * ===================================
 *
 * Issue #83: validates that the CLI entrypoint works the way users
 * actually run it (`npx ship-safe scan <project>`), instead of importing
 * internals directly. Uses a small fixture project with one risky pattern
 * and asserts the command exits successfully while printing the expected
 * finding and summary line.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = path.join(ROOT, 'cli', 'bin', 'ship-safe.js');
const FIXTURE = path.join(ROOT, 'cli', '__tests__', 'fixtures', 'smoke-project');

describe('packaged CLI smoke test (issue #83)', () => {
  it('runs through the package entrypoint and reports the fixture finding', () => {
    const res = spawnSync(
      process.execPath,
      [BIN, 'scan', FIXTURE, '--no-color', '--no-cache', '--include-tests'],
      { encoding: 'utf8', timeout: 60_000 },
    );

    // The CLI is designed to exit 1 when findings exist (CI gate), 0 when clean.
    // A crash would surface as a different status or a stack trace on stderr,
    // so status 1 + the expected output below proves the entrypoint ran.
    assert.strictEqual(
      res.status,
      1,
      `CLI should exit 1 when findings exist\nstdout: ${res.stdout}\nstderr: ${res.stderr}`,
    );
    assert.match(
      res.stdout,
      /Password Assignment/,
      'stdout should contain the expected finding from the fixture project',
    );
    assert.match(
      res.stdout,
      /Found 1 secret/,
      'stdout should contain the summary line with the finding count',
    );
  });
});
