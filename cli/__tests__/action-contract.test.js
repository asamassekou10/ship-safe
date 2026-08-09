import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ACTION = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8');

describe('GitHub Action contract', () => {
  it('installs the version bundled with the action instead of latest', () => {
    assert.match(ACTION, /GITHUB_ACTION_PATH.*package\.json/);
    assert.match(ACTION, /npm install -g "ship-safe@\$VERSION"/);
    assert.doesNotMatch(ACTION, /ship-safe@latest/);
  });

  it('generates SARIF during the primary scan', () => {
    assert.match(ACTION, /--sarif \/tmp\/ship-safe-results\.sarif/);
    assert.doesNotMatch(ACTION, /name: Generate SARIF/);
    assert.match(ACTION, /steps\.scan\.outputs\.sarif_file/);
  });

  it('passes fail-on through to the CLI gate', () => {
    assert.match(ACTION, /FLAGS\+=\(--fail-on "\$SHIP_SAFE_FAIL_ON"\)/);
  });
});
