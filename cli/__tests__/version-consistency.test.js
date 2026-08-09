import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MCP_SERVER_VERSION } from '../commands/mcp.js';
import { PACKAGE_VERSION } from '../utils/package-version.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));

describe('release version consistency', () => {
  it('keeps package.json, package-lock.json, and MCP metadata aligned', () => {
    const packageJson = readJson('package.json');
    const packageLock = readJson('package-lock.json');

    assert.equal(packageLock.version, packageJson.version);
    assert.equal(packageLock.packages[''].version, packageJson.version);
    assert.equal(PACKAGE_VERSION, packageJson.version);
    assert.equal(MCP_SERVER_VERSION, packageJson.version);
  });
});
