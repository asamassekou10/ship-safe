import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';

import { VibeCodingAgent } from '../agents/vibe-coding-agent.js';

const tempDirs = [];

function writeFixture(source) {
  const rootPath = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-vibe-sql-'));
  const file = path.join(rootPath, 'fixture.js');
  fs.writeFileSync(file, source);
  tempDirs.push(rootPath);
  return { rootPath, file };
}

async function scan(source) {
  const { rootPath, file } = writeFixture(source);
  return new VibeCodingAgent().analyze({
    rootPath,
    files: [file],
    recon: {},
    options: {},
  });
}

afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('VibeCodingAgent SQL interpolation detection', () => {
  it('does not classify an interpolated shell command as SQL injection', async () => {
    // Shell interpolation belongs to command-injection detection, not SQL detection.
    const findings = await scan('exec(`deploy ${userInput}`);');

    assert.equal(
      findings.some((finding) => finding.rule === 'VIBE_NO_PARAMETERIZED_QUERY'),
      false,
    );
  });

  it('detects an interpolated SQL template passed to a query method', async () => {
    const findings = await scan('db.query(`SELECT * FROM users WHERE id = ${userInput}`);');

    assert.equal(
      findings.some((finding) => finding.rule === 'VIBE_NO_PARAMETERIZED_QUERY'),
      true,
    );
  });

  it('detects concatenated SQL passed to an execute method', async () => {
    const findings = await scan('db.execute("DELETE FROM users WHERE id = " + userInput);');

    assert.equal(
      findings.some((finding) => finding.rule === 'VIBE_NO_PARAMETERIZED_QUERY'),
      true,
    );
  });
});
