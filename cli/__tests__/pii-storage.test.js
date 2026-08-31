/**
 * Regression coverage for declaration-scoped PII encryption checks.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PIIComplianceAgent } from '../agents/pii-compliance-agent.js';

function writeTempFile(content, ext = '.sql') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-pii-storage-'));
  const file = path.join(dir, `schema${ext}`);
  fs.writeFileSync(file, content);
  return { dir, file };
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('PII storage encryption scope', () => {
  const agent = new PIIComplianceAgent();

  it('does not let unrelated encryption text hide an unencrypted PII column', async () => {
    const { dir, file } = writeTempFile(`
      CREATE TABLE customers (
        ssn TEXT,
        notes TEXT
      );
      // encrypt the separate notes payload before sending it elsewhere
      const encryptedNotes = encrypt(notes);
    `);

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.equal(
        findings.filter(f => f.rule === 'PII_NO_ENCRYPTION_AT_REST').length,
        1,
        'The unencrypted ssn declaration should remain visible'
      );
    } finally {
      cleanup(dir);
    }
  });

  it('stays quiet when encryption is declared on the same PII field', async () => {
    const { dir, file } = writeTempFile(`
      CREATE TABLE customers (
        ssn TEXT ENCRYPTED,
        notes TEXT
      );
      addColumn('passport', 'TEXT', { encrypted: true });
    `);

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.equal(
        findings.filter(f => f.rule === 'PII_NO_ENCRYPTION_AT_REST').length,
        0,
        'A field with an explicit encryption annotation should stay quiet'
      );
    } finally {
      cleanup(dir);
    }
  });

  it('accepts an explicit quoted encryption mode in an ORM declaration', async () => {
    const { dir, file } = writeTempFile(`
      addColumn('passport', 'TEXT', { encrypted: 'aes' });
    `, '.js');

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.equal(
        findings.filter(f => f.rule === 'PII_NO_ENCRYPTION_AT_REST').length,
        0,
        'An explicit encryption mode should keep the PII field quiet'
      );
    } finally {
      cleanup(dir);
    }
  });

  it('does not treat encryption prose or a false annotation as protection', async () => {
    const { dir, file } = writeTempFile(`
      CREATE TABLE customers (
        ssn TEXT /* encryption planned later */,
        passport TEXT /* encrypted: false */
      );
    `);

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.equal(
        findings.filter(f => f.rule === 'PII_NO_ENCRYPTION_AT_REST').length,
        2,
        'Comments must not hide unencrypted PII fields'
      );
    } finally {
      cleanup(dir);
    }
  });

  it('does not treat a descriptive object value as an encryption control', async () => {
    const { dir, file } = writeTempFile(`
      const field = {
        name: 'ssn',
        type: 'TEXT',
        description: 'encrypted: true'
      };
    `, '.js');

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.equal(
        findings.filter(f => f.rule === 'PII_NO_ENCRYPTION_AT_REST').length,
        1,
        'Descriptive prose is not evidence of encrypted storage'
      );
    } finally {
      cleanup(dir);
    }
  });
});
