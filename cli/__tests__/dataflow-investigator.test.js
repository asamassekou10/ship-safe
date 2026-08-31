/**
 * DataflowInvestigator — what it traces, and what it refuses to guess at.
 *
 * The refusals matter more than the traces. This pass can file a 'refuted'
 * verdict, and a wrong one is the single error class that loses a real
 * vulnerability quietly, so most of what follows checks that it abstains where
 * it cannot see.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { DataflowInvestigator } from '../agents/dataflow-investigator.js';
import { createFinding } from '../agents/base-agent.js';
import { attachEvidence, createClaim, validateCitations } from '../utils/evidence.js';

let ROOT;

const source = (name, lines) => {
  const abs = path.join(ROOT, name);
  fs.writeFileSync(abs, lines.join('\n'));
  return abs;
};

/** Investigate one finding and hand back its dataflow claim, if any. */
const trace = (file, line, overrides = {}) => {
  const finding = createFinding({
    file, line, rule: 'SQL_INJECTION_TEMPLATE_LITERAL', title: 'SQL injection',
    category: 'injection', severity: 'critical', ...overrides,
  });
  new DataflowInvestigator().investigate([finding], { rootPath: ROOT });
  return {
    finding,
    claim: finding.evidence.claims.find((c) => c.source === 'dataflow') || null,
  };
};

before(() => { ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-dataflow-')); });
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));

describe('tracing to an untrusted source', () => {
  it('confirms a source written directly into the sink', () => {
    const file = source('direct.js', [
      'export function handler(req, db) {',
      '  return db.raw(`SELECT * FROM users WHERE id = ${req.query.id}`);',
      '}',
    ]);
    const { claim } = trace(file, 2);
    assert.equal(claim.verdict, 'confirmed');
    assert.match(claim.rationale, /directly from the HTTP request/);
  });

  it('confirms across intermediate assignments', () => {
    const file = source('hops.js', [
      'export function handler(req, db) {',
      '  const raw = req.params.id;',
      '  const userId = raw;',
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    const { claim } = trace(file, 4);
    assert.equal(claim.verdict, 'confirmed');
    assert.equal(claim.attackPath.length, 3, 'sink, then each assignment it walked through');
  });

  it('cites every hop it walked, and the citations resolve', () => {
    const file = source('cited.js', [
      'export function handler(req, db) {',
      '  const userId = req.body.id;',
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    const { claim } = trace(file, 3);
    assert.equal(validateCitations(claim, { rootPath: ROOT }).status, 'valid');
    assert.deepEqual(claim.citations.map((c) => c.line), [3, 2]);
  });
});

describe('refuting a traced path', () => {
  it('refutes when a sanitizer produced the value', () => {
    const file = source('sanitized.js', [
      'export function handler(req, db) {',
      '  const userId = parseInt(req.params.id, 10);',
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    const { claim, finding } = trace(file, 3);
    assert.equal(claim.verdict, 'refuted');
    assert.equal(finding.evidence.verdict, 'refuted');
  });

  it('refutes when the value is a literal in the source', () => {
    const file = source('literal.js', [
      'export function handler(db) {',
      "  const userId = 'system';",
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    assert.equal(trace(file, 3).claim.verdict, 'refuted');
  });

  it('does not treat a validator applied to some other value as a mitigation', () => {
    const file = source('elsewhere.js', [
      'export function handler(req, db) {',
      '  const email = validateEmail(req.body.email);',
      '  const userId = req.body.id;',
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    const { claim } = trace(file, 4);
    assert.equal(claim.verdict, 'confirmed', 'the sanitizer guards email, not userId');
  });
});

describe('sinks with more than one input', () => {
  // Regression: the tracer used to return on the first seed that resolved. On
  // NodeGoat's allocations-dao.js that meant reading the coerced half of a
  // two-value template, refuting it, and never looking at the raw half — a
  // live NoSQL injection reported as handled.
  it('confirms when any one input is tainted, however safe the others are', () => {
    const file = source('mixed.js', [
      'export function handler(req, db) {',
      '  const parsedId = parseInt(req.params.id, 10);',
      '  const threshold = req.query.threshold;',
      '  return db.raw(`SELECT * FROM s WHERE id = ${parsedId} AND n > ${threshold}`);',
      '}',
    ]);
    const { claim } = trace(file, 4);
    assert.equal(claim.verdict, 'confirmed', 'the coerced value does not launder the raw one');
  });

  it('refutes only when every input is accounted for', () => {
    const file = source('allsafe.js', [
      'export function handler(req, db) {',
      '  const parsedId = parseInt(req.params.id, 10);',
      '  const parsedMax = parseInt(req.query.max, 10);',
      '  return db.raw(`SELECT * FROM s WHERE id = ${parsedId} AND n > ${parsedMax}`);',
      '}',
    ]);
    const { claim } = trace(file, 4);
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /Every value reaching the sink/);
  });

  it('abstains when one input is safe and another cannot be resolved', () => {
    const file = source('partial.js', [
      'export function handler(req, db, threshold) {',
      '  const parsedId = parseInt(req.params.id, 10);',
      '  return db.raw(`SELECT * FROM s WHERE id = ${parsedId} AND n > ${threshold}`);',
      '}',
    ]);
    assert.equal(trace(file, 3).claim, null, 'a partial trace is not a mitigation');
  });
});

describe('abstaining', () => {
  it('files nothing when the value comes from outside the file', () => {
    const file = source('param.js', [
      'export function handler(userId, db) {',
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    const { claim, finding } = trace(file, 2);
    assert.equal(claim, null, 'a trace that dies teaches nothing and says nothing');
    assert.equal(finding.evidence.verdict, 'unknown');
  });

  it('leaves languages it cannot parse alone', () => {
    const file = source('handler.py', [
      'def handler(request, db):',
      '    user_id = request.GET["id"]',
      '    return db.raw(f"SELECT * FROM users WHERE id = {user_id}")',
    ]);
    assert.equal(trace(file, 3).claim, null);
  });

  it('never refutes a finding whose evidence is the literal itself', () => {
    const file = source('secret.js', [
      'export const config = {',
      "  apiKey: 'sk-live-000000000000000000000000',",
      '};',
    ]);
    const { claim } = trace(file, 2, { rule: 'HARDCODED_API_KEY', category: 'secret' });
    assert.equal(claim, null, 'a hardcoded secret is proven by being a literal, not disproven');
  });

  it('says nothing about a file it cannot read', () => {
    const { claim } = trace(path.join(ROOT, 'absent.js'), 3);
    assert.equal(claim, null);
  });

  it('ignores identifiers that are only words inside a string', () => {
    const file = source('prose.js', [
      'export function handler(db) {',
      '  return db.raw(`SELECT name FROM users WHERE role = admin`);',
      '}',
    ]);
    assert.equal(trace(file, 2).claim, null, 'SELECT and FROM are not values to walk');
  });
});

describe('precedence in production', () => {
  it('outranks the heuristic pass when they disagree', () => {
    const file = source('conflict.js', [
      'export function handler(req, db) {',
      '  const userId = parseInt(req.params.id, 10);',
      '  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      '}',
    ]);
    const finding = createFinding({
      file, line: 3, rule: 'SQL_INJECTION_TEMPLATE_LITERAL', title: 'SQL injection',
      category: 'injection', severity: 'critical',
    });

    // The heuristic sees "req.params" in the window and calls it likely.
    attachEvidence(finding, createClaim({ source: 'heuristic', verdict: 'likely', rationale: 'user input nearby' }));
    new DataflowInvestigator().investigate([finding], { rootPath: ROOT });

    assert.equal(finding.evidence.verdict, 'refuted');
    assert.deepEqual(finding.evidence.decidedBy, ['dataflow']);
  });
});
