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

import { DataflowInvestigator, enclosingFunctions, LANGUAGES } from '../agents/dataflow-investigator.js';

const PY = LANGUAGES.py;
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

describe('sources the operator already controls', () => {
  // Flask's own `flask shell` reads PYTHONSTARTUP and evals it, exactly as the
  // CPython REPL documents. Confirming that against a project with no known
  // vulnerabilities is the kind of claim that costs a reader their trust in
  // every other confirmation.
  it('stops at likely for a value read from the environment', () => {
    const file = source('startup.py', [
      'import os',
      '',
      'def shell(ctx):',
      '    startup = os.environ.get("PYTHONSTARTUP")',
      '    eval(compile(open(startup).read(), startup, "exec"), ctx)',
    ]);

    const { claim } = trace(file, 5, { rule: 'CODE_INJECTION_EVAL_GENERIC' });
    assert.equal(claim.verdict, 'likely', 'the flow is real; the threat model is not');
    assert.match(claim.rationale, /already runs this process/);
  });

  it('stops at likely for argv, in either language', () => {
    const js = source('cli.js', [
      'export function run(db) {',
      '  const name = process.argv[2];',
      '  return db.raw(`SELECT * FROM t WHERE n = ${name}`);',
      '}',
    ]);
    assert.equal(trace(js, 3).claim.verdict, 'likely');
  });

  it('still confirms a request-sourced value in the same file', () => {
    const file = source('mixed.py', [
      'import os',
      'from flask import request',
      '',
      'def handler(db):',
      '    home = os.environ.get("HOME")',
      '    name = request.args.get("name")',
      '    return db.execute(f"SELECT * FROM t WHERE n = {name}")',
    ]);
    assert.equal(trace(file, 7).claim.verdict, 'confirmed', 'a remote caller controls this one');
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

  it('leaves languages it has no vocabulary for alone', () => {
    const file = source('handler.go', [
      'func handler(r *http.Request, db *sql.DB) {',
      '\tuserID := r.URL.Query().Get("id")',
      '\tdb.Query("SELECT * FROM users WHERE id = " + userID)',
      '}',
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

  it('does not trace a line that is a comment', () => {
    const file = source('documented.js', [
      '/**',
      ' * Never write eval(req.body.x) in a handler.',
      ' */',
      'export const safe = 1;',
    ]);
    assert.equal(trace(file, 2, { rule: 'CODE_INJECTION_EVAL' }).claim, null,
      'a comment is not code that runs');
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

describe('Python', () => {
  // The walk is the same; the vocabulary and the scope rule are not. Python
  // closes a function by dedenting, so containment cannot be shared with a
  // language that closes it with a brace.
  it('confirms a value from the Flask request', () => {
    const file = source('app.py', [
      'from flask import request',
      '',
      'def get_user(db):',
      '    user_id = request.args.get("id")',
      '    query = f"SELECT * FROM users WHERE id = {user_id}"',
      '    return db.execute(query)',
    ]);

    const { claim } = trace(file, 5);
    assert.equal(claim.verdict, 'confirmed');
    assert.match(claim.rationale, /Flask request/);
  });

  it('refutes a coerced value', () => {
    const file = source('coerced.py', [
      'from flask import request',
      '',
      'def get_user(db):',
      '    user_id = int(request.args.get("id"))',
      '    query = f"SELECT * FROM users WHERE id = {user_id}"',
      '    return db.execute(query)',
    ]);
    assert.equal(trace(file, 5).claim.verdict, 'refuted');
  });

  it('does not read braces in a plain string as interpolation', () => {
    const file = source('plain.py', [
      'def render(db):',
      '    query = "SELECT * FROM users WHERE meta = {}"',
      '    return db.execute(query)',
    ]);
    assert.equal(trace(file, 3).claim, null, 'only an f-string interpolates');
  });

  it('drops self so parameter indexes line up with call sites', () => {
    const dao = source('dao.py', [
      'class UserDAO:',
      '    def __init__(self, db):',
      '        self.db = db',
      '',
      '    def find(self, threshold):',
      '        return self.db.execute(f"SELECT * FROM s WHERE n > {threshold}")',
    ]);
    const routes = source('routes.py', [
      'from flask import request',
      'from dao import UserDAO',
      '',
      'def allocations(dao):',
      '    threshold = request.args.get("threshold")',
      '    return dao.find(threshold)',
    ]);

    const finding = createFinding({
      file: dao, line: 6, rule: 'SQL_INJECTION_TEMPLATE_LITERAL', title: 'SQL injection',
      category: 'injection', severity: 'critical',
    });
    new DataflowInvestigator().investigate([finding], { rootPath: ROOT, files: [dao, routes] });

    const claim = finding.evidence.claims.find((c) => c.source === 'dataflow');
    assert.equal(claim.verdict, 'confirmed', 'threshold is the first argument a caller passes, not the second');
    assert.equal(validateCitations(claim, { rootPath: ROOT }).status, 'valid');
  });

  it('does not treat a sibling def above the sink as its parent', () => {
    const lines = [
      'def sibling(threshold):',
      '    return threshold',
      '',
      'def target(db):',
      '    return db.execute(f"SELECT {threshold}")',
    ];
    const scopes = enclosingFunctions(lines, 5, null, PY);
    assert.deepEqual(scopes.map((s) => s.name), ['target'], 'the sibling dedented before the sink');
  });

  it('sees an outer def when the sink is nested inside a block', () => {
    const lines = [
      'def handler(threshold, db):',
      '    if threshold:',
      '        return db.execute(f"SELECT {threshold}")',
    ];
    assert.deepEqual(enclosingFunctions(lines, 3, null, PY).map((s) => s.name), ['handler']);
  });

  it('does not index a def as a call to itself', () => {
    const dao = source('selfcall.py', [
      'def find(threshold):',
      '    return db.execute(f"SELECT {threshold}")',
    ]);
    const finding = createFinding({
      file: dao, line: 2, rule: 'SQL_INJECTION_TEMPLATE_LITERAL', title: 'x',
      category: 'injection', severity: 'critical',
    });
    new DataflowInvestigator().investigate([finding], { rootPath: ROOT, files: [dao] });
    assert.equal(finding.evidence.verdict, 'unknown', 'no caller exists, so nothing is established');
  });
});

describe('crossing the function boundary', () => {
  // The dominant shape in real handler code: the sink is in a helper, the value
  // arrives as a parameter, and the caller lives in another file. Found against
  // NodeGoat's allocations-dao.js, where the tainted value is destructured in a
  // route file and passed into a DAO.
  const withCaller = (callerBody) => {
    source('dao.js', [
      'export function runQuery(db, threshold) {',
      '  return db.raw(`SELECT * FROM s WHERE n > \'${threshold}\'`);',
      '}',
    ]);
    source('caller.js', callerBody);
    return {
      dao: path.join(ROOT, 'dao.js'),
      files: [path.join(ROOT, 'dao.js'), path.join(ROOT, 'caller.js')],
    };
  };

  const traceWithFiles = (file, line, files) => {
    const finding = createFinding({
      file, line, rule: 'SQL_INJECTION_TEMPLATE_LITERAL', title: 'SQL injection',
      category: 'injection', severity: 'critical',
    });
    new DataflowInvestigator().investigate([finding], { rootPath: ROOT, files });
    return finding.evidence.claims.find((c) => c.source === 'dataflow') || null;
  };

  it('confirms through a caller in another file', () => {
    const { dao, files } = withCaller([
      "import { runQuery } from './dao.js';",
      'export function handler(req, db) {',
      '  const threshold = req.query.threshold;',
      '  return runQuery(db, threshold);',
      '}',
    ]);

    const claim = traceWithFiles(dao, 2, files);
    assert.equal(claim.verdict, 'confirmed');
    assert.ok(claim.attackPath.some((step) => step.includes('runQuery is called here')),
      'the path names the boundary it crossed');
  });

  it('resolves a value destructured across several lines', () => {
    const { dao, files } = withCaller([
      "import { runQuery } from './dao.js';",
      'export function handler(req, db) {',
      '  const {',
      '    threshold',
      '  } = req.query;',
      '  return runQuery(db, threshold);',
      '}',
    ]);

    assert.equal(traceWithFiles(dao, 2, files).verdict, 'confirmed', 'formatters write destructuring this way constantly');
  });

  it('cites the caller file for the caller hops', () => {
    const { dao, files } = withCaller([
      "import { runQuery } from './dao.js';",
      'export function handler(req, db) {',
      '  const threshold = req.query.threshold;',
      '  return runQuery(db, threshold);',
      '}',
    ]);

    const claim = traceWithFiles(dao, 2, files);
    assert.equal(validateCitations(claim, { rootPath: ROOT }).status, 'valid');
    const files_ = new Set(claim.citations.map((c) => path.basename(c.file)));
    assert.deepEqual([...files_].sort(), ['caller.js', 'dao.js'], 'a cross-file trace cites both files');
  });

  it('refutes when the only caller passes a value it does not control', () => {
    const { dao, files } = withCaller([
      "import { runQuery } from './dao.js';",
      'export function handler(req, db) {',
      '  return runQuery(db, parseInt(req.query.threshold, 10));',
      '}',
    ]);

    assert.equal(traceWithFiles(dao, 2, files).verdict, 'refuted');
  });

  it('confirms when any one caller is tainted, however safe the others are', () => {
    source('dao.js', [
      'export function runQuery(db, threshold) {',
      '  return db.raw(`SELECT * FROM s WHERE n > \'${threshold}\'`);',
      '}',
    ]);
    source('safe-caller.js', [
      "import { runQuery } from './dao.js';",
      'export const a = (db) => runQuery(db, 5);',
    ]);
    source('bad-caller.js', [
      "import { runQuery } from './dao.js';",
      'export const b = (req, db) => runQuery(db, req.query.threshold);',
    ]);

    const files = ['dao.js', 'safe-caller.js', 'bad-caller.js'].map((f) => path.join(ROOT, f));
    assert.equal(traceWithFiles(path.join(ROOT, 'dao.js'), 2, files).verdict, 'confirmed');
  });

  it('abstains when a caller argument cannot be resolved', () => {
    const { dao, files } = withCaller([
      "import { runQuery } from './dao.js';",
      'export function handler(db, threshold) {',
      '  return runQuery(db, threshold);',
      '}',
    ]);

    assert.equal(traceWithFiles(dao, 2, files), null, 'one boundary, not a call tree');
  });

  it('does not resolve a common function name without an import link', () => {
    source('dao.js', [
      'export function handler(db, threshold) {',
      '  return db.raw(`SELECT * FROM s WHERE n > \'${threshold}\'`);',
      '}',
    ]);
    source('unrelated.js', [
      'export const go = (req) => handler(req.db, req.query.threshold);',
    ]);

    const files = ['dao.js', 'unrelated.js'].map((f) => path.join(ROOT, f));
    assert.equal(traceWithFiles(path.join(ROOT, 'dao.js'), 2, files), null,
      'some other `handler` in the repo is not evidence about this one');
  });

  it('files nothing when no file list was provided', () => {
    withCaller([
      "import { runQuery } from './dao.js';",
      'export function handler(req, db) {',
      '  return runQuery(db, req.query.threshold);',
      '}',
    ]);
    assert.equal(traceWithFiles(path.join(ROOT, 'dao.js'), 2, null), null,
      'the pass never crawls the disk on its own');
  });
});

describe('enclosing scopes', () => {
  it('returns outer functions, not just the nearest', () => {
    const lines = [
      'this.getByThreshold = (userId, threshold, callback) => {',
      '  const criteria = () => {',
      '    if (threshold) {',
      '      return { $where: `n > ${threshold}` };',
      '    }',
      '  };',
      '};',
    ];
    const scopes = enclosingFunctions(lines, 4);
    const names = scopes.map((s) => s.name);

    assert.ok(names.includes('criteria'), 'the nearest scope');
    assert.ok(names.includes('getByThreshold'), 'and the one that declares the parameter');
    assert.equal(names.includes('if'), false, 'a condition is not a parameter list');
  });

  it('ignores a function whose body closed before the target line', () => {
    const lines = [
      'function sibling(a) {',
      '  return a;',
      '}',
      'const x = 1;',
    ];
    assert.deepEqual(enclosingFunctions(lines, 4), []);
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
