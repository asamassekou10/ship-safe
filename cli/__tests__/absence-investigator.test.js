/**
 * AbsenceInvestigator — deciding rules that assert a control is missing.
 *
 * These rules are scoped to a file while the claim they make is about an
 * application, which is why they are the noisiest category in the tool. The
 * tests below pin both directions: found elsewhere refutes, absent everywhere
 * raises to 'likely' and no higher.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { AbsenceInvestigator, isAbsenceRule } from '../agents/absence-investigator.js';
import { createFinding } from '../agents/base-agent.js';
import { validateCitations } from '../utils/evidence.js';

let ROOT;
before(() => { ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-absence-')); });
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
beforeEach(() => {
  for (const entry of fs.readdirSync(ROOT)) fs.rmSync(path.join(ROOT, entry), { recursive: true, force: true });
});

const write = (name, lines) => {
  const abs = path.join(ROOT, name);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, lines.join('\n'));
  return abs;
};

const investigate = (rule, files, { file = files[0], line = 1 } = {}) => {
  const finding = createFinding({
    file, line, rule, title: rule, category: 'api', severity: 'medium',
  });
  new AbsenceInvestigator().investigate([finding], { rootPath: ROOT, files });
  return {
    finding,
    claim: finding.evidence.claims.find((c) => c.source === 'presence') || null,
  };
};

const EXPRESS_APP = [
  "import express from 'express';",
  'export const app = express();',
  "app.post('/login', (req, res) => res.json({ ok: true }));",
];

describe('finding the control elsewhere', () => {
  it('refutes when the control is applied in another file', () => {
    const route = write('routes/login.js', EXPRESS_APP);
    const setup = write('src/app.js', [
      "import helmet from 'helmet';",
      "import express from 'express';",
      'const app = express();',
      'app.use(helmet());',
    ]);

    const { claim } = investigate('API_NO_SECURITY_HEADERS', [route, setup]);
    assert.equal(claim.verdict, 'refuted');
    assert.equal(claim.citations[0].line, 4, 'cites where the control is actually applied');
  });

  it('does not accept an import as evidence the control is applied', () => {
    const route = write('routes/login.js', EXPRESS_APP);
    const setup = write('src/app.js', [
      "import helmet from 'helmet';",
      "import express from 'express';",
      'const app = express();',
      '// app.use(helmet());',
    ]);

    const { claim } = investigate('API_NO_SECURITY_HEADERS', [route, setup]);
    assert.equal(claim.verdict, 'likely', 'a dependency proves the idea occurred to someone, not that it was carried out');
  });

  it('does not accept a commented-out control', () => {
    const app = write('app.js', [...EXPRESS_APP, '// app.use(rateLimit({ max: 5 }));']);
    assert.equal(investigate('NO_RATE_LIMIT_LOGIN', [app]).claim.verdict, 'likely');
  });

  it('cites code that resolves', () => {
    const route = write('routes/login.js', EXPRESS_APP);
    const setup = write('src/app.js', ["import express from 'express';", 'const app = express();', 'app.use(helmet());']);

    const { claim } = investigate('API_NO_SECURITY_HEADERS', [route, setup]);
    assert.equal(validateCitations(claim, { rootPath: ROOT }).status, 'valid');
  });
});

describe('when the control is nowhere', () => {
  it('raises to likely, never to confirmed', () => {
    const app = write('app.js', EXPRESS_APP);
    const { claim } = investigate('API_NO_SECURITY_HEADERS', [app]);

    assert.equal(claim.verdict, 'likely');
    assert.match(claim.rationale, /proxy, gateway, or platform control/,
      'the ceiling is honest: absence cannot be proven by searching');
  });

  it('says the gap is project-wide rather than local to the file', () => {
    const app = write('app.js', EXPRESS_APP);
    assert.match(investigate('NO_RATE_LIMIT_LOGIN', [app]).claim.rationale, /not local to this file/);
  });
});

describe('when the rule is describing nothing', () => {
  it('refutes when the precondition is met nowhere', () => {
    const helper = write('util.js', ['export const shout = (s) => s.toUpperCase();']);
    const { claim } = investigate('MCP_SERVER_NO_AUTH', [helper]);

    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /precondition is not met/);
  });

  it('does not refute when the precondition is met and the control is not', () => {
    const server = write('server.js', [
      "import { McpServer } from '@modelcontextprotocol/sdk';",
      'const server = new McpServer({ name: "x" });',
      'server.tool("run", async () => ({}));',
    ]);
    assert.equal(investigate('MCP_SERVER_NO_AUTH', [server]).claim.verdict, 'likely');
  });
});

describe('absences that are local to a handler', () => {
  // Found by sweeping the pinned corpus: six API_NO_VALIDATION findings in
  // hermes-agent were being confirmed by the data-flow tracer because req.body
  // does reach the line -- with the guard clause sitting two lines below.
  const handler = (guard) => write('routes/send.js', [
    "import express from 'express';",
    'export const app = express();',
    "app.post('/send', (req, res) => {",
    '  const { chatId, message } = req.body;',
    ...guard,
    '  return res.json({ ok: true });',
    '});',
  ]);

  it('refutes when a guard clause follows the destructure', () => {
    const file = handler([
      '  if (!chatId || !message) {',
      "    return res.status(400).json({ error: 'required' });",
      '  }',
    ]);

    const { claim } = investigate('API_NO_VALIDATION', [file], { file, line: 4 });
    assert.equal(claim.verdict, 'refuted');

    // A multi-line `if (...) {` puts the condition and the 4xx response on
    // different lines; either is the guard, and neither is the destructure.
    assert.ok(claim.citations[0].line >= 5 && claim.citations[0].line <= 7,
      `cites the guard block, not the destructure (got line ${claim.citations[0].line})`);
  });

  it('raises to likely when the handler checks nothing', () => {
    const file = handler([]);
    assert.equal(investigate('API_NO_VALIDATION', [file], { file, line: 4 }).claim.verdict, 'likely');
  });

  it('does not accept a commented-out guard', () => {
    const file = handler(['  // if (!chatId) return res.status(400).end();']);
    assert.equal(investigate('API_NO_VALIDATION', [file], { file, line: 4 }).claim.verdict, 'likely');
  });

  it('does not reach past the window for a guard that guards something else', () => {
    const file = handler([
      ...Array.from({ length: 20 }, (_, i) => `  const filler${i} = ${i};`),
      '  if (!chatId) return res.status(400).end();',
    ]);
    assert.equal(investigate('API_NO_VALIDATION', [file], { file, line: 4 }).claim.verdict, 'likely');
  });

  it('does not refute a finding with the line the finding is on', () => {
    // AGENT_TOOL_CALL_REPLAY matched `tool_calls` on the very line whose
    // handling of tool_calls it objected to, refuting itself 30 times on
    // hermes-agent.
    const file = write('replay.js', [
      'export function record(history, result) {',
      '  history.push({ role: "tool", tool_calls: result.calls });',
      '  return history;',
      '}',
    ]);

    const { claim } = investigate('AGENT_TOOL_CALL_REPLAY_MISSING_ASSISTANT', [file], { file, line: 2 });
    assert.equal(claim.verdict, 'likely', 'the rule fired because of that line; it cannot also be the answer');
  });

  it('accepts a control on a later line', () => {
    const file = write('replay-ok.js', [
      'export function record(history, assistantMsg, result) {',
      '  history.push({ role: "tool", content: result.text });',
      '  history.push({ role: "assistant", tool_calls: assistantMsg.tool_calls });',
      '  return history;',
      '}',
    ]);

    assert.equal(investigate('AGENT_TOOL_CALL_REPLAY_MISSING_ASSISTANT', [file], { file, line: 2 }).claim.verdict, 'refuted');
  });

  it('is still not refuted by an unrelated module that sets the control', () => {
    // The property the earlier version of this rule got wrong: max_tokens is a
    // per-call argument, so one in a batch runner this file never calls says
    // nothing about it. Registered against the whole project it refuted
    // twenty-five findings against a single line.
    const caller = write('runner.py', [
      'def run(client):',
      '    return client.messages.create(model="x")',
    ]);
    const unrelated = write('batch.py', [
      'def batch(client):',
      '    return client.messages.create(model="x", max_tokens=100)',
    ]);

    const { claim } = investigate('AGENT_NO_COST_LIMIT', [caller, unrelated], { file: caller, line: 2 });
    assert.equal(claim.verdict, 'likely', 'a module this file never calls is not evidence about it');
  });

  it('refutes when a wrapper the file calls sets the control', () => {
    const caller = write('runner.py', [
      'from llm import complete',
      '',
      'def run(prompt):',
      '    return complete(prompt)',
      '',
      'def other(client):',
      '    return client.messages.create(model="x")',
    ]);
    const wrapper = write('llm.py', [
      'def complete(prompt):',
      '    return client.messages.create(model="x", prompt=prompt, max_tokens=512)',
    ]);

    const { claim } = investigate('AGENT_NO_COST_LIMIT', [caller, wrapper], { file: caller, line: 7 });
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /is set in complete, which this file calls/);
    assert.equal(claim.citations[0].line, 2, 'cites the line in the wrapper that sets it');
  });

  it('refutes when the control is in the file itself', () => {
    const file = write('direct.py', [
      'def run(client):',
      '    return client.messages.create(model="x", max_tokens=256)',
    ]);
    assert.equal(investigate('AGENT_NO_COST_LIMIT', [file], { file, line: 2 }).claim.verdict, 'refuted');
  });

  it('never refutes without pointing at the control it found', () => {
    // The first version re-derived the rule's own precondition with a narrower
    // pattern and refuted when the two disagreed. That is not evidence about
    // the control; it is this pass overruling the detector on the detector's
    // own question, and it refuted twenty-four findings with no citation at all.
    const file = write('plain.py', ['def add(a, b):', '    return a + b']);
    const { claim } = investigate('AGENT_NO_COST_LIMIT', [file], { file, line: 2 });

    assert.equal(claim.verdict, 'likely', 'finding nothing is not the same as finding it safe');
    assert.ok(claim.citations.length > 0 || claim.verdict !== 'refuted');
  });

  it('cites a real line on every refutation it makes', () => {
    const caller = write('runner.py', ['from llm import complete', '', 'def run(p):', '    return complete(p)']);
    const wrapper = write('llm.py', ['def complete(prompt):', '    return client.create(prompt=prompt, max_tokens=512)']);
    const direct = write('direct.py', ['def run(client):', '    return client.create(model="x", max_tokens=256)']);

    for (const file of [caller, direct]) {
      const { claim } = investigate('AGENT_NO_COST_LIMIT', [caller, wrapper, direct], { file, line: 2 });
      assert.equal(claim.verdict, 'refuted');
      assert.ok(claim.citations.length > 0, `${file} refuted with no citation`);
    }
  });

  it('follows a call for audit logging too', () => {
    const caller = write('dispatch.js', [
      "import { record } from './audit.js';",
      'export function dispatch(tool) {',
      '  record(tool);',
      '  return tool.run();',
      '}',
    ]);
    const wrapper = write('audit.js', [
      'export function record(tool) {',
      '  logger.info("tool dispatched", { tool });',
      '}',
    ]);

    const { claim } = investigate('AGENT_NO_AUDIT_LOG', [caller, wrapper], { file: caller, line: 3 });
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /which this file calls/);
  });

  it('stops at one hop rather than chasing a chain', () => {
    const caller = write('a.js', ["import { b } from './b.js';", 'export function run() { return b(); }']);
    const middle = write('b.js', ["import { c } from './c.js';", 'export function b() { return c(); }']);
    const deep = write('c.js', ['export function c() { return client.messages.create({ max_tokens: 10 }); }']);
    const app = write('app.js', ['export function go(client) { return client.messages.create({ model: "x" }); }']);

    const { claim } = investigate('AGENT_NO_COST_LIMIT', [caller, middle, deep, app], { file: app, line: 1 });
    assert.equal(claim.verdict, 'likely', 'app.js calls nothing that sets it; two hops away is out of reach');
    assert.match(claim.rationale, /further down the call chain than this pass follows/);
  });

  it('answers without a project file list, because the question is local', () => {
    const file = handler(['  if (!chatId) return res.status(400).end();']);
    assert.equal(investigate('API_NO_VALIDATION', [], { file, line: 4 }).claim.verdict, 'refuted');
  });
});

describe('staying in its lane', () => {
  it('says nothing about rules that are not absence-shaped', () => {
    const app = write('app.js', EXPRESS_APP);
    assert.equal(investigate('SQL_INJECTION_TEMPLATE_LITERAL', [app]).claim, null);
  });

  it('files nothing when given no file list', () => {
    write('app.js', EXPRESS_APP);
    assert.equal(investigate('API_NO_SECURITY_HEADERS', []).claim, null, 'the pass never crawls the disk');
  });

  it('declares which rules it owns, so the tracer can stand down', () => {
    assert.equal(isAbsenceRule('API_NO_SECURITY_HEADERS'), true);
    assert.equal(isAbsenceRule('NO_RATE_LIMIT_LOGIN'), true);
    assert.equal(isAbsenceRule('SQL_INJECTION_TEMPLATE_LITERAL'), false);
  });
});
