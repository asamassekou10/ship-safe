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

  it('leaves a rule alone when a project-wide search would contradict its own claim', () => {
    // AGENT_NO_COST_LIMIT says the file sets no ceiling anywhere in it.
    // max_tokens is a per-call argument, so one in another module refutes
    // nothing -- and registering it refuted 25 findings against a single line.
    const caller = write('runner.py', ['def run(client):', '    return client.messages.create(model="x")']);
    const other = write('batch.py', ['def batch(client):', '    return client.messages.create(model="x", max_tokens=100)']);

    assert.equal(investigate('AGENT_NO_COST_LIMIT', [caller, other], { file: caller, line: 2 }).claim, null);
    assert.equal(isAbsenceRule('AGENT_NO_COST_LIMIT'), false);
    assert.equal(isAbsenceRule('AGENT_NO_AUDIT_LOG'), false);
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
