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
