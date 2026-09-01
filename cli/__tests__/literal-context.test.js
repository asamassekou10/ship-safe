/**
 * LiteralContextInvestigator and the shared prose detection under it.
 *
 * These rules fire on a value written into the source, where the value is
 * exactly what the rule says and the finding is usually still noise. On
 * hermes-agent SSRF_INTERNAL_IP was the largest unresolved group at 96, and the
 * samples were a loopback default, a help string, and an "(e.g. ...)" prompt.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { LiteralContextInvestigator } from '../agents/literal-context-investigator.js';
import { commentMask, isHumanReadableString } from '../utils/source-context.js';
import { createFinding } from '../agents/base-agent.js';

let ROOT;
before(() => { ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-literal-')); });
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
beforeEach(() => {
  for (const entry of fs.readdirSync(ROOT)) fs.rmSync(path.join(ROOT, entry), { recursive: true, force: true });
});

const check = (name, lines, line, rule = 'SSRF_INTERNAL_IP') => {
  const file = path.join(ROOT, name);
  fs.writeFileSync(file, lines.join('\n'));
  const finding = createFinding({ file, line, rule, title: rule, category: 'vulnerability', severity: 'medium' });
  new LiteralContextInvestigator().investigate([finding], { rootPath: ROOT });
  return finding.evidence.claims.find((c) => c.source === 'presence') || null;
};

describe('addresses reserved for exactly this', () => {
  it('refutes loopback', () => {
    const claim = check('client.py', [
      'def build():',
      '    return Client(base_url="http://127.0.0.1:1234/v1")',
    ], 2);
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /loopback/);
  });

  it('refutes an RFC 5737 documentation address', () => {
    assert.equal(check('doc.js', ['const host = "203.0.113.10";'], 1).verdict, 'refuted');
  });

  it('refutes the unspecified bind address', () => {
    assert.equal(check('bind.py', ['HOST = "0.0.0.0"'], 1).verdict, 'refuted');
  });

  it('says nothing about a real private address in real code', () => {
    assert.equal(check('real.py', [
      'def fetch(session):',
      '    return session.get("http://10.4.2.7/admin")',
    ], 2), null, 'whether that is reachable is a question this pass cannot answer');
  });
});

describe('prose rather than code', () => {
  it('refutes an address inside a Python docstring', () => {
    const claim = check('ids.py', [
      'def normalize(jid):',
      '    """Convert an identifier.',
      '',
      '    Example: connect to http://192.168.1.10:1234',
      '    """',
      '    return jid',
    ], 4);
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /comment or docstring/);
  });

  it('refutes an address inside a JavaScript block comment', () => {
    const claim = check('note.js', [
      '/*',
      ' * Point this at 192.168.1.10 in development.',
      ' */',
      'export const x = 1;',
    ], 2);
    assert.equal(claim.verdict, 'refuted');
  });

  it('refutes an address in a help string', () => {
    const claim = check('config.py', [
      'OPTION = {',
      '    "description": "OpenViking server URL (default: http://192.168.1.9:1933)",',
      '}',
    ], 2);
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /written for a person/);
  });

  it('refutes an address in an example prompt', () => {
    const claim = check('prompt.py', [
      'FIELD = {"prompt": "BlueBubbles server URL (e.g. http://192.168.1.10:1234)"}',
    ], 1);
    assert.equal(claim.verdict, 'refuted');
  });
});

describe('emails', () => {
  it('refutes a reserved domain', () => {
    assert.equal(check('mail.js', ['const to = "someone@example.com";'], 1, 'PII_EMAIL_HARDCODED').verdict, 'refuted');
  });

  it('refutes a role address', () => {
    const claim = check('bot.py', ['AUTHORS = ["noreply@github.com"]'], 1, 'PII_EMAIL_HARDCODED');
    assert.equal(claim.verdict, 'refuted');
    assert.match(claim.rationale, /role address/);
  });

  it('refutes a platform identifier', () => {
    assert.equal(check('wa.py', ['JID = "50766715226@s.whatsapp.net"'], 1, 'PII_EMAIL_HARDCODED').verdict, 'refuted');
  });

  it('says nothing about what looks like a real person', () => {
    assert.equal(check('real.py', ['OWNER = "jane.doe@acme-industrial.co.uk"'], 1, 'PII_EMAIL_HARDCODED'), null);
  });
});

describe('scope', () => {
  it('leaves rules that are not about a written-in value alone', () => {
    assert.equal(check('x.js', ['const q = `SELECT ${id}`;'], 1, 'SQL_INJECTION_TEMPLATE_LITERAL'), null);
  });
});

describe('prose detection', () => {
  it('does not let a single-line docstring open a run to end of file', () => {
    const mask = commentMask(['"""One line."""', 'HOST = "10.0.0.1"'], { file: 'x.py' });
    assert.equal(mask[0], true);
    assert.equal(mask[1], false, 'the block closed on its own line');
  });

  it('marks the body of a multi-line docstring', () => {
    const mask = commentMask(['"""Start', 'middle', '"""', 'code = 1'], { file: 'x.py' });
    assert.deepEqual(mask, [true, true, true, false]);
  });

  it('does not mark code that precedes a block opener', () => {
    const mask = commentMask(['const a = 1; /* note', 'inside', '*/'], { file: 'x.js' });
    assert.equal(mask[0], false, 'the statement runs');
    assert.equal(mask[1], true);
  });

  it('recognises a message meant for a person', () => {
    assert.equal(isHumanReadableString('  "help": "set to http://10.0.0.1"'), true);
    assert.equal(isHumanReadableString('  url = "http://10.0.0.1"'), false);
  });
});
