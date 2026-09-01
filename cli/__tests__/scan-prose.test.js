/**
 * `scan` is the fast path and does not run the investigation layer, so nothing
 * downstream refutes a match on prose. A doc comment reading `eval(req.body.x)`
 * as an example was reported as a high-severity code vulnerability in this
 * project's own repository — by this project's own CI, which failed the release.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { isExecutionPattern, isAgentReadable } from '../commands/scan.js';

describe('which rules a comment can excuse', () => {
  it('excuses rules about code that executes', () => {
    for (const name of ['SQL_INJECTION_TEMPLATE_LITERAL', 'Code Injection: eval()', 'CMD_INJECTION_EXEC', 'XSS_INNERHTML', 'REDOS_NESTED_QUANTIFIER']) {
      assert.equal(isExecutionPattern({ name }), true, `${name} should be excusable`);
    }
  });

  it('never excuses a secret', () => {
    // A key written in a comment has leaked exactly as thoroughly as one
    // written in code.
    for (const name of ['AWS Secret Key', 'GITHUB_TOKEN', 'Hardcoded Password', 'Stripe API Key', 'PII_EMAIL_HARDCODED']) {
      assert.equal(isExecutionPattern({ name }), false, `${name} must still be reported`);
    }
  });

  it('does not excuse a rule that is about neither', () => {
    assert.equal(isExecutionPattern({ name: 'MISSING_LOCKFILE' }), false);
  });
});

describe('files where prose is the subject', () => {
  it('leaves documents alone, because an instruction in one is the finding', () => {
    for (const file of ['/repo/CLAUDE.md', '/repo/notes.txt', '/repo/.cursorrules', '/repo/docs/guide.mdx']) {
      assert.equal(isAgentReadable(file), true, `${file} is read as content`);
    }
  });

  it('treats source files as source', () => {
    for (const file of ['/repo/src/app.js', '/repo/main.py', '/repo/lib/x.ts']) {
      assert.equal(isAgentReadable(file), false);
    }
  });
});
