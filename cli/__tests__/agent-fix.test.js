/**
 * Ship Safe — agent-fix internals
 * ================================
 *
 * Tests the v9.2.0 fix-first agent: JSON parsing of LLM responses,
 * plan validation, find-string drift recovery, file windowing, and
 * undo replay (round-trip apply → reverse).
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import {
  parseJsonLoose,
  validatePlan,
  locateFindString,
  countOccurrences,
  windowFileContent,
  verifyFile,
} from '../commands/agent-fix.js';
import { reverseEntry } from '../commands/undo.js';
import { findUpwards } from '../commands/audit.js';
import { spawnSync } from 'node:child_process';

describe('verification boundaries', () => {
  const target = { file: 'a.js', line: 1, rule: 'DEMO', evidence: { verdict: 'confirmed' } };

  it('retains cross-file regressions instead of filtering them to the target file', async () => {
    const result = await verifyFile('/fixture', 'a.js', [target], {
      audit: async () => ({ findings: [
        { ...target, evidence: { verdict: 'refuted' } },
        { ...target, file: 'b.js' },
      ] }),
    });
    assert.equal(result.allResolved, false);
    assert.equal(result.verification.introduced[0].file, 'b.js');
    assert.equal(result.verification.scope.kind, 'repository');
  });

  it('does not interpret an incomplete rescan as detector disappearance', async () => {
    const result = await verifyFile('/fixture', 'a.js', [target], { audit: async () => ({}) });
    assert.equal(result.allResolved, false);
    assert.equal(result.verification, null);
  });

  it('rejects an unavailable sandbox before provider lookup or workspace access', () => {
    const result = spawnSync(process.execPath, [
      path.resolve('cli/bin/ship-safe.js'), 'agent', '/nonexistent/ship-safe-fixture',
      '--sandbox', '--branch', '--allow-dirty',
    ], { encoding: 'utf8', timeout: 15000 });
    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /sandbox is unsupported/);
    assert.doesNotMatch(result.stdout + result.stderr, /falling back|No LLM provider|Path does not exist/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function tempDir(prefix = 'ship-safe-agentfix-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// parseJsonLoose
// ─────────────────────────────────────────────────────────────────────────────

describe('parseJsonLoose', () => {
  it('parses raw JSON', () => {
    const r = parseJsonLoose('{"files":[{"path":"a.js"}]}');
    assert.deepEqual(r, { files: [{ path: 'a.js' }] });
  });

  it('strips ```json fences', () => {
    const r = parseJsonLoose('```json\n{"a":1}\n```');
    assert.deepEqual(r, { a: 1 });
  });

  it('strips bare ``` fences without language tag', () => {
    const r = parseJsonLoose('```\n{"b":2}\n```');
    assert.deepEqual(r, { b: 2 });
  });

  it('falls back to brace-extraction when surrounded by prose', () => {
    const r = parseJsonLoose('Here is the plan: {"x":42} as requested.');
    assert.deepEqual(r, { x: 42 });
  });

  it('returns null for truly malformed input', () => {
    assert.equal(parseJsonLoose('not json at all'), null);
  });

  it('returns null for empty input', () => {
    assert.equal(parseJsonLoose(''), null);
    assert.equal(parseJsonLoose(null), null);
    assert.equal(parseJsonLoose(undefined), null);
  });

  it('handles JSON inside trailing whitespace + fences', () => {
    const r = parseJsonLoose('   ```json\n  {"k":"v"}  \n```\n   ');
    assert.deepEqual(r, { k: 'v' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// countOccurrences + locateFindString (find-string drift recovery)
// ─────────────────────────────────────────────────────────────────────────────

describe('countOccurrences', () => {
  it('counts non-overlapping occurrences', () => {
    assert.equal(countOccurrences('abcabcabc', 'abc'), 3);
  });

  it('returns 0 for empty needle', () => {
    assert.equal(countOccurrences('any haystack', ''), 0);
  });

  it('returns 0 when needle absent', () => {
    assert.equal(countOccurrences('hello world', 'xyz'), 0);
  });
});

describe('locateFindString', () => {
  it('finds unique exact match', () => {
    const r = locateFindString('foo bar baz', 'bar');
    assert.equal(r.kind, 'unique');
    assert.equal(r.matched, 'bar');
    assert.equal(r.count, 1);
  });

  it('reports ambiguous when needle appears more than once', () => {
    const r = locateFindString('cat cat cat', 'cat');
    assert.equal(r.kind, 'ambiguous');
    assert.equal(r.count, 3);
  });

  it('reports missing when needle absent', () => {
    const r = locateFindString('hello world', 'xyz');
    assert.equal(r.kind, 'missing');
    assert.equal(r.matched, null);
  });

  it('whitespace-tolerant fallback recovers a unique multi-line match', () => {
    const haystack = `function foo() {
    const x = 1;
    return x;
}`;
    // Same code with normalized indentation/newlines (drifted whitespace)
    const needle = `const x = 1;
return x;`;
    const r = locateFindString(haystack, needle);
    assert.equal(r.kind, 'unique', `expected unique, got: ${JSON.stringify(r)}`);
    assert.match(r.matched, /const x = 1;/);
    assert.match(r.matched, /return x;/);
  });

  it('whitespace fallback works on single-line drift too', () => {
    // The fallback collapses whitespace runs and re-tries — it does this even
    // for single-line needles, which is documented behavior here.
    const r = locateFindString('foo  bar', 'foo bar');
    assert.equal(r.kind, 'unique');
    assert.equal(r.matched, 'foo  bar');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// windowFileContent
// ─────────────────────────────────────────────────────────────────────────────

describe('windowFileContent', () => {
  it('returns small content unchanged', () => {
    const small = 'line1\nline2\nline3';
    assert.equal(windowFileContent(small, 2), small);
  });

  it('windows around target line for large files (>8000 chars)', () => {
    // Need >8000 chars to trip the windowing branch
    const lines = Array.from({ length: 1500 }, (_, i) => `line ${i + 1} padding-padding-padding`);
    const content = lines.join('\n');
    assert.ok(content.length > 8000, 'precondition: content exceeds threshold');
    const windowed = windowFileContent(content, 750);
    assert.ok(windowed.length < content.length);
    assert.match(windowed, /line 750/);
    // Should include +/- ~40 lines around target
    assert.match(windowed, /line 720/);
    assert.match(windowed, /line 780/);
    // Should NOT include lines far outside the window
    assert.equal(/line 100\b/.test(windowed), false);
  });

  it('returns prefix slice when no line provided on a large file', () => {
    const huge = 'x'.repeat(10000);
    const w = windowFileContent(huge, null);
    assert.equal(w.length, 8000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// validatePlan
// ─────────────────────────────────────────────────────────────────────────────

describe('validatePlan', () => {
  it('rejects plan with no files array', () => {
    const dir = tempDir();
    try {
      const r = validatePlan(dir, {});
      assert.equal(r.ok, false);
      assert.match(r.reason, /no files in plan/);
    } finally { cleanup(dir); }
  });

  it('rejects plan with empty files array', () => {
    const dir = tempDir();
    try {
      const r = validatePlan(dir, { files: [] });
      assert.equal(r.ok, false);
      assert.match(r.reason, /no files in plan/);
    } finally { cleanup(dir); }
  });

  it('rejects file entry missing path', () => {
    const dir = tempDir();
    try {
      const r = validatePlan(dir, { files: [{ edits: [] }] });
      assert.equal(r.ok, false);
      assert.match(r.reason, /missing path/);
    } finally { cleanup(dir); }
  });

  it('rejects edits on protected paths (.env, lockfiles, node_modules)', () => {
    const dir = tempDir();
    try {
      // .env is in NEVER_EDIT
      const r1 = validatePlan(dir, {
        files: [{ path: '.env', edits: [{ find: 'a', replace: 'b' }] }],
      });
      assert.equal(r1.ok, false);
      assert.match(r1.reason, /protected path/);

      // package-lock.json is in NEVER_EDIT
      const r2 = validatePlan(dir, {
        files: [{ path: 'package-lock.json', edits: [{ find: 'a', replace: 'b' }] }],
      });
      assert.equal(r2.ok, false);
      assert.match(r2.reason, /protected path/);

      // node_modules/ paths are in NEVER_EDIT
      const r3 = validatePlan(dir, {
        files: [{ path: 'node_modules/foo/index.js', edits: [{ find: 'a', replace: 'b' }] }],
      });
      assert.equal(r3.ok, false);
      assert.match(r3.reason, /protected path/);
    } finally { cleanup(dir); }
  });

  it('rejects creation of unsafe new files', () => {
    const dir = tempDir();
    try {
      const r = validatePlan(dir, {
        files: [{ path: 'random/new-thing.txt', create: true, content: 'hi' }],
      });
      assert.equal(r.ok, false);
      assert.match(r.reason, /cannot create new file/);
    } finally { cleanup(dir); }
  });

  it('allows .env.example creation (known-safe companion)', () => {
    const dir = tempDir();
    try {
      const r = validatePlan(dir, {
        files: [{ path: '.env.example', create: true, content: 'KEY=' }],
      });
      assert.equal(r.ok, true);
    } finally { cleanup(dir); }
  });

  it('rejects no-op edit (find === replace)', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'a.js');
      fs.writeFileSync(file, 'const x = 1;');
      const r = validatePlan(dir, {
        files: [{ path: 'a.js', edits: [{ find: 'const x', replace: 'const x' }] }],
      });
      assert.equal(r.ok, false);
      assert.match(r.reason, /no-op/);
    } finally { cleanup(dir); }
  });

  it('rejects when find string is missing in target file', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'a.js');
      fs.writeFileSync(file, 'const x = 1;');
      const r = validatePlan(dir, {
        files: [{ path: 'a.js', edits: [{ find: 'nonexistent', replace: 'foo' }] }],
      });
      assert.equal(r.ok, false);
      assert.match(r.reason, /find string not present/);
    } finally { cleanup(dir); }
  });

  it('rejects when find string is ambiguous (multiple matches)', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'a.js');
      fs.writeFileSync(file, 'cat\ncat\ncat\n');
      const r = validatePlan(dir, {
        files: [{ path: 'a.js', edits: [{ find: 'cat', replace: 'dog' }] }],
      });
      assert.equal(r.ok, false);
      assert.match(r.reason, /ambiguous/);
    } finally { cleanup(dir); }
  });

  it('accepts a valid edit and annotates it with _resolvedFind', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'a.js');
      fs.writeFileSync(file, 'const apiKey = "sk_live_123";\n');
      const plan = {
        files: [{
          path: 'a.js',
          edits: [{ find: 'sk_live_123', replace: 'process.env.STRIPE_KEY' }],
        }],
      };
      const r = validatePlan(dir, plan);
      assert.equal(r.ok, true);
      assert.equal(plan.files[0].edits[0]._resolvedFind, 'sk_live_123');
    } finally { cleanup(dir); }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// reverseEntry — undo replay round-trip
// ─────────────────────────────────────────────────────────────────────────────

describe('reverseEntry (undo round-trip)', () => {
  it('reverses a standard find/replace edit', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'src.js');
      const original = 'const stripe = new Stripe("sk_live_xxx");\n';
      const fixed    = 'const stripe = new Stripe(process.env.STRIPE_KEY);\n';
      fs.writeFileSync(file, fixed);

      reverseEntry(dir, {
        plan: {
          files: [{
            path: 'src.js',
            edits: [{
              find: 'sk_live_xxx',
              replace: 'process.env.STRIPE_KEY',
              _resolvedFind: '"sk_live_xxx"',
            }],
          }],
        },
      });
      // The reverse swaps `process.env.STRIPE_KEY` back into `"sk_live_xxx"` (using _resolvedFind)
      const after = fs.readFileSync(file, 'utf8');
      assert.match(after, /sk_live_xxx/);
      assert.equal(after.includes('process.env.STRIPE_KEY'), false);
      // We don't require byte-exact equality with `original` because _resolvedFind may differ slightly
      assert.equal(after, original);
    } finally { cleanup(dir); }
  });

  it('deletes a file that was created (companion change)', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, '.env.example');
      fs.writeFileSync(file, 'STRIPE_KEY=\n');
      reverseEntry(dir, {
        plan: { files: [{ path: '.env.example', create: true, content: 'STRIPE_KEY=\n' }] },
      });
      assert.equal(fs.existsSync(file), false);
    } finally { cleanup(dir); }
  });

  it('strips appended content (companion append to .gitignore)', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, '.gitignore');
      const before = 'node_modules/\n.next/\n';
      const appended = '.env\n';
      fs.writeFileSync(file, before + appended);

      reverseEntry(dir, {
        plan: { files: [{ path: '.gitignore', append: appended }] },
      });
      const after = fs.readFileSync(file, 'utf8');
      assert.equal(after, before);
    } finally { cleanup(dir); }
  });

  it('reverses multiple edits in opposite order', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'mod.js');
      // Two replacements: a → A, b → B
      const fixed = 'A and B';
      fs.writeFileSync(file, fixed);

      reverseEntry(dir, {
        plan: {
          files: [{
            path: 'mod.js',
            edits: [
              // _resolvedFind matches what `find` resolved to during the original
              // forward apply (i.e. the lowercase original)
              { find: 'a', replace: 'A', _resolvedFind: 'a' },
              { find: 'b', replace: 'B', _resolvedFind: 'b' },
            ],
          }],
        },
      });
      const after = fs.readFileSync(file, 'utf8');
      assert.equal(after, 'a and b');
    } finally { cleanup(dir); }
  });

  it('throws when entry has no plan', () => {
    const dir = tempDir();
    try {
      assert.throws(() => reverseEntry(dir, {}), /no plan/);
      assert.throws(() => reverseEntry(dir, { plan: { files: [] } }), /no plan/);
    } finally { cleanup(dir); }
  });

  it('throws when reverted text not found (file changed since fix)', () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'src.js');
      // Hand-edited away from the post-fix state
      fs.writeFileSync(file, 'something completely different');
      assert.throws(
        () => reverseEntry(dir, {
          plan: { files: [{ path: 'src.js', edits: [{ find: 'a', replace: 'b', _resolvedFind: 'a' }] }] },
        }),
        /reverted text not found/,
      );
    } finally { cleanup(dir); }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// findUpwards — .ship-safeignore walk-up from subdirectory scans
// ─────────────────────────────────────────────────────────────────────────────

describe('findUpwards (.ship-safeignore walk-up)', () => {
  it('finds file in starting directory', () => {
    const dir = tempDir();
    try {
      const target = path.join(dir, '.ship-safeignore');
      fs.writeFileSync(target, '*.log\n');
      const found = findUpwards(dir, '.ship-safeignore');
      assert.equal(found, target);
    } finally { cleanup(dir); }
  });

  it('walks up to find file in parent directory', () => {
    const dir = tempDir();
    try {
      const sub = path.join(dir, 'sub', 'deep');
      fs.mkdirSync(sub, { recursive: true });
      const target = path.join(dir, '.ship-safeignore');
      fs.writeFileSync(target, '*.log\n');
      const found = findUpwards(sub, '.ship-safeignore');
      assert.equal(found, target);
    } finally { cleanup(dir); }
  });

  it('returns null when file does not exist in any ancestor', () => {
    const dir = tempDir();
    try {
      const sub = path.join(dir, 'a', 'b');
      fs.mkdirSync(sub, { recursive: true });
      const found = findUpwards(sub, 'absolutely-does-not-exist.txt');
      assert.equal(found, null);
    } finally { cleanup(dir); }
  });

  it('caps walk depth at 8 levels (does not recurse forever)', () => {
    // A starting path that would exceed 8 levels above tempDir before reaching a
    // fictional .ship-safeignore — we just verify the function returns null cleanly,
    // not that it explodes or hangs.
    const dir = tempDir();
    try {
      let p = dir;
      for (let i = 0; i < 12; i++) {
        p = path.join(p, `lvl${i}`);
        fs.mkdirSync(p, { recursive: true });
      }
      const found = findUpwards(p, '.ship-safeignore');
      assert.equal(found, null);
    } finally { cleanup(dir); }
  });
});
