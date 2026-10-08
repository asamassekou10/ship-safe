import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import fg from '../utils/glob.js';

async function makeFixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ship-safe-glob-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'src'), { recursive: true });
  await fs.mkdir(path.join(root, 'node_modules', 'sample'), { recursive: true });
  await fs.writeFile(path.join(root, 'src', 'app.js'), 'export {}');
  await fs.writeFile(path.join(root, 'src', 'types.ts'), 'export {}');
  await fs.writeFile(path.join(root, 'src', '.hidden.js'), 'export {}');
  await fs.writeFile(path.join(root, 'node_modules', 'sample', 'index.js'), 'export {}');
  return root;
}

test('glob wrapper preserves common fast-glob matching and ignore behavior', async (t) => {
  const root = await makeFixture(t);
  const files = await fg('src/**/*.{js,ts}', {
    cwd: root,
    absolute: true,
    onlyFiles: true,
    dot: true,
    ignore: ['**/*.ts'],
  });

  assert.deepEqual(files.sort(), [
    path.join(root, 'src', '.hidden.js'),
    path.join(root, 'src', 'app.js'),
  ].sort());

  assert.deepEqual(fg.sync('src/**/*.js', { cwd: root }), ['src/app.js']);
  const directoryMatch = fg.sync('src', { cwd: root, onlyFiles: false });
  assert.equal(directoryMatch.length, 1);
  assert.match(directoryMatch[0], /^src\/?$/);
});

test('glob wrapper rejects excessive brace nesting before matching', async (t) => {
  const root = await makeFixture(t);
  const nestedPattern = `${'{'.repeat(101)}a,b${'}'.repeat(101)}`;

  assert.throws(
    () => fg.sync(nestedPattern, { cwd: root }),
    /safe brace-nesting limit/,
  );
  await assert.rejects(
    fg(nestedPattern, { cwd: root }),
    /safe brace-nesting limit/,
  );
  assert.throws(
    () => fg.sync('**/*', { cwd: root, ignore: [nestedPattern] }),
    /safe brace-nesting limit/,
  );
});
