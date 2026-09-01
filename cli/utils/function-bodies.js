/**
 * Finding a named function and reading its body
 * ==============================================
 *
 * Some questions are only answerable one call away. "This file issues LLM
 * completions and sets no token ceiling" is true of most files that issue
 * completions, because the ceiling is set once in whatever wraps the provider
 * client and every call site inherits it by calling that wrapper.
 *
 * Answering those needs two things a line-based scan does not have: where a
 * name is defined, and where its body ends. Both are approximations here —
 * braces for C-like languages, indentation for Python — and both are wrong on
 * code that a parser would handle. That is the trade this file makes: it is
 * cheap, it has no dependencies, and it is used only to look for something,
 * never to conclude that a thing is absent from a body it may have measured
 * badly.
 */

import fs from 'fs';
import path from 'path';

const JS_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const PY_EXT = new Set(['.py', '.pyi']);

/** Definitions worth indexing: a name, and a line its body starts on. */
const JS_DEFINITION = [
  /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/,
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/,
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b/,
  /^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/,
];

const PY_DEFINITION = [/^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(/];

/** Keywords that look like definitions to the shorthand-method pattern. */
const NOT_A_NAME = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'with', 'do', 'else', 'return',
  'function', 'class', 'constructor', 'super', 'typeof', 'await', 'new',
]);

const MAX_INDEXED_FILES = 4000;
const MAX_BODY_LINES = 400;

/**
 * Build name → definitions across the given files.
 *
 * A name may be defined more than once in a project, and every definition is
 * kept. A caller searching for a control checks all of them and takes any hit:
 * looking in one too many bodies costs a false refutation only if the control
 * is genuinely there, in which case the code does have it somewhere.
 */
export function buildDefinitionIndex(files = []) {
  const index = new Map();

  for (const file of files.slice(0, MAX_INDEXED_FILES)) {
    const patterns = definitionPatterns(file);
    if (!patterns) continue;

    let lines;
    try { lines = fs.readFileSync(file, 'utf-8').split('\n'); } catch { continue; }

    lines.forEach((line, i) => {
      for (const pattern of patterns) {
        const match = line.match(pattern);
        if (!match || NOT_A_NAME.has(match[1])) continue;
        if (!index.has(match[1])) index.set(match[1], []);
        index.get(match[1]).push({ file, line: i + 1 });
        break;
      }
    });
  }

  return index;
}

function definitionPatterns(file) {
  const ext = path.extname(String(file)).toLowerCase();
  if (JS_EXT.has(ext)) return JS_DEFINITION;
  if (PY_EXT.has(ext)) return PY_DEFINITION;
  return null;
}

/**
 * The lines belonging to the definition starting at `startLine` (1-based).
 *
 * Braces for C-like languages, indentation for Python. Capped, because a body
 * this long is either generated or not a function, and either way reading all
 * of it to look for one call is not worth the pages.
 */
export function functionBody(lines, startLine, file) {
  const ext = path.extname(String(file)).toLowerCase();
  const limit = Math.min(lines.length, startLine - 1 + MAX_BODY_LINES);

  if (PY_EXT.has(ext)) {
    const indent = indentOf(lines[startLine - 1] || '');
    const body = [];
    for (let i = startLine; i < limit; i++) {
      const line = lines[i];
      if (line.trim() && indentOf(line) <= indent) break;
      body.push({ line: i + 1, text: line });
    }
    return body;
  }

  let depth = 0;
  let opened = false;
  const body = [];

  for (let i = startLine - 1; i < limit; i++) {
    const line = lines[i];
    for (const char of line) {
      if (char === '{') { depth += 1; opened = true; }
      else if (char === '}') depth -= 1;
    }
    if (i >= startLine - 1) body.push({ line: i + 1, text: line });
    if (opened && depth <= 0) break;
  }

  return body;
}

function indentOf(line) {
  const match = String(line).match(/^[ \t]*/);
  return match ? match[0].replace(/\t/g, '    ').length : 0;
}

/** Names this file calls, so a search can follow them one hop. */
export function calledNames(lines) {
  const names = new Set();

  for (const line of lines) {
    if (/^\s*(?:\/\/|#|\*)/.test(line)) continue;
    for (const match of line.matchAll(/(?:\b|\.)([A-Za-z_$][\w$]*)\s*\(/g)) {
      const name = match[1];
      if (NOT_A_NAME.has(name)) continue;

      // A definition is not a call to itself.
      const before = line.slice(0, match.index).trimEnd();
      if (/\b(?:function|class|def)$/.test(before)) continue;
      names.add(name);
    }
  }

  return [...names];
}
