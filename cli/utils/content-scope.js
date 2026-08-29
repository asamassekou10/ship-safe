/**
 * Content scope helpers
 * =====================
 *
 * Markdown is both documentation and a container for code examples. Treating
 * every token in it as deployed source makes ordinary security guidance look
 * like a vulnerability. These helpers keep the distinction explicit while
 * preserving line numbers for an opt-in example scan.
 */

import path from 'path';

const MARKDOWN_EXTENSIONS = new Set([
  '.md', '.markdown', '.mdown', '.mkdn', '.mkd', '.mdx', '.mdc',
  '.rst', '.adoc', '.asciidoc', '.rdoc',
]);

/** Whether a path is a documentation format with fenced code blocks. */
export function isDocumentationFile(filePath) {
  return MARKDOWN_EXTENSIONS.has(path.extname(String(filePath || '')).toLowerCase());
}

/**
 * Return the zero-based line indexes contained by CommonMark-style fenced
 * code blocks. Opening and closing fence lines are not code lines.
 *
 * This intentionally implements the fence rules rather than looking for a
 * bare ``` substring: a fence may be indented by up to three spaces, may use
 * tildes, and a closing fence must use the same marker and be at least as long
 * as the opener. An unclosed fence runs to EOF, as CommonMark specifies.
 */
export function markdownCodeLines(source) {
  const lines = String(source || '').split('\n');
  const codeLines = new Set();
  let fence = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].replace(/\r$/, '');

    if (!fence) {
      const opening = line.match(/^( {0,3})(`{3,}|~{3,})(.*)$/);
      if (!opening) continue;

      const marker = opening[2][0];
      const info = opening[3];
      // Backtick info strings cannot contain another backtick. Without this
      // guard, inline code such as ```` ``` ```` becomes a false fence.
      if (marker === '`' && info.includes('`')) continue;

      fence = { marker, length: opening[2].length };
      continue;
    }

    const closing = line.match(/^( {0,3})(`{3,}|~{3,})[ \t]*$/);
    if (closing && closing[2][0] === fence.marker && closing[2].length >= fence.length) {
      fence = null;
      continue;
    }

    codeLines.add(index);
  }

  return codeLines;
}

