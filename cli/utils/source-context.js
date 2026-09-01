/**
 * Source context — which lines are prose rather than code
 * ========================================================
 *
 * Several passes need the same distinction and get it wrong in the same way. A
 * `throw` inside a commented-out block is not control flow. An IP address in a
 * docstring is not a request target. An email in an RST example is not somebody's
 * personal data. Each of those was a real wrong conclusion before this existed,
 * and each was reached by a line-prefix test that cannot see a block it is in
 * the middle of.
 *
 * Prefixes are not enough because the lines that matter carry no marker: a
 * commented-out fix inside a block comment looks exactly like code, and the
 * body of a Python docstring looks exactly like text.
 */

/** Languages differ in how they open prose, not in that they do. */
const BLOCK_FORMS = {
  js: { line: [/^\s*\/\//], blocks: [{ open: '/*', close: '*/' }] },
  py: {
    line: [/^\s*#/],
    // Triple quotes are strings, not comments, but a module- or function-level
    // one is documentation in every way that matters here.
    blocks: [{ open: '"""', close: '"""' }, { open: "'''", close: "'''" }],
  },
};

const BY_EXT = {
  '.js': 'js', '.jsx': 'js', '.mjs': 'js', '.cjs': 'js',
  '.ts': 'js', '.tsx': 'js', '.mts': 'js', '.cts': 'js',
  '.py': 'py', '.pyi': 'py',
};

/** Which dialect of prose a file uses, defaulting to the C-like one. */
export function dialectFor(file = '') {
  const match = String(file).toLowerCase().match(/\.[a-z]+$/);
  return BLOCK_FORMS[BY_EXT[match?.[0]] || 'js'];
}

/**
 * A boolean per line: is this line inside a comment or a docstring?
 *
 * Scanning stops at `upto` because callers only ever ask about a region, and a
 * file whose first ten lines are a licence header should not cost a full read
 * to answer a question about line eleven.
 *
 * A quote inside a string literal can open a phantom block. That error marks
 * more lines as prose, which makes every caller abstain rather than conclude —
 * the safe direction for all of them.
 */
export function commentMask(lines, { upto = lines.length, file = null, dialect = null } = {}) {
  const forms = dialect || dialectFor(file);
  const limit = Math.min(upto, lines.length);
  const mask = new Array(limit).fill(false);

  let open = null;

  for (let i = 0; i < limit; i++) {
    const line = lines[i] || '';
    const trimmed = line.trim();

    if (open) {
      mask[i] = true;
      if (line.includes(open.close)) open = null;
      continue;
    }

    if (forms.line.some((pattern) => pattern.test(line))) { mask[i] = true; continue; }

    for (const block of forms.blocks) {
      const at = line.indexOf(block.open);
      if (at === -1) continue;

      // A block that closes on its own line encloses nothing further. Look past
      // the opener so `""" one line """` does not open a run to end of file.
      const rest = line.slice(at + block.open.length);
      if (rest.includes(block.close)) {
        mask[i] = trimmed.startsWith(block.open);
        break;
      }

      open = block;
      // The opening line is prose only when nothing precedes the marker.
      mask[i] = line.slice(0, at).trim() === '';
      break;
    }
  }

  return mask;
}

/**
 * Is this line a human-readable message rather than an instruction?
 *
 * A help string, a prompt, or an example is documentation that happens to live
 * in a string literal. The address inside `"OpenViking server URL (default:
 * http://127.0.0.1:1933)"` is being described, not contacted.
 */
export function isHumanReadableString(line) {
  const text = String(line);

  // A value under a key whose whole purpose is to be read by a person.
  if (/["'`]?\b(?:description|help|hint|prompt|label|placeholder|example|usage|title|message|doc|summary|tooltip)\b["'`]?\s*[:=]/i.test(text)) {
    return true;
  }

  // Prose markers inside the string itself.
  return /\((?:e\.?g\.?|default|example|for example)[:.]?\s/i.test(text)
    || /\b(?:e\.?g\.?|for example|such as)\b[^\n]{0,40}["'`]?https?:\/\//i.test(text);
}
