/**
 * Git config parsing
 * ==================
 *
 * A minimal reader for git's INI-with-subsections config format, written for
 * detection rather than for round-tripping. It exists because the values that
 * matter to WorkspaceTrustAgent are execution sinks, and reporting one means
 * pointing at the exact line a reviewer has to look at.
 *
 * What it deliberately does NOT do: resolve includes (`[include]` /
 * `[includeIf]`), merge system and global scopes, or expand `~`. A detector
 * that followed includes would start reporting on files outside the scanned
 * tree, and a detector that merged scopes could not tell the reader whether a
 * dangerous value arrived with the repository or was already on their machine.
 * That distinction is the entire point of the workspace-trust rules, so the
 * parser stays scoped to one file and the caller decides what that file means.
 *
 * USAGE:
 *   const entries = parseGitConfig(source);
 *   // → [{ section: 'core', subsection: null, key: 'fsmonitor',
 *   //      value: '.git/hooks/watch', line: 3, raw: 'fsmonitor = ...' }]
 */

/**
 * Booleans git accepts, lowercased. A key with no `=` is also true.
 *
 * This list is why `core.fsmonitor = true` must never be reported: it selects
 * git's own built-in FSMonitor daemon and runs no external program. Only a
 * value that is not a boolean names a command.
 */
const BOOLEAN_VALUES = new Set(['true', 'false', 'yes', 'no', 'on', 'off', '1', '0']);

/** Whether a git config value is one of git's boolean spellings. */
export function isBooleanValue(value) {
  if (value === null || value === undefined) return true; // bare key means true
  return BOOLEAN_VALUES.has(String(value).trim().toLowerCase());
}

/**
 * Strip an unquoted trailing comment.
 *
 * Git treats `#` and `;` as comment introducers outside quotes, so
 * `fsmonitor = ./watch # fast` has the value `./watch`. Doing this wrong in
 * either direction is a detection bug: keeping the comment inflates what we
 * quote back to the user, and stripping inside quotes truncates a real command.
 */
function splitValueAndComment(text) {
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\') { i++; continue; }
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    if (!inQuotes && (ch === '#' || ch === ';')) return text.slice(0, i);
  }
  return text;
}

/**
 * Remove surrounding quotes and resolve the escapes git recognises in values.
 */
function unquote(value) {
  const text = value.trim();
  if (!text) return '';

  let out = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\') {
      const next = text[i + 1];
      if (next === 'n') { out += '\n'; i++; continue; }
      if (next === 't') { out += '\t'; i++; continue; }
      if (next === '"' || next === '\\') { out += next; i++; continue; }
      continue;
    }
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    out += ch;
  }

  return inQuotes ? out : out.trim();
}

/**
 * Parse git config source into flat entries.
 *
 * Line numbers are 1-based and point at the line the key was written on, which
 * for a continued value is where it started. Section headers may carry a
 * subsection (`[filter "lfs"]`), and git treats section and key names as
 * case-insensitive while subsection names stay case-sensitive. Entries are
 * returned lowercased on section and key for that reason.
 *
 * @param {string} source raw contents of a git config file
 * @returns {Array<{section:string, subsection:string|null, key:string,
 *                  value:string|null, line:number, raw:string}>}
 */
export function parseGitConfig(source) {
  const entries = [];
  if (typeof source !== 'string' || !source) return entries;

  const lines = source.split(/\r?\n/);
  let section = null;
  let subsection = null;

  for (let i = 0; i < lines.length; i++) {
    let text = lines[i];

    // A value ending in a backslash continues on the next line. Consume the
    // continuation here so the entry keeps the line number it started on.
    const startLine = i + 1;
    while (/\\\s*$/.test(text) && i + 1 < lines.length) {
      text = text.replace(/\\\s*$/, '') + lines[i + 1];
      i++;
    }

    const trimmed = text.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

    const header = trimmed.match(/^\[([A-Za-z0-9._-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/);
    if (header) {
      section = header[1].toLowerCase();
      subsection = header[2] === undefined ? null : unquote(`"${header[2]}"`);
      continue;
    }

    if (section === null) continue;

    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      // Bare key. Git reads this as boolean true.
      const key = splitValueAndComment(trimmed).trim();
      if (!/^[A-Za-z0-9._-]+$/.test(key)) continue;
      entries.push({ section, subsection, key: key.toLowerCase(), value: null, line: startLine, raw: trimmed });
      continue;
    }

    const key = trimmed.slice(0, eq).trim();
    if (!/^[A-Za-z0-9._-]+$/.test(key)) continue;
    const value = unquote(splitValueAndComment(trimmed.slice(eq + 1)));

    entries.push({ section, subsection, key: key.toLowerCase(), value, line: startLine, raw: trimmed });
  }

  return entries;
}

/**
 * All entries matching a section and key, in file order.
 *
 * Git's last-one-wins semantics mean a later duplicate overrides an earlier
 * one, but a detector wants every occurrence: a config that sets a safe value
 * and then a dangerous one is exactly the shape worth reporting, and reporting
 * only the effective value would hide the first line a reviewer should read.
 */
export function findEntries(entries, section, key) {
  const wantSection = String(section).toLowerCase();
  const wantKey = String(key).toLowerCase();
  return entries.filter((e) => e.section === wantSection && e.key === wantKey);
}
