import os from 'os';

/**
 * Keep structured reports shareable without leaking the checkout or home path.
 * Applies recursively because evidence and user-supplied configuration can
 * carry paths in nested strings as well as in `file` fields.
 */
export function redactLocalPaths(value, rootPath) {
  const replacements = [
    [rootPath, '.'],
    [process.env.HOME, '~'],
    [process.env.USERPROFILE, '~'],
    [os.homedir(), '~'],
  ]
    .filter(([prefix]) => typeof prefix === 'string' && prefix.length > 0)
    .flatMap(([prefix, replacement]) => [...new Set([
      prefix,
      prefix.replace(/\\/g, '/'),
      prefix.replace(/\//g, '\\'),
    ])].map((variant) => [variant, replacement]))
    .sort(([left], [right]) => right.length - left.length)
    .map(([prefix, replacement]) => {
      const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return [
        new RegExp(`${escaped}(?![A-Za-z0-9._-])`, process.platform === 'win32' ? 'gi' : 'g'),
        replacement,
      ];
    });

  const visit = (entry) => {
    if (typeof entry === 'string') {
      return replacements.reduce((result, [pattern, replacement]) => result.replace(pattern, replacement), entry);
    }
    if (Array.isArray(entry)) return entry.map(visit);
    if (entry && typeof entry === 'object') {
      return Object.fromEntries(Object.entries(entry).map(([key, nested]) => [visit(key), visit(nested)]));
    }
    return entry;
  };

  return visit(value);
}
