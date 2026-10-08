import { glob, globSync } from 'tinyglobby';

const MAX_BRACE_NESTING = 100;

function assertSafePatterns(patterns, ignorePatterns = []) {
  const candidates = [
    ...(Array.isArray(patterns) ? patterns : [patterns]),
    ...(Array.isArray(ignorePatterns) ? ignorePatterns : [ignorePatterns]),
  ];

  for (const pattern of candidates) {
    if (typeof pattern !== 'string') continue;

    let depth = 0;
    let inCharacterClass = false;
    let escaped = false;

    for (const character of pattern) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\') {
        escaped = true;
        continue;
      }
      if (inCharacterClass) {
        if (character === ']') inCharacterClass = false;
        continue;
      }
      if (character === '[') {
        inCharacterClass = true;
      } else if (character === '{') {
        depth += 1;
        if (depth > MAX_BRACE_NESTING) {
          throw new Error(`Glob pattern exceeds the safe brace-nesting limit (${MAX_BRACE_NESTING})`);
        }
      } else if (character === '}' && depth > 0) {
        depth -= 1;
      }
    }
  }
}

/**
 * Keep the fast-glob call shape while using the maintained, smaller matcher.
 * fast-glob does not expand directory arguments automatically, so preserve
 * that behavior explicitly when callers pass a directory-like pattern.
 */
async function fg(patterns, options = {}) {
  assertSafePatterns(patterns, options.ignore);
  return glob(patterns, { expandDirectories: false, ...options });
}

fg.sync = (patterns, options = {}) => {
  assertSafePatterns(patterns, options.ignore);
  return globSync(patterns, { expandDirectories: false, ...options });
};

export default fg;
