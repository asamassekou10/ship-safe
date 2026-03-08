/**
 * Auto-Fix Rules
 * ================
 *
 * Pure functions that transform a source line to fix a security issue.
 * Each rule maps to a finding rule name from the agents.
 *
 * Used by `ship-safe remediate --all` to auto-fix agent-detected issues
 * beyond just secrets.
 */

export const AUTOFIX_RULES = [
  {
    rule: 'TLS_REJECT_UNAUTHORIZED',
    match: /rejectUnauthorized\s*:\s*false/g,
    replace: (line) => line.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true // TODO: configure proper CA bundle'),
    description: 'Enable TLS certificate verification',
  },
  {
    rule: 'DOCKER_LATEST_TAG',
    match: /FROM\s+(\S+):latest/gi,
    replace: (line) => {
      return line.replace(/FROM\s+(\S+):latest/i, (_, image) => {
        const pinned = { node: 'node:20-alpine', python: 'python:3.12-slim', nginx: 'nginx:1.25-alpine', ruby: 'ruby:3.3-slim' };
        return `FROM ${pinned[image] || image + ':latest'} # TODO: pin to specific version`;
      });
    },
    description: 'Pin Docker base image to a specific version',
  },
  {
    rule: 'DEBUG_MODE_PRODUCTION',
    match: /(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|['"]true['"])/g,
    replace: (line) => line
      .replace(/DEBUG\s*=\s*True/, 'DEBUG = False')
      .replace(/DEBUG\s*=\s*true/, 'DEBUG = false')
      .replace(/debug\s*:\s*true/, 'debug: false')
      .replace(/debug\s*=\s*['"]true['"]/, "debug = 'false'"),
    description: 'Disable debug mode for production',
  },
  {
    rule: 'XSS_DANGEROUS_INNER_HTML',
    match: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/g, // ship-safe-ignore: autofix pattern
    replace: (line) => {
      return line.replace(
        /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/,
        (_, value) => `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(${value.trim()}) }}` // ship-safe-ignore: replacement template
      );
    },
    description: 'Wrap dangerouslySetInnerHTML value in DOMPurify.sanitize()',
  },
  {
    rule: 'CMD_INJECTION_SHELL_TRUE',
    match: /shell\s*:\s*true/g,
    replace: (line) => line.replace(/shell\s*:\s*true/, 'shell: false // TODO: ensure command works without shell'),
    description: 'Disable shell execution in spawn/exec',
  },
];

/**
 * Check if a finding's rule has an autofix available.
 */
export function hasAutofix(rule) {
  return AUTOFIX_RULES.some(r => r.rule === rule);
}

/**
 * Apply an autofix rule to a line.
 * Returns the fixed line, or the original if no rule matches.
 */
export function applyAutofix(rule, line) {
  const fixRule = AUTOFIX_RULES.find(r => r.rule === rule);
  if (!fixRule) return line;
  return fixRule.replace(line);
}
