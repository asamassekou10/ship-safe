/** Offline checks for A2A discovery cards, push callbacks, and card consumers. */
import path from 'node:path';
import { BaseAgent, createFinding, isInsideJavaScriptNonCode } from './base-agent.js';
import { hasHiddenAgentInstruction } from '../utils/agent-instructions.js';
import { agentCardSignatureState } from '../utils/a2a-signatures.js';
import { isLoopbackDestination, isUnsafeCallbackDestination } from '../utils/ssrf-destinations.js';
import { commentMask } from '../utils/source-context.js';

const CARD_PATH = /(?:^|[/\\])\.well-known[/\\]agent(?:-card)?\.json$/;
const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);
const PUSH_KEYS = new Set(['pushNotificationConfig', 'taskPushNotificationConfig', 'push_notification_config', 'task_push_notification_config']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const urlOf = value => { try { return typeof value === 'string' ? new URL(value) : null; } catch { return null; } };

// Record the actual JSON value offsets, including repeated values in skills.
// JSON.parse validates the document before this small location-only traversal.
function jsonLocations(source) {
  const tokens = [...source.matchAll(/"(?:\\.|[^"\\])*"|[{}[\]:,]|[^\s{}[\]:,]+/g)];
  const locations = new Map();
  let cursor = 0;
  function walk(parts) {
    if (parts.length > 128) throw new Error('JSON nesting limit');
    const token = tokens[cursor++];
    locations.set(JSON.stringify(parts), token.index);
    if (token[0] === '{') {
      while (tokens[cursor][0] !== '}') {
        const key = JSON.parse(tokens[cursor++][0]);
        cursor++; // colon
        walk([...parts, key]);
        if (tokens[cursor][0] === ',') cursor++;
      }
      cursor++;
    } else if (token[0] === '[') {
      let index = 0;
      while (tokens[cursor][0] !== ']') {
        walk([...parts, index++]);
        if (tokens[cursor][0] === ',') cursor++;
      }
      cursor++;
    }
  }
  walk([]);
  return locations;
}

function hasAuthentication(card) {
  const schemes = card.securitySchemes;
  const validScheme = scheme => object(scheme) && (
    ['http', 'apiKey', 'oauth2', 'openIdConnect', 'mutualTLS'].includes(scheme.type)
      && !(scheme.type === 'http' && (typeof scheme.scheme !== 'string' || !scheme.scheme.trim() || scheme.scheme.toLowerCase() === 'none'))
    || ['httpAuthSecurityScheme', 'apiKeySecurityScheme', 'oauth2SecurityScheme', 'openIdConnectSecurityScheme', 'mtlsSecurityScheme']
      .some(key => object(scheme[key]) && (key === 'mtlsSecurityScheme' || Object.keys(scheme[key]).length > 0)
        && (key !== 'httpAuthSecurityScheme' || (typeof scheme[key].scheme === 'string' && scheme[key].scheme.trim() && scheme[key].scheme.toLowerCase() !== 'none')))
  );
  const declared = object(schemes) && Object.values(schemes).some(validScheme);
  if (!declared) {
    // Early A2A cards used authentication.schemes instead of securitySchemes.
    return !Object.hasOwn(card, 'securitySchemes') && Array.isArray(card.authentication?.schemes)
      && card.authentication.schemes.some(scheme => typeof scheme === 'string' && scheme.trim() && scheme.toLowerCase() !== 'none');
  }
  // An explicit empty alternative permits anonymous access. If requirements
  // are absent, report only the declaration, not whether a server enforces it.
  const requirements = card.securityRequirements ?? card.security;
  if (requirements === undefined) return true;
  return Array.isArray(requirements) && requirements.length > 0 && requirements.every(requirement => {
    const entries = requirement?.schemes ?? requirement;
    return object(entries) && Object.keys(entries).length > 0
      && Object.keys(entries).every(name => Object.hasOwn(schemes, name) && validScheme(schemes[name]));
  });
}

// Bound one call, respecting strings/comments and nested options. A pin on a
// different fetch must not suppress this fetch's absence finding.
function callEnd(source, start) {
  let depth = 0;
  let quote = null;
  for (let i = start; i < Math.min(source.length, start + 8192); i++) {
    const c = source[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
    } else if ('\'"`'.includes(c)) quote = c;
    else if (source.startsWith('//', i) || c === '#') {
      const end = source.indexOf('\n', i);
      if (end === -1) return -1;
      i = end;
    } else if (source.startsWith('/*', i)) {
      const end = source.indexOf('*/', i + 2);
      if (end === -1) return -1;
      i = end + 1;
    } else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return i + 1;
  }
  return -1;
}


function sourceTokens(source) {
  return (source.match(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|[A-Za-z_$][\w$]*|\.\.\.|[^\s]/g) || [])
    .filter(token => !token.startsWith('//') && !token.startsWith('/*') && !token.startsWith('#'));
}

// Read direct properties without confusing nested objects with their parent.
// Unknown keys and spreads can overwrite a property, so they remain unproven.
function literalObject(tokens, start) {
  if (tokens[start] !== '{') return null;
  const properties = new Map();
  const closers = { '{': '}', '[': ']', '(': ')' };
  let cursor = start + 1;
  while (cursor < tokens.length) {
    if (tokens[cursor] === '}') return { properties, end: cursor };
    const key = tokens[cursor];
    if (!/^(?:[A-Za-z_$][\w$]*|"[^"\\]*"|'[^'\\]*')$/.test(key) || tokens[cursor + 1] !== ':') return null;
    cursor += 2;
    const valueStart = cursor;
    const stack = [];
    while (cursor < tokens.length) {
      const token = tokens[cursor];
      if (stack.length === 0 && (token === ',' || token === '}')) break;
      if (Object.hasOwn(closers, token)) stack.push(closers[token]);
      else if (['}', ']', ')'].includes(token) && stack.pop() !== token) return null;
      cursor++;
    }
    if (cursor === valueStart || cursor >= tokens.length || stack.length) return null;
    properties.set(key.replace(/^['"]|['"]$/g, ''), tokens.slice(valueStart, cursor));
    if (tokens[cursor] === ',') cursor++;
  }
  return null;
}

function hasFetchIntegrity(call) {
  const tokens = sourceTokens(call);
  // The first argument is the literal discovery URL. Only an unconditional
  // object in the second argument establishes Fetch's native SRI behavior.
  if (tokens[0] !== 'fetch' || tokens[1] !== '(' || tokens[3] !== ',') return false;
  const options = literalObject(tokens, 4);
  if (!options) return false;
  if (![')', ','].includes(tokens[options.end + 1])) return false;
  const integrity = options.properties.get('integrity');
  return integrity?.length === 1 && /^['"]sha(?:256-[A-Za-z0-9+/]{43}=|384-[A-Za-z0-9+/]{64}|512-[A-Za-z0-9+/]{86}==)['"]$/.test(integrity[0]);
}

export class A2ASecurityAgent extends BaseAgent {
  constructor({ pinnedKeys = new Map() } = {}) {
    super('A2ASecurityAgent', 'A2A card poisoning, authentication, transport, callbacks, and integrity', 'llm');
    this.pinnedKeys = pinnedKeys;
  }

  async analyze(context) {
    const files = this.getFilesToScan(context) ?? await this.discoverFiles(context.rootPath);
    const findings = [];
    for (const file of files) {
      const isCard = CARD_PATH.test(file);
      const ext = path.extname(file);
      if (!isCard && ext !== '.json' && !SOURCE_EXTENSIONS.has(ext)) continue;
      const source = this.readFile(file);
      if (!source) continue;
      const add = (rule, offset, title, description, fix, severity = 'high', confidence = 'high', signatureState) => {
        const finding = createFinding({ file, line: source.slice(0, offset).split('\n').length,
          rule, title, description, fix, severity, confidence, category: this.category,
          cwe: rule.includes('SSRF') ? 'CWE-918' : rule.includes('NO_AUTH') ? 'CWE-306'
            : rule.includes('HTTP_ENDPOINT') ? 'CWE-319' : rule.includes('UNPINNED') ? 'CWE-494' : 'CWE-74',
          // Never copy descriptions, credentials, URL userinfo, or query tokens.
          matched: rule,
        });
        if (signatureState) finding.signatureState = signatureState;
        findings.push(finding);
      };
      const callback = (value, offset) => {
        const url = urlOf(value);
        if (url && isUnsafeCallbackDestination(url)) add('A2A_PUSH_NOTIFICATION_SSRF', offset,
          'A2A: Unsafe push notification destination',
          'An A2A push callback targets a non-public address or an unsupported URL scheme. A server accepting this destination could make internal requests.',
          'Allowlist HTTPS callback destinations; reject private and metadata addresses after DNS resolution and on every redirect.');
      };
      if (ext === '.json') {
        let document;
        try { document = JSON.parse(source); } catch { continue; }
        if (!object(document)) continue;
        let locations;
        try { locations = jsonLocations(source); } catch { continue; }
        const offset = parts => locations.get(JSON.stringify(parts)) ?? 0;
        if (isCard) {
          const signatureState = agentCardSignatureState(document, this.pinnedKeys);
          const cardAdd = (rule, parts, title, description, fix) => add(rule, offset(parts), title,
            `${description} Card signature: ${signatureState}.`, fix, 'high', 'high', signatureState);
          const descriptions = [[['description'], document.description]];
          if (Array.isArray(document.skills)) document.skills.forEach((skill, i) => descriptions.push([['skills', i, 'description'], skill?.description]));
          for (const [parts, value] of descriptions) {
            if (typeof value === 'string' && hasHiddenAgentInstruction(value)) cardAdd('A2A_CARD_HIDDEN_INSTRUCTION', parts,
              'A2A: Instructions embedded in card description',
              'Discovery metadata contains instruction override, role hijacking, hidden comments, or invisible text that can poison a consuming agent’s context.',
              'Treat card descriptions as untrusted data; remove injected instructions and review the card publisher.');
          }
          if (!hasAuthentication(document)) cardAdd('A2A_CARD_NO_AUTH', [], 'A2A: No effective authentication declaration',
            'The card has no supported authentication declaration, or explicitly permits anonymous access. Static metadata does not establish server-side enforcement.',
            'Declare an authentication scheme and require it for protected operations; enforce it on the server.');
          const endpoints = [[['url'], document.url]];
          for (const key of ['supportedInterfaces', 'additionalInterfaces']) {
            if (Array.isArray(document[key])) document[key].forEach((entry, i) => endpoints.push([[key, i, 'url'], entry?.url]));
          }
          for (const [parts, value] of endpoints) {
            const url = urlOf(value);
            if (url?.protocol === 'http:' && !isLoopbackDestination(url)) cardAdd('A2A_CARD_HTTP_ENDPOINT', parts,
              'A2A: Plaintext agent endpoint', 'Tasks and forwarded credentials may travel over plaintext HTTP.',
              'Use HTTPS for non-loopback agent endpoints.');
          }
        }
        const walk = (value, parts = []) => {
          if (!value || typeof value !== 'object') return;
          for (const [key, child] of Object.entries(value)) {
            const next = [...parts, Array.isArray(value) ? Number(key) : key];
            if (PUSH_KEYS.has(key) && object(child)) callback(child.url, offset([...next, 'url']));
            walk(child, next);
          }
        };
        walk(document);
        continue;
      }
      const masks = commentMask(source.split('\n'), { file });
      const isCode = index => !masks[source.slice(0, index).split('\n').length - 1]
        && !isInsideJavaScriptNonCode(source, index);
      const pushes = /\b(?:task_?push_?notification_?config|push_?notification_?config)["']?\s*[:=]\s*\{/gi;
      for (const match of source.matchAll(pushes)) {
        // Quoted property names start one character before the regex match.
        const start = /["']/.test(source[match.index - 1] || '') ? match.index - 1 : match.index;
        if (!isCode(start)) continue;
        const objectStart = match.index + match[0].length - 1;
        const config = literalObject(sourceTokens(source.slice(objectStart, objectStart + 8192)), 0);
        const value = config?.properties.get('url');
        // Resolve only a direct literal URL; nested authentication URLs and
        // expressions do not establish the push callback's destination.
        if (value?.length === 1 && /^(["'])([^"'\\\n]*)\1$/.test(value[0])) callback(value[0].slice(1, -1), match.index);
      }
      const fetches = /(?<![\w.])(?:fetch|axios\.get|requests\.get|httpx\.get)\s*\(\s*(["'`])(https?:\/\/[^"'`\n]+\/\.well-known\/agent(?:-card)?\.json(?:[?#][^"'`\n]*)?)\1/g;
      for (const match of source.matchAll(fetches)) {
        if (!isCode(match.index)) continue;
        const end = callEnd(source, source.indexOf('(', match.index));
        if (end === -1) continue;
        const call = source.slice(match.index, end);
        // Fetch's native SRI is an enforceable hash check. Do not mistake a
        // signature property, comment, or unrelated verify() for verification.
        const pinned = call.startsWith('fetch') && hasFetchIntegrity(call);
        if (!pinned) add('A2A_REMOTE_CARD_UNPINNED', match.index, 'A2A: Remote card fetch without a recognized integrity pin',
          'A runtime fetch loads an A2A discovery card without a literal Fetch integrity pin. No signature verification is established by this check; review any verification performed after the fetch.',
          'Pin the expected card hash with Fetch integrity, or verify its JWS against an independently pinned key before using the card.', 'medium', 'medium');
      }
    }
    return findings;
  }
}
