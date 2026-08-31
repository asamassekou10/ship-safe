/**
 * DataflowInvestigator — trace the value, not the neighbourhood
 * ==============================================================
 *
 * VerifierAgent asks whether the words "req.query" and "sanitize" appear within
 * a few lines of a finding. That is cheap and it is why it settles two of the
 * twelve corpus findings: proximity is not a data path. A validator three lines
 * above the sink may guard a different variable entirely, and the value that
 * reaches the sink may have been assigned six lines earlier from a constant.
 *
 * This pass follows the actual value. From the sink it takes the identifiers
 * that feed it, walks backwards through assignments, destructurings, and
 * parameters, and asks what each one resolves to — an untrusted source, a
 * literal, a sanitizer's return value, or nothing it can determine. Every hop
 * it takes becomes a citation, so the claim it files can be checked line by
 * line rather than believed.
 *
 * It ranks above the LLM pass deliberately. A traced path is a stronger fact
 * than a model's reading of the same file, and when the two disagree the trace
 * should win.
 *
 * Deliberate limits, because a tracer that guesses is worse than one that
 * abstains:
 *
 *   - JavaScript and TypeScript only. Python and Go get no claim at all rather
 *     than a JS-shaped guess about their syntax.
 *   - One function boundary. When the value arrives as a parameter — the
 *     dominant case in real handler code — the pass looks for calls to the
 *     enclosing function and continues the trace in the caller, including
 *     across files. It stops there rather than walking a whole call tree,
 *     because each hop multiplies the chance of following the wrong `handler`.
 *   - Taint-shaped rules only. A hardcoded secret is *proven* by its value
 *     being a literal; concluding "refuted, it is a constant" there would
 *     invert the finding. Categories where a literal is the vulnerability are
 *     skipped outright.
 *
 * When the trace dies, the pass files nothing. Silence keeps the verdict at
 * whatever a better-informed pass concluded, which is the correct outcome for a
 * pass that learned nothing.
 */

import fs from 'fs';
import path from 'path';
import { attachEvidence, createClaim } from '../utils/evidence.js';

// =============================================================================
// VOCABULARY
// =============================================================================

const TRACEABLE_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);

/**
 * Categories where the value reaching the sink is what makes the finding real.
 * Everything else — secrets, supply chain, configuration, licensing — is about
 * the value being present, not about where it came from.
 */
const TAINT_CATEGORIES = new Set(['vulnerability', 'api', 'injection', 'auth', 'llm']);

/** Expressions that introduce a value an attacker controls. */
const UNTRUSTED_SOURCE = [
  { re: /\breq(?:uest)?\.(?:body|query|params|headers|cookies|url|originalUrl)\b/, what: 'the HTTP request' },
  { re: /\bctx\.(?:request|query|params|body|headers)\b/,                          what: 'the HTTP request' },
  { re: /\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b/,        what: 'the invocation event' },
  { re: /\b(?:searchParams|URLSearchParams)\b/,                                    what: 'the URL query string' },
  { re: /\bformData\b/,                                                            what: 'submitted form data' },
  { re: /\bprocess\.argv\b/,                                                       what: 'the command line' },
  { re: /\bawait\s+(?:req|request)\.(?:json|text|formData)\s*\(/,                  what: 'the HTTP request body' },
  { re: /\b(?:completion|response|message|choice)s?\.(?:content|text|message|output)\b/, what: 'model output' },
  { re: /\bwindow\.location\b|\bdocument\.(?:URL|referrer|cookie)\b/,              what: 'the browser environment' },
];

/**
 * Calls whose return value is no longer the attacker's to shape. Applied only
 * to the expression actually assigned to the traced variable — a validator
 * called on some other value is not a mitigation, which is precisely the
 * mistake the heuristic pass makes.
 */
const SANITIZER = [
  { re: /\b(?:parseInt|parseFloat|Number|BigInt)\s*\(/,        what: 'numeric coercion' },
  { re: /\bencodeURIComponent\s*\(/,                           what: 'URI encoding' },
  { re: /\b(?:escape|escapeHtml|sanitize\w*|purify|DOMPurify\.sanitize)\s*\(/i, what: 'escaping or sanitization' },
  { re: /\b\w*(?:[sS]chema|validator)\w*\.(?:parse|validate|assert)\s*\(/,      what: 'schema validation' },
  { re: /\bz\.[\w.]+\.parse\s*\(/,                             what: 'zod validation' },
  { re: /\b(?:validate|assertValid|checkAllowed|isAllowed)\w*\s*\(/i,           what: 'an explicit validation call' },
  { re: /\bALLOW(?:ED|LIST)\w*\.(?:includes|has)\s*\(/i,       what: 'an allowlist membership test' },
  { re: /\.(?:includes|indexOf)\s*\(\s*\w+\s*\)\s*\?/,         what: 'an allowlist ternary' },
];

/** A value written into the source rather than arriving from outside. */
const LITERAL = /^\s*(?:'[^']*'|"[^"]*"|`[^`$]*`|-?\d+(?:\.\d+)?|true|false|null)\s*$/;

const MAX_HOPS = 12;
const MAX_SEEDS = 4;

/** Call sites examined per function before the pass gives up on distinguishing them. */
const MAX_CALL_SITES = 12;

/** Files scanned when looking for callers. Beyond this the index is not worth its cost. */
const MAX_INDEXED_FILES = 4000;

/**
 * Names too common to resolve by name alone. A call to `handler(x)` somewhere in
 * the repo is not evidence about *this* handler, so a match on one of these is
 * only accepted when the caller demonstrably imports the defining file.
 */
const AMBIGUOUS_NAME = new Set([
  'handler', 'handle', 'run', 'main', 'execute', 'process', 'callback', 'cb',
  'init', 'start', 'get', 'post', 'put', 'update', 'create', 'remove', 'send',
  'query', 'find', 'load', 'save', 'render', 'next', 'done', 'fn', 'apply',
]);

// =============================================================================
// PASS
// =============================================================================

export class DataflowInvestigator {
  constructor() {
    this.name = 'DataflowInvestigator';
    this.description = 'Traces a finding\'s value back to its origin and files a cited claim';
  }

  /**
   * Investigate findings in place. Returns the same array so this composes with
   * the other passes in the orchestrator.
   */
  investigate(findings, { rootPath = process.cwd(), files = null } = {}) {
    const fileCache = new Map();

    // Built once per run and only when something actually needs a caller, so a
    // scan whose findings all resolve locally never pays for the index.
    this._rootPath = rootPath;
    this._fileList = files;
    this._callIndex = null;
    this._fileCache = fileCache;

    for (const finding of findings) {
      if (!this._traceable(finding)) continue;

      const lines = this._read(finding.file, fileCache);
      if (!lines) continue;

      const trace = this._trace(finding, lines);
      if (!trace) continue;

      attachEvidence(finding, createClaim({
        source: 'dataflow',
        verdict: trace.verdict,
        rationale: trace.rationale,
        // A hop names the file it was read in. Once the trace crosses a
        // function boundary those differ, and citing the sink's file for a line
        // in the caller produces a citation that resolves — to the wrong code.
        citations: trace.hops.map((hop) => ({
          file: path.resolve(rootPath, hop.file || finding.file),
          line: hop.line,
          excerpt: hop.excerpt,
        })),
        attackPath: trace.hops.map((hop) => hop.text),
      }));
    }

    return findings;
  }

  _traceable(finding) {
    if (!finding.file || !finding.line) return false;
    if (!TRACEABLE_EXT.has(path.extname(finding.file).toLowerCase())) return false;
    return TAINT_CATEGORIES.has(finding.category);
  }

  _read(file, cache) {
    if (cache.has(file)) return cache.get(file);
    let lines;
    try {
      lines = fs.readFileSync(file, 'utf-8').split('\n');
    } catch { lines = null; }
    cache.set(file, lines);
    return lines;
  }

  // ── The trace ────────────────────────────────────────────────────────────

  _trace(finding, lines) {
    const sinkLine = lines[finding.line - 1];
    if (sinkLine === undefined) return null;

    const hops = [{
      line: finding.line,
      excerpt: sinkLine.trim().slice(0, 120),
      text: `value reaches ${finding.rule} here`,
      file: finding.file,
    }];

    // A source written directly into the sink needs no walk.
    const direct = matchAny(UNTRUSTED_SOURCE, sinkLine);
    if (direct) {
      return {
        verdict: 'confirmed',
        rationale: `The value passed to the sink comes directly from ${direct.what}, with no intervening assignment to validate it.`,
        hops,
      };
    }

    const seeds = identifiersIn(sinkLine).slice(0, MAX_SEEDS);
    if (!seeds.length) return null;

    const traces = seeds.map((seed) => this._walk(seed, finding.line, lines, hops.slice(), 0, finding.file));

    // One tainted input is enough to confirm: the sink receives a value the
    // caller shaped, whatever else it also receives.
    const tainted = traces.find((t) => t && t.verdict === 'confirmed');
    if (tainted) return tainted;

    // Refutation is the opposite — it requires *every* value reaching the sink
    // to be accounted for. Returning on the first safe seed is how a tracer
    // refutes `${coercedId} ... '${rawThreshold}'` by looking only at the half
    // that was coerced, which is a live injection reported as handled.
    const refuted = traces.filter((t) => t && t.verdict === 'refuted');
    if (refuted.length === seeds.length) {
      return {
        verdict: 'refuted',
        rationale: seeds.length === 1
          ? refuted[0].rationale
          : `Every value reaching the sink is accounted for: ${refuted.map((r) => r.rationale.replace(/\.$/, '')).join('; ')}.`,
        hops: dedupeHops(refuted.flatMap((r) => r.hops)),
      };
    }

    // Some input could not be resolved. Saying nothing is the only honest
    // outcome; a partial trace is not a mitigation.
    return null;
  }

  /** Walk one identifier backwards through the file. */
  _walk(name, fromLine, lines, hops, depth, file) {
    if (depth >= MAX_HOPS) return null;

    for (let i = fromLine - 2; i >= 0; i--) {
      const line = lines[i];
      const rhs = assignmentTo(name, line) ?? destructuredAcrossLines(lines, i, name);
      if (rhs === null || rhs === undefined) continue;

      const hop = {
        line: i + 1,
        excerpt: line.trim().slice(0, 120),
        text: `${name} is assigned here`,
        file,
      };
      const path_ = [...hops, hop];

      const sanitizer = matchAny(SANITIZER, rhs);
      if (sanitizer) {
        return {
          verdict: 'refuted',
          rationale: `${name} is the result of ${sanitizer.what} on the path to the sink, so the value reaching it is not the caller's to shape.`,
          hops: path_,
        };
      }

      const source = matchAny(UNTRUSTED_SOURCE, rhs);
      if (source) {
        return {
          verdict: 'confirmed',
          rationale: `${name} is assigned from ${source.what} and reaches the sink without validation on that path.`,
          hops: path_,
        };
      }

      if (LITERAL.test(rhs)) {
        return {
          verdict: 'refuted',
          rationale: `${name} resolves to a literal written into the source, so no caller controls the value reaching the sink.`,
          hops: path_,
        };
      }

      // The value came from another identifier — keep walking that one.
      const next = identifiersIn(rhs).find((id) => id !== name);
      if (next) return this._walk(next, i + 1, lines, path_, depth + 1, file);

      return null;
    }

    // Not defined in this file. If it is a parameter of the enclosing function,
    // the value was handed in from somewhere, and that somewhere is knowable.
    return this._walkIntoCallers(name, fromLine, lines, hops, depth, file);
  }

  // ── Across the function boundary ─────────────────────────────────────────

  /**
   * Continue the trace in whoever called the function this value is a parameter
   * of. This is where real handler code lives: `req.query.threshold` is passed
   * into a DAO three files away, and a tracer that stops at the parameter list
   * abstains on the majority of genuine findings.
   */
  _walkIntoCallers(name, fromLine, lines, hops, depth, file) {
    if (depth > 0) return null;                       // one boundary, not a call tree

    // Innermost first, so the closest function that actually declares this
    // parameter wins when nested scopes share a name.
    const scopes = enclosingFunctions(lines, fromLine, file);
    const enclosing = scopes.find((scope) => scope.name && scope.params.includes(name));
    if (!enclosing) return null;                      // not a parameter; genuinely unknown

    const index = enclosing.params.indexOf(name);
    const sites = this._callSites(enclosing.name, enclosing.file);
    if (!sites.length) return null;

    const verdicts = [];

    for (const site of sites) {
      const argument = site.args[index];
      if (argument === undefined) return null;        // arity mismatch: not the same function

      const callerLines = this._read(site.file, this._fileCache);
      if (!callerLines) return null;

      const hop = {
        line: site.line,
        excerpt: (callerLines[site.line - 1] || '').trim().slice(0, 120),
        text: `${enclosing.name} is called here with ${truncate(argument, 40)}`,
        file: site.file,
      };

      // Sanitizer before source, and not the other way round: an argument like
      // `parseInt(req.query.threshold, 10)` contains an untrusted source and is
      // still not attacker-shaped. Checking the source first reports every
      // sanitized call site as tainted.
      if (matchAny(SANITIZER, argument) || LITERAL.test(argument)) {
        verdicts.push({
          verdict: 'refuted',
          rationale: `${name} is the ${ordinal(index + 1)} argument to ${enclosing.name}, and every call site passes a value the caller does not control.`,
          hops: [...hops, hop],
        });
        continue;
      }

      const source = matchAny(UNTRUSTED_SOURCE, argument);
      if (source) {
        verdicts.push({
          verdict: 'confirmed',
          rationale: `${name} is the ${ordinal(index + 1)} argument to ${enclosing.name}, passed from ${source.what} at the call site, and reaches the sink without validation.`,
          hops: [...hops, hop],
        });
        continue;
      }

      // The argument is itself an identifier — resolve it in the caller.
      const [argName] = identifiersIn(argument);
      if (!argName) return null;

      const traced = this._walk(argName, site.line, callerLines, [...hops, hop], depth + 1, site.file);
      if (!traced) return null;                       // one unresolved caller ends it
      verdicts.push(traced);
    }

    if (!verdicts.length) return null;

    // Same rule as a sink with several inputs: one tainted caller is enough to
    // confirm, and refutation requires every call site to be safe.
    const tainted = verdicts.find((v) => v.verdict === 'confirmed');
    if (tainted) return tainted;
    if (verdicts.every((v) => v.verdict === 'refuted')) return verdicts[0];
    return null;
  }

  /** Call sites of a function, excluding its own definition. */
  _callSites(name, definedIn) {
    if (!this._callIndex) this._callIndex = buildCallIndex(this._fileList, this._rootPath, this._fileCache);

    const sites = (this._callIndex.get(name) || []).filter((site) => site.line !== undefined);
    if (!sites.length || sites.length > MAX_CALL_SITES) return [];

    // A common name matched by name alone says nothing about *this* function.
    // Require the caller to import the file that defines it.
    if (AMBIGUOUS_NAME.has(name)) {
      return sites.filter((site) => site.file !== definedIn && importsFrom(this._read(site.file, this._fileCache), definedIn));
    }
    return sites;
  }
}

// =============================================================================
// SYNTAX HELPERS
// =============================================================================

/** Merge hop lists from several seeds, keeping each line once and in order. */
function dedupeHops(hops) {
  const seen = new Set();
  return hops
    .filter((hop) => (seen.has(hop.line) ? false : seen.add(hop.line)))
    .sort((a, b) => a.line - b.line);
}

function matchAny(patterns, text) {
  return patterns.find((p) => p.re.test(text)) || null;
}

const KEYWORD = new Set([
  'const', 'let', 'var', 'function', 'return', 'await', 'async', 'new', 'typeof',
  'if', 'else', 'for', 'while', 'true', 'false', 'null', 'undefined', 'this',
  'try', 'catch', 'throw', 'class', 'extends', 'import', 'from', 'export', 'default',
]);

/**
 * Identifiers a line reads, in the order they matter.
 *
 * Order is the whole trick. In `db.raw(`SELECT ... ${userId}`)` the only
 * identifier worth walking is the one inside the interpolation; the words
 * SELECT and FROM are prose inside a string, and seeding from them wastes the
 * walk and returns nothing. So: interpolations first, then call arguments, and
 * string contents never.
 */
function identifiersIn(line) {
  const body = line.replace(/^\s*(?:const|let|var)\s+[\w{}[\],\s:]+=\s*/, '');

  const interpolated = [...body.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]).join(' ');
  const scope = interpolated || stripStrings(body);

  const names = [];
  for (const match of scope.matchAll(/\b([A-Za-z_$][\w$]*)\b(?!\s*\()/g)) {
    const name = match[1];
    if (KEYWORD.has(name) || names.includes(name)) continue;
    names.push(name);
  }
  return names;
}

/** Remove quoted text so words inside a message are never mistaken for values. */
function stripStrings(text) {
  return text
    .replace(/'[^']*'/g, "''")
    .replace(/"[^"]*"/g, '""')
    .replace(/`(?:[^`$]|\$(?!\{))*`/g, '``');
}

/**
 * The right-hand side when `name` sits alone on a line inside a destructuring
 * that spans several lines:
 *
 *   const {
 *     threshold
 *   } = req.query;
 *
 * Formatters produce this constantly, and a single-line matcher walks straight
 * past it — which is how a trace loses the tainted half of a NodeGoat handler
 * and reports nothing at all.
 */
function destructuredAcrossLines(lines, index, name) {
  const bare = new RegExp(`^\\s*${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*,?\\s*$`);
  if (!bare.test(lines[index] || '')) return null;

  // The opener must be a declaration, not an object literal being built.
  let opened = false;
  for (let i = index - 1; i >= 0 && i >= index - 6; i--) {
    const line = lines[i] || '';
    if (/(?:const|let|var)\s*\{\s*$/.test(line)) { opened = true; break; }
    if (line.trim() && !/^[\s\w$,]*$/.test(line.trim())) return null;
  }
  if (!opened) return null;

  for (let i = index + 1; i < lines.length && i <= index + 10; i++) {
    const closing = (lines[i] || '').match(/^\s*\}\s*=\s*(.+?);?\s*$/);
    if (closing) return closing[1];
    if (/[^\s\w$,]/.test(lines[i] || '')) return null;
  }
  return null;
}

/**
 * The right-hand side if this line assigns to `name`, otherwise null.
 * Handles declarations, bare reassignment, and object destructuring.
 */
function assignmentTo(name, line) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const declaration = line.match(new RegExp(`(?:const|let|var)\\s+${escaped}\\s*(?::[^=]+)?=\\s*(.+?);?\\s*$`));
  if (declaration) return declaration[1];

  const reassignment = line.match(new RegExp(`^\\s*${escaped}\\s*=\\s*(.+?);?\\s*$`));
  if (reassignment) return reassignment[1];

  // const { name } = expr  /  const { other: name } = expr
  const destructured = line.match(new RegExp(`(?:const|let|var)\\s*\\{[^}]*\\b${escaped}\\b[^}]*\\}\\s*=\\s*(.+?);?\\s*$`));
  if (destructured) return destructured[1];

  return null;
}

// =============================================================================
// FUNCTION AND CALL-SITE RESOLUTION
// =============================================================================

/** Statement keywords whose parenthesised head is not a parameter list. */
const CONTROL_FLOW = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'do', 'else']);

/** Ways a function acquires a name and a parameter list. */
const FUNCTION_DEF = [
  /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/,
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\*?\s*\(([^)]*)\)/,
  /this\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  /this\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)/,
  /^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{/,
];

/**
 * Every function definition above `lineNum` whose body still contains it,
 * innermost first.
 *
 * All of them, not just the nearest: a value is often a parameter of an outer
 * function while the sink sits inside a nested arrow that takes none. Returning
 * only the innermost scope is why an earlier version abstained on NodeGoat's
 * `getByUserIdAndThreshold` — the sink lives in a nested `searchCriteria = () =>`,
 * and the tainted `threshold` belongs to the method wrapping it.
 *
 * Containment is checked by brace balance rather than indentation, because
 * indentation is a style and braces are the language. A definition whose braces
 * close before the target line is a sibling, not a parent, and treating one as
 * a parent is how a trace ends up in the wrong function's caller.
 */
export function enclosingFunctions(lines, lineNum, file = null) {
  const found = [];

  for (let i = lineNum - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line) continue;

    const match = FUNCTION_DEF.reduce((hit, re) => hit || line.match(re), null);
    if (!match) continue;

    // `if (threshold) {` has the shape of a method shorthand. Reading it as a
    // function named "if" makes its condition look like a parameter list, and
    // the trace then goes looking for callers of `if`.
    if (KEYWORD.has(match[1]) || CONTROL_FLOW.has(match[1])) continue;

    let depth = 0;
    let closedEarly = false;
    for (let j = i; j < lineNum - 1; j++) {
      depth += bracketDelta(lines[j] || '');
      if (j > i && depth <= 0) { closedEarly = true; break; }
    }
    if (closedEarly || depth <= 0) continue;

    found.push({ name: match[1], params: splitParams(match[2]), line: i + 1, file });
  }

  return found;
}

function bracketDelta(line) {
  let depth = 0;
  for (const char of line) {
    if (char === '{') depth += 1;
    else if (char === '}') depth -= 1;
  }
  return depth;
}

/**
 * Parameter names in order. A destructured or rest parameter yields an empty
 * slot: the position still counts, so later parameters keep their index, but
 * nothing is claimed about what the value inside it is.
 */
function splitParams(text) {
  return splitTopLevel(text).map((param) => {
    const cleaned = param.replace(/=[\s\S]*$/, '').replace(/:[\s\S]*$/, '').trim();
    return /^[A-Za-z_$][\w$]*$/.test(cleaned) ? cleaned : '';
  });
}

/** Split on commas that are not inside brackets, braces, parens, or quotes. */
function splitTopLevel(text) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let current = '';

  for (const char of String(text)) {
    if (quote) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === '`') { quote = char; current += char; continue; }
    if ('([{'.includes(char)) depth += 1;
    if (')]}'.includes(char)) depth -= 1;
    if (char === ',' && depth === 0) { parts.push(current.trim()); current = ''; continue; }
    current += char;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

/**
 * Where every function name is called, across the files given.
 *
 * Built from the file list the orchestrator already discovered. When none was
 * passed the index is empty rather than crawling the disk: a pass that silently
 * walks a filesystem is not a pass whose cost anyone can predict.
 */
function buildCallIndex(files, rootPath, cache) {
  const index = new Map();
  const list = (files || []).filter((f) => TRACEABLE_EXT.has(path.extname(f).toLowerCase()));
  if (!list.length) return index;

  for (const file of list.slice(0, MAX_INDEXED_FILES)) {
    let lines;
    if (cache.has(file)) lines = cache.get(file);
    else {
      try { lines = fs.readFileSync(file, 'utf-8').split('\n'); } catch { lines = null; }
      cache.set(file, lines);
    }
    if (!lines) continue;

    lines.forEach((line, i) => {
      for (const match of line.matchAll(/(?:\b|\.)([A-Za-z_$][\w$]*)\s*\(/g)) {
        const name = match[1];
        if (KEYWORD.has(name)) continue;

        // A definition is not a call. `function f(a)` and `f(a)` look alike to a
        // regex, and counting the definition as its own caller traces a
        // parameter to itself.
        const before = line.slice(0, match.index).trimEnd();
        if (/\b(?:function|class)$/.test(before) || /(?:const|let|var)\s+[\w$.]*\s*=?\s*$/.test(before)) continue;

        const args = splitTopLevel(argumentText(line, match.index + match[0].length));
        if (!index.has(name)) index.set(name, []);
        index.get(name).push({ file, line: i + 1, args });
      }
    });
  }

  return index;
}

/** The text between a call's parentheses, as far as this line goes. */
function argumentText(line, start) {
  let depth = 1;
  let out = '';
  for (let i = start; i < line.length; i++) {
    const char = line[i];
    if ('([{'.includes(char)) depth += 1;
    if (')]}'.includes(char)) { depth -= 1; if (depth === 0) break; }
    out += char;
  }
  return out;
}

/** Whether a caller file imports or requires the file a function is defined in. */
function importsFrom(callerLines, definedIn) {
  if (!callerLines || !definedIn) return false;
  const base = path.basename(definedIn).replace(/\.[^.]+$/, '');
  return callerLines.some((line) =>
    /^\s*(?:import\b|const\s|let\s|var\s).*(?:from\s*['"`]|require\s*\(\s*['"`])/.test(line)
    && line.includes(base));
}

function truncate(value, max = 60) {
  const str = String(value).trim();
  return str.length > max ? `${str.slice(0, max - 1)}…` : str;
}

function ordinal(n) {
  return ['first', 'second', 'third', 'fourth', 'fifth'][n - 1] || `${n}th`;
}
