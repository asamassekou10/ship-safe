/**
 * Pinned Agent Advisory Table
 * ============================
 *
 * Answers one narrow question: is a configured execution sink actually
 * reachable by an agent this machine has installed?
 *
 * A sink in `.git/config` is a fact about the repository. Whether it fires is
 * a fact about the agent that opens it, and those are different claims. Ship
 * Safe reports the first as `configured` and only promotes it to `reachable`
 * when a detected, installed version is documented to invoke it — documented
 * meaning an advisory or a disclosure writeup, never a vendor's release-note
 * phrasing.
 *
 * Three properties keep this from becoming a claim generator:
 *
 *   - The table is pinned, versioned, and carries a date. It lags disclosure,
 *     so `trust` prints how old it is and lets the reader discount it.
 *   - Version detection is best effort. When a version cannot be determined,
 *     the finding stays `unresolved`. It never falls through to `reachable`.
 *   - Absence from the table is not safety. An agent nobody has written up is
 *     undocumented, not clean, and the vocabulary here says so.
 *
 * See docs/adding-a-security-rule.md for the review discipline on edits.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TABLE_PATH = path.join(HERE, '..', 'data', 'agent-advisories.json');

/**
 * Reachability states, ordered from weakest claim to strongest.
 *
 *   'configured'  — the sink is in the repository. Says nothing about agents.
 *   'unresolved'  — an affected agent may be installed but no version was
 *                   readable, so the question was not answered.
 *   'reachable'   — a detected installed version is documented to invoke it.
 */
export const REACHABILITY = Object.freeze(['configured', 'unresolved', 'reachable']);

/** How long an agent gets to answer `--version` before it is given up on. */
const VERSION_TIMEOUT_MS = 2000;

let cachedTable = null;

// =============================================================================
// TABLE
// =============================================================================

export function loadAdvisoryTable(tablePath = TABLE_PATH) {
  if (cachedTable && tablePath === TABLE_PATH) return cachedTable;

  let table;
  try {
    table = JSON.parse(fs.readFileSync(tablePath, 'utf8'));
  } catch {
    // A missing or unparseable table must not fail a scan, and must not
    // silently behave like an empty one that clears every finding. Callers
    // read `entries.length === 0` and keep findings at `configured`.
    return { schemaVersion: 0, tableVersion: 'unavailable', recordedAt: null, entries: [] };
  }

  if (tablePath === TABLE_PATH) cachedTable = table;
  return table;
}

/** Days between the table's recorded date and now, or null if unknown. */
export function tableAgeDays(table, now = new Date()) {
  if (!table?.recordedAt) return null;
  const recorded = new Date(`${table.recordedAt}T00:00:00Z`);
  if (Number.isNaN(recorded.getTime())) return null;
  return Math.max(0, Math.floor((now - recorded) / 86_400_000));
}

// =============================================================================
// VERSION COMPARISON
// =============================================================================

/**
 * Compare two dotted numeric versions.
 *
 * Deliberately not semver-complete. The table holds release versions, and a
 * comparator that guessed at prerelease ordering would let an entry cover more
 * than the writeup it came from. A version this cannot parse returns null and
 * the caller reports `unresolved`.
 */
export function compareVersions(a, b) {
  const parse = (v) => {
    const core = String(v).trim().replace(/^v/, '').split(/[-+]/)[0];
    if (!/^\d+(\.\d+)*$/.test(core)) return null;
    return core.split('.').map(Number);
  };

  const left = parse(a);
  const right = parse(b);
  if (!left || !right) return null;

  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Whether a version falls in an entry's affected set.
 *
 * Returns null rather than false when the comparison cannot be made, so an
 * unparseable version is reported as unresolved instead of quietly clearing
 * the finding.
 */
export function isAffected(version, affected) {
  if (!affected || !version) return null;

  if (Array.isArray(affected.exact)) {
    // An exact list is exactly what it says. The writeup tested these
    // versions; the ones around them were not tested and are not claimed.
    for (const candidate of affected.exact) {
      const cmp = compareVersions(version, candidate);
      if (cmp === null) return null;
      if (cmp === 0) return true;
    }
    return false;
  }

  const checks = [
    ['lt', -1], ['lte', 0], ['gt', 1], ['gte', 0],
  ];

  let matched = false;
  for (const [key] of checks) {
    if (affected[key] === undefined) continue;
    const cmp = compareVersions(version, affected[key]);
    if (cmp === null) return null;

    const ok =
      (key === 'lt' && cmp < 0) ||
      (key === 'lte' && cmp <= 0) ||
      (key === 'gt' && cmp > 0) ||
      (key === 'gte' && cmp >= 0);

    if (!ok) return false;
    matched = true;
  }

  return matched ? true : null;
}

// =============================================================================
// LOCAL AGENT DETECTION
// =============================================================================

/**
 * Directories that may be searched for an agent binary.
 *
 * PATH is filtered rather than trusted. A relative entry, an empty entry
 * (which POSIX reads as the current directory), or anything inside the folder
 * being inspected would let the scanned repository supply the binary whose
 * version we are about to ask for — turning a read-only pre-flight check into
 * one that executes repository-supplied code. That is precisely the attack
 * `ship-safe trust` exists to warn about.
 */
function searchablePathDirs(excludeRoot) {
  const raw = String(process.env.PATH ?? '').split(path.delimiter);
  const exclude = excludeRoot ? path.resolve(excludeRoot) : null;

  return raw.filter((dir) => {
    if (!dir) return false;
    if (!path.isAbsolute(dir)) return false;

    const resolved = path.resolve(dir);
    if (!exclude) return true;
    return resolved !== exclude && !resolved.startsWith(`${exclude}${path.sep}`);
  });
}

/** Absolute path of a binary on PATH, or null. */
function resolveBinary(name, excludeRoot) {
  for (const dir of searchablePathDirs(excludeRoot)) {
    const candidate = path.join(dir, name);
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111)) return candidate;
    } catch { /* next */ }
  }
  return null;
}

/**
 * Ask an installed agent for its version.
 *
 * Never through a shell, never with the scanned folder as cwd, and never a
 * binary resolved from inside it. This runs a program the user installed, not
 * one the repository supplied, and the distinction is the whole safety
 * argument for doing it at all.
 */
export function detectAgentVersion(binaryName, { excludeRoot = null } = {}) {
  const binary = resolveBinary(binaryName, excludeRoot);
  if (!binary) return null;

  let output;
  try {
    output = execFileSync(binary, ['--version'], {
      timeout: VERSION_TIMEOUT_MS,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      // Never the folder under inspection: a cwd inside it would let the
      // repository influence a tool that reads config from its working
      // directory.
      cwd: os.tmpdir(),
      shell: false,
    });
  } catch {
    return null;
  }

  const match = String(output).match(/\d+(?:\.\d+)+/);
  return match ? { binary, version: match[0] } : null;
}

// =============================================================================
// RESOLUTION
// =============================================================================

/**
 * Decide reachability for one rule.
 *
 * Returns the state plus the evidence behind it, so a report can say why
 * rather than only what. `installed` lists the agents actually detected;
 * `candidates` lists the table entries that cover this rule at all, which is
 * what makes an `unresolved` result legible.
 */
export function resolveReachability(rule, { table = loadAdvisoryTable(), excludeRoot = null, detect = detectAgentVersion } = {}) {
  const candidates = (table.entries ?? []).filter((e) => (e.sinks ?? []).includes(rule));

  if (candidates.length === 0) {
    // No advisory covers this sink. That is not evidence of safety, so the
    // finding stays where it started rather than being cleared.
    return {
      state: 'configured',
      reason: 'No pinned advisory covers this sink, so reachability was not assessed.',
      candidates: [],
      installed: [],
    };
  }

  const installed = [];
  let sawAgentWithUnknownVersion = false;

  for (const entry of candidates) {
    for (const binary of entry.binaries ?? []) {
      const found = detect(binary, { excludeRoot });
      if (!found) continue;

      const affected = isAffected(found.version, entry.affected);
      if (affected === null) {
        sawAgentWithUnknownVersion = true;
        continue;
      }

      installed.push({
        agent: entry.displayName,
        version: found.version,
        affected,
        cve: entry.cve ?? null,
        patchedIn: entry.patchedIn ?? null,
        source: entry.source,
        entryId: entry.id,
      });
    }
  }

  const hits = installed.filter((i) => i.affected);

  if (hits.length > 0) {
    const names = hits.map((h) => `${h.agent} ${h.version}${h.cve ? ` (${h.cve})` : ''}`);
    return {
      state: 'reachable',
      reason: `Installed and documented to invoke this sink: ${names.join(', ')}.`,
      candidates: candidates.map((c) => c.id),
      installed,
    };
  }

  if (sawAgentWithUnknownVersion) {
    return {
      state: 'unresolved',
      reason: 'An agent covered by an advisory is installed but its version could not be read, so reachability is unknown.',
      candidates: candidates.map((c) => c.id),
      installed,
    };
  }

  if (installed.length > 0) {
    return {
      state: 'configured',
      reason: `Installed agents are outside the affected versions: ${installed.map((i) => `${i.agent} ${i.version}`).join(', ')}. Other agents may still reach this sink.`,
      candidates: candidates.map((c) => c.id),
      installed,
    };
  }

  return {
    state: 'unresolved',
    reason: 'No agent covered by an advisory was detected on this machine. Absence of a local install is not evidence the folder is safe to open elsewhere.',
    candidates: candidates.map((c) => c.id),
    installed: [],
  };
}

export default { loadAdvisoryTable, resolveReachability, detectAgentVersion, compareVersions, isAffected, tableAgeDays, REACHABILITY };
