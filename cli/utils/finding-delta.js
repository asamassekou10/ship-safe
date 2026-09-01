import crypto from 'crypto';
import path from 'path';
import { findingFingerprint } from './finding-fingerprint.js';

function normalizedEvidence(finding) {
  const matched = String(finding?.matched || '').replace(/\s+/g, ' ').trim();
  return matched || String(finding?.title || finding?.description || '').replace(/\s+/g, ' ').trim();
}

/**
 * A path-independent identity used only when an exact fingerprint misses.
 * The value is hashed because matched evidence may contain a credential.
 */
export function findingRelocationFingerprint(finding) {
  const canonical = [
    finding?.rule || 'unknown-rule',
    normalizedEvidence(finding),
  ].join('|');

  return `move-v1-${crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16)}`;
}

/**
 * Produce the safe, portable representation stored in machine reports.
 * Raw matched evidence and absolute workstation paths are intentionally absent.
 */
export function snapshotFinding(finding, rootPath = process.cwd()) {
  const relativeFile = finding?.relativeFile
    || path.relative(rootPath, finding?.file || '').replace(/\\/g, '/');
  const absoluteFile = path.resolve(rootPath, relativeFile);

  return {
    fingerprint: finding?.fingerprint || findingFingerprint({ ...finding, file: absoluteFile }, rootPath),
    relocationFingerprint: finding?.relocationFingerprint || findingRelocationFingerprint(finding),
    rule: finding?.rule || 'unknown-rule',
    file: relativeFile,
    line: finding?.line || 1,
    severity: finding?.severity || 'medium',
    title: finding?.title || finding?.rule || 'Security finding',
    codeScope: finding?.codeScope || 'unknown',
    evidenceLevel: finding?.evidenceLevel || 'heuristic',
  };
}

const SEVERITY_RANK = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

function severityIncreased(previous, current) {
  return (SEVERITY_RANK[current?.severity] ?? 0) > (SEVERITY_RANK[previous?.severity] ?? 0);
}

function queueBy(items, key) {
  const result = new Map();
  for (const item of items) {
    const value = item[key];
    if (!result.has(value)) result.set(value, []);
    result.get(value).push(item);
  }
  return result;
}

/**
 * Compare two scans without guessing when the evidence is ambiguous.
 * Exact identities match first. A unique path-independent 1:1 match is then
 * accepted as a relocation. Duplicate relocation candidates remain uncertain.
 */
export function compareFindingSets(baseFindings = [], headFindings = [], options = {}) {
  const baseRoot = options.baseRoot || options.rootPath || process.cwd();
  const headRoot = options.headRoot || options.rootPath || process.cwd();
  const base = baseFindings.map(finding => snapshotFinding(finding, baseRoot));
  const head = headFindings.map(finding => snapshotFinding(finding, headRoot));

  const exactBase = queueBy(base, 'fingerprint');
  const introduced = [];
  const unchanged = [];
  const unmatchedHead = [];

  for (const finding of head) {
    const candidates = exactBase.get(finding.fingerprint);
    if (candidates?.length) {
      const previous = candidates.shift();
      if (severityIncreased(previous, finding)) {
        introduced.push({
          status: 'introduced',
          finding,
          previous,
          reason: 'severity-increased',
        });
      } else {
        unchanged.push({ status: 'unchanged', finding, previous, relocated: false });
      }
    } else {
      unmatchedHead.push(finding);
    }
  }

  const unmatchedBase = [];
  for (const candidates of exactBase.values()) unmatchedBase.push(...candidates);

  const baseMoves = queueBy(unmatchedBase, 'relocationFingerprint');
  const headMoves = queueBy(unmatchedHead, 'relocationFingerprint');
  const consumedBase = new Set();
  const consumedHead = new Set();
  const uncertain = [];

  for (const [key, current] of headMoves) {
    const previous = baseMoves.get(key) || [];
    if (current.length === 1 && previous.length === 1) {
      consumedHead.add(current[0]);
      consumedBase.add(previous[0]);
      if (severityIncreased(previous[0], current[0])) {
        introduced.push({
          status: 'introduced',
          finding: current[0],
          previous: previous[0],
          reason: 'severity-increased',
        });
      } else {
        unchanged.push({
          status: 'unchanged',
          finding: current[0],
          previous: previous[0],
          relocated: current[0].file !== previous[0].file,
        });
      }
    } else if (previous.length > 0) {
      current.forEach(item => consumedHead.add(item));
      previous.forEach(item => consumedBase.add(item));
      uncertain.push({
        status: 'uncertain',
        relocationFingerprint: key,
        current,
        previous,
        reason: 'multiple findings share the same path-independent identity',
      });
    }
  }

  introduced.push(...unmatchedHead
    .filter(finding => !consumedHead.has(finding))
    .map(finding => ({ status: 'introduced', finding })));
  const resolved = unmatchedBase
    .filter(finding => !consumedBase.has(finding))
    .map(finding => ({ status: 'resolved', finding }));

  return {
    version: 1,
    introduced,
    resolved,
    unchanged,
    uncertain,
    counts: {
      introduced: introduced.length,
      resolved: resolved.length,
      unchanged: unchanged.length,
      uncertain: uncertain.reduce((count, group) => count + group.current.length, 0),
    },
  };
}
