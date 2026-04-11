/**
 * AgentAttestationAgent — Ship Safe × Hermes Agent
 * ==================================================
 *
 * Detects missing or broken attestation in agent manifests and deployment
 * configurations: unsigned manifests, missing provenance, unpinned package
 * versions, integrity hash drift, and lack of supply-chain controls.
 *
 * OWASP Agentic AI: ASI-10 (Supply Chain), ASI-07 (Lack of Oversight)
 * SLSA Level 0 → checking for basic provenance and version pinning.
 *
 * SCANNING TARGETS:
 *   - agent-manifest.{json,yaml,yml}
 *   - agents.{json,yaml,yml}
 *   - hermes.config.{js,ts,json,yaml,yml}
 *   - openclaw.json
 *   - package.json, package-lock.json
 *   - .hermes/**
 *   - Any file declaring agent versions, integrity hashes, or provenance
 */

import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// PATTERNS — detected in source files
// =============================================================================

const PATTERNS = [
  // ── Unpinned versions ──────────────────────────────────────────────────────
  {
    rule: 'AGENT_UNPINNED_VERSION_LATEST',
    title: 'Agent: Unpinned version "latest" (ASI-10 Supply Chain)',
    regex: /["'](?:\w*[Vv]ersion|tag|image|ref)["']\s*:\s*["']latest["']/gi,
    severity: 'high',
    cwe: 'CWE-1104',
    owasp: 'ASI-10',
    confidence: 'high',
    description: 'Agent/image version pinned to "latest" — next pull may silently upgrade to a tampered or incompatible version.',
    fix: 'Pin to a specific semantic version (e.g., "1.2.3") or commit SHA.',
  },
  {
    rule: 'AGENT_UNPINNED_VERSION_STAR',
    title: 'Agent: Unpinned version wildcard (* or ^) (ASI-10)',
    regex: /["'](?:\w*[Vv]ersion|tag)["']\s*:\s*["'][\^~*><=][^"']{1,20}["']/gi,
    severity: 'high',
    cwe: 'CWE-1104',
    owasp: 'ASI-10',
    confidence: 'high',
    description: 'Agent version uses a mutable range specifier — version may float to an attacker-controlled release.',
    fix: 'Pin to an exact version string without range operators.',
  },
  {
    rule: 'AGENT_HERMES_UNPINNED',
    title: 'Hermes: @nousresearch/hermes-agent not pinned to exact version',
    regex: /["']@nousresearch\/hermes-agent["']\s*:\s*["'][\^~*><=][^"']{1,20}["']/gi,
    severity: 'high',
    cwe: 'CWE-1104',
    owasp: 'ASI-10',
    confidence: 'high',
    description: 'hermes-agent package version is not pinned — a malicious minor/patch release could modify agent behavior.',
    fix: 'Pin to exact version: "\"@nousresearch/hermes-agent\": \"1.2.3\""',
  },

  // ── Missing integrity fields ────────────────────────────────────────────────
  {
    rule: 'AGENT_NO_INTEGRITY_HASH',
    title: 'Agent: No integrity hash on remote resource (ASI-10)',
    regex: /["'](?:url|source|registry|endpoint)["']\s*:\s*["']https?:\/\/[^"']{10,}["'](?!\s*,?\s*["']integrity["'])/gi,
    severity: 'high',
    cwe: 'CWE-494',
    owasp: 'ASI-10',
    confidence: 'medium',
    description: 'Remote resource loaded without an integrity hash — no way to detect tampering between publish and load time.',
    fix: 'Add an "integrity": "sha256-..." or "sha512-..." field alongside the URL.',
  },
  {
    rule: 'AGENT_MANIFEST_NO_SIGNATURE',
    title: 'Agent: Manifest loaded without signature verification',
    regex: /(?:loadManifest|readManifest|parseManifest|loadConfig|readConfig|parseConfig)\s*\([^)]{0,80}\)(?!\s*\.(?:verify|checkSignature|assertIntegrity))/gi,
    severity: 'high',
    cwe: 'CWE-345',
    owasp: 'ASI-10',
    confidence: 'medium',
    description: 'Agent manifest is loaded/parsed without a subsequent signature or integrity check — manifest tampering goes undetected.',
    fix: 'Verify manifest signature or compute expected SHA-256 before trusting its contents.',
  },

  // ── Missing provenance fields ──────────────────────────────────────────────
  {
    rule: 'AGENT_NO_AUTHOR_FIELD',
    title: 'Agent manifest: No author/publisher field',
    regex: /^\s*\{\s*"(?:name|id|version)":/m,
    severity: 'low',
    cwe: 'CWE-1059',
    owasp: 'ASI-10',
    confidence: 'low',
    description: 'Agent manifest has no author or publisher field — provenance cannot be established.',
    fix: 'Add "author", "publisher", or "maintainer" fields with contact information.',
  },

  // ── Attestation bypass patterns ────────────────────────────────────────────
  {
    rule: 'AGENT_SKIP_INTEGRITY_CHECK',
    title: 'Agent: Integrity check explicitly skipped',
    regex: /(?:skipIntegrityCheck\s*:\s*true|verifyIntegrity\s*:\s*false|integrity\s*:\s*false|bypassAttestation\s*:\s*true|noVerify\s*:\s*true)/gi,
    severity: 'critical',
    cwe: 'CWE-345',
    owasp: 'ASI-10',
    confidence: 'high',
    description: 'Code explicitly disables integrity checking — removes the primary defense against supply-chain attacks.',
    fix: 'Remove the integrity bypass flag and restore verification.',
  },
  {
    rule: 'AGENT_DYNAMIC_REQUIRE_MANIFEST',
    title: 'Agent: Dynamic require/import of manifest path from user input',
    regex: /(?:require|import)\s*\(\s*(?:req\.|request\.|body\.|params\.|process\.env\.[A-Z_]{3,})\s*\)/gi,
    severity: 'critical',
    cwe: 'CWE-706',
    owasp: 'ASI-10',
    confidence: 'medium',
    description: 'Manifest/module path resolved from external input — attacker can redirect load to a malicious file.',
    fix: 'Use a hardcoded manifest path or validate against an allowlist of safe paths.',
  },

  // ── No changelog / audit trail ────────────────────────────────────────────
  {
    rule: 'AGENT_NO_CHANGELOG_REFERENCE',
    title: 'Agent manifest: No changelog or audit trail reference',
    regex: /^\s*\{\s*(?:(?:"(?:name|id|version|description)":[^}]{0,200})){2,}\}/ms,
    severity: 'low',
    cwe: 'CWE-778',
    owasp: 'ASI-07',
    confidence: 'low',
    description: 'Agent manifest has no changelog, releaseNotes, or auditLog field — version changes cannot be audited.',
    fix: 'Add a "changelog" or "releaseNotes" URL field to the manifest.',
  },
];

// =============================================================================
// STRUCTURAL CHECKS
// =============================================================================

const MANIFEST_EXTENSIONS = new Set(['.json', '.yaml', '.yml']);

function checkManifestFields(filePath, content) {
  const findings = [];
  let manifest;

  try {
    // Only handle JSON manifests for deep structural checks
    if (!filePath.endsWith('.json')) return findings;
    manifest = JSON.parse(content);
  } catch {
    return findings;
  }

  const basename = path.basename(filePath);
  const isAgentManifest = /(?:agent[-_]manifest|agents|hermes\.config|openclaw)/i.test(basename);
  if (!isAgentManifest) return findings;

  // ── Missing integrity hash on tools array ─────────────────────────────────
  const tools = manifest.tools || manifest.skills || [];
  if (Array.isArray(tools)) {
    for (const tool of tools) {
      const remoteRef = (tool.url || tool.source || '');
      const isRemote = /^https?:\/\//i.test(remoteRef);
      if (isRemote && !tool.integrity && !tool.hash && !tool.checksum) {
        findings.push(createFinding({
          rule: 'AGENT_TOOL_NO_INTEGRITY',
          title: `Tool "${tool.name || tool.id || '?'}" has remote source but no integrity hash`,
          severity: 'high',
          file: filePath,
          line: 0,
          snippet: JSON.stringify(tool).slice(0, 120),
          cwe: 'CWE-494',
          owasp: 'ASI-10',
          confidence: 'high',
          description: `Tool "${tool.name || tool.id}" is loaded from a remote URL without an integrity constraint — can be silently replaced.`,
          fix: 'Add integrity: "sha256-<base64>" to each remotely-sourced tool definition.',
          category: 'supply-chain',
        }));
      }
    }
  }

  // ── Agent version unpinned (no exact semver) ──────────────────────────────
  const version = manifest.version || manifest.agentVersion;
  if (version && /[\^~*]/.test(String(version))) {
    findings.push(createFinding({
      rule: 'AGENT_MANIFEST_UNPINNED',
      title: 'Agent manifest version uses mutable range',
      severity: 'high',
      file: filePath,
      line: 0,
      snippet: `version: "${version}"`,
      cwe: 'CWE-1104',
      owasp: 'ASI-10',
      confidence: 'high',
      description: 'Manifest version field uses a range specifier — future installs may receive a different agent.',
      fix: 'Use an exact version string without ^ or ~.',
      category: 'supply-chain',
    }));
  }

  // ── Hermes-specific: missing hermes version pin ───────────────────────────
  const hermesVersion = manifest.hermes?.version || manifest.hermesVersion || manifest.dependencies?.['@nousresearch/hermes-agent'];
  if (hermesVersion && /[\^~*><=]/.test(String(hermesVersion))) {
    findings.push(createFinding({
      rule: 'HERMES_AGENT_UNPINNED',
      title: 'hermes-agent dependency not pinned in manifest',
      severity: 'high',
      file: filePath,
      line: 0,
      snippet: `hermes-agent: "${hermesVersion}"`,
      cwe: 'CWE-1104',
      owasp: 'ASI-10',
      confidence: 'high',
      description: 'The hermes-agent version is not pinned — a compromised minor release would affect all agents using this manifest.',
      fix: 'Pin to exact version: "@nousresearch/hermes-agent": "x.y.z"',
      category: 'supply-chain',
    }));
  }

  // ── No signature/provenance field at all ─────────────────────────────────
  const hasProvenance = manifest.signature || manifest.provenance || manifest.attestation || manifest.integrity;
  if (!hasProvenance && isAgentManifest) {
    findings.push(createFinding({
      rule: 'AGENT_NO_PROVENANCE',
      title: 'Agent manifest has no signature, provenance, or attestation field',
      severity: 'medium',
      file: filePath,
      line: 0,
      snippet: `(top-level keys: ${Object.keys(manifest).join(', ')})`,
      cwe: 'CWE-345',
      owasp: 'ASI-10',
      confidence: 'high',
      description: 'No attestation metadata found in manifest — cannot verify the manifest was produced by the expected pipeline.',
      fix: 'Add a "provenance" or "signature" field referencing a SLSA attestation or signed hash.',
      category: 'supply-chain',
    }));
  }

  return findings;
}

// =============================================================================
// AGENT
// =============================================================================

export class AgentAttestationAgent extends BaseAgent {
  constructor() {
    super('AgentAttestationAgent', 'Agent Attestation & Supply Chain — unsigned manifests, unpinned versions, missing provenance', 'supply-chain');
  }

  shouldRun() { return true; }

  async analyze(context) {
    const { files = [], rootPath } = context;
    const findings = [];

    for (const file of files) {
      const basename = path.basename(file);
      const ext = path.extname(file);

      // Only scan relevant files
      const isManifest = MANIFEST_EXTENSIONS.has(ext) && /(?:agent|manifest|hermes|openclaw|config)/i.test(basename);
      const isPackageJson = basename === 'package.json';
      const isSourceWithLoad = /\.[jt]s$/.test(ext);

      if (!isManifest && !isPackageJson && !isSourceWithLoad) continue;

      let content;
      try {
        content = fs.readFileSync(file, 'utf-8');
      } catch {
        continue;
      }

      // Skip huge source files that are unlikely to contain manifest loading
      if (isSourceWithLoad && content.length > 200_000) continue;

      // Pattern-based checks
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of PATTERNS) {
          pattern.regex.lastIndex = 0;
          if (pattern.regex.test(line)) {
            findings.push(createFinding({
              rule: pattern.rule,
              title: pattern.title,
              severity: pattern.severity,
              file,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              cwe: pattern.cwe,
              owasp: pattern.owasp,
              confidence: pattern.confidence || 'medium',
              description: pattern.description,
              fix: pattern.fix,
              category: 'supply-chain',
            }));
          }
        }
      }

      // Structural checks on manifest files
      if (isManifest || isPackageJson) {
        findings.push(...checkManifestFields(file, content));
      }
    }

    return findings;
  }
}
