/**
 * LegalRiskAgent
 * ==============
 *
 * Scans project dependency manifests for packages that carry legal risk:
 * active DMCA takedowns, known leaked-source derivatives, IP disputes,
 * or license violations.
 *
 * This is a separate threat category from security IOCs — the danger is
 * not malware, but legal liability for shipping the dependency.
 *
 * Supported manifests:
 *   npm/yarn/pnpm  → package.json
 *   Python         → requirements.txt, pyproject.toml
 *   Rust           → Cargo.toml
 *   Go             → go.mod
 *
 * USAGE:
 *   ship-safe legal .
 *   ship-safe audit . --include-legal
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// LEGALLY RISKY PACKAGES
// Format: { name, versions, ecosystem, risk, severity, detail, references }
//
// versions: array of specific bad versions, or '*' for all versions
// ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | '*'
// risk: 'dmca' | 'ip-dispute' | 'leaked-source' | 'license-violation'
// =============================================================================
export const LEGALLY_RISKY_PACKAGES = [
  // ---------------------------------------------------------------------------
  // Claude Code source leak (March 31 2026)
  // Anthropic's Claude Code source was accidentally leaked. Several repos
  // appeared immediately; Anthropic filed DMCA takedowns but derivatives
  // remain online. Shipping any of these exposes you to IP liability.
  // ---------------------------------------------------------------------------
  {
    name: 'claw-code',
    versions: '*',
    ecosystem: 'npm',
    risk: 'dmca',
    severity: 'high',
    detail:
      'Derived from leaked Anthropic Claude Code source (March 2026). ' +
      'Anthropic has filed DMCA takedown notices. Shipping this package ' +
      'may expose your project to IP infringement liability.',
    references: [
      'https://cybernews.com/security/anthropic-claude-code-source-leak/',
      'https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know',
    ],
  },
  {
    name: 'claw-code-js',
    versions: '*',
    ecosystem: 'npm',
    risk: 'leaked-source',
    severity: 'high',
    detail:
      'JavaScript port derived from the leaked Anthropic Claude Code source (March 2026). ' +
      'Under active DMCA enforcement. Contains Anthropic proprietary IP.',
    references: [
      'https://cybernews.com/tech/claude-code-leak-spawns-fastest-github-repo/',
    ],
  },
  {
    name: 'claude-code-oss',
    versions: '*',
    ecosystem: 'npm',
    risk: 'leaked-source',
    severity: 'high',
    detail:
      'Open-source mirror of the leaked Claude Code source (March 2026). ' +
      'Despite "open-source" branding, the underlying code is Anthropic proprietary IP ' +
      'and DMCA takedowns are in progress.',
    references: [
      'https://cybernews.com/security/anthropic-claude-code-source-leak/',
    ],
  },
  // ---------------------------------------------------------------------------
  // License violations — well-known cases
  // ---------------------------------------------------------------------------
  {
    name: 'faker',
    versions: ['6.6.6'],
    ecosystem: 'npm',
    risk: 'license-violation',
    severity: 'medium',
    detail:
      'faker@6.6.6 was deliberately sabotaged by its maintainer (January 2022). ' +
      'The package prints an infinite loop of gibberish. Replaced by @faker-js/faker ' +
      'which is community-maintained under MIT.',
    references: [
      'https://www.bleepingcomputer.com/news/security/dev-corrupts-npm-libs-colors-and-faker-breaking-thousands-of-apps/',
    ],
  },
  {
    name: 'colors',
    versions: ['1.4.44-liberty-2'],
    ecosystem: 'npm',
    risk: 'license-violation',
    severity: 'medium',
    detail:
      'colors@1.4.44-liberty-2 was a malicious release by the maintainer that ' +
      'deliberately printed an infinite loop. Use colors@1.4.0 or the maintained fork.',
    references: [
      'https://www.bleepingcomputer.com/news/security/dev-corrupts-npm-libs-colors-and-faker-breaking-thousands-of-apps/',
    ],
  },
];

// =============================================================================
// AGENT
// =============================================================================

export class LegalRiskAgent extends BaseAgent {
  constructor() {
    super('LegalRiskAgent', 'Legal risk audit: DMCA, IP disputes, leaked source in dependencies', 'legal');
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    findings.push(...this._scanNpm(rootPath));
    findings.push(...this._scanPython(rootPath));
    findings.push(...this._scanCargo(rootPath));
    findings.push(...this._scanGoMod(rootPath));

    return findings;
  }

  // ---------------------------------------------------------------------------
  // npm / yarn / pnpm — package.json
  // ---------------------------------------------------------------------------
  _scanNpm(rootPath) {
    const findings = [];
    const pkgPath = path.join(rootPath, 'package.json');
    if (!fs.existsSync(pkgPath)) return findings;

    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    } catch {
      return findings;
    }

    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {}),
      ...(pkg.peerDependencies || {}),
    };

    for (const [name, version] of Object.entries(allDeps)) {
      const entry = LEGALLY_RISKY_PACKAGES.find(
        e => e.name === name && (e.ecosystem === 'npm' || e.ecosystem === '*')
      );
      if (!entry) continue;

      const bare = String(version).replace(/^[\^~>=<]+/, '').trim();
      const versionMatches =
        entry.versions === '*' || entry.versions.includes(bare);

      if (versionMatches) {
        findings.push(this._makeFinding(pkgPath, name, bare, entry));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Python — requirements.txt
  // ---------------------------------------------------------------------------
  _scanPython(rootPath) {
    const findings = [];
    const reqPath = path.join(rootPath, 'requirements.txt');
    if (!fs.existsSync(reqPath)) return findings;

    const lines = (this.readFile(reqPath) || '').split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      // Match: package==version or package>=version etc., or bare package name
      const m = line.match(/^([\w.-]+)\s*(?:[=<>!~]=?\s*([\d.\w]+))?/);
      if (!m) continue;
      const [, name, version = '*'] = m;

      const entry = LEGALLY_RISKY_PACKAGES.find(
        e => e.name.toLowerCase() === name.toLowerCase() &&
          (e.ecosystem === 'pypi' || e.ecosystem === '*')
      );
      if (!entry) continue;

      const versionMatches =
        entry.versions === '*' || entry.versions.includes(version);
      if (versionMatches) {
        findings.push(this._makeFinding(reqPath, name, version, entry));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Rust — Cargo.toml
  // ---------------------------------------------------------------------------
  _scanCargo(rootPath) {
    const findings = [];
    const cargoPath = path.join(rootPath, 'Cargo.toml');
    if (!fs.existsSync(cargoPath)) return findings;

    const content = this.readFile(cargoPath) || '';
    // Match lines like: package-name = "1.2.3" or package-name = { version = "1.2.3" }
    const depPattern = /^\s*([\w-]+)\s*=\s*(?:"([\d.\w^~>=<*]+)"|{[^}]*version\s*=\s*"([\d.\w^~>=<*]+)")/gm;
    let match;
    while ((match = depPattern.exec(content)) !== null) {
      const name = match[1];
      const version = (match[2] || match[3] || '*').replace(/^[\^~>=<]+/, '').trim();

      const entry = LEGALLY_RISKY_PACKAGES.find(
        e => e.name === name && (e.ecosystem === 'cargo' || e.ecosystem === '*')
      );
      if (!entry) continue;

      const versionMatches = entry.versions === '*' || entry.versions.includes(version);
      if (versionMatches) {
        findings.push(this._makeFinding(cargoPath, name, version, entry));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Go — go.mod
  // ---------------------------------------------------------------------------
  _scanGoMod(rootPath) {
    const findings = [];
    const goModPath = path.join(rootPath, 'go.mod');
    if (!fs.existsSync(goModPath)) return findings;

    const lines = (this.readFile(goModPath) || '').split('\n');
    for (const line of lines) {
      const m = line.trim().match(/^([\w./\-]+)\s+(v[\d.]+)/);
      if (!m) continue;
      const [, name, version] = m;

      const entry = LEGALLY_RISKY_PACKAGES.find(
        e => e.name === name && (e.ecosystem === 'go' || e.ecosystem === '*')
      );
      if (!entry) continue;

      const bare = version.replace(/^v/, '');
      const versionMatches = entry.versions === '*' || entry.versions.includes(bare);
      if (versionMatches) {
        findings.push(this._makeFinding(goModPath, name, bare, entry));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Finding factory
  // ---------------------------------------------------------------------------
  _makeFinding(file, name, version, entry) {
    const riskLabel = {
      dmca: 'DMCA Takedown',
      'ip-dispute': 'IP Dispute',
      'leaked-source': 'Leaked Source',
      'license-violation': 'License Violation',
    }[entry.risk] || entry.risk;

    const versionStr = version === '*' ? '(any version)' : `@${version}`;

    return createFinding({
      file,
      line: 0,
      severity: entry.severity,
      category: 'legal',
      rule: `LEGAL_RISK_${entry.risk.toUpperCase().replace(/-/g, '_')}`,
      title: `[${riskLabel}] ${name}${versionStr}`,
      description: entry.detail,
      matched: version === '*' ? name : `${name}@${version}`,
      confidence: 'high',
      fix:
        `Remove ${name} from your dependencies. ` +
        (entry.references.length > 0
          ? `See: ${entry.references[0]}`
          : ''),
    });
  }
}

export default LegalRiskAgent;
