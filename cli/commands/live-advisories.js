/**
 * Live Advisory Feed
 * ===================
 *
 * Queries the GitHub Advisory Database and OSV.dev API for real-time
 * advisories on your exact dependency versions. Unlike static CVE checks,
 * this catches actively-compromised packages (Axios 1.8.2, LiteLLM 1.82.7)
 * within hours of publication.
 *
 * USAGE:
 *   ship-safe advisories .              # Check npm + PyPI deps
 *   ship-safe advisories . --ecosystem npm
 *   ship-safe advisories . --json
 *
 * APIs used:
 *   - OSV.dev (https://api.osv.dev) — aggregates GitHub Advisories, PyPI, npm
 *   - No API key needed — fully open, rate-limited to 1000 req/min
 */

import fs from 'fs';
import path from 'path';

// =============================================================================
// DEPENDENCY EXTRACTION
// =============================================================================

/**
 * Extract package names + versions from project manifests.
 * Returns: [{ name, version, ecosystem, file }]
 */
export function extractDependencies(rootPath) {
  const deps = [];

  // npm / Node.js
  const pkgPath = path.join(rootPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };
      for (const [name, versionRange] of Object.entries(allDeps)) {
        // Strip semver prefix (^, ~, >=)
        const version = String(versionRange).replace(/^[\^~>=<]+/, '').trim();
        if (/^\d/.test(version)) {
          deps.push({ name, version, ecosystem: 'npm', file: pkgPath });
        }
      }
    } catch { /* skip */ }
  }

  // Also check package-lock.json for pinned versions (more accurate)
  const lockPath = path.join(rootPath, 'package-lock.json');
  if (fs.existsSync(lockPath)) {
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
      const packages = lock.packages || {};
      for (const [pkgKey, info] of Object.entries(packages)) {
        if (!pkgKey || pkgKey === '') continue; // root entry
        const name = pkgKey.replace(/^node_modules\//, '');
        if (info.version && /^\d/.test(info.version)) {
          // Only add if not already present from package.json
          if (!deps.find(d => d.name === name && d.ecosystem === 'npm')) {
            deps.push({ name, version: info.version, ecosystem: 'npm', file: lockPath });
          }
        }
      }
    } catch { /* skip */ }
  }

  // Python
  const reqPath = path.join(rootPath, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const lines = fs.readFileSync(reqPath, 'utf-8').split('\n');
      for (const line of lines) {
        const m = line.trim().match(/^([\w-]+)==([\d.]+)/);
        if (m) {
          deps.push({ name: m[1], version: m[2], ecosystem: 'PyPI', file: reqPath });
        }
      }
    } catch { /* skip */ }
  }

  // Poetry (pyproject.toml)
  const pyprojectPath = path.join(rootPath, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      const depSection = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
      if (depSection) {
        const lines = depSection[1].split('\n');
        for (const line of lines) {
          const m = line.match(/^([\w-]+)\s*=\s*"([\d.]+)"/);
          if (m) {
            deps.push({ name: m[1], version: m[2], ecosystem: 'PyPI', file: pyprojectPath });
          }
        }
      }
    } catch { /* skip */ }
  }

  return deps;
}

// =============================================================================
// OSV.DEV API
// =============================================================================

/**
 * Query OSV.dev for known vulnerabilities affecting a specific package version.
 * Uses the batch query endpoint for efficiency.
 *
 * @param {{ name: string, version: string, ecosystem: string }[]} deps
 * @returns {Promise<object[]>} — Array of advisory objects
 */
export async function queryOSV(deps) {
  if (deps.length === 0) return [];

  // OSV batch query supports up to 1000 packages per request
  const batchSize = 1000;
  const allResults = [];

  for (let i = 0; i < deps.length; i += batchSize) {
    const batch = deps.slice(i, i + batchSize);
    const queries = batch.map(d => ({
      package: { name: d.name, ecosystem: d.ecosystem },
      version: d.version,
    }));

    try {
      const response = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
      });

      if (!response.ok) {
        throw new Error(`OSV API error: HTTP ${response.status}`);
      }

      const data = await response.json();
      const results = data.results || [];

      for (let j = 0; j < results.length; j++) {
        const vulns = results[j].vulns || [];
        for (const vuln of vulns) {
          allResults.push({
            id: vuln.id,
            summary: vuln.summary || '',
            severity: extractSeverity(vuln),
            package: batch[j].name,
            version: batch[j].version,
            ecosystem: batch[j].ecosystem,
            file: deps[i + j].file,
            aliases: vuln.aliases || [],
            published: vuln.published || null,
            modified: vuln.modified || null,
            isMalware: (vuln.id || '').startsWith('MAL-') ||
                       (vuln.summary || '').toLowerCase().includes('malicious') ||
                       (vuln.summary || '').toLowerCase().includes('malware'),
          });
        }
      }
    } catch (err) {
      // Network error — return what we have so far
      if (allResults.length === 0) {
        throw new Error(`Failed to reach OSV.dev: ${err.message}. Run with --offline to skip live checks.`);
      }
    }
  }

  return allResults;
}

/**
 * Extract the highest severity from an OSV vulnerability object.
 */
function extractSeverity(vuln) {
  // Check database_specific severity first
  if (vuln.database_specific?.severity) {
    return vuln.database_specific.severity.toLowerCase();
  }

  // Check CVSS in severity array
  const sevEntries = vuln.severity || [];
  for (const entry of sevEntries) {
    if (entry.type === 'CVSS_V3') {
      const score = parseFloat(entry.score) || 0;
      if (score >= 9.0) return 'critical';
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      return 'low';
    }
  }

  // Malware is always critical
  if ((vuln.id || '').startsWith('MAL-')) return 'critical';

  return 'medium';
}

// =============================================================================
// MAIN COMMAND
// =============================================================================

/**
 * Run the live advisory check.
 * Returns findings in ship-safe standard format.
 */
export async function runLiveAdvisories(rootPath, options = {}) {
  const deps = extractDependencies(rootPath);

  if (deps.length === 0) {
    return { advisories: [], deps: 0, checked: 0 };
  }

  // Filter by ecosystem if requested
  const filtered = options.ecosystem
    ? deps.filter(d => d.ecosystem.toLowerCase() === options.ecosystem.toLowerCase())
    : deps;

  const advisories = await queryOSV(filtered);

  // Sort: malware first, then by severity
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  advisories.sort((a, b) => {
    if (a.isMalware && !b.isMalware) return -1;
    if (!a.isMalware && b.isMalware) return 1;
    return (sevOrder[a.severity] || 2) - (sevOrder[b.severity] || 2);
  });

  return {
    advisories,
    deps: filtered.length,
    checked: filtered.length,
  };
}

export default { extractDependencies, queryOSV, runLiveAdvisories };
