/**
 * SlopSquatAgent — hallucinated-package (slopsquatting) detection
 * ==============================================================
 *
 * AI coding assistants confidently import packages that do not exist. Attackers
 * register those hallucinated names and ship malware under them ("slopsquatting"
 * / "HalluSquatting", 2026). The hallucinations are predictable — ~43% recur on
 * every run — so registering ahead of the next agent is a reliable supply-chain
 * vector.
 *
 * Detection is structural and offline: a bare module specifier that is imported
 * in source but is (a) not a Node builtin, (b) not declared in package.json, and
 * (c) not present in node_modules — i.e. referenced but never really installed.
 * That "phantom import" is exactly the slot an attacker registers. A small
 * curated list of known-hallucinated names raises confirmed cases to high.
 *
 * Maps to: CWE-1357 (Reliance on Insufficiently Trustworthy Component),
 *          CWE-829. Class: Supply Chain.
 */

import fs from 'fs';
import path from 'path';
import { builtinModules } from 'node:module';
import { BaseAgent, createFinding } from './base-agent.js';

const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

// Curated, high-confidence known hallucinations (populated from threat feeds).
// Kept deliberately small — the phantom-import engine is the primary detector.
const KNOWN_HALLUCINATED = new Set([
  'react-codeshift', // documented: model-conflated jscodeshift + react-codemod
]);

const IMPORT_RE = [
  /\bimport\s+(?:[\w*{}\s,]+\s+from\s+)?["']([^"']+)["']/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\bexport\s+(?:[\w*{}\s,]+\s+)?from\s+["']([^"']+)["']/g,
];

export class SlopSquatAgent extends BaseAgent {
  constructor() {
    super(
      'SlopSquatAgent',
      'Detects hallucinated / phantom package imports (slopsquatting) that attackers register with malware',
      'supply-chain'
    );
  }

  shouldRun(recon) {
    // JS/TS projects only for now (declared-deps + node_modules ground truth).
    if (!recon) return true;
    const langs = recon.languages instanceof Set ? recon.languages : new Set(recon.languages || []);
    return langs.has('javascript') || langs.has('typescript') || (recon.packageManagers || []).includes('npm');
  }

  async analyze(context) {
    const { rootPath } = context;
    const pkgPath = path.join(rootPath, 'package.json');
    if (!fs.existsSync(pkgPath)) return [];

    const declared = this._declaredDeps(pkgPath);
    const selfName = this._selfName(pkgPath);
    const nodeModules = path.join(rootPath, 'node_modules');
    const findings = [];
    const reported = new Set(); // pkg -> first finding only, to avoid noise

    for (const file of this.getFilesToScan(context)) {
      const ext = path.extname(file).toLowerCase();
      if (!['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'].includes(ext)) continue;

      const content = this.readFile(file);
      if (!content) continue;
      const lines = content.split('\n');

      for (const re of IMPORT_RE) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(content)) !== null) {
          const pkg = this._pkgName(m[1]);
          if (!pkg || reported.has(pkg)) continue;
          if (BUILTINS.has(pkg) || declared.has(pkg) || pkg === selfName) continue;
          if (this._installed(nodeModules, pkg)) continue;
          if (this._resolvesNearby(file, rootPath, pkg)) continue;

          reported.add(pkg);
          const line = content.slice(0, m.index).split('\n').length;
          const known = KNOWN_HALLUCINATED.has(pkg);
          findings.push(createFinding({
            file, line,
            column: (lines[line - 1] || '').indexOf(m[1]) + 1,
            severity: known ? 'high' : 'medium',
            category: 'supply-chain',
            rule: known ? 'SLOPSQUAT_KNOWN_HALLUCINATION' : 'SLOPSQUAT_PHANTOM_IMPORT',
            title: known
              ? 'Import of a known AI-hallucinated package name'
              : 'Undeclared import — verify before install (slopsquatting risk)',
            description: known
              ? `\`${pkg}\` is a documented AI package hallucination. Names like this are registered by attackers to serve malware to agents that install what the model invented.`
              : `\`${pkg}\` is imported here but is not a Node builtin, not declared in package.json, and not present in node_modules — it will not resolve as-is. If this name was suggested by an AI assistant, confirm it exists on the registry before installing: attackers register hallucinated names and ship malware under them (slopsquatting).`,
            matched: m[1],
            confidence: known ? 'high' : 'low',
            cwe: 'CWE-1357',
            fix: known
              ? `Remove the import of \`${pkg}\`. Verify the real package you intended (this name does not exist).`
              : `Confirm \`${pkg}\` is a real, intended dependency before installing it. If your AI assistant suggested it, verify it exists on the registry and matches a maintained project.`,
          }));
        }
      }
    }

    return findings;
  }

  _declaredDeps(pkgPath) {
    const set = new Set();
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        for (const name of Object.keys(pkg[field] || {})) set.add(name);
      }
    } catch { /* malformed package.json — treat as no declared deps */ }
    return set;
  }

  _selfName(pkgPath) {
    try { return JSON.parse(fs.readFileSync(pkgPath, 'utf-8')).name || null; } catch { return null; }
  }

  _pkgName(spec) {
    if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('#')) return null; // relative / absolute / subpath-import
    if (/^[a-zA-Z]+:/.test(spec) && !spec.startsWith('node:')) return null; // url / data: / bun:
    const clean = spec.startsWith('node:') ? spec : spec;
    const parts = clean.split('/');
    return clean.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  }

  _installed(nodeModules, pkg) {
    try { return fs.existsSync(path.join(nodeModules, ...pkg.split('/'))); } catch { return false; }
  }

  /**
   * Resolve an import the way Node does: walk up from the importing file,
   * checking each ancestor's package.json and node_modules until the project
   * root.
   *
   * Resolving only against the root pair mis-reads any repository with more
   * than one package in it. On hermes-agent — which has package.json files
   * under apps/, web/, website/, ui-tui/ and tests-js/ — every dependency of
   * every sub-package looked phantom, and the agent reported 137 of them as
   * possible AI hallucinations. A workspace dependency is the opposite of a
   * hallucination: it is declared, installed, and resolving fine.
   */
  _resolvesNearby(file, rootPath, pkg) {
    let dir = path.dirname(path.resolve(file));
    const stop = path.resolve(rootPath);

    for (;;) {
      if (this._installed(path.join(dir, 'node_modules'), pkg)) return true;

      const pkgJson = path.join(dir, 'package.json');
      if (fs.existsSync(pkgJson)) {
        if (this._declaredDeps(pkgJson).has(pkg)) return true;
        if (this._selfName(pkgJson) === pkg) return true;
      }

      if (dir === stop) return false;
      const parent = path.dirname(dir);
      if (parent === dir) return false;
      dir = parent;
    }
  }
}

export default SlopSquatAgent;
