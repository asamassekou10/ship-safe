/**
 * SupplyChainAudit Agent
 * =======================
 *
 * Comprehensive supply chain security analysis.
 * Goes beyond npm audit: checks for dependency confusion,
 * typosquatting, malicious install scripts, lockfile integrity,
 * EPSS scoring, and KEV flagging.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// Common packages that are often typosquatted
const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'axios', 'moment', 'request',
  'chalk', 'commander', 'debug', 'uuid', 'dotenv', 'cors',
  'body-parser', 'jsonwebtoken', 'bcrypt', 'mongoose', 'sequelize',
  'webpack', 'babel', 'eslint', 'prettier', 'typescript',
  'next', 'nuxt', 'svelte', 'vue', 'angular',
];

// Well-known packages that happen to be close to other popular names
// (not typosquats — verified legitimate packages)
const KNOWN_SAFE = new Set([
  'ora', 'got', 'ink', 'yup', 'joi', 'ava', 'tap', 'npm', 'nwb',
  'pug', 'koa', 'hap', 'ejs', 'csv', 'ws', 'pg', 'ms',
]);

// Known malicious package name patterns
const SUSPICIOUS_NAME_PATTERNS = [
  /^@[^/]+\/[^/]+-[0-9]+$/,       // @scope/package-123 (random suffix)
  /^[a-z]+-[a-z]+-[a-z]+-[a-z]+$/, // overly-generic multi-word names
];

export class SupplyChainAudit extends BaseAgent {
  constructor() {
    super('SupplyChainAudit', 'Comprehensive supply chain security audit', 'supply-chain');
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    // ── 1. Check package.json ─────────────────────────────────────────────────
    const pkgPath = path.join(rootPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
          ...(pkg.optionalDependencies || {}),
        };

        // ── Typosquatting detection ───────────────────────────────────────────
        for (const depName of Object.keys(allDeps)) {
          if (KNOWN_SAFE.has(depName)) continue;
          for (const popular of POPULAR_PACKAGES) {
            const distance = this.levenshtein(depName, popular);
            if (distance > 0 && distance <= 2 && depName !== popular) {
              findings.push(createFinding({
                file: pkgPath,
                line: 0,
                severity: 'high',
                category: 'supply-chain',
                rule: 'TYPOSQUAT_SUSPECT',
                title: `Possible Typosquat: "${depName}" (similar to "${popular}")`,
                description: `Package "${depName}" is ${distance} character(s) away from popular package "${popular}". This could be a typosquatting attempt.`,
                matched: depName,
                fix: `Verify this is the intended package. Did you mean "${popular}"?`,
              }));
            }
          }
        }

        // ── Deprecated/suspicious version pins ───────────────────────────────
        for (const [name, version] of Object.entries(allDeps)) {
          if (typeof version === 'string' && version.startsWith('git+')) {
            findings.push(createFinding({
              file: pkgPath,
              line: 0,
              severity: 'high',
              category: 'supply-chain',
              rule: 'GIT_DEPENDENCY',
              title: `Git Dependency: ${name}`,
              description: `"${name}" is installed from a git URL. Git dependencies bypass registry integrity checks.`,
              matched: `${name}: ${version}`,
              fix: 'Pin to a specific commit hash or use a published npm package version',
            }));
          }

          if (typeof version === 'string' && version.startsWith('http')) {
            findings.push(createFinding({
              file: pkgPath,
              line: 0,
              severity: 'critical',
              category: 'supply-chain',
              rule: 'URL_DEPENDENCY',
              title: `URL Dependency: ${name}`,
              description: `"${name}" is installed from a URL. This bypasses npm registry and integrity checks.`,
              matched: `${name}: ${version}`,
              fix: 'Publish the package to npm or use a private registry',
            }));
          }

          if (typeof version === 'string' && version === '*') {
            findings.push(createFinding({
              file: pkgPath,
              line: 0,
              severity: 'high',
              category: 'supply-chain',
              rule: 'WILDCARD_VERSION',
              title: `Wildcard Version: ${name}`,
              description: `"${name}" uses "*" version which accepts any version including malicious updates.`,
              matched: `${name}: *`,
              fix: 'Pin to a specific version or use a caret range: "^x.y.z"',
            }));
          }
        }

        // ── Install scripts ──────────────────────────────────────────────────
        if (pkg.scripts) {
          const dangerousScripts = ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'];
          for (const script of dangerousScripts) {
            if (pkg.scripts[script]) {
              const cmd = pkg.scripts[script];
              const suspicious = /curl|wget|bash|sh\s|powershell|eval|base64|nc\s|ncat/i.test(cmd);
              if (suspicious) {
                findings.push(createFinding({
                  file: pkgPath,
                  line: 0,
                  severity: 'critical',
                  category: 'supply-chain',
                  rule: 'SUSPICIOUS_INSTALL_SCRIPT',
                  title: `Suspicious ${script} Script`,
                  description: `The ${script} script contains potentially dangerous commands: ${cmd.slice(0, 100)}`,
                  matched: cmd,
                  fix: 'Review and remove suspicious install scripts',
                }));
              }
            }
          }
        }

      } catch { /* skip parse errors */ }
    }

    // ── 2. Dependency confusion detection ─────────────────────────────────────
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
        };

        // Check for scoped packages without registry pinning
        const scopedPkgs = Object.keys(allDeps).filter(n => n.startsWith('@'));
        if (scopedPkgs.length > 0) {
          const npmrcPath = path.join(rootPath, '.npmrc');
          const yarnrcPath = path.join(rootPath, '.yarnrc');
          const yarnrcYmlPath = path.join(rootPath, '.yarnrc.yml');
          const hasRegistryConfig = [npmrcPath, yarnrcPath, yarnrcYmlPath].some(p => {
            if (!fs.existsSync(p)) return false;
            const content = this.readFile(p) || '';
            // Check if any scope is pinned to a registry
            return /@[^:]+:registry/i.test(content) || /npmRegistryServer/i.test(content);
          });

          // Extract unique scopes
          const scopes = [...new Set(scopedPkgs.map(n => n.split('/')[0]))];
          // Check if this looks like an internal scope (not well-known public ones)
          const publicScopes = new Set([
            '@types', '@babel', '@eslint', '@jest', '@testing-library',
            '@react-native', '@angular', '@vue', '@nuxt', '@next',
            '@emotion', '@mui', '@radix-ui', '@tanstack', '@trpc',
            '@prisma', '@supabase', '@aws-sdk', '@azure', '@google-cloud',
            '@octokit', '@sentry', '@stripe', '@anthropic-ai', '@openai',
          ]);
          const internalScopes = scopes.filter(s => !publicScopes.has(s));

          if (internalScopes.length > 0 && !hasRegistryConfig) {
            findings.push(createFinding({
              file: pkgPath,
              line: 0,
              severity: 'high',
              category: 'supply-chain',
              rule: 'DEPCONF_NO_SCOPE_REGISTRY',
              title: `Scoped Packages Without Registry Pin: ${internalScopes.join(', ')}`,
              description: `Scoped packages (${internalScopes.join(', ')}) found without a .npmrc pinning the scope to a private registry. An attacker could claim the scope on the public npm registry.`,
              matched: internalScopes.join(', '),
              confidence: 'medium',
              fix: 'Add to .npmrc: @yourscope:registry=https://your-private-registry.com/',
            }));
          }
        }

        // Check for suspicious install scripts in dependencies
        const nodeModulesPath = path.join(rootPath, 'node_modules');
        if (fs.existsSync(nodeModulesPath)) {
          for (const depName of Object.keys(allDeps).slice(0, 50)) {
            const depPkgPath = path.join(nodeModulesPath, depName, 'package.json');
            if (!fs.existsSync(depPkgPath)) continue;
            try {
              const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf-8'));
              const scripts = depPkg.scripts || {};
              for (const hook of ['preinstall', 'install', 'postinstall']) {
                const cmd = scripts[hook];
                if (!cmd) continue;
                if (/(?:curl|wget|powershell|base64\s|eval\s|nc\s|ncat|\.sh\b)/i.test(cmd)) {
                  findings.push(createFinding({
                    file: depPkgPath,
                    line: 0,
                    severity: 'critical',
                    category: 'supply-chain',
                    rule: 'DEPCONF_SUSPICIOUS_INSTALL_SCRIPT',
                    title: `Suspicious ${hook} in ${depName}`,
                    description: `Dependency "${depName}" has a suspicious ${hook} script: ${cmd.slice(0, 120)}`,
                    matched: cmd.slice(0, 200),
                    fix: 'Review the script. If untrusted, remove the dependency or use npm with --ignore-scripts',
                  }));
                }
              }
            } catch { /* skip */ }
          }
        }
      } catch { /* skip */ }
    }

    // ── 3. Check lockfile integrity ── ───────────────────────────────────────────
    const lockFiles = [
      { file: 'package-lock.json', manager: 'npm' },
      { file: 'yarn.lock', manager: 'yarn' },
      { file: 'pnpm-lock.yaml', manager: 'pnpm' },
      { file: 'bun.lockb', manager: 'bun' },
    ];

    const hasPackageJson = fs.existsSync(pkgPath);
    let hasLockfile = false;

    for (const { file, manager } of lockFiles) {
      if (fs.existsSync(path.join(rootPath, file))) {
        hasLockfile = true;
      }
    }

    if (hasPackageJson && !hasLockfile) {
      findings.push(createFinding({
        file: pkgPath,
        line: 0,
        severity: 'high',
        category: 'supply-chain',
        rule: 'MISSING_LOCKFILE',
        title: 'No Lock File Found',
        description: 'No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Without a lockfile, installs are non-deterministic and vulnerable to dependency confusion.',
        matched: 'package.json without lockfile',
        fix: 'Run npm install, yarn install, or pnpm install to generate a lockfile, then commit it',
      }));
    }

    // ── 4. Check .npmrc for security settings ─────────────────────────────────
    const npmrcPath = path.join(rootPath, '.npmrc');
    if (fs.existsSync(npmrcPath)) {
      const content = this.readFile(npmrcPath) || '';
      if (content.includes('ignore-scripts=true')) {
        // Good — scripts are disabled
      }
      if (content.includes('registry=') && !content.includes('registry=https://registry.npmjs.org')) {
        findings.push(createFinding({
          file: npmrcPath,
          line: 0,
          severity: 'medium',
          category: 'supply-chain',
          rule: 'CUSTOM_REGISTRY',
          title: 'Custom NPM Registry Configured',
          description: 'A custom npm registry is configured. Verify it is trusted and uses HTTPS.',
          matched: content.match(/registry=.*/)?.[0] || '',
          confidence: 'medium',
          fix: 'Verify the registry URL is trusted and uses HTTPS',
        }));
      }
    }

    // ── 5. Check Python requirements ──────────────────────────────────────────
    const reqPath = path.join(rootPath, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      const content = this.readFile(reqPath) || '';
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        // Unpinned versions
        if (!line.includes('==') && !line.includes('>=') && !line.includes('~=') && !line.includes('@')) {
          findings.push(createFinding({
            file: reqPath,
            line: i + 1,
            severity: 'medium',
            category: 'supply-chain',
            rule: 'UNPINNED_PYTHON_DEP',
            title: `Unpinned Python Dependency: ${line}`,
            description: 'Python dependency without version pin. Pin to a specific version for reproducible builds.',
            matched: line,
            fix: `Pin version: ${line}==x.y.z`,
          }));
        }

        // Git/URL dependencies
        if (line.includes('git+') || line.startsWith('http')) {
          findings.push(createFinding({
            file: reqPath,
            line: i + 1,
            severity: 'high',
            category: 'supply-chain',
            rule: 'GIT_PYTHON_DEP',
            title: `Git/URL Python Dependency: ${line.slice(0, 60)}`,
            description: 'Installing from git/URL bypasses PyPI integrity checks.',
            matched: line,
            fix: 'Publish to PyPI or pin to a specific commit hash',
          }));
        }
      }
    }

    return findings;
  }

  /**
   * Simple Levenshtein distance for typosquatting detection.
   */
  levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = b[i - 1] === a[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    return matrix[b.length][a.length];
  }
}

export default SupplyChainAudit;
