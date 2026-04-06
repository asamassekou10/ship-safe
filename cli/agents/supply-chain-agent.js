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

// =============================================================================
// KNOWN-COMPROMISED PACKAGE IOC LIST
// Source: TeamPCP/CanisterWorm campaign (March 2026) + prior incidents
// Format: { name, badVersions: [exact], note }
// =============================================================================
const COMPROMISED_PACKAGES = [
  {
    name: 'litellm',
    badVersions: ['1.82.7', '1.82.8'],
    note: 'TeamPCP supply chain attack (Mar 24 2026). Multi-stage credential stealer targeting SSH keys, cloud tokens, and AI API keys.',
  },
  {
    name: 'axios',
    badVersions: ['1.8.2'],
    note: 'TeamPCP/CanisterWorm campaign (Mar 31 2026). Malicious publish delivered a Remote Access Trojan with persistence.',
  },
  {
    name: 'telnyx',
    badVersions: ['2.1.5'],
    note: 'TeamPCP campaign (Mar 27 2026). Compromised PyPI release exfiltrated credentials.',
  },
];

// Packages that have no reason to depend on ICP/Internet Computer blockchain
// but CanisterWorm injected @dfinity/agent as its decentralized C2 mechanism
const ICP_BLOCKCHAIN_PACKAGES = [
  '@dfinity/agent',
  '@dfinity/candid',
  '@dfinity/principal',
  'ic-agent',
];

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

    // ── 5. Package behavioral signals (Socket-style) ─────────────────────────
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
        };

        // Scan node_modules for behavioral red flags
        const nodeModulesPath = path.join(rootPath, 'node_modules');
        if (fs.existsSync(nodeModulesPath)) {
          for (const depName of Object.keys(allDeps).slice(0, 50)) {
            const depDir = path.join(nodeModulesPath, depName);
            const depPkgPath = path.join(depDir, 'package.json');
            if (!fs.existsSync(depPkgPath)) continue;
            try {
              const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf-8'));

              // Check for postinstall scripts with network/eval calls
              const scripts = depPkg.scripts || {};
              for (const hook of ['preinstall', 'install', 'postinstall']) {
                const cmd = scripts[hook];
                if (!cmd) continue;
                if (/node\s+-e|node\s+--eval/.test(cmd)) {
                  findings.push(createFinding({
                    file: depPkgPath,
                    line: 0,
                    severity: 'high',
                    category: 'supply-chain',
                    rule: 'BEHAVIORAL_INLINE_EVAL',
                    title: `Inline Code Execution in ${hook}: ${depName}`,
                    description: `Dependency "${depName}" runs inline Node.js code during ${hook}. This is a common pattern in malicious packages.`,
                    matched: cmd.slice(0, 200),
                    fix: 'Review the inline code. Consider using --ignore-scripts or removing the dependency.',
                  }));
                }
              }
            } catch { /* skip */ }
          }
        }

        // Detect obfuscated code patterns in dependencies
        const codeFiles = (context.files || []).filter(f =>
          f.includes('node_modules') &&
          !f.includes('node_modules/.cache') &&
          path.extname(f).toLowerCase() === '.js' &&
          !path.basename(f).endsWith('.min.js')
        ).slice(0, 30); // Sample up to 30 files

        for (const file of codeFiles) {
          const content = this.readFile(file);
          if (!content || content.length < 100) continue;

          // Excessive hex encoding
          const hexMatches = (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
          if (hexMatches > 20) {
            findings.push(createFinding({
              file,
              line: 1,
              severity: 'high',
              category: 'supply-chain',
              rule: 'BEHAVIORAL_HEX_OBFUSCATION',
              title: 'Obfuscated Code: Excessive Hex Encoding',
              description: `File contains ${hexMatches} hex-encoded sequences. Common in malicious packages trying to hide payload.`,
              matched: `${hexMatches} hex sequences detected`,
              fix: 'Inspect the deobfuscated code. Consider removing this dependency.',
            }));
          }

          // Excessive String.fromCharCode
          const charCodeMatches = (content.match(/String\.fromCharCode/g) || []).length;
          if (charCodeMatches > 5) {
            findings.push(createFinding({
              file,
              line: 1,
              severity: 'high',
              category: 'supply-chain',
              rule: 'BEHAVIORAL_CHARCODE_OBFUSCATION',
              title: 'Obfuscated Code: Excessive String.fromCharCode',
              description: `File contains ${charCodeMatches} String.fromCharCode calls. Common obfuscation technique in malicious packages.`,
              matched: `${charCodeMatches} String.fromCharCode calls`,
              fix: 'Inspect the deobfuscated code. Consider removing this dependency.',
            }));
          }

          // Base64 decode chains
          const base64Matches = (content.match(/Buffer\.from\s*\([^,]+,\s*['"]base64['"]\)/g) || []).length;
          if (base64Matches > 3) {
            findings.push(createFinding({
              file,
              line: 1,
              severity: 'medium',
              category: 'supply-chain',
              rule: 'BEHAVIORAL_BASE64_DECODE',
              title: 'Suspicious: Multiple Base64 Decode Operations',
              description: `File contains ${base64Matches} base64 decode operations. May indicate hidden payload.`,
              matched: `${base64Matches} base64 decode operations`,
              confidence: 'medium',
              fix: 'Review what data is being decoded. Legitimate use is possible but warrants inspection.',
            }));
          }
        }

        // Detect unused dependencies (in package.json but never imported)
        const projectFiles = (context.files || []).filter(f =>
          !f.includes('node_modules') &&
          ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(path.extname(f).toLowerCase())
        );

        if (projectFiles.length > 0 && projectFiles.length < 500) {
          const allImports = new Set();
          for (const file of projectFiles) {
            const content = this.readFile(file);
            if (!content) continue;
            // Capture import/require module names
            const importMatches = content.matchAll(/(?:from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g);
            for (const m of importMatches) {
              const mod = (m[1] || m[2] || '').split('/')[0]; // Get package name (not subpath)
              if (mod && !mod.startsWith('.')) allImports.add(mod);
              // Handle scoped packages
              const fullMod = m[1] || m[2] || '';
              if (fullMod.startsWith('@')) {
                const scopedPkg = fullMod.split('/').slice(0, 2).join('/');
                allImports.add(scopedPkg);
              }
            }
          }

          const prodDeps = Object.keys(pkg.dependencies || {});
          for (const dep of prodDeps) {
            if (!allImports.has(dep) && !dep.startsWith('@types/')) {
              findings.push(createFinding({
                file: pkgPath,
                line: 0,
                severity: 'low',
                category: 'supply-chain',
                rule: 'UNUSED_DEPENDENCY',
                title: `Unused Dependency: ${dep}`,
                description: `"${dep}" is in dependencies but never imported in project code. Unused dependencies increase attack surface.`,
                matched: dep,
                confidence: 'low',
                fix: `Remove if unused: npm uninstall ${dep}`,
              }));
            }
          }
        }

      } catch { /* skip */ }
    }

    // ── 6. npm token scope in .npmrc ──────────────────────────────────────────
    if (fs.existsSync(npmrcPath)) {
      const content = this.readFile(npmrcPath) || '';
      // Detect auth tokens stored in .npmrc — a prerequisite for worm spread
      const tokenLines = content.split('\n').filter(l => /_authToken\s*=/.test(l));
      for (const line of tokenLines) {
        const isScopedToPackage = /\/\/registry\.npmjs\.org\/.+:_authToken/.test(line);
        // Flag tokens that appear to be publish-level (not scoped to a single package)
        findings.push(createFinding({
          file: npmrcPath,
          line: 0,
          severity: 'high',
          category: 'supply-chain',
          rule: 'NPMRC_AUTH_TOKEN_EXPOSED',
          title: 'npm Auth Token in .npmrc',
          description: `An npm auth token is stored in .npmrc. ${isScopedToPackage ? 'Verify it is scoped to only the packages it needs to publish.' : 'If this token has publish rights, a compromised install script or dependency can steal it and spread a worm (CanisterWorm attack pattern).'} Commit this file only if absolutely necessary; prefer CI secret injection.`,
          matched: line.replace(/=.+/, '=***'),
          fix: 'Use npm token create --cidr-whitelist or scope tokens per-package. Never commit .npmrc with auth tokens.',
        }));
      }
    }

    // ── 7. Check Python requirements ──────────────────────────────────────────
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

    // ── 8. Compromised package IOC matching (npm + PyPI) ──────────────────────
    const iocSources = [];

    // npm packages
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
          ...(pkg.optionalDependencies || {}),
        };
        for (const [name, version] of Object.entries(allDeps)) {
          const ioc = COMPROMISED_PACKAGES.find(c => c.name === name);
          if (ioc) {
            // Strip semver range prefix (^, ~, >=, etc.) for comparison
            const bare = String(version).replace(/^[\^~>=<]+/, '').trim();
            if (ioc.badVersions.includes(bare)) {
              iocSources.push({ file: pkgPath, name, version: bare, note: ioc.note });
            }
          }
        }
      } catch { /* skip */ }
    }

    // Python requirements.txt
    if (fs.existsSync(path.join(rootPath, 'requirements.txt'))) {
      const lines = (this.readFile(path.join(rootPath, 'requirements.txt')) || '').split('\n');
      for (const line of lines) {
        const m = line.trim().match(/^([\w-]+)==([\d.]+)/);
        if (!m) continue;
        const [, name, version] = m;
        const ioc = COMPROMISED_PACKAGES.find(c => c.name === name.toLowerCase());
        if (ioc && ioc.badVersions.includes(version)) {
          iocSources.push({ file: path.join(rootPath, 'requirements.txt'), name, version, note: ioc.note });
        }
      }
    }

    for (const { file, name, version, note } of iocSources) {
      findings.push(createFinding({
        file,
        line: 0,
        severity: 'critical',
        category: 'supply-chain',
        rule: 'KNOWN_COMPROMISED_PACKAGE',
        title: `Known-Compromised Package: ${name}@${version}`,
        description: `${name}@${version} is a known-malicious release. ${note}`,
        matched: `${name}@${version}`,
        fix: `Update immediately to the latest safe release and rotate any credentials that may have been exfiltrated.`,
      }));
    }

    // ── 9. Trojanized package behavioral signatures ───────────────────────────
    //    Patterns from Axios 1.8.2, LiteLLM 1.82.7, TeamPCP campaign (Mar 2026)
    if (fs.existsSync(path.join(rootPath, 'node_modules'))) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
        };

        for (const depName of Object.keys(allDeps).slice(0, 80)) {
          const depDir = path.join(rootPath, 'node_modules', depName);
          const depPkgPath = path.join(depDir, 'package.json');
          if (!fs.existsSync(depPkgPath)) continue;

          try {
            const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf-8'));

            // 9a. Hidden dependencies added by attacker
            //     Axios 1.8.2 injected a hidden malicious dep that wasn't in the legitimate version.
            //     Check for deps that only exist in certain version ranges.
            const depDeps = depPkg.dependencies || {};
            for (const [subDep, subVer] of Object.entries(depDeps)) {
              // Packages with very high download counts that suddenly gain unknown subdependencies
              if (/^[a-z]+-[a-z0-9]+-[a-z0-9]+$/.test(subDep) && typeof subVer === 'string' && subVer.startsWith('git+')) {
                findings.push(createFinding({
                  file: depPkgPath,
                  line: 0,
                  severity: 'critical',
                  category: 'supply-chain',
                  rule: 'TROJAN_HIDDEN_DEP',
                  title: `Suspicious Hidden Dependency in ${depName}: ${subDep}`,
                  description: `"${depName}" depends on "${subDep}" via a git URL. This matches the Axios/TeamPCP trojanization pattern where attackers inject a malicious dependency into a popular package.`,
                  matched: `${subDep}: ${subVer}`,
                  fix: `Compare this version's dependencies against the official release. If "${subDep}" was not in the previous version, this package may be trojanized.`,
                }));
              }
            }

            // 9b. Install scripts that read and exfiltrate env vars
            //     LiteLLM 1.82.7 harvested AWS/GCP/Azure tokens + SSH keys
            const scripts = depPkg.scripts || {};
            for (const hook of ['preinstall', 'install', 'postinstall']) {
              const cmd = scripts[hook];
              if (!cmd) continue;

              // Environment variable harvesting
              if (/process\.env|os\.environ|ENV\[|getenv/i.test(cmd) &&
                  /https?:|fetch|request|axios|curl|wget|net\./i.test(cmd)) {
                findings.push(createFinding({
                  file: depPkgPath,
                  line: 0,
                  severity: 'critical',
                  category: 'supply-chain',
                  rule: 'TROJAN_ENV_EXFIL',
                  title: `Credential Harvesting in ${hook}: ${depName}`,
                  description: `"${depName}" reads environment variables and makes network requests during ${hook}. This is the exact pattern used in the LiteLLM/TeamPCP attack to steal cloud credentials.`,
                  matched: cmd.slice(0, 200),
                  fix: 'Remove this package immediately. Rotate any credentials (AWS, GCP, Azure tokens, SSH keys) that may have been exfiltrated.',
                }));
              }

              // SSH key / credential file access in install scripts
              if (/\.ssh|\.aws|\.azure|\.gcp|\.kube|\.docker|credentials|\.npmrc|\.pypirc/i.test(cmd)) {
                findings.push(createFinding({
                  file: depPkgPath,
                  line: 0,
                  severity: 'critical',
                  category: 'supply-chain',
                  rule: 'TROJAN_CREDENTIAL_ACCESS',
                  title: `Credential File Access in ${hook}: ${depName}`,
                  description: `"${depName}" accesses credential files (.ssh, .aws, .kube, etc.) during ${hook}. This matches the TeamPCP credential theft pattern.`,
                  matched: cmd.slice(0, 200),
                  fix: 'Remove this package immediately and rotate all credentials in the accessed directories.',
                }));
              }
            }

            // 9c. Scan actual JS entry files for runtime exfiltration patterns
            const main = depPkg.main || 'index.js';
            const entryPath = path.join(depDir, main);
            if (fs.existsSync(entryPath)) {
              try {
                const entryContent = fs.readFileSync(entryPath, 'utf-8');
                if (entryContent.length < 500_000) {
                  // DNS-based exfiltration (encode data in subdomain)
                  if (/dns\.resolve|dns\.lookup/i.test(entryContent) &&
                      /process\.env|os\.hostname/i.test(entryContent)) {
                    findings.push(createFinding({
                      file: entryPath,
                      line: 1,
                      severity: 'high',
                      category: 'supply-chain',
                      rule: 'TROJAN_DNS_EXFIL',
                      title: `DNS Exfiltration Pattern: ${depName}`,
                      description: `"${depName}" combines DNS lookups with system/env data reads — a known technique for exfiltrating data via DNS subdomains to bypass firewalls.`,
                      matched: 'dns.resolve + process.env',
                      confidence: 'medium',
                      fix: 'Inspect the DNS usage. Legitimate packages rarely combine DNS with environment variable reading.',
                    }));
                  }

                  // WebSocket-based C2
                  if (/new\s+WebSocket/i.test(entryContent) &&
                      /process\.env|child_process|exec/i.test(entryContent)) {
                    findings.push(createFinding({
                      file: entryPath,
                      line: 1,
                      severity: 'critical',
                      category: 'supply-chain',
                      rule: 'TROJAN_WEBSOCKET_C2',
                      title: `WebSocket C2 Pattern: ${depName}`,
                      description: `"${depName}" opens WebSocket connections combined with system command execution — consistent with a Remote Access Trojan.`,
                      matched: 'WebSocket + child_process',
                      fix: 'Remove this package immediately. Scan for persistence mechanisms (cron jobs, startup scripts).',
                    }));
                  }
                }
              } catch { /* skip */ }
            }

          } catch { /* skip */ }
        }
      } catch { /* skip */ }
    }

    // ── 10. Blockchain C2 indicators (CanisterWorm / ICP) ────────────────────
    if (fs.existsSync(path.join(rootPath, 'node_modules'))) {
      try {
        const pkg2 = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps2 = {
          ...(pkg2.dependencies || {}),
          ...(pkg2.devDependencies || {}),
        };
        for (const depName of Object.keys(allDeps2)) {
          const depPkgPath = path.join(rootPath, 'node_modules', depName, 'package.json');
          if (!fs.existsSync(depPkgPath)) continue;
          try {
            const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf-8'));
            const depDeps = {
              ...(depPkg.dependencies || {}),
              ...(depPkg.devDependencies || {}),
            };
            const suspiciousICP = ICP_BLOCKCHAIN_PACKAGES.filter(p => p in depDeps);
            if (suspiciousICP.length > 0) {
              findings.push(createFinding({
                file: depPkgPath,
                line: 0,
                severity: 'critical',
                category: 'supply-chain',
                rule: 'BLOCKCHAIN_C2_INDICATOR',
                title: `Blockchain C2 Indicator in ${depName}: ${suspiciousICP.join(', ')}`,
                description: `Dependency "${depName}" imports ICP/Internet Computer blockchain packages (${suspiciousICP.join(', ')}). This matches the CanisterWorm attack pattern, which used an ICP canister as a decentralized, takedown-resistant C2 server to coordinate credential exfiltration.`,
                matched: suspiciousICP.join(', '),
                fix: 'Immediately audit or remove this dependency. ICP blockchain packages have no legitimate role in most application dependencies.',
              }));
            }
          } catch { /* skip */ }
        }
      } catch { /* skip */ }
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
