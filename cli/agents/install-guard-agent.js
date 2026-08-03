/**
 * InstallGuardAgent — npm lifecycle-script & native-build worm hardening
 * =====================================================================
 *
 * The Shai-Hulud → Mini Shai-Hulud → Miasma lineage of self-propagating npm
 * worms (2025–2026) share a playbook: run before defenses engage via a
 * lifecycle script or a weaponized `binding.gyp`, harvest developer/CI
 * credentials (npm, GitHub, AWS, GCP, Azure, Vault, K8s), self-spread, then
 * turn destructive (wiping home directories) when no creds are found.
 *
 * This agent inspects auto-run package installation entry points that other
 * agents don't cover in depth: npm `pre/postinstall`-class scripts,
 * `binding.gyp` (node-gyp) build files, Python `setup.py`, and local PEP 517
 * build backends.
 *
 * (Plain `curl | bash` fake installers are covered by ClickFixAgent; this
 * agent targets the credential-theft / destruction / obfuscation behaviors.)
 *
 * Maps to: CWE-506 (Embedded Malicious Code), CWE-829, CWE-77. Class: Supply Chain.
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import { BaseAgent, createFinding } from './base-agent.js';
import { SKIP_DIRS } from '../utils/patterns.js';

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preuninstall', 'prepublishOnly'];

// Credential / secret stores a lifecycle script should never touch.
const CRED_PATHS = /(?:~|\$HOME|%USERPROFILE%)?[/\\]?\.(?:npmrc|netrc|aws[/\\]credentials|ssh[/\\]|docker[/\\]config|kube[/\\]|config[/\\]gcloud|gnupg|git-credentials)\b|\bnpm_token\b|GITHUB_TOKEN|AWS_(?:SECRET_)?ACCESS_KEY|VAULT_TOKEN/i;
// Obfuscated / dynamic execution.
const OBFUSCATED = /node\s+(?:-e|--eval)\b|\beval\s*\(|\batob\s*\(|Buffer\.from\s*\([^)]*['"]base64['"]|frombase64string|[|`$]\(.*base64/i;
// Destructive commands aimed at the home dir / root.
const DESTRUCTIVE = /\brm\s+-rf?\s+(?:~|\$HOME|\/\s|\/\*|\.\.?\/)|\brmdir\s+\/s|\bdel\s+\/[fsq]|\bRemove-Item\b[^\n]*-Recurse[^\n]*(?:HOME|~)/i;
// Network exfil of environment / secrets.
const EXFIL = /(?:curl|wget|fetch|Invoke-RestMethod|http[s]?:\/\/)[^\n]{0,120}(?:\$\{?(?:process\.)?env|printenv|\benv\b|\$AWS|\$GITHUB|token|secret)/i;

const PY_CREDENTIAL_ACCESS = /(?:\b(?:open|io\.open)\s*\([\s\S]{0,240}?(?:\.pypirc|\.netrc|\.aws|\.ssh|\.git-credentials|GOOGLE_APPLICATION_CREDENTIALS)|(?:\.pypirc|\.netrc|\.aws|\.ssh|\.git-credentials|GOOGLE_APPLICATION_CREDENTIALS)[\s\S]{0,180}?\.(?:open|read_text|read_bytes)\s*\(|\bos\.(?:getenv\s*\(|environ\s*\[)[\s\S]{0,100}?(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|PYPI_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS))/i;
const PY_NETWORK = /\b(?:requests|httpx)\.(?:post|put|patch)\s*\(|\burllib\.request\.(?:urlopen|Request)\s*\(|\bsocket\.(?:create_connection|socket)\s*\(|\b(?:os\.system|subprocess\.(?:run|call|Popen|check_call|check_output))\s*\([\s\S]{0,180}?\b(?:curl|wget)\b/i;
const PY_SECRET_SOURCE = /\bos\.(?:environ|getenv)\b|\b(?:token|secret|password|credential)s?\b|\.pypirc|\.netrc|\.aws|\.ssh|\.git-credentials/i;
// Local source-file exec is a common setup.py versioning idiom. Decoded,
// fetched, evaluated, or otherwise dynamic input remains suspicious.
const PY_DYNAMIC_EXEC = /\b(?:exec|eval)\s*\((?!\s*(?:open|io\.open)\s*\(\s*["'](?!https?:))/i;
const PY_DYNAMIC_IMPORT = /\b__import__\s*\(/i;
const PY_DECODER = /\b(?:base64\.b64decode|marshal\.loads|zlib\.decompress|codecs\.decode)\s*\(/i;
const PY_DESTRUCTIVE = /\bshutil\.rmtree\s*\(\s*(?:(?:pathlib\.)?Path\.home\s*\(\s*\)|os\.path\.expanduser\s*\(\s*["']~|os\.(?:environ|getenv)[\s\S]{0,80}?["']HOME)|\b(?:os\.system|subprocess\.(?:run|call|Popen|check_call|check_output))\s*\([\s\S]{0,240}?\brm\s+-rf?\s+(?:~|\$HOME|\/home\/|\/\s|\/\*)/i;

export class InstallGuardAgent extends BaseAgent {
  constructor() {
    super(
      'InstallGuardAgent',
      'Detects npm and Python install-hook worm behaviors: credential harvesting, exfiltration, obfuscated execution, and destructive commands',
      'supply-chain'
    );
  }

  shouldRun() {
    return true;
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    findings.push(...this._scanLifecycle(rootPath));
    findings.push(...await this._scanBindingGyp(rootPath));
    findings.push(...await this._scanPythonInstallHooks(rootPath));

    return findings;
  }

  _scanLifecycle(rootPath) {
    const pkgPath = path.join(rootPath, 'package.json');
    if (!fs.existsSync(pkgPath)) return [];
    let pkg;
    try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')); } catch { return []; }
    const scripts = pkg.scripts || {};
    const findings = [];

    for (const name of LIFECYCLE) {
      const cmd = scripts[name];
      if (typeof cmd !== 'string') continue;
      const checks = [
        { re: CRED_PATHS, rule: 'WORM_LIFECYCLE_CRED_HARVEST', sev: 'critical', what: 'reads a credential / secret store' },
        { re: EXFIL, rule: 'WORM_LIFECYCLE_EXFIL', sev: 'critical', what: 'exfiltrates environment variables or secrets over the network' },
        { re: DESTRUCTIVE, rule: 'WORM_LIFECYCLE_DESTRUCTIVE', sev: 'high', what: 'runs a destructive command against the home directory' },
        { re: OBFUSCATED, rule: 'WORM_LIFECYCLE_OBFUSCATED_EXEC', sev: 'high', what: 'runs obfuscated / dynamically-evaluated code' },
      ];
      for (const c of checks) {
        if (c.re.test(cmd)) {
          findings.push(createFinding({
            file: pkgPath, line: 0, severity: c.sev, category: 'supply-chain',
            rule: c.rule,
            title: `npm ${name} script ${c.what}`,
            description: `The \`${name}\` lifecycle script ${c.what}. Lifecycle scripts run automatically on install, before most defenses engage — the entry point used by the Shai-Hulud / Miasma npm worms.`,
            matched: cmd.slice(0, 120),
            confidence: 'high', cwe: 'CWE-506',
            fix: `Remove this behavior from \`${name}\`. Installation must never read credentials, exfiltrate env, run obfuscated code, or delete files.`,
          }));
        }
      }
    }
    return findings;
  }

  async _scanBindingGyp(rootPath) {
    const files = await fg(['**/binding.gyp'], {
      cwd: rootPath, absolute: true, onlyFiles: true,
      ignore: Array.from(SKIP_DIRS).map((d) => `**/${d}/**`),
    });
    const findings = [];
    const SUSPICIOUS = /(?:curl|wget)\b|https?:\/\/[^\s"']+\.(?:sh|js|py|exe)|node\s+-e\b|child_process|frombase64string|Buffer\.from\s*\([^)]*base64|\beval\s*\(|\.npmrc|\.aws|\.ssh/i;

    for (const file of files) {
      const content = this.readFile(file);
      if (!content) continue;
      // A binding.gyp with an "actions"/"action" that runs network/obfuscated
      // code — not plain codegen — is a node-gyp worm launcher.
      if (/["']actions?["']/.test(content) && SUSPICIOUS.test(content)) {
        const m = content.match(SUSPICIOUS);
        const line = m ? content.slice(0, content.indexOf(m[0])).split('\n').length : 0;
        findings.push(createFinding({
          file, line, severity: 'high', category: 'supply-chain',
          rule: 'WORM_BINDING_GYP',
          title: 'Weaponized binding.gyp (node-gyp) action',
          description: 'This binding.gyp defines a build action that fetches remote content, spawns a subprocess, or runs obfuscated code — not native compilation. node-gyp executes it automatically during `npm install` (the binding.gyp / Miasma worm technique).',
          matched: (m && m[0]) ? m[0].slice(0, 80) : 'binding.gyp action',
          confidence: 'medium', cwe: 'CWE-829',
          fix: 'Inspect the binding.gyp action. A native addon build should only compile sources — never download, spawn shells, or evaluate encoded strings.',
        }));
      }
    }
    return findings;
  }

  async _scanPythonInstallHooks(rootPath) {
    const globOptions = {
      cwd: rootPath,
      absolute: true,
      onlyFiles: true,
      ignore: Array.from(SKIP_DIRS).map((d) => `**/${d}/**`),
    };
    const setupFiles = await fg(['**/setup.py'], globOptions);
    const pyprojectFiles = await fg(['**/pyproject.toml'], globOptions);

    const entrypoints = new Set(setupFiles.map((file) => path.resolve(file)));
    for (const pyproject of pyprojectFiles) {
      const content = this.readFile(pyproject);
      if (!content) continue;
      for (const backendFile of this._resolveLocalBuildBackend(pyproject, content)) {
        entrypoints.add(backendFile);
      }
    }

    const findings = [];
    for (const file of entrypoints) {
      const content = this.readFile(file);
      if (!content) continue;

      const checks = [
        {
          match: this._findMatch(content, PY_CREDENTIAL_ACCESS),
          rule: 'WORM_PYTHON_INSTALL_CRED_HARVEST', severity: 'critical',
          title: 'Python install hook accesses a credential store',
          description: 'This Python package installation entry point reads a developer or CI credential store. Build hooks run during installation and must not access user credentials.',
          matched: 'credential-store access', cwe: 'CWE-506',
          fix: 'Remove credential access from the package build hook. Build steps must use only declared source files and explicitly provided build inputs.',
        },
        {
          match: this._findNearbyMatch(content, PY_NETWORK, PY_SECRET_SOURCE),
          rule: 'WORM_PYTHON_INSTALL_EXFIL', severity: 'critical',
          title: 'Python install hook may exfiltrate secrets',
          description: 'This Python package installation entry point combines an outbound network operation with environment, token, or credential data.',
          matched: 'network request with secret source', cwe: 'CWE-506',
          fix: 'Remove network transmission of environment or credential data. Package builds must be offline and reproducible.',
        },
        {
          match: this._findMatch(content, PY_DYNAMIC_EXEC) || this._findNearbyMatch(content, PY_DYNAMIC_IMPORT, PY_DECODER),
          rule: 'WORM_PYTHON_INSTALL_OBFUSCATED_EXEC', severity: 'high',
          title: 'Python install hook uses dynamic or decoded execution',
          description: 'This Python package installation entry point uses exec/eval, or combines dynamic import with decoded or decompressed content.',
          matched: 'dynamic or decoded execution', cwe: 'CWE-506',
          fix: 'Replace encoded dynamic execution with auditable, static build code.',
        },
        {
          match: this._findMatch(content, PY_DESTRUCTIVE),
          rule: 'WORM_PYTHON_INSTALL_DESTRUCTIVE', severity: 'high',
          title: 'Python install hook deletes home-directory data',
          description: 'This Python package installation entry point runs a destructive operation against the user home directory.',
          matched: 'destructive home-directory operation', cwe: 'CWE-77',
          fix: 'Remove destructive filesystem operations from the package build hook.',
        },
      ];

      for (const check of checks) {
        if (!check.match) continue;
        findings.push(createFinding({
          file,
          line: content.slice(0, check.match.index).split('\n').length,
          severity: check.severity,
          category: 'supply-chain',
          rule: check.rule,
          title: check.title,
          description: check.description,
          matched: check.matched,
          confidence: 'high',
          cwe: check.cwe,
          fix: check.fix,
        }));
      }
    }
    return findings;
  }

  _resolveLocalBuildBackend(pyproject, content) {
    const buildSystem = content.match(/^\s*\[build-system\]\s*$([\s\S]*?)(?=^\s*\[[^\]]+\]\s*$|(?![\s\S]))/mi)?.[1];
    if (!buildSystem) return [];

    const backend = buildSystem.match(/^\s*build-backend\s*=\s*["']([^"']+)["']/mi)?.[1]?.split(':')[0];
    const backendPathValue = buildSystem.match(/^\s*backend-path\s*=\s*\[([\s\S]*?)\]/mi)?.[1];
    if (!backend || backendPathValue === undefined) return [];

    const projectDir = path.dirname(pyproject);
    const backendPaths = Array.from(backendPathValue.matchAll(/["']([^"']+)["']/g), (match) => match[1]);
    const modulePath = backend.split('.').join(path.sep);
    const resolved = [];

    for (const relativeBackendPath of backendPaths) {
      const searchRoot = path.resolve(projectDir, relativeBackendPath);
      if (!this._isWithin(projectDir, searchRoot)) continue;
      for (const candidate of [
        path.resolve(searchRoot, `${modulePath}.py`),
        path.resolve(searchRoot, modulePath, '__init__.py'),
      ]) {
        if (this._isWithin(projectDir, candidate) && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          resolved.push(candidate);
        }
      }
    }
    return resolved;
  }

  _isWithin(parent, candidate) {
    const relative = path.relative(path.resolve(parent), path.resolve(candidate));
    return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
  }

  _findMatch(content, primary) {
    const match = content.match(primary);
    if (!match) return null;
    return { index: match.index || 0 };
  }

  _findNearbyMatch(content, primary, secondary, radius = 500) {
    const flags = primary.flags.includes('g') ? primary.flags : `${primary.flags}g`;
    const re = new RegExp(primary.source, flags);
    let match;
    while ((match = re.exec(content)) !== null) {
      const start = Math.max(0, match.index - radius);
      const end = Math.min(content.length, match.index + match[0].length + radius);
      if (secondary.test(content.slice(start, end))) return { index: match.index };
      if (match[0].length === 0) re.lastIndex++;
    }
    return null;
  }
}

export default InstallGuardAgent;
