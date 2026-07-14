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
 * This agent inspects the two auto-run entry points that other agents don't
 * cover in depth: npm `pre/postinstall`-class scripts and `binding.gyp`
 * (node-gyp) build files, for credential harvesting, obfuscated execution, and
 * destructive commands.
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

export class InstallGuardAgent extends BaseAgent {
  constructor() {
    super(
      'InstallGuardAgent',
      'Detects npm worm behaviors in lifecycle scripts and binding.gyp: credential harvesting, obfuscated execution, and destructive commands',
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
}

export default InstallGuardAgent;
