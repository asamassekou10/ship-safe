/**
 * ClickFixAgent — paste-and-run social-engineering detector
 * =========================================================
 *
 * ClickFix (and its CrashFix / fake-CAPTCHA variants) tricks a victim into
 * copying text and running it via a keystroke sequence — "to fix this error,
 * press Win+R, Ctrl+V, Enter." Activity surged ~517% into 2026 and is now aimed
 * squarely at developers: a malicious npm package posed as an OpenClaw installer
 * (Mar 2026), showing a fake CLI before prompting for the system password.
 *
 * This is the promotion of the ClickFix rule (originally embedded in
 * RobloxSecurityAgent) into a first-class, cross-platform detector. It runs
 * over anything a developer might read or execute — docs, HTML, source, and
 * especially npm lifecycle scripts (`preinstall` / `postinstall`) where a fake
 * installer would live.
 *
 * Maps to: CWE-1357 (Insufficiently Trustworthy Component), CWE-506, CWE-77.
 *          Class: Supply Chain.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// Fake-error / verification framing that fronts the lure.
const FRAMING = /(?:error\s*\d{3}|something\s+went\s+wrong|verify\s+(?:you\s+are|that\s+you'?re)\s+(?:a\s+)?human|i'?m\s+not\s+a\s+robot|confirm\s+you'?re\s+human|to\s+(?:fix|resolve|continue|proceed)\b|cloudflare\s+(?:check|verification)|complete\s+the\s+(?:captcha|verification))/i;

// The paste-and-run action: keystroke choreography or an explicit run target.
const ACTION = /(?:ctrl\s*\+\s*c\b[\s\S]{0,180}ctrl\s*\+\s*v|win(?:dows)?\s*\+\s*r|cmd\s*\+\s*(?:space|v)|shift\s*\+\s*f5|(?:run|open)\s+(?:the\s+)?(?:command\s+bar|terminal|run\s+dialog|powershell)|paste\s+(?:it|this|the\s+(?:text|code|command)))/i;

// PowerShell download-cradle often hidden in the pasted payload.
const PS_CRADLE = /\b(?:i(?:ex|nvoke-expression)|iwr|invoke-webrequest|new-object\s+net\.webclient|downloadstring|frombase64string)\b/i;

// Files worth scanning for a lure (docs/pages/source a dev reads or runs).
const SCAN_EXT = new Set([
  '.md', '.txt', '.html', '.htm', '.mdx', '.rst',
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.sh', '.bash', '.ps1', '.bat', '.cmd', '.py', '.lua', '.luau', '.rbxmx', '.rbxlx',
]);

// npm lifecycle scripts a fake installer would abuse.
const RISKY_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare', 'preuninstall'];

export class ClickFixAgent extends BaseAgent {
  constructor() {
    super(
      'ClickFixAgent',
      'Detects ClickFix / fake-CAPTCHA paste-and-run social-engineering lures and fake installers',
      'supply-chain'
    );
  }

  shouldRun() {
    return true;
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    for (const file of this.getFilesToScan(context)) {
      const ext = path.extname(file).toLowerCase();
      if (SCAN_EXT.has(ext)) findings.push(...this._scanLure(file));
    }

    // npm lifecycle scripts that pull-and-run a remote script (fake installer).
    findings.push(...this._scanPackageScripts(rootPath));

    return findings;
  }

  _scanLure(file) {
    const content = this.readFile(file);
    if (!content || !FRAMING.test(content)) return [];

    const idx = content.search(FRAMING);
    // framing and action must sit near each other
    const near = content.slice(Math.max(0, idx - 240), idx + 700);
    if (!ACTION.test(near)) return [];

    const line = content.slice(0, idx).split('\n').length;
    const hasCradle = PS_CRADLE.test(near);
    return [createFinding({
      file, line, severity: 'high', category: 'supply-chain',
      rule: 'CLICKFIX_PASTE_RUN',
      title: 'ClickFix paste-and-run social-engineering lure',
      description: `A fake error / human-verification prompt appears next to an instruction to copy content and run it via a keystroke sequence (Ctrl+C→Ctrl+V→Enter, Win+R, command bar).${hasCradle ? ' The nearby payload contains a PowerShell download-cradle.' : ''} No legitimate tool asks a developer to paste and run code to recover from an error.`,
      matched: (content.slice(idx).match(FRAMING) || [''])[0].slice(0, 80),
      confidence: hasCradle ? 'high' : 'medium',
      cwe: 'CWE-1357',
      fix: 'Do not run the instructed command. Remove this lure; treat the page/asset that rendered it as compromised.',
    })];
  }

  _scanPackageScripts(rootPath) {
    const pkgPath = path.join(rootPath, 'package.json');
    if (!fs.existsSync(pkgPath)) return [];
    let pkg;
    try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')); } catch { return []; }
    const scripts = pkg.scripts || {};
    const findings = [];

    for (const name of RISKY_SCRIPTS) {
      const cmd = scripts[name];
      if (typeof cmd !== 'string') continue;
      // Remote fetch piped straight into a shell/interpreter.
      if (/(?:curl|wget|iwr|invoke-webrequest)\b[^\n|;&]{0,200}[|;&]{1,2}\s*(?:sudo\s+)?(?:bash|sh|zsh|node|python3?|pwsh|powershell|iex)\b/i.test(cmd)) {
        findings.push(createFinding({
          file: pkgPath, line: 0, severity: 'high', category: 'supply-chain',
          rule: 'CLICKFIX_FAKE_INSTALLER',
          title: `npm ${name} script downloads and runs a remote script`,
          description: `The \`${name}\` lifecycle script fetches a remote script and pipes it into a shell. This runs automatically on install — the mechanism behind fake-installer packages (e.g. the OpenClaw ClickFix npm package).`,
          matched: cmd.slice(0, 100),
          confidence: 'high', cwe: 'CWE-506',
          fix: `Remove the download-and-run from \`${name}\`. Vendor and pin any install steps; never pipe a network fetch into a shell in a lifecycle script.`,
        }));
      }
    }
    return findings;
  }
}

export default ClickFixAgent;
