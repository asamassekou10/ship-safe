/**
 * TrustBoundaryAgent — AI coding-agent trust-boundary attacks
 * ===========================================================
 *
 * As coding agents gained the ability to act, a malicious repository became an
 * execution primitive. Two 2026 techniques define the risk:
 *
 *   1. GhostApproval (Wiz, Jul 2026) — a repo file with an innocuous name
 *      (e.g. `project_settings.json`) is actually a **symlink** pointing at a
 *      sensitive path such as `~/.ssh/authorized_keys`. When the agent "sets up
 *      the workspace" and writes what it thinks is config, it writes an
 *      attacker-controlled key into the real target. Hit 6 major assistants.
 *
 *   2. Friendly Fire (AI Now, Jul 2026) — a repo's own docs / agent-context
 *      files instruct the agent to run a command as part of setup or its
 *      security-review pass, turning the review step into the exploit.
 *
 * This agent inspects the repo for both: symlinks that escape the repo or point
 * at sensitive targets, and agent-ingested files that direct running code.
 *
 * Maps to: CWE-59 (Link Following), CWE-61 (UNIX Symbolic Link), CWE-77.
 *          OWASP Agentic 2026: Tool Use, Human-Agent Trust. Class: Agentic.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';
import { SKIP_DIRS } from '../utils/patterns.js';

// Sensitive targets a symlink should never point at from inside a repo.
const SENSITIVE_TARGET = [
  /(^|\/)\.ssh(\/|$)/i, /authorized_keys/i, /id_rsa|id_ed25519|id_ecdsa/i,
  /(^|\/)\.aws(\/|$)/i, /(^|\/)credentials$/i,
  /(^|\/)\.gnupg(\/|$)/i, /(^|\/)\.kube(\/|$)/i, /(^|\/)\.docker(\/|$)/i,
  /(^|\/)\.npmrc$/i, /(^|\/)\.netrc$/i, /(^|\/)\.pypirc$/i,
  /(^|\/)\.gitconfig$/i, /(^|\/)\.git-credentials$/i,
  /(^|\/)\.env(\.[\w-]+)?$/i,
  /(^|\/)\.bash_history$|(^|\/)\.zsh_history$/i,
  /^\/etc\//i, /\/etc\/passwd|\/etc\/shadow/i,
];

// Agent-context files an assistant reads and may act on.
const AGENT_CONTEXT = new Set([
  'readme.md', 'readme', 'agents.md', 'claude.md', 'contributing.md',
  '.cursorrules', '.windsurfrules', 'setup.md', 'install.md', 'onboarding.md',
  'copilot-instructions.md', 'gemini.md',
]);

// Remote download-and-execute in an agent-ingested doc.
const CURL_BASH = /(?:curl|wget|iwr|invoke-webrequest)\b[^\n|;]{0,200}[|;]\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|pwsh|powershell|iex)\b/i;
// PowerShell download-cradle.
const IEX_CRADLE = /\bi(?:ex|nvoke-expression)\b[^\n]{0,80}(?:iwr|invoke-webrequest|net\.webclient|downloadstring)/i;
// "…during setup / while reviewing … run <something>" — agent-workflow hijack.
const RUN_ON_TRIGGER = /(?:before|during|when|while|as part of|to)\s+(?:you\s+)?(?:review|reviewing|scan|scanning|audit|auditing|analy[sz]e|analy[sz]ing|set(?:ting)?\s?up|onboard|initiali[sz]e|build)[\s\S]{0,80}?\b(?:run|execute|invoke|source)\b\s*[`'"./$]/i;

export class TrustBoundaryAgent extends BaseAgent {
  constructor() {
    super(
      'TrustBoundaryAgent',
      'Detects AI coding-agent trust-boundary attacks: GhostApproval symlinks and Friendly Fire run-on-review instructions',
      'agentic'
    );
  }

  shouldRun() {
    return true;
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    // 1. Symlink inspection — walk the tree with lstat (glob skips symlinks).
    this._walkSymlinks(rootPath, rootPath, findings, 0);

    // 2. Friendly Fire — agent-ingested files that direct running code.
    for (const file of this.getFilesToScan(context)) {
      const base = path.basename(file).toLowerCase();
      if (AGENT_CONTEXT.has(base) || /(^|\/)docs\//.test(file.replace(/\\/g, '/'))) {
        findings.push(...this._scanAgentDoc(file));
      }
    }

    return findings;
  }

  // ── Symlinks ────────────────────────────────────────────────────────────────

  _walkSymlinks(dir, root, findings, depth) {
    if (depth > 12) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        this._checkSymlink(full, root, findings);
      } else if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        this._walkSymlinks(full, root, findings, depth + 1);
      }
    }
  }

  _checkSymlink(linkPath, root, findings) {
    let target;
    try { target = fs.readlinkSync(linkPath); } catch { return; }
    const resolved = path.resolve(path.dirname(linkPath), target);
    const rel = path.relative(root, linkPath);
    const looksLikeConfig = /\.(json|ya?ml|toml|ini|env|config|conf|cfg|txt|md)$|settings|config|credentials/i.test(path.basename(linkPath));

    // Sensitive target — the GhostApproval core.
    if (SENSITIVE_TARGET.some((re) => re.test(target) || re.test(resolved))) {
      findings.push(createFinding({
        file: linkPath, line: 0, severity: 'critical', category: 'agentic',
        rule: 'SYMLINK_SENSITIVE_TARGET',
        title: 'Symlink points at a sensitive path (GhostApproval)',
        description: `\`${rel}\` is a symlink to \`${target}\`. An AI coding agent asked to edit this "file" would read or write the real target instead — the GhostApproval technique for stealing SSH keys / credentials or planting an authorized key.`,
        matched: `${path.basename(linkPath)} -> ${target}`,
        confidence: 'high', cwe: 'CWE-59',
        fix: 'Remove the symlink. A repository should never contain links into ~/.ssh, ~/.aws, .env, or other credential paths.',
      }));
      return;
    }

    // Escapes the repository root.
    const escapes = path.isAbsolute(target) || path.relative(root, resolved).startsWith('..');
    if (escapes) {
      findings.push(createFinding({
        file: linkPath, line: 0, severity: looksLikeConfig ? 'high' : 'medium', category: 'agentic',
        rule: 'SYMLINK_ESCAPES_REPO',
        title: 'Symlink resolves outside the repository',
        description: `\`${rel}\` is a symlink to \`${target}\`, which resolves outside the repo.${looksLikeConfig ? ' Its config-like name makes it a plausible target for an agent write, redirecting the write outside the project.' : ''}`,
        matched: `${path.basename(linkPath)} -> ${target}`,
        confidence: looksLikeConfig ? 'high' : 'medium', cwe: 'CWE-61',
        fix: 'Replace the symlink with the real file, or remove it. Agent edits to a link write through to wherever it points.',
      }));
    }
  }

  // ── Friendly Fire ─────────────────────────────────────────────────────────────

  _scanAgentDoc(file) {
    const content = this.readFile(file);
    if (!content) return [];
    const findings = [];
    const lineOf = (idx) => content.slice(0, idx).split('\n').length;

    let m;
    if ((m = CURL_BASH.exec(content)) || (m = IEX_CRADLE.exec(content))) {
      findings.push(createFinding({
        file, line: lineOf(m.index), severity: 'high', category: 'agentic',
        rule: 'AGENT_REMOTE_EXEC_INSTRUCTION',
        title: 'Download-and-run command in an agent-read file',
        description: 'This file — which AI coding agents ingest as context — instructs downloading and executing a remote script (curl|bash / PowerShell cradle). An agent following the repo\'s setup steps would run attacker-controlled code (Friendly Fire).',
        matched: m[0].slice(0, 100).replace(/\n/g, ' '),
        confidence: 'high', cwe: 'CWE-77',
        fix: 'Never pipe a downloaded script to a shell. Pin and vendor install steps; agents should not execute remote code from a repo\'s docs.',
      }));
    }

    RUN_ON_TRIGGER.lastIndex = 0;
    if ((m = RUN_ON_TRIGGER.exec(content))) {
      findings.push(createFinding({
        file, line: lineOf(m.index), severity: 'medium', category: 'agentic',
        rule: 'AGENT_RUN_ON_REVIEW',
        title: 'Instruction to run code during setup or review',
        description: 'An agent-read file directs running a command as part of setup, review, or scanning. This is the Friendly Fire pattern — the agent is steered into executing the repo\'s workflow during its own review pass.',
        matched: m[0].slice(0, 100).replace(/\n/g, ' '),
        confidence: 'medium', cwe: 'CWE-77',
        fix: 'Treat repo-supplied "run this to set up / review" steps as untrusted. Do not let an agent execute them automatically.',
      }));
    }

    return findings;
  }
}

export default TrustBoundaryAgent;
