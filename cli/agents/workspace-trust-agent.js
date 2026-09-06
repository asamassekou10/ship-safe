/**
 * Workspace Trust Agent
 * =====================
 *
 * Detects configuration that a repository carries with it and that an agent
 * can be made to execute before anyone approves anything.
 *
 * Manifold Security's GitSpawn research (1 September 2026) showed that nearly
 * every CLI coding agent runs `git status` or `git diff` in the background to
 * build project context. Git refreshes its index to answer, and `.git/config`
 * decides what that refresh executes. The command runs with the user's
 * privileges, outside the agent's sandbox, before the workspace-trust dialog.
 * Seven agents were affected and four were unpatched at publication, including
 * Hermes Agent v0.21.0 under CVE-2026-71963 — the release Ship Safe pins as its
 * own coverage baseline.
 *
 * The delivery constraint is what makes this worth a detector rather than a
 * vendor patch note. `git clone`, `fetch`, and `pull` never transmit a hostile
 * `.git/config`, so this arrives the way take-home projects and client handoffs
 * actually arrive: a zip, a shared drive, a synced folder, a USB stick. By the
 * time a human could inspect it, the agent has already read the directory.
 *
 * Scans: .git/config (and the gitdir it points at), .git/hooks/
 * Detects: fsmonitor command sinks, redirected hooks paths, repo-controlled
 *          attribute trees, content filter commands, planted hook scripts
 *
 * Maps to: OWASP Agentic AI ASI04 (Supply Chain), ASI05 (Code Execution)
 *
 * References:
 *   https://www.manifold.security/blog/ai-coding-agents-git-hijack
 *   CVE-2026-72718, CVE-2026-19592, CVE-2026-71963
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';
import { parseGitConfig, findEntries, isBooleanValue } from '../utils/git-config.js';

// =============================================================================
// BENIGN CONFIGURATIONS
// =============================================================================

/**
 * Filter commands that ship as part of a normal toolchain.
 *
 * Git LFS is the overwhelmingly common `filter.*` configuration and appears in
 * a large share of healthy repositories. A rule that flagged it would fire on
 * more real projects than hostile ones, which is worse than not shipping the
 * rule: it teaches people to ignore the category.
 */
const KNOWN_FILTER_COMMANDS = [
  /^git-lfs(\s|$)/,
  /^git\s+lfs(\s|$)/,
  /^git-crypt(\s|$)/,
];

/**
 * Hook managers that legitimately redirect `core.hooksPath` into the worktree.
 *
 * Each entry names the marker that proves the tool is actually installed rather
 * than merely named. Presence of the marker suppresses WORKSPACE_GIT_HOOKS_PATH
 * for that directory — but never suppresses WORKSPACE_GIT_HOOK_PRESENT, which
 * still reads the scripts inside it. A poisoned `.husky/` is a real attack, and
 * suppressing the redirect must not also suppress its contents.
 */
const HOOK_MANAGERS = [
  { name: 'husky', dir: '.husky', markers: ['_/husky.sh', '_/h', 'husky.sh'] },
  { name: 'lefthook', dir: '.lefthook', markers: [] },
];

/** Config files whose presence proves a hook manager is installed. */
const HOOK_MANAGER_ROOT_MARKERS = {
  lefthook: ['lefthook.yml', 'lefthook.yaml', 'lefthook.toml', 'lefthook.json'],
};

// =============================================================================
// AGENT
// =============================================================================

export class WorkspaceTrustAgent extends BaseAgent {
  constructor() {
    super(
      'WorkspaceTrustAgent',
      'Detect repository-supplied configuration that executes when an agent opens the folder — git config command sinks and planted hooks',
      'supply-chain'
    );
  }

  async analyze(context) {
    const { rootPath } = context;
    if (!rootPath) return [];

    const gitDir = this._resolveGitDir(rootPath);
    if (!gitDir) return [];

    let findings = [];

    const configPath = path.join(gitDir, 'config');
    const entries = this._readConfig(configPath);

    if (entries) {
      findings = findings.concat(this._checkFsmonitor(entries, configPath));
      findings = findings.concat(this._checkAttrTree(entries, configPath));
      findings = findings.concat(this._checkFilters(entries, configPath));
      findings = findings.concat(this._checkHooksPath(entries, configPath, rootPath));
    }

    findings = findings.concat(this._checkHookScripts(entries, gitDir, rootPath));

    return findings;
  }

  // ---------------------------------------------------------------------------
  // DISCOVERY
  // ---------------------------------------------------------------------------

  /**
   * Locate the git directory for a scanned root.
   *
   * `.git` is in the scanner's global skip list, so nothing reaches this agent
   * through the normal file-discovery path and every read here is explicit.
   * That is deliberate: the skip list exists to keep object storage out of
   * content scanning, and lifting it would pull thousands of loose objects into
   * every scan to reach two files.
   *
   * `.git` may also be a file rather than a directory. Submodules and linked
   * worktrees write `gitdir: <path>` there, and since a submodule is one of the
   * ways a hostile config arrives inside an otherwise ordinary checkout, the
   * pointer is followed.
   */
  _resolveGitDir(rootPath) {
    const candidate = path.join(rootPath, '.git');

    let stat;
    try { stat = fs.statSync(candidate); } catch { return null; }

    if (stat.isDirectory()) return candidate;
    if (!stat.isFile()) return null;

    let pointer;
    try { pointer = fs.readFileSync(candidate, 'utf8'); } catch { return null; }

    const match = pointer.match(/^\s*gitdir:\s*(.+?)\s*$/m);
    if (!match) return null;

    const target = path.isAbsolute(match[1]) ? match[1] : path.resolve(rootPath, match[1]);
    try {
      return fs.statSync(target).isDirectory() ? target : null;
    } catch { return null; }
  }

  _readConfig(configPath) {
    try {
      return parseGitConfig(fs.readFileSync(configPath, 'utf8'));
    } catch { return null; }
  }

  // ---------------------------------------------------------------------------
  // RULES
  // ---------------------------------------------------------------------------

  /**
   * core.fsmonitor pointing at a command.
   *
   * This is GitSpawn's primary sink. `true` and `false` are not findings:
   * `true` selects git's built-in FSMonitor daemon, which runs no external
   * program, and treating it as a sink would flag a documented performance
   * setting on every repository that enables it.
   */
  _checkFsmonitor(entries, configPath) {
    const findings = [];

    for (const entry of findEntries(entries, 'core', 'fsmonitor')) {
      if (isBooleanValue(entry.value)) continue;
      if (!entry.value) continue;

      findings.push(createFinding({
        file: configPath,
        line: entry.line,
        severity: 'critical',
        category: this.category,
        rule: 'WORKSPACE_GIT_FSMONITOR_EXEC',
        title: 'Workspace Trust: git fsmonitor runs a repository-supplied command',
        description:
          'core.fsmonitor names an external program that git executes whenever it refreshes the index. '
          + 'Coding agents run git in the background to gather project context, so opening this folder with an agent '
          + 'can execute this command with your privileges, outside the agent sandbox and before any approval prompt. '
          + 'This configuration is present in the repository; whether a given agent reaches it depends on that agent and version.',
        matched: this._quote(entry.value),
        confidence: 'high',
        cwe: 'CWE-77',
        owasp: 'ASI05',
        fix: 'Remove the core.fsmonitor entry from .git/config, or set it to `true` to use git\'s built-in daemon. '
          + 'Do not open this directory with a coding agent until it is removed. To disable the setting everywhere, run '
          + '`git config --global core.fsmonitor false`.',
      }));
    }

    return findings;
  }

  /**
   * attr.tree sourcing gitattributes from a repository-controlled tree.
   *
   * Attributes decide which filters and diff drivers apply to a path, so
   * controlling the attributes source is a step toward controlling what runs.
   * It is reported as high rather than critical because reaching execution
   * needs a second configured piece, unlike fsmonitor which is the sink itself.
   */
  _checkAttrTree(entries, configPath) {
    const findings = [];

    for (const entry of findEntries(entries, 'attr', 'tree')) {
      if (!entry.value) continue;

      findings.push(createFinding({
        file: configPath,
        line: entry.line,
        severity: 'high',
        category: this.category,
        rule: 'WORKSPACE_GIT_ATTR_TREE',
        title: 'Workspace Trust: gitattributes sourced from a repository-controlled tree',
        description:
          'attr.tree makes git read .gitattributes from a tree the repository controls rather than the checked-out worktree. '
          + 'Attributes select the filters and diff drivers applied to a path, so a repository that also configures a filter '
          + 'command can direct it at files of its choosing.',
        matched: this._quote(entry.value),
        confidence: 'high',
        cwe: 'CWE-77',
        owasp: 'ASI04',
        fix: 'Remove the attr.tree entry from .git/config and review any filter or diff driver configured alongside it.',
      }));
    }

    return findings;
  }

  /**
   * filter.<name>.process / .clean / .smudge naming a command.
   *
   * Filters run during checkout and staging, which an agent triggers routinely.
   * Known toolchain filters are excluded by command, not by filter name, so a
   * hostile entry cannot hide by calling itself `lfs`.
   */
  _checkFilters(entries, configPath) {
    const findings = [];
    const keys = new Set(['process', 'clean', 'smudge']);

    for (const entry of entries) {
      if (entry.section !== 'filter' || !keys.has(entry.key)) continue;
      if (!entry.value || isBooleanValue(entry.value)) continue;
      if (this._isKnownFilterCommand(entry.value)) continue;

      const label = entry.subsection ? `filter.${entry.subsection}.${entry.key}` : `filter.${entry.key}`;

      findings.push(createFinding({
        file: configPath,
        line: entry.line,
        severity: 'high',
        category: this.category,
        rule: 'WORKSPACE_GIT_FILTER_PROCESS',
        title: 'Workspace Trust: git content filter runs a repository-supplied command',
        description:
          `${label} names a command that git runs while checking out or staging matching files. `
          + 'An agent that checks out a branch, stages a change, or resets a file executes it. '
          + 'The command is configured in the repository rather than by the user.',
        matched: this._quote(entry.value),
        confidence: 'high',
        cwe: 'CWE-77',
        owasp: 'ASI05',
        fix: `Remove ${label} from .git/config unless you installed this filter yourself and recognise the command.`,
      }));
    }

    return findings;
  }

  _isKnownFilterCommand(value) {
    const command = String(value).trim();
    return KNOWN_FILTER_COMMANDS.some((pattern) => pattern.test(command));
  }

  /**
   * core.hooksPath redirected into the worktree.
   *
   * Only a path that resolves inside the scanned tree is reported. A hooksPath
   * pointing outside it is a machine-level choice the user made, and this agent
   * deliberately does not judge the user's own environment — the question it
   * answers is what arrived with the repository.
   *
   * Recognised hook managers are excluded, because husky and lefthook both do
   * exactly this by design and are far too common to report. The exclusion
   * requires an installed marker, not just the directory name, and it never
   * extends to the scripts themselves.
   */
  _checkHooksPath(entries, configPath, rootPath) {
    const findings = [];

    for (const entry of findEntries(entries, 'core', 'hookspath')) {
      if (!entry.value || isBooleanValue(entry.value)) continue;

      const resolved = path.resolve(rootPath, entry.value);
      const relative = path.relative(rootPath, resolved);
      const insideTree = relative && !relative.startsWith('..') && !path.isAbsolute(relative);
      if (!insideTree) continue;

      const manager = this._detectHookManager(rootPath, resolved);
      if (manager) continue;

      findings.push(createFinding({
        file: configPath,
        line: entry.line,
        severity: 'critical',
        category: this.category,
        rule: 'WORKSPACE_GIT_HOOKS_PATH',
        title: 'Workspace Trust: git hooks redirected into the repository',
        description:
          `core.hooksPath points at ${relative}, inside the repository itself, so the hook scripts that git runs are `
          + 'content the repository ships rather than files you wrote. Any git operation an agent performs on this '
          + 'folder can execute them.',
        matched: this._quote(entry.value),
        confidence: 'high',
        cwe: 'CWE-77',
        owasp: 'ASI05',
        fix: `Remove core.hooksPath from .git/config, then review the scripts in ${relative} before running any git command here.`,
      }));
    }

    return findings;
  }

  /**
   * Identify an installed hook manager owning a hooks directory.
   * Returns the manager name, or null when nothing proves one is installed.
   */
  _detectHookManager(rootPath, hooksDir) {
    for (const manager of HOOK_MANAGERS) {
      const managerDir = path.resolve(rootPath, manager.dir);
      const withinManagerDir = hooksDir === managerDir || hooksDir.startsWith(managerDir + path.sep);
      if (!withinManagerDir) continue;

      const markers = manager.markers.map((m) => path.join(managerDir, m));
      const rootMarkers = (HOOK_MANAGER_ROOT_MARKERS[manager.name] || []).map((m) => path.join(rootPath, m));

      if ([...markers, ...rootMarkers].some((p) => this._exists(p))) return manager.name;
    }
    return null;
  }

  /**
   * Executable hook scripts that are not git's shipped samples.
   *
   * Git populates .git/hooks/ with `*.sample` files that are inert because of
   * the extension. Anything else there is executable on the next matching git
   * operation, and since .git/hooks/ is not transmitted by clone, a populated
   * hooks directory in a folder that arrived whole is worth a reviewer's time.
   *
   * When core.hooksPath redirects into the worktree the redirected directory is
   * read instead, including for recognised hook managers: suppressing the
   * redirect finding must not suppress inspection of what it points at.
   */
  _checkHookScripts(entries, gitDir, rootPath) {
    const findings = [];

    const hooksDir = this._effectiveHooksDir(entries, gitDir, rootPath);
    if (!hooksDir) return findings;

    let names;
    try { names = fs.readdirSync(hooksDir); } catch { return findings; }

    for (const name of names.sort()) {
      if (name.endsWith('.sample')) continue;

      const scriptPath = path.join(hooksDir, name);
      let stat;
      try { stat = fs.statSync(scriptPath); } catch { continue; }
      if (!stat.isFile()) continue;
      if (!this._isExecutable(stat)) continue;

      findings.push(createFinding({
        file: scriptPath,
        line: 1,
        severity: 'high',
        category: this.category,
        rule: 'WORKSPACE_GIT_HOOK_PRESENT',
        title: 'Workspace Trust: executable git hook present in the repository',
        description:
          `An executable ${name} hook is installed for this repository. Git hooks are not transmitted by clone, `
          + 'so in a directory that arrived as an archive or a shared folder this script came with the folder. '
          + 'It runs on the matching git operation, including operations an agent performs on its own.',
        matched: name,
        confidence: 'medium',
        cwe: 'CWE-77',
        owasp: 'ASI05',
        fix: `Read ${name} before running git in this directory, and remove it if you did not install it.`,
      }));
    }

    return findings;
  }

  /**
   * The hooks directory git will actually use, honouring core.hooksPath.
   *
   * A redirect that leaves the scanned tree yields nothing rather than the
   * default `.git/hooks`. Git does not consult `.git/hooks` once hooksPath is
   * set, so reading it would report scripts that will never run; and reading
   * the redirect target instead would report the user's own hooks, sitting in
   * their home directory or /usr/local, as though the repository had shipped
   * them. Neither is true, so this reports neither.
   *
   * Last-one-wins matches git's own precedence for a repeated key.
   */
  _effectiveHooksDir(entries, gitDir, rootPath) {
    const redirects = entries ? findEntries(entries, 'core', 'hookspath') : [];
    const last = redirects.filter((e) => e.value && !isBooleanValue(e.value)).pop();

    if (!last) {
      const dir = path.join(gitDir, 'hooks');
      return this._isDirectory(dir) ? dir : null;
    }

    const resolved = path.resolve(rootPath, last.value);
    const relative = path.relative(rootPath, resolved);
    const insideTree = relative && !relative.startsWith('..') && !path.isAbsolute(relative);
    if (!insideTree) return null;

    return this._isDirectory(resolved) ? resolved : null;
  }

  // ---------------------------------------------------------------------------
  // HELPERS
  // ---------------------------------------------------------------------------

  /**
   * Whether a mode bit marks the file executable by anyone.
   *
   * Windows checkouts do not carry POSIX permission bits, so on that platform
   * this reports nothing rather than reporting everything. Over-reporting here
   * would mean flagging every hooks directory on Windows, and a rule that fires
   * on all input carries no information.
   */
  _isExecutable(stat) {
    return (stat.mode & 0o111) !== 0;
  }

  _exists(target) {
    try { fs.accessSync(target); return true; } catch { return false; }
  }

  _isDirectory(target) {
    try { return fs.statSync(target).isDirectory(); } catch { return false; }
  }

  /**
   * Bound what a value contributes to output.
   *
   * The value is attacker-controlled text that reaches reports, terminals, and
   * SARIF. It is truncated and stripped of control characters so a crafted
   * config cannot rewrite the surrounding line or smuggle escape sequences
   * through a reviewer's terminal.
   */
  _quote(value) {
    // Matching control characters is the point: they are what must not survive
    // into a terminal or a report.
    // eslint-disable-next-line no-control-regex
    const clean = String(value).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
    return clean.length > 160 ? `${clean.slice(0, 157)}...` : clean;
  }
}

export default WorkspaceTrustAgent;
