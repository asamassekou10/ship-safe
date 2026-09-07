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


/**
 * Devcontainer lifecycle hooks, mapped to whether they run on the host.
 *
 * `initializeCommand` is the only one that executes outside the container.
 * The distinction decides severity, so it lives in the data rather than in a
 * conditional someone can forget to update.
 */
const DEVCONTAINER_HOOKS = {
  initializeCommand: true,
  onCreateCommand: false,
  updateContentCommand: false,
  postCreateCommand: false,
  postStartCommand: false,
  postAttachCommand: false,
};

/**
 * Commands in an .envrc that mean "run a program" rather than "set a value".
 *
 * Deliberately narrow. An .envrc is a bash script, so almost anything is
 * technically execution; flagging every line would make the rule useless.
 * These are the forms that fetch, spawn, or evaluate.
 */
const ENVRC_EXEC_RE = /(?:^|[\s;|&(`$])(?:curl|wget|nc|ncat|bash|sh|zsh|python[0-9.]*|perl|ruby|node|npx|eval|exec)\b|\$\(|`/;

/** Repository-scoped agent configuration files that can carry hooks. */
const AGENT_HOOK_CONFIGS = [
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.cursor/settings.json',
  '.windsurf/settings.json',
  '.gemini/settings.json',
  '.continue/config.json',
];

/**
 * Ship Safe's own hooks, which a user installs deliberately.
 *
 * Matched on the invocation rather than the file, so that only a command that
 * actually runs Ship Safe's hook entry point is exempt.
 */
const SHIP_SAFE_HOOK_RE = /^(?:npx\s+(?:-y\s+)?)?ship-safe\s+(?:guard|hooks)\b/;

/**
 * Forms AgentConfigScanner already reports on .claude/settings.json.
 *
 * Kept in sync deliberately rather than shared: this rule suppresses to avoid
 * a duplicate finding, and a broken match here costs a second finding, not a
 * missed one.
 */
const CLAUDE_HOOK_SHELL_RE = /(?:bash\s+-c|sh\s+-c|cmd\s+\/c|powershell\s+-|pwsh\s+-)/i;
const CLAUDE_HOOK_DOWNLOAD_RE = /(?:curl|wget|fetch|http\.get|Invoke-WebRequest)\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i;

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

    // A folder that is not a git repository can still carry tasks.json,
    // a devcontainer, an .envrc, or agent hook config. Those arrive by the
    // same route — a zip or a shared drive — and execute by the same
    // mechanism, so a missing .git must not skip them.
    const gitDir = this._resolveGitDir(rootPath);

    let findings = [];

    if (gitDir) {
      const configPath = path.join(gitDir, 'config');
      const entries = this._readConfig(configPath);

      if (entries) {
        findings = findings.concat(this._checkFsmonitor(entries, configPath));
        findings = findings.concat(this._checkAttrTree(entries, configPath));
        findings = findings.concat(this._checkFilters(entries, configPath));
        findings = findings.concat(this._checkHooksPath(entries, configPath, rootPath));
      }

      findings = findings.concat(this._checkHookScripts(entries, gitDir, rootPath));
    }

    // Folder-open sinks that do not live in .git. These are reachable even
    // when the directory is not a git repository at all, so they are checked
    // from the scanned root rather than the git dir.
    findings = findings.concat(this._checkTaskAutorun(rootPath));
    findings = findings.concat(this._checkDevcontainer(rootPath));
    findings = findings.concat(this._checkEnvrc(rootPath));
    findings = findings.concat(this._checkAgentHookConfig(rootPath));

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


  // ---------------------------------------------------------------------------
  // FOLDER-OPEN RULES
  // ---------------------------------------------------------------------------

  /**
   * .vscode/tasks.json configured to run a task on folder open.
   *
   * VS Code, Cursor, and Windsurf all honour `runOptions.runOn: "folderOpen"`,
   * and TasksJacker campaigns are exploiting it now. The task runs when the
   * folder is opened, which for an agent-driven workflow means before anyone
   * has read a line of the code.
   *
   * Severity follows what the victim can notice. A task whose presentation
   * reveals a terminal panel at least gives a person a chance to see it and
   * close the window; `reveal: "silent"` removes that, and is the form the
   * campaigns actually use.
   */
  _checkTaskAutorun(rootPath) {
    const findings = [];
    const file = path.join(rootPath, '.vscode', 'tasks.json');
    const parsed = this._readJsonc(file);
    if (!parsed) return findings;

    const tasks = Array.isArray(parsed.json?.tasks) ? parsed.json.tasks : [];

    for (const task of tasks) {
      if (!task || typeof task !== 'object') continue;
      if (task.runOptions?.runOn !== 'folderOpen') continue;

      const command = this._taskCommand(task);
      if (!command) continue;

      const silent = task.presentation?.reveal === 'silent';
      const label = typeof task.label === 'string' ? task.label : '(unlabelled task)';

      findings.push(createFinding({
        file,
        line: this._lineOf(parsed.text, command) || this._lineOf(parsed.text, 'folderOpen'),
        severity: silent ? 'critical' : 'high',
        category: this.category,
        rule: 'WORKSPACE_TASK_AUTORUN',
        title: silent
          ? 'Workspace Trust: task runs silently when the folder is opened'
          : 'Workspace Trust: task runs when the folder is opened',
        description:
          `The task "${label}" is configured with runOn: folderOpen, so the editor executes it as soon as this `
          + 'folder is opened, before any file has been reviewed. VS Code, Cursor, and Windsurf all honour this setting. '
          + (silent
            ? 'Its presentation is set to reveal: silent, so no terminal panel appears and there is no visible sign it ran. '
            : 'Its terminal panel is visible, which gives some chance of noticing it. ')
          + 'This configuration is present in the repository; whether it fires depends on the editor used to open the folder.',
        matched: this._quote(command),
        confidence: 'high',
        cwe: 'CWE-94',
        owasp: 'ASI05',
        fix: 'Remove the runOptions.runOn setting from this task, or delete the task. Do not open this folder in an '
          + 'editor until it is removed — inspect it with a plain file viewer instead. VS Code’s "Restricted Mode" '
          + 'blocks automatic tasks if you must open it.',
      }));
    }

    return findings;
  }

  /**
   * Devcontainer lifecycle commands.
   *
   * The severity split is the whole point of this rule. `initializeCommand`
   * runs on the *host*, before the container exists, with the developer's own
   * privileges and no isolation. Every other lifecycle hook runs inside the
   * container, where the blast radius is whatever the container can reach.
   * Reporting both at one severity would either overstate the container hooks
   * or understate the one that escapes.
   */
  _checkDevcontainer(rootPath) {
    const findings = [];

    for (const file of this._devcontainerFiles(rootPath)) {
      const parsed = this._readJsonc(file);
      if (!parsed?.json) continue;

      for (const [key, hostSide] of Object.entries(DEVCONTAINER_HOOKS)) {
        const command = this._flattenCommand(parsed.json[key]);
        if (!command) continue;

        findings.push(createFinding({
          file,
          line: this._lineOf(parsed.text, key),
          severity: hostSide ? 'high' : 'medium',
          category: this.category,
          rule: 'WORKSPACE_DEVCONTAINER_INIT',
          title: hostSide
            ? `Workspace Trust: devcontainer ${key} runs on your host`
            : `Workspace Trust: devcontainer ${key} runs in the container`,
          description: hostSide
            ? `${key} is executed on the host machine, before the container is built and outside any isolation it `
              + 'would have provided. Opening this folder in a devcontainer-aware editor runs it with your privileges. '
              + 'This is the devcontainer hook that does not stay in the container.'
            : `${key} runs inside the container once it is built. The blast radius is bounded by the container, but it `
              + 'still executes repository-supplied commands without an approval step, and a container with mounted '
              + 'credentials or host sockets is not a boundary.',
          matched: this._quote(command),
          confidence: 'high',
          cwe: 'CWE-94',
          owasp: 'ASI05',
          fix: hostSide
            ? `Remove ${key} from the devcontainer definition, or move the work into a container-side hook such as `
              + 'postCreateCommand where it is at least isolated. Review it before opening this folder in an editor '
              + 'that supports devcontainers.'
            : `Review what ${key} does before building this container, and confirm the container does not mount host `
              + 'credentials, docker sockets, or SSH agents.',
        }));
      }
    }

    return findings;
  }

  /**
   * .envrc carrying command execution.
   *
   * Medium rather than high because direnv gates execution on a content hash:
   * a new or changed `.envrc` is refused until someone runs `direnv allow`.
   * That is a real control and the finding says so. It is still worth
   * reporting, because "run direnv allow" is exactly the instruction a
   * take-home README gives you, and the file is rarely read first.
   */
  _checkEnvrc(rootPath) {
    const file = path.join(rootPath, '.envrc');

    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { return []; }

    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      // direnv's own stdlib helpers are what an ordinary .envrc is made of,
      // and several of them name an interpreter as an argument — `layout node`
      // would otherwise read as execution.
      if (/^(?:dotenv|dotenv_if_exists|source_env|source_env_if_exists|source_up|watch_file|PATH_add|path_add|layout|use)\b/.test(line)) continue;

      if (!ENVRC_EXEC_RE.test(line)) continue;

      // An assignment is only inert if its value is. `export FOO=bar` sets a
      // variable; `export TOKEN=$(cat /etc/passwd)` runs a program and assigns
      // the output, so the assignment check has to come after the execution
      // check rather than before it.
      if (/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=/.test(line) && !/\$\(|`/.test(line)) continue;

      return [createFinding({
        file,
        line: i + 1,
        severity: 'medium',
        category: this.category,
        rule: 'WORKSPACE_ENVRC_EXEC',
        title: 'Workspace Trust: .envrc runs a command when the directory is entered',
        description:
          'This .envrc executes a command rather than only setting environment variables. direnv runs it whenever a '
          + 'shell enters the directory, which includes the shells that coding agents and editor terminals open. '
          + 'direnv refuses a new or modified .envrc until `direnv allow` is run, so this is not automatic on first '
          + 'contact — but that approval is a single command, and it is commonly the first thing a project README '
          + 'tells you to do.',
        matched: this._quote(line),
        confidence: 'medium',
        cwe: 'CWE-94',
        owasp: 'ASI05',
        fix: 'Read this .envrc before running `direnv allow`. Restrict it to variable assignments, or use '
          + '`dotenv` to load a .env file instead of executing commands. `direnv deny .` blocks it explicitly.',
      })];
    }

    return [];
  }

  /**
   * Repository-scoped agent hook configuration.
   *
   * CVE-2026-48124's shape: hook configuration that ships inside the
   * repository, is picked up because the agent was pointed at the folder, and
   * executes on a lifecycle event before the session is trusted.
   *
   * Two suppressions matter here. Ship Safe installs its own hooks, and a
   * scanner that reports its own installation is noise — but only user-scope
   * installs are exempt, because a repo-scoped file claiming to be Ship Safe
   * is exactly what an attacker would write. And AgentConfigScanner already
   * reports `.claude/settings.json` hooks whose command is recognisably a
   * shell invocation or a download; this rule covers the rest of the shape
   * rather than issuing a second finding for the same line.
   */
  _checkAgentHookConfig(rootPath) {
    const findings = [];

    for (const rel of AGENT_HOOK_CONFIGS) {
      const file = path.join(rootPath, rel);
      const parsed = this._readJsonc(file);
      if (!parsed?.json) continue;

      const hooks = parsed.json.hooks;
      if (!hooks || typeof hooks !== 'object') continue;

      for (const [event, value] of Object.entries(hooks)) {
        for (const command of this._hookCommands(value)) {
          if (this._isShipSafeHook(command)) continue;
          // Already reported by AgentConfigScanner in a more specific form.
          if (CLAUDE_HOOK_SHELL_RE.test(command) || CLAUDE_HOOK_DOWNLOAD_RE.test(command)) continue;

          findings.push(createFinding({
            file,
            line: this._lineOf(parsed.text, command) || this._lineOf(parsed.text, event),
            severity: 'critical',
            category: this.category,
            rule: 'WORKSPACE_AGENT_HOOK_CONFIG',
            title: `Workspace Trust: repository-supplied agent hook runs on "${event}"`,
            description:
              `This hook configuration ships inside the repository and runs on the "${event}" lifecycle event. `
              + 'An agent pointed at this folder loads it because the folder was opened, not because anyone approved it, '
              + 'and the command executes with your privileges. This is the shape described by CVE-2026-48124. '
              + 'The configuration is present in the repository; whether it fires depends on the agent and version.',
            matched: this._quote(command),
            confidence: 'high',
            cwe: 'CWE-94',
            owasp: 'ASI05',
            fix: `Remove the "${event}" hook from ${rel}, or move the configuration to your user-scope settings where `
              + 'a repository cannot supply it. Do not open this folder with an agent until it is removed.',
          }));
        }
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // FOLDER-OPEN HELPERS
  // ---------------------------------------------------------------------------

  /** devcontainer.json in either of the two documented locations. */
  _devcontainerFiles(rootPath) {
    const files = [];
    const root = path.join(rootPath, '.devcontainer');

    for (const candidate of [
      path.join(rootPath, '.devcontainer.json'),
      path.join(root, 'devcontainer.json'),
    ]) {
      if (this._isFile(candidate)) files.push(candidate);
    }

    // .devcontainer/<name>/devcontainer.json, the multi-container layout.
    let subdirs = [];
    try {
      subdirs = fs.readdirSync(root, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => path.join(root, e.name, 'devcontainer.json'));
    } catch { /* no .devcontainer directory */ }

    for (const candidate of subdirs) {
      if (this._isFile(candidate)) files.push(candidate);
    }

    return files;
  }

  _isFile(candidate) {
    try { return fs.statSync(candidate).isFile(); } catch { return false; }
  }

  /**
   * Parse a JSON file that is JSONC in practice.
   *
   * tasks.json and devcontainer.json both permit comments and both are
   * routinely written with them. A strict parse would silently skip the
   * commented files, which are the majority.
   */
  _readJsonc(file) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { return null; }

    const stripped = text
      .replace(/^\s*\/\/.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '');

    try {
      return { json: JSON.parse(stripped), text };
    } catch {
      // A config that does not parse is not one to reason about. Guessing at
      // half-valid JSON would produce findings nobody can act on.
      return null;
    }
  }

  /** The command a tasks.json entry runs, including its arguments. */
  _taskCommand(task) {
    const base = this._flattenCommand(task.command);
    if (!base) return '';

    const args = Array.isArray(task.args)
      ? task.args.map((a) => (typeof a === 'string' ? a : this._flattenCommand(a))).filter(Boolean)
      : [];

    return args.length ? `${base} ${args.join(' ')}` : base;
  }

  /**
   * Reduce a command field to a string.
   *
   * These fields accept a string, an array of arguments, or an object keyed by
   * platform. All three appear in real config, and a rule that only understood
   * strings would miss the array form entirely.
   */
  _flattenCommand(value) {
    if (typeof value === 'string') return value.trim();
    if (Array.isArray(value)) return value.filter((v) => typeof v === 'string').join(' ').trim();
    if (value && typeof value === 'object') {
      return Object.values(value)
        .map((v) => this._flattenCommand(v))
        .filter(Boolean)
        .join('; ');
    }
    return '';
  }

  /** Every command string reachable from one hook event's value. */
  _hookCommands(value) {
    const items = Array.isArray(value) ? value : [value];
    const commands = [];

    for (const item of items) {
      if (typeof item === 'string') {
        if (item.trim()) commands.push(item.trim());
        continue;
      }
      if (!item || typeof item !== 'object') continue;

      const direct = this._flattenCommand(item.command ?? item.cmd ?? item.run);
      if (direct) commands.push(direct);

      // Claude Code nests the runnable entries under `hooks`.
      if (Array.isArray(item.hooks)) {
        for (const nested of item.hooks) {
          const cmd = this._flattenCommand(nested?.command ?? nested?.cmd ?? nested?.run);
          if (cmd) commands.push(cmd);
        }
      }
    }

    return commands;
  }

  /**
   * Whether a hook is Ship Safe's own, installed by the user rather than
   * supplied by the repository.
   *
   * Only the user-scope form is exempt. A repo-scoped file invoking
   * `ship-safe` is not evidence of a Ship Safe install; it is the obvious way
   * to get a scanner to ignore your hook.
   */
  _isShipSafeHook(command) {
    return SHIP_SAFE_HOOK_RE.test(command);
  }

  /** 1-based line of the first occurrence of a needle, or 1. */
  _lineOf(text, needle) {
    if (!needle) return 1;
    const index = text.indexOf(String(needle).split('\n')[0].slice(0, 80));
    if (index < 0) return 1;
    return text.slice(0, index).split('\n').length;
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
