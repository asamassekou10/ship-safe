# Adding a Security Rule

Security rules are the smallest useful checks in Ship Safe. Add a rule when an existing agent already owns the domain and your change is one new pattern, heuristic, or remediation message.

## Start Here

Use the existing agent that matches the risk:

| Risk | Common file |
|------|-------------|
| Secrets and tokens | `cli/utils/patterns.js` |
| MCP server or tool-call risk | `cli/agents/mcp-security-agent.js` |
| Agentic AI behavior | `cli/agents/agentic-security-agent.js` |
| Prompt or agent config injection | `cli/agents/agent-config-scanner.js` |
| CI/CD pipeline risk | `cli/agents/cicd-scanner.js` |
| Package install risk | `cli/agents/install-guard-agent.js` |
| App vulnerabilities | `cli/agents/injection-tester.js`, `cli/agents/auth-bypass-agent.js`, `cli/agents/ssrf-prober.js` |

## Rule Checklist

Every rule should include:

- a stable `rule` id
- a clear title
- severity based on likely impact
- confidence based on signal strength
- evidence that is useful but does not expose full secrets
- fix guidance that names the safer configuration or code pattern

## Secret Patterns

For secret formats, edit `cli/utils/patterns.js`.

```js
{
  name: 'Example API Key',
  pattern: /example_[A-Za-z0-9]{32}/g,
  severity: 'high',
  description: 'Example API keys can grant access to protected service data.',
}
```

Secret rules need a low false-positive rate. Prefer provider-specific prefixes, fixed lengths, checksums, or nearby context when available.

## Tests

Add or update a test in `cli/__tests__/`. A strong test includes:

- one vulnerable fixture
- one safe fixture
- an assertion for the rule id
- an assertion that secrets are masked or bounded in output

Run:

```bash
npm test
node cli/bin/ship-safe.js scan . --no-ai
```

### Never commit a fixture that attacks the person running the tests

Some rules describe configuration that executes. `WORKSPACE_GIT_FSMONITOR_EXEC` is the clearest case: a `.git/config` containing `core.fsmonitor = <command>` runs that command on the next git operation in that directory. Committing one as a fixture would mean any contributor, any editor indexing the tree, and CI itself could execute it. `npm test` alone runs git plenty of times.

Build these fixtures at run time instead. Create a temp directory, write the files into it, scan it, and remove it in a `finally` block:

```js
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-rule-'));
try {
  fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n\tfsmonitor = ./payload.sh\n');
  const findings = await new MyAgent().analyze({ rootPath: dir, files: [], recon: {}, options: {} });
  assert.ok(findings.some((f) => f.rule === 'MY_RULE'));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
```

If a fixture genuinely has to exist on disk, store the directory as `dot-git` and rename it into place inside the temp tree. A directory literally named `.git` in the repository is never acceptable, because git will find it.

See `cli/__tests__/workspace-trust-git.test.js` for the full pattern.

### Pair every rule with the benign form it must not flag

A rule that fires on healthy repositories is worse than no rule, because it teaches people to skip the whole category. Write the safe fixture first when the benign form is common:

| Rule | Benign form that must stay silent |
|------|-----------------------------------|
| `WORKSPACE_GIT_FSMONITOR_EXEC` | `core.fsmonitor = true`, which selects git's built-in daemon |
| `WORKSPACE_GIT_FILTER_PROCESS` | Git LFS `clean` / `smudge` / `process` commands |
| `WORKSPACE_GIT_HOOKS_PATH` | husky and lefthook, which redirect hooks by design |
| `WORKSPACE_GIT_HOOK_PRESENT` | git's shipped `*.sample` hooks |
| `WORKSPACE_TASK_AUTORUN` | any task without `runOptions.runOn: folderOpen` |
| `WORKSPACE_ENVRC_EXEC` | variable assignments and direnv stdlib helpers such as `layout node` |
| `WORKSPACE_AGENT_HOOK_CONFIG` | Ship Safe's own `ship-safe guard` hook, and forms `CLAUDE_HOOK_*` already reports |

Exempt by the specific evidence, not by the label. The filter exemption matches the LFS command, not the filter named `lfs`, so a hostile entry cannot claim the name and inherit the exemption. The husky exemption requires an installed marker file, not just a `.husky` directory. The Ship Safe hook exemption matches the invocation, so a repository cannot opt itself out by writing the scanner's name into a comment.

### Do not report the same line twice

`WORKSPACE_AGENT_HOOK_CONFIG` and `AgentConfigScanner`'s `CLAUDE_HOOK_SHELL_CMD` both read `.claude/settings.json`. Two findings for one hook is noise, and the reader has no way to tell whether they are looking at one problem or two. The newer rule suppresses the forms the existing one already reports and covers the rest of the shape.

When a rule overlaps an existing one, decide which owns the overlap and make the other silent there. Do it with an explicit check that names the other rule, so the next person can find both ends of the arrangement.

### Severity should track what the victim can notice or reach

Two of these rules carry a severity split rather than a fixed level, and both splits are about blast radius rather than about how clever the attack is:

- `WORKSPACE_TASK_AUTORUN` is high when the task reveals a terminal panel and critical when `presentation.reveal` is `silent`. A visible panel is a real chance to notice and close the window.
- `WORKSPACE_DEVCONTAINER_INIT` is high for `initializeCommand`, which runs on the host before the container exists, and medium for every other lifecycle hook, which runs inside it.

## What to Avoid

Avoid rules that flag common strings without strong context, require network access for core scanning, or create findings that only say "review this." Ship Safe should help developers decide what to fix next.

## Updating the Pinned Advisory Table

`cli/data/agent-advisories.json` maps installed agent versions to the execution sinks they are documented to invoke. It is what promotes a `WORKSPACE_*` finding from `configured` to `reachable`, so an edit to it changes what Ship Safe claims about a user's machine. Treat it like the Hermes baseline: a normal reviewable pull request, never a silent expansion.

Every entry states where the claim came from and when:

```json
{
  "id": "goose-fsmonitor",
  "binaries": ["goose"],
  "sinks": ["WORKSPACE_GIT_FSMONITOR_EXEC"],
  "affected": { "lt": "1.44.0" },
  "patchedIn": "1.44.0",
  "cve": "CVE-2026-72718",
  "source": "https://www.manifold.security/blog/ai-coding-agents-git-hijack",
  "recordedAt": "2026-09-05"
}
```

Rules for an edit:

- **Source it from an advisory or a disclosure writeup**, never from a vendor's release notes or marketing page. "Improved security of git integration" is not a documented sink.
- **Record only what was tested.** `affected` takes `{ lt }`, `{ gte, lte }`, or `{ exact: [...] }`. When a writeup names two versions, use `exact` with those two. The versions between them were not tested, and a range would claim them.
- **A patched version is not a safe version.** It is outside *this entry*. The resolver says so explicitly rather than reporting the folder as clean.
- **Absence is not safety.** An agent nobody has written up is undocumented. There is no entry that means "checked and fine".

Three properties are enforced by `cli/__tests__/agent-advisories.test.js` and should stay that way: an unreadable version resolves to `unresolved` and never to `reachable`; a table that fails to load behaves like one that assessed nothing rather than one that cleared everything; and version detection never resolves a binary from inside the folder being inspected, because running a repository-supplied executable is the attack `ship-safe trust` exists to warn about.
