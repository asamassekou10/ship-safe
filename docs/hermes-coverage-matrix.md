# Hermes Agent coverage baseline

Ship Safe 10.0 targets one immutable upstream snapshot:

- release: **Hermes Agent v0.21.0**
- tag: [`v2026.8.31`](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.31)
- commit: [`29112bef099274229cadff79cdff7bf7b99c4b77`](https://github.com/NousResearch/hermes-agent/commit/29112bef099274229cadff79cdff7bf7b99c4b77)
- release published: **2026-08-31 19:29:49 UTC**
- baseline audited: **2026-09-04**

The tag and commit were resolved through the GitHub API. GitHub reports both
the annotated tag object and its commit as unsigned, so the commit SHA is the
identity Ship Safe pins. We do not follow `main` or a mutable release label.

The machine-readable copy is
[`cli/data/hermes-baseline.json`](../cli/data/hermes-baseline.json). Hermes's
policy at the pinned commit remains authoritative:
[`SECURITY.md`](https://github.com/NousResearch/hermes-agent/blob/29112bef099274229cadff79cdff7bf7b99c4b77/SECURITY.md).
The test fixture
[`hermes-v0.21.0-baseline.json`](../cli/__tests__/fixtures/hermes-v0.21.0-baseline.json)
pins representative paths from the same snapshot.

## Status definitions

- **Covered** means a detector is calibrated to this pinned surface and has a
  vulnerable fixture plus a safely constrained counterpart.
- **Partial** means Ship Safe has relevant detection, but it does not model the
  complete current surface or cannot support every implied verdict.
- **Uncovered** means there is no dedicated detector for the surface.

These labels describe Ship Safe's coverage, not Hermes Agent's security.

## Coverage matrix

| Surface | Upstream implementation | Boundary in the upstream model | Ship Safe status | Current detection | Known limitation / next issue |
|---|---|---|---|---|---|
| Plugin manifests | `plugins/**/plugin.yaml`, `hermes_cli/plugins.py` | Operator review before code loads into the agent process | **Partial** | Provenance, undeclared hooks, undeclared listeners | Install/discovery paths that hide code from review are not modeled; revalidate rules against the 101 manifests in this release |
| Network adapters | `gateway/platforms/**`, `plugins/platforms/**`, `gateway/platform_registry.py` | Caller authorization at every network surface | **Partial** | `HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN` checks Python adapter dispatch | Shared authorization, relay, HTTP-plugin, and bind-scope paths are incomplete |
| Terminal backends | `tools/environments/**`, `tools/terminal_tool.py`, `tools/code_execution_tool.py`, `hermes_cli/config.py`, `hermes_cli/setup.py` | OS isolation for shell and file operations only | **Partial** | `HERMES_LOCAL_BACKEND_UNTRUSTED_INPUT` and `HERMES_TERMINAL_BACKEND_SCOPE_GAP` correlate the configured backend with an enabled untrusted MCP path that remains in the agent process | Runtime-only CLI/environment overrides, OpenShell session binding, and custom terminal-environment plugins are not resolved statically |
| ACP | `acp_adapter/**` | Host-user controls for editor IPC | **Partial** | `HERMES_ACP_GATEWAY_EXPOSED` traces an unauthenticated, configured non-loopback WebSocket route to `HermesACPAgent.prompt` and agent tool execution | External reverse proxies, inherited deployment binds, and custom ACP transports are not resolved statically |
| TUI gateway | `tui_gateway/**`, `ui-tui/**` | Host-user controls for local JSON-RPC IPC | **Partial** | `HERMES_TUI_GATEWAY_EXPOSED` traces an unauthenticated, configured non-loopback WebSocket route through `handle_ws` to the shared dispatcher and its prompt, command, plugin, MCP, and terminal effects | Dynamic bind values, external reverse proxies, and authorization hidden in custom middleware are not resolved statically |
| Cron | `cron/**`, `tools/cronjob_tools.py` | Job identity, lifecycle, subprocess environment, and effects | **Partial** | Creation/update guard symmetry and run-scoped authority cleanup, plus legacy JavaScript skill-to-prompt detection | Dynamic call targets, third-party scheduler providers, custom persistence layers, and unknown authority wrappers remain unresolved |
| Credential scoping | `tools/environments/local.py`, `tools/code_execution_tool.py`, `tools/credential_files.py`, `cron/scheduler.py` | Filtered flow into lower-trust subprocesses; not containment | **Partial** | Configured credential declarations are correlated to registered project plugins, platform adapters, terminal skills, and persisted cron effects | Dynamic names, indirect registrations, external plugin installations, templated jobs, and unknown wrappers remain unresolved |

No surface is marked fully covered at this baseline. That is deliberate: the
matrix records what the current implementation can prove, not what its rule
names suggest.

## Boundary interpretation

Hermes's only containment boundary against an adversarial model is the OS.
Terminal-backend isolation confines shell and file operations (and, in the
pinned implementation, remote `execute_code` children), but not MCP clients,
plugins, hooks, or skills running in the agent process. Whole-process wrapping
can contain the complete process tree.

Ship Safe models all seven built-in backends in the pinned release: `local`,
`docker`, `modal`, `ssh`, `daytona`, `vercel_sandbox`, and `singularity`. An
explicit `local` selection is silent by itself. A hygiene finding requires a
second fact: an enabled MCP server marked untrusted whose client or subprocess
remains reachable from the agent process. For non-local backends, the finding
explains that this path sits outside terminal/file isolation. A repository that
runs Hermes itself through a Docker/Compose entrypoint carrying the scanned
Hermes config is treated as whole-process wrapped and is the safely constrained
counterpart. OpenShell can provide the same runtime posture, but repository
configuration alone does not yet prove that a particular Hermes process runs in
that session.

For local IPC, loopback binds and OS file permissions are the authorization
boundary. For network adapters, an operator-configured allowlist must fail
closed. A documented break-glass setting or an explicitly selected local
backend is not a vulnerability on its own.

### ACP and TUI gateway reachability

At the pinned release, ACP is JSON-RPC over inherited stdin/stdout. Its caller
is the local editor process; provider authentication supplies model credentials
but does not authorize the IPC caller. `HermesACPAgent.prompt` can run the
agent's configured tools, and `conn.request_permission` is an in-process user
interaction, not containment.

The classic TUI gateway is likewise JSON-RPC over inherited stdin/stdout (or a
parent-owned local socket). Its shared dispatcher reaches `prompt.submit`,
`command.dispatch`, plugins, MCP lifecycle actions, and terminal execution. The
dashboard also mounts that dispatcher over WebSocket, but rejects the upgrade
unless a server-verified token, ticket, or internal credential passes and the
Host/Origin and peer checks match the configured bind.

The two dedicated rules require all of the following before reporting a
boundary finding: an executable non-loopback bind, a network route, no
fail-closed caller-authentication branch before dispatch, and a route-local
call to the ACP prompt or TUI gateway sink. Imports and file-level
co-occurrence decide nothing. Findings record the caller, transport,
authentication, bind scope, handler, permission model, effect, and each source
location in the chain.

`reachabilityBasis` distinguishes how the conclusion was reached:

- `configured`: executable repository configuration proves the route and bind.
- `inferred`: code structure supports a path, but runtime configuration remains
  unresolved. The current rules do not promote this alone to a boundary
  finding.
- `reproduced`: an investigation exercised the path and captured runtime
  evidence. Static scanning never claims this value by itself.

The positive fixtures are executable configurations and therefore report
`configured`. Their loopback ACP and authenticated TUI counterparts remain
quiet. Reproducing a finding can strengthen it later through Ship Safe's
investigation layer without changing what the scanner observed.

### Cron lifecycle and retained authority

The pinned scheduler defines jobs through `create_job` and stores them in the
active profile's `jobs.json`. A fire combines the job ID with an execution ID,
acquires a durable fire claim, and installs profile-scoped secrets and
task-scoped working-directory state. Cooperative cancellation and fire-claim
ownership fence execution, saved output, delivery, and terminal bookkeeping.
Function-level `finally` blocks clear session state, task working directories,
secret scopes, and short-lived agent resources on successful, failed,
cancelled, and retried runs.

Ship Safe checks two lifecycle invariants:

- `HERMES_CRON_UPDATE_LIFECYCLE_GUARD_BYPASS` requires a persisted schedule,
  a lifecycle check on creation, an update that can change effective prompt,
  script, skills, or toolsets without the same check, and a reachable scheduled
  action. The finding cites all four locations. A wrapper-level check does not
  settle the result because the lower-level persistence API remains callable
  by recovery code and future entry points.
- `HERMES_CRON_RETAINED_AUTHORITY` requires a cron execution function that
  acquires a recognized run-scoped authority and then reaches a scheduled
  action. It reports only when the matching authority type is not released in
  a function-level `finally` block. Clearing unrelated context does not count
  as revoking a secret scope, permission, capability, or working-directory
  grant.

The v0.21.0 baseline produces one update-guard finding in `cron/jobs.py`: job
creation checks the effective prompt and script before persistence, while the
low-level update path persists merged payload fields without repeating that
check; the retained schedule later reaches script execution in
`cron/scheduler.py`. The pinned scheduler's normal, error, retry, cancellation,
and delivery paths do perform matching cleanup, so it produces no retained-
authority finding.

Cron remains **Partial** rather than Covered. Static analysis cannot resolve
dynamically selected call targets, scheduler-provider code outside the
repository, custom persistence implementations, or project-specific authority
wrappers it does not recognize. The older `HERMES_CRON_SKILL_INJECTION` rule is
explicitly scoped to JavaScript and TypeScript callback schedulers; JavaScript-
shaped strings in Python are not lifecycle evidence.

### Credential reachability

Credential presence is not a verdict. Hermes intentionally keeps provider and
platform secrets in profile-scoped storage, allows selected third-party values
through `terminal.env_passthrough`, and makes project plugins opt-in. Reporting
each declaration would confuse intended configuration with a demonstrated
exposure path.

`HERMES_CREDENTIAL_REACHABLE_EFFECT` therefore requires five resolved facts:

1. a credential name declared in Hermes configuration or a plugin manifest;
2. a scope that makes it available to a specific execution context;
3. a lower-trust recipient that is enabled and reachable;
4. executable code or a scheduled command that consumes that credential; and
5. an external network effect reached by the consuming operation.

For project plugins and platform adapters, the plugin must be listed in
`plugins.enabled`, project-plugin loading must be explicitly enabled, Hermes's
plugin API must register the consuming function, and that function must read
the named secret and pass it to a network operation. A declaration, dead
helper, or unregistered function decides nothing. For terminal skills, an
explicit passthrough entry, matching skill requirement, credential-bearing
command, and external operation are all required. Cron additionally requires
an enabled persisted job whose scheduled script consumes the credential.

Findings record only credential identifiers such as `DEPLOY_TOKEN`, never the
resolved value. JSON and SARIF carry the source, scope, recipient, reachable
operation, external effect, reachability basis, and resolvable locations. The
deterministic finding remains visible; static evidence does not claim a
reproduced or human-confirmed verdict.

Credential coverage remains **Partial**. Dynamic secret names, registration
through unknown wrappers, user and pip plugins outside the scanned repository,
generated job definitions, and network effects hidden behind custom clients
cannot be connected safely by this structural pass.

## Maintaining the baseline

Baseline updates are reviewed changes, never automatic tag following:

1. Query the latest GitHub release and resolve its tag to a full commit SHA.
2. Review the release notes, `SECURITY.md`, and the seven surface groups above.
3. Update the JSON baseline and this document in the same pull request.
4. Re-run the baseline contract test and relevant positive/safe fixtures.
5. Change a matrix status only when the detector is calibrated to the new
   snapshot and its evidence supports the advertised verdict.

Version drift is therefore visible as a code review. A newer Hermes release
does not silently expand Ship Safe's coverage claim.
