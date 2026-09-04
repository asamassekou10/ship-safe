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
| Cron | `cron/**`, `tools/cronjob_tools.py` | Job identity, lifecycle, subprocess environment, and effects | **Partial** | Generic scheduled skill-to-prompt detection | Existing rule is not calibrated to the current Python scheduler, lifecycle guard, retries, or retained authority; #187 |
| Credential scoping | `tools/environments/local.py`, `tools/code_execution_tool.py`, `tools/credential_files.py`, `cron/scheduler.py` | Filtered flow into lower-trust subprocesses; not containment | **Partial** | Generic sub-agent forwarding and credential-store exposure | Environment presence does not prove reachability or use; build the source-to-consumer-to-effect chain in #188 |

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
