# Changelog

All notable changes to ship-safe are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [9.3.2] — 2026-05-20 — HermesSecurityAgent wiring fix

### Fixed

- **`HermesSecurityAgent` never ran in a real scan.** Its `shouldRun()`
  gate tested `recon.dependencies` — a field the `ReconAgent` does not
  produce (recon emits `frameworks`, `configFiles`, `languages`,
  `packageManagers`, but never `dependencies`). The gate therefore always
  returned `false`, so the agent was skipped in every `audit` and
  `red-team` run. Unit tests passed because they call `analyze()`
  directly, bypassing the gate.

  Impact: **every Hermes rule shipped to date was dead code in production**
  — the original tool-registry / memory / skill rules, the three v9.3.0
  "Tenacity" rules, and the three v9.3.1 `xurl` rules. None of them could
  fire in a real scan.

  Fix: `shouldRun()` now returns `true` unconditionally. The real gate is
  `_findHermesFiles()` inside `analyze()`, which does precise content-based
  detection (hermes imports, `hermes.config`, `agent-manifest`, `.hermes/`,
  `hermes-skills/`, `xurl`) and returns nothing on non-Hermes projects. The
  per-file read cost is already paid by the secret scanner and other agents.

### Tests

- New orchestrator-path integration test: builds the full orchestrator,
  runs `runAll()` on a Hermes fixture, and asserts `HermesSecurityAgent`
  appears in `agentResults` and that a `HERMES_` finding surfaces. The
  pre-existing unit tests only exercised `analyze()` directly, which is
  why this class of regression went uncaught — the new test closes that
  gap. Suite: 195 → 196.
- Updated the `shouldRun` unit test to assert the corrected behavior and
  added a companion test proving `analyze()` emits nothing on a
  non-Hermes project (the actual gate).

## [9.3.1] — 2026-05-12 — xurl skill coverage

Detection for the `xurl` skill attack surface — the xAI guide published
this week walks Hermes Agent users through wiring an agent to read and
write to X (post, reply, quote, DM, manage lists) through the `xurl`
CLI. That introduces a credentialed, subprocess-driven, cron-schedulable
write path to a live social account. This release adds coverage for the
three highest-impact failure modes.

### Agent security

- **`HERMES_XURL_READ_WRITE_LOOP`** (critical — ASI-01, CWE-94) — a
  structural check that flags a skill, cron task, or source flow which
  both reads X content (`xurl search` / `timeline` / `bookmarks` — all
  attacker-controlled) and writes to X (`xurl post` / `reply` / `quote`
  / `like` / `dm`) with no human-approval gate. A poisoned post the
  agent reads while summarizing a timeline can hijack it via indirect
  prompt injection into posting on the linked account. Suppressed when
  a `requireApproval` / `human-review` / `dry-run`-style gate is present.

- **`HERMES_XURL_SUBPROCESS_INJECTION`** (critical — ASI-03, CWE-78) —
  flags an `xurl` command assembled as a shell template string with a
  `${…}` interpolation. The agent's natural-language → `xurl` translation
  is being built as a string; a prompt injection reaching the
  interpolation controls real write actions on a live X account.

- **`HERMES_XURL_TOKEN_STORE_EXPOSURE`** (critical — ASI-10, CWE-538) —
  flags a `COPY` / `ADD` / `cp` / `rsync` / `scp` / `tar` / `mv` of the
  `~/.xurl` credential store (OAuth tokens + X API client secrets, YAML)
  or `~/.hermes/auth.json` (auto-refreshing provider tokens) into an
  image, archive, or another host.

The `HermesSecurityAgent` source-file content filter now also matches
files that reference `xurl` so xurl-driving code is scanned even when it
does not import the hermes-agent SDK directly.

### Secrets

- **X API OAuth Client Secret** — new `SECRET_PATTERNS` entry (critical).
  Detects a high-entropy value next to `client_secret` / `consumer_secret`.
- **X API v2 Bearer Token** — new `SECRET_PATTERNS` entry (critical).
  Detects the `AAAA…`-prefixed v2 bearer-token shape.

  (xAI `xai-` keys were already covered since v9.2.)

### Tests

- 7 new tests (188 → 195): 4 for the xurl agent rules — including a
  negative test confirming the human-approval gate suppresses
  `HERMES_XURL_READ_WRITE_LOOP` — and 3 for the X API secret patterns.

## [9.3.0] — 2026-05-11 — Tenacity Patch

This release picks up the security flow from the past 30 days — the
MCP-ecosystem CVE wave (Anthropic declined a protocol-level fix) and the
Hermes Agent v0.13.0 "Tenacity Release" P0 patches (May 7, 2026). Three
new structural checks land, four MCP rules carry CVE annotations, plus
the hardening work that originally motivated the release.

### Agent security

- **Three new Hermes structural checks** mapped to specific PRs in
  Hermes Agent v0.13.0 (NousResearch/hermes-agent@v2026.5.7):
  - **`HERMES_AUTH_JSON_TOCTOU`** (high — ASI-04, CWE-367) — race
    between stat/read and non-atomic write of `auth.json` or MCP OAuth
    credential paths. Skips files that import `write-file-atomic` or
    use the temp+rename idiom. Maps to PRs #21176 + #21194.
  - **`HERMES_CRON_SKILL_INJECTION`** (high — ASI-01, CWE-94) — a
    scheduled task (`cron.schedule`, `setInterval`, `nodeCron`,
    `scheduler.*`) loads a Hermes skill file and assembles its content
    into a prompt without a `scanForInjection`/`sanitize`/`validatePrompt`
    call in the handler body. Maps to PR #21350.
  - **`HERMES_BROWSER_CLOUD_METADATA_SSRF`** (high — ASI-04, CWE-918) —
    a browser- or HTTP-fetch tool definition performs an outbound
    request without enforcing the cloud-metadata SSRF floor
    (169.254.169.254, 100.100.100.200, metadata.google.internal,
    169.254.170.2, fd00:ec2::254). Skips files that already reference
    a metadata host (assumed to be blocking it). Maps to PR #21228.

- **CVE annotations on four existing MCP rules.** The MCP-ecosystem
  RCE wave that broke in April 2026 maps to patterns Ship Safe has
  detected for releases; we now name the CVEs directly in finding
  output so users can speak about coverage in CVE terms:
  - `MCP_TOOL_SHELL_EXEC` → **CVE-2026-30615** (Windsurf prompt-injection
    → local RCE, zero user interaction)
  - `MCP_DYNAMIC_TOOL_REGISTRATION` → **CVE-2026-26118** (Microsoft MCP
    tool hijacking)
  - `MCP_TOOL_NETWORK_REQUEST` → **CVE-2026-44284** (FastGPT MCP SSRF in
    tool URL handling)
  - `MCP_NO_AUTH_TRANSPORT` → **CVE-2026-33032** (nginx-ui MCP unauth
    RCE, CVSS 9.8, 2,600+ exposed instances)

  No detector logic changes — only the `description` strings and a new
  optional `cves` array on the affected rule objects. Findings carry
  CVE IDs in their description text from this release forward.

### Fixed

- **`ship-safe plugin new` crashed with `ReferenceError: path is not defined`.**
  The plugin subcommand in `cli/bin/ship-safe.js` called `path.resolve()`
  without importing the `path` namespace — only `dirname, join` were
  destructured at the top of the file. Now uses `resolve` from the same
  named import, matching the existing pattern.

- **Vestigial `if (force || true)` in `cli/commands/init.js`.** Removed a
  conditional whose condition was always true (left over from a removed
  `--force` flag). Behavior unchanged — the rule already short-circuited
  on the `AGENT_MARKER` check above it.

- **Missing error-cause chain in `cli/commands/live-advisories.js`.** OSV.dev
  network errors are now rethrown with `{ cause: err }` so downstream
  handlers can inspect the original failure.

- **`BUILT_IN_AGENTS` docstring said "22 scanning agents"** when the array
  has had 23 entries since v9.0. Corrected to 23.

### Quality

- **First real lint gate.** Adds `eslint.config.js` (ESLint 9 flat config),
  `eslint`/`@eslint/js`/`globals` as devDependencies, and `npm run lint` /
  `npm run lint:fix` scripts. First run surfaced 34 errors — all fixed in
  this release. 86 non-blocking warnings remain in legacy code paths.

  The 34 fixes break down as: 20 redundant regex escapes (no semantic
  change — `\-` at end of character class, `\.` outside a class, `\[`
  inside a negated class, `\/` inside `[...]`), 6 dead-write
  initializers in `red-team.js`/`agent-fix.js`/`swarm-orchestrator.js`/
  `agent.js`, 3 intentional ANSI ESC matches in `team-report.js`
  inline-disabled with comments, 2 BMP zero-width Unicode hunters in
  `agent-config-scanner.js` and `memory-poisoning-agent.js`
  inline-disabled (the chars are intentionally treated as a class).

- **38 new unit tests for the v9.2.0 agent fix system.** The agent fix
  loop landed in v9.2.0 with zero test coverage. This release adds
  `cli/__tests__/agent-fix.test.js` covering: `parseJsonLoose` (8 tests
  — bare JSON, ```json fences, brace-extraction from prose, etc.),
  `countOccurrences` (3), `locateFindString` (5 — including the
  whitespace-tolerant find-string drift recovery, both multi-line and
  single-line modes), `windowFileContent` (3), `validatePlan` (10 — all
  rejection paths plus the happy path with `_resolvedFind` annotation),
  `reverseEntry` (6 — standard find/replace round-trip, delete-on-create
  reverse, append strip, multi-edit reverse in opposite order, and
  failure modes), and `findUpwards` (4 — the `.ship-safeignore` walk-up
  used by subdirectory scans). Suite: **147 → 185 tests, 0 failures.**

  To support these tests, the following internals are exposed as named
  exports without changing the public API:
  - `cli/commands/agent-fix.js`: `parseJsonLoose`, `validatePlan`,
    `locateFindString`, `countOccurrences`, `windowFileContent`
  - `cli/commands/undo.js`: `reverseEntry`
  - `cli/commands/audit.js`: `findUpwards`

  These are not re-exported from `cli/index.js` — they remain test-only
  helpers and are not part of the published API surface.

---

## [9.2.1] — 2026-04-26

### Fixed

- **Double banner on bare `ship-safe`**: launching the REPL without arguments showed the help banner concurrently with the REPL banner because `shellCommand` was not awaited before `program.parse()` ran. Fixed by gating `program.parse()` in the `else` branch.

### Added

- **Glitch animation on startup**: the SHIP SAFE wordmark now animates in on REPL launch — each line scrambles through box-drawing characters and locks into place over ~300ms.

---

## [9.2.0] — 2026-04-26 — Ship Safe Agent: scan, plan, fix, ship

This release reorients ship-safe from a scanner into a fix-first agent. Find an issue, see a plan, accept it, ship the fix — all from your terminal or wired into CI.

### Added

- **`ship-safe agent [path]`** — interactive plan-then-execute fix loop.
  - Scans, then for each affected file: generates a structured fix plan via LLM, shows a unified diff, prompts `[a]ccept / [s]kip / [e]dit / [q]uit`, applies atomically, re-scans to verify, logs to `.ship-safe/fixes.jsonl`.
  - **Multi-file plans**: a single fix can also create `.env.example` and append to `.gitignore` as companion changes.
  - **Find-string drift recovery**: if the LLM's exact-match string drifts (whitespace), the agent retries with a normalized match before giving up.
  - **Failure diagnostics**: every plan that doesn't apply (parse error / LLM declined / validation rejected / provider error / empty response) is recorded with full context to `.ship-safe/failures.jsonl`.

- **`ship-safe shell`** — interactive REPL with persistent session state.
  - Slash commands: `/scan`, `/rescan`, `/findings`, `/show <n>`, `/plan <n>`, `/agent`, `/undo`, `/diff`, `/git`, `/provider`, `/clear`, `/help`, `/quit`.
  - Free-form prompts → LLM with the latest scan results as context.
  - **Streaming output**: tokens render as they arrive (OpenAI-compatible SSE — covers OpenAI, DeepSeek, Kimi, xAI).
  - **Bare `ship-safe` on a TTY drops into the shell** automatically; help banner is preserved for `--help` and piped stdin.

- **`ship-safe undo`** — revert the most recent agent fix (or all fixes with `--all`). Reverses edits, deletes created files, trims appended content. `--dry-run` shows what would change.

- **Agent flags**:
  - `--severity <level>` filter (default: low)
  - `--plan-only` to inspect plans without writing
  - `--branch [name]` to isolate fixes on a new branch with one commit per file
  - `--pr` to push the branch and open a PR via `gh` CLI; in CI on a PR event, also leaves a comment on the originating PR
  - `--yolo` to auto-accept every plan
  - `--auto-low` to auto-accept only plans the LLM marked `risk:low`
  - `--allow-dirty` to override the clean-tree check
  - `--provider`, `--model`, `--think` to control the LLM
  - `--sandbox` reserved for future Docker-isolated verification

- **`.ship-safeignore` walks up** from the scan target to the project root — subdirectory scans now honor the repo-level ignore file.

### Changed

- **`PROMPT_INJECTION_PATTERN`** rule no longer fires on the literal phrase "system prompt" (which appears in every line of legitimate LLM-using code). Tightened to actual jailbreak verbs.

- **`LLM_SYSTEM_PROMPT_CLIENT`** rule now skips server-side paths (`cli/`, `server/`, `lib/`, `api/`) — its whole premise is *client-side* exposure.

- Per-pattern `skipFile` predicate support in `LLMRedTeam` for context-aware suppression.

### Webapp

- Settings → AI Models — pick a default LLM provider, model, think-mode, and per-key API tokens.
- Scan form — per-scan AI options panel (provider picker, swarm/think toggles).
- Provider badges on every scan in history and team-runs (colored per provider).
- `aiOptions` now flow from form → API → `auditCommand`; `aiProvider` is recorded on completed scans and team runs.
- New columns added to the schema: `User.llmSettings`, `Scan.aiProvider`, `TeamRun.aiProvider`.

### Notes

- Old non-interactive Claude-only `ship-safe agent` behavior preserved as `ship-safe agent --legacy`.
- Real-CLI feel: bare `ship-safe`, streaming, persistent shell session, slash commands, edit-plan in `$EDITOR`.

---

## [9.1.0] — 2026-04-19 — AgenticSupplyChainAgent & Vercel Breach Impact Checker

### Added

- **`AgenticSupplyChainAgent`** — new 23rd security agent covering AI integration supply chain attack vectors, modelled on the Vercel April 2026 incident. Four detection tracks:

  | Rule | Severity | Category |
  |------|----------|----------|
  | `AI_CI_UNPINNED_AI_ACTION` | Critical | AI-named GitHub Actions referenced by mutable tags instead of commit SHAs |
  | `AI_CI_WRITE_ALL` | Critical | `permissions: write-all` in workflows that include AI actions |
  | `AI_CI_ADMIN_SCOPE` | Critical | `administration: write` paired with an AI action |
  | `AI_CI_SECRETS_WRITE` | Critical | `secrets: write` in workflows with AI actions |
  | `AI_CI_PACKAGES_WRITE` | High | `packages: write` paired with an AI action |
  | `VERCEL_AI_INTEGRATION_BROAD_SCOPE` | High | Vercel AI integrations holding write/admin/secret scopes (`vercel.json`) |
  | `GITHUB_APP_DANGEROUS_SCOPE` | High | GitHub App manifests with `administration`, `secrets`, or `members` write access |
  | `GITHUB_APP_INSECURE_WEBHOOK` | High | GitHub App webhook URLs using plain HTTP |
  | `NETLIFY_AI_PLUGIN_SECRET_EXPOSURE` | High | Netlify AI plugins receiving secrets via build config (`netlify.toml`) |
  | `WEBHOOK_NO_HMAC_VERIFICATION` | High | AI/payment platform webhook handlers with no HMAC signature check |
  | `WEBHOOK_RAW_BODY_NOT_USED` | Medium | JSON-parsed body used as HMAC input (invalidates the signature) |
  | `MCP_TOKEN_FORWARD_ENV` | High | High-value credentials in MCP/agent configs pointing at non-localhost URLs |
  | `MCP_THIRD_PARTY_SERVER_WITH_AUTH` | Critical | MCP server configs sending auth headers to third-party endpoints |
  | `HERMES_TOOL_EXFIL` | Critical | Hermes tool configs forwarding credentials cross-boundary |
  | `AGENT_OAUTH_SCOPE_CREEP` | High | Agent configs requesting 4+ OAuth scopes |

  Maps to: ASI-02, ASI-06, ASI-09, CICD-SEC-8, CWE-200, CWE-250, CWE-272, CWE-345, CWE-829.

- **Vercel April 2026 Breach Impact Checker** (`/breach/vercel-april-2026`) — public web tool letting anyone check whether their project is exposed to the same attack patterns. Four self-service checks:
  - **GitHub workflow scan** — fetches `.github/workflows/*.yml` via the GitHub API and flags unpinned AI actions (no auth required)
  - **Vercel integration scope audit** — lists installed integrations and flags dangerous scope combinations using a user-supplied read-only Vercel token
  - **Vercel audit log analysis** — pulls the audit log and looks for env reads, unexpected deployments, and new token creations during the incident window (Mar 28 – Apr 12, 2026)
  - **Config paste scanner** — runs `AgenticSupplyChainAgent` Track 4 patterns against a pasted `.mcp.json` or Hermes config inline; handles both JSON and YAML format. Tokens used for one request, never stored.

- **Blog post** — full incident analysis: *The Vercel April 2026 Incident: How a Compromised AI Integration Became a Supply Chain Attack* (`/blog/vercel-april-2026-ai-integration-supply-chain-attack`). Covers the four attack vectors, exact detection rules, remediation steps, and IOCs from the Vercel bulletin.

- **Agent team orchestration hardening** (from previous session, landing in this release):
  - `stripAnsi()` — strips ANSI escape codes from Hermes terminal output before it enters synthesis prompts
  - `parseFindings()` — parses `FINDING:` JSON lines from raw agent text as a fallback to SSE events
  - `deduplicateAndCorrelate()` — deduplicates findings across agents by `(title + location)`, escalates severity when 2+ agents flag the same asset, emits attack chains
  - `extractRecon()` — captures Lead agent's Phase 1 attack surface prose and injects it into sub-agent prompts as structured handoff context
  - `ROLE_STRATEGY` — per-role focused search instructions (pen tester, red team, secrets, CVE analyst) to prevent wasted tool iterations
  - `ROLE_TIMEOUT_MS` — per-role timeout budget: pen tester 10 min, red team / secrets 8 min, CVE analyst 6 min, custom 5 min
  - `collectAgentRun` — optional `timeoutMs` parameter so team orchestrator can apply per-role budgets
  - Synthesis fallback — if the Lead returns an empty report, the orchestrator constructs one directly from deduplicated sub-agent findings

### Changed

- Agent count updated from 22 to 23 across README, webapp hero stat, AgentDirectory component, docs metadata, deploy page, hermes page, pricing page, features component, blog post footer CTA, and plans data.
- `AgenticSupplyChainAgent` registered in `BUILT_IN_AGENTS` alongside all existing agents.
- Sitemap updated with `/breach/vercel-april-2026` at priority 0.9.

---

## [9.0.0] — 2026-04-15 — Agent Studio, Teams, Findings & Monthly Billing

### Added

- **Agent Studio** — full CRUD UI for creating and managing Hermes agents. Wizard-based creation, settings editor, per-agent findings tab, and run history.
- **VPS Deployment Infrastructure** — one-click deploy from the dashboard to the Hermes orchestrator on the VPS. Agents run in isolated Docker containers with memory/CPU limits. Port allocator, health checks, and nginx reverse proxy managed automatically.
- **Agent Console** — live chat interface with SSE streaming, ANSI color rendering, tool-call display, and per-session run records saved to the database.
- **Agent Triggers** — webhook and cron triggers per agent. Webhook triggers expose a public `POST /api/trigger/[id]` endpoint; cron triggers fire via the Vercel daily cron job.
- **Agent Teams** — multi-agent team orchestration with a 4-phase pipeline: Planning → Delegating → Synthesizing → Done. Lead agent delegates tasks to specialists in parallel; results are synthesised into an executive report.
- **Team Run Viewer** — live auto-polling UI showing phase progress, hierarchical run tree (parent/child runs), and the final synthesised report.
- **Findings Dashboard** (`/app/findings`) — aggregated findings across all agents with severity chart, trend data, status filtering, and one-click GitHub issue creation.
- **Scan Investigation** — fire an agent directly from a scan result to deep-dive a specific finding.
- **Agent Sharing** — share an agent to an org so all org members can use it.
- **How-it-works explainers** on the Agents and Agent Teams pages.
- **Dark theme** with system preference detection (`prefers-color-scheme`).
- **Hermes Setup wizard** (`/app/deploy`) — config generator for self-hosted Hermes deployments.
- **Global error pages** — `not-found.tsx` (404) and `error.tsx` (500) for the full app.
- **CLI flags** — `--hermes-only` and `--fail-below <score>` added to the `audit` command.
- **Monthly subscription billing** — Pro ($9/month) and Team ($19/seat/month) plans replace the previous one-time payment model. Webhook handles `customer.subscription.deleted` to downgrade plans on cancellation.

### Changed

- Mobile nav fully synced with desktop nav (Agents, Agent Teams, Findings, Hermes Setup all added).
- Scheduled repo scans now wired to `/api/cron` (previously unconnected).
- Vercel cron schedule set to `"0 0 * * *"` (daily) for Hobby plan compatibility.
- Scan branch defaults to `""` (maps to `HEAD`) so repos not using `main` are handled correctly.
- Deploy Config renamed to Hermes Setup throughout the nav and UI.
- Stripe checkout updated to `mode: 'subscription'` with new monthly price IDs.
- Agent count corrected to 22 across pricing page, open-source section, and feature lists.

### Fixed

- SSE payloads JSON-encoded so newlines survive SSE framing.
- Hermes UI chrome (box borders, session_id, warnings) filtered from the token stream.
- `--continue` flag removed from Hermes CLI invocation (caused session-not-found errors).
- Orchestrator bound to `0.0.0.0` so Vercel can reach the VPS.
- VPS port allocator now scans live Docker ports instead of relying on a stale `ports.json`.
- Agent settings reload full agent object after save to prevent missing-deployments crash.
- Broken `/app/orgs` link fixed.
- XSS false positive suppressed on agent console markdown renderer.

---

## [8.0.0] — 2026-04-10 — Ship Safe × Hermes Agent

### Added

- **`HermesSecurityAgent`** — new agent purpose-built for Hermes Agent (NousResearch) deployments. Detects 17 attack patterns across the full OWASP Agentic AI Top 10 surface. Only runs when Hermes is detected in the project (via deps, frameworks, or config files — zero overhead otherwise).

  Detection rules:

  | Rule | Severity | OWASP |
  |------|----------|-------|
  | `HERMES_REGISTRY_REMOTE_URL` | critical | ASI-05 |
  | `HERMES_REGISTRY_ENV_VAR_URL` | high | ASI-05 |
  | `HERMES_FUNCTION_CALL_NO_ALLOWLIST` | critical | ASI-03 |
  | `HERMES_XML_TOOL_CALL_UNSAFE_PARSE` | high | ASI-03 |
  | `HERMES_TOOL_ARGS_UNVALIDATED` | critical | ASI-03 |
  | `HERMES_ADDITIONAL_PROPERTIES_TRUE` | high | ASI-03 |
  | `HERMES_PLAN_USER_INPUT` | critical | ASI-01 |
  | `HERMES_GOAL_PROMPT_INJECTION` | critical | ASI-01 |
  | `HERMES_MEMORY_UNVALIDATED_WRITE` | critical | ASI-06 |
  | `HERMES_MEMORY_EXFIL_PATTERN` | critical | ASI-06 |
  | `HERMES_SKILL_NO_PERMISSIONS_FIELD` | medium | ASI-02 |
  | `HERMES_SKILL_WILDCARD_PERMISSIONS` | high | ASI-02 |
  | `HERMES_SUB_AGENT_CREDENTIAL_FORWARD` | critical | ASI-07 |
  | `HERMES_UNBOUNDED_AGENT_DEPTH` | high | ASI-02 |
  | `HERMES_AGENT_OUTPUT_UNVALIDATED_ACTION` | high | ASI-03 |
  | `HERMES_MANIFEST_NO_INTEGRITY` | high | ASI-10 |
  | `HERMES_MANIFEST_NO_VERSION_PIN` | medium | ASI-10 |

  Plus 4 structural checks: tool name collisions, tool context forwarding, skill frontmatter permission drift, memory file deserialization.

- **`AgentAttestationAgent`** — new supply-chain agent detecting missing attestation in agent manifests. Checks unpinned versions (`latest`, `^`, `~`), missing integrity hashes on remote resources, manifest loaded without signature verification, `skipIntegrityCheck: true` bypass, dynamic `require()` of manifest from env vars, and missing provenance fields. Maps to ASI-10 and SLSA Level 0.

- **Hermes function-call poisoning patterns in `scan-mcp`** — 8 new patterns added to the MCP manifest scanner: `<tool_call>` injection, `<function_calls>` injection, `tool_choice` manipulation, forced tool invocation, `additionalProperties: true` schema bypass, env-var late binding registry, namespace collision/shadowing, recursive sub-agent spawning.

- **Cross-skill/tool binding validation in `scan-skill`** — frontmatter YAML parser validates `tools:`, `permissions:`, and `version:` fields in Hermes skill markdown. Flags unresolvable tool references, missing permissions field, tools declared without permissions (permission drift), wildcard permissions, and Hermes function-call injection in skill bodies.

- **`skills/ship-safe-security.md`** — first-class Hermes skill definition making Ship Safe a Hermes Agent citizen. Declares 5 tools with proper `permissions:` and `version:` frontmatter fields.

- **`hermes-tool-registry.js`** — 5 Ship Safe tools declared in Hermes tool-registry format with integrity hash verification. `registerWithHermes(toolRegistry)` integrates Ship Safe into any Hermes agent bootstrap. Throws on integrity mismatch (supply-chain protection).

- **`--agentic [iterations]` flag for `audit`** — scan → annotate fixes → re-scan loop. Delegates annotation to the existing `autofix` module (correct comment style, idempotency, NEVER_EDIT list). Runs up to N iterations (default: 3) or until score reaches `--agentic-target` (default: 75).

- **Exports** — `HermesSecurityAgent`, `AgentAttestationAgent`, `HERMES_TOOLS`, `registerWithHermes`, `verifyIntegrity` now exported from `cli/index.js`.

### Changed

- Agent pool bumped from 20 to 22 agents (`HermesSecurityAgent` + `AgentAttestationAgent`).
- `HermesSecurityAgent.shouldRun()` now returns `false` for non-Hermes projects (checks deps, frameworks, and config file names) — zero overhead on standard codebases.
- `scan-skill` imports `hermes-tool-registry` lazily (first Hermes frontmatter check only) — no startup cost for non-Hermes skill scans.

### Fixed

- `AgentAttestationAgent.analyze()` was receiving a `context` object instead of a files array — now correctly destructures `{ files, rootPath }` from context.
- Integrity hashes in `hermes-tool-registry.js` corrected to match actual tool definition content.
- Agentic loop no longer calls `process.exit()` on inner re-scan iterations — returns `{ score, findings }` instead and defers exit to the outermost call.

---

## [7.1.0] — 2026-04-08

### Added

- **`ManagedAgentScanner`** — new 20th scanning agent purpose-built for Claude Managed Agents configuration security. Anthropic's Managed Agents platform (beta, April 2026) runs Claude in cloud containers with bash, file system access, and web browsing. The default configuration is maximally permissive: all 8 tools enabled, `always_allow` permission policy, and unrestricted outbound networking. This agent detects 12 classes of misconfiguration across every security-relevant surface in the Managed Agents API.

  Detection rules:

  | Rule | Severity | OWASP |
  |------|----------|-------|
  | `MANAGED_AGENT_ALWAYS_ALLOW` | critical | ASI-03 |
  | `MANAGED_AGENT_BASH_NO_CONFIRM` | critical | ASI-03 |
  | `MANAGED_AGENT_ALL_TOOLS_DEFAULT` | high | ASI-05 |
  | `MANAGED_AGENT_MCP_ALWAYS_ALLOW` | high | ASI-05 |
  | `MANAGED_AGENT_UNRESTRICTED_NET` | high | ASI-04 |
  | `MANAGED_AGENT_NO_NETWORK_LIMIT` | medium | ASI-04 |
  | `MANAGED_AGENT_MCP_HTTP` | critical | ASI-04 |
  | `MANAGED_AGENT_CALLABLE_AGENTS` | medium | ASI-03 |
  | `MANAGED_AGENT_NO_SYSTEM_PROMPT` | low | ASI-07 |
  | `MANAGED_AGENT_HARDCODED_TOKEN` | critical | ASI-04 |
  | `MANAGED_AGENT_STATIC_BEARER_INLINE` | critical | ASI-04 |
  | `MANAGED_AGENT_UNPINNED_PACKAGE` | medium | ASI-04 |

  The scanner uses a relevance signal check (API calls, SDK usage, `agent_toolset_20260401` references) before running patterns, so it adds zero overhead to projects not using Managed Agents.

- **Blog post** — "Scanning Claude Managed Agents: 12 Security Rules for the OWASP Agentic Top 10" covering the full config schema, dangerous defaults, and a secure-by-default configuration checklist.

- **Webapp updates** — new FAQ entry, 4 new ThreatMarquee entries, updated JSON-LD structured data, agent count bumped to 20 throughout.

### Changed

- Agent pool bumped from 19 to 20 agents in `buildOrchestrator()`.
- `package.json` version bumped to `7.1.0`, description updated.
- README: all "19 agents" references updated to 20, v7.1.0 highlights added, ManagedAgentScanner added to the agent table.

---

## [6.4.0] — 2026-04-01

### Added

- **`ship-safe scan-mcp [target]`** — new command that fetches and analyzes an MCP server's tool manifest before you connect to it. Accepts a remote URL (queries `tools/list` via JSON-RPC 2.0, with fallbacks to `GET /tools` and root endpoint) or a local manifest file. Checks every tool definition for prompt injection in descriptions, silent exfiltration instructions, credential harvesting patterns, sensitive path references, output suppression, permission escalation, known exfiltration service domains, dangerous tool names (`exec`, `shell`, `bash`, `run_command`), unsafe input schema parameters (`command`, `code`, `script`, `eval`), and tools requiring sensitive credential parameters. Runs threat intel hash and signature matching on the full manifest. Exits non-zero on critical findings for use in CI. `--json` flag for machine-readable output.

- **openclaude detection** — `AgentConfigScanner` now detects `.openclaude-profile.json` (the only persistent file openclaude creates) and flags `OPENAI_BASE_URL` values using plain `http://` for non-localhost endpoints. This covers the real security surface of openclaude: a CLI tool whose config is env-var-only, with the profile file as the sole file artifact. Corrects earlier detection rules that were based on a server architecture openclaude does not have.

- **claw-code detection** — `AgentConfigScanner` now scans `.claw.json`, `.claw/settings.json`, and `.claw/settings.local.json` (the actual config files used by the claw-code Rust/Python rewrite). Detects: `permissionMode: danger-full-access` or `dangerouslySkipPermissions: true` (disables all confirmation dialogs), `sandbox.enabled: false` (removes filesystem isolation), hook commands containing shell execution or remote download patterns (RCE via committed `.claw.json`), and MCP server connections over unencrypted `ws://` or `http://` to non-localhost hosts.

- **CI/CD agent safety patterns** — four new rules in `CICDScanner`:
  - `CICD_AGENT_SKIP_PERMISSIONS` — flags `--dangerously-skip-permissions` in CI workflow steps (critical)
  - `CICD_AGENT_INSECURE_PROVIDER` — flags AI agent provider env vars using `http://` for non-localhost (high)
  - `CICD_OPENCLAUDE_IN_CI` — flags `openclaude` invoked in CI, reminding operators to verify secrets and profile hygiene (medium)
  - `CICD_CLAW_DANGER_MODE` — flags `claw --dangerously-skip-permissions` in CI (critical)

- **Legal dataset corrections** — removed `claw-code` from `LEGALLY_RISKY_PACKAGES`. The instructkr/claw-code repository has pivoted to a clean-room Rust + Python rewrite and explicitly removed the leaked Anthropic TypeScript. It is not a DMCA-covered derivative. `claw-code-js` and `openclaude`/`openclaude-core` remain flagged as leaked-source derivatives under active enforcement.

- **openclaude and claw-code blog posts** — two new security research posts on the Ship Safe blog: architecture breakdowns, real config surfaces, and concrete risks for teams running either tool.

- **KAIROS blog post** — analysis of the autonomous background agent mode discovered in the leaked Claude Code source. Documents why proactive/heartbeat-loop agents change the threat model for prompt injection, which attack vectors become practical, and what to configure in claw-code and openclaude to reduce exposure.

### Fixed

- **openclaude detection correctness** — previous release incorrectly modeled openclaude as a server with auth/host/port config fields. Replaced with accurate profile-file-based detection. Previous blog post claiming openclaude binds to `0.0.0.0:18789` has been corrected.
- **claw-code legal classification** — previous release classified claw-code as a DMCA-covered leaked-source derivative. Corrected after reading the actual repository: it is a clean-room rewrite.

---

## [6.3.0] — 2026-04-01

### Added
- **`ship-safe legal [path]`** — new standalone command that scans dependency manifests (`package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`) for packages carrying legal risk: DMCA takedowns, leaked-source derivatives, IP disputes, and license violations.
- **`LegalRiskAgent`** — new agent in `cli/agents/legal-risk-agent.js`. Exports `LEGALLY_RISKY_PACKAGES` — a structured dataset where each entry carries name, ecosystem, risk type (`dmca` | `ip-dispute` | `leaked-source` | `license-violation`), severity, human-readable detail, and reference URLs.
- **Initial legal dataset** — seeds five entries:
  - `claw-code` (npm, all versions) — DMCA, derived from leaked Anthropic Claude Code source (March 2026)
  - `claw-code-js` (npm, all versions) — leaked-source, JavaScript port of the same leak
  - `claude-code-oss` (npm, all versions) — leaked-source, open-source mirror of the Claude Code leak
  - `faker@6.6.6` (npm) — license-violation, deliberately sabotaged release (January 2022)
  - `colors@1.4.44-liberty-2` (npm) — license-violation, deliberate infinite-loop sabotage
- **`--include-legal` flag on `audit`** — `ship-safe audit . --include-legal` runs the legal risk scan as Phase 3b and merges findings into the final report and score.
- **`legal` category** — added to `CATEGORY_LABELS` and `EFFORT_MAP` in `audit.js` so legal findings appear correctly in HTML reports and remediation plans.
- **8 new unit tests** for `LegalRiskAgent` covering: DMCA detection, leaked-source detection, clean project pass, specific-version matching, safe-version pass, semver prefix stripping, Python manifest (no cross-ecosystem false positives), and category assertion.

---

## [6.2.0] — 2026-04-01

### Added
- **Claude Code hooks** — `npx ship-safe hooks install` registers `PreToolUse` and `PostToolUse` hooks in `~/.claude/settings.json`. Hooks block critical secrets before they land on disk and inject advisory scan results into Claude's context after every file write.
- **`cli/hooks/pre-tool-use.js`** — Blocks Write/Edit/MultiEdit/NotebookEdit if critical secrets detected; blocks dangerous Bash patterns (curl|bash pipe, PowerShell iex, credential file reads, env-var exfiltration, `rm -rf /`, `--unsafe-perm`). Warns on `.env` files not covered by `.gitignore`. Provides language-specific fix suggestions.
- **`cli/hooks/post-tool-use.js`** — Advisory-only scanner that runs after every successful file write. Reports critical and high-severity findings into Claude's context without blocking. Never scans `.env`, `.env.example`, test fixtures, or mocks.
- **`cli/hooks/patterns.js`** — Shared pattern module: 18 `CRITICAL_PATTERNS` (AWS, GitHub PAT × 4, Anthropic, OpenAI, Stripe × 2, Slack × 2, Twilio, Google, npm, PyPI, Supabase service role, PEM private key), 3 `HIGH_PATTERNS` with Shannon entropy gate, 7 `DANGEROUS_BASH_PATTERNS`, `scanCritical()`, `scanHigh()`, `buildFixSuggestion()`.
- **Stable hook script location** — hooks are copied to `~/.ship-safe/hooks/` at install time; registered paths point there rather than the volatile `npx` cache directory. Hooks survive `npx` cache rotations and package updates.
- **Universal LLM support** — `--provider <name>` and `--base-url <url>` flags on `audit` and `red-team`. Supports Groq, Together AI, Mistral, DeepSeek, xAI/Grok, Perplexity, LM Studio, and any OpenAI-compatible endpoint. Auto-detects `GROQ_API_KEY`, `TOGETHER_API_KEY`, `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY` from environment.
- **`OpenAICompatibleProvider`** — new provider class in `cli/providers/llm-provider.js` with preset configurations for 7 providers and generic custom-URL support.
- **Supply chain IOC detection** — `COMPROMISED_PACKAGES` list in `supply-chain-agent.js` with known-bad versions (`litellm 1.82.7/1.82.8`, `axios 1.8.2`, `telnyx 2.1.5`). `ICP_BLOCKCHAIN_PACKAGES` check for CanisterWorm-style C2 indicators in transitive deps.
- **CI/CD hardening patterns** — `CICD_ENV_EXFILTRATION` (secrets sent over network in Actions), `CICD_OIDC_BROAD_SUBJECT` (wildcard OIDC subjects), `CICD_OIDC_MISSING_SUBJECT` (id-token write without subject constraint) in `cicd-scanner.js`.
- **Unpinned action detection fix** — `CICD_UNPINNED_ACTION` now catches `@v1.2.3` semver tags in addition to `@main`/`@latest` (requires 40-char SHA hex to be considered pinned).
- **Hook pattern tests** — 30+ unit tests covering `scanCritical`, `scanHigh`, `shannonEntropy`, and `DANGEROUS_BASH_PATTERNS` in `cli/__tests__/agents.test.js`.

### Fixed
- **npx path instability** — `hooks install` no longer writes the volatile npx cache path to `~/.claude/settings.json`. Scripts are now copied to `~/.ship-safe/hooks/` before registration.
- **Supabase JWT false positives** — pattern now requires `c2VydmljZV9yb2xl` (base64 of `service_role`) in the payload section, eliminating matches on arbitrary HS256 JWTs.
- **Twilio Account SID false positives** — pattern tightened to `AC[a-f0-9]{32}` (lowercase hex only), removing matches on mixed-case alphanumeric strings.
- **`/dev/stdin` not available on Windows** — hooks now read stdin via async `process.stdin` event listeners with a 3-second safety timeout instead of synchronous `/dev/stdin` reads.

---

## [5.0.0] — 2026-03-16

### Added
- **3 new security agents** — MCPSecurityAgent (MCP server misuse, tool poisoning), AgenticSecurityAgent (OWASP Agentic AI Top 10), RAGSecurityAgent (RAG pipeline security, context injection), PIIComplianceAgent (PII detection in source code)
- **VerifierAgent** — post-processor that probes provider APIs (GitHub, OpenAI, Stripe, Slack, etc.) to verify if leaked secrets are still active
- **DeepAnalyzer** — LLM-powered taint analysis sends critical/high findings to LLM for exploitability verification; supports Anthropic, OpenAI, Google, Ollama with budget controls (`--budget <cents>`)
- **`ship-safe ci`** — dedicated CI/CD command with compact one-line output, threshold-based gating (`--threshold`, `--fail-on`), SARIF output for GitHub Code Scanning
- **Cross-agent awareness** — `sharedFindings` in orchestrator context allows later agents to see findings from earlier agents
- **Framework-aware scanning** — agents implement `shouldRun(recon)` to skip irrelevant projects (e.g., MobileScanner skips non-mobile projects)
- **`--deep` flag** — LLM-powered deep analysis on `audit` and `red-team` commands
- **`--local` flag** — use local Ollama model for deep analysis
- **`--verify` flag** — probe provider APIs to check if leaked secrets are still active
- **`--budget <cents>` flag** — cap LLM spend for deep analysis (default: 50 cents)
- **CRA-ready SBOM** — EU Cyber Resilience Act compliance fields: supplier, lifecycles, licenses, vulnerability attachment
- **OWASP Agentic AI Top 10 coverage** — ASI01-ASI10 via AgenticSecurityAgent
- **Claude Code plugin v3.0** — added `/ship-safe-deep` and `/ship-safe-ci` skills
- **90 unit tests** across 26 suites

---

## [4.3.0] — 2026-03-08

### Added
- **Supabase RLS Agent** — dedicated agent for Row Level Security auditing: detects `service_role` key in client code, `CREATE TABLE` without `ENABLE ROW LEVEL SECURITY`, anon key inserts, unprotected storage
- **Context-aware confidence tuning** — post-processing step downgrades confidence for test files, docs, comments, and example paths to reduce false positives by up to 70%
- **`ship-safe baseline`** — accept current findings as a baseline, only report new findings on subsequent runs (`--diff`, `--clear`)
- **`--baseline` flag on `audit`** — filter out baselined findings, only show regressions
- **`--pdf` flag on `audit`** — generate PDF report via Chrome headless (falls back to print-optimized HTML)
- **Expanded auto-fix** — `remediate --all` fixes 5 common agent patterns: TLS bypass, Docker `:latest`, debug mode, dangerouslySetInnerHTML, `shell: true`
- **Dependency confusion detection** — scoped packages without `.npmrc` registry pinning, suspicious install scripts (`curl`, `eval`, `base64`)
- **Rate limiting detection** — project-level check for Express/Fastify apps without rate-limiting libraries
- **OpenAPI spec scanning** — missing `securitySchemes`, HTTP server URLs, secrets in example values
- **Terraform patterns** — RDS public access, CloudFront HTTP, Lambda admin role, S3 no versioning
- **Kubernetes patterns** — `:latest` image tags, missing NetworkPolicy
- **Code context in findings** — 3 lines before/after with highlighted flagged line in HTML report and verbose output
- **API pagination check** — `.find({})` without `.limit()` detection
- **49 unit tests** (16 new) covering all v4.3 features

---

## [4.2.0] — 2026-03-05

### Added
- **Parallel agent execution** — all 12 agents run concurrently with configurable concurrency (default: 6)
- **Per-agent timeouts** — `--timeout <ms>` flag (default: 30s) prevents agent hangs
- **Confidence-weighted scoring** — low-confidence findings count for 30%, medium for 60%, reducing noise
- **`ship-safe doctor`** — environment diagnostics (Node.js, git, npm, API keys, cache, version)
- **`--compare` flag** — per-category score delta table vs. previous scan
- **`--csv` flag** — CSV export for spreadsheets
- **`--md` flag** — Markdown report export
- **LLM response caching** — AI classifications cached for 7 days in `.ship-safe/llm-cache.json`
- **False positive suppression tracking** — counts `ship-safe-ignore` comments per rule in JSON output and history
- **Python security patterns** — f-string SQL injection, `subprocess.run(shell=True)`
- **Go security patterns** — `fmt.Sprintf` SQL injection, unescaped `template.HTML()`
- **Rust security patterns** — `unsafe` blocks, `.unwrap()` in production code
- **Django/Flask patterns** — `DEBUG = True`, hardcoded `secret_key`
- **33 unit tests** — using Node.js built-in test runner (`node:test`)

### Fixed
- Patched ReDoS vulnerabilities in 6 regex patterns across agents
- Fixed command injection risk in dependency audit (`execFileSync` instead of `exec`)
- Fixed API key exposure in error messages
- Fixed false positive SQL injection detection in version strings

---

## [4.1.0] — 2025-02-26

### Added
- **`audit` command** — full security audit: secrets + 12 agents + deps + scoring + remediation plan
- **HTML report** — standalone dark-themed report with table of contents (`--html`)
- **Incremental scanning** — cache file hashes and findings, ~40% faster on repeated scans
- **Smart `.gitignore` handling** — respects gitignore but always scans `.env`, `*.pem`, `*.key`

---

## [4.0.0] — 2025-02-24

### Added
- **12 security agents** — InjectionTester, AuthBypassAgent, SSRFProber, SupplyChainAudit, ConfigAuditor, LLMRedTeam, MobileScanner, GitHistoryScanner, CICDScanner, APIFuzzer, ReconAgent, ScoringEngine
- **`red-team` command** — run agents standalone with `--agents` filter
- **`score` command** — 8-category weighted scoring (0-100, A-F grades)
- **`watch` command** — continuous monitoring with file change detection
- **`sbom` command** — CycloneDX SBOM generation
- **`policy init` command** — policy-as-code with `.ship-safe.policy.json`
- **`deps` command** — dependency CVE audit with `--fix` option
- **SARIF output** — `--sarif` flag on audit/scan for GitHub Code Scanning
- **Multi-LLM support** — Anthropic, OpenAI, Google AI, Ollama
- **Claude Code plugin** — `/ship-safe`, `/ship-safe-scan`, `/ship-safe-score`
- **OWASP coverage** — Web Top 10 2025, Mobile Top 10 2024, LLM Top 10 2025, CI/CD Top 10

---

## [3.1.0] — 2025-02-19

### Added
- `remediate` command — auto-fix detected secrets by replacing hardcoded values with environment variable references
- `rotate` command — guide for rotating leaked credentials across supported services (AWS, OpenAI, Stripe, GitHub, Supabase, and more)

---

## [3.0.0] — 2025-01-XX

### Added
- `guard` command — install a git pre-push or pre-commit hook that blocks commits/pushes when secrets are detected
- `fix` command — scan and auto-generate a `.env.example` file with placeholder values for every found secret type
- `mcp` command — start ship-safe as an MCP (Model Context Protocol) server; lets Claude Desktop, Cursor, Windsurf, and Zed call `scan_secrets`, `get_checklist`, and `analyze_file` directly
- `--sarif` flag on `scan` — outputs SARIF 2.1.0 format for GitHub Code Scanning integration
- Custom pattern support via `.ship-safe.json` in the project root

### Changed
- Major CLI restructure — all commands are now subcommands of `ship-safe`

---

## [2.1.0] — 2024-12-XX

### Added
- Shannon entropy scoring for generic secret patterns — filters out placeholder values like `your_api_key_here`
- `.ship-safeignore` support — gitignore-style path exclusions
- Test file exclusion by default — test/spec/fixture/mock/story files are skipped unless `--include-tests` is passed
- `// ship-safe-ignore` inline suppression comment

### Changed
- Reduced false positives significantly with entropy threshold (3.5 bits)
- Each finding now includes a `confidence` level: `high`, `medium`, or `low`

---

## [2.0.0] — 2024-11-XX

### Added
- Comprehensive security toolkit: configs, snippets, and checklists for Next.js, Supabase, and Firebase
- `init` command — copy pre-built security configs into a project (`.gitignore`, security headers)
- `checklist` command — interactive 10-point launch-day security checklist
- `/ai-defense` directory — LLM security checklist, prompt injection patterns, cost protection guide, system prompt armor
- `/snippets` directory — rate limiting, CORS, input validation, JWT security
- `/configs` directory — Supabase RLS templates, Firebase rules, Next.js security headers

---

## [1.2.0] — 2024-10-XX

### Added
- 50+ new secret detection patterns covering AI/ML providers, cloud platforms, databases, payment processors, communication services, and hosting providers
- Patterns now include: Anthropic, OpenAI, Replicate, Hugging Face, Cohere, Groq, Mistral, Perplexity, Together AI, Vercel, Netlify, Heroku, Railway, Fly.io, Render, DigitalOcean, Cloudflare, Linear, Notion, Airtable, Figma, Lemon Squeezy, Paddle, Slack, Discord, Telegram, Mailgun, Resend, Postmark, Mailchimp, Upstash, Turso, and more

---

## [1.0.0] — 2024-09-XX

### Added
- `scan` command — scan a directory or file for leaked secrets using pattern matching
- Initial secret patterns: AWS keys, GitHub tokens, Stripe keys, private keys, database URLs, OpenAI keys, Supabase keys, Clerk keys
- `--json` flag for CI pipeline integration (exit code `1` if secrets found)
- `-v` verbose mode
- GitHub Actions CI workflow
