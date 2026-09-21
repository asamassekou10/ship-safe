# Roadmap

What Ship Safe is working on, what just shipped, and what we are deliberately
not building. Updated when a release goes out.

If you want to help, the [11.0 milestone](https://github.com/asamassekou10/ship-safe/milestone/3)
is the current work and its open issues are claimable. Comment on an issue to
take it. Every new rule still needs a false-positive story before it is
considered finished.

---

## Just shipped — 10.1.0, attestation precision

A small, single-purpose release. The pinned advisory table in
`cli/data/agent-advisories.json` records disclosure URLs as *evidence*, and the
attestation agent was reporting those URLs as unsigned executable resources —
Ship Safe flagging its own citations. The exemption is scoped to the
package-owned table, so a project file that happens to reuse that filename is
still scanned, and a regression test covers both halves.

Published with [provenance](https://www.npmjs.com/package/ship-safe): the npm
tarball carries a signed SLSA attestation naming the workflow and commit that
built it.

Full detail in the [changelog](CHANGELOG.md).

---

## Before that — 10.0.0, Hermes Agent coverage

The 10.0 milestone is closed: twelve issues, no open work. Ship Safe records a
pinned Hermes v0.21.0 baseline and traces security-relevant reachability across
plugin manifests, network adapters, terminal backends, ACP, TUI, cron jobs and
credential-scoping paths. The coverage matrix records what is checked and where
external or custom schedulers stay outside the model.

Also in 10.0.0: cron lifecycle evidence — schedule definition, persistence,
execution identity, cancellation, cleanup, and symmetry between guarded creation
and later updates, including that run-scoped authority is cleaned up on
exception and retry paths. And MCP protocol compatibility across legacy
initialize versions and the modern discovery request.

Full detail in the [changelog](CHANGELOG.md).

---

## Now — 11.0, Untrusted Inputs

An agent reads your repository before you type anything. Ship Safe 11.0 reads it
first, and says which files can cause execution and which agent versions are
documented to reach them. Scope and evidence model in
[#202](https://github.com/asamassekou10/ship-safe/issues/202).

**Landed so far**

- [#203](https://github.com/asamassekou10/ship-safe/issues/203) workspace trust —
  nine `WORKSPACE_*` rules over repo-borne execution sinks
- [#204](https://github.com/asamassekou10/ship-safe/issues/204) pinned advisory
  table mapping agent versions to documented execution sinks
- [#205](https://github.com/asamassekou10/ship-safe/issues/205) baseline drift —
  a reviewable workflow for tracking upstream Hermes releases
- [#125](https://github.com/asamassekou10/ship-safe/issues/125) language-scoped
  rules for `RAGSecurityAgent`

**Open, and claimable — comment on an issue to take it**

| issue | |
|---|---|
| [#103](https://github.com/asamassekou10/ship-safe/issues/103) | Scan A2A agent cards for poisoning, missing auth, and callback SSRF — *good first issue* |
| [#105](https://github.com/asamassekou10/ship-safe/issues/105) | Give rules a language scope so JS patterns stop running against Python and Ruby — *good first issue* |
| [#135](https://github.com/asamassekou10/ship-safe/issues/135) | Machine-readable protection status for agent integrations — *good first issue* |
| [#136](https://github.com/asamassekou10/ship-safe/issues/136) | A truthful "Protected by Ship Safe" session indicator |
| [#206](https://github.com/asamassekou10/ship-safe/issues/206) | Capability graph: repository-origin and A2A-delegation nodes |
| [#202](https://github.com/asamassekou10/ship-safe/issues/202) | The 11.0 scope issue itself |

### Two ideas shaping the work

**Posture-aware severity.** Hermes publishes an unusually explicit
[security policy](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md).
It names OS-level isolation as the only real boundary and says plainly that
in-process heuristics are not boundaries. A report that ignores that is noise to
anyone who has read it. So Hermes findings carry a posture: `boundary` for
classes their policy treats as in scope, `hygiene` for everything else, rendered
separately.

**Read their policy before writing rules.** See
[docs/hermes-security-model.md](docs/hermes-security-model.md). A rule that flags
something a trust model deliberately permits is a false positive no matter how
clever the regex.

**Note on scope.** Hermes coverage is built for our users who run Hermes. It is
not coordinated with Nous Research, and nothing here should be read as an
endorsement by them.

---

## Not planned

Saying this out loud so nobody builds it and gets turned away.

- **A new composite score.** The score saturates and we stopped gating on it.
  Proposals to re-weight it are unlikely to land; severity-based gating is the
  direction.
- **Rules without a false-positive story.** Every new rule needs a run of
  `node benchmarks/false-positives/run.mjs` showing the clean corpus holding
  and NodeGoat and DVWA unchanged. A rule that fires on a mature codebase is
  not finished.
- **Auto-fixing security findings without review.** `agent` and `fix` propose
  and require approval. That stays.
- **Runtime or agent-side containment.** Ship Safe detects and investigates
  repository and configuration evidence. CI can gate on its verdicts, but the
  report itself is not an OS isolation boundary.

---

## How to help

Best entry points, roughly by size:

1. **Run the benchmark and tell us what is wrong.** Seriously. Nearly every
   fix in 9.7.0 came from someone pointing the scanner at a real codebase and
   looking at the output honestly.
2. **Convert one agent to language-scoped rules** ([#105](https://github.com/asamassekou10/ship-safe/issues/105)).
   Self-contained, one file, clear success criteria.
3. **Take a [`good first issue`](https://github.com/asamassekou10/ship-safe/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).**
   Linked live rather than counted here, because a number in a file is a
   number that goes stale.
4. **Write a Hermes rule.** Read
   [docs/hermes-security-model.md](docs/hermes-security-model.md) first.

[Contributor guide](CONTRIBUTING.md) has the mechanics.
