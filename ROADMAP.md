# Roadmap

What Ship Safe is working on, what just shipped, and what we are deliberately
not building. Updated when a release goes out.

If you want to help, the [10.0 milestone](https://github.com/asamassekou10/ship-safe/milestone/1)
is the current work and everything in it is claimable. Comment on an issue to
take it.

---

## Just shipped — 9.7.0, Calibration

Pointed the scanner at [hermes-agent](https://github.com/NousResearch/hermes-agent),
about 8,400 files of actively maintained Python, and took the result seriously.
First run reported 6,948 findings and graded 13/F. It now reports 785.

Fourteen rules were recalibrated, and none of them needed a threshold nudged.
Every one was a defect. Two asserted an absence using a construct that could
never fail. Two read English as code. One counted any method named `eval`.

`ci` now gates on severity rather than the composite score, because the score
saturated after three to five findings per category and could not distinguish
30 findings from 7,000.

Detection did not move: NodeGoat held at 74 findings across the entire release.

Full detail in the [changelog](CHANGELOG.md) and the
[false-positive benchmark](benchmarks/false-positives/).

---

## Now — 10.0, Hermes Agent coverage

Ship Safe 10.0 targets Hermes Agent **v0.21.0** at pinned commit
[`29112bef099274229cadff79cdff7bf7b99c4b77`](https://github.com/NousResearch/hermes-agent/commit/29112bef099274229cadff79cdff7bf7b99c4b77).
Some older rules overlap the current surface, but overlap is not verified
coverage. The [coverage matrix](docs/hermes-coverage-matrix.md) records each
surface as partial or uncovered until its current paths and safe counterpart
are tested.

**Note on scope.** This is coverage we build for our users who run Hermes. It
is not coordinated with Nous Research, and nothing here should be read as an
endorsement by them.

### The surfaces

| area | 10.0 status |
|---|---|
| plugin manifests | partial: provenance, hook, and listener checks shipped; install/discovery review remains |
| external surfaces | partial: adapter fail-open detection shipped; shared auth, relay, HTTP, and bind scope remain |
| terminal backends | uncovered: seven backends from local to container, remote, and cloud sandboxes |
| ACP and TUI gateway | uncovered: editor and local-IPC surfaces with their own permission models |
| cron | partial: the older generic rule is not calibrated to the current Python lifecycle |
| credential scoping | partial: generic exposure rules do not prove credential reachability or use |

### Two ideas shaping the work

**Posture-aware severity.** Hermes publishes an unusually explicit
[security policy](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md).
It names OS-level isolation as the only real boundary and says plainly that
in-process heuristics are not boundaries. A report that ignores that is noise
to anyone who has read it. So Hermes findings will carry a posture: `boundary`
for classes their policy treats as in scope, `hygiene` for everything else,
rendered separately.

**Read their policy before writing rules.** See
[docs/hermes-security-model.md](docs/hermes-security-model.md). A rule that
flags something their trust model deliberately permits is a false positive no
matter how clever the regex.

### Also in 10.0

- **Language-scoped rules** ([#105](https://github.com/asamassekou10/ship-safe/issues/105)).
  Rules can declare `langs: ['js']` and stop being applied to Ruby. The
  mechanism shipped in 9.7.0; nine agents still need converting, one per pull
  request. Good first issues.
- **MCP OAuth** ([#104](https://github.com/asamassekou10/ship-safe/issues/104))
  shipped in 9.7.5. **A2A agent cards**
  ([#103](https://github.com/asamassekou10/ship-safe/issues/103)) moved to a
  post-10.0 milestone so this release keeps one verifiable upstream target.

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
3. **Take a `good first issue`.** Eight are open and unclaimed.
4. **Write a Hermes rule.** Read
   [docs/hermes-security-model.md](docs/hermes-security-model.md) first.

[Contributor guide](CONTRIBUTING.md) has the mechanics.
