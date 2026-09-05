# Hermes 10.0 release evidence

This benchmark is the release-evidence layer for Ship Safe 10.0. It is
separate from the deterministic corpus, the verdict benchmark, and the
application audit because those answer different questions.

The scenarios are calibrated against Hermes Agent v0.21.0, tag v2026.8.31,
commit 29112bef099274229cadff79cdff7bf7b99c4b77. The manifest refuses to run
if its pin differs from cli/data/hermes-baseline.json.

Run it from the repository root:

    npm run benchmark:hermes-release
    node benchmarks/hermes-release-evidence/run.mjs --json
    node benchmarks/hermes-release-evidence/run.mjs --write

Each scenario has a deliberately vulnerable fixture and a safely constrained
counterpart. The runner verifies all of the following against actual rendered
output:

- the target rule appears only in the vulnerable fixture;
- citations resolve to files and lines inside the fixture;
- JSON and SARIF carry the same reachability basis;
- ci --fail-on-verdict confirmed --json parses and does not treat a static
  configured or inferred finding as a reproduced confirmation.

Evidence labels have a strict meaning:

- configured: repository configuration establishes the path;
- inferred: source structure establishes the path, but runtime configuration
  is not proven;
- traced: a data-flow or chain pass follows the path;
- reproduced: an execution exercises the path and captures the effect.

These fixtures are static. They may emit configured or inferred; they do not
claim traced or reproduced runtime evidence. Human review of the cited
vulnerable and safe counterparts is recorded in human-review.md.

The checked-in result, when refreshed with --write, is descriptive release
evidence. It is not a production precision rate and does not replace the
false-positive, verdict, or application benchmarks.
