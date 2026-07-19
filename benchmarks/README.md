# Ship Safe deterministic corpus

This directory contains a first-party regression benchmark for Ship Safe CLI. It pairs one intentionally vulnerable fixture with one safe control for each target rule.

Run it from the repository root:

```bash
npm run benchmark:corpus
```

Refresh the checked-in result after an intentional scanner or corpus change:

```bash
npm run benchmark:corpus:write
```

## What the result means

- **Scenario recall** is the percentage of labeled vulnerable scenarios where the expected rule was emitted.
- **Target-rule clean-control pass rate** is the percentage of paired safe controls where the labeled target rule was not emitted. Other advisory findings are preserved in the machine-readable result.
- The corpus is synthetic, deterministic, and maintained by the Ship Safe project.
- It does not measure vulnerability prevalence, production-repository precision, or comparative performance against another scanner.
- It is not independent validation. Pinned third-party vulnerable repositories and externally reviewed labels are a separate future evaluation track.

The machine-readable result is stored in `results/latest.json` and published at `https://www.shipsafecli.com/benchmarks/latest.json`. The website renders the same data from `webapp/data/benchmark-results.json`.
