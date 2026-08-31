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

The machine-readable result is stored in `results/latest.json`. Ship Safe Cloud imports the same result for the hosted benchmark page from its private repository.

## Verdict benchmark

The corpus above measures the sensor layer: did the rule fire. `verdicts.mjs` measures what happens next — whether the passes that investigate a finding reach the right conclusion about it.

```bash
npm run benchmark:verdicts          # gate, deterministic, no API key
npm run benchmark:verdicts:write    # refresh results/verdicts.json
node benchmarks/verdicts.mjs --llm  # include the DeepAnalyzer pass, ungated
```

Ground truth lives in `verdicts.json`: which fixtures hold a real vulnerability, and which findings on a *safe* control are noise, each with a written reason. Four numbers come out.

- **settledRate** — of the findings known to be real, the fraction that investigation resolved to `confirmed` or `likely` rather than leaving at `unknown`. This is what the data-flow and reproduction passes exist to raise.
- **noiseStanding** — labeled noise on safe controls that investigation failed to refute. What they exist to lower.
- **falseRefutations** — a known-real finding marked `refuted`. Budget zero, permanently: it is the only error here that loses a vulnerability silently rather than merely wasting attention.
- **unlabeled** — a finding on a safe control that `verdicts.json` does not describe. Also a hard failure. New noise gets read and written down, not absorbed into a drifting number.

The middle two are ratchets recorded in `verdicts.json`; improving one means editing the number deliberately. Neither can be gamed on its own — refuting everything trips `falseRefutations`, and detecting nothing trips the detection corpus, which runs alongside this one in CI.

As of the first run the settled rate is **2/12**. The heuristic verifier reaches a conclusion on two of twelve known-real findings and returns `unknown` on the rest, which is the honest starting line for everything built on top of it.

Same limits as above, plus: twelve synthetic scenarios are not a production precision estimate, the noise labels are first-party judgements about first-party fixtures, and `--llm` is never gated because a benchmark that moves with a model's sampling is not a regression test.

## Where the numbers came from

The settled rate moved from 2/12 to 6/15 when `DataflowInvestigator` landed. The
flow fixtures under `corpus/flow/` are the ones that moved it: the original
detection fixtures are one-liners, which is right for testing a regex and useless
for testing a tracer, because there is no path in them to follow.

One fixture pair exists because of a bug rather than a feature. `sql-mixed` puts
two values into one query template, one numerically coerced and one raw. An
earlier tracer returned on the first input it resolved, refuted on the coerced
half, and never looked at the other — which is a live injection reported as
handled. It was found against OWASP NodeGoat's `allocations-dao.js` and not by
this corpus, which is the honest reason the pair is here now.
