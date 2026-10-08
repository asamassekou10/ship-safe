# False-Positive Benchmark

Most scanner benchmarks measure recall: point the tool at deliberately vulnerable
code and count what it catches. Recall is the easy half. A scanner that flags
every line has perfect recall and is useless.

This measures the other half. What does Ship Safe report on mature projects
with no known active vulnerabilities? These are raw scanner findings, not a
count of confirmed defects. The table also shows what the investigation pass
concluded, so unresolved evidence is not mistaken for a confirmed issue.

## Results — 11.0.0 (unpublished)

The table below and [`results/latest.json`](results/latest.json) were generated
on October 7, 2026 by `ship-safe ci --no-deps` and `ship-safe investigate
--json`, with all corpus revisions pinned by commit. This is an unpublished
release candidate; counts are not defect counts or verified false-positive
rates.

### Clean corpus

Mature, heavily reviewed projects with no known active vulnerabilities.

| project | raw findings | critical | score | grade | labels (confirmed / likely / unknown / refuted / unlabeled) |
|---|---:|---:|---:|:---:|---|
| [express](https://github.com/expressjs/express) | 10 | 0 | 88.2 | B | 0 / 2 / 7 / 1 / 0 |
| [requests](https://github.com/psf/requests) | 7 | 0 | 95.5 | A | 0 / 0 / 4 / 3 / 0 |
| [flask](https://github.com/pallets/flask) | 17 | 0 | 81.4 | B | 0 / 5 / 10 / 1 / 1 |
| [chalk](https://github.com/chalk/chalk) | 4 | 0 | 89.4 | B | 0 / 0 / 4 / 0 / 0 |
| [hermes-agent](https://github.com/NousResearch/hermes-agent) | 654 | 63 | 20.2 | F | 0 / 96 / 344 / 192 / 22 |
| **total (original four)** | **38** | **0** | | | **0 / 7 / 25 / 5 / 1** |
| **total (all five)** | **692** | **63** | | | **0 / 103 / 369 / 197 / 23** |

Before the 9.6.3 false-positive work these same four projects produced **1031**
findings, with express alone at 811. The 9.6.3 snapshot recorded 73 findings
across the same four; the current pinned run records 38. These are scanner
counts across a small sample, not false-positive rates. The comment-context
fixes in this run also remove executable-looking examples from JSDoc without
weakening the corresponding checks on real code.

### hermes-agent, and why it is here

[hermes-agent](https://github.com/NousResearch/hermes-agent) joined the clean
corpus because the original four are small, and three of them are libraries. It
is ~8,400 files of actively maintained Python, and it is in our own domain: an
AI agent with tools, MCP servers, memory, and a gateway. Rules written for
agent security should be measured against a real agent.

It found more than any other corpus entry ever has. The first run reported
**6,948 findings**, of which five rules were 4,684 — including 1,963 on a single
contributor credit map, and two rules whose absence-assertions could not fail on
input like theirs. The preceding snapshot was **662** findings; the 11.0.0
candidate now reports **654**, about a 90% reduction from that initial scan.

The October 7, 2026 run reports **654 findings** (63 critical) for Hermes at the
same pinned commit, with 96 likely, 344 unknown, and 192 refuted investigator
labels, no confirmed locations, and 22 findings without a label. That is eight
fewer raw findings than the preceding snapshot, but it is not an accuracy
result. The labels are tool conclusions, not independent human adjudications;
the remaining tail still needs review.

The preceding detector refresh removed two prompt-injection matches caused by the
`signed_content` identifier in Hermes's webhook HMAC verification. That value
combines a timestamp and request body for signature verification; it is not an
LLM prompt. The rule now requires an exact prompt-shaped identifier. The earlier
16-finding reduction removed WhatsApp user or group identifiers from
hardcoded-email findings; ordinary hardcoded-email detection remains covered by
a regression test.

A later focused review of Hermes matches in the historical snapshot found
overbroad credential-store matches on `.hermes-update-*` application bundles,
an Electron native OAuth token-store I/O adapter, and Modal's stdout-based
temporary sync-back archive. Regression tests now distinguish those cases
from a persistent credential archive or an explicit network sink. The October 7
run completed against the same Hermes corpus pin and is the result shown above.

The Hermes corpus revision is pinned separately from the dedicated security
coverage baseline: this snapshot uses
[`743dc94`](https://github.com/NousResearch/hermes-agent/commit/743dc94ab90adb0529bb233b8498c6fd6ee0e020),
while the coverage matrix targets the v0.21.0 release at
[`29112bef`](https://github.com/NousResearch/hermes-agent/commit/29112bef099274229cadff79cdff7bf7b99c4b77).
Do not interpret either count as a result on the v0.21.0 coverage baseline.
The corpus run and the dedicated release-coverage fixtures intentionally use
different Hermes revisions; a full-corpus result on v0.21.0 has not been run.

### Vulnerable corpus

Deliberately insecure applications, included so a drop in noise cannot be
mistaken for progress when it is really lost detection.

| project | raw findings | critical | high |
|---|---|---|---|
| [NodeGoat](https://github.com/OWASP/NodeGoat) | 57 | 9 | 18 |
| [DVWA](https://github.com/digininja/DVWA) | 71 | 1 | 55 |

All required detection-floor rules still fire in both vulnerable projects.
NodeGoat's raw count fell from 67 to 57 after comment-only matches were
excluded; that is not evidence that ten vulnerabilities disappeared.

DVWA's criticals went from 6 to 1 when rules gained language scope, and that
number deserves explaining rather than burying, because a drop in the
vulnerable corpus is exactly what this table exists to catch.

All five were `SSRF_USER_URL_FETCH` on `fetch(url, {...})` inside `<script>`
blocks in PHP templates. That is browser JavaScript making a client-side
request. Server-side request forgery requires the server to make the request,
so a client-side `fetch` is not SSRF under any reading. DVWA has plenty of real
vulnerabilities; these five were not among them, and the one remaining critical
is unaffected. Highs are unchanged at 55.

### Historical Requests score example (not the current snapshot)

Because the score and the grade answer different questions, on purpose.

At that earlier snapshot, Requests had 11 findings and one critical, so its
grade was capped despite the low volume. The current pinned run is different:
seven findings, zero criticals, and a 95.5 score. The current numbers are in the
table above; this example remains only to explain why score and grade differ.

A critical finding caps the grade at D. Without that cap a repository with a
single command injection scored 91.4 and graded "A — Ship it!" while `ci` on
the same repository exited 1, which is the tool contradicting itself in the
direction of reassurance.

That critical was the known false positive described below. It is not present
in the current snapshot.

### The score column is less informative than it looks

Category deductions are capped at the category's weight, and the eight weights
sum to 100. Each category therefore saturates after **3 to 5 medium-severity
findings**. Past that point the score stops responding. Hermes Agent still
grades F at 662 findings, so the score does not summarize the evidence or its
accuracy.

This is why the table leads with finding counts. Treat the score as a signal
only for small, already-clean projects, and see the tracking issue on scoring
saturation.

## Previously recorded false positives

In an earlier snapshot, the Requests history scan reported this known test
fixture. It is not a current finding in this shallow, commit-pinned run:

- **`GIT_HISTORY_SECRET` — requests `tests/certs/expired/ca/ca-private.key`.**
  A deliberately expired test-fixture private key. Working-tree findings in test
  directories are filtered, but history scanning reads commits rather than
  paths, so the filter does not reach it.

Fixed since the first run of this benchmark:

- **`API_PATH_IN_FILENAME` — flask `src/flask/config.py:204,290`.** The rule
  targets Express file uploads but its regex matched the substring `path.join(`
  inside Python's `os.path.join(self.root_path, filename)`. Fixed in 9.6.4 by
  anchoring the pattern so it cannot match `os.path.join`, and by requiring a
  property access such as `file.originalname` rather than any variable named
  `filename`. This benchmark is what surfaced it.

Flask has 17 raw findings in the current run. Its investigator labels are
reported in the table; they have not all been adjudicated by a human.

### Earlier Hermes Agent triage snapshot (799 findings)

This table is historical and is not the current 662-finding snapshot. It is
retained as context for changes made after that run.

| rule | count | first read |
|---|---|---|
| `SSRF_INTERNAL_IP` | 98 | local-first software talking to its own loopback services |
| `RUST_UNWRAP_IN_PROD` | 58 | `.unwrap()` in a small native extension; a lint, not a vulnerability, and arguably out of scope at medium |
| `AGENT_TOOL_CALL_REPLAY_MISSING_ASSISTANT` | 33 | needs checking against their actual message-history handling |
| `AGENT_NO_COST_LIMIT` | 33 | now per-file; a project-level question asked per file will always over-report |
| `SLOPSQUAT_PHANTOM_IMPORT` | 33 | down from 137 after workspace resolution; the rest need checking |
| `AGENT_REMOTE_EXEC_INSTRUCTION` | 32 | `curl \| bash` in the project's own install docs, across translations |
| `AGENT_NO_OUTPUT_SCHEMA` | 22 | same shape as the cost-limit rule |
| `Password Assignment` | 21 | secret scanner; needs sampling |

The scoring saturation described above is tracked as an issue rather than
patched here.

## Honest limits

Read these before quoting any number above.

- **This is a proxy for a false-positive rate, not a rate.** "No known active
  vulnerabilities" is not "no vulnerabilities", and these findings have not each
  been adjudicated by hand. Turning the proxy into a real rate means triaging
  each finding individually. That work has not been done.
- **Five projects is a small corpus**, skewed toward JavaScript and Python. The
  original four are libraries; hermes-agent is the first application in it. A
  web app with real authentication and deployment configuration still exercises
  rules none of these reach.
- **Grades are not comparable across projects.** Score is normalized by codebase
  size, so a small package and a framework with a large test suite are not on
  the same footing.
- **Findings are not defects.** Raw counts and automated investigator labels
  do not replace human review, and these results do not estimate production
  accuracy.

## Reproducing

```bash
node benchmarks/false-positives/run.mjs --clone   # fetch the pinned corpus
node benchmarks/false-positives/run.mjs           # print results as JSON
node benchmarks/false-positives/run.mjs --write   # refresh results/latest.json
```

The corpus is pinned by commit in [`corpus.json`](corpus.json). An unpinned
benchmark reports a different number every week and cannot be argued with. If
you get different numbers on the same commits and the same version, that is a
bug worth filing.

Machine-readable results: [`results/latest.json`](results/latest.json).


## Why this is not in CI

The other two benchmarks gate every pull request. This one does not, deliberately.

It clones seven repositories at pinned commits and scans each of them twice, which
takes minutes and needs the network. A gate with those properties fails for
reasons that have nothing to do with the change under review — a rate limit, a
slow mirror, a repository that moved — and a gate that fails for unrelated
reasons is one people learn to re-run rather than read.

The deterministic corpus and the verdict benchmark cover regressions in CI
because they are fast, offline, and hermetic. This one answers a different
question — what does the tool say about real code it was not written against —
and that question is worth asking deliberately, before a release, rather than on
every commit.

Run it with `npm run benchmark:fp`, and `npm run benchmark:fp:write` to update
`results/latest.json`. Fetch the corpus first with
`node benchmarks/false-positives/run.mjs --clone`.
