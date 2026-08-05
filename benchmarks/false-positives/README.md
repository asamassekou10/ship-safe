# False-Positive Benchmark

Most scanner benchmarks measure recall: point the tool at deliberately vulnerable
code and count what it catches. Recall is the easy half. A scanner that flags
every line has perfect recall and is useless.

This measures the other half. What does Ship Safe say about code that is almost
certainly fine? Every finding on a healthy codebase is triage work a user
inherits, and enough of them make a tool something you turn off.

## Results — unreleased

Ship Safe at `HEAD`, `ship-safe ci --no-deps`, corpus pinned by commit.

### Clean corpus

Mature, heavily reviewed projects with no known active vulnerabilities.

| project | findings | critical | score | grade | was (9.6.3) |
|---|---|---|---|---|---|
| [express](https://github.com/expressjs/express) | 22 | 0 | 81.2 | B | 26 |
| [requests](https://github.com/psf/requests) | 11 | 1 | 87 | D | 15 |
| [flask](https://github.com/pallets/flask) | 20 | 0 | 81.6 | B | 28 |
| [chalk](https://github.com/chalk/chalk) | 4 | 0 | 91.8 | A | 4 |
| [hermes-agent](https://github.com/NousResearch/hermes-agent) | 785 | 101 | 20.9 | F | — |
| **total (original four)** | **57** | **1** | | | **73** |

Before the 9.6.3 false-positive work these same four projects produced **1031**
findings, with express alone at 811 and three of the four graded F. The bulk of
that noise was test and fixture code, which deliberately contains
credential-shaped strings and minimal apps that skip production controls. 528 of
express's 601 `API_NO_SECURITY_HEADERS` hits were in `test/`, against 2 in
`lib/`.

### hermes-agent, and why it is here

[hermes-agent](https://github.com/NousResearch/hermes-agent) joined the clean
corpus because the original four are small, and three of them are libraries. It
is ~8,400 files of actively maintained Python, and it is in our own domain: an
AI agent with tools, MCP servers, memory, and a gateway. Rules written for
agent security should be measured against a real agent.

It found more than any other corpus entry ever has. The first run reported
**6,948 findings**, of which five rules were 4,684 — including 1,963 on a single
contributor credit map, and two rules whose absence-assertions could not fail on
input like theirs. It is now at **799**, an 89% reduction, with the full
accounting in the changelog for this release.

799 is not a passing number and this table does not pretend otherwise. The
remaining tail is documented under "Known false positives" below.

### Vulnerable corpus

Deliberately insecure applications, included so a drop in noise cannot be
mistaken for progress when it is really lost detection.

| project | findings | critical | high |
|---|---|---|---|
| [NodeGoat](https://github.com/OWASP/NodeGoat) | 74 | 9 | 18 |
| [DVWA](https://github.com/digininja/DVWA) | 71 | 1 | 55 |

Across the entire recalibration NodeGoat did not move by a single finding.

DVWA's criticals went from 6 to 1 when rules gained language scope, and that
number deserves explaining rather than burying, because a drop in the
vulnerable corpus is exactly what this table exists to catch.

All five were `SSRF_USER_URL_FETCH` on `fetch(url, {...})` inside `<script>`
blocks in PHP templates. That is browser JavaScript making a client-side
request. Server-side request forgery requires the server to make the request,
so a client-side `fetch` is not SSRF under any reading. DVWA has plenty of real
vulnerabilities; these five were not among them, and the one remaining critical
is unaffected. Highs are unchanged at 55.

### Why requests scores 87 and grades D

Because the score and the grade answer different questions, on purpose.

The score is about volume: 11 findings on a large mature library is very
little, and 87 says so. The grade is about worst case: one of those 11 is
critical, so the answer to "can I ship this" is no regardless of how few there
are.

A critical finding caps the grade at D. Without that cap a repository with a
single command injection scored 91.4 and graded "A — Ship it!" while `ci` on
the same repository exited 1, which is the tool contradicting itself in the
direction of reassurance.

requests' one critical is the known false positive named below. It should stop
grading D once that is fixed, which is the right incentive.

### The score column is less informative than it looks

Category deductions are capped at the category's weight, and the eight weights
sum to 100. Each category therefore saturates after **3 to 5 medium-severity
findings**. Past that point the score stops responding: hermes-agent scored 13/F
at 6,948 findings and still scores 13/F at 799.

This is why the table leads with finding counts. Treat the score as a signal
only for small, already-clean projects, and see the tracking issue on scoring
saturation.

## Known false positives

The 1 remaining critical finding on the clean corpus is a false positive.
Naming it is the point of running this:

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

Beyond critical, flask's remaining 20 findings are a mix rather than one
dominant cause.

### hermes-agent's remaining 799

Not yet triaged, listed so the next pass has a starting point. Counts are from
the run that produced this table.

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
- **Findings are not defects.** A finding is a thing worth a human looking at.
  The claim here is only that there are few enough of them to look at.

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
