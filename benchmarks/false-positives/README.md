# False-Positive Benchmark

Most scanner benchmarks measure recall: point the tool at deliberately vulnerable
code and count what it catches. Recall is the easy half. A scanner that flags
every line has perfect recall and is useless.

This measures the other half. What does Ship Safe say about code that is almost
certainly fine? Every finding on a healthy codebase is triage work a user
inherits, and enough of them make a tool something you turn off.

## Results — v9.6.3

Ship Safe `9.6.3`, `ship-safe ci --no-deps`, corpus pinned by commit.

### Clean corpus

Mature, heavily reviewed projects with no known active vulnerabilities.

| project | findings | critical | high | score | grade |
|---|---|---|---|---|---|
| [express](https://github.com/expressjs/express) | 26 | 0 | 9 | 63.1 | C |
| [requests](https://github.com/psf/requests) | 15 | 1 | 4 | 74.5 | C |
| [flask](https://github.com/pallets/flask) | 30 | 2 | 12 | 54.1 | D |
| [chalk](https://github.com/chalk/chalk) | 4 | 0 | 4 | 87.2 | B |
| **total** | **75** | **3** | **29** | | |

Before the 9.6.3 false-positive work these same four projects produced **1031**
findings, with express alone at 811 and three of the four graded F. The bulk of
that noise was test and fixture code, which deliberately contains
credential-shaped strings and minimal apps that skip production controls. 528 of
express's 601 `API_NO_SECURITY_HEADERS` hits were in `test/`, against 2 in
`lib/`.

### Vulnerable corpus

Deliberately insecure applications, included so a drop in noise cannot be
mistaken for progress when it is really lost detection.

| project | findings | critical | high |
|---|---|---|---|
| [NodeGoat](https://github.com/OWASP/NodeGoat) | 74 | 9 | 18 |
| [DVWA](https://github.com/digininja/DVWA) | 83 | 6 | 55 |

## Known false positives

The 3 critical findings on the clean corpus are all false positives. Naming them
is the point of running this:

- **`API_PATH_IN_FILENAME` — flask `src/flask/config.py:204,290` (2 findings).**
  The rule targets Express file uploads
  (`path.join(dir, req.file.originalname)`) but its regex matches the substring
  `path.join(` inside Python's `os.path.join(self.root_path, filename)`, where
  `filename` is an ordinary local variable. A JavaScript upload rule firing on
  Python framework code, at the severity that gates CI. This is the highest
  impact remaining false positive.

- **`GIT_HISTORY_SECRET` — requests `tests/certs/expired/ca/ca-private.key`.**
  A deliberately expired test-fixture private key. Working-tree findings in test
  directories are filtered, but history scanning reads commits rather than
  paths, so the filter does not reach it.

Beyond critical, flask's remaining 30 findings are the weakest result in the
corpus and are a mix rather than one dominant cause.

## Honest limits

Read these before quoting any number above.

- **This is a proxy for a false-positive rate, not a rate.** "No known active
  vulnerabilities" is not "no vulnerabilities", and these findings have not each
  been adjudicated by hand. Turning the proxy into a real rate means triaging
  all 75 findings individually. That work has not been done.
- **Four projects is a small corpus**, skewed toward JavaScript and Python, and
  toward libraries rather than applications. A web app with real authentication
  and deployment configuration exercises rules these do not reach.
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
