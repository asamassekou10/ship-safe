# How Ship Safe works, and why

What the tool is trying to do, the decisions behind it, and the rules we hold
ourselves to. If you are adding a rule or an agent, this is the reasoning you
are inheriting.

[CONTRIBUTING.md](../CONTRIBUTING.md) has the mechanics. This is the intent.

---

## The goal

**Find security problems in code that AI agents write, read, or act on, and
report them in a way somebody actually acts on.**

The second half is the hard half, and it is where most of our engineering time
goes. A scanner that reports everything has perfect recall and zero value,
because the person reading it learns to close the tab. Every false positive
spends a user's attention and some of their trust, and trust does not come
back.

So the working definition of a finding is narrow:

> A finding is a thing worth a human looking at.

Not "a thing that matches a pattern". Not "a thing that could theoretically be
exploited". Something a competent engineer, seeing it, would want to know.

---

## What a scan actually does

```
recon → agents → findings → scoring → gate
```

**Recon** identifies languages, frameworks and package managers so agents can
skip work that cannot apply.

**Agents** are the units of detection. There are 29. Each owns a domain —
injection, secrets, MCP configuration, AI agent behaviour, supply chain — and
declares which file types it reads. Most detection is regex patterns run per
line; some is structural, reading a whole file and answering a question about
it.

**Findings** carry a rule ID, severity, confidence, a CWE and OWASP mapping
where one applies, and a fix.

**Scoring** turns findings into a 0–100 number and a letter grade.

**The gate** decides the exit code for `ci`.

---

## The four ideas that shape everything

### 1. A rule that asserts an absence needs a different shape

The single most expensive class of bug we have shipped. A rule that reports
something *missing* — no logging, no rate limit, no schema validation — cannot
be written as a line pattern.

This is what it looked like:

```js
regex: /tool_call[\s\S]{0,300}(?![\s\S]{0,300}(?:log|audit))/
```

The gap backtracks until the lookahead succeeds, so the assertion can never
fail. The rule degrades into "this line contains `tool_call`", and it produced
**1,904 findings** on one repository.

Absence is a property of a scope, not a line. The scope is usually a file,
sometimes the whole project. `AGENT_STRUCTURAL_RULES` in
`cli/agents/agentic-security-agent.js` is the shape: a `test(content)` that
answers two questions — does this file do the thing, and does anything here
mitigate it — emitting at most one finding per file.

Be generous about what counts as mitigation. The finding claims nothing here
does X, so one instance of X refutes it. A stingy mitigation check trades a
loud wrong answer for a quiet one, which is worse because nobody notices.

### 2. A rule describes a language, and should say so

`API_PATH_IN_FILENAME` targets Express file uploads. It matched the substring
`path.join(` inside Python's `os.path.join(self.root_path, filename)` and
reported **critical** on Flask's own config loader.

We patched that regex. The real problem was that nothing let the rule say which
language it described, so the next collision was a matter of which token
happened to be shared.

Rules can now declare `langs: ['js']`. Files with no language of their own —
`.json`, `.yml`, `.md` — are never skipped, because dropping a JS-scoped rule
on a JSON config would be a detection loss dressed up as precision.

**A wrong tag is a silent detection loss.** When `SSRFProber` was converted, an
automated classifier disagreed with a hand pass on four rules of nine. Untagged
behaves exactly as before, so leaving a rule alone is always safe.

### 3. Volume and severity are different questions

The score used to gate CI, and it was the wrong instrument.

Category deductions were clamped at the category weight, the eight weights sum
to 100, and each category saturated after three to five medium findings. A
repository we cleaned from 6,948 findings to 785 scored **13/F both times**.

Two separate fixes came out of that, and the distinction between them is the
point:

- **The score answers "how much is there."** That is a volume question, so it
  needs a curve that keeps responding. Deductions are now asymptotic:
  `weight × raw / (raw + weight)`. Bounded, but strictly monotonic, so more
  findings always cost more.
- **The grade and the gate answer "can I ship this."** That is a worst-case
  question. `ci` fails on any critical by default, and a critical finding caps
  the grade at D regardless of score.

That second cap exists because without it a repository with one command
injection scored 91.4 and graded "A — Ship it!" while `ci` on the same
repository exited 1. Two parts of the tool told a user opposite things about
the same code, and the friendlier one was wrong.

Peer tools agree on the split. Snyk gates on `--severity-threshold`, Trivy on
`--severity`, and SonarQube's security rating is set by the most severe issue
rather than the count.

### 4. Not everything true is a vulnerability

Two categories exist to keep the security report honest about what it is.

**`quality`** is reported and never scored. `RUST_UNWRAP_IN_PROD` and the
maintainability half of the `EXCEPTION_*` family live here. `.unwrap()` in Rust
is worth mentioning and is not a security defect, and 58 of them inside a
security report is how a report teaches people to stop reading. SonarQube draws
the same line between vulnerabilities and code smells.

**`posture`** applies to targets that publish their own trust model. Hermes
Agent says plainly that OS isolation is the only boundary and that in-process
heuristics are not. So Hermes findings are tagged `boundary` when their policy
treats the class as in scope, and `hygiene` when it does not. A `critical`
sitting next to something the target's own maintainers would close as out of
scope is how you lose a reader who has done the reading. See
[hermes-security-model.md](hermes-security-model.md).

---

## How we know any of this works

**The false-positive benchmark** is the load-bearing check.
`node benchmarks/false-positives/run.mjs`, pinned by commit.

- **Clean corpus** — five mature projects with no known active vulnerabilities.
  Findings here are triage work a user inherits.
- **Vulnerable corpus** — NodeGoat and DVWA, present so a drop in noise cannot
  be mistaken for progress when it is really lost detection.

The rule when you change a rule: clean corpus drops or holds, and **NodeGoat
and DVWA must not move**. If they move, explain why in the PR. Sometimes it is
correct — converting `SSRFProber` removed five DVWA criticals that were
client-side browser `fetch` in PHP templates, which is not server-side request
forgery — but it always needs tracing before it is accepted.

**Tests assert behaviour, not values.** Freezing a number means the test breaks
when anything changes and proves nothing when it passes. `scoring-resolution`
asserts the score is strictly decreasing across four orders of magnitude rather
than that some project scores 81.2.

**Absence rules get a quiet-direction test.**
`cli/__tests__/absence-rules.test.js` gives a rule an input where the mitigation
is present and asserts silence. A detection test only ever exercises the loud
direction, which is exactly how a rule that could never fail shipped.

---

## Things we deliberately do not do

- **Gate on the composite score by default.** It saturates. `--threshold` still
  works for pipelines that pinned it.
- **Let code-quality findings move a security score.**
- **Auto-fix without review.** `agent` and `fix` propose and require approval.
- **Enforce at runtime.** Ship Safe is a static scanner. It reports.
- **Claim to be containment.** We are a review aid. Any target whose threat
  model includes an adversarial LLM needs OS-level isolation, and a scanner is
  not that.

---

## The honest limits

Worth stating because a security tool that oversells itself is worse than one
that does not exist.

- The clean corpus is five projects, skewed toward JavaScript and Python.
- "No known active vulnerabilities" is not "no vulnerabilities", and corpus
  findings have not each been adjudicated by hand.
- Findings are not defects. The claim is that there are few enough to look at.
- The score still saturates on large repositories even with the curve, which is
  why it no longer gates. Treat it as a signal for small, already-clean
  projects.
- `hermes-agent` reports 785 findings and that tail is not fully triaged. The
  benchmark README lists it by rule so the next pass has a starting point.
