# Application corpus

The false-positive corpus is five libraries and two teaching fixtures. A library
has no request handlers, so the investigation layer barely engages with it:
scanning express produced twenty findings and no traced paths at all.

These are the shapes users actually scan — HTTP services, an auth-heavy web app —
pinned by commit.

The question here is different from the other benchmarks. Not how much noise
there is, and not whether known vulnerabilities are still found, but **whether
the confirmations are right**. A confirmation is the strongest thing this tool
says, and the only way to check one is to read the code it cites.

So this corpus has no pass/fail gate. It produces confirmations for a person to
audit, and the audit is the output.

```bash
node benchmarks/applications/run.mjs --clone   # fetch the pinned checkouts
node benchmarks/applications/run.mjs           # list confirmations for review
```

## Adjudicating the first audit

The pre-fix audit produced one tool-level confirmation across three
applications. Manual review found that it was a false confirmation.

- `API_SPREAD_BODY` in an Express controller:
  `createUser({ ...req.body.user, demo: false })`.
  The request body is spread into `createUser`, but the downstream service
  explicitly reads `email`, `username`, `password`, `image`, `bio`, and `demo`,
  then constructs the Prisma `data` object from only those fields. The route
  also forces `demo: false`. Arbitrary properties such as a role or admin flag
  are not persisted, so this cited path does not establish a mass-assignment
  vulnerability. The confirmation was incorrect.

This review shows why a source-to-call trace is not sufficient evidence for
mass assignment: the investigator must follow the callee to the actual write
and account for its allowlist and model fields. A focused regression now caps
these rule verdicts at `likely` unless those downstream semantics are known.
