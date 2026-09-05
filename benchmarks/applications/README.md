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

## What the first audit found

The current audit produced one confirmation across three applications.

- `API_SPREAD_BODY` in an Express controller: `createUser({ ...req.body.user })`.
  Genuine mass assignment. Correct.

One audit of three repositories found a confirmation that still requires a
person to inspect the cited code. That is the argument for this corpus
existing.
