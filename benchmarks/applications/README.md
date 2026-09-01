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

Two confirmations across three applications.

- `API_SPREAD_BODY` in an Express controller: `createUser({ ...req.body.user })`.
  Genuine mass assignment. Correct.
- `API_EXCESSIVE_DATA` in another: `const result = await getArticles(req.query, id)`.
  The rationale claimed `result` came from the HTTP request. It came from the
  database; the request was an argument to the call.

The second was a general defect — an untrusted source anywhere in a right-hand
side was read as the origin of the assigned value, so every
`const x = await something(req...)` confirmed. That is one of the most common
lines in any web application.

One audit of two confirmations, on three repositories, found a fault that six
scans of the other corpora had not. That is the argument for this corpus
existing.
