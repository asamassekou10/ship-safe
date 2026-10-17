# Fix outcomes: static evidence is not an independent retest

This change introduces fix-outcome `schemaVersion: 2`. It does not change the
top-level scan-report schema version. Release compatibility must be reviewed
before publishing; this document describes the proposed change, not npm 11.0.0.

## Outcome vocabulary

| Existing outcome | Meaning in v2 |
| --- | --- |
| `resolved` | No matching detector finding remains. This is only **no longer detected**, not proof of remediation. |
| `neutralised` | The matching finding is refuted by the static investigation. No independent replay occurred. |
| `weakened` | A previously established finding is now uncertain. |
| `unchanged` | The comparison establishes no improvement. |
| `introduced` | A confirmed or likely finding absent from the complete pre-edit baseline appears in the rescan. |

Keep the old counters for consumers, but use `summary.status` for decisions:

- `not_applicable`: no target findings; not a successful verification.
- `inconclusive`: disappearance, uncertainty, unchanged findings or mixed results.
- `statically_refuted`: every target has a matching static refutation and no
  new confirmed or likely finding is found across the repository baseline.
- `regression_detected`: a new confirmed or likely finding appears.

`summary.staticallyRefuted` is a convenience boolean for the static-only case.
`summary.verified` remains present for JSON readers, but is **always false** in
this comparator: it does not execute an independent retest. Old consumers that
treated `resolved` as proof must migrate. Do not relabel static refutation as an
independent verification, or treat an empty comparison as success.

The comparator receives target findings plus the full pre-edit repository
baseline. Cross-file results are not filtered out. Existing unrelated debt is
not a new regression. A one-to-one baseline match cannot hide added duplicates.
The interactive fix session uses its initial complete scan as that baseline;
new concerns remain visible on later iterations rather than being silently
accepted as existing debt. Matching still uses rule, file and a small line
window. It is not a durable identity or proof that a moved finding was fixed.

## CLI and logs

The fix agent reports static refutation, disappearance or inconclusive results,
not “Fix verified.” Generated PR descriptions and `.ship-safe/fixes.jsonl` use
the same distinction. The log's legacy `verified` field is false; the versioned
comparison summary and scope are stored in `verification` for inspection.
Source-bearing rationales are not copied into this new log field.

`--sandbox` now fails before provider lookup, branch creation, scans or edits.
There is no silent downgrade to an in-process rescan. An independent replay
runner and durable cases are separate workstreams (#227, #234 and #235).

## Limits and release checklist

- This is static evidence, not formal proof or exploit reproduction.
- Imported or stale evidence is not authenticated by this comparator. Future
  connected tools must validate provenance and source freshness separately.
- Newly uncertain findings are not classified as established regressions.
- This slice does not add a sandbox, case store or new MCP tools.
- Review the boolean semantic tightening and release version before publishing.
- Add moved/renamed findings, empty scans, cross-file regressions, incomplete
  rescans and unavailable-sandbox tests to the release gate. See #228.
