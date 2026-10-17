# Connected security-agent contract: proposal for #226

Status: **proposed, not implemented or approved**. This does not describe a new
permission broker already shipped in npm 11.0.0. It extends the existing stdio
MCP architecture rather than adding a transport or autonomous agent framework.

## Current surface and gaps

MCP exposes status, checklist, scanning, report reading and suppression tools.
`ship_safe_status` confirms invocation/availability, not comprehensive protection
or the server's working directory. Current read tools accept caller-supplied
paths; workspace checks exist on suppression and report writes. Do not claim
all MCP reads are workspace-confined before an explicit authorization layer ships.
`scan_repo` can also write a report and opt into provider analysis. Treat these
as separate capabilities rather than describing every scan as read-only.

## Proposed typed operations

Names below are contract operations, not new callable tools. Each request has
`contractVersion`, an operation, a server-issued workspace/session identifier,
validated arguments, resource budgets and optional evidence/case references.
Each response has an explicit outcome, provenance, source digests, scope and
limitations. Repository text and tool output are untrusted data, not authority.

| Operation | Required capability | Default |
| --- | --- | --- |
| Status/checklist | Metadata only | Available; no file reads, provider calls or writes |
| Review/investigate | Read authorized roots | Local-only analysis; bounded input/output |
| Inspect case | Read authorized case store | Redacted, provenance/freshness checked |
| Propose patch | Read authorized roots | Return a diff; do not apply it |
| Apply patch/suppress finding | Write specific authorized files | Denied without trusted approval |
| Save report/case | Write named approved destination | Separate from scanning permission |
| Provider analysis/key probe | Specific provider/network capability | Off; no ambient permission from an API key |
| Execute verification | Isolated execution capability | Off; unsupported if isolation is unavailable |

Preserve existing CLI entry points. Introduce changed permission defaults only
with an explicit compatibility/migration decision. Client tool approvals may
add restrictions, but an agent-supplied `approved: true` is never authorization.

## Workspace authority

The human or trusted launcher authorizes canonical roots before requests.
MCP client roots are hints, not permission grants. Resolve the root and target
canonically; check containment by path components, not string prefix. A new
write target requires checking its nearest existing parent. Reject traversal,
symlink escapes, unsupported links and root changes until reauthorized.
Do not confuse a symlinked root's lexical spelling with its canonical identity.

Each multi-root grant names its roots and read/write modes independently.
A root/session change revokes prior approvals and evidence freshness. Report
which root was used without leaking unrelated host paths. Revalidate before
execution; a check-then-use path race must fail closed or use safe handle-based
access. Never claim race-free confinement from a `realpath` precheck alone.

## Trusted policy and approval binding

Policy belongs outside repository-controlled files, in a human-owned user-level
store selected by the trusted launcher. A repository can request narrower access,
not grant broader authority. Do not accept trust material from imported reports,
prompts, workspace settings, child agents or unverified caller metadata.

A trusted approval broker must bind the exact operation and canonical arguments,
workspace identity, source/content digest, trusted-policy digest, authenticated
caller/session, expiry, budgets and one-use request identifier. A changed file,
patch, target, network destination, policy or session invalidates it. Replays,
expired requests and mismatches are denied before side effects. Do not ship an
approval token format or broker without maintainer security review.

## Outcomes, freshness and budgets

Keep connection states distinct: configured, connected, invoked and enforced.
“Enforced” requires evidence of the specific active lifecycle control, not an
MCP connection or badge. Denied, cancelled, unsupported, timed out, failed and
inconclusive are distinct outcomes, never success.

Static detector disappearance is not verified remediation. Static refutation
and independent retest are different evidence levels (see [fix outcomes #228](https://github.com/asamassekou10/ship-safe/issues/228)).
Cases must bind source, policy, tool version, acquisition time and evidence
origin. Changed source or policy makes an old decision stale. Treat imported
claims as untrusted until validated; no agent can forge a successful retest by
submitting a JSON object that says it passed.

Use bounded file sizes, findings, transport messages, elapsed time and provider
cost. Cancellation stops child work and prevents pending writes. Network/probe
and execution requests require explicit destination/command budgets. If an
execution backend is unavailable, return unsupported, never run on the host.
Default network access off in verification; do not inherit provider credentials.

## Required threat-model conformance specifications

These are acceptance specifications, not claims of passing runtime tests:

| Input or state | Required result |
| --- | --- |
| Absolute outside path, `../`, sibling with a shared prefix | Deny without reading or writing |
| Existing or newly created symlink escaping a grant | Deny; no write through the link |
| Legitimate symlinked root | Canonical grant works without widening scope |
| Root change, changed source or multi-root crossover | Reauthorize; old approvals/evidence invalid |
| Forged `approved: true`, replay or expired approval | Deny before any side effect |
| Imported “verified” claim with no trusted provenance | Untrusted/inconclusive, not verified |
| Scan with report output/provider option but only a read grant | Deny the additional capability |
| Suppression/patch touching a different path than approved | Deny without partial application |
| Missing sandbox, denied network, timeout or cancellation | Explicit non-success; no host fallback |
| Moved/renamed sink, empty comparison, incomplete rescan | No independent-verification claim |

## Decisions before implementation

Maintainers must approve operation schemas, trusted launcher/store ownership,
session authentication and revocation, budget defaults, case schema/freshness,
and CLI/MCP migration/versioning. #227 owns durable cases, #229 tool exposure,
#230 client configuration and #234 isolation. This proposal adds none of those
privileged operations. Do not close #226 solely because this draft exists.
