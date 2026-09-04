# Hermes Agent's security model

Read this before writing a Hermes rule. Hermes publishes an unusually explicit
[security policy](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md),
and a rule that contradicts it is a false positive no matter how good the regex
is.

This is our summary for rule authors. Their document is the authority; if the
two disagree, theirs wins and this file needs updating.

## The one boundary

> The only security boundary against an adversarial LLM is the operating
> system. Nothing inside the agent process constitutes containment — not the
> approval gate, not output redaction, not any pattern scanner, not any tool
> allowlist.

That is a direct quote, and the emphasis is theirs. It has two consequences for
us.

**We are not containment either.** Ship Safe investigates repository and
configuration evidence; it does not create an isolation boundary. Framing a
finding as if the report itself prevents an attack contradicts their model and
ours.

**In-process heuristics are not boundaries.** Their approval gate, output
redaction, and Skills Guard are review aids by design. A finding that says "the
approval gate can be bypassed" is describing intended behaviour.

## Two isolation postures

Operators choose one deliberately, and the difference matters for severity.

**Terminal-backend isolation** runs shell and file operations inside a
container or remote host. It does not confine the code-execution tool, MCP
subprocesses, plugin loading, hook dispatch, or skill loading, all of which run
in the agent's own Python process.

**Whole-process wrapping** puts the entire process tree in a sandbox. Every
path is subject to the same policy.

The interesting finding is a **mismatch**: a repository running the local
backend while ingesting untrusted input, or running terminal-backend isolation
while expecting it to confine code paths that never touch the shell. Their
policy calls that "operating outside the supported security posture", which is
exactly the sentence a finding should be able to point at.

## What their policy treats as in scope

Rules that find these are finding real, reportable problems:

- Escape from a declared isolation posture
- A caller outside the configured allowlist dispatching work, receiving output,
  or resolving approvals
- Credential exfiltration through a mechanism meant to prevent it
- Code behaving contrary to a documented stance

That fourth one is broader than it looks. If Hermes documents that a consuming
layer treats agent output as inert and some path breaks that, it is in scope.

**Adapters that fail open are explicitly named.** Their §2.6 says every enabled
network-exposed adapter requires an allowlist, and that code paths failing open
when none is configured are bugs in scope. A static rule that finds those is
our highest-value Hermes rule. Ship Safe reports this as
`HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN` with `critical` severity and `boundary`
posture.

## What their policy treats as out of scope

Do not write rules whose entire claim is one of these:

- Bypassing an in-process heuristic, including Skills Guard patterns
- Prompt injection on its own, without a chained outcome
- Consequences of a posture the operator chose, such as shell reaching host
  state under the local backend
- Documented break-glass settings like `--insecure` or disabled approvals

These can still be worth reporting to a user as hygiene. They are not boundary
findings and should not be severity-inflated to look like they are.

## Posture-aware severity

Every Hermes finding carries a posture:

- `boundary` — a class their policy treats as in scope
- `hygiene` — a real improvement that their policy does not treat as a
  vulnerability

Rendered separately, so someone who has read their policy can tell instantly
which half of the report to act on. This is the difference between a report a
Hermes operator trusts and one they close.

## Version drift

Ship Safe 10.0 is baselined against Hermes Agent v0.21.0 at commit
`29112bef099274229cadff79cdff7bf7b99c4b77`. The exact surface-by-surface claim
and its limitations live in
[hermes-coverage-matrix.md](hermes-coverage-matrix.md).

Hermes moves quickly. Baseline changes must pin a release tag to a full commit,
review upstream's security policy and affected surfaces, and update the
machine-readable baseline and matrix together. Never make a coverage claim
follow `main` or `latest` automatically.
