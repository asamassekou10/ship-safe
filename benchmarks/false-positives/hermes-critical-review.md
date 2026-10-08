# Hermes critical-finding source review

## Scope

This is a source-level triage of the 63 critical findings in the October 7,
2026 Ship Safe 11.0.0 candidate scan of `NousResearch/hermes-agent` at pinned
commit [`743dc94`](https://github.com/NousResearch/hermes-agent/commit/743dc94ab90adb0529bb233b8498c6fd6ee0e020).
The scan produced 654 findings in total. The review inspected the reported
critical source locations and their nearby call paths. It was AI-assisted; it
is not an independent human security audit, a dynamic test, or proof that the
repository has no vulnerabilities. No exploit was reproduced.

## Triage summary

| Disposition after source review | Findings | What the review found |
|---|---:|---|
| Appear to be rule/context false positives | 55 | The reported locations were examples, comments, tests, fixed or constrained values, guarded command construction, or otherwise lacked the threat path asserted by the rule in the examined context. This is a source-review judgment, not proof of safety. |
| Keep flagged: explicitly opted-in unsafe deserialization | 2 | `optional-skills/research/darwinian-evolver/scripts/show_snapshot.py:59,62` calls `pickle.loads` only after an explicit trust flag and warning. Pickle can execute code; the opt-in does not make untrusted input safe. |
| Keep flagged: host-network isolation tradeoff | 2 | `docker-compose.yml:35,67` uses host networking. The reviewed dashboard binds locally and the API is off by default, but host networking weakens container network isolation and deployment context matters. |
| Expected fixed-destination credential actions; review context | 2 | `.github/workflows/deploy-site.yml:47` uses a deploy-hook secret with the configured deployment endpoint; `skills/productivity/google-workspace/scripts/setup.py:470` sends a token to Google's fixed revocation endpoint. No attacker-controlled destination was identified in the reviewed paths. Query-string logging behavior for the OAuth request was not assessed. |
| Follow up; no exploit demonstrated | 2 | `hermes_cli/cli_commands_mixin.py:2624` uses `shell=True` for a configured `$VISUAL`/`$EDITOR`; `hermes_state_search.py` interpolates a table name read from local SQLite metadata into SQL/PRAGMA statements. Prefer an argv-based editor invocation and validate/quote the identifier. |
| **Total critical locations reviewed** | **63** | Counts describe this pinned run only; they are not rates, prevalence estimates, or production accuracy measurements. |

The 55 context/rule findings should not be represented as 55 confirmed
vulnerabilities or as an independently measured false-positive rate. The
remaining eight include explicit risky behavior or context that deserves
attention; this source review does not establish exploitability in a particular
Hermes deployment. Hermes is a separate project and this review does not make
changes to it.

The 55 apparent context/rule false positives break down as follows: one
credential-key-block match; 15 `PYTHON_SQL_FSTRING`; one
`CMD_INJECTION_PYTHON_OS`; 16 `CMD_INJECTION_EXEC_TEMPLATE`; five
`CMD_INJECTION_SECRET_INTERPOLATION`; one `LLM_OUTPUT_TO_SQL`; two
`LLM_FILE_WRITE`; four `LLM_DB_WRITE_ACCESS`; one `MCP_NO_AUTH_TRANSPORT`; five
`AGENT_UNRESTRICTED_TOOLS`; one each of `RAG_PICKLE_EMBEDDING_MODEL`,
`RAG_USER_UPLOAD_TO_VECTORDB`, `PII_PLAINTEXT_PASSWORD_STORE`, and
`MEMORY_POISON_EXFILTRATE`. The other `PYTHON_SQL_FSTRING` and
`CMD_INJECTION_PYTHON_OS` findings are the two follow-ups above.

## Reproduce the scan

From the Ship Safe repository, fetch the pinned corpus and rerun the benchmark:

```bash
node benchmarks/false-positives/run.mjs --clone
npm run benchmark:fp
```

The corpus revision and machine-readable aggregate are in
[`corpus.json`](corpus.json) and [`results/latest.json`](results/latest.json).
The aggregate does not serialize this source-level triage; rerun the pinned
scan to inspect individual locations.
