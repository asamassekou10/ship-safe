# Hermes 10.0 boundary confirmation review

Review date: 2026-09-05
Reviewer: Ship Safe maintainer review
Upstream pin: Hermes Agent v0.21.0, 29112bef099274229cadff79cdff7bf7b99c4b77

This is a fixture adjudication record, not a claim that the upstream Hermes
release was exploited. Each positive is checked against the cited source and
its constrained counterpart. Static evidence remains configured or inferred;
no row claims traced or reproduced runtime evidence.

| Scenario | Vulnerable evidence inspected | Safe counterpart inspected | Boundary confirmation survives? |
| --- | --- | --- | --- |
| Unauthorized adapter caller | fixtures/unauthorized-adapter/vulnerable/plugins/platforms/telegram/adapter.py:5 receives a caller and reaches dispatch_agent at line 8 without a rejecting allowlist branch | fixtures/unauthorized-adapter/safe/plugins/platforms/telegram/adapter.py:6 rejects before dispatch_agent at line 8 | Yes |
| Credential present but unreachable | cli/__tests__/fixtures/hermes-credentials/plugin-vulnerable/.hermes/plugins/deploy-reporter/__init__.py:6-7 reads DEPLOY_TOKEN and passes it to httpx.post | cli/__tests__/fixtures/hermes-credentials/plugin-safe/.hermes/plugins/deploy-reporter/__init__.py:1-2 has no credential consumer | Yes |
| Plugin operation outside terminal sandbox | cli/__tests__/fixtures/hermes-terminal-posture/vulnerable/.hermes/config.yaml:3-8 selects Docker for terminal operations while retaining an untrusted MCP process in Hermes | cli/__tests__/fixtures/hermes-terminal-posture/safe/Dockerfile:2-4 wraps Hermes itself in Docker | Yes |
| Scheduled task retaining authority | cli/__tests__/fixtures/hermes-cron/authority-vulnerable/jobs.py:7-12 acquires authority and reaches the job action without function-level cleanup | cli/__tests__/fixtures/hermes-cron/authority-safe/jobs.py:7-14 resets the authority in finally | Yes |

The corresponding machine-readable scenario manifest is scenarios.json; the
runner rechecks every citation and output contract.
