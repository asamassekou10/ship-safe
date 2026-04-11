---
name: ship-safe-security
version: 8.0.0
description: Run Ship Safe security scans from within a Hermes Agent workflow. Detects vulnerabilities in codebases, MCP servers, agent manifests, and Hermes deployments.
author: Ship Safe (https://shipsafe.dev)
tools:
  - ship_safe_audit
  - ship_safe_scan_mcp
  - ship_safe_get_findings
  - ship_safe_suppress_finding
  - ship_safe_memory_list
permissions:
  - filesystem: read-only
  - network: none
  - shell: none
tags:
  - security
  - devsecops
  - hermes
  - mcp
  - agent-security
---

# Ship Safe Security Skill

This skill enables a Hermes Agent to run security audits on codebases and MCP server manifests, retrieve findings, suppress false positives, and query the persistent security memory.

## When to use this skill

Use this skill when the agent needs to:
- Audit a codebase for security vulnerabilities before deployment
- Validate an MCP server manifest before connecting to it
- Check historical scan findings for a project
- Suppress known-safe findings to reduce noise in future scans
- List what the security memory has learned about a project

## Tool guide

### ship_safe_audit
Runs a full security audit on a local codebase directory.

```
ship_safe_audit({ path: "/path/to/project", severity: "high", deep: true })
```

Returns a findings report with severity-graded issues, CWE/OWASP mappings, and remediation guidance.

### ship_safe_scan_mcp
Analyzes an MCP server manifest (URL or local file) for tool poisoning, prompt injection, and Hermes function-call poisoning patterns.

```
ship_safe_scan_mcp({ target: "https://mcp.example.com" })
ship_safe_scan_mcp({ target: "/path/to/manifest.json" })
```

Returns per-tool findings including any embedded `<tool_call>` injection, credential harvesting patterns, and schema bypass indicators.

### ship_safe_get_findings
Retrieves findings from the last saved scan report for a project.

```
ship_safe_get_findings({ path: "/path/to/project", severity: "critical" })
```

### ship_safe_suppress_finding
Inserts an inline `ship-safe-ignore` comment in source code to suppress a known-safe finding.

```
ship_safe_suppress_finding({ file: "src/api.js", line: 42, reason: "False positive — value is sanitized upstream" })
```

### ship_safe_memory_list
Lists all entries in the project's security memory (previously learned false positives).

```
ship_safe_memory_list({ path: "/path/to/project" })
```

## Security constraints

- This skill operates **read-only** on the filesystem by default. It does not modify source files unless explicitly invoked via `ship_safe_suppress_finding`.
- Network access is disabled — MCP manifest fetching must be explicitly permitted by the agent operator.
- This skill never forwards credentials or secrets to external endpoints.
- All findings are stored locally at `.ship-safe/last-report.json`.

## Example workflow

```
1. Agent receives task: "Audit the codebase before merging PR #42"
2. Agent calls: ship_safe_audit({ path: process.cwd(), severity: "high" })
3. If critical findings: agent reports findings and blocks merge recommendation
4. If high findings only: agent calls ship_safe_get_findings to get details
5. Agent surfaces remediation suggestions from the findings' `fix` fields
6. If finding is known-safe: agent calls ship_safe_suppress_finding to mark it
```
