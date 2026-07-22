# Adding a Security Rule

Security rules are the smallest useful checks in Ship Safe. Add a rule when an existing agent already owns the domain and your change is one new pattern, heuristic, or remediation message.

## Start Here

Use the existing agent that matches the risk:

| Risk | Common file |
|------|-------------|
| Secrets and tokens | `cli/utils/patterns.js` |
| MCP server or tool-call risk | `cli/agents/mcp-security-agent.js` |
| Agentic AI behavior | `cli/agents/agentic-security-agent.js` |
| Prompt or agent config injection | `cli/agents/agent-config-scanner.js` |
| CI/CD pipeline risk | `cli/agents/cicd-scanner.js` |
| Package install risk | `cli/agents/install-guard-agent.js` |
| App vulnerabilities | `cli/agents/injection-tester.js`, `cli/agents/auth-bypass-agent.js`, `cli/agents/ssrf-prober.js` |

## Rule Checklist

Every rule should include:

- a stable `rule` id
- a clear title
- severity based on likely impact
- confidence based on signal strength
- evidence that is useful but does not expose full secrets
- fix guidance that names the safer configuration or code pattern

## Secret Patterns

For secret formats, edit `cli/utils/patterns.js`.

```js
{
  name: 'Example API Key',
  pattern: /example_[A-Za-z0-9]{32}/g,
  severity: 'high',
  description: 'Example API keys can grant access to protected service data.',
}
```

Secret rules need a low false-positive rate. Prefer provider-specific prefixes, fixed lengths, checksums, or nearby context when available.

## Tests

Add or update a test in `cli/__tests__/`. A strong test includes:

- one vulnerable fixture
- one safe fixture
- an assertion for the rule id
- an assertion that secrets are masked or bounded in output

Run:

```bash
npm test
node cli/bin/ship-safe.js scan . --no-ai
```

## What to Avoid

Avoid rules that flag common strings without strong context, require network access for core scanning, or create findings that only say "review this." Ship Safe should help developers decide what to fix next.
