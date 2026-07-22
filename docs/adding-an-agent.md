# Adding a Ship Safe Agent

Ship Safe agents are focused scanners. Each agent detects one family of risk, returns standard findings, and skips projects where it does not apply.

## When to Add an Agent

Add a new agent when the check needs its own domain logic, file discovery, scoring behavior, or multiple related rules. If you only need one pattern inside an existing scanner, add a rule instead.

Good agent ideas:

- MCP registry and tool permission checks
- AI-agent memory poisoning checks
- New framework-specific config checks
- Cloud or CI misconfiguration families
- Supply-chain attack patterns with several signals

## Agent Shape

Create a file in `cli/agents/` and extend `BaseAgent`.

```js
import { BaseAgent, createFinding } from './base-agent.js';

export class ExampleSecurityAgent extends BaseAgent {
  constructor() {
    super(
      'ExampleSecurityAgent',
      'Detects example risky configuration',
      'AI/LLM',
    );
  }

  shouldRun(recon) {
    return true;
  }

  async analyze(context) {
    const files = await this.discoverFiles(context.rootPath, ['**/*.json']);
    const findings = [];

    for (const file of files) {
      // Read and inspect the file here.
      findings.push(createFinding({
        file,
        line: 1,
        severity: 'medium',
        category: this.category,
        rule: 'example-risky-config',
        title: 'Risky example configuration',
        description: 'Explain why this creates risk and when it matters.',
        confidence: 'high',
        fix: 'Describe the smallest safe remediation.',
      }));
    }

    return findings;
  }
}
```

## Register the Agent

Update `cli/agents/index.js`:

1. Export the class near the other agent exports.
2. Import the class for the built-in registry.
3. Add `new ExampleSecurityAgentClass()` inside `BUILT_IN_AGENTS()`.

If the public agent count changes, update the README and website copy that mentions the count.

## Testing

Add a focused test under `cli/__tests__/`.

Use a tiny temporary fixture that includes one vulnerable file and one safe file. The test should prove:

- the risky file produces a finding
- the safe file does not produce a finding
- severity, rule id, title, and fix guidance are stable

Run:

```bash
npm test
node cli/bin/ship-safe.js scan . --no-ai
```

## Review Standard

A good agent is precise, quiet, and useful. It should avoid broad guesses, never print real secrets, and always explain the remediation in language a developer can act on during a PR review.
