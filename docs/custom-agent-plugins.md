# Custom Agent Plugins

Ship Safe can load project-local security agents without publishing a package. Drop a file in `.ship-safe/agents/` and it runs alongside the built-in agents on every scan.

Use a plugin for a check that only makes sense for your codebase or company, such as an internal API convention or an in-house secret format. For a check general enough to help every Ship Safe user, contribute it upstream instead — see [Add an Agent](./adding-an-agent.md).

## Where to Put It

Create `.ship-safe/agents/<name>.js` in your project root. Any `.js` or `.mjs` file in that directory is picked up automatically; no registration step is required.

## A Minimal Plugin

```js
// .ship-safe/agents/no-console-token.js
import { BaseAgent, createFinding } from 'ship-safe';
import fs from 'fs';

export default class NoConsoleToken extends BaseAgent {
  constructor() {
    super();
    this.name = 'NoConsoleToken';
    this.category = 'custom';
  }

  async analyze({ files }) {
    const findings = [];

    for (const file of files) {
      if (!/\.(js|ts)$/.test(file)) continue;

      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      lines.forEach((line, i) => {
        if (/console\.log\(.*(token|apiKey)/i.test(line)) {
          findings.push(createFinding({
            file,
            line: i + 1,
            severity: 'medium',
            category: this.category,
            rule: 'NO_CONSOLE_TOKEN',
            title: 'Token logged to console',
            description: 'Logging a token or API key can leak it into CI logs or terminal history.',
            confidence: 'medium',
            fix: 'Remove the log statement or log a redacted value instead.',
          }));
        }
      });
    }

    return findings;
  }
}
```

You can scaffold this same shape with:

```bash
npx ship-safe plugins new no-console-token
```

That writes a template to `.ship-safe/agents/no-console-token.js` with the required class shape already in place.

## How Ship Safe Loads It

`cli/utils/plugin-loader.js` scans `.ship-safe/agents/*.js` on startup. Each file must have a default export that is a class extending `BaseAgent` and implementing `async analyze(context)`. Files that fail validation are skipped with a warning; they do not stop the rest of the scan.

Loaded plugins register on the same orchestrator as the built-in agents and receive the same `context` object: `rootPath`, `files`, `recon`, and `options`.

## How to Run It Locally

```bash
npx ship-safe plugins list
npx ship-safe audit .
```

`plugins list` confirms Ship Safe sees your file before you run a full scan. `audit` (or `scan`) runs it for real; findings from a plugin appear in the normal report, labeled with the agent name you set in the constructor.

## Safety Guidance

- Keep plugins local-only. `.ship-safe/agents/` is arbitrary code that runs in the same process as the scanner; only add files you wrote or reviewed yourself.
- Never read the value of a secret to decide whether to flag it. Match on file path, key name, or pattern shape, and pass only a truncated or masked snippet into `matched`.
- Keep each plugin narrow. A rule that fires on common strings without real context creates noise that trains developers to ignore findings.
- Give every finding concrete `fix` guidance. A finding without a next step is not actionable during a PR review.
