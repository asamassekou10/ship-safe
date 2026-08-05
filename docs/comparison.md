# Ship Safe compared to other scanners

**Short version: run Ship Safe alongside Semgrep, Gitleaks and Trivy, not instead
of them.** They are better than Ship Safe at the things they are built for, and
this page says where. If you are choosing exactly one security scanner and your
main risk is injection bugs in application code, pick Semgrep or CodeQL.

Ship Safe is aimed at a narrower question: *what did an AI coding agent just do
to my repository, my CI, and my local tool configuration?*

## Coverage

Verified against each project's public rule registry and changelog in August
2026. This space moves fast — if a cell is out of date, please open an issue.

| | Ship Safe | Semgrep | Gitleaks | Trivy | CodeQL |
|---|---|---|---|---|---|
| Interprocedural taint analysis | ✗ | ✅ | ✗ | ✗ | ✅✅ |
| Secrets in git history | ✅ | ✗ | ✅✅ | ✗ | ✗ |
| Dependency CVEs | basic | ✗ | ✗ | ✅✅ | ✗ |
| Container / IaC misconfig | basic | ✅ | ✗ | ✅✅ | ✗ |
| Prompt injection in app code | ✅ | ✅ | ✗ | ✗ | ✅ (JS/TS) |
| Malicious agent skill definitions | ✅ | ✅ (Pro) | ✗ | ✗ | ✗ |
| CI/CD workflow misconfig | ✅ | ✅ | ✗ | ✗ | ✗ |
| **MCP client config files** | ✅ | ✗ | ✗ | ✗ | ✗ |
| **Agent memory poisoning** | ✅ | ✗ | ✗ | ✗ | ✗ |
| **Hallucinated-package imports** | ✅ | ✗ | ✗ | ✗ | ✗ |
| **AIBOM / agent attestation** | ✅ | ✗ | ✗ | ✗ | ✗ |
| Zero-config, no rule selection | ✅ | partial | ✅ | ✅ | ✗ |
| Runs without a build | ✅ | ✅ | ✅ | ✅ | ✗ |

`✅✅` means this is the tool's core competency and it is the best available
option. `basic` means Ship Safe checks it but a dedicated tool is better.

## Where the others are clearly better

- **CodeQL** does real interprocedural dataflow. If a tainted value crosses four
  function boundaries before reaching a sink, CodeQL follows it and Ship Safe
  does not. Ship Safe is pattern-based and does not attempt this.
- **Gitleaks** has years of tuned entropy heuristics and detector coverage for
  secrets. Ship Safe scans history too, but Gitleaks is the specialist.
- **Trivy** has a real vulnerability database behind it, plus container image and
  full IaC scanning. Ship Safe's dependency checking is not a substitute.
- **Semgrep** has ~5,000 rules, a large community registry, and custom rule
  authoring. It has also moved into AI security: 27 AI security rules covering
  prompt injection and unrestricted tool use, 186 Shadow AI rules, and 122 Pro
  rules for malicious patterns in agent skill definitions.

## Where Ship Safe is currently alone

These are the bolded rows above. We found no equivalent public rules in the
other four projects as of August 2026:

- **MCP client configuration.** Semgrep can analyze the *source code* of an MCP
  server. Ship Safe reads the config files that decide which servers your editor
  actually launches (`.cursor/mcp.json`, `.vscode/mcp.json`,
  `claude_desktop_config.json`) and flags risky declarations: unpinned remote
  servers, broad filesystem scope, secrets inline in the server definition.
  Auditing a server's source is a different question from auditing what your
  machine is configured to run.
- **Agent memory poisoning.** Persistent instruction stores that an agent will
  re-read on a later run, where an attacker who writes once influences every
  subsequent session.
- **Hallucinated-package imports.** Ship Safe flags imports that are not Node
  builtins, not declared in `package.json`, and not present in `node_modules`,
  which is the shape a slopsquatted suggestion takes before you install it. Note
  this is a heuristic on unresolvable imports, not live registry verification —
  commercial supply-chain tools such as Socket and Snyk do verify against the
  registry and go deeper here.
- **AIBOM and agent attestation.** Inventory of which models, agents and tools a
  repository depends on.

The honest read: this gap is narrowing. Semgrep shipped Guardian specifically to
scan AI-generated code as it is written, and CodeQL added prompt injection
queries in 2026. Ship Safe's advantage is in the agent's *environment and
configuration* rather than the code it emits, and that is a smaller island than
it was a year ago.

## Noise

The other half of picking a scanner is how much triage it creates. We publish a
[false-positive benchmark](../benchmarks/false-positives/) measuring Ship Safe on
mature projects with no known active vulnerabilities: 73 findings across express,
requests, flask and chalk, with the 1 remaining critical documented as a false
positive.

We deliberately do **not** publish a head-to-head detection comparison. A
vendor-run benchmark where the vendor picks the corpus is worth very little, and
we would rather give you a reproducible measurement of our own noise than a
scoreboard we designed to win.

## Suggested combination

```bash
trivy fs .          # dependency CVEs and container/IaC misconfiguration
gitleaks detect     # secrets across git history
semgrep --config auto   # application-code vulnerabilities and taint
ship-safe ci .      # agent, MCP, CI/CD and AI supply-chain surface
```

Sources: [Semgrep Guardian](https://semgrep.dev/products/product-updates/detect-risks-in-ai-generated-code-with-semgrep-guardian/),
[Semgrep github-actions ruleset](https://registry.semgrep.dev/ruleset/github-actions),
[CodeQL 2.26.0 changelog](https://github.blog/changelog/2026-07-10-codeql-2-26-0-adds-kotlin-2-4-0-support-and-ai-prompt-injection-detection/),
[Trivy scanners](https://trivy.dev/latest/docs/scanner/misconfiguration/),
[Gitleaks](https://gitleaks.org/how-gitleaks-works-deep-dive-into-secret-detection-scanning-engine-and-security-automation/).
