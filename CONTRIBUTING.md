# Contributing to Ship Safe

Thanks for helping build Ship Safe. The best contributions make local-first security stronger for developers using AI agents, MCP servers, LLM tool calls, supply-chain checks, and CI.

## Quick Links

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Issue Tracker](https://github.com/asamassekou10/ship-safe/issues)
- [Good first issues](https://github.com/asamassekou10/ship-safe/contribute)
- [Add an Agent](docs/adding-an-agent.md)
- [Add a Security Rule](docs/adding-a-security-rule.md)
- [Release Process](docs/releasing.md)

## How Can I Contribute?

### Pick a Contribution Lane

| Lane | Good first contribution | Where to start |
|------|-------------------------|----------------|
| Security agents | Add one focused detector or improve an existing one | `cli/agents/`, [docs/adding-an-agent.md](docs/adding-an-agent.md) |
| MCP and AI rules | Detect unsafe tool permissions, prompt-controlled tools, or risky agent config | `cli/agents/mcp-security-agent.js`, `cli/agents/agentic-security-agent.js` |
| Fixtures and tests | Add vulnerable examples and regression coverage | `cli/__tests__/` |
| Docs and examples | Explain setup, CI, red team, Kimi K3, MCP, or agent workflows | `README.md`, `docs/` |

If you are new, look for issues labeled `good first issue`, `help wanted`, `docs`, `agent`, `security rule`, or `tests`.

### Public CLI and Private Cloud Boundary

This public repo contains the MIT-licensed CLI, security agents, rules, fixtures, docs, examples, and CI integrations. Ship Safe Cloud, the hosted dashboard for billing, scan history, PR Guardian, teams, and commercial workflows, is developed in a private repository.

Please keep public contributions focused on the CLI/security engine unless a maintainer explicitly links you to private cloud work.

### Working on an Assigned Issue

If you ask to work on an issue, we are happy to assign it to you. A few small habits help everyone keep momentum:

- Comment when you start so maintainers know the issue is active
- Open a draft PR early if you can, even with a small first pass
- Ask questions in the issue if you get blocked or are unsure about the approach
- Share a quick update if the work takes more than a few days

No pressure if life gets busy. Maintainers may check in after about a week just to see whether you still want the issue or need help.

### Reporting Bugs

Found a bug? Please open an issue with:

1. **Clear title** describing the problem
2. **Steps to reproduce** the issue
3. **Expected behavior** vs **actual behavior**
4. **Environment** (OS, Node.js version, npm version)
5. **Error messages** or screenshots if applicable

### Suggesting Features

Have an idea? Open an issue with:

1. **Problem statement** - What security issue are you trying to solve?
2. **Proposed solution** - How would ship-safe help?
3. **Alternatives considered** - Other approaches you thought about
4. **Target audience** - Who benefits from this feature?

### Contributing Code

#### What We're Looking For

- **New AI and MCP checks** - Tool-call abuse, prompt-controlled tools, unsafe transports, risky agent memory, agentic supply-chain issues
- **New secret patterns** - Add detection for more API key formats with low false positives
- **Stack-specific configs** - Supabase, Firebase, Vercel, Stripe, GitHub Actions, Docker, Kubernetes
- **Vulnerable fixtures** - Small examples that prove a detector catches a real issue
- **Docs and examples** - Clear workflows for local scanning, CI, red team, MCP, and agent usage
- **Bug fixes** - Always welcome

#### Pull Request Process

1. **Fork the repo** and create your branch from `main`
2. **Make your changes** with clear, educational comments
3. **Test locally**:
   ```bash
   npm install
   npm test
   node cli/bin/ship-safe.js scan . --no-ai
   ```
4. **Update documentation** if needed
5. **Open a PR** with a clear description

#### Code Style

- **Explain the risk** - Every security pattern needs a short "why it matters" explanation
- **Keep checks focused** - Prefer one precise detector over a broad noisy rule
- **Minimize false positives** - A finding should have clear evidence, not vibes
- **Respect local-first scanning** - Core checks must work without network calls or API keys
- **Mask secrets in output** - Never print full credentials in findings, logs, tests, or docs
- **Use the standard finding shape** - Include file, line, severity, rule, title, description, confidence, and fix guidance when possible

### Pull Request Checklist

Before opening a PR, please confirm:

- [ ] The change is scoped to one problem
- [ ] `npm test` passes
- [ ] `node cli/bin/ship-safe.js scan . --no-ai` runs
- [ ] New detector behavior has a test or fixture when practical
- [ ] Documentation changed if the user-facing behavior changed
- [ ] No real secrets, tokens, customer data, or private repo URLs were added
- [ ] The false-positive benchmark was run, if you touched a rule (see below)
- [ ] Absence rules assert the quiet direction (see below)

### If You Touched a Rule: Run the Benchmark

```bash
node benchmarks/false-positives/run.mjs --clone   # first time only
node benchmarks/false-positives/run.mjs
```

Paste the before and after in your PR. What we look for:

- **Clean corpus should drop or hold.** These are mature, heavily reviewed
  projects. A finding on one of them is triage work a user inherits.
- **NodeGoat and DVWA must not move.** They are deliberately vulnerable and
  exist so a drop in noise cannot be mistaken for progress when it is really
  lost detection. If they do move, say why in the PR. Sometimes it is correct,
  but it always needs explaining.

This is not ceremony. Nearly every fix in 9.7.0 came from running this and
reading the output honestly, including a rule that reported 1,963 findings on a
single contributor credits file.

### If Your Rule Asserts an Absence, Test the Quiet Direction

A rule that reports something *missing* — no logging, no rate limit, no schema
validation — has a failure mode a normal detection test never catches. It can
be structurally incapable of staying quiet.

Written like this, it never fails:

```js
regex: /tool_call[\s\S]{0,300}(?![\s\S]{0,300}(?:log|audit))/
```

The gap backtracks until the lookahead succeeds, so the rule degrades into
"this line contains `tool_call`". That exact pattern shipped and produced 1,904
findings on one repository.

Prefer a structural check that answers two questions per file: does this file
do the thing, and does anything here mitigate it. `AGENT_STRUCTURAL_RULES` in
`cli/agents/agentic-security-agent.js` is the shape to copy.

Then add a case to `cli/__tests__/absence-rules.test.js`: give the rule an
input where the mitigation is present, and assert it stays silent. Be generous
about what counts as a mitigation. The finding claims nothing here does X, so
one instance of X refutes it, and a stingy check trades a loud wrong answer for
a quiet one.

### Adding Secret Patterns

To add a new secret detection pattern, edit `cli/utils/patterns.js`:

```javascript
{
  name: 'Your Service API Key',
  pattern: /your-regex-here/g,
  severity: 'high',  // 'critical', 'high', or 'medium'
  description: 'Why this secret is dangerous if exposed.'
}
```

**Requirements for new patterns:**
- Low false-positive rate (test against real codebases)
- Clear description of the risk
- Appropriate severity level

### Adding Security Configs

Place new config files in `/configs/` with:

1. **Heavy comments** explaining each setting
2. **Why it matters** for each security control
3. **How to integrate** into a project
4. **Common customizations** users might need

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ship-safe.git
cd ship-safe

# Install dependencies
npm install

# Run locally
node cli/bin/ship-safe.js scan .
node cli/bin/ship-safe.js checklist
node cli/bin/ship-safe.js init

# Test the full flow
npm run ship-safe scan .
```

## CI on Your Pull Request

Workflows on pull requests from forks wait for a maintainer to approve them
before they run. On your first pull request you will usually see no checks at
all for a while. That is expected, it is not a problem with your branch, and
there is nothing you need to do.

This repository builds a security scanner, so running code from a fork
automatically is a risk we would rather not take. The approval is a deliberate
gate, not an oversight.

Once approved you get the full matrix: Node 18, 20, and 22, plus the
integration suite. Before pushing you can run the same checks locally:

```bash
node --test cli/__tests__/*.test.js
npx eslint cli/
```

## Community

- Be respectful and inclusive
- Help newcomers learn
- Focus on the mission: making security accessible

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes for significant contributions
- Social posts for major new agents, rules, integrations, or docs

Thank you for helping make AI-assisted development safer.
