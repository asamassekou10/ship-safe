# Contributing to Ship Safe

Thanks for helping build Ship Safe. The best contributions make local-first security stronger for developers using AI agents, MCP servers, LLM tool calls, cloud dashboards, and CI.

## Quick Links

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Issue Tracker](https://github.com/asamassekou10/ship-safe/issues)
- [Good first issues](https://github.com/asamassekou10/ship-safe/contribute)
- [Add an Agent](docs/adding-an-agent.md)
- [Add a Security Rule](docs/adding-a-security-rule.md)

## How Can I Contribute?

### Pick a Contribution Lane

| Lane | Good first contribution | Where to start |
|------|-------------------------|----------------|
| Security agents | Add one focused detector or improve an existing one | `cli/agents/`, [docs/adding-an-agent.md](docs/adding-an-agent.md) |
| MCP and AI rules | Detect unsafe tool permissions, prompt-controlled tools, or risky agent config | `cli/agents/mcp-security-agent.js`, `cli/agents/agentic-security-agent.js` |
| Fixtures and tests | Add vulnerable examples and regression coverage | `cli/__tests__/` |
| Docs and examples | Explain setup, CI, red team, Kimi K3, or dashboard workflows | `README.md`, `docs/`, `webapp/app/app/guide/` |
| Web dashboard | Improve scan history, findings, actions, onboarding, and reports | `webapp/app/`, `webapp/components/` |

If you are new, look for issues labeled `good first issue`, `help wanted`, `docs`, `agent`, `security rule`, `tests`, or `webapp`.

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
- **Dashboard UX improvements** - Better scan triage, actions, onboarding, account setup, and reports
- **Docs and examples** - Clear workflows for local scanning, CI, red team, and web app usage
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
