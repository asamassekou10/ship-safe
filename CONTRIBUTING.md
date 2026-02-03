# Contributing to Ship Safe

First off, thanks for taking the time to contribute! This project exists because of people like you.

## Quick Links

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Issue Tracker](https://github.com/asamassekou10/ship-safe/issues)

## How Can I Contribute?

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

- **New secret patterns** - Add detection for more API key formats
- **Stack-specific configs** - Supabase, Firebase, Vercel, etc.
- **Security checklists** - Deployment checklists for specific platforms
- **Snippets** - Copy-paste security code for common patterns
- **Bug fixes** - Always welcome!

#### Pull Request Process

1. **Fork the repo** and create your branch from `main`
2. **Make your changes** with clear, educational comments
3. **Test locally**:
   ```bash
   npm install
   node cli/bin/ship-safe.js scan .
   node cli/bin/ship-safe.js checklist --no-interactive
   ```
4. **Update documentation** if needed
5. **Open a PR** with a clear description

#### Code Style

- **Comments are mandatory** - Every security pattern needs a "why it matters" explanation
- **Keep it simple** - This is for indie hackers who move fast
- **Educational tone** - Explain, don't just implement
- **No external services** - Everything should work offline

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

Thank you for helping make the indie web more secure!
