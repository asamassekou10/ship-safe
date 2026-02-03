# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ship-safe, please report it responsibly.

### For Security Issues in Ship-Safe Itself

**Do NOT open a public issue.** Instead:

1. Email the maintainers directly (check the npm package for contact info)
2. Or use GitHub's private security advisory feature:
   - Go to the repository's Security tab
   - Click "Report a vulnerability"

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

### For False Positives in Secret Detection

If you find that ship-safe is incorrectly flagging something as a secret:

1. Open a regular GitHub issue
2. Include the pattern that's causing false positives
3. Explain why it's not actually a secret

### For Missing Secret Patterns

If you know of a secret format that ship-safe should detect but doesn't:

1. Open a GitHub issue or PR
2. Include the pattern format
3. Explain the risk if this secret is exposed

## Scope

This security policy covers:

- The ship-safe npm package
- The ship-safe CLI tool
- Detection patterns and their accuracy
- Any code in this repository

## Security Best Practices

Remember: ship-safe is a helper tool, not a guarantee. Always:

1. **Use multiple tools** - Combine with gitleaks, trufflehog, or detect-secrets
2. **Enable pre-commit hooks** - Catch secrets before they're committed
3. **Rotate exposed secrets immediately** - Even if you delete them from git
4. **Use environment variables** - Never hardcode secrets
5. **Regular audits** - Run security scans as part of CI/CD

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

We support the latest major version with security updates.
