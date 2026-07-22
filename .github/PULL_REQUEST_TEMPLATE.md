## Description

Brief description of the changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] New security agent
- [ ] New security rule
- [ ] New secret detection pattern
- [ ] New security config/checklist
- [ ] Documentation update
- [ ] Other (describe below)

## Checklist

- [ ] I've tested my changes locally
- [ ] I've added or updated tests when behavior changed
- [ ] I've explained security impact and remediation in finding copy/docs
- [ ] I've updated documentation if needed
- [ ] My code follows the project's style
- [ ] I've checked for false positives for new detectors
- [ ] I did not add real secrets, tokens, customer data, or private repo URLs

## Testing Done

Describe how you tested your changes:

```bash
# Commands you ran
npm test
node cli/bin/ship-safe.js scan . --no-ai
```

## Related Issues

Fixes #(issue number)

## Additional Notes

Any other context for reviewers.
