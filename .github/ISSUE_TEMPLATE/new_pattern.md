---
name: New Secret Pattern
about: Suggest a new secret detection pattern
title: '[PATTERN] '
labels: pattern
assignees: ''
---

## Secret Type

What type of secret should be detected? (e.g., Twilio API Key, MongoDB Atlas credentials)

## Pattern

The regex pattern or string format to match:

```
Example: TWILIO_[A-Za-z0-9]{32}
```

## Real-World Examples

Redacted examples of what this secret looks like:

```
TWILIO_SK***************************abc123
```

## Risk Level

- [ ] Critical - Full account access, financial impact
- [ ] High - Significant access or data exposure
- [ ] Medium - Limited scope or test credentials

## Why It Matters

What can an attacker do with this secret if exposed?

## References

- Link to the service's documentation about API keys
- Any public incidents involving this secret type
