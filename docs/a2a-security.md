# A2A security scanning

`A2ASecurityAgent` runs in the standard agent pool. It discovers both
`.well-known/agent-card.json` and legacy `.well-known/agent.json`, including
nested directories. Discovery respects the scanner's ignore rules and changed
file selection. JSON is parsed before inspecting descriptions, so escaped
Unicode instructions are checked too.

| Rule | Evidence |
| --- | --- |
| `A2A_CARD_HIDDEN_INSTRUCTION` | Instruction overrides, role hijacking, suspicious HTML comments, zero-width runs, or Unicode tag payloads in card and skill descriptions. Shares AgentConfigScanner's detectors and emoji exceptions. |
| `A2A_CARD_NO_AUTH` | Missing, empty, or unsupported authentication declarations, or explicitly anonymous security requirements. Supports legacy authentication, v0.3 security schemes, and v1 security requirements. A declaration does not prove enforcement by a server. |
| `A2A_CARD_HTTP_ENDPOINT` | Non-loopback HTTP in the card URL or its additional/supported interfaces. Local HTTP development endpoints are allowed. |
| `A2A_PUSH_NOTIFICATION_SSRF` | A literal non-public or non-HTTP(S) destination in an A2A push configuration. Shares cloud metadata hosts with SSRFProber and private-address classification with remote-fetch. |
| `A2A_REMOTE_CARD_UNPINNED` | A literal runtime discovery-card fetch without a recognized Fetch SRI hash. Medium-confidence review finding; post-fetch verification may require manual review. |

Push configurations are recognized in JSON and literal JavaScript/TypeScript
and Python objects under `pushNotificationConfig`, `taskPushNotificationConfig`,
or their snake_case spellings. Nested authentication fields may precede the
callback URL; only the configuration's direct literal URL is inspected. An
unrelated OAuth callback is not A2A evidence.
Remote fetch detection covers `fetch`, `axios.get`, `requests.get`, and
`httpx.get` with literal discovery URLs. Dynamic URLs, arbitrary SDK wrappers,
and cross-file signature/hash verification are outside this static check.
Fetch integrity is recognized only on an unconditional literal options object
in the second argument. Conditional options and hashes in other arguments do
not establish an integrity check.

## Signature states

Card findings carry `signatureState` with one of three values:

- `absent`
- `present but unverified`
- `verified against a pinned key`

CLI scans have no implicit trusted keys, so a signature alone always remains
unverified. Programmatic callers can supply independently obtained public keys:

```js
import { A2ASecurityAgent } from './cli/agents/a2a-security-agent.js';

const agent = new A2ASecurityAgent({
  pinnedKeys: new Map([
    ['publisher-key-id', { algorithm: 'ES256', key: publicKeyPem }],
  ]),
});
const findings = await agent.analyze({ rootPath: projectPath });
```

Verification supports ES256 (P-256) and RS256 using Node's crypto implementation
and the card's canonical JSON payload. Unsupported algorithms, malformed
signatures, missing keys, unsupported critical headers, and verification
failures remain unverified. The scanner never fetches `jku` or accepts an
embedded `jwk` as a trust anchor. A verified signature does not suppress card
poisoning, authentication, endpoint, or callback findings.

These checks make no network requests, resolve no DNS names, and do not prove
runtime exploitability. Servers must still validate resolved callback addresses
and redirects to prevent DNS rebinding. Finding output omits description text,
URL credentials, query strings, and callback authentication tokens.

Protocol reference: [A2A specification](https://a2a-protocol.org/latest/specification/).
