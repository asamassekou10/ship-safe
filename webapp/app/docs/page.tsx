import Nav from '@/components/Nav';
import styles from './docs.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/api/og?title=Ship+Safe+Docs&description=Every+command%2C+agent%2C+and+flag.+LLM+vulnerability+CLI%2C+MCP+security+config%2C+RAG+poisoning+detection%2C+CI%2FCD+integration%2C+and+API+reference.&label=Documentation&badge=v7.0.0';

export const metadata: Metadata = {
  title: 'Documentation',
  description: 'Complete Ship Safe documentation: LLM vulnerability CLI commands, MCP configuration security scanning, RAG poisoning detection, CI/CD integration, 19 agent reference, and API docs.',
  keywords: ['Ship Safe docs', 'LLM vulnerability CLI', 'MCP configuration security', 'RAG poisoning detection', 'AI agent security scanner', 'ship-safe commands', 'ship-safe agents', 'DevSecOps documentation', 'OWASP Agentic AI Top 10'],
  alternates: {
    canonical: 'https://www.shipsafecli.com/docs',
  },
  openGraph: {
    title: 'Ship Safe Documentation — v7.0.0',
    description: 'Every command, agent, and flag. LLM vulnerability CLI, MCP security configuration, RAG poisoning detection, CI/CD integration, and API reference.',
    url: 'https://www.shipsafecli.com/docs',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Ship Safe Documentation' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe Documentation — v7.0.0',
    description: 'Every command, agent, and flag. LLM vulnerability CLI, MCP security configuration, RAG poisoning detection, CI/CD integration, and API reference.',
    images: [ogImage],
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'TechArticle',
  headline: 'Ship Safe Documentation',
  description: 'Complete documentation for Ship Safe CLI security scanner.',
  url: 'https://www.shipsafecli.com/docs',
  author: { '@type': 'Organization', name: 'Ship Safe', url: 'https://www.shipsafecli.com' },
};

export default function Docs() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} // ship-safe-ignore — static JSON-LD, no user input
      />
      <Nav />
      <main className={styles.docsPage}>
        <div className={styles.layout}>
          <aside className={styles.sidebar}>
            <nav className={styles.tocNav}>
              <h3>Documentation</h3>
              <a href="#installation">Installation</a>
              <a href="#quick-start">Quick Start</a>
              <a href="#commands">Commands</a>
              <a href="#agents">19 Security Agents</a>
              <a href="#scoring">Scoring System</a>
              <a href="#cicd">CI/CD Integration</a>
              <a href="#github-action">GitHub Action</a>
              <a href="#llm">Multi-LLM Support</a>
              <a href="#scanning">Incremental Scanning</a>
              <a href="#suppression">Suppressing Findings</a>
              <a href="#policy">Policy-as-Code</a>
              <a href="#owasp">OWASP Coverage</a>
              <a href="#openclaw">OpenClaw Security</a>
              <a href="#claude-code">Claude Code Plugin</a>
              <a href="#config">Configuration Files</a>
              <a href="#supply-chain">Supply Chain Hardening</a>
            </nav>
          </aside>

          <article className={styles.content}>
            <header className={styles.header}>
              <span className="section-label">Documentation</span>
              <h1>Ship Safe CLI</h1>
              <p className={styles.subtitle}>
                19 AI security agents. 80+ attack classes. One command.
              </p>
              <pre className={styles.heroCode}><code>npx ship-safe audit .</code></pre>
            </header>

            {/* ── Installation ──────────────────────────────────────── */}
            <section id="installation">
              <h2>Installation</h2>
              <p>Ship Safe requires Node.js 18 or later. No signup or API key required.</p>
              <pre><code>{`# Run directly (no install)
npx ship-safe audit .

# Or install globally
npm install -g ship-safe
ship-safe audit .`}</code></pre>
              <p>For AI-powered deep analysis, set one of these environment variables (optional):</p>
              <pre><code>{`export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export GOOGLE_AI_API_KEY=AIza...`}</code></pre>
            </section>

            {/* ── Quick Start ───────────────────────────────────────── */}
            <section id="quick-start">
              <h2>Quick Start</h2>
              <pre><code>{`# Full security audit with remediation plan + HTML report
npx ship-safe audit .

# Red team: 18 agents, 80+ attack classes
npx ship-safe red-team .

# Quick secret scan
npx ship-safe scan .

# Security health score (0-100, A-F)
npx ship-safe score .

# Fun emoji security grade
npx ship-safe vibe-check .

# Scan only changed files (fast pre-commit)
npx ship-safe diff --staged

# CI/CD mode with threshold gating
npx ship-safe ci . --threshold 80`}</code></pre>
            </section>

            {/* ── Commands ──────────────────────────────────────────── */}
            <section id="commands">
              <h2>Commands</h2>

              <h3>Core Audit</h3>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Command</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>audit .</code></td><td>Full audit: secrets + 18 agents + deps + remediation plan + HTML report</td></tr>
                    <tr><td><code>red-team .</code></td><td>Run 18 agents with 80+ attack classes</td></tr>
                    <tr><td><code>scan .</code></td><td>Secret scanner (pattern matching + entropy scoring)</td></tr>
                    <tr><td><code>score .</code></td><td>Security health score (0-100, A-F grade)</td></tr>
                    <tr><td><code>deps .</code></td><td>Dependency CVE audit with EPSS scores</td></tr>
                    <tr><td><code>diff</code></td><td>Scan only changed files (supports <code>--staged</code>)</td></tr>
                  </tbody>
                </table>
              </div>

              <h3>AI-Powered</h3>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Command</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>hooks install</code></td><td>Install real-time Claude Code hooks — block secrets before they land on disk</td></tr>
                    <tr><td><code>hooks status</code></td><td>Check if Claude Code hooks are installed</td></tr>
                    <tr><td><code>hooks remove</code></td><td>Uninstall Claude Code hooks</td></tr>
                    <tr><td><code>agent .</code></td><td>AI audit: scan + classify with LLM + auto-fix</td></tr>
                    <tr><td><code>remediate .</code></td><td>Auto-fix hardcoded secrets (rewrite code + write .env)</td></tr>
                    <tr><td><code>rotate .</code></td><td>Open provider dashboards to revoke exposed keys</td></tr>
                    <tr><td><code>audit . --deep</code></td><td>LLM-powered taint analysis for critical/high findings</td></tr>
                    <tr><td><code>audit . --verify</code></td><td>Probe provider APIs to check if leaked secrets are active</td></tr>
                  </tbody>
                </table>
              </div>

              <h3>CI/CD &amp; Baseline</h3>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Command</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>ci .</code></td><td>Pipeline mode: compact output, exit codes, threshold gating</td></tr>
                    <tr><td><code>baseline .</code></td><td>Accept current findings, only report regressions</td></tr>
                    <tr><td><code>vibe-check .</code></td><td>Fun emoji security grade with shareable badge</td></tr>
                    <tr><td><code>benchmark .</code></td><td>Compare score against industry averages</td></tr>
                    <tr><td><code>watch .</code></td><td>Continuous monitoring (watch files for changes)</td></tr>
                  </tbody>
                </table>
              </div>

              <h3>Infrastructure</h3>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Command</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>init</code></td><td>Initialize security configs (.gitignore, headers)</td></tr>
                    <tr><td><code>doctor</code></td><td>Environment diagnostics</td></tr>
                    <tr><td><code>sbom .</code></td><td>Generate CycloneDX SBOM (CRA-ready)</td></tr>
                    <tr><td><code>abom .</code></td><td>Agent Bill of Materials (CycloneDX 1.5)</td></tr>
                    <tr><td><code>policy init</code></td><td>Create policy-as-code config</td></tr>
                    <tr><td><code>guard</code></td><td>Block git push if secrets found</td></tr>
                    <tr><td><code>checklist</code></td><td>Launch-day security checklist</td></tr>
                    <tr><td><code>update-intel</code></td><td>Update threat intelligence feed</td></tr>
                  </tbody>
                </table>
              </div>

              <h3>Flags</h3>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Flag</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>--json</code></td><td>Structured JSON output</td></tr>
                    <tr><td><code>--sarif</code></td><td>SARIF format for GitHub Code Scanning</td></tr>
                    <tr><td><code>--csv</code></td><td>CSV export</td></tr>
                    <tr><td><code>--md</code></td><td>Markdown report</td></tr>
                    <tr><td><code>--html [file]</code></td><td>Custom HTML report path</td></tr>
                    <tr><td><code>--pdf [file]</code></td><td>PDF report (requires Chrome/Chromium)</td></tr>
                    <tr><td><code>--deep</code></td><td>LLM-powered taint analysis</td></tr>
                    <tr><td><code>--local</code></td><td>Use local Ollama for deep analysis</td></tr>
                    <tr><td><code>--model &lt;model&gt;</code></td><td>Specify LLM model</td></tr>
                    <tr><td><code>--provider &lt;name&gt;</code></td><td>LLM provider: groq, together, mistral, deepseek, xai, perplexity, lmstudio</td></tr>
                    <tr><td><code>--base-url &lt;url&gt;</code></td><td>Custom OpenAI-compatible base URL (e.g. LM Studio, vLLM)</td></tr>
                    <tr><td><code>--budget &lt;cents&gt;</code></td><td>Cap LLM spend (default: 50 cents)</td></tr>
                    <tr><td><code>--verify</code></td><td>Check if leaked secrets are still active</td></tr>
                    <tr><td><code>--baseline</code></td><td>Only show findings not in baseline</td></tr>
                    <tr><td><code>--compare</code></td><td>Show score delta vs. last scan</td></tr>
                    <tr><td><code>--timeout &lt;ms&gt;</code></td><td>Per-agent timeout (default: 30s)</td></tr>
                    <tr><td><code>--no-deps</code></td><td>Skip dependency audit</td></tr>
                    <tr><td><code>--no-ai</code></td><td>Skip AI classification</td></tr>
                    <tr><td><code>--no-cache</code></td><td>Force full rescan</td></tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* ── Agents ────────────────────────────────────────────── */}
            <section id="agents">
              <h2>19 Security Agents</h2>
              <p>All agents run in parallel with per-agent timeouts. Each implements <code>shouldRun(recon)</code> to skip irrelevant projects automatically.</p>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Agent</th><th>Category</th><th>What It Detects</th></tr></thead>
                  <tbody>
                    <tr><td><strong>InjectionTester</strong></td><td>Code Vulns</td><td>SQL/NoSQL injection, command injection, XSS, path traversal, XXE, ReDoS, prototype pollution</td></tr>
                    <tr><td><strong>AuthBypassAgent</strong></td><td>Auth</td><td>JWT flaws (alg:none, weak secrets), cookie security, CSRF, OAuth misconfig, BOLA/IDOR, TLS bypass</td></tr>
                    <tr><td><strong>SSRFProber</strong></td><td>SSRF</td><td>User input in fetch/axios, cloud metadata endpoints, internal IPs, redirect following</td></tr>
                    <tr><td><strong>SupplyChainAudit</strong></td><td>Supply Chain</td><td>Typosquatting, git/URL deps, wildcard versions, suspicious install scripts, dependency confusion</td></tr>
                    <tr><td><strong>ConfigAuditor</strong></td><td>Config</td><td>Docker (root user, :latest), Terraform, Kubernetes, CORS, CSP, Firebase, Nginx</td></tr>
                    <tr><td><strong>SupabaseRLSAgent</strong></td><td>Auth</td><td>Row Level Security issues, service_role key exposure, anon key inserts</td></tr>
                    <tr><td><strong>LLMRedTeam</strong></td><td>AI/LLM</td><td>OWASP LLM Top 10: prompt injection, excessive agency, system prompt leakage</td></tr>
                    <tr><td><strong>MCPSecurityAgent</strong></td><td>AI/LLM</td><td>MCP server misuse, tool poisoning, typosquatting, unvalidated inputs</td></tr>
                    <tr><td><strong>AgenticSecurityAgent</strong></td><td>AI/LLM</td><td>OWASP Agentic AI Top 10: agent hijacking, privilege escalation, memory poisoning</td></tr>
                    <tr><td><strong>RAGSecurityAgent</strong></td><td>AI/LLM</td><td>RAG pipeline security: context injection, document poisoning, vector DB access</td></tr>
                    <tr><td><strong>PIIComplianceAgent</strong></td><td>Compliance</td><td>PII detection: SSNs, credit cards, emails, phone numbers in source code</td></tr>
                    <tr><td><strong>VibeCodingAgent</strong></td><td>Code Vulns</td><td>AI-generated code anti-patterns: no validation, empty catches, TODO-auth</td></tr>
                    <tr><td><strong>ExceptionHandlerAgent</strong></td><td>Code Vulns</td><td>OWASP A10:2025: empty catches, unhandled rejections, leaked stack traces</td></tr>
                    <tr><td><strong>AgentConfigScanner</strong></td><td>AI/LLM</td><td>Prompt injection in .cursorrules, CLAUDE.md, malicious hooks, OpenClaw security</td></tr>
                    <tr><td><strong>MobileScanner</strong></td><td>Mobile</td><td>OWASP Mobile Top 10 2024: insecure storage, WebView injection, debug mode</td></tr>
                    <tr><td><strong>GitHistoryScanner</strong></td><td>Secrets</td><td>Leaked secrets in git commit history</td></tr>
                    <tr><td><strong>CICDScanner</strong></td><td>CI/CD</td><td>OWASP CI/CD Top 10: pipeline poisoning, unpinned actions, secret logging</td></tr>
                    <tr><td><strong>APIFuzzer</strong></td><td>API</td><td>Routes without auth, mass assignment, GraphQL introspection, debug endpoints</td></tr>
                  </tbody>
                </table>
              </div>
              <p><strong>Post-processors:</strong> ScoringEngine (8-category weighted scoring), VerifierAgent (secrets liveness verification), DeepAnalyzer (LLM-powered taint analysis)</p>
            </section>

            {/* ── Scoring ───────────────────────────────────────────── */}
            <section id="scoring">
              <h2>Scoring System</h2>
              <p>Starts at 100. Each finding deducts points by severity and category, weighted by confidence level (high: 100%, medium: 60%, low: 30%).</p>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Category</th><th>Weight</th><th>Critical</th><th>High</th><th>Medium</th><th>Cap</th></tr></thead>
                  <tbody>
                    <tr><td>Secrets</td><td>15%</td><td>-25</td><td>-15</td><td>-5</td><td>-15</td></tr>
                    <tr><td>Code Vulnerabilities</td><td>15%</td><td>-20</td><td>-10</td><td>-3</td><td>-15</td></tr>
                    <tr><td>Dependencies</td><td>13%</td><td>-20</td><td>-10</td><td>-5</td><td>-13</td></tr>
                    <tr><td>Auth &amp; Access Control</td><td>15%</td><td>-20</td><td>-10</td><td>-3</td><td>-15</td></tr>
                    <tr><td>Configuration</td><td>8%</td><td>-15</td><td>-8</td><td>-3</td><td>-8</td></tr>
                    <tr><td>Supply Chain</td><td>12%</td><td>-15</td><td>-8</td><td>-3</td><td>-12</td></tr>
                    <tr><td>API Security</td><td>10%</td><td>-15</td><td>-8</td><td>-3</td><td>-10</td></tr>
                    <tr><td>AI/LLM Security</td><td>12%</td><td>-15</td><td>-8</td><td>-3</td><td>-12</td></tr>
                  </tbody>
                </table>
              </div>
              <p><strong>Grades:</strong> A (90-100), B (75-89), C (60-74), D (40-59), F (0-39)</p>
              <p><strong>Exit codes:</strong> <code>0</code> for A/B (&gt;= 75), <code>1</code> for C/D/F. Use in CI to fail builds.</p>
            </section>

            {/* ── CI/CD ─────────────────────────────────────────────── */}
            <section id="cicd">
              <h2>CI/CD Integration</h2>
              <pre><code>{`# Basic CI: fail if score < 75
npx ship-safe ci .

# Strict: fail on any critical finding
npx ship-safe ci . --fail-on critical

# Custom threshold + SARIF for GitHub Security tab
npx ship-safe ci . --threshold 80 --sarif results.sarif

# Post results as PR comment
npx ship-safe ci . --github-pr

# Only report new findings (not in baseline)
npx ship-safe ci . --baseline`}</code></pre>
              <p>Export formats: <code>--json</code>, <code>--sarif</code>, <code>--csv</code>, <code>--md</code>, <code>--html</code>, <code>--pdf</code></p>
            </section>

            {/* ── GitHub Action ──────────────────────────────────────── */}
            <section id="github-action">
              <h2>GitHub Action</h2>
              <pre><code>{`# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: asamassekou10/ship-safe@v6
        with:
          path: .
          threshold: 75
          sarif: true
          comment: true

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: /tmp/ship-safe-results.sarif`}</code></pre>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Input</th><th>Default</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>path</code></td><td><code>.</code></td><td>Path to scan</td></tr>
                    <tr><td><code>threshold</code></td><td><code>75</code></td><td>Minimum passing score (0-100)</td></tr>
                    <tr><td><code>fail-on</code></td><td></td><td>Fail on severity: critical, high, medium, low</td></tr>
                    <tr><td><code>sarif</code></td><td><code>true</code></td><td>Generate SARIF for Code Scanning</td></tr>
                    <tr><td><code>deep</code></td><td><code>false</code></td><td>Enable LLM deep analysis</td></tr>
                    <tr><td><code>deps</code></td><td><code>true</code></td><td>Audit dependency CVEs</td></tr>
                    <tr><td><code>baseline</code></td><td><code>false</code></td><td>Only report new findings</td></tr>
                    <tr><td><code>comment</code></td><td><code>true</code></td><td>Post PR comment with results</td></tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* ── LLM ───────────────────────────────────────────────── */}
            <section id="llm">
              <h2>Multi-LLM Support</h2>
              <p>AI classification is optional. All core commands work fully offline. Use <code>--provider &lt;name&gt;</code> or set the matching environment variable.</p>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Provider</th><th>Env Variable</th><th>Flag</th><th>Default Model</th></tr></thead>
                  <tbody>
                    <tr><td>Anthropic</td><td><code>ANTHROPIC_API_KEY</code></td><td><em>auto-detected</em></td><td>claude-haiku-4-5</td></tr>
                    <tr><td>OpenAI</td><td><code>OPENAI_API_KEY</code></td><td><em>auto-detected</em></td><td>gpt-4o-mini</td></tr>
                    <tr><td>Google</td><td><code>GOOGLE_AI_API_KEY</code></td><td><em>auto-detected</em></td><td>gemini-2.0-flash</td></tr>
                    <tr><td>Ollama</td><td><code>OLLAMA_HOST</code></td><td><code>--local</code></td><td>Local models</td></tr>
                    <tr><td>Groq</td><td><code>GROQ_API_KEY</code></td><td><code>--provider groq</code></td><td>llama-3.3-70b-versatile</td></tr>
                    <tr><td>Together AI</td><td><code>TOGETHER_API_KEY</code></td><td><code>--provider together</code></td><td>Llama-3-70b-chat-hf</td></tr>
                    <tr><td>Mistral</td><td><code>MISTRAL_API_KEY</code></td><td><code>--provider mistral</code></td><td>mistral-small-latest</td></tr>
                    <tr><td>DeepSeek</td><td><code>DEEPSEEK_API_KEY</code></td><td><code>--provider deepseek</code></td><td>deepseek-chat</td></tr>
                    <tr><td>xAI (Grok)</td><td><code>XAI_API_KEY</code></td><td><code>--provider xai</code></td><td>grok-beta</td></tr>
                    <tr><td>Perplexity</td><td><code>PERPLEXITY_API_KEY</code></td><td><code>--provider perplexity</code></td><td>llama-3.1-sonar-small-128k-online</td></tr>
                    <tr><td>LM Studio</td><td><em>none</em></td><td><code>--provider lmstudio</code></td><td>Local server</td></tr>
                    <tr><td>Custom</td><td><em>any</em></td><td><code>--base-url &lt;url&gt; --model &lt;model&gt;</code></td><td>Any OpenAI-compatible</td></tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* ── Incremental Scanning ──────────────────────────────── */}
            <section id="scanning">
              <h2>Incremental Scanning</h2>
              <p>Ship Safe caches file hashes and findings in <code>.ship-safe/context.json</code>. Only changed files are re-scanned on subsequent runs.</p>
              <ul>
                <li>~40% faster on repeated scans</li>
                <li>Auto-invalidation after 24 hours or when ship-safe updates</li>
                <li><code>--no-cache</code> to force a full rescan</li>
              </ul>
              <p>LLM responses are cached in <code>.ship-safe/llm-cache.json</code> with a 7-day TTL to reduce API costs.</p>
            </section>

            {/* ── Suppression ───────────────────────────────────────── */}
            <section id="suppression">
              <h2>Suppressing Findings</h2>
              <p><strong>Inline:</strong> Add <code># ship-safe-ignore</code> on any line:</p>
              <pre><code>{`password = get_password()  # ship-safe-ignore`}</code></pre>
              <p><strong>File-level:</strong> Create <code>.ship-safeignore</code> (gitignore syntax):</p>
              <pre><code>{`# Exclude test fixtures
tests/fixtures/
*.test.js

# Exclude documentation
docs/`}</code></pre>
            </section>

            {/* ── Policy ────────────────────────────────────────────── */}
            <section id="policy">
              <h2>Policy-as-Code</h2>
              <pre><code>{`npx ship-safe policy init`}</code></pre>
              <p>Creates <code>.ship-safe.policy.json</code>:</p>
              <pre><code>{`{
  "minimumScore": 70,
  "failOn": "critical",
  "requiredScans": ["secrets", "injection", "deps", "auth"],
  "ignoreRules": [],
  "maxAge": { "criticalCVE": "7d", "highCVE": "30d", "mediumCVE": "90d" }
}`}</code></pre>
            </section>

            {/* ── OWASP ─────────────────────────────────────────────── */}
            <section id="owasp">
              <h2>OWASP Coverage</h2>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Standard</th><th>Coverage</th></tr></thead>
                  <tbody>
                    <tr><td><strong>OWASP Top 10 Web 2025</strong></td><td>A01-A10: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Data Integrity, Logging Failures, SSRF</td></tr>
                    <tr><td><strong>OWASP Mobile 2024</strong></td><td>M1-M10: Improper Credentials, Supply Chain, Insecure Auth, Insufficient Validation, Insecure Communication, Privacy, Binary Protections, Misconfiguration, Insecure Storage, Insufficient Crypto</td></tr>
                    <tr><td><strong>OWASP LLM 2025</strong></td><td>LLM01-LLM10: Prompt Injection, Sensitive Disclosure, Supply Chain, Data Poisoning, Output Handling, Excessive Agency, System Prompt Leakage, Vector Weaknesses, Misinformation, Unbounded Consumption</td></tr>
                    <tr><td><strong>OWASP CI/CD Top 10</strong></td><td>CICD-SEC-1 to 10: Flow Control, Identity Management, Dependency Chain, Pipeline Poisoning, PBAC, Credential Hygiene, System Config, Ungoverned Usage, Artifact Integrity, Logging</td></tr>
                    <tr><td><strong>OWASP Agentic AI</strong></td><td>ASI01-ASI10: Agent Hijacking, Tool Misuse, Privilege Escalation, Unsafe Execution, Memory Poisoning, Identity Spoofing, Excessive Autonomy, Logging Gaps, Supply Chain, Cascading Hallucination</td></tr>
                  </tbody>
                </table>
              </div>
              <p>Compliance mapping to SOC 2 Type II, ISO 27001:2022, and NIST AI RMF is included in audit reports.</p>
            </section>

            {/* ── OpenClaw ──────────────────────────────────────────── */}
            <section id="openclaw">
              <h2>OpenClaw Security</h2>
              <pre><code>{`# Focused OpenClaw security scan
npx ship-safe openclaw .

# Auto-harden configs (0.0.0.0->127.0.0.1, add auth, ws->wss)
npx ship-safe openclaw . --fix

# Red team: simulate ClawJacked, prompt injection, data exfil
npx ship-safe openclaw . --red-team

# CI preflight
npx ship-safe openclaw . --preflight

# Scan a skill before installing
npx ship-safe scan-skill https://clawhub.io/skills/some-skill

# Generate Agent Bill of Materials
npx ship-safe abom .

# Update threat intelligence (ClawHavoc IOCs, malicious skills)
npx ship-safe update-intel`}</code></pre>

              <h3>OpenClaw GitHub Action</h3>
              <p>Drop-in CI action that blocks PRs introducing agent config vulnerabilities:</p>
              <pre><code>{`# .github/workflows/openclaw-security.yml
name: OpenClaw Security Check
on: [pull_request]
permissions:
  contents: read
jobs:
  openclaw:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: asamassekou10/ship-safe/.github/actions/openclaw-check@main
        with:
          fail-on-critical: 'true'`}</code></pre>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Input</th><th>Default</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>path</code></td><td><code>.</code></td><td>Path to scan</td></tr>
                    <tr><td><code>fail-on-critical</code></td><td><code>true</code></td><td>Fail the check if critical findings are found</td></tr>
                    <tr><td><code>node-version</code></td><td><code>20</code></td><td>Node.js version to use</td></tr>
                  </tbody>
                </table>
              </div>
              <p>Scans <code>openclaw.json</code>, <code>.cursorrules</code>, <code>CLAUDE.md</code>, Claude Code hooks, and MCP configs. Checks against the bundled threat intelligence database for known ClawHavoc IOCs.</p>
            </section>

            {/* ── Claude Code ───────────────────────────────────────── */}
            <section id="claude-code">
              <h2>Claude Code Plugin</h2>
              <pre><code>{`claude plugin add github:asamassekou10/ship-safe`}</code></pre>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>Command</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td><code>/ship-safe</code></td><td>Full security audit with remediation plan</td></tr>
                    <tr><td><code>/ship-safe-scan</code></td><td>Quick scan for leaked secrets</td></tr>
                    <tr><td><code>/ship-safe-score</code></td><td>Security health score (0-100)</td></tr>
                    <tr><td><code>/ship-safe-deep</code></td><td>LLM-powered deep taint analysis</td></tr>
                    <tr><td><code>/ship-safe-ci</code></td><td>CI/CD pipeline setup guide</td></tr>
                  </tbody>
                </table>
              </div>
            </section>

            {/* ── Config Files ──────────────────────────────────────── */}
            <section id="config">
              <h2>Configuration Files</h2>
              <div className={styles.tableWrap}>
                <table>
                  <thead><tr><th>File</th><th>Purpose</th></tr></thead>
                  <tbody>
                    <tr><td><code>.ship-safeignore</code></td><td>Exclude paths from scanning (gitignore syntax)</td></tr>
                    <tr><td><code>.ship-safe.policy.json</code></td><td>Policy-as-code: minimum score, fail-on severity, required scans</td></tr>
                    <tr><td><code>.ship-safe/context.json</code></td><td>Incremental scan cache (auto-generated)</td></tr>
                    <tr><td><code>.ship-safe/history.json</code></td><td>Score history for trend tracking</td></tr>
                    <tr><td><code>.ship-safe/baseline.json</code></td><td>Accepted findings baseline</td></tr>
                    <tr><td><code>.ship-safe/llm-cache.json</code></td><td>LLM response cache (7-day TTL)</td></tr>
                  </tbody>
                </table>
              </div>
              <p>The <code>.ship-safe/</code> directory is automatically excluded from scans and should be added to <code>.gitignore</code>.</p>
            </section>

            {/* ── Supply Chain ──────────────────────────────────────── */}
            <section id="supply-chain">
              <h2>Supply Chain Hardening</h2>
              <p>Ship Safe practices what it preaches. Our own supply chain is hardened against the <a href="/blog/supply-chain-attacks-2026-how-we-hardened-ship-safe">2026 Trivy/CanisterWorm attack chain</a>:</p>
              <ul>
                <li>All GitHub Actions pinned to full commit SHAs</li>
                <li>CI token scoped to <code>contents: read</code></li>
                <li><code>npm ci --ignore-scripts</code> in all pipelines</li>
                <li>OIDC trusted publishing with provenance attestation</li>
                <li>CODEOWNERS on supply-chain-critical files</li>
                <li>Strict <code>files</code> allowlist in package.json</li>
                <li>Self-scanning with ship-safe in CI</li>
                <li>5 direct dependencies (minimal attack surface)</li>
              </ul>
            </section>
          </article>
        </div>
      </main>
    </>
  );
}
