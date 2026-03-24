import Nav from '@/components/Nav';
import Link from 'next/link';
import styles from './openclaw.module.css';
import ScrollAnimator from '@/components/ScrollAnimator';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'OpenClaw Security Scanner — Ship Safe',
  description: 'Secure your OpenClaw setup in 60 seconds. Detect ClawJacked (CVE-2026-25253), malicious skills from ClawHavoc, missing auth, public bindings, and prompt injection in agent configs.',
  keywords: ['OpenClaw security', 'ClawJacked', 'CVE-2026-25253', 'ClawHavoc', 'OpenClaw audit', 'AI agent security', 'MCP security'],
};

const threats = [
  {
    icon: '🔓',
    title: 'Public Gateway Binding',
    description: 'OpenClaw bound to 0.0.0.0 exposes your agent to the entire network. ClawJacked (CVE-2026-25253, CVSS 8.8) exploits this for full agent takeover via WebSocket.',
    severity: 'critical',
    rule: 'OPENCLAW_PUBLIC_BIND',
  },
  {
    icon: '🔑',
    title: 'Missing Authentication',
    description: 'No auth configured means anyone who can reach your OpenClaw instance can control your agent — execute commands, read files, exfiltrate data.',
    severity: 'critical',
    rule: 'OPENCLAW_NO_AUTH',
  },
  {
    icon: '☠️',
    title: 'Malicious Skills (ClawHavoc)',
    description: '1,184 malicious skills were uploaded to ClawHub delivering the AMOS stealer. Ship-safe checks skill hashes against known IOCs and analyzes skill code for malicious patterns.',
    severity: 'critical',
    rule: 'OPENCLAW_UNTRUSTED_SKILL',
  },
  {
    icon: '💉',
    title: 'Prompt Injection in Config Files',
    description: 'Attackers inject "ignore previous instructions" into .cursorrules, CLAUDE.md, or agent memory files to hijack AI agents. Ship-safe detects 15+ injection patterns.',
    severity: 'critical',
    rule: 'AGENT_CFG_PROMPT_OVERRIDE',
  },
  {
    icon: '🪝',
    title: 'Malicious Claude Code Hooks',
    description: 'Check Point disclosed RCE via malicious hooks in .claude/settings.json. Ship-safe scans hooks for shell commands, piped downloads, and encoded payloads.',
    severity: 'critical',
    rule: 'CLAUDE_HOOK_SHELL_CMD',
  },
  {
    icon: '🔒',
    title: 'Unencrypted WebSocket (No TLS)',
    description: 'Using ws:// instead of wss:// transmits all agent communication in plaintext — credentials, code, and commands visible to anyone on the network.',
    severity: 'high',
    rule: 'OPENCLAW_NO_TLS',
  },
];

export default function OpenClaw() {
  return (
    <>
      <ScrollAnimator />
      <Nav />
      <main>
        {/* Hero */}
        <section className={styles.hero}>
          <div className="container">
            <div className={styles.cveCallout}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
              CVE-2026-25253 · ClawJacked · CVSS 8.8
            </div>
            <h1>Secure your <span className="gradient-text">OpenClaw</span> in 60 seconds.</h1>
            <p className={styles.heroSub}>
              OpenClaw had 7 CVEs in 60 days. ClawHavoc injected 1,184 malicious skills into ClawHub.
              Ship-safe scans your agent configs, MCP servers, and skills before attackers exploit them.
            </p>
            <div className="install-box">
              <span className="install-prompt">$</span>
              <span>npx ship-safe openclaw .</span>
            </div>
          </div>
        </section>

        {/* What we detect */}
        <section className={styles.threatsSection}>
          <div className="container">
            <span className="section-label">What we detect</span>
            <h2>6 critical attack vectors. One command.</h2>
            <p className="section-sub">
              Every check maps to a real CVE, OWASP Agentic Top 10 control, or active campaign.
            </p>

            <div className={styles.threatsGrid}>
              {threats.map((t) => (
                <div key={t.rule} className={`${styles.threatCard} card`} data-animate>
                  <div className={styles.threatIcon}>{t.icon}</div>
                  <span className={styles.sevBadge} data-sev={t.severity}>{t.severity}</span>
                  <h3>{t.title}</h3>
                  <p>{t.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <hr className="section-divider" />

        {/* Before/After */}
        <section className={styles.compareSection}>
          <div className="container">
            <span className="section-label">Auto-fix</span>
            <h2>Harden with <code className="mono">--fix</code></h2>
            <p className="section-sub">
              Ship-safe rewrites your openclaw.json to close every attack vector automatically.
            </p>

            <div className={styles.compareGrid}>
              <div className={`${styles.compareCard} card`} data-animate>
                <h3>
                  <span style={{ color: 'var(--red)' }}>✘</span> Vulnerable
                </h3>
                <pre>
{`{
`}<span className={styles.badLine}>{`  "host": "0.0.0.0",`}</span>{`
  "port": 3100,
`}<span className={styles.badLine}>{`  "url": "ws://my-server:3100",`}</span>{`
  "skills": [
    { "name": "unknown-skill" }
  ]
}`}
                </pre>
              </div>

              <div className={`${styles.compareCard} card`} data-animate data-delay="80">
                <h3>
                  <span style={{ color: 'var(--green)' }}>✔</span> Hardened
                </h3>
                <pre>
{`{
`}<span className={styles.goodLine}>{`  "host": "127.0.0.1",`}</span>{`
  "port": 3100,
`}<span className={styles.goodLine}>{`  "auth": { "type": "apiKey" },`}</span>{`
`}<span className={styles.goodLine}>{`  "url": "wss://my-server:3100",`}</span>{`
`}<span className={styles.goodLine}>{`  "safeBins": ["node", "git"],`}</span>{`
  "skills": []
}`}
                </pre>
              </div>
            </div>
          </div>
        </section>

        {/* Context: CVEs */}
        <section className={styles.contextSection}>
          <div className="container">
            <span className="section-label">Why this matters</span>
            <h2>The OpenClaw security timeline</h2>

            <div className={styles.contextGrid}>
              <div className={styles.contextCard} data-animate>
                <h3>ClawJacked</h3>
                <p>Full agent takeover via WebSocket. Any OpenClaw instance bound to 0.0.0.0 without auth is vulnerable. Attackers can execute commands, read files, and exfiltrate data.</p>
                <span className={styles.cveBadge}>CVE-2026-25253 · CVSS 8.8</span>
              </div>

              <div className={styles.contextCard} data-animate data-delay="80">
                <h3>ClawHavoc</h3>
                <p>1,184 malicious skills uploaded to ClawHub — roughly 20% of the registry. Skills delivered the AMOS stealer targeting macOS and Linux credential stores.</p>
                <span className={styles.cveBadge}>Campaign · Jan–Mar 2026</span>
              </div>

              <div className={styles.contextCard} data-animate data-delay="160">
                <h3>Claude Code Hooks RCE</h3>
                <p>Check Point disclosed remote code execution via malicious hooks in .claude/settings.json. Any repo with a compromised hooks config can execute arbitrary commands.</p>
                <span className={styles.cveBadge}>Check Point Research · 2026</span>
              </div>

              <div className={styles.contextCard} data-animate data-delay="240">
                <h3>OWASP Agentic Top 10</h3>
                <p>OWASP released ASI01–ASI10 covering goal hijacking, tool misuse, privilege abuse, and supply chain attacks specific to AI agents.</p>
                <span className={styles.cveBadge}>ASI01–ASI10 · 2026</span>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className={styles.ctaSection}>
          <div className="container">
            <h2>Start scanning in one command.</h2>
            <p>Free, open source, runs locally. No signup, no API keys, no data sent anywhere.</p>

            <div className={styles.ctaActions}>
              <div className="install-box">
                <span className="install-prompt">$</span>
                <span>npx ship-safe openclaw .</span>
              </div>
            </div>

            <div className={styles.ctaActions} style={{ marginTop: '1.5rem' }}>
              <Link href="/signup" className="btn btn-primary">Try the web dashboard</Link>
              <a href="https://github.com/asamassekou10/ship-safe" target="_blank" rel="noopener noreferrer" className="btn btn-ghost">View on GitHub</a>
            </div>
          </div>
        </section>
      </main>
    </>
  );
}
