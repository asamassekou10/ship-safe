import Nav from '@/components/Nav';
import Link from 'next/link';
import styles from './openclaw.module.css';
import ScrollAnimator from '@/components/ScrollAnimator';
import type { Metadata } from 'next';

const ogImage = 'https://shipsafecli.com/api/og?title=OpenClaw+Security+Scanner&description=Detect+ClawJacked%2C+malicious+skills%2C+missing+auth%2C+and+prompt+injection+in+your+agent+configs+in+60+seconds.&label=AI+Agent+Security&badge=CVE-2026-25253';

export const metadata: Metadata = {
  title: 'OpenClaw Security Scanner',
  description: 'Secure your OpenClaw setup in 60 seconds. Detect ClawJacked (CVE-2026-25253), malicious skills from ClawHavoc, missing auth, public bindings, and prompt injection in agent configs.',
  keywords: ['OpenClaw security', 'ClawJacked', 'CVE-2026-25253', 'ClawHavoc', 'OpenClaw audit', 'AI agent security', 'MCP security'],
  alternates: {
    canonical: 'https://shipsafecli.com/openclaw',
  },
  openGraph: {
    title: 'OpenClaw Security Scanner — Ship Safe',
    description: 'Detect ClawJacked, malicious skills, missing auth, and prompt injection in your agent configs in 60 seconds.',
    type: 'website',
    url: 'https://shipsafecli.com/openclaw',
    siteName: 'Ship Safe',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'OpenClaw Security Scanner' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'OpenClaw Security Scanner — Ship Safe',
    description: 'Detect ClawJacked, malicious skills, missing auth, and prompt injection in your agent configs in 60 seconds.',
    images: [ogImage],
  },
};

/* ── SVG Icons ─────────────────────────────────────────────────────────────── */

const icons = {
  unlock: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 9.9-1" />
    </svg>
  ),
  key: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  ),
  skull: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="12" r="1" /><circle cx="15" cy="12" r="1" /><path d="M8 20l2-2h4l2 2" /><path d="M12 2a8 8 0 0 0-8 8v1a4 4 0 0 0 2 3.46V16a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-1.54A4 4 0 0 0 20 11v-1a8 8 0 0 0-8-8z" />
    </svg>
  ),
  injection: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.5 2v6.5L18 12l-3.5 3.5V22" /><path d="M9.5 2v6.5L6 12l3.5 3.5V22" />
    </svg>
  ),
  hook: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  ),
  shield: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  terminal: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  ),
  wrench: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  ),
  scan: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  box: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /><polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" />
    </svg>
  ),
  alert: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  arrowRight: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" />
    </svg>
  ),
};

/* ── Data ──────────────────────────────────────────────────────────────────── */

const threats = [
  {
    icon: icons.unlock,
    title: 'Public Gateway Binding',
    description: 'OpenClaw bound to 0.0.0.0 exposes your agent to the entire network. ClawJacked (CVE-2026-25253, CVSS 8.8) exploits this for full agent takeover via WebSocket.',
    severity: 'critical' as const,
    rule: 'OPENCLAW_PUBLIC_BIND',
  },
  {
    icon: icons.key,
    title: 'Missing Authentication',
    description: 'No auth configured means anyone who can reach your OpenClaw instance can control your agent — execute commands, read files, exfiltrate data.',
    severity: 'critical' as const,
    rule: 'OPENCLAW_NO_AUTH',
  },
  {
    icon: icons.skull,
    title: 'Malicious Skills (ClawHavoc)',
    description: '1,184 malicious skills were uploaded to ClawHub delivering the AMOS stealer. Ship Safe checks skill hashes against known IOCs and analyzes skill code for malicious patterns.',
    severity: 'critical' as const,
    rule: 'OPENCLAW_UNTRUSTED_SKILL',
  },
  {
    icon: icons.injection,
    title: 'Prompt Injection in Config Files',
    description: 'Attackers inject "ignore previous instructions" into .cursorrules, CLAUDE.md, or agent memory files to hijack AI agents. Ship Safe detects 15+ injection patterns.',
    severity: 'critical' as const,
    rule: 'AGENT_CFG_PROMPT_OVERRIDE',
  },
  {
    icon: icons.hook,
    title: 'Malicious Claude Code Hooks',
    description: 'Check Point disclosed RCE via malicious hooks in .claude/settings.json. Ship Safe scans hooks for shell commands, piped downloads, and encoded payloads.',
    severity: 'critical' as const,
    rule: 'CLAUDE_HOOK_SHELL_CMD',
  },
  {
    icon: icons.shield,
    title: 'Unencrypted WebSocket',
    description: 'Using ws:// instead of wss:// transmits all agent communication in plaintext — credentials, code, and commands visible to anyone on the network.',
    severity: 'high' as const,
    rule: 'OPENCLAW_NO_TLS',
  },
];

const capabilities = [
  {
    icon: icons.scan,
    title: 'Scan',
    command: 'npx ship-safe openclaw .',
    description: 'Full security audit of your OpenClaw config, MCP servers, skills, and agent instruction files.',
  },
  {
    icon: icons.wrench,
    title: 'Auto-fix',
    command: 'npx ship-safe openclaw . --fix',
    description: 'Rebind to localhost, add auth, upgrade to wss://, enable safeBins. One flag.',
  },
  {
    icon: icons.terminal,
    title: 'Red Team',
    command: 'npx ship-safe openclaw . --red-team',
    description: '7 adversarial tests simulating ClawJacked, prompt injection, data exfiltration, and encoded payloads.',
  },
  {
    icon: icons.box,
    title: 'Skill Scanner',
    command: 'npx ship-safe scan-skill <url>',
    description: 'Analyze any skill before installing. Typosquatting detection, static analysis, and threat intel matching.',
  },
];

/* ── Component ─────────────────────────────────────────────────────────────── */

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
              {icons.alert}
              CVE-2026-25253 &middot; ClawJacked &middot; CVSS 8.8
            </div>
            <h1>
              Secure your <span className="gradient-text">OpenClaw</span> in 60&nbsp;seconds.
            </h1>
            <p className={styles.heroSub}>
              OpenClaw had 7 CVEs in 60 days. ClawHavoc injected 1,184 malicious skills into ClawHub.
              Ship Safe scans your agent configs, MCP servers, and skills before attackers exploit them.
            </p>
            <div className="install-box">
              <span className="install-prompt">$</span>
              <span>npx ship-safe openclaw .</span>
            </div>
          </div>
        </section>

        {/* Threats */}
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

        {/* Capabilities */}
        <section className={styles.capSection}>
          <div className="container">
            <span className="section-label">How it works</span>
            <h2>Scan. Fix. Red team. Repeat.</h2>
            <p className="section-sub">
              Four modes, one tool. No API keys. No cloud. Everything runs locally.
            </p>

            <div className={styles.capGrid}>
              {capabilities.map((c) => (
                <div key={c.title} className={`${styles.capCard} card`} data-animate>
                  <div className={styles.capHeader}>
                    <div className={styles.capIcon}>{c.icon}</div>
                    <h3>{c.title}</h3>
                  </div>
                  <p>{c.description}</p>
                  <code className={styles.capCommand}>{c.command}</code>
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
              Ship Safe rewrites your openclaw.json to close every attack vector automatically.
            </p>

            <div className={styles.compareGrid}>
              <div className={`${styles.compareCard} card`} data-animate>
                <h3>
                  <span style={{ color: 'var(--red)' }}>&#x2718;</span> Vulnerable
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
                  <span style={{ color: 'var(--green)' }}>&#x2714;</span> Hardened
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

        {/* Timeline */}
        <section className={styles.timelineSection}>
          <div className="container">
            <span className="section-label">Context</span>
            <h2>The OpenClaw security timeline</h2>

            <div className={styles.timeline}>
              <div className={styles.timelineItem} data-animate>
                <div className={styles.timelineDot} />
                <div className={styles.timelineContent}>
                  <span className={styles.timelineDate}>CVE-2026-25253 &middot; CVSS 8.8</span>
                  <h3>ClawJacked</h3>
                  <p>Full agent takeover via WebSocket. Any OpenClaw instance bound to 0.0.0.0 without auth is vulnerable. Attackers can execute commands, read files, and exfiltrate data.</p>
                </div>
              </div>

              <div className={styles.timelineItem} data-animate data-delay="80">
                <div className={styles.timelineDot} />
                <div className={styles.timelineContent}>
                  <span className={styles.timelineDate}>Campaign &middot; Jan–Mar 2026</span>
                  <h3>ClawHavoc</h3>
                  <p>1,184 malicious skills uploaded to ClawHub — roughly 20% of the registry. Skills delivered the AMOS stealer targeting macOS and Linux credential stores.</p>
                </div>
              </div>

              <div className={styles.timelineItem} data-animate data-delay="160">
                <div className={styles.timelineDot} />
                <div className={styles.timelineContent}>
                  <span className={styles.timelineDate}>Check Point Research &middot; 2026</span>
                  <h3>Claude Code Hooks RCE</h3>
                  <p>Remote code execution via malicious hooks in .claude/settings.json. Any repo with a compromised hooks config can execute arbitrary commands on the developer&apos;s machine.</p>
                </div>
              </div>

              <div className={styles.timelineItem} data-animate data-delay="240">
                <div className={styles.timelineDot} />
                <div className={styles.timelineContent}>
                  <span className={styles.timelineDate}>ASI01–ASI10 &middot; 2026</span>
                  <h3>OWASP Agentic Top 10</h3>
                  <p>OWASP released ASI01–ASI10 covering goal hijacking, tool misuse, privilege abuse, and supply chain attacks specific to AI agents.</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className={styles.ctaSection}>
          <div className="container">
            <h2>Start scanning in one command.</h2>
            <p>Free, open source, runs locally. No signup, no API keys, no data sent anywhere.</p>

            <div className={styles.ctaInstall}>
              <div className="install-box">
                <span className="install-prompt">$</span>
                <span>npx ship-safe openclaw .</span>
              </div>
            </div>

            <div className={styles.ctaActions}>
              <Link href="/signup" className="btn btn-primary">Try the web dashboard</Link>
              <a href="https://github.com/asamassekou10/ship-safe" target="_blank" rel="noopener noreferrer" className="btn btn-ghost">
                View on GitHub {icons.arrowRight}
              </a>
            </div>
          </div>
        </section>
      </main>
    </>
  );
}
