import Nav from '@/components/Nav';
import type { Metadata } from 'next';
import BreachChecker from './BreachChecker';
import styles from './breach.module.css';

const ogImage = 'https://shipsafecli.com/api/og?title=Vercel+April+2026+Breach+Checker&description=Check+if+your+project+was+impacted+by+the+Vercel+April+2026+AI+integration+supply+chain+attack.&label=Breach+Impact+Check&badge=CVE-2026-VERCEL';

export const metadata: Metadata = {
  title: 'Vercel April 2026 Breach — Impact Checker | Ship Safe',
  description: 'Check if your project was impacted by the Vercel April 2026 AI integration supply chain attack. Scans GitHub workflows, Vercel integration scopes, audit logs, and MCP configs.',
  keywords: [
    'Vercel April 2026 breach',
    'Vercel security incident checker',
    'AI integration supply chain attack',
    'was my Vercel project hacked',
    'Vercel token exfiltration check',
    'MCP config security scan',
    'GitHub Actions AI action pinning',
  ],
  alternates: {
    canonical: 'https://shipsafecli.com/breach/vercel-april-2026',
  },
  openGraph: {
    title: 'Vercel April 2026 Breach — Impact Checker',
    description: 'Check if your project was impacted by the Vercel April 2026 AI integration supply chain attack.',
    type: 'website',
    url: 'https://shipsafecli.com/breach/vercel-april-2026',
    siteName: 'Ship Safe',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Vercel April 2026 Breach Impact Checker' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Vercel April 2026 Breach — Impact Checker',
    description: 'Check if your project was impacted by the Vercel April 2026 AI integration supply chain attack.',
    images: [ogImage],
  },
};

export default function BreachPage() {
  return (
    <>
      <Nav />
      <main className={styles.page}>

        {/* ── Hero ── */}
        <section className={styles.hero}>
          <div className="container">
            <div className={styles.alertBadge}>
              <span className={styles.alertDot} />
              Security Advisory — April 2026
            </div>

            <h1>
              Was your project affected by the<br />
              Vercel April 2026 incident?
            </h1>

            <p className={styles.heroSub}>
              Attackers compromised a third-party AI integration and used it to silently exfiltrate
              Vercel deployment tokens across hundreds of projects. Run the four checks below to see
              if your project is exposed to the same attack patterns.
            </p>

            <div className={styles.heroPillRow}>
              <span className={styles.heroPill}>
                <strong>Incident window:</strong> Mar 28 – Apr 12, 2026
              </span>
              <span className={styles.heroPill}>
                <strong>Vector:</strong> Compromised AI integration OAuth token
              </span>
              <span className={styles.heroPill}>
                <strong>Impact:</strong> Deployment token exfiltration
              </span>
            </div>

            <p className={styles.privacyNote}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              Tokens are used for a single API request and never stored or logged. GitHub checks use only the public API.
            </p>
          </div>
        </section>

        {/* ── Checker ── */}
        <BreachChecker />

        {/* ── What the checks cover ── */}
        <section style={{ maxWidth: 820, margin: '3rem auto 0', padding: '0 1rem' }}>
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: '2.5rem' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              What each check detects
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1rem' }}>
              {[
                {
                  num: '01',
                  title: 'AI Action Pinning',
                  desc: 'Finds GitHub Actions with AI-related names (copilot, claude, openai, devin, cursor…) that are referenced by mutable tags like @v2 instead of a full 40-character commit SHA. A tag-repointing attack can silently replace any of these with a credential stealer.',
                },
                {
                  num: '02',
                  title: 'Integration Scope Audit',
                  desc: 'Lists your Vercel integrations and flags any that hold env:read, env:write, deployments:write, or secrets:read scopes. These are the scopes that gave the April 2026 attack access to deployment tokens without triggering any anomaly alerts.',
                },
                {
                  num: '03',
                  title: 'Audit Log Analysis',
                  desc: 'Pulls your Vercel audit log and looks for environment variable reads, unexpected deployments, and new token creations that occurred between March 28 and April 12 — the confirmed incident window from the Vercel security bulletin.',
                },
                {
                  num: '04',
                  title: 'Config Token Forwarding',
                  desc: 'Runs the same patterns as AgenticSupplyChainAgent on your pasted MCP or Hermes config to detect high-value credentials (VERCEL_TOKEN, GITHUB_TOKEN, API keys) being forwarded to non-localhost tool servers — a silent ongoing exfiltration channel.',
                },
              ].map(c => (
                <div key={c.num} style={{ display: 'flex', gap: '1rem' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)', flexShrink: 0, paddingTop: '2px' }}>{c.num}</span>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem', marginBottom: '0.35rem' }}>{c.title}</div>
                    <p style={{ fontSize: '0.83rem', color: 'var(--text-muted)', lineHeight: 1.65, margin: 0 }}>{c.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Source attribution ── */}
        <section style={{ maxWidth: 820, margin: '2.5rem auto 0', padding: '0 1rem' }}>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.7 }}>
            Based on the{' '}
            <a href="https://vercel.com/kb/bulletin/vercel-april-2026-security-incident" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }} target="_blank" rel="noopener noreferrer">
              Vercel April 2026 Security Bulletin
            </a>{' '}
            and{' '}
            <a href="/blog/vercel-april-2026-ai-integration-supply-chain-attack" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }}>
              our full incident analysis
            </a>.
            Detection powered by{' '}
            <a href="https://github.com/asamassekou10/ship-safe" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }} target="_blank" rel="noopener noreferrer">
              AgenticSupplyChainAgent
            </a>{' '}
            — open source, MIT licensed.
          </p>
        </section>

      </main>
    </>
  );
}
