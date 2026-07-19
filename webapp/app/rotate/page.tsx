import Nav from '@/components/Nav';
import type { Metadata } from 'next';
import RotateWizard from './RotateWizard';
import styles from './rotate.module.css';

const ogImage = 'https://www.shipsafecli.com/og1.png';

export const metadata: Metadata = {
  title: 'Credential Rotation Wizard — Ship Safe',
  description: 'After a breach, rotate credentials across all your Vercel projects in minutes. Discovers high-value env vars by name (never values), groups by issuer, and generates a rotation plan.',
  keywords: [
    'credential rotation',
    'Vercel env var rotation',
    'rotate API keys after breach',
    'bulk credential rotation',
    'Vercel security tools',
    'rotate secrets across projects',
  ],
  alternates: {
    canonical: 'https://www.shipsafecli.com/rotate',
  },
  openGraph: {
    title: 'Credential Rotation Wizard — Ship Safe',
    description: 'Rotate credentials across all your Vercel projects after a breach. Discovers env var names, groups by issuer, generates a rotation plan.',
    type: 'website',
    url: 'https://www.shipsafecli.com/rotate',
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Credential Rotation Wizard' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Credential Rotation Wizard — Ship Safe',
    description: 'Rotate credentials across all your Vercel projects after a breach. Discovers env var names, groups by issuer, generates a rotation plan.',
    images: [ogImage],
  },
};

export default function RotatePage() {
  return (
    <>
      <Nav />
      <main className={styles.page}>

        {/* ── Hero ── */}
        <section className={styles.hero}>
          <div className="container">
            <div className={styles.badge}>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <polyline points="1 4 1 10 7 10" />
                <path d="M3.51 15a9 9 0 1 0 .49-3.51" />
              </svg>
              Credential Rotation
            </div>

            <h1>
              Rotate credentials across<br />
              all your Vercel projects — fast.
            </h1>

            <p className={styles.heroSub}>
              After a breach, finding and updating credentials across dozens of projects takes hours.
              Ship Safe scans every project, groups by issuer, and generates a rotation plan you can
              execute in one CLI command.
            </p>

            <div className={styles.heroPillRow}>
              <span className={styles.heroPill}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                Env var values never leave your browser
              </span>
              <span className={styles.heroPill}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                Names and IDs only
              </span>
              <span className={styles.heroPill}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                </svg>
                25+ credential types
              </span>
            </div>
          </div>
        </section>

        {/* ── Wizard ── */}
        <RotateWizard />

        {/* ── How it works ── */}
        <section className={styles.howSection}>
          <div className={styles.howInner}>
            <h2>How it works</h2>
            <div className={styles.howGrid}>
              {[
                {
                  n: '01',
                  title: 'Scan without reading values',
                  desc: 'We call the Vercel API to list env var names and IDs across all your projects. Values are never fetched, never transmitted to our servers.',
                },
                {
                  n: '02',
                  title: 'Group by credential issuer',
                  desc: 'Env var names are matched against 25+ patterns (GitHub, OpenAI, Stripe, Supabase, AWS…) and grouped by the service that issued them.',
                },
                {
                  n: '03',
                  title: 'Download your rotation plan',
                  desc: 'A JSON file with project IDs, env var names, and the rotation URL for each issuer. No secrets — safe to share with your team.',
                },
                {
                  n: '04',
                  title: 'Execute with one CLI command',
                  desc: 'npx ship-safe rotate --plan rotation-plan.json opens each issuer dashboard, prompts for the new credential, and updates every affected project via the Vercel API.',
                },
              ].map(s => (
                <div key={s.n} className={styles.howCard}>
                  <span className={styles.howNum}>{s.n}</span>
                  <div>
                    <div className={styles.howTitle}>{s.title}</div>
                    <p className={styles.howDesc}>{s.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

      </main>
    </>
  );
}
