import Nav from '@/components/Nav';
import Link from 'next/link';
import type { Metadata } from 'next';
import LovableChecker from './LovableChecker';
import styles from '../vercel-april-2026/breach.module.css';

const ogImage = 'https://www.shipsafecli.com/og2.png';

export const metadata: Metadata = {
  title: 'Lovable Public Project Exposure — Self-Audit | Ship Safe',
  description: 'Check if your Lovable projects exposed credentials or sensitive data. Lovable public project chats were re-accessible in early 2026 after a backend permissions change.',
  keywords: [
    'Lovable security incident',
    'Lovable public project chat exposed',
    'vibe coding credential leak',
    'Lovable chat history visible',
    'AI coding tool security audit',
    'rotate credentials after Lovable',
  ],
  alternates: {
    canonical: 'https://www.shipsafecli.com/breach/lovable-2025',
  },
  openGraph: {
    title: 'Lovable Public Project Exposure — Self-Audit',
    description: 'Check if your Lovable projects exposed credentials or sensitive data from chat histories.',
    type: 'website',
    url: 'https://www.shipsafecli.com/breach/lovable-2025',
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Lovable Public Project Exposure Self-Audit' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Lovable Public Project Exposure — Self-Audit',
    description: 'Check if your Lovable projects exposed credentials or sensitive data from chat histories.',
    images: [ogImage],
  },
};

export default function LovableBreachPage() {
  return (
    <>
      <Nav />
      <main className={styles.page}>

        {/* ── Hero ── */}
        <section className={styles.hero}>
          <div className="container">
            <div className={styles.alertBadge}>
              <span className={styles.alertDot} />
              Security Advisory — Lovable 2025/2026
            </div>

            <h1>
              Did your Lovable projects<br />
              expose credentials or sensitive data?
            </h1>

            <p className={styles.heroSub}>
              Lovable accidentally re-enabled access to chat histories on public projects after a
              backend permissions change. Because developers paste API keys, database URLs, and
              credentials into AI prompts, public chat histories are higher-risk than public code.
              Answer 4 questions to assess your exposure.
            </p>

            <div className={styles.heroPillRow}>
              <span className={styles.heroPill}>
                <strong>Exposure window:</strong> Feb 2026 (re-enabled after backend change)
              </span>
              <span className={styles.heroPill}>
                <strong>Root cause:</strong> Permissions unification re-enabled public chat access
              </span>
              <span className={styles.heroPill}>
                <strong>Fixed:</strong> Lovable reverted — all public project chats now private
              </span>
            </div>

            <p className={styles.privacyNote}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              This is a local self-assessment — no data is sent to our servers. Answers stay in your browser.
            </p>
          </div>
        </section>

        {/* ── Checker ── */}
        <LovableChecker />

        {/* ── What the checklist covers ── */}
        <section style={{ maxWidth: 820, margin: '3rem auto 0', padding: '0 1rem' }}>
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: '2.5rem' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Background
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1rem' }}>
              {[
                {
                  num: '01',
                  title: 'The "public" confusion',
                  desc: 'Lovable\'s public/private toggle controlled the entire project - chat history, code, and build artifacts. Many users assumed "public" only meant their published app was visible, not the prompts they used to build it.',
                },
                {
                  num: '02',
                  title: 'What chats contain',
                  desc: 'Vibe-coding prompts typically include API keys pasted for context, database URLs shared to explain errors, service credentials dropped in mid-session, and internal system details. This makes chat histories higher-risk than the generated code.',
                },
                {
                  num: '03',
                  title: 'The backend re-exposure',
                  desc: 'A February 2026 backend change accidentally re-enabled access to public project chats. Two HackerOne reports were closed without escalation - the triage team read it as intended behavior based on old documentation.',
                },
                {
                  num: '04',
                  title: 'Who was affected',
                  desc: 'Free tier users before May 2025 could not make projects private. Anyone on any tier who had projects set to public and pasted credentials into chats should assume those chats were accessible during the window.',
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
            <a href="https://lovable.dev/blog/public-projects" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }} target="_blank" rel="noopener noreferrer">
              Lovable public statement
            </a>{' '}
            and{' '}
            <Link href="/blog/lovable-2025-public-project-chat-exposure" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }}>
              our full incident analysis
            </Link>.
          </p>
        </section>

      </main>
    </>
  );
}
