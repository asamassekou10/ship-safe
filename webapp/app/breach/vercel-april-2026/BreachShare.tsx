'use client';
import { useState } from 'react';
import styles from './BreachShare.module.css';

const URL = 'https://www.shipsafecli.com/breach/vercel-april-2026';
const TITLE = 'Vercel April 2026 Breach - Impact Checker';
const EMAIL_SUBJECT = 'Check if your Vercel project was affected by the April 2026 breach';
const EMAIL_BODY = `Hey,

There's a free tool that checks if your Vercel project was impacted by the April 2026 security incident (Context.ai breach - compromised deployment tokens and environment variables).

You can run 4 checks directly in your browser - no install needed:
${URL}

It scans for:
- GitHub Actions with unpinned AI integrations
- Vercel integrations with dangerous OAuth scopes
- Suspicious activity in your Vercel audit log (Mar 28 - Apr 12 window)
- MCP/agent configs forwarding credentials cross-boundary

Takes about 2 minutes. Worth checking.`;

export default function BreachShare() {
  const [copied, setCopied] = useState(false);

  function copyLink() {
    navigator.clipboard.writeText(URL);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const encoded = encodeURIComponent(URL);
  const encodedTitle = encodeURIComponent(TITLE);
  const emailHref = `mailto:?subject=${encodeURIComponent(EMAIL_SUBJECT)}&body=${encodeURIComponent(EMAIL_BODY)}`;

  return (
    <section className={styles.section}>
      <div className={styles.inner}>
        <div className={styles.textCol}>
          <p className={styles.eyebrow}>Spread the word</p>
          <h2 className={styles.heading}>Know someone on Vercel?</h2>
          <p className={styles.sub}>
            Forward this checker to teammates or coworkers who use Vercel.
            The checks take 2 minutes and require no account.
          </p>
        </div>
        <div className={styles.actions}>
          <a href={emailHref} className={styles.emailBtn}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="2" y="4" width="20" height="16" rx="2"/>
              <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
            </svg>
            Send via email
          </a>

          <div className={styles.secondaryRow}>
            <a
              href={`https://x.com/intent/tweet?text=${encodedTitle}&url=${encoded}`}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.iconBtn}
              aria-label="Share on X"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.747l7.73-8.835L1.254 2.25H8.08l4.253 5.622 5.91-5.622zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
              </svg>
              Share on X
            </a>

            <a
              href={`https://www.linkedin.com/sharing/share-offsite/?url=${encoded}`}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.iconBtn}
              aria-label="Share on LinkedIn"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
              </svg>
              LinkedIn
            </a>

            <button className={styles.iconBtn} onClick={copyLink} type="button">
              {copied ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>
              )}
              {copied ? 'Copied!' : 'Copy link'}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
