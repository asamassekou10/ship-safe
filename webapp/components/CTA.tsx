'use client';
import Link from 'next/link';
import styles from './CTA.module.css';

export default function CTA() {
  function handleCopy() {
    const btn = document.getElementById('cta-copy');
    navigator.clipboard.writeText('npx ship-safe audit .').then(() => {
      if (btn) {
        btn.style.color = 'var(--green)';
        setTimeout(() => { btn.style.color = ''; }, 2000);
      }
    });
  }

  return (
    <>
      <section className={styles.cta}>
        <div className={styles.ctaGlow} aria-hidden="true" />
        <div className="container">
          <div className={styles.ctaInner} data-animate>
            <span className="section-label">Get Started</span>
            <h2>Ready to ship with confidence?</h2>
            <p className={styles.ctaSub}>
              Free CLI — no signup. Or use the web dashboard for history, teams, and AI-powered fixes.
            </p>

            <div className={styles.ctaInstall}>
              <div className="install-box">
                <span className="install-prompt">$</span>
                <span id="cta-cmd">npx ship-safe audit .</span>
                <button className="copy-btn" id="cta-copy" onClick={handleCopy} title="Copy" aria-label="Copy install command">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                </button>
              </div>
            </div>

            <div className={styles.ctaActions}>
              <Link href="/signup" className="btn btn-primary">
                Start for free
              </Link>
              <a href="https://github.com/asamassekou10/ship-safe" className="btn btn-ghost" target="_blank" rel="noopener noreferrer">
                View on GitHub
              </a>
              <a href="https://www.npmjs.com/package/ship-safe" className="btn btn-ghost" target="_blank" rel="noopener noreferrer">
                npm package
              </a>
            </div>
          </div>
        </div>
      </section>

      <footer className={styles.footer}>
        <div className="container">
          <div className={styles.footerInner}>
            <span className={styles.footerBrand}>ship-safe</span>
            <span className={styles.footerSep}>·</span>
            <span className={styles.footerMeta}>Open-source security toolkit</span>
            <span className={styles.footerSep}>·</span>
            <Link href="/pricing">Pricing</Link>
            <span className={styles.footerSep}>·</span>
            <a href="https://github.com/asamassekou10/ship-safe/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">MIT License</a>
          </div>
        </div>
      </footer>
    </>
  );
}
