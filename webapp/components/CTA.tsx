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
        <div className={styles.ctaGlow2} aria-hidden="true" />
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
              <Link href="/signup" className="btn btn-primary"> {/* ship-safe-ignore — navigation Link, not an auth endpoint */}
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
            <Link href="/openclaw">OpenClaw Security</Link>
            <span className={styles.footerSep}>·</span>
            <a href="https://www.linkedin.com/company/ship-safe" target="_blank" rel="noopener noreferrer" className={styles.socialLink}>
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5.2 3.5A2.2 2.2 0 1 1 5.2 8a2.2 2.2 0 0 1 0-4.5ZM3.3 9.6h3.8V21H3.3V9.6Zm6.2 0h3.6v1.6h.1c.5-.9 1.7-2 3.6-2 3.9 0 4.6 2.5 4.6 5.9V21h-3.8v-5.2c0-1.3 0-2.9-1.8-2.9s-2.1 1.4-2.1 2.8V21H9.5V9.6Z" /></svg>
              LinkedIn
            </a>
            <span className={styles.footerSep}>·</span>
            <a href="https://x.com/shipsafeAI" target="_blank" rel="noopener noreferrer" className={styles.socialLink}>
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18.9 3H22l-6.8 7.8L23.2 21H17l-4.9-6.4L6.5 21H3.4l7.2-8.2L2.8 3h6.4l4.4 5.8L18.9 3Zm-1.1 16h1.7L8.3 4.9H6.5L17.8 19Z" /></svg>
              X
            </a>
            <span className={styles.footerSep}>·</span>
            <a href="https://github.com/asamassekou10/ship-safe/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">MIT License</a>
            <span className={styles.footerSep}>·</span>
            <span className={styles.footerMeta}>Ship Safe by <a href="https://github.com/asamassekou10" target="_blank" rel="noopener noreferrer">Alhassane Samassekou</a></span>
          </div>
        </div>
      </footer>
    </>
  );
}
