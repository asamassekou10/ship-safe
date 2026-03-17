'use client';
import { useRef } from 'react';
import styles from './CICD.module.css';

const yamlCode = `name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Security gate
        run: npx ship-safe ci . --threshold 75 --sarif results.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif`;

export default function CICD() {
  const labelRef = useRef<HTMLSpanElement>(null);

  function handleCopy(btn: HTMLButtonElement) {
    navigator.clipboard.writeText(yamlCode).then(() => {
      if (labelRef.current) {
        labelRef.current.textContent = 'Copied!';
        btn.style.color = 'var(--green)';
        setTimeout(() => {
          if (labelRef.current) labelRef.current.textContent = 'Copy';
          btn.style.color = '';
        }, 2000);
      }
    });
  }

  return (
    <section className={styles.cicd}>
      <div className="container">
        <span className="section-label">CI / CD</span>
        <h2>Drop it into your pipeline.</h2>
        <p className="section-sub">Use <code>ship-safe ci</code> for threshold-based gating, compact output, and SARIF. Zero config.</p>

        <div className={`${styles.codeBlock} card`} data-animate>
          <div className={styles.codeHeader}>
            <div className={styles.codeFilename}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
              .github/workflows/security.yml
            </div>
            <button
              className={`copy-btn ${styles.ciCopy}`}
              onClick={e => handleCopy(e.currentTarget as HTMLButtonElement)}
              title="Copy workflow"
              aria-label="Copy GitHub Actions workflow"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
              </svg>
              <span ref={labelRef}>Copy</span>
            </button>
          </div>
          <pre className={styles.yamlPre}>{yamlCode}</pre>
        </div>

        <p className={styles.sarifTip} data-animate data-delay="100">
          Use <code>--sarif</code> with <code>scan</code> to upload findings directly to GitHub's Security tab via <code>github/codeql-action/upload-sarif</code>.
        </p>
      </div>
    </section>
  );
}
