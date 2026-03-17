'use client';
import { useEffect } from 'react';
import Link from 'next/link';
import styles from './Hero.module.css';

export default function Hero() {
  useEffect(() => {
    const scoreEl = document.getElementById('score-val');
    const arcEl = document.getElementById('score-arc') as SVGCircleElement | null;
    if (!scoreEl || !arcEl) return;

    function easeOut(t: number) { return 1 - Math.pow(1 - t, 3); }
    const target = 100;
    const fullDash = 251.3;
    const duration = 1800;
    const start = performance.now();

    function tick(now: number) {
      const p = Math.min((now - start) / duration, 1);
      const ep = easeOut(p);
      (scoreEl as HTMLElement).textContent = String(Math.round(ep * target));
      arcEl!.style.strokeDashoffset = String(fullDash * (1 - ep));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }, []);

  function handleCopy() {
    navigator.clipboard.writeText('npx ship-safe audit .').then(() => {
      const btn = document.getElementById('hero-copy');
      if (btn) {
        btn.style.color = 'var(--green)';
        setTimeout(() => { btn.style.color = ''; }, 1500);
      }
    });
  }

  return (
    <section className={styles.hero}>
      <div className={`${styles.heroOrb} ${styles.heroOrb1}`} aria-hidden="true" />
      <div className={`${styles.heroOrb} ${styles.heroOrb2}`} aria-hidden="true" />

      <div className={`container ${styles.heroLayout}`}>
        {/* Left */}
        <div className={styles.heroLeft}>
          <div className={styles.badge}>
            <span className={styles.badgeDot} />
            Open source · Free · No signup
          </div>

          <h1 className={styles.h1}>
            Ship code,<br />
            <span className={styles.h1Line2}>not <span className={styles.gradientText}>vulnerabilities.</span></span>
          </h1>

          <p className={styles.heroSub}>
            16 security agents scan for secrets, injection, auth bypass, SSRF, supply chain attacks, agentic AI, MCP, RAG, PII, and more — with LLM-powered deep analysis and confidence tuning that cuts false positives by 70%.
          </p>

          <div className={`install-box ${styles.installBox}`}>
            <span className="install-prompt">$</span>
            <span className={styles.installCmd}>npx ship-safe audit .</span>
            <button className="copy-btn" id="hero-copy" onClick={handleCopy} title="Copy command" aria-label="Copy install command">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
              </svg>
            </button>
          </div>

          <div className={styles.heroCtas}>
            <Link href="/signup" className="btn btn-primary">
              Start for free
            </Link>
            <a href="#how-it-works" className="btn btn-ghost">See how it works</a>
          </div>
        </div>

        {/* Right: dashboard card */}
        <div className={styles.heroRight} aria-hidden="true">
          <div className={styles.dashCard}>
            <div className={styles.dashHeader}>
              <div className={styles.dashDots}>
                <span className={`${styles.dot} ${styles.dotR}`} />
                <span className={`${styles.dot} ${styles.dotY}`} />
                <span className={`${styles.dot} ${styles.dotG}`} />
              </div>
              <span className={styles.dashTitle}>ship-safe audit .</span>
              <span className={styles.dashBadge}>LIVE</span>
            </div>

            <div className={styles.dashTerminal}>
              {[
                { icon: '✔', text: 'Secrets: 4 found', tag: 'CRITICAL', tagCls: styles.tagRed },
                { icon: '✔', text: '16 agents: 23 findings', tag: 'HIGH', tagCls: styles.tagYellow },
                { icon: '✔', text: 'Dependencies: 3 CVEs', tag: 'HIGH', tagCls: styles.tagYellow },
                { icon: '✔', text: 'Remediation plan ready', tag: null, dim: true },
              ].map((l, i) => (
                <div key={i} className={styles.termLine}>
                  <span className={`${styles.termPrompt} ${styles.green}`}>{l.icon}</span>
                  <span className={`${styles.termText} ${l.dim ? styles.dim : ''}`}>{l.text}</span>
                  {l.tag && <span className={`${styles.termTag} ${l.tagCls}`}>{l.tag}</span>}
                </div>
              ))}
            </div>

            <div className={styles.dashScore}>
              <div className={styles.scoreLeft}>
                <div className={styles.ringWrap}>
                  <svg viewBox="0 0 96 96" width="96" height="96" className={styles.scoreRing}>
                    <circle cx="48" cy="48" r="40" fill="none" stroke="var(--border)" strokeWidth="6" />
                    <circle
                      cx="48" cy="48" r="40"
                      fill="none"
                      stroke="url(#scoreGrad)"
                      strokeWidth="6"
                      strokeLinecap="round"
                      strokeDasharray="251.3"
                      strokeDashoffset="218"
                      transform="rotate(-90 48 48)"
                      className={styles.scoreArc}
                      id="score-arc"
                    />
                    <defs>
                      <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#22d3ee" />
                        <stop offset="100%" stopColor="#60a5fa" />
                      </linearGradient>
                    </defs>
                  </svg>
                  <div className={styles.ringLabel}>
                    <span className={styles.scoreNum} id="score-val">0</span>
                    <span className={styles.scoreSub}>/100</span>
                  </div>
                </div>
                <div className={styles.gradeRow}>
                  <span className={styles.gradeLetter}>A</span>
                  <span className={styles.gradeText}>Ship it!</span>
                </div>
              </div>

              <div className={styles.scoreRight}>
                {[
                  { label: 'Secrets', val: '0' },
                  { label: 'Code vulns', val: '0' },
                  { label: 'CVEs', val: '0' },
                ].map((m) => (
                  <div key={m.label} className={styles.metric}>
                    <div className={styles.metricTop}>
                      <span className={styles.metricLabel}>{m.label}</span>
                      <span className={`${styles.metricVal} ${styles.ok}`}>{m.val}</span>
                    </div>
                    <div className={styles.metricBar}>
                      <div className={`${styles.metricFill} ${styles.fillFull}`} style={{ background: 'var(--green)' }} />
                    </div>
                  </div>
                ))}
                <div className={styles.metricFiles}>847 files · 3.2s</div>
              </div>
            </div>

            <div className={styles.dashFooter}>
              <span className={styles.statusDot} />
              <span>All checks passed — ready to push</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
