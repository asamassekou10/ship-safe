'use client';
import { useEffect } from 'react';
import Link from 'next/link';
import styles from './Hero.module.css';
import { formatNumber } from '@/lib/stats';

interface HeroProps {
  stars?: number;
  downloads?: number;
}

const FLOAT_CARDS = [
  { sev: 'critical', title: 'AWS key in .env.example', file: 'config/.env.example', sevColor: '#dc2626' },
  { sev: 'high',     title: 'SQL injection in query endpoint', file: 'api/users.ts:42', sevColor: '#ea580c' },
  { sev: 'critical', title: 'JWT secret hardcoded', file: 'auth/middleware.ts:18', sevColor: '#dc2626' },
  { sev: 'medium',   title: 'Missing rate limiting on login', file: 'routes/auth.ts:91', sevColor: '#d97706' },
];

export default function Hero({ stars, downloads }: HeroProps) {
  const stats = [
    { num: '22',  label: 'Security agents' },
    { num: '80+', label: 'Attack classes' },
    { num: stars ? formatNumber(stars) : '1.2k+', label: 'GitHub stars' },
    { num: downloads ? formatNumber(downloads) : '8k+', label: 'Weekly downloads' },
  ];

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
      if (btn) { btn.style.color = 'var(--green)'; setTimeout(() => { btn.style.color = ''; }, 1500); }
    });
  }

  return (
    <section className={styles.hero}>
      {/* Mesh gradient background */}
      <div className={styles.meshBg} aria-hidden="true" />

      {/* Animated orbs */}
      <div className={`${styles.orb} ${styles.orb1}`} aria-hidden="true" />
      <div className={`${styles.orb} ${styles.orb2}`} aria-hidden="true" />
      <div className={`${styles.orb} ${styles.orb3}`} aria-hidden="true" />
      <div className={styles.heroHorizon} aria-hidden="true" />

      <div className={`container ${styles.heroLayout}`}>

        {/* ── Left ─────────────────────────────────── */}
        <div className={styles.heroLeft}>
          <div className={styles.badge}>
            <span className={styles.badgeDot} />
            v8.0 · MIT open source · No account required
          </div>

          <h1 className={styles.h1}>
            Find vulnerabilities<br />
            before <span className={styles.gradientText}>attackers do.</span>
          </h1>

          <p className={styles.heroSub}>
            22 security agents. One command. Catches secrets, injection, memory poisoning,
            Hermes Agent misconfigs, and CVEs — with OWASP&nbsp;Agentic&nbsp;AI&nbsp;Top&nbsp;10 mapping built in.
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
            <Link href="/signup" className="btn btn-primary"> {/* ship-safe-ignore */}
              Scan your code free
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </Link>
            <a href="#demo" className="btn btn-ghost">See it in action</a>
          </div>

          {/* Inline stats row */}
          <div className={styles.statsRow}>
            {stats.map((s, i) => (
              <div key={s.label} className={styles.statItem}>
                {i > 0 && <span className={styles.statSep} aria-hidden="true" />}
                <span className={styles.statNum}>{s.num}</span>
                <span className={styles.statLabel}>{s.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Right: stacked scan UI ────────────────── */}
        <div className={styles.heroRight} aria-hidden="true">

          {/* Floating threat cards */}
          {FLOAT_CARDS.map((card, i) => (
            <div key={i} className={`${styles.floatCard} ${styles[`float${i}`]}`}>
              <span className={styles.floatSev} style={{ color: card.sevColor, background: `${card.sevColor}12`, borderColor: `${card.sevColor}25` }}>
                {card.sev}
              </span>
              <span className={styles.floatTitle}>{card.title}</span>
              <span className={styles.floatFile}>{card.file}</span>
            </div>
          ))}

          {/* Main dashboard card */}
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
                { icon: '✔', text: 'Secrets: 4 found',      tag: 'CRITICAL', tagCls: styles.tagRed },
                { icon: '✔', text: '22 agents: 23 findings', tag: 'HIGH',     tagCls: styles.tagYellow },
                { icon: '✔', text: 'Dependencies: 3 CVEs',  tag: 'HIGH',     tagCls: styles.tagYellow },
                { icon: '✔', text: 'Remediation plan ready', tag: null, dim: true },
              ].map((l, i) => (
                <div key={i} className={styles.termLine} style={{ animationDelay: `${0.3 + i * 0.22}s` }}>
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
                      fill="none" stroke="url(#scoreGrad)" strokeWidth="6"
                      strokeLinecap="round" strokeDasharray="251.3" strokeDashoffset="218"
                      transform="rotate(-90 48 48)" className={styles.scoreArc} id="score-arc"
                    />
                    <defs>
                      <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#0891b2" />
                        <stop offset="100%" stopColor="#2563eb" />
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
                      <div className={styles.metricFill} style={{ background: 'var(--green)', width: '100%' }} />
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
