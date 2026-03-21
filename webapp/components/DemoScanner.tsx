'use client';

import { useState, FormEvent } from 'react';
import Link from 'next/link';
import styles from './DemoScanner.module.css';

interface ScanResult {
  repo: string;
  score: number | null;
  grade: string | null;
  totalFindings: number;
  categories: Record<string, number>;
  highlights: { title: string; severity: string; category: string }[];
  duration: number;
}

/* Pre-rendered example so visitors see value immediately */
const EXAMPLE_RESULT: ScanResult = {
  repo: 'example/vulnerable-app',
  score: 62,
  grade: 'C',
  totalFindings: 12,
  categories: { secrets: 3, injection: 4, auth: 2, dependencies: 3 },
  highlights: [
    { title: 'AWS access key exposed in .env.example', severity: 'critical', category: 'secrets' },
    { title: 'SQL injection in user query endpoint', severity: 'high', category: 'injection' },
    { title: 'JWT secret hardcoded in auth config', severity: 'critical', category: 'auth' },
    { title: 'lodash@4.17.20 — prototype pollution (CVE-2021-23337)', severity: 'high', category: 'dependencies' },
    { title: 'Missing rate limiting on login route', severity: 'medium', category: 'auth' },
  ],
  duration: 4,
};

type Phase = 'idle' | 'scanning' | 'done' | 'error';

const SCAN_STEPS = [
  'Fetching repository tree…',
  'Scanning for secrets…',
  'Checking code patterns…',
  'Analyzing configurations…',
  'Generating report…',
];

function scoreColor(score: number | null) {
  if (score === null) return 'var(--text-dim)';
  if (score >= 90) return 'var(--green)';
  if (score >= 70) return 'var(--cyan)';
  if (score >= 50) return 'var(--yellow)';
  return 'var(--red)';
}

function sevClass(sev: string) {
  switch (sev) {
    case 'critical': return styles.sevCritical;
    case 'high': return styles.sevHigh;
    case 'medium': return styles.sevMedium;
    default: return styles.sevLow;
  }
}

export default function DemoScanner() {
  const [url, setUrl] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [step, setStep] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [isExample, setIsExample] = useState(true);

  const displayResult = isExample ? EXAMPLE_RESULT : result;

  async function handleScan(e: FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;

    setPhase('scanning');
    setStep(0);
    setError('');
    setIsExample(false);
    setResult(null);

    // Animate through steps
    const stepInterval = setInterval(() => {
      setStep((s) => Math.min(s + 1, SCAN_STEPS.length - 1));
    }, 3000);

    try {
      const res = await fetch('/api/demo-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: url.trim() }),
      });

      clearInterval(stepInterval);

      if (!res.ok) {
        const data = await res.json().catch(() => ({ error: 'Scan failed' }));
        setError(data.error || 'Scan failed');
        setPhase('error');
        return;
      }

      const data: ScanResult = await res.json();
      setResult(data);
      setPhase('done');
    } catch {
      clearInterval(stepInterval);
      setError('Network error. Please try again.');
      setPhase('error');
    }
  }

  const showResult = phase === 'idle' || phase === 'done';
  const activeResult = showResult ? displayResult : null;

  return (
    <section className={styles.section} id="demo">
      <div className="container">
        <div className={styles.sectionHeader}>
          <div className={styles.sectionTag}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            Live Demo
          </div>
          <h2 className={styles.sectionTitle}>Try it now</h2>
          <p className={styles.sectionSub}>
            Paste any public GitHub repo URL and see what ship-safe finds in seconds.
          </p>
        </div>

        <form onSubmit={handleScan} className={styles.inputRow}>
          <input
            type="url"
            className={styles.urlInput}
            placeholder="https://github.com/owner/repo"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={phase === 'scanning'}
          />
          <button
            type="submit"
            className={styles.scanBtn}
            disabled={phase === 'scanning' || !url.trim()}
          >
            {phase === 'scanning' ? (
              <>
                <span className={styles.spinner} />
                Scanning…
              </>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                Scan
              </>
            )}
          </button>
        </form>

        {/* Result card */}
        <div className={styles.resultCard}>
          <div className={styles.cardHeader}>
            <div className={styles.dots}>
              <span className={`${styles.dot} ${styles.dotR}`} />
              <span className={`${styles.dot} ${styles.dotY}`} />
              <span className={`${styles.dot} ${styles.dotG}`} />
            </div>
            <span className={styles.cardTitle}>
              {activeResult ? `ship-safe audit — ${activeResult.repo}` : 'ship-safe audit'}
            </span>
            <span className={`${styles.cardBadge} ${isExample ? styles.badgeDemo : styles.badgeLive}`}>
              {isExample ? 'EXAMPLE' : 'LIVE'}
            </span>
          </div>

          {/* Scanning state */}
          {phase === 'scanning' && (
            <div className={styles.scanning}>
              {SCAN_STEPS.map((text, i) => (
                <div key={i} className={styles.scanLine}>
                  {i < step ? (
                    <span className={styles.checkmark}>✓</span>
                  ) : i === step ? (
                    <span className={styles.spinner} />
                  ) : (
                    <span style={{ width: 14 }} />
                  )}
                  <span style={{ opacity: i <= step ? 1 : 0.4 }}>{text}</span>
                  {i > step && <span className={styles.shimmer} />}
                </div>
              ))}
            </div>
          )}

          {/* Error state */}
          {phase === 'error' && (
            <div className={styles.error}>{error}</div>
          )}

          {/* Results */}
          {activeResult && showResult && (
            <>
              {isExample && (
                <div className={styles.exampleLabel}>Example scan result</div>
              )}
              <div className={styles.resultBody}>
                <div className={styles.scoreCol}>
                  <div className={styles.ringWrap}>
                    <svg viewBox="0 0 88 88" width="88" height="88" className={styles.scoreRing}>
                      <circle cx="44" cy="44" r="36" fill="none" stroke="var(--border)" strokeWidth="5" />
                      <circle
                        cx="44" cy="44" r="36"
                        fill="none"
                        stroke={scoreColor(activeResult.score)}
                        strokeWidth="5"
                        strokeLinecap="round"
                        strokeDasharray={`${2 * Math.PI * 36}`}
                        strokeDashoffset={`${2 * Math.PI * 36 * (1 - (activeResult.score ?? 0) / 100)}`}
                        transform="rotate(-90 44 44)"
                        className={styles.scoreArc}
                      />
                    </svg>
                    <div className={styles.ringLabel}>
                      <span className={styles.scoreNum} style={{ color: scoreColor(activeResult.score) }}>
                        {activeResult.score ?? '—'}
                      </span>
                      <span className={styles.scoreSub}>/100</span>
                    </div>
                  </div>
                  <div className={styles.gradeRow}>
                    <span className={styles.gradeLetter} style={{ color: scoreColor(activeResult.score) }}>
                      {activeResult.grade ?? '—'}
                    </span>
                    <span className={styles.gradeText}>
                      {(activeResult.score ?? 0) >= 90 ? 'Ship it!' :
                       (activeResult.score ?? 0) >= 70 ? 'Almost there' :
                       (activeResult.score ?? 0) >= 50 ? 'Needs work' : 'Critical'}
                    </span>
                  </div>
                </div>

                <div className={styles.findingsCol}>
                  <div className={styles.findingsTitle}>
                    {activeResult.totalFindings} finding{activeResult.totalFindings !== 1 ? 's' : ''} detected
                  </div>
                  {activeResult.highlights.map((h, i) => (
                    <div key={i} className={styles.findingRow}>
                      <span className={`${styles.severityDot} ${sevClass(h.severity)}`} />
                      <span className={styles.findingText}>{h.title}</span>
                      <span className={styles.findingCat}>{h.category}</span>
                    </div>
                  ))}
                  {Object.keys(activeResult.categories).length > 0 && (
                    <div className={styles.statsPills}>
                      {Object.entries(activeResult.categories).map(([cat, count]) => (
                        <span key={cat} className={styles.pill}>{cat}: {count}</span>
                      ))}
                    </div>
                  )}
                  <div className={styles.duration}>{activeResult.duration}s scan time</div>
                </div>
              </div>

              <div className={styles.cardFooter}>
                <span className={styles.footerText}>
                  {isExample
                    ? 'Scan your own repo to see real results'
                    : 'Full report available with a free account'}
                </span>
                {/* ship-safe-ignore — /signup Link is a navigation element, not an auth endpoint call */}
                <Link href="/signup" className={styles.footerCta}>
                  Get full report →
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
