'use client';
import { useEffect, useRef } from 'react';
import styles from './Terminal.module.css';

const LINES: { text: string; cls?: string; pause?: number }[] = [
  { text: '$ npx ship-safe audit .', cls: 'cmd', pause: 400 },
  { text: '', pause: 200 },
  { text: '  ════════════════════════════════════════════════════', cls: 'dim', pause: 100 },
  { text: '    Ship Safe v5.0 — Full Security Audit', cls: 'white bold', pause: 300 },
  { text: '  ════════════════════════════════════════════════════', cls: 'dim', pause: 300 },
  { text: '', pause: 100 },
  { text: '  [Phase 1/4] Scanning for secrets...         ✔ 4 found', cls: 'yellow', pause: 400 },
  { text: '  [Phase 2/4] Running 16 security agents...   ✔ 23 findings', cls: 'yellow', pause: 400 },
  { text: '  [Phase 3/4] Auditing dependencies...        ✔ 3 CVEs', cls: 'yellow', pause: 400 },
  { text: '  [Phase 4/4] Computing security score...     ✔ 72/100 C', cls: 'cyan', pause: 500 },
  { text: '', pause: 100 },
  { text: '  Remediation Plan', cls: 'white bold', pause: 200 },
  { text: '  ────────────────────────────────────────────────────', cls: 'dim', pause: 100 },
  { text: '', pause: 100 },
  { text: '  🔴 CRITICAL — fix immediately', cls: 'red', pause: 200 },
  { text: '   1. [SECRETS] Rotate Stripe Live Secret Key', cls: 'red', pause: 120 },
  { text: '      .env:12 → Move to secrets manager', cls: 'dim', pause: 120 },
  { text: '   2. [INJECTION] Unsafe eval' + '() with user input', cls: 'red', pause: 120 },
  { text: '      api/process.js:41 → Use safe parser', cls: 'dim', pause: 400 },
  { text: '', pause: 100 },
  { text: '  🟠 HIGH — fix before deploy', cls: 'yellow', pause: 200 },
  { text: '   3. [XSS] dangerouslySetInnerHTML without sanitization', cls: 'yellow', pause: 120 },
  { text: '      src/BlogRenderer.jsx:28 → Add DOMPurify', cls: 'dim', pause: 400 },
  { text: '', pause: 100 },
  { text: '  📊 Full report: ship-safe-report.html', cls: 'cyan', pause: 0 },
];

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

export default function Terminal() {
  const wrapRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const wrapper = wrapRef.current;
    if (!wrapper) return;

    const obs = new IntersectionObserver(async (entries) => {
      if (!entries[0].isIntersecting || started.current) return;
      started.current = true;
      obs.unobserve(wrapper);

      const body = bodyRef.current;
      if (!body) return;

      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduced) {
        LINES.forEach(line => {
          const div = document.createElement('div');
          div.className = `${styles.tLine} ${line.cls ? line.cls.split(' ').map(c => styles[c] || c).join(' ') : styles.dim}`;
          div.textContent = line.text;
          body.appendChild(div);
        });
        return;
      }

      const cursorEl = document.createElement('div');
      cursorEl.className = `${styles.tLine} ${styles.cursorLine}`;
      const cursorSpan = document.createElement('span');
      cursorSpan.className = styles.cursor;
      cursorSpan.textContent = '▋';
      cursorEl.appendChild(cursorSpan);
      body.appendChild(cursorEl);

      for (const line of LINES) {
        await sleep(line.pause ?? 100);
        const el = document.createElement('div');
        const clsNames = (line.cls || 'dim').split(' ').map(c => styles[c] || '').filter(Boolean).join(' ');
        el.className = `${styles.tLine} ${clsNames}`;
        el.textContent = line.text;
        body.insertBefore(el, cursorEl);
        body.scrollTop = body.scrollHeight;
      }
      cursorEl.remove();
    }, { threshold: 0.3 });

    obs.observe(wrapper);
    return () => obs.disconnect();
  }, []);

  return (
    <section className={styles.terminalSection}>
      <div className="container">
        <div className={`${styles.terminal} card`} id="terminal-wrapper" ref={wrapRef} data-animate>
          <div className={styles.terminalBar}>
            <span className={`${styles.dot} ${styles.dotR}`} />
            <span className={`${styles.dot} ${styles.dotY}`} />
            <span className={`${styles.dot} ${styles.dotG}`} />
            <span className={styles.terminalTitle}>npx ship-safe audit .</span>
          </div>
          <div className={styles.terminalBody} ref={bodyRef} aria-live="polite" />
        </div>
      </div>
    </section>
  );
}
