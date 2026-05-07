'use client';

import { useEffect, useRef, useState } from 'react';
import styles from './HeroMock.module.css';

type Phase = 'idle' | 'typing' | 'scanning' | 'results';

const command = 'npx ship-safe scan .';

const findings = [
  { sev: 'critical', label: 'Hardcoded AWS key', path: 'src/api/upload.ts:14', tag: 'SECRET-001' },
  { sev: 'high', label: 'Prompt injection in tool description', path: 'agents/router.ts:88', tag: 'LLM-014' },
  { sev: 'high', label: 'MCP server over plaintext HTTP', path: '.mcp/config.json:7', tag: 'MCP-003' },
  { sev: 'medium', label: 'Outdated next dependency (CVE)', path: 'package.json', tag: 'DEP-029' },
];

const scanLines = [
  'analyzing 1,284 files',
  'matched 12 secret patterns',
  'OWASP Agentic AI Top 10 ✓',
  'ranking by exploitability',
];

export default function HeroMock() {
  const [phase, setPhase] = useState<Phase>('idle');
  const [typed, setTyped] = useState('');
  const [scanIdx, setScanIdx] = useState(0);
  const [revealed, setRevealed] = useState(0);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      setTyped(command);
      setScanIdx(scanLines.length);
      setRevealed(findings.length);
      setPhase('results');
      return;
    }

    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting && phase === 'idle') {
            setPhase('typing');
            obs.disconnect();
          }
        });
      },
      { threshold: 0.4 }
    );
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [phase]);

  useEffect(() => {
    if (phase !== 'typing') return;
    if (typed.length >= command.length) {
      const t = setTimeout(() => setPhase('scanning'), 320);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setTyped(command.slice(0, typed.length + 1)), 55);
    return () => clearTimeout(t);
  }, [phase, typed]);

  useEffect(() => {
    if (phase !== 'scanning') return;
    if (scanIdx >= scanLines.length) {
      const t = setTimeout(() => setPhase('results'), 280);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setScanIdx(scanIdx + 1), 380);
    return () => clearTimeout(t);
  }, [phase, scanIdx]);

  useEffect(() => {
    if (phase !== 'results') return;
    if (revealed >= findings.length) return;
    const t = setTimeout(() => setRevealed(revealed + 1), 260);
    return () => clearTimeout(t);
  }, [phase, revealed]);

  return (
    <div ref={ref} className={styles.frame} aria-hidden="true">
      <div className={styles.glow} />
      <div className={styles.scanline} />

      <div className={styles.terminal}>
        <div className={styles.termBar}>
          <span /><span /><span />
          <strong>ship-safe</strong>
          <em className={styles.live}><i />live</em>
        </div>
        <div className={styles.termBody}>
          <div className={styles.line}>
            <span className={styles.prompt}>$</span>
            <code>
              {typed}
              {phase === 'typing' && <i className={styles.caret} />}
            </code>
          </div>
          {scanLines.slice(0, scanIdx).map((line, i) => (
            <div key={line} className={styles.scanLog} style={{ animationDelay: `${i * 60}ms` }}>
              <span className={styles.dot} />
              <code>{line}</code>
            </div>
          ))}
        </div>
      </div>

      <div className={`${styles.results} ${phase === 'results' ? styles.resultsOn : ''}`}>
        <div className={styles.resultsHead}>
          <div>
            <span className={styles.resultsKicker}>scan complete</span>
            <strong>4 risks found</strong>
          </div>
          <div className={styles.score}>
            <svg viewBox="0 0 36 36">
              <circle cx="18" cy="18" r="15.9" className={styles.scoreTrack} />
              <circle cx="18" cy="18" r="15.9" className={styles.scoreFill} />
            </svg>
            <span>72</span>
          </div>
        </div>

        <ul className={styles.findings}>
          {findings.map((f, i) => (
            <li
              key={f.tag}
              className={`${styles.finding} ${i < revealed ? styles.findingOn : ''}`}
              style={{ transitionDelay: `${i * 60}ms` }}
            >
              <span className={`${styles.sev} ${styles[`sev_${f.sev}`]}`} />
              <div className={styles.findingMeta}>
                <strong>{f.label}</strong>
                <code>{f.path}</code>
              </div>
              <span className={styles.tag}>{f.tag}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
