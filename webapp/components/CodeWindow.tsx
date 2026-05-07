'use client';

import { useEffect, useRef, useState } from 'react';
import styles from './CodeWindow.module.css';

type Line =
  | { kind: 'cmd'; text: string }
  | { kind: 'log'; text: string }
  | { kind: 'sev'; level: 'critical' | 'high' | 'medium'; tag: string; file: string; msg: string }
  | { kind: 'rule' }
  | { kind: 'summary'; score: number; counts: { c: number; h: number; m: number } }
  | { kind: 'hint'; text: string };

const script: Line[] = [
  { kind: 'cmd', text: 'npx ship-safe scan .' },
  { kind: 'log', text: '⠋ analyzing 1,284 files across 3 agents, 5 MCP servers, 14 deps' },
  { kind: 'log', text: '⠙ matched 12 secret patterns · ranked by exploitability' },
  { kind: 'log', text: '✓ OWASP Agentic AI Top 10 controls evaluated' },
  { kind: 'rule' },
  { kind: 'sev', level: 'critical', tag: 'SECRET-001', file: 'api-gateway/upload.ts:14', msg: 'Hardcoded sk_live_4eC3XHa0…' },
  { kind: 'sev', level: 'high',     tag: 'LLM-014',    file: 'agents/router.ts:88',     msg: 'Prompt injection in tool description' },
  { kind: 'sev', level: 'high',     tag: 'MCP-003',    file: '.mcp/config.json:7',      msg: 'mcp/vault token over plaintext HTTP' },
  { kind: 'sev', level: 'medium',   tag: 'DEP-029',    file: 'package.json:23',          msg: 'next 14.2.3 → CVE-2026-12 (high)' },
  { kind: 'rule' },
  { kind: 'summary', score: 72, counts: { c: 1, h: 2, m: 1 } },
  { kind: 'hint', text: '↳ run `ship-safe fix --interactive` to remediate' },
];

export default function CodeWindow() {
  const ref = useRef<HTMLDivElement>(null);
  const [revealed, setRevealed] = useState(0);
  const startedRef = useRef(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      setRevealed(script.length);
      return;
    }
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting && !startedRef.current) {
            startedRef.current = true;
            obs.disconnect();
            // Reveal lines progressively, faster on log-spinners and instant on summary
            let i = 0;
            const next = () => {
              i += 1;
              setRevealed(i);
              if (i >= script.length) return;
              const line = script[i];
              const delay =
                line.kind === 'cmd' ? 480 :
                line.kind === 'log' ? 320 :
                line.kind === 'rule' ? 90 :
                line.kind === 'sev' ? 240 :
                line.kind === 'summary' ? 380 :
                160;
              setTimeout(next, delay);
            };
            setTimeout(next, 260);
          }
        });
      },
      { threshold: 0.4 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  return (
    <div ref={ref} className={styles.window}>
      {/* Top chrome — traffic lights + file tabs + meta */}
      <div className={styles.chrome}>
        <div className={styles.lights} aria-hidden="true">
          <span className={styles.dotR} />
          <span className={styles.dotY} />
          <span className={styles.dotG} />
        </div>
        <div className={styles.tabs} role="tablist" aria-label="Open files">
          <span className={`${styles.tab} ${styles.tabActive}`}>scan output</span>
          <span className={styles.tab}>findings.json</span>
          <span className={styles.tab}>report.sarif</span>
        </div>
        <span className={styles.meta}>ship-safe v9.2.1</span>
      </div>

      {/* Body — animated lines */}
      <div className={styles.body} aria-live="polite">
        {script.slice(0, revealed).map((line, i) => {
          if (line.kind === 'cmd') {
            return (
              <div key={i} className={styles.lineCmd}>
                <span className={styles.prompt}>$</span>
                <code>{line.text}</code>
              </div>
            );
          }
          if (line.kind === 'log') {
            return (
              <div key={i} className={styles.lineLog}>
                <code>{line.text}</code>
              </div>
            );
          }
          if (line.kind === 'rule') {
            return <div key={i} className={styles.rule} aria-hidden="true" />;
          }
          if (line.kind === 'sev') {
            return (
              <div key={i} className={styles.lineSev}>
                <span className={`${styles.sev} ${styles[`sev_${line.level}`]}`}>{line.level}</span>
                <span className={styles.sevTag}>{line.tag}</span>
                <span className={styles.sevFile}>{line.file}</span>
                <span className={styles.sevMsg}>{line.msg}</span>
              </div>
            );
          }
          if (line.kind === 'summary') {
            return (
              <div key={i} className={styles.summary}>
                <span className={styles.sumLabel}>summary</span>
                <span className={styles.sumScore}>
                  score <strong>{line.score}</strong>/100
                </span>
                <span className={styles.sumCounts}>
                  <span className={styles.dotR} />{line.counts.c}{' '}
                  <span className={styles.dotY} />{line.counts.h}{' '}
                  <span className={styles.dotG} />{line.counts.m}
                </span>
              </div>
            );
          }
          return (
            <div key={i} className={styles.lineHint}>
              <code>{line.text}</code>
            </div>
          );
        })}

        {revealed < script.length && (
          <div className={styles.lineCmd} aria-hidden="true">
            <span className={styles.caret} />
          </div>
        )}
      </div>
    </div>
  );
}
