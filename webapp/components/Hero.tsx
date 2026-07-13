'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import NumberFlow from '@number-flow/react';
import { MeshGradient } from '@paper-design/shaders-react';
import AgentNetwork, { type Finding, type NetworkEvent } from './AgentNetwork';
import AgentTimeline from './AgentTimeline';
import MagneticButton from './MagneticButton';
import { formatNumber } from '@/lib/stats';
import styles from './Hero.module.css';

type Props = {
  stars: number;
  downloads: number;
};

const initialFinding: Finding = {
  node: 'r1',
  label: 'Hardcoded sk_live_ in api-gateway/upload.ts',
  tag: 'SECRET-001',
  file: 'api-gateway/upload.ts',
  line: 14,
  snippet: 'const stripe = new Stripe("sk_live_4eC3XHa0…");',
  column: 28,
  hint: 'rotate via stripe.dashboard',
};

const fmtTime = (ms: number) => {
  const d = new Date(ms);
  return `${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
};

const labelForEvent = (e: NetworkEvent): string => {
  switch (e.kind) {
    case 'pulse': return `scan  ${e.from} → ${e.to}`;
    case 'flash': return `flag  ${e.node}  ${e.tag}`;
    case 'tick':  return e.label;
  }
};

const colorClassForEvent = (e: NetworkEvent): string => {
  switch (e.kind) {
    case 'pulse': return 'evCyan';
    case 'flash': return 'evRed';
    case 'tick':  return 'evGreen';
  }
};

type LogEntry = { id: number; ts: number; kind: NetworkEvent['kind']; text: string };

export default function Hero({ stars, downloads }: Props) {
  const reduceMotion = useReducedMotion();
  const [finding, setFinding] = useState<Finding>(initialFinding);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [latestEvent, setLatestEvent] = useState<NetworkEvent | null>(null);
  const [statsOn, setStatsOn] = useState(false);
  const heroRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const t = setTimeout(() => setStatsOn(true), 350);
    return () => clearTimeout(t);
  }, []);

  // Cursor-followed spotlight on the hero — sets --sx/--sy, used by ::after radial gradient
  useEffect(() => {
    const el = heroRef.current;
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    let raf = 0;
    let pending: { x: number; y: number } | null = null;
    const flush = () => {
      raf = 0;
      if (pending) {
        el.style.setProperty('--sx', `${pending.x}%`);
        el.style.setProperty('--sy', `${pending.y}%`);
        pending = null;
      }
    };
    const onMove = (e: MouseEvent) => {
      const rect = el.getBoundingClientRect();
      pending = {
        x: ((e.clientX - rect.left) / rect.width) * 100,
        y: ((e.clientY - rect.top) / rect.height) * 100,
      };
      if (!raf) raf = requestAnimationFrame(flush);
    };
    el.addEventListener('mousemove', onMove);
    return () => {
      el.removeEventListener('mousemove', onMove);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  const handleEvent = (e: NetworkEvent) => {
    const entry: LogEntry = { id: e.t, ts: e.t, kind: e.kind, text: labelForEvent(e) };
    setLog((prev) => [entry, ...prev].slice(0, 5));
    setLatestEvent(e);
  };

  // Caret position under the offending column for the snippet line
  const caretPad = ' '.repeat(Math.max(0, finding.column - 1));
  const caretLen = '^'.repeat(Math.min(18, Math.max(3, finding.snippet.length - finding.column + 1)));

  return (
    <section className={styles.hero} ref={heroRef}>
      <div className={styles.bg} aria-hidden="true">
        <MeshGradient
          className={styles.shader}
          colors={['#050507', '#08161d', '#0b3a4a', '#22d3ee', '#050507']}
          distortion={0.78}
          swirl={0.28}
          grainMixer={0.22}
          grainOverlay={0.06}
          speed={reduceMotion ? 0 : 0.16}
        />
        <div className={styles.bgFade} />
        <div className={styles.bgGrid} />
      </div>

      <div className={styles.inner}>
        <div className={styles.copy}>
          <motion.span
            className={styles.statusPill}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
          >
            <i /> Live <span className={styles.pillSep}>•</span>{' '}
            <code>npx ship-safe scan</code>
          </motion.span>

          <motion.h1
            initial="hidden"
            animate="visible"
            variants={{
              hidden: {},
              visible: { transition: { staggerChildren: 0.045, delayChildren: 0.15 } },
            }}
          >
            {['Catch', 'the', 'breach'].map((word, i) => (
              <motion.span
                key={i}
                className={styles.word}
                variants={{
                  hidden: { opacity: 0, y: 18 },
                  visible: { opacity: 1, y: 0, transition: { duration: 0.55, ease: [0.22, 0.8, 0.36, 1] } },
                }}
              >
                {word}
              </motion.span>
            ))}
            <motion.span
              className={`${styles.word} ${styles.gradientText}`}
              variants={{
                hidden: { opacity: 0, y: 18 },
                visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.22, 0.8, 0.36, 1] } },
              }}
            >
              before you push.
            </motion.span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.5, ease: 'easeOut' }}
          >
            One command, 24 agents. Ship Safe scans your code, dependencies, configs, MCP
            servers, and AI prompts — flagging the leaked secrets, prompt injections, and CVEs
            every traditional scanner misses.
          </motion.p>

          <motion.div
            className={styles.actions}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.7 }}
          >
            <MagneticButton>
              <Link href="/signup" className={styles.primaryCta}>
                Start free scan <span aria-hidden="true">→</span>
              </Link>
            </MagneticButton>
            <Link href="/docs" className={styles.secondaryCta}>View docs</Link>
          </motion.div>

          <motion.div
            className={styles.proof}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.9 }}
          >
            <span className={styles.tabular}>
              <strong>
                <NumberFlow value={statsOn ? stars : 0} format={{ notation: 'compact' }} />
              </strong>{' '}
              GitHub stars
            </span>
            <span className={styles.proofDivider} />
            <span className={styles.tabular}>
              <strong>
                <NumberFlow value={statsOn ? downloads : 0} format={{ notation: 'compact' }} />
              </strong>{' '}
              npm downloads
            </span>
            <span className={styles.proofDivider} />
            <span><strong>MIT</strong> open-source</span>
            <span className={styles.proofDivider} />
            <span
              className={styles.tabular}
              title={`${formatNumber(stars)} stars · ${formatNumber(downloads)} downloads`}
            >
              24 agents
            </span>
          </motion.div>

          <motion.div
            className={styles.trust}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 1.1 }}
          >
            <span className={styles.trustLabel}>Catches misconfigs in</span>
            <span className={styles.trustList}>
              {['Anthropic', 'OpenAI', 'Stripe', 'Vercel', 'Cursor', 'Supabase', 'MCP'].map((name) => (
                <span key={name} className={styles.trustItem}>{name}</span>
              ))}
            </span>
          </motion.div>
        </div>

        <motion.div
          className={styles.networkSlot}
          initial={{ opacity: 0, scale: 0.97, y: 16 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2, ease: [0.22, 0.8, 0.36, 1] }}
        >
          <div className={styles.networkFrame}>
            <AgentNetwork onFinding={setFinding} onEvent={handleEvent} />

            {/* Code-shaped callout — looks like real CLI scan output */}
          <motion.div
            className={styles.codeCallout}
            key={finding.tag}
            initial={{ opacity: 0, y: 12, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.5, ease: [0.22, 0.8, 0.36, 1] }}
          >
            <div className={styles.codeHead}>
              <span className={styles.sevDot} />
              <span className={styles.codeFile}>{finding.file}:{finding.line}</span>
              <span className={styles.codeTag}>{finding.tag}</span>
            </div>
            <pre className={styles.codeBody}>
              <code>
                <span className={styles.codeGutter}>{String(finding.line).padStart(3, ' ')} │ </span>
                <span className={styles.codeLine}>{finding.snippet}</span>
                {'\n'}
                <span className={styles.codeGutter}>{'    │ '}</span>
                <span className={styles.codeCaret}>{caretPad}{caretLen}</span>
              </code>
            </pre>
            <div className={styles.codeFoot}>
              <span className={styles.codeArrow}>↳</span>
              <span className={styles.codeHint}>{finding.hint}</span>
            </div>
          </motion.div>

            {/* Live signal log */}
            <div className={styles.signalLog} aria-hidden="true">
              <div className={styles.signalHead}>
                <span className={styles.signalDot} />
                <span>signal</span>
              </div>
              <ul>
                {log.length === 0 ? (
                  <li className={styles.signalEmpty}><code>—</code></li>
                ) : (
                  log.map((entry) => (
                    <li key={entry.id} className={styles[colorClassForEvent({ kind: entry.kind } as NetworkEvent)]}>
                      <code>
                        <span className={styles.signalTs}>{fmtTime(entry.ts)}</span>
                        <span className={styles.signalText}>{entry.text}</span>
                      </code>
                    </li>
                  ))
                )}
              </ul>
            </div>
          </div>

          {/* AI timeline pills — light up by stage as the network ticks */}
          <div className={styles.timelineRow}>
            <AgentTimeline event={latestEvent} />
          </div>
        </motion.div>
      </div>
    </section>
  );
}
