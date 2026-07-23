'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import NumberFlow from '@number-flow/react';
import { MeshGradient } from '@paper-design/shaders-react';
import { track } from '@vercel/analytics/react';
import MagneticButton from './MagneticButton';
import { formatNumber } from '@/lib/stats';
import styles from './Hero.module.css';

type Props = {
  stars: number;
  downloads: number;
};

type StackTone = 'anthropic' | 'openai' | 'stripe' | 'vercel' | 'cursor' | 'supabase' | 'mcp';

const stackLogos: Array<{ name: string; tone: StackTone }> = [
  { name: 'Anthropic', tone: 'anthropic' },
  { name: 'OpenAI', tone: 'openai' },
  { name: 'Stripe', tone: 'stripe' },
  { name: 'Vercel', tone: 'vercel' },
  { name: 'Cursor', tone: 'cursor' },
  { name: 'Supabase', tone: 'supabase' },
  { name: 'MCP', tone: 'mcp' },
];

const stackToneClass: Record<StackTone, string> = {
  anthropic: styles.anthropic,
  openai: styles.openai,
  stripe: styles.stripe,
  vercel: styles.vercel,
  cursor: styles.cursor,
  supabase: styles.supabase,
  mcp: styles.mcp,
};

function StackLogo({ tone }: { tone: StackTone }) {
  if (tone === 'vercel') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 4 22 20H2L12 4Z" />
      </svg>
    );
  }
  if (tone === 'supabase') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M13.4 3.6 5.4 14h6.2l-1 6.4L18.6 10h-6.2l1-6.4Z" />
      </svg>
    );
  }
  if (tone === 'openai') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 3.3a3.9 3.9 0 0 1 3.2 1.7 4 4 0 0 1 4.4 5.4 4 4 0 0 1-2.3 6.3 4 4 0 0 1-6.5 2.3 4 4 0 0 1-5.9-3.4 4 4 0 0 1 .8-7.1A4 4 0 0 1 12 3.3Zm-1.2 4.1v3.4L7.9 9.1a2.3 2.3 0 0 0-.6 3.2l3.5-2Zm2.4 0-3.5 2 2.9 1.7 2.9-1.7a2.3 2.3 0 0 0-2.3-2Zm-4.1 5-2.9 1.7a2.3 2.3 0 0 0 2.9 1.9v-3.6Zm5.8 0v3.4l2.9-1.7a2.3 2.3 0 0 0-2.9-1.7Zm-4.1 2v3.4a2.3 2.3 0 0 0 2.4-2v-3.1l-2.4 1.7Zm2.4-5.8v3.1l2.4 1.4V9.7a2.3 2.3 0 0 0-2.4-.1Z" />
      </svg>
    );
  }
  if (tone === 'cursor') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 4 20 12 4 20l3.8-8L4 4Z" />
      </svg>
    );
  }
  if (tone === 'mcp') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M6 7a3 3 0 1 1 2.8 4H8v2h8v-2h-.8a3 3 0 1 1 0-2H16V7h2v10h-4v-2H8v2H6V7Z" />
      </svg>
    );
  }
  return <span aria-hidden="true">{tone === 'stripe' ? 'S' : 'A'}</span>;
}

function ProofIcon({ kind }: { kind: 'github' | 'npm' | 'mit' | 'agents' }) {
  if (kind === 'github') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 .7a11.3 11.3 0 0 0-3.6 22c.57.1.78-.25.78-.55v-2.02c-3.17.69-3.84-1.36-3.84-1.36-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.67 1.24 3.32.95.1-.74.4-1.24.72-1.53-2.53-.29-5.2-1.27-5.2-5.63 0-1.24.45-2.26 1.18-3.06-.12-.29-.51-1.45.11-3.02 0 0 .96-.31 3.13 1.17a10.8 10.8 0 0 1 5.7 0c2.17-1.48 3.13-1.17 3.13-1.17.62 1.57.23 2.73.11 3.02.73.8 1.18 1.82 1.18 3.06 0 4.38-2.67 5.34-5.21 5.62.41.36.77 1.05.77 2.12v3.14c0 .3.2.66.79.55A11.3 11.3 0 0 0 12 .7Z" />
      </svg>
    );
  }
  if (kind === 'mit') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M5 3h14v18H5V3Zm3 4v10h2V7H8Zm4 0v10h2V7h-2Zm4 0v10h2V7h-2Z" />
      </svg>
    );
  }
  if (kind === 'agents') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 4.5a3 3 0 1 1 0 6 3 3 0 0 1 0-6ZM6 13.2a2.4 2.4 0 1 1 0 4.8 2.4 2.4 0 0 1 0-4.8Zm12 0a2.4 2.4 0 1 1 0 4.8 2.4 2.4 0 0 1 0-4.8Zm-6-1.3 4 2.4-.8 1.35L12 13.75l-3.2 1.9L8 14.3l4-2.4Z" />
      </svg>
    );
  }
  return <span aria-hidden="true">npm</span>;
}

export default function Hero({ stars, downloads }: Props) {
  const reduceMotion = useReducedMotion();
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
        <div className={styles.logoVideoWrap}>
          <video
            className={styles.logoVideo}
            autoPlay
            muted
            loop
            playsInline
            preload="metadata"
            poster="/logo.png"
            aria-hidden="true"
          >
            <source src="/Animate_logo_ship-safe-bg.mp4" type="video/mp4" />
          </video>
        </div>
        <div className={styles.bgFade} />
        <div className={styles.bgGrid} />
      </div>

      <div className={styles.inner}>
        <div className={styles.copy}>
          <motion.h1
            initial="hidden"
            animate="visible"
            variants={{
              hidden: {},
              visible: { transition: { staggerChildren: 0.045, delayChildren: 0.15 } },
            }}
          >
            <span className={styles.titleLine}>
              {['Find', 'risky', 'code.'].map((word, i) => (
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
            </span>
            <span className={styles.titleLine}>
              <motion.span
                className={`${styles.word} ${styles.gradientText}`}
                variants={{
                  hidden: { opacity: 0, y: 18 },
                  visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.22, 0.8, 0.36, 1] } },
                }}
              >
                Fix it before it ships.
              </motion.span>
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.5, ease: 'easeOut' }}
          >
            Local scans, PR fixes, and cloud history when your team needs it.
          </motion.p>

          <motion.div
            className={styles.actions}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.7 }}
          >
            <MagneticButton>
              <Link
                href="/signup"
                className={styles.primaryCta}
                onClick={() => track('Homepage CTA Clicked', { item: 'start_free_scan', section: 'hero' })}
              >
                Start free scan <span aria-hidden="true">→</span>
              </Link>
            </MagneticButton>
            <Link
              href="#get-started"
              className={styles.secondaryCta}
              onClick={() => track('Homepage CTA Clicked', { item: 'run_locally', section: 'hero' })}
            >
              Run locally
            </Link>
          </motion.div>

          <motion.div
            className={styles.proof}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.9 }}
          >
            <span className={styles.tabular}>
              <span className={`${styles.proofIcon} ${styles.githubProof}`}>
                <ProofIcon kind="github" />
              </span>
              <strong>
                <NumberFlow value={statsOn ? stars : 0} format={{ notation: 'compact' }} />
              </strong>{' '}
              stars
            </span>
            <span className={styles.proofDivider} />
            <span className={styles.tabular}>
              <span className={`${styles.proofIcon} ${styles.npmProof}`}>
                <ProofIcon kind="npm" />
              </span>
              <strong>
                <NumberFlow value={statsOn ? downloads : 0} format={{ notation: 'compact' }} />
              </strong>{' '}
              downloads
            </span>
            <span className={styles.proofDivider} />
            <span>
              <span className={`${styles.proofIcon} ${styles.mitProof}`}>
                <ProofIcon kind="mit" />
              </span>
              <strong>MIT</strong>
            </span>
            <span className={styles.proofDivider} />
            <span
              className={styles.tabular}
              title={`${formatNumber(stars)} stars · ${formatNumber(downloads)} downloads`}
            >
              <span className={`${styles.proofIcon} ${styles.agentsProof}`}>
                <ProofIcon kind="agents" />
              </span>
              29 agents
            </span>
          </motion.div>
        </div>

        <motion.div
          className={styles.demoSlot}
          initial={{ opacity: 0, scale: 0.97, y: 16 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2, ease: [0.22, 0.8, 0.36, 1] }}
        >
          <div className={styles.demoFrame}>
            <div className={styles.demoTopbar}>
              <span className={styles.demoDots} aria-hidden="true">
                <i /><i /><i />
              </span>
              <span className={styles.demoTitle}>Kimi K3 red-team demo</span>
              <span className={styles.demoSpeed}>3.5x</span>
            </div>
            <video
              className={styles.demoVideo}
              autoPlay={!reduceMotion}
              muted
              loop
              playsInline
              preload="metadata"
              poster="/scan result.png"
              aria-label="Ship Safe Kimi K3 red-team command demo"
            >
              <source src="/ship-safe-hero-demo.mp4" type="video/mp4" />
            </video>
          </div>
          <motion.div
            className={styles.trust}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.95 }}
          >
            <span className={styles.trustLabel}>Built for stacks using</span>
            <span className={styles.trustList}>
              {stackLogos.map((item) => (
                <span key={item.name} className={styles.trustItem}>
                  <span className={`${styles.stackLogo} ${stackToneClass[item.tone]}`} aria-hidden="true">
                    <StackLogo tone={item.tone} />
                  </span>
                  {item.name}
                </span>
              ))}
            </span>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}
