import Nav from '@/components/Nav';
import Link from 'next/link';
import VideoEmbed from '@/components/VideoEmbed';
import CursorGlow from '@/components/CursorGlow';
import MagneticButton from '@/components/MagneticButton';
import ScrollAnimator from '@/components/ScrollAnimator';
import styles from './hermes.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/og1.png';

export const metadata: Metadata = {
  title: 'Hermes Agent Security — Ship Safe',
  description: 'Harden your Hermes agent against tool poisoning, function-call injection, and memory attacks. Answer 4 questions, get one setup command, deploy 29 security agents.',
  keywords: ['Hermes agent security', 'Hermes tool poisoning', 'function-call injection', 'LLM agent security', 'Hermes framework hardening', 'agentic security', 'AI agent security'],
  alternates: {
    canonical: 'https://www.shipsafecli.com/hermes',
  },
  openGraph: {
    title: 'Hermes Agent Security — Ship Safe',
    description: 'Harden your Hermes agent against tool poisoning, function-call injection, and memory attacks in one command.',
    type: 'website',
    url: 'https://www.shipsafecli.com/hermes',
    siteName: 'Ship Safe',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Hermes Agent Security' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Hermes Agent Security — Ship Safe',
    description: 'Harden your Hermes agent against tool poisoning, function-call injection, and memory attacks in one command.',
    images: [ogImage],
  },
};

const STEPS = [
  { n: '1', title: 'Answer 4 questions',  desc: 'Project name, your registered tools (from tools/registry.py), which memory provider you use, and whether you use delegate_task. Takes under a minute.' },
  { n: '2', title: 'Get your setup command', desc: 'Ship Safe generates a one-time command. Nothing is uploaded — the config is encoded in the URL itself.' },
  { n: '3', title: 'Run one command',    desc: 'npx ship-safe init --hermes --from <url> writes all files, generates integrity hashes, and runs your first audit.' },
  { n: '4', title: 'CI guards every PR', desc: 'The generated workflow posts a security score on every pull request and fails if your score drops below baseline.' },
];

const FILES = [
  { path: 'agent-manifest.json',                 desc: 'Ship Safe security manifest — tool allowlist, integrity hashes, MAX_DEPTH enforcement. Complements your ~/.hermes/config.yaml.', color: 'cyan' },
  { path: '.ship-safe/agents/hermes-policy.js',  desc: 'Custom security agent — enforces your allowlist and runs on every ship-safe audit automatically.', color: 'green' },
  { path: '.ship-safe/hermes-baseline.json',     desc: 'Baseline score. CI fails any PR that drops below it.', color: 'yellow' },
  { path: '.github/workflows/ship-safe-hermes.yml', desc: 'GitHub Actions workflow — audits on every PR and posts a score comment.', color: 'cyan' },
];

const THREATS = [
  {
    accent: 'red',
    rule: 'HERMES_TOOL_NO_INTEGRITY',
    title: 'Tool registry poisoning',
    body: 'Hermes loads tools via registry.register() at import time. A compromised dependency or malicious MCP tool can register under a trusted name. Without integrity checks, your agent calls it without question.',
  },
  {
    accent: 'yellow',
    rule: 'HERMES_FUNCTION_CALL_NO_ALLOWLIST',
    title: 'Function-call injection',
    body: 'A prompt injection tricks your agent into calling registry.dispatch() with an attacker-chosen tool name. Hermes has 30+ registered tools — without an allowlist check, any of them can be invoked.',
  },
  {
    accent: 'cyan',
    rule: 'HERMES_MEMORY_INJECTION',
    title: 'Memory poisoning',
    body: 'Hermes injects MEMORY.md and USER.md into the system prompt at session start. Poisoned entries — via prompt injection patterns or invisible unicode — can hijack the agent’s behavior across all future sessions.',
  },
];

export default function HermesPage() {
  return (
    <>
      <ScrollAnimator />
      <Nav />
      <main className={styles.page}>
        {/* ── Hero ──────────────────────────────────── */}
        <section className={styles.hero}>
          <div className={styles.heroInner}>
            <span className={styles.statusPill}>
              <i /> 23 Hermes security agents
            </span>
            <h1>
              Secure your Hermes agent <span className={styles.gradientText}>before it ships.</span>
            </h1>
            <p>
              Hermes agents are powerful — and exposed to three attack classes your code won&apos;t catch on its own.
              Answer 4 questions and get a hardened config bundle dropped straight into your project.
            </p>
            <div className={styles.heroCommand}>
              <span>$</span>
              <code>npx ship-safe init --hermes --from shipsafecli.com/s/&lt;token&gt;</code>
            </div>
            <div className={styles.actions}>
              <MagneticButton>
                <Link href="/signup" className={styles.primaryCta}>
                  Secure my agent <span aria-hidden="true">→</span>
                </Link>
              </MagneticButton>
              <Link href="/blog/hermes-agent-security-tool-registry-poisoning-function-call-injection" className={styles.secondaryCta}>
                Read the threat breakdown
              </Link>
            </div>
          </div>
        </section>

        {/* ── Deploy video ──────────────────────────── */}
        <section className={styles.videoSection}>
          <div className={styles.videoFrame} data-animate>
            <VideoEmbed
              videoId="nGH1chUHzKQ"
              title="Deploy Hermes agents in a few seconds - Ship Safe"
              format="landscape"
              caption="Deploy a hardened Hermes agent in seconds"
            />
          </div>
        </section>

        {/* ── New to Hermes? (split) ────────────────── */}
        <section className={styles.section}>
          <div className={styles.explainer}>
            <div className={styles.explainerCopy} data-animate="left">
              <span className={styles.sectionLabel}>// 01 — context</span>
              <h2>New to Hermes?</h2>
              <p>
                <strong>Hermes</strong> is an open-source agent framework by <strong>Nous Research</strong> with 30+ toolsets
                {' '}(<code>web_search</code>, <code>terminal</code>, <code>browser_navigate</code>, <code>delegate_task</code>, and more),
                pluggable memory providers (built-in MEMORY.md/USER.md, Honcho, Mem0), and subagent delegation via <code>delegate_task</code>.
              </p>
              <p>
                Every tool dispatch through <code>registry.dispatch()</code>, every memory write to MEMORY.md,
                and every subagent spawn is an attack surface. Ship Safe audits all three — automatically, on every PR.
              </p>
            </div>
            <div className={styles.explainerCode} data-animate="right">
              <div className={styles.codeChrome}>
                <span /><span /><span />
                <strong>agent-manifest.json</strong>
              </div>
              <pre className={styles.codeBody}>
                <code>{`{
  "tools": [
    { "name": "web_search",
      "integrity": "sha256-abc..." },
    { "name": "terminal",
      "integrity": "sha256-xyz..." }
  ],
  "security": {
    "allowlist": ["web_search", "terminal"],
    "requireIntegrity": true,
    "maxRecursionDepth": 2
  }
}`}</code>
              </pre>
            </div>
          </div>
        </section>

        {/* ── 3 attack classes ──────────────────────── */}
        <section className={styles.section}>
          <div className={styles.sectionHeader} data-animate>
            <span className={styles.sectionLabel}>// 02 — threats</span>
            <h2>Three attacks your agent is exposed to right now.</h2>
            <p>These don&apos;t require a breach. They exploit the trust your agent places in its own tools, inputs, and memory.</p>
          </div>

          <CursorGlow className={styles.threatGrid}>
            {THREATS.map((t, i) => (
              <article
                key={t.rule}
                data-glow
                data-animate
                data-delay={String(i * 70)}
                className={`${styles.threatCard} ${styles[`accent_${t.accent}`]}`}
              >
                <span className={styles.threatTag}>{t.rule}</span>
                <h3>{t.title}</h3>
                <p>{t.body}</p>
                <span className={styles.threatFoot}>Detected by Ship Safe</span>
              </article>
            ))}
          </CursorGlow>
        </section>

        {/* ── How it works ──────────────────────────── */}
        <section className={styles.section}>
          <div className={styles.sectionHeader} data-animate>
            <span className={styles.sectionLabel}>// 03 — flow</span>
            <h2>From zero to hardened in one command.</h2>
            <p>No code uploaded. No config files to learn. Just answers to 4 questions.</p>
          </div>

          <CursorGlow className={styles.stepsRow}>
            {STEPS.map((s, i) => (
              <div
                key={s.n}
                data-glow
                data-animate
                data-delay={String(i * 60)}
                className={styles.stepCard}
              >
                <span className={styles.stepNum}>{s.n}</span>
                <h3>{s.title}</h3>
                <p>{s.desc}</p>
              </div>
            ))}
          </CursorGlow>
        </section>

        {/* ── What gets generated ───────────────────── */}
        <section className={styles.section}>
          <div className={styles.sectionHeader} data-animate>
            <span className={styles.sectionLabel}>// 04 — output</span>
            <h2>What gets generated.</h2>
            <p>Everything drops into your project at the correct paths. No manual placement.</p>
          </div>

          <CursorGlow className={styles.fileGrid}>
            {FILES.map((f, i) => (
              <div
                key={f.path}
                data-glow
                data-animate
                data-delay={String(i * 60)}
                className={`${styles.fileCard} ${styles[`accent_${f.color}`]}`}
              >
                <code className={styles.filePath}>{f.path}</code>
                <p>{f.desc}</p>
              </div>
            ))}
          </CursorGlow>
        </section>

        {/* ── Final CTA ─────────────────────────────── */}
        <section className={styles.finalCta}>
          <div className={styles.finalBg} aria-hidden="true">
            <div className={styles.mesh} />
          </div>
          <div className={styles.finalInner}>
            <span className={styles.statusPill}><i /> Free for the first scan</span>
            <h2>Ready to harden your agent?</h2>
            <div className={styles.actions}>
              <MagneticButton>
                <Link href="/signup" className={styles.primaryCta}>
                  Get started free <span aria-hidden="true">→</span>
                </Link>
              </MagneticButton>
              <Link href="/app/deploy" className={styles.secondaryCta}>
                Already signed in? Open the deploy wizard
              </Link>
            </div>
          </div>
        </section>
      </main>
    </>
  );
}
