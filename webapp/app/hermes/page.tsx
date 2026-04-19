import Nav from '@/components/Nav';
import Link from 'next/link';
import styles from './hermes.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://shipsafecli.com/api/og?title=Hermes+Agent+Security&description=Harden+your+Hermes+agent+against+tool+poisoning%2C+function-call+injection%2C+and+memory+attacks+in+one+command.&label=Hermes+Security&badge=22+security+agents';

export const metadata: Metadata = {
  title: 'Hermes Agent Security — Ship Safe',
  description: 'Harden your Hermes agent against tool poisoning, function-call injection, and memory attacks. Answer 4 questions, get one setup command, deploy 23 security agents.',
  keywords: ['Hermes agent security', 'Hermes tool poisoning', 'function-call injection', 'LLM agent security', 'Hermes framework hardening', 'agentic security', 'AI agent security'],
  alternates: {
    canonical: 'https://shipsafecli.com/hermes',
  },
  openGraph: {
    title: 'Hermes Agent Security — Ship Safe',
    description: 'Harden your Hermes agent against tool poisoning, function-call injection, and memory attacks in one command.',
    type: 'website',
    url: 'https://shipsafecli.com/hermes',
    siteName: 'Ship Safe',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Hermes Agent Security' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Hermes Agent Security — Ship Safe',
    description: 'Harden your Hermes agent against tool poisoning, function-call injection, and memory attacks in one command.',
    images: [ogImage],
  },
};

export default function HermesPage() {
  return (
    <>
      <Nav />
      <main className={styles.main}>

        {/* ── Hero ── */}
        <section className={styles.hero}>
          <>
            <div className={styles.heroBadge}>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
              22 Hermes security agents
            </div>
            <h1 className={styles.heroTitle}>
              Secure your Hermes agent<br />
              <span className={styles.heroAccent}>before it ships.</span>
            </h1>
            <p className={styles.heroSub}>
              Hermes agents are powerful — and exposed to three attack classes your code won&apos;t catch on its own.
              Answer 4 questions and get a hardened config bundle dropped straight into your project.
            </p>
            <div className={styles.heroCommand}>
              <code>npx ship-safe init --hermes --from shipsafecli.com/s/&lt;token&gt;</code>
            </div>
            <div className={styles.heroActions}>
              <Link href="/signup" className="btn btn-primary">
                Secure my agent →
              </Link>
              <Link href="/blog/hermes-agent-security-tool-registry-poisoning-function-call-injection" className={styles.heroLearn}>
                Read the threat breakdown
              </Link>
            </div>
          </>
        </section>

        {/* ── What is Hermes? ── */}
        <section className={styles.section}>
          <>
            <div className={styles.explainer}>
              <div className={styles.explainerText}>
                <h2>New to Hermes?</h2>
                <p>
                  <strong>Hermes</strong> is an open-source agent framework by <strong>Nous Research</strong> with 30+ toolsets
                  (<code>web_search</code>, <code>terminal</code>, <code>browser_navigate</code>, <code>delegate_task</code>, and more),
                  pluggable memory providers (built-in MEMORY.md/USER.md, Honcho, Mem0),
                  and subagent delegation via <code>delegate_task</code>.
                </p>
                <p>
                  Every tool dispatch through <code>registry.dispatch()</code>, every memory write to
                  MEMORY.md, and every subagent spawn is an attack surface. Ship Safe audits all three —
                  automatically, on every PR.
                </p>
              </div>
              <div className={styles.explainerCode}>
                <div className={styles.codeFile}>agent-manifest.json (Ship Safe security manifest)</div>
                <pre className={styles.codePre}>{`{
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
}`}</pre>
              </div>
            </div>
          </>
        </section>

        {/* ── 3 Attack Classes ── */}
        <section className={styles.section}>
          <>
            <div className={styles.sectionHeader}>
              <h2>Three attacks your agent is exposed to right now</h2>
              <p>These don&apos;t require a breach. They exploit the trust your agent places in its own tools, inputs, and memory.</p>
            </div>
            <div className={styles.threatGrid}>
              <div className={styles.threatCard}>
                <div className={`${styles.threatIcon} ${styles.red}`}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                </div>
                <h3>Tool registry poisoning</h3>
                <p>
                  Hermes loads tools via <code>registry.register()</code> at import time. A compromised dependency or
                  malicious MCP tool can register under a trusted name. Without integrity checks, your agent calls it without question.
                </p>
                <div className={styles.threatRule}>
                  <span className={styles.ruleTag}>HERMES_TOOL_NO_INTEGRITY</span>
                  Detected by Ship Safe
                </div>
              </div>

              <div className={styles.threatCard}>
                <div className={`${styles.threatIcon} ${styles.yellow}`}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14.5 2v6.5L18 12l-3.5 3.5V22"/><path d="M9.5 2v6.5L6 12l3.5 3.5V22"/></svg>
                </div>
                <h3>Function-call injection</h3>
                <p>
                  A prompt injection tricks your agent into calling <code>registry.dispatch()</code> with an attacker-chosen tool name.
                  Hermes has 30+ registered tools — without an allowlist check, any of them can be invoked.
                </p>
                <div className={styles.threatRule}>
                  <span className={styles.ruleTag}>HERMES_FUNCTION_CALL_NO_ALLOWLIST</span>
                  Detected by Ship Safe
                </div>
              </div>

              <div className={styles.threatCard}>
                <div className={`${styles.threatIcon} ${styles.cyan}`}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                </div>
                <h3>Memory poisoning</h3>
                <p>
                  Hermes injects MEMORY.md and USER.md into the system prompt at session start.
                  Poisoned entries — via prompt injection patterns or invisible unicode — can hijack the agent&apos;s behavior across all future sessions.
                </p>
                <div className={styles.threatRule}>
                  <span className={styles.ruleTag}>HERMES_MEMORY_INJECTION</span>
                  Detected by Ship Safe
                </div>
              </div>
            </div>
          </>
        </section>

        {/* ── How it works ── */}
        <section className={styles.section}>
          <>
            <div className={styles.sectionHeader}>
              <h2>From zero to hardened in one command</h2>
              <p>No code uploaded. No config files to learn. Just answers to 4 questions.</p>
            </div>
            <div className={styles.stepsRow}>
              {[
                {
                  n: '1',
                  title: 'Answer 4 questions',
                  desc: 'Project name, your registered tools (from tools/registry.py), which memory provider you use, and whether you use delegate_task. Takes under a minute.',
                },
                {
                  n: '2',
                  title: 'Get your setup command',
                  desc: 'Ship Safe generates a one-time command. Nothing is uploaded — the config is encoded in the URL itself.',
                },
                {
                  n: '3',
                  title: 'Run one command',
                  desc: 'npx ship-safe init --hermes --from <url> writes all files, generates integrity hashes, and runs your first audit.',
                },
                {
                  n: '4',
                  title: 'CI guards every PR',
                  desc: 'The generated workflow posts a security score on every pull request and fails if your score drops below baseline.',
                },
              ].map(s => (
                <div key={s.n} className={styles.stepCard}>
                  <div className={styles.stepNum}>{s.n}</div>
                  <h3>{s.title}</h3>
                  <p>{s.desc}</p>
                </div>
              ))}
            </div>
          </>
        </section>

        {/* ── What you get ── */}
        <section className={styles.section}>
          <>
            <div className={styles.sectionHeader}>
              <h2>What gets generated</h2>
              <p>Everything drops into your project at the correct paths. No manual placement.</p>
            </div>
            <div className={styles.fileGrid}>
              {[
                {
                  path: 'agent-manifest.json',
                  desc: 'Ship Safe security manifest — tool allowlist, integrity hashes, MAX_DEPTH enforcement. Complements your ~/.hermes/config.yaml.',
                  color: 'cyan',
                },
                {
                  path: '.ship-safe/agents/hermes-policy.js',
                  desc: 'Custom security agent — enforces your allowlist and runs on every ship-safe audit automatically.',
                  color: 'green',
                },
                {
                  path: '.ship-safe/hermes-baseline.json',
                  desc: 'Baseline score. CI fails any PR that drops below it.',
                  color: 'yellow',
                },
                {
                  path: '.github/workflows/ship-safe-hermes.yml',
                  desc: 'GitHub Actions workflow — audits on every PR and posts a score comment.',
                  color: 'cyan',
                },
              ].map(f => (
                <div key={f.path} className={styles.fileCard}>
                  <div className={`${styles.fileBar} ${styles[f.color]}`} />
                  <div className={styles.fileCardInner}>
                    <code className={styles.filePath}>{f.path}</code>
                    <p className={styles.fileDesc}>{f.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </>
        </section>

        {/* ── CTA ── */}
        <section className={styles.ctaSection}>
          <>
            <h2>Ready to harden your agent?</h2>
            <p>Free for the first scan. No credit card required.</p>
            <Link href="/signup" className="btn btn-primary">
              Get started free →
            </Link>
            <div className={styles.ctaNote}>
              Already have an account?{' '}
              <Link href="/app/deploy">Go to the deploy wizard →</Link>
            </div>
          </>
        </section>

      </main>
    </>
  );
}
