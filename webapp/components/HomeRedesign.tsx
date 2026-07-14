import Image from 'next/image';
import Link from 'next/link';
import Hero from './Hero';
import StatsCounter from './StatsCounter';
import IntelScrolly from './IntelScrolly';
import LazyVideo from './LazyVideo';
import CursorGlow from './CursorGlow';
import CodeWindow from './CodeWindow';
import AnimatedCheck from './AnimatedCheck';
import MagneticButton from './MagneticButton';
import styles from './HomeRedesign.module.css';

type HomeRedesignProps = {
  stars: number;
  downloads: number;
};

const coverage = [
  'Secrets',
  'Dependencies',
  'Code vulns',
  'CI/CD',
  'Cloud config',
  'LLM security',
  'Mobile',
  'Agents',
  'MCP servers',
  'OWASP Agentic Top 10',
  'Container CVEs',
  'PR review',
];

const proofItems = [
  { value: 'MIT', label: 'open-source CLI' },
  { value: '28', label: 'specialized agents' },
  { value: 'SARIF', label: 'GitHub-ready output' },
  { value: 'CI', label: 'pipeline gating' },
];

const workflowSteps = [
  { label: 'Scan', detail: 'Run locally, in CI, or from the dashboard.' },
  { label: 'Triage', detail: 'Rank findings by severity, confidence, and exploitability.' },
  { label: 'Fix', detail: 'Turn issues into remediation steps and PR comments.' },
  { label: 'Guard', detail: 'Keep watching repos, dependencies, advisories, and agent config.' },
];

const compareRows = [
  { label: 'Setup time',           legacy: 'Hours of config',        ours: 'One command' },
  { label: 'Triage',               legacy: 'Manual',                  ours: 'Severity + exploitability ranked' },
  { label: 'AI / LLM coverage',    legacy: 'None or basic',           ours: 'OWASP Agentic Top 10' },
  { label: 'Local-first',          legacy: 'Cloud upload required',   ours: 'Core scans run offline' },
  { label: 'Cost',                 legacy: 'Per-seat pricing',        ours: 'Free CLI, optional cloud' },
  { label: 'Action loop',          legacy: 'PDF reports',             ours: 'CLI + dashboard + PR Guardian' },
];

const faqs = [
  {
    q: 'Does Ship Safe work without an API key?',
    a: 'Yes. All core commands (audit, scan, red-team, ci, score, deps, diff, vibe-check, benchmark, guard) work fully offline with no API key. AI classification is optional — pass --no-ai to skip it.',
  },
  {
    q: 'Is my code sent to an LLM?',
    a: 'Only if you use the agent command or omit --no-ai. When AI is used, only matched snippets are sent. Secret values are masked. The audit command with --no-ai is fully local.',
  },
  {
    q: 'How is Ship Safe different from Semgrep or Snyk?',
    a: 'Ship Safe is purpose-built for indie devs and small teams. One command covers secrets, code vulns, deps, config, CI/CD, LLM security, and mobile — no account, no config files, no dashboard to log into.',
  },
  {
    q: 'What about false positives?',
    a: 'Ship Safe has context-aware confidence tuning that automatically downgrades findings in test files, documentation, comments, and example code, reducing false positives by up to 70%.',
  },
  {
    q: 'Is the CLI always free?',
    a: 'Yes. The CLI is MIT open-source and always free. Run unlimited scans locally on any repo. The paid plans are for the hosted dashboard with history, teams, and automation.',
  },
  {
    q: 'Is it safe to run in CI?',
    a: 'Yes. Use ship-safe ci for pipeline-optimized output with threshold gating, severity-based failure, and GitHub PR comments. SARIF output is available for the GitHub Security tab.',
  },
  {
    q: 'Does Ship Safe scan Claude Managed Agents configs?',
    a: 'Yes. Ship Safe detects misconfigurations in Managed Agents definitions — unrestricted networking, always_allow permission policies, bash without human confirmation, MCP over HTTP, hardcoded vault tokens, unpinned environment packages.',
  },
  {
    q: 'Can it detect attack patterns from the Anthropic Mythos sandbox escape?',
    a: 'Yes. The Mythos escape involved privilege escalation, unrestricted network egress, and autonomous actions without approval — all mapped to the OWASP Agentic AI Top 10 controls Ship Safe covers today.',
  },
];

export default function HomeRedesign({ stars, downloads }: HomeRedesignProps) {
  return (
    <main className={styles.page}>
      {/* ── Hero ───────────────────────────────────── */}
      <Hero stars={stars} downloads={downloads} />

      {/* ── Proof strip ────────────────────────────── */}
      <section className={styles.proofStrip} aria-label="Ship Safe proof points">
        <div className={styles.proofStripInner}>
          <span className={styles.proofStripLabel}>// trusted signals</span>
          <div className={styles.proofStripGrid}>
            <div>
              <strong><StatsCounter value={stars} /></strong>
              <span>GitHub stars</span>
            </div>
            <div>
              <strong><StatsCounter value={downloads} /></strong>
              <span>npm downloads</span>
            </div>
            {proofItems.map((item) => (
              <div key={item.label}>
                <strong>{item.value}</strong>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
          <div className={styles.proofStripActions}>
            <Link href="/signup" className={styles.inlineCta}>Start free scan</Link>
            <Link href="/pricing" className={styles.inlineLink}>Compare plans</Link>
          </div>
        </div>
      </section>

      {/* ── Coverage marquee ──────────────────────── */}
      <section className={styles.marquee} aria-label="Ship Safe coverage">
        <span className={styles.marqueeLabel}>// coverage</span>
        <div className={styles.marqueeTrack}>
          <div className={styles.marqueeRow}>
            {[...coverage, ...coverage].map((item, i) => (
              <span key={`${item}-${i}`} className={styles.marqueeItem}>
                <i className={styles.marqueeDot} />
                {item}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Bento workflows ───────────────────────── */}
      <section id="features" className={styles.section}>
        <div className={styles.sectionHeader} data-animate>
          <span className={styles.sectionLabel}>// 01 — workflow</span>
          <h2>Security that stays in your workflow.</h2>
          <p>Most tools stop at findings. Ship Safe keeps the full loop connected: scan, triage, fix, and guard every release.</p>
        </div>

        <CursorGlow className={styles.bento}>
          <article className={`${styles.bentoCard} ${styles.bentoLg}`} data-glow data-animate>
            <div className={styles.bentoCopy}>
              <span className={styles.bentoStep}>01</span>
              <h3>Monitor in one command</h3>
              <p>Run the scanner locally, in CI, or in the cloud across code, deps, secrets, config, CI/CD, AI usage, and mobile risk.</p>
              <div className={styles.bentoTags}>
                <span>One-command CLI</span>
                <span>Hosted history</span>
                <span>Security score</span>
              </div>
            </div>
            <div className={styles.bentoMedia}>
              <Image
                src="/scan%20result.png"
                alt="Ship Safe scan results"
                width={2862}
                height={1386}
                sizes="(max-width: 1024px) 100vw, 1100px"
                priority
              />
            </div>
          </article>

          <article className={styles.bentoCard} data-glow data-animate>
            <span className={styles.bentoStep}>02</span>
            <h3>Root-cause with context</h3>
            <p>See why a finding matters, where it came from, what changed, and which fix should happen first.</p>
            <div className={styles.bentoTags}>
              <span>Exploitability rank</span>
              <span>GitHub issues</span>
            </div>
          </article>

          <article className={styles.bentoCard} data-glow data-animate>
            <span className={styles.bentoStep}>03</span>
            <h3>Break production less</h3>
            <p>Catch secrets, risky config, vulnerable packages, and AI-agent exposure before they become release blockers.</p>
            <div className={styles.bentoTags}>
              <span>PR checks</span>
              <span>CI gates</span>
            </div>
          </article>

          <article className={`${styles.bentoCard} ${styles.bentoMini}`} data-glow data-animate>
            <div className={styles.statBig}>
              <strong>
                <StatsCounter value={5} suffix="s" />
              </strong>
              <span>typical scan time on a mid-sized repo</span>
            </div>
          </article>

          <article className={`${styles.bentoCard} ${styles.bentoMini} ${styles.bentoAccent}`} data-glow data-animate>
            <div className={styles.statBig}>
              <strong>
                <StatsCounter value={24} />
              </strong>
              <span>specialized AI security agents working in parallel</span>
            </div>
          </article>
        </CursorGlow>

        <div className={styles.workflowRail} data-animate aria-label="Ship Safe connected workflow">
          {workflowSteps.map((step, idx) => (
            <div key={step.label} className={styles.workflowStep}>
              <span>{String(idx + 1).padStart(2, '0')}</span>
              <strong>{step.label}</strong>
              <p>{step.detail}</p>
            </div>
          ))}
        </div>
        <div className={styles.sectionCta} data-animate>
          <p>Ready to see this loop on your own repo?</p>
          <div className={styles.heroActions}>
            <Link href="/signup" className={styles.primaryCta}>Scan your repo <span aria-hidden="true">→</span></Link>
            <Link href="#get-started" className={styles.secondaryCta}>Try the CLI</Link>
          </div>
        </div>
      </section>

      {/* ── Triage / PR Guardian ──────────────────── */}
      <section className={`${styles.section} ${styles.splitSection}`}>
        <div className={styles.splitMedia} data-animate="left">
          <div className={styles.tiltedFrame}>
            <Image
              src="/PR%20Guardian.png"
              alt="Ship Safe PR Guardian automation settings"
              width={2700}
              height={1298}
              sizes="(max-width: 1024px) 100vw, 600px"
            />
            <div className={styles.floatBadge}>
              <span className={styles.floatBadgeLabel}>blocked</span>
              <strong>Hardcoded API key in src/api/upload.ts</strong>
            </div>
          </div>
        </div>
        <div className={styles.splitCopy} data-animate="right">
          <span className={styles.sectionLabel}>// 02 — triage</span>
          <h2>Catch risk before it merges.</h2>
          <p>
            PR Guardian turns scan context into pull-request automation: risky lines, dependency changes,
            AI-agent config, fix hints, and threshold gates beside the code reviewers are already reading.
          </p>
          <ul className={styles.checkList}>
            <li>Inline comments on the exact lines that introduce risk.</li>
            <li>Severity, confidence, and a one-line remediation hint.</li>
            <li>Threshold gates that fail the check, not just warn.</li>
          </ul>
          <div className={styles.heroActions}>
            <Link href="/signup" className={styles.primaryCta}>Set up PR Guardian <span aria-hidden="true">→</span></Link>
            <Link href="/docs" className={styles.secondaryCta}>Read CI docs</Link>
          </div>
        </div>
      </section>

      {/* ── Intelligence (scroll-pinned) ─────────── */}
      <IntelScrolly />

      {/* ── Hermes Agents ─────────────────────────── */}
      <section className={`${styles.section} ${styles.splitSection} ${styles.splitReverse}`}>
        <div className={styles.splitCopy} data-animate="left">
          <span className={styles.sectionLabel}>// 04 — hermes</span>
          <h2>Custom agents for your security workflows.</h2>
          <p>
            Compose agent teams for deploy checks, anomaly investigation, monitoring, and incident
            response. Ship Safe coordinates the runs, you write the playbook.
          </p>
          <div className={styles.heroActions}>
            <Link href="/hermes" className={styles.secondaryCta}>Explore Hermes →</Link>
          </div>
        </div>
        <div className={styles.splitMedia} data-animate="right">
          <div className={styles.videoFrame}>
            <LazyVideo
              src="/demo%20hermes%20agents.mp4"
              poster="/Agent%20Team.png"
              ariaLabel="Hermes agent team demo"
            />
          </div>
        </div>
      </section>

      {/* ── Output: real CLI terminal + serif manifesto ─── */}
      <section className={styles.outputSection} id="get-started">
        <div className={styles.outputInner}>
          <div className={styles.outputHead} data-animate>
            <span className={styles.sectionLabel}>// 05 — get started</span>
            <p className={styles.outputLead}>
              Five seconds to your first security report.
            </p>
            <h2>Run locally before you connect anything.</h2>
            <p className={styles.outputBlurb}>
              Start with <code>npx ship-safe scan</code>. Add <code>--sarif</code>, <code>--github-pr</code>,
              or <code>--fail-on critical</code> when you are ready to wire the same signal into CI.
            </p>
            <div className={styles.heroActions}>
              <Link href="/docs" className={styles.secondaryCta}>Open setup docs</Link>
              <Link href="/signup" className={styles.primaryCta}>Save scan history <span aria-hidden="true">→</span></Link>
            </div>
          </div>
          <div className={styles.outputMedia} data-animate>
            <CodeWindow />
          </div>
        </div>
      </section>

      {/* ── Comparison table ──────────────────────── */}
      <section className={styles.section}>
        <div className={styles.sectionHeader} data-animate>
          <span className={styles.sectionLabel}>// 06 — different by design</span>
          <h2>Built for teams that actually ship.</h2>
        </div>

        <CursorGlow className={styles.compareTable}>
          <div className={styles.compareHead}>
            <span />
            <span>Traditional scanners</span>
            <span className={styles.compareUs}>Ship Safe</span>
          </div>
          {compareRows.map((row, i) => (
            <div key={row.label} data-glow className={styles.compareRow} style={{ transitionDelay: `${i * 60}ms` }}>
              <span className={styles.compareLabel}>{row.label}</span>
              <span className={styles.compareLegacy}>
                <AnimatedCheck variant="cross" delay={120 + i * 90} />
                {row.legacy}
              </span>
              <span className={styles.compareOurs}>
                <AnimatedCheck variant="check" delay={300 + i * 90} />
                {row.ours}
              </span>
            </div>
          ))}
        </CursorGlow>
      </section>

      {/* ── Stats band ────────────────────────────── */}
      <section className={styles.statsBand} data-animate>
        <div>
          <strong><StatsCounter value={stars} /></strong>
          <span>GitHub stars</span>
        </div>
        <div>
          <strong><StatsCounter value={downloads} /></strong>
          <span>npm downloads</span>
        </div>
        <div>
          <strong>28</strong>
          <span>AI security agents</span>
        </div>
        <div>
          <strong>MIT</strong>
          <span>Open-source CLI</span>
        </div>
      </section>

      {/* ── Pricing teaser (thin) ─────────────────── */}
      <section id="pricing" className={styles.pricingTeaser}>
        <div className={styles.pricingTeaserInner}>
          <div data-animate>
            <span className={styles.sectionLabel}>// 07 — pricing</span>
            <h2>Free CLI. Cloud when you need it.</h2>
            <p>Start with the open-source scanner. Add the hosted dashboard for history, teams, agents, and Security Intelligence.</p>
            <div className={styles.heroActions}>
              <Link href="/signup" className={styles.primaryCta}>Start with cloud <span aria-hidden="true">→</span></Link>
              <Link href="/pricing" className={styles.secondaryCta}>View pricing</Link>
            </div>
          </div>
          <div className={styles.pricingCards}>
            <div className={styles.priceCard} data-animate>
              <h3>Free CLI</h3>
              <strong>$0</strong>
              <p>Local scans, CI checks, security score, secrets, dependencies, and core app coverage.</p>
              <Link href="/docs" className={styles.priceLink}>Read the docs →</Link>
            </div>
            <div className={`${styles.priceCard} ${styles.priceFeatured}`} data-animate>
              <h3>Cloud</h3>
              <strong>Pro</strong>
              <p>Scan history, teams, AI-assisted fixes, agents, PR Guardian, and Security Intelligence.</p>
              <Link href="/pricing" className={styles.priceLink}>See plans →</Link>
            </div>
          </div>
          <div className={styles.dashboardPreview} data-animate>
            <Image
              src="/Dashboard.png"
              alt="Ship Safe hosted dashboard overview"
              width={2458}
              height={1280}
              sizes="(max-width: 1024px) 100vw, 760px"
            />
          </div>
        </div>
      </section>

      {/* ── FAQ ───────────────────────────────────── */}
      <section className={styles.faqSection}>
        <div className={styles.faqInner}>
          <div className={styles.faqHead} data-animate>
            <span className={styles.sectionLabel}>// 08 — faq</span>
            <h2>Questions, answered.</h2>
            <p>Everything we get asked most. Still curious? <Link href="/docs">Read the docs</Link>.</p>
          </div>
          <CursorGlow className={styles.faqList}>
            {faqs.map((item) => (
              <details key={item.q} data-glow className={styles.faqItem}>
                <summary>
                  <span>{item.q}</span>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9l6 6 6-6" /></svg>
                </summary>
                <div className={styles.faqAnswer}>{item.a}</div>
              </details>
            ))}
          </CursorGlow>
        </div>
      </section>

      {/* ── Final CTA (full-bleed) ────────────────── */}
      <section className={styles.finalCta}>
        <div className={styles.finalBg} aria-hidden="true">
          <div className={styles.mesh} />
        </div>
        <div className={styles.finalInner}>
          <span className={styles.statusPill}><i /> Ready when you are</span>
          <h2>Check your app before the next deploy.</h2>
          <div className={styles.finalCommand}>
            <span>$</span>
            <code>npx ship-safe scan</code>
          </div>
          <div className={styles.heroActions}>
            <MagneticButton>
              <Link href="/signup" className={styles.primaryCta}>Start free scan <span aria-hidden="true">→</span></Link>
            </MagneticButton>
            <a href="https://github.com/asamassekou10/ship-safe" className={styles.secondaryCta}>View on GitHub</a>
          </div>
        </div>
      </section>
    </main>
  );
}
