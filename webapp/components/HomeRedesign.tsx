import Link from 'next/link';
import { formatNumber } from '@/lib/stats';
import styles from './HomeRedesign.module.css';

type HomeRedesignProps = {
  stars: number;
  downloads: number;
};

const coverage = ['Secrets', 'Dependencies', 'Code vulns', 'CI/CD', 'Cloud config', 'LLM security', 'Mobile', 'Agents'];

const workflows = [
  {
    label: '01',
    title: 'Scan before you ship',
    copy: 'Run local or cloud checks across code, dependencies, secrets, config, CI/CD, AI usage, and mobile risk.',
    points: ['One-command CLI', 'Hosted scan history', 'Security score'],
  },
  {
    label: '02',
    title: 'Fix what matters',
    copy: 'Prioritize the risks that can hurt your app now, then turn them into concrete fixes and team work.',
    points: ['AI remediation guidance', 'GitHub issues', 'Finding workflow'],
  },
  {
    label: '03',
    title: 'Stay ahead of new risk',
    copy: 'Track fresh advisories, security news, Reddit, Hacker News, vendor blogs, and agent signals in one place.',
    points: ['Security Intelligence', 'Breach playbooks', 'Hermes agents'],
  },
];

const signals = [
  { name: 'Exposed token pattern', value: 'Critical', tone: 'critical' },
  { name: 'Docker CVE advisory', value: 'High', tone: 'high' },
  { name: 'MCP server over HTTP', value: 'High', tone: 'high' },
  { name: 'RAG poisoning surface', value: 'Medium', tone: 'medium' },
];

export default function HomeRedesign({ stars, downloads }: HomeRedesignProps) {
  return (
    <main className={styles.page}>
      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <div className={styles.heroCopy} data-animate="left">
            <span className={styles.kicker}>Security for builders shipping fast</span>
            <h1>Know what is risky before you ship.</h1>
            <p>
              Ship Safe scans your code, dependencies, secrets, configs, CI/CD, LLM usage, and cloud exposure,
              then turns the results into fixes, reports, and security intelligence your team can act on.
            </p>
            <div className={styles.heroActions}>
              <Link href="/signup" className={styles.primaryCta}>Start free scan</Link>
              <Link href="/docs" className={styles.secondaryCta}>View docs</Link>
            </div>
            <div className={styles.installBox} aria-label="Install Ship Safe CLI">
              <span>$</span>
              <code>npx ship-safe scan</code>
            </div>
          </div>

          <div className={styles.productPreview} data-animate="right" aria-label="Ship Safe product preview">
            <div className={styles.previewTop}>
              <div>
                <span>ship-safe dashboard</span>
                <strong>Production API</strong>
              </div>
              <span className={styles.livePill}>Live scan</span>
            </div>
            <div className={styles.scorePanel}>
              <div>
                <span className={styles.panelLabel}>Security score</span>
                <strong>82</strong>
              </div>
              <div className={styles.scoreRing} aria-hidden="true">
                <span />
              </div>
            </div>
            <div className={styles.previewGrid}>
              <div className={styles.metricCard}>
                <span>Critical</span>
                <strong>2</strong>
              </div>
              <div className={styles.metricCard}>
                <span>Fixes ready</span>
                <strong>7</strong>
              </div>
              <div className={styles.metricCard}>
                <span>Agents</span>
                <strong>4</strong>
              </div>
            </div>
            <div className={styles.findingList}>
              {signals.map((signal) => (
                <div key={signal.name} className={styles.findingRow}>
                  <span className={`${styles.severityDot} ${styles[signal.tone]}`} />
                  <span>{signal.name}</span>
                  <strong>{signal.value}</strong>
                </div>
              ))}
            </div>
            <div className={styles.intelCard}>
              <span>Security Intelligence</span>
              <strong>New vendor advisory matches your dependency graph.</strong>
              <p>Recommended next: run a targeted scan and review open findings.</p>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.coverageStrip} aria-label="Ship Safe coverage">
        {coverage.map((item) => <span key={item}>{item}</span>)}
      </section>

      <section id="features" className={styles.section}>
        <div className={styles.sectionHeader} data-animate>
          <span className={styles.kicker}>Workflows, not noise</span>
          <h2>One security loop from scan to action.</h2>
          <p>Most tools stop at findings. Ship Safe helps you decide what matters, fix it, and keep watching.</p>
        </div>
        <div className={styles.workflowGrid}>
          {workflows.map((workflow) => (
            <article key={workflow.title} className={styles.workflowCard} data-animate>
              <span className={styles.workflowLabel}>{workflow.label}</span>
              <h3>{workflow.title}</h3>
              <p>{workflow.copy}</p>
              <div>
                {workflow.points.map((point) => <span key={point}>{point}</span>)}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section id="how-it-works" className={`${styles.section} ${styles.demoSection}`}>
        <div className={styles.demoCopy} data-animate="left">
          <span className={styles.kicker}>Product surface</span>
          <h2>A dashboard built for security triage.</h2>
          <p>
            See active findings, recent scans, agent runs, and fresh intelligence in one operator view.
            It is designed for repeated use, not a one-time report download.
          </p>
          <ul>
            <li>Prioritized findings with severity, confidence, and remediation context.</li>
            <li>Security Intelligence mapped to your repos and recent scans.</li>
            <li>Hermes agents for monitoring, deploy checks, and custom security workflows.</li>
          </ul>
        </div>
        <div className={styles.consoleMock} data-animate="right">
          <div className={styles.consoleHeader}>
            <span>Intelligence run</span>
            <strong>Today</strong>
          </div>
          <div className={styles.consoleBody}>
            <div className={styles.consoleLine}><span>01</span><code>collect: advisories, vendor blogs, reddit, hn</code></div>
            <div className={styles.consoleLine}><span>02</span><code>match: repos, scans, dependencies, agents</code></div>
            <div className={styles.consoleLine}><span>03</span><code>rank: urgency, relevance, confidence</code></div>
            <div className={styles.consoleResult}>
              <strong>12 relevant signals</strong>
              <p>3 high urgency items need review before your next release.</p>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.intelligenceSpotlight}>
        <div className={styles.spotlightInner}>
          <div data-animate>
            <span className={styles.kicker}>New</span>
            <h2>Security news becomes app-specific action.</h2>
            <p>
              Checking the news matters in cybersecurity. Ship Safe turns fresh incidents, CVEs, and social
              signals into ranked next steps for your own application.
            </p>
          </div>
          <div className={styles.signalStack} data-animate>
            <div><span>Fresh signal</span><strong>OAuth token leakage pattern trending today</strong></div>
            <div><span>Why it matters</span><strong>Your latest scan found two token-like secrets.</strong></div>
            <div><span>Next step</span><strong>Run a targeted scan, rotate affected credentials, review findings.</strong></div>
          </div>
        </div>
      </section>

      <section className={styles.section}>
        <div className={styles.sectionHeader} data-animate>
          <span className={styles.kicker}>Different by design</span>
          <h2>Built for small teams that actually ship.</h2>
        </div>
        <div className={styles.compareGrid}>
          <div className={styles.compareCard} data-animate>
            <h3>Traditional scanners</h3>
            <p>Long setup, disconnected alerts, generic severity, and findings that pile up after the release.</p>
            <span>Findings first</span>
            <span>Manual triage</span>
            <span>Separate tools</span>
          </div>
          <div className={`${styles.compareCard} ${styles.comparePrimary}`} data-animate>
            <h3>Ship Safe</h3>
            <p>One loop for scans, findings, fixes, agents, breach workflows, reports, and live security intelligence.</p>
            <span>App-specific priority</span>
            <span>Actionable next steps</span>
            <span>CLI plus dashboard</span>
          </div>
        </div>
      </section>

      <section className={styles.proofBand}>
        <div>
          <strong>{formatNumber(stars)}</strong>
          <span>GitHub stars</span>
        </div>
        <div>
          <strong>{formatNumber(downloads)}</strong>
          <span>npm downloads</span>
        </div>
        <div>
          <strong>MIT</strong>
          <span>open-source CLI</span>
        </div>
        <div>
          <strong>Local</strong>
          <span>core scans can run without sending code to an LLM</span>
        </div>
      </section>

      <section id="pricing" className={styles.pricingSection}>
        <div className={styles.pricingCopy} data-animate>
          <span className={styles.kicker}>Simple start</span>
          <h2>Free CLI. Cloud dashboard when you need history, teams, and automation.</h2>
          <p>
            Start with the open-source scanner. Add hosted workflows when you want reports, team review,
            agents, and Security Intelligence.
          </p>
        </div>
        <div className={styles.priceCards}>
          <div className={styles.priceCard} data-animate>
            <h3>Free CLI</h3>
            <strong>$0</strong>
            <p>Local scans, CI checks, security score, secrets, dependencies, and core app security coverage.</p>
          </div>
          <div className={`${styles.priceCard} ${styles.priceFeatured}`} data-animate>
            <h3>Cloud dashboard</h3>
            <strong>Pro</strong>
            <p>Scan history, teams, reports, AI-assisted fixes, agents, and Security Intelligence.</p>
          </div>
        </div>
      </section>

      <section className={styles.finalCta}>
        <span className={styles.kicker}>Ready when you are</span>
        <h2>Check your app before the next deploy.</h2>
        <div className={styles.heroActions}>
          <Link href="/signup" className={styles.primaryCta}>Start free scan</Link>
          <a href="https://github.com/asamassekou10/ship-safe" className={styles.secondaryCta}>View GitHub</a>
        </div>
      </section>
    </main>
  );
}
