import type { Metadata } from 'next';
import Link from 'next/link';
import styles from './guide.module.css';

const canonicalUrl = 'https://www.shipsafecli.com/app/guide';
const title = 'Ship Safe Web App Guide — Scan, Triage, and Fix Security Findings';
const description = 'Step-by-step Ship Safe web app guide for setting up AI security scanning, running repository scans, triaging findings, creating GitHub issues, and enabling continuous protection.';

export const metadata: Metadata = {
  title,
  description,
  keywords: [
    'Ship Safe guide',
    'AI security scanner tutorial',
    'repository security scan guide',
    'MCP security scanner web app',
    'LLM security findings workflow',
    'GitHub issue security remediation',
    'PR Guardian setup',
    'AI agent security dashboard',
  ],
  alternates: {
    canonical: canonicalUrl,
  },
  openGraph: {
    title,
    description,
    url: canonicalUrl,
    type: 'article',
    siteName: 'Ship Safe CLI',
    images: [
      {
        url: 'https://www.shipsafecli.com/guide/dashboard-overview.jpg',
        width: 1280,
        height: 720,
        alt: 'Ship Safe web app dashboard and security findings guide',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title,
    description,
    images: ['https://www.shipsafecli.com/guide/dashboard-overview.jpg'],
  },
};

const quickSteps = [
  { number: '01', title: 'Set up the account', body: 'Choose an AI provider, connect GitHub, and select the alerts you need.', href: '/app/settings' },
  { number: '02', title: 'Run the baseline', body: 'Scan a repository with the recommended checks before changing advanced options.', href: '/app/scan' },
  { number: '03', title: 'Triage the evidence', body: 'Open critical and high findings, then acknowledge or dismiss each signal.', href: '/app/findings?status=open' },
  { number: '04', title: 'Assign the work', body: 'Copy the fix, create a GitHub issue, or send complex evidence to an agent.', href: '#actions' },
  { number: '05', title: 'Verify the fix', body: 'Rescan the same repository and only close findings after the evidence clears.', href: '/app/history' },
  { number: '06', title: 'Keep it protected', body: 'Add monitoring, PR Guardian, and focused agents after the first baseline.', href: '/app/repos' },
];

const accountSteps = [
  { title: 'Confirm profile and plan', body: 'Check the signed-in identity and which cloud features are available.', href: '/app/settings#profile' },
  { title: 'Choose an AI provider', body: 'Select the model used for analysis and store its key securely.', href: '/app/settings#ai-models' },
  { title: 'Connect GitHub', body: 'Add a token so Ship Safe can create issues from verified findings.', href: '/app/settings#integrations' },
  { title: 'Set alerts and CI access', body: 'Choose useful notifications and create an API key only when CI needs one.', href: '/app/settings#notifications' },
];

const guideJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'HowTo',
  name: 'How to use the Ship Safe web app',
  description,
  url: canonicalUrl,
  image: 'https://www.shipsafecli.com/guide/dashboard-overview.jpg',
  totalTime: 'PT15M',
  tool: [
    { '@type': 'HowToTool', name: 'Ship Safe web app' },
    { '@type': 'HowToTool', name: 'Ship Safe CLI' },
    { '@type': 'HowToTool', name: 'GitHub repository' },
  ],
  step: quickSteps.map((step, index) => ({
    '@type': 'HowToStep',
    position: index + 1,
    name: step.title,
    text: step.body,
    url: `${canonicalUrl}${step.href.startsWith('#') ? step.href : ''}`,
  })),
};

export default function GuidePage() {
  return (
    <div className={styles.page}>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(guideJsonLd) }}
      />
      <header className={styles.hero}>
        <div>
          <span className={styles.eyebrow}>Ship Safe field guide</span>
          <h1>From first scan to continuous protection.</h1>
          <p>Follow one practical workflow, then use the deeper guides when your team is ready for monitoring, PR checks, and AI agents.</p>
        </div>
        <div className={styles.heroActions}>
          <Link href="/app/scan" className={styles.primaryAction}>Run your first scan <span aria-hidden="true">→</span></Link>
          <a href="#quick-start" className={styles.secondaryAction}>View the steps</a>
        </div>
      </header>

      <nav className={styles.chapterNav} aria-label="Guide chapters">
        <a href="#quick-start">Quick start</a>
        <a href="#account">Account</a>
        <a href="#dashboard">Dashboard</a>
        <a href="#scan">Scan</a>
        <a href="#actions">Take action</a>
        <a href="#automation">Automation</a>
        <a href="#agents">Agents</a>
      </nav>

      <section id="quick-start" className={styles.quickStart}>
        <div className={styles.sectionHeading}>
          <span className={styles.eyebrow}>Six-step workflow</span>
          <h2>Your first secure baseline</h2>
          <p>Complete these in order. Each step leaves the workspace in a useful state, so you can stop and return later.</p>
        </div>
        <ol className={styles.stepGrid}>
          {quickSteps.map(step => (
            <li key={step.number}>
              <span className={styles.stepNumber}>{step.number}</span>
              <div>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
                <Link href={step.href}>Open workflow <span aria-hidden="true">→</span></Link>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section id="account" className={styles.accountSection}>
        <div className={styles.sectionHeading}>
          <span className={styles.eyebrow}>00 / Configure</span>
          <h2>Set up the account once.</h2>
          <p>Start with the integrations that unlock the workflow. You can add advanced alerts and CI access later.</p>
        </div>
        <div className={styles.accountLayout}>
          <ol className={styles.accountSteps}>
            {accountSteps.map((step, index) => (
              <li key={step.title}>
                <span>{String(index + 1).padStart(2, '0')}</span>
                <div>
                  <h3>{step.title}</h3>
                  <p>{step.body}</p>
                  <Link href={step.href}>Open setting <span aria-hidden="true">→</span></Link>
                </div>
              </li>
            ))}
          </ol>
          <figure className={styles.mediaFrame}>
            <video controls autoPlay loop muted playsInline preload="auto" poster="/guide/account-setup.jpg">
              <source src="/guide/account-setup-walkthrough.mp4" type="video/mp4" />
            </video>
            <figcaption>Profile, AI model, GitHub integration, and notification setup without exposing secret values.</figcaption>
          </figure>
        </div>
        <div className={styles.setupNote}>
          <strong>Minimum useful setup</strong>
          <span>An AI provider is optional for core scanning. GitHub is only required for private repositories and issue creation.</span>
        </div>
      </section>

      <section id="dashboard" className={styles.featureSection}>
        <div className={styles.copy}>
          <span className={styles.eyebrow}>01 / Orient</span>
          <h2>Read the workspace in under a minute.</h2>
          <p>The dashboard answers three questions first: what needs attention, whether risk is improving, and which repositories are protected.</p>
          <ul>
            <li>Start with the recommended next step.</li>
            <li>Use the severity chart to enter a focused findings queue.</li>
            <li>Check repository posture before enabling automation.</li>
          </ul>
          <Link href="/app">Open dashboard <span aria-hidden="true">→</span></Link>
        </div>
        <figure className={styles.mediaFrame}>
          <img src="/guide/dashboard-overview.jpg" alt="Ship Safe dashboard showing priority findings and workspace posture" />
          <figcaption>Security overview uses real scan, finding, repository, and agent data.</figcaption>
        </figure>
      </section>

      <section id="scan" className={`${styles.featureSection} ${styles.reverse}`}>
        <div className={styles.copy}>
          <span className={styles.eyebrow}>02 / Scan</span>
          <h2>Start with the recommended profile.</h2>
          <p>Choose the target and run the default checks before opening advanced settings. This gives you a consistent baseline that is easier to compare later.</p>
          <div className={styles.callout}>
            <strong>Local-first option</strong>
            <code>npx ship-safe audit .</code>
            <span>Use the CLI when source code must remain on the machine.</span>
          </div>
          <Link href="/app/scan">Create a scan <span aria-hidden="true">→</span></Link>
        </div>
        <figure className={styles.mediaFrame}>
          <video controls autoPlay loop muted playsInline preload="auto" poster="/guide/scan-wide-00-repository.jpg">
            <source src="/guide/real-repository-scan.mp4" type="video/mp4" />
            Your browser does not support the Ship Safe repository scan walkthrough.
          </video>
          <figcaption>A real scan of OWASP NodeGoat, from GitHub URL to prioritized findings.</figcaption>
        </figure>
      </section>

      <section id="findings" className={styles.resultSection}>
        <div className={styles.sectionHeading}>
          <span className={styles.eyebrow}>03 / Remediate</span>
          <h2>Move from signal to verified fix.</h2>
          <p>Filter first, inspect the evidence, apply the smallest safe change, and rescan before closing the finding.</p>
        </div>
        <figure className={styles.wideMedia}>
          <video controls autoPlay loop muted playsInline preload="auto" poster="/guide/findings-inbox.jpg">
            <source src="/guide/security-workflow-walkthrough.mp4" type="video/mp4" />
          </video>
        </figure>
        <div className={styles.workflowLine} aria-label="Finding workflow">
          <span>Prioritize</span><i aria-hidden="true" />
          <span>Inspect evidence</span><i aria-hidden="true" />
          <span>Fix</span><i aria-hidden="true" />
          <span>Rescan</span><i aria-hidden="true" />
          <span>Close</span>
        </div>
        <Link href="/app/findings?status=open" className={styles.inlineAction}>Open findings inbox <span aria-hidden="true">→</span></Link>
      </section>

      <section id="actions" className={styles.actionSection}>
        <div className={styles.sectionHeading}>
          <span className={styles.eyebrow}>04 / Act</span>
          <h2>Turn the finding into owned work.</h2>
          <p>Choose the lightest action that moves the risk forward. The scan remains the source of evidence; GitHub or an agent becomes the place where the work continues.</p>
        </div>
        <div className={styles.actionLayout}>
          <figure className={styles.mediaFrame}>
            <video controls autoPlay loop muted playsInline preload="auto" poster="/guide/finding-actions.jpg">
              <source src="/guide/finding-actions-walkthrough.mp4" type="video/mp4" />
            </video>
            <figcaption>Expand a finding, preserve its triage state, and preview a GitHub issue before creating it.</figcaption>
          </figure>
          <div className={styles.actionChoices}>
            <article><span>01</span><div><h3>Acknowledge</h3><p>Use when the signal is valid and has been accepted into the team&apos;s work.</p></div></article>
            <article><span>02</span><div><h3>Copy the fix</h3><p>Move the recommended remediation into the editor or the existing work item.</p></div></article>
            <article><span>03</span><div><h3>Create an issue</h3><p>Send the evidence, location, rule, and fix to the repository with one confirmation.</p></div></article>
            <article><span>04</span><div><h3>Investigate</h3><p>Use a deployed security agent when the evidence needs deeper analysis.</p></div></article>
          </div>
        </div>
        <div className={styles.verifyBar}>
          <span>After the change</span>
          <strong>Scan again</strong><i aria-hidden="true" /><strong>Compare evidence</strong><i aria-hidden="true" /><strong>Mark fixed</strong>
        </div>
      </section>

      <section id="automation" className={styles.splitMediaSection}>
        <div className={styles.sectionHeading}>
          <span className={styles.eyebrow}>05 / Automate</span>
          <h2>Keep the baseline from drifting.</h2>
          <p>Repository monitoring watches the default branch. PR Guardian adds a security decision before risky code merges.</p>
        </div>
        <figure className={styles.wideMedia}>
          <video controls autoPlay loop muted playsInline preload="auto" poster="/guide/repository-monitoring.jpg">
            <source src="/guide/continuous-protection-walkthrough.mp4" type="video/mp4" />
          </video>
          <figcaption>Move from a recurring repository schedule to controlled PR Guardian automation.</figcaption>
        </figure>
        <div className={styles.dualActions}>
          <Link href="/app/repos">Manage repositories <span aria-hidden="true">→</span></Link>
          <Link href="/app/guardian">Open PR Guardian <span aria-hidden="true">→</span></Link>
        </div>
      </section>

      <section id="agents" className={styles.videoChapter}>
        <div className={styles.sectionHeading}>
          <span className={styles.eyebrow}>06 / Extend</span>
          <h2>Add agent intelligence where it earns its place.</h2>
          <p>Use dedicated agents for recurring specialist work, then review their findings alongside repository scans instead of creating a separate security workflow.</p>
        </div>
        <div className={styles.videoGrid}>
          <article>
            <video controls autoPlay loop muted playsInline preload="auto" poster="/app intelligence.png">
              <source src="/demo-app-intelligence-web.mp4" type="video/mp4" />
            </video>
            <div>
              <span className={styles.eyebrow}>Intelligence</span>
              <h3>Turn scan history into a security briefing.</h3>
              <p>Summarize patterns, changing risk, and the next actions worth taking.</p>
              <Link href="/app/intelligence">Open intelligence <span aria-hidden="true">→</span></Link>
            </div>
          </article>
          <article>
            <video controls autoPlay loop muted playsInline preload="auto" poster="/Agent Team.png">
              <source src="/demo-hermes-agents-web.mp4" type="video/mp4" />
            </video>
            <div>
              <span className={styles.eyebrow}>Hermes agents</span>
              <h3>Deploy focused security roles.</h3>
              <p>Give each agent a clear objective, constrained tools, and a reviewable findings trail.</p>
              <Link href="/app/deploy">Set up Hermes <span aria-hidden="true">→</span></Link>
            </div>
          </article>
        </div>
      </section>

      <footer className={styles.finish}>
        <div>
          <span className={styles.eyebrow}>Ready to begin</span>
          <h2>Run the baseline. Fix what matters. Keep it protected.</h2>
        </div>
        <Link href="/app/scan" className={styles.primaryAction}>Start a scan <span aria-hidden="true">→</span></Link>
      </footer>
    </div>
  );
}
