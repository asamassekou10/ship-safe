import type { Metadata } from 'next';
import Image from 'next/image';
import Link from 'next/link';
import Nav from '@/components/Nav';
import styles from './security.module.css';

const canonicalUrl = 'https://www.shipsafecli.com/security';
const ogImage = '/api/og?title=Security%20and%20Data%20Flow&description=See%20what%20stays%20local%2C%20what%20reaches%20an%20AI%20provider%2C%20and%20how%20to%20force%20offline%20scanning.&label=Security&badge=v9.5.2';

export const metadata: Metadata = {
  title: 'Security and Data Flow',
  description: 'How Ship Safe CLI processes code in local, provider-backed, GPT-Red, and hosted workflows, including credential masking and offline controls.',
  keywords: ['Ship Safe CLI security', 'local code scanner privacy', 'AI code scanner data flow', 'offline security scanner', 'GPT-Red privacy', 'MCP security scanner'],
  alternates: { canonical: canonicalUrl },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'Ship Safe CLI Security and Data Flow',
    description: 'A precise breakdown of what stays local, what reaches an AI provider, and how to force fully offline scanning.',
    type: 'article',
    url: canonicalUrl,
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Ship Safe CLI security and data flow' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe CLI Security and Data Flow',
    description: 'Local scanning, provider boundaries, credential masking, and strict offline controls.',
    images: [ogImage],
  },
};

const securityFaq = [
  {
    question: 'Does Ship Safe CLI send source code to the cloud?',
    answer: 'The 29 built-in agents can run locally without sending source code to Ship Safe or an AI provider. Provider-backed analysis and GPT-Red send bounded repository context to the provider you select. Use --no-ai to force offline scanning.',
  },
  {
    question: 'Does Ship Safe CLI require an API key?',
    answer: 'No API key is required for local scanning. A provider API key is required only when you explicitly use remote AI classification, deep analysis, or provider-backed GPT-Red workflows.',
  },
  {
    question: 'How do I run Ship Safe completely offline?',
    answer: 'Run npx ship-safe audit . --no-ai. The local agent pool, dependency checks, scoring, policies, and report generation remain on your machine.',
  },
];

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'TechArticle',
      '@id': `${canonicalUrl}#article`,
      headline: 'Ship Safe CLI Security and Data Flow',
      description: 'How Ship Safe CLI processes repository data in local, AI-provider, GPT-Red, and hosted modes.',
      datePublished: '2026-07-19',
      dateModified: '2026-07-19',
      url: canonicalUrl,
      image: `https://www.shipsafecli.com${ogImage}`,
      about: ['Local security scanning', 'AI provider data flow', 'Credential redaction', 'Offline code scanning'],
      author: { '@type': 'Organization', name: 'Ship Safe CLI', url: 'https://www.shipsafecli.com' },
      publisher: { '@type': 'Organization', name: 'Ship Safe CLI', url: 'https://www.shipsafecli.com' },
    },
    {
      '@type': 'FAQPage',
      '@id': `${canonicalUrl}#faq`,
      mainEntity: securityFaq.map((item) => ({
        '@type': 'Question',
        name: item.question,
        acceptedAnswer: { '@type': 'Answer', text: item.answer },
      })),
    },
    {
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Ship Safe CLI', item: 'https://www.shipsafecli.com' },
        { '@type': 'ListItem', position: 2, name: 'Security and Data Flow', item: canonicalUrl },
      ],
    },
  ],
};

const modes = [
  {
    mode: 'Local scan',
    command: 'npx ship-safe audit . --no-ai',
    destination: 'Stays on your machine',
    detail: 'The 29 built-in agents, dependency checks, scoring, policy evaluation, and report generation run locally. No AI provider is called.',
  },
  {
    mode: 'Provider analysis',
    command: 'npx ship-safe audit . --provider <name>',
    destination: 'Your selected provider',
    detail: 'Ship Safe sends finding metadata and bounded matched-code context for classification or deep analysis. Common credential patterns are masked before provider-bound prompts.',
  },
  {
    mode: 'GPT-Red',
    command: 'npx ship-safe red-team . --gpt-red --provider <name>',
    destination: 'Your selected provider',
    detail: 'The red-team harness sends bounded agent-readable files and relevant configuration so attacker, defender, and judge scenarios can reason across real repository context.',
  },
  {
    mode: 'Hosted workflows',
    command: 'Dashboard, reports, and PR Guardian',
    destination: 'Ship Safe cloud services',
    detail: 'Repository metadata, scan results, findings, and reports are processed as needed to provide the hosted feature you explicitly use.',
  },
];

export default function SecurityPage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} // ship-safe-ignore - static JSON-LD, no user input
      />
      <Nav />
      <main className={styles.page}>
        <header className={styles.hero}>
          <span className={styles.eyebrow}>Security and data flow</span>
          <h1>Know where your code goes.</h1>
          <p>
            Ship Safe CLI is local-first. Remote AI analysis and hosted workflows are separate modes with explicit data boundaries and controls.
          </p>
          <div className={styles.verified}>Verified against Ship Safe CLI v9.5.2 · July 19, 2026</div>
          <div className={styles.actions}>
            <a href="#modes" className={styles.primaryAction}>Review every mode</a>
            <Link href="/privacy" className={styles.secondaryAction}>Privacy policy</Link>
          </div>
        </header>

        <section className={styles.summary} aria-label="Security summary">
          <div><strong>29</strong><span>built-in agents run locally</span></div>
          <div><strong>0</strong><span>API keys required for core scans</span></div>
          <div><strong>1 flag</strong><span><code>--no-ai</code> forces offline scanning</span></div>
        </section>

        <section className={styles.mediaSection} aria-labelledby="security-output-heading">
          <div className={styles.mediaIntro}>
            <span className={styles.eyebrow}>Real product output</span>
            <h2 id="security-output-heading">Findings remain reviewable.</h2>
            <p>Local scans can produce structured findings and reports. Hosted review is a separate workflow you choose when you need history, investigation, and team collaboration.</p>
          </div>
          <figure className={styles.productFigure}>
            <div className={styles.productImage}>
              <Image
                src="/scan result.png"
                alt="Ship Safe dashboard showing a security scan result, severity breakdown, and prioritized findings"
                fill
                sizes="(max-width: 820px) 100vw, 1120px"
              />
            </div>
            <figcaption>Example hosted scan review. Local-only scanning does not require this dashboard.</figcaption>
          </figure>
        </section>

        <section id="modes" className={styles.section}>
          <div className={styles.sectionIntro}>
            <span className={styles.eyebrow}>Processing modes</span>
            <h2>Local by default. Remote when selected.</h2>
            <p>Having a supported provider key in your environment may enable optional AI classification unless you pass <code>--no-ai</code>.</p>
          </div>

          <div className={styles.modeTable}>
            {modes.map((item) => (
              <article className={styles.modeRow} key={item.mode}>
                <div className={styles.modeName}>{item.mode}</div>
                <code>{item.command}</code>
                <div className={styles.destination}>{item.destination}</div>
                <p>{item.detail}</p>
              </article>
            ))}
          </div>
        </section>

        <section className={`${styles.section} ${styles.detailGrid}`}>
          <article>
            <span className={styles.eyebrow}>Provider boundaries</span>
            <h2>What remote AI modes receive</h2>
            <ul>
              <li>Standard classification includes finding metadata and a matched excerpt capped at 100 characters.</li>
              <li>Deep analysis can include a bounded code window around a finding to reason about reachability and sanitization.</li>
              <li>Standard GPT-Red selects up to 12 relevant files, 6,000 characters per file, and 60,000 characters total.</li>
              <li>Kimi K3 long-context mode raises those caps to 60 files, 12,000 characters per file, and 250,000 characters total.</li>
            </ul>
          </article>

          <article>
            <span className={styles.eyebrow}>Credential handling</span>
            <h2>Masking before provider calls</h2>
            <p>
              Provider-bound classification, deep-analysis, and GPT-Red context applies best-effort masking for private keys, authorization headers, common secret assignments, and recognizable provider-token formats.
            </p>
            <p>
              Masking is defense in depth, not a guarantee that arbitrary sensitive business data can be identified. Use <code>--no-ai</code> when repository content must not leave the machine.
            </p>
          </article>

          <article>
            <span className={styles.eyebrow}>Provider choice</span>
            <h2>Your key, your endpoint</h2>
            <p>
              The CLI calls the provider configured through your environment or command options. Provider API keys authenticate directly to that endpoint; they are not uploaded to the Ship Safe dashboard by the local CLI.
            </p>
            <p>For local model inference, use a supported localhost provider such as Ollama or LM Studio.</p>
          </article>

          <article>
            <span className={styles.eyebrow}>Local artifacts</span>
            <h2>What is stored on disk</h2>
            <p>
              Incremental scan context, score history, accepted baselines, fix logs, and time-limited LLM response caches can be written under <code>.ship-safe/</code> in the scanned project.
            </p>
            <p>Add that directory to <code>.gitignore</code> when you do not want local scan state committed.</p>
          </article>
        </section>

        <section className={styles.controlBand}>
          <div>
            <span className={styles.eyebrow}>Strict local mode</span>
            <h2>Keep the scan entirely offline.</h2>
            <p>Use the explicit control when source code or findings cannot be sent to any external model.</p>
          </div>
          <code>$ npx ship-safe audit . --no-ai</code>
        </section>

        <section className={styles.faqSection} aria-labelledby="security-faq-heading">
          <div>
            <span className={styles.eyebrow}>Common questions</span>
            <h2 id="security-faq-heading">Security, without ambiguity.</h2>
          </div>
          <div className={styles.faqList}>
            {securityFaq.map((item) => (
              <article key={item.question}>
                <h3>{item.question}</h3>
                <p>{item.answer}</p>
              </article>
            ))}
          </div>
        </section>

        <section className={styles.footerLinks}>
          <Link href="/benchmarks">Review the reproducible benchmark</Link>
          <Link href="/docs">Read the CLI documentation</Link>
          <Link href="/privacy">Read the privacy policy</Link>
          <a href="https://github.com/asamassekou10/ship-safe" target="_blank" rel="noopener noreferrer">Inspect the source on GitHub</a>
        </section>
      </main>
    </>
  );
}
