import type { Metadata } from 'next';
import Link from 'next/link';
import Nav from '@/components/Nav';
import results from '@/data/benchmark-results.json';
import styles from './benchmarks.module.css';

const canonicalUrl = 'https://www.shipsafecli.com/benchmarks';
const resultUrl = 'https://www.shipsafecli.com/benchmarks/latest.json';
const ogImage = '/api/og?title=Reproducible%20Security%20Benchmark&description=Inspect%2012%20paired%20vulnerable%20and%20safe%20controls%2C%20the%20methodology%2C%20and%20machine-readable%20results.&label=Benchmark&badge=Corpus%20v1.0.0';
const scenarioRecall = Math.round(results.metrics.scenarioRecall * 100);
const cleanControlRate = Math.round(results.metrics.targetRuleCleanControlPassRate * 100);

export const metadata: Metadata = {
  title: 'Reproducible Security Benchmark',
  description: 'Reproduce Ship Safe CLI detection results across paired vulnerable and safe controls, with methodology and limitations stated plainly.',
  keywords: ['Ship Safe CLI benchmark', 'AI security scanner benchmark', 'MCP security benchmark', 'agentic AI security testing', 'SAST test corpus', 'security scanner evaluation'],
  alternates: { canonical: canonicalUrl },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'Ship Safe CLI Reproducible Benchmark',
    description: 'A checked-in first-party corpus with paired vulnerable and safe controls for conventional and AI-native security rules.',
    type: 'article',
    url: canonicalUrl,
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Ship Safe CLI reproducible security benchmark' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe CLI Reproducible Security Benchmark',
    description: 'Paired vulnerable and safe controls with public methodology and machine-readable results.',
    images: [ogImage],
  },
};

const benchmarkFaq = [
  {
    question: 'What does the Ship Safe benchmark measure?',
    answer: 'It measures whether a labeled target rule detects its vulnerable synthetic fixture and stays quiet for that same rule on a paired safe control.',
  },
  {
    question: 'Is this an independent security benchmark?',
    answer: 'No. This is a transparent first-party regression corpus maintained by Ship Safe. It does not claim independent validation or production-repository precision.',
  },
  {
    question: 'How can I reproduce the benchmark?',
    answer: 'Clone the Ship Safe repository and run npm run benchmark:corpus. The command exits with an error if a labeled detection or paired target-rule control regresses.',
  },
];

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Dataset',
      '@id': `${canonicalUrl}#dataset`,
      name: 'Ship Safe CLI deterministic security corpus',
      description: results.methodology,
      version: results.corpusVersion,
      datePublished: '2026-07-19',
      dateModified: '2026-07-19',
      url: canonicalUrl,
      isAccessibleForFree: true,
      license: 'https://opensource.org/licenses/MIT',
      keywords: ['AI security', 'MCP security', 'agentic AI', 'SAST', 'security scanner benchmark'],
      measurementTechnique: 'Paired synthetic vulnerable and safe controls evaluated against labeled target rules in deterministic local mode.',
      variableMeasured: ['Scenario recall', 'Target-rule clean-control pass rate'],
      creator: { '@type': 'Organization', name: 'Ship Safe CLI', url: 'https://www.shipsafecli.com' },
      distribution: { '@type': 'DataDownload', encodingFormat: 'application/json', contentUrl: resultUrl },
    },
    {
      '@type': 'FAQPage',
      '@id': `${canonicalUrl}#faq`,
      mainEntity: benchmarkFaq.map((item) => ({
        '@type': 'Question',
        name: item.question,
        acceptedAnswer: { '@type': 'Answer', text: item.answer },
      })),
    },
    {
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Ship Safe CLI', item: 'https://www.shipsafecli.com' },
        { '@type': 'ListItem', position: 2, name: 'Reproducible Security Benchmark', item: canonicalUrl },
      ],
    },
  ],
};

function titleFromId(id: string) {
  return id.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
}

export default function BenchmarksPage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} // ship-safe-ignore - static JSON-LD, no user input
      />
      <Nav />
      <main className={styles.page}>
        <header className={styles.hero}>
          <span className={styles.eyebrow}>Reproducible evidence</span>
          <h1>A security benchmark you can reproduce.</h1>
          <p>
            This checked-in corpus tests labeled security rules against paired vulnerable and safe controls. The result is deterministic, public, and enforced in CI.
          </p>
          <div className={styles.verified}>Ship Safe CLI v{results.shipSafeVersion} · Corpus v{results.corpusVersion} · First-party evaluation</div>
          <div className={styles.actions}>
            <a href="https://github.com/asamassekou10/ship-safe/tree/main/benchmarks" target="_blank" rel="noopener noreferrer" className={styles.primaryAction}>Inspect the corpus</a>
            <a href="#methodology" className={styles.secondaryAction}>Read the methodology</a>
          </div>
        </header>

        <section className={styles.metrics} aria-label="Benchmark results">
          <div><strong>{results.metrics.detected}/{results.metrics.scenarios}</strong><span>labeled scenarios detected</span></div>
          <div><strong>{scenarioRecall}%</strong><span>scenario recall on this corpus</span></div>
          <div><strong>{cleanControlRate}%</strong><span>target-rule clean-control pass rate</span></div>
        </section>

        <section className={styles.mediaSection} aria-labelledby="benchmark-demo-heading">
          <div className={styles.mediaIntro}>
            <span className={styles.eyebrow}>From command to evidence</span>
            <h2 id="benchmark-demo-heading">The same local scanner, tested in CI.</h2>
            <p>The visual demo shows Ship Safe running against a repository. The benchmark itself runs without animation, accounts, or external AI calls so every assertion remains deterministic.</p>
          </div>
          <figure className={styles.demoFigure}>
            <video autoPlay muted loop playsInline preload="metadata" aria-label="Ship Safe CLI scan demonstration">
              <source src="/ship-safe-hero-demo.mp4" type="video/mp4" />
            </video>
            <figcaption>Product demonstration. Benchmark measurements come from the checked-in corpus and JSON result below.</figcaption>
          </figure>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionIntro}>
            <span className={styles.eyebrow}>Scenario results</span>
            <h2>Conventional and AI-native risks.</h2>
            <p>Every row maps a labeled fixture to one expected rule and a paired safe control.</p>
          </div>

          <div className={styles.resultTable}>
            <div className={styles.tableHeader} aria-hidden="true">
              <span>Scenario</span><span>Category</span><span>Expected rule</span><span>Result</span>
            </div>
            {results.scenarios.map((scenario) => (
              <article className={styles.resultRow} key={scenario.id}>
                <div><strong>{titleFromId(scenario.id)}</strong><small>{scenario.agent}</small></div>
                <span>{scenario.category}</span>
                <code>{scenario.expectedRule}</code>
                <div className={styles.pass}><span aria-hidden="true">✓</span> Detected · control passed</div>
              </article>
            ))}
          </div>
        </section>

        <section className={styles.methodology} id="methodology">
          <div>
            <span className={styles.eyebrow}>Methodology</span>
            <h2>Small, explicit, and regression-focused.</h2>
          </div>
          <div className={styles.methodCopy}>
            <p>{results.methodology}</p>
            <ol>
              <li>Run the named local agent against the vulnerable fixture.</li>
              <li>Require the labeled target rule to appear.</li>
              <li>Run the same agent against its safe control.</li>
              <li>Require the labeled target rule not to appear.</li>
              <li>Fail CI if either assertion regresses.</li>
            </ol>
            <code className={styles.command}>$ npm run benchmark:corpus</code>
          </div>
        </section>

        <section className={styles.limitations}>
          <span className={styles.eyebrow}>What this does not prove</span>
          <div>
            <h2>No inflated claims.</h2>
            {results.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}
            <p>Independent review, pinned third-party vulnerable repositories, and comparative scanner testing remain separate evidence tracks.</p>
          </div>
        </section>

        <section className={styles.faqSection} aria-labelledby="benchmark-faq-heading">
          <div>
            <span className={styles.eyebrow}>Benchmark FAQ</span>
            <h2 id="benchmark-faq-heading">Read the result correctly.</h2>
          </div>
          <div className={styles.faqList}>
            {benchmarkFaq.map((item) => (
              <article key={item.question}>
                <h3>{item.question}</h3>
                <p>{item.answer}</p>
              </article>
            ))}
          </div>
        </section>

        <section className={styles.footerLinks}>
          <a href="/benchmarks/latest.json">Machine-readable result</a>
          <Link href="/security">Security and data flow</Link>
          <Link href="/docs">CLI documentation</Link>
        </section>
      </main>
    </>
  );
}
