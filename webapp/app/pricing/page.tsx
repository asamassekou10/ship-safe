import Nav from '@/components/Nav';
import Link from 'next/link';
import { plans, pricingFaq } from '@/data/plans';
import AnimatedCheck from '@/components/AnimatedCheck';
import MagneticButton from '@/components/MagneticButton';
import CursorGlow from '@/components/CursorGlow';
import ScrollAnimator from '@/components/ScrollAnimator';
import styles from './pricing.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/og1.png';

export const metadata: Metadata = {
  title: 'Pricing',
  description: 'Ship Safe pricing: free open-source CLI for everyone. Pro ($9/month) and Team ($19/seat/month) plans for cloud dashboard, GitHub integration, and team collaboration.',
  keywords: ['Ship Safe pricing', 'AI agent security scanner pricing', 'LLM vulnerability CLI cost', 'free security tool', 'DevSecOps pricing', 'application security cost'],
  alternates: {
    canonical: 'https://www.shipsafecli.com/pricing',
  },
  openGraph: {
    title: 'Simple, transparent pricing — Ship Safe',
    description: 'The CLI is always free and open-source. Pro & Team plans for the cloud dashboard, GitHub integration, and team collaboration.',
    type: 'website',
    url: 'https://www.shipsafecli.com/pricing',
    siteName: 'Ship Safe',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Ship Safe Pricing' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Simple, transparent pricing — Ship Safe',
    description: 'The CLI is always free and open-source. Pro & Team plans for the cloud dashboard, GitHub integration, and team collaboration.',
    images: [ogImage],
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Product',
      name: 'Ship Safe Pro',
      description: 'Cloud dashboard for developers who ship fast and need full security coverage.',
      offers: { '@type': 'Offer', price: '9', priceCurrency: 'USD', availability: 'https://schema.org/InStock' },
    },
    {
      '@type': 'Product',
      name: 'Ship Safe Team',
      description: 'Team collaboration, shared workspace, and aggregate security scoring.',
      offers: {
        '@type': 'Offer',
        price: '19',
        priceCurrency: 'USD',
        availability: 'https://schema.org/InStock',
        priceSpecification: { '@type': 'UnitPriceSpecification', price: '19', priceCurrency: 'USD', unitText: 'per seat' },
      },
    },
    {
      '@type': 'FAQPage',
      mainEntity: pricingFaq.map((item) => ({
        '@type': 'Question',
        name: item.q,
        acceptedAnswer: { '@type': 'Answer', text: item.a },
      })),
    },
  ],
};

const upgradeReasons = [
  'Save scan history',
  'Monitor private repos',
  'Get PR checks',
  'Share reports',
];

const openSourcePoints = [
  'Unlimited local scans',
  'MIT licensed CLI',
  '29 agents included',
];

export default function Pricing() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} // ship-safe-ignore — static JSON-LD, no user input
      />
      <ScrollAnimator />
      <Nav />
      <main className={styles.page}>
        {/* ── Hero ──────────────────────────────────── */}
        <section className={styles.hero}>
          <div className={styles.heroInner}>
            <span className={styles.sectionLabel}>// 01 — pricing</span>
            <h1>Simple, transparent <span className={styles.gradientText}>pricing.</span></h1>
            <p>
              The CLI is always free and open-source. Pay only when you want the hosted dashboard,
              team collaboration, or PR Guardian.
            </p>
          </div>
        </section>

        <section className={styles.upgradeReasons} aria-label="Why upgrade">
          <div className={styles.upgradeReasonsInner}>
            <span>Upgrade when you need to</span>
            <ul>
              {upgradeReasons.map((reason) => (
                <li key={reason}>
                  <AnimatedCheck variant="check" delay={80} />
                  {reason}
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ── Plans ─────────────────────────────────── */}
        <section className={styles.plansSection}>
          <CursorGlow className={styles.plansGrid}>
            {plans.map((plan, i) => (
              <article
                key={plan.name}
                data-glow
                data-animate
                data-delay={String(i * 60)}
                className={`${styles.planCard} ${plan.featured ? styles.featured : ''}`}
              >
                {plan.featured && <span className={styles.popularBadge}>Most popular</span>}
                <header className={styles.planHeader}>
                  <h3 className={styles.planName}>{plan.name}</h3>
                  <div className={styles.planPrice}>
                    <strong className={styles.priceNum}>{plan.price}</strong>
                    {plan.period && <span className={styles.pricePeriod}>{plan.period}</span>}
                  </div>
                  <p className={styles.planDesc}>{plan.desc}</p>
                </header>

                {plan.featured ? (
                  <MagneticButton>
                    <Link href={plan.ctaHref} className={styles.primaryCta}>
                      {plan.cta} <span aria-hidden="true">→</span>
                    </Link>
                  </MagneticButton>
                ) : (
                  <Link href={plan.ctaHref} className={styles.secondaryCta}>
                    {plan.cta}
                  </Link>
                )}

                <ul className={styles.featureList}>
                  {plan.features.map((f, idx) => (
                    <li key={f} className={styles.featureItem}>
                      <AnimatedCheck variant="check" delay={140 + idx * 70} />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </article>
            ))}
          </CursorGlow>
        </section>

        {/* ── Open-source band ──────────────────────── */}
        <section className={styles.osSection}>
          <div className={styles.osInner} data-animate>
            <div className={styles.osCopy}>
              <span className={styles.sectionLabel}>// 02 — open source</span>
              <h2>Start free. Upgrade when the workflow needs a home.</h2>
              <p>
                The CLI stays free and open source. Paid plans add the hosted dashboard,
                scan history, reports, PR checks, and team collaboration around the same scanner.
              </p>
            </div>
            <div className={styles.osPanel}>
              <ul className={styles.osPoints}>
                {openSourcePoints.map((point, idx) => (
                  <li key={point}>
                    <AnimatedCheck variant="check" delay={120 + idx * 80} />
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
              <a href="https://github.com/asamassekou10/ship-safe" target="_blank" rel="noopener noreferrer" className={styles.secondaryCta}>
                View on GitHub <span aria-hidden="true">→</span>
              </a>
            </div>
          </div>
        </section>

        {/* ── FAQ ────────────────────────────────────── */}
        <section className={styles.faqSection}>
          <div className={styles.faqInner}>
            <div className={styles.faqHead} data-animate>
              <span className={styles.sectionLabel}>// 03 — faq</span>
              <h2>Pricing questions, answered.</h2>
              <p>Anything else? <Link href="/docs">Read the docs</Link> or <a href="mailto:hello@shipsafecli.com">email us</a>.</p>
            </div>
            <CursorGlow className={styles.faqList}>
              {pricingFaq.map((item) => (
                <details key={item.q} data-glow className={styles.faqItem}>
                  <summary>
                    <span>{item.q}</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M6 9l6 6 6-6" />
                    </svg>
                  </summary>
                  <div className={styles.faqAnswer}>{item.a}</div>
                </details>
              ))}
            </CursorGlow>
          </div>
        </section>

        {/* ── Final CTA ──────────────────────────────── */}
        <section className={styles.finalCta}>
          <div className={styles.finalBg} aria-hidden="true">
            <div className={styles.mesh} />
          </div>
          <div className={styles.finalInner}>
            <span className={styles.statusPill}><i /> Try without signing up</span>
            <h2>Run your first scan in under a minute.</h2>
            <div className={styles.finalCommand}>
              <span>$</span>
              <code>npx ship-safe scan</code>
            </div>
            <div className={styles.actions}>
              <MagneticButton>
                <Link href="/signup" className={styles.primaryCta}>
                  Start free <span aria-hidden="true">→</span>
                </Link>
              </MagneticButton>
              <a href="https://github.com/asamassekou10/ship-safe" className={styles.secondaryCta}>View on GitHub</a>
            </div>
          </div>
        </section>
      </main>
    </>
  );
}
