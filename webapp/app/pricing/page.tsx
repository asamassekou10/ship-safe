import Nav from '@/components/Nav';
import { pricingFaq } from '@/data/plans';
import AnimatedCheck from '@/components/AnimatedCheck';
import MagneticButton from '@/components/MagneticButton';
import CursorGlow from '@/components/CursorGlow';
import ScrollAnimator from '@/components/ScrollAnimator';
import TrackedLink from '@/components/TrackedLink';
import styles from './pricing.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/og1.png';

export const metadata: Metadata = {
  title: 'Pricing',
  description: 'Ship Safe pricing: start free with the open-source CLI. Upgrade to Pro for scan history, PR checks, private repos, and hosted reports.',
  keywords: ['Ship Safe pricing', 'AI agent security scanner pricing', 'LLM vulnerability CLI cost', 'free security tool', 'DevSecOps pricing', 'application security cost'],
  alternates: {
    canonical: 'https://www.shipsafecli.com/pricing',
  },
  openGraph: {
    title: 'Start free. Upgrade when your team needs history — Ship Safe',
    description: 'Run Ship Safe locally for free. Add the dashboard when you need scan history, PR checks, private repos, and team workflows.',
    type: 'website',
    url: 'https://www.shipsafecli.com/pricing',
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Ship Safe Pricing' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Start free. Upgrade when your team needs history — Ship Safe',
    description: 'Run Ship Safe locally for free. Add the dashboard when you need scan history, PR checks, private repos, and team workflows.',
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

const pricingCards = [
  {
    name: 'Free CLI',
    eyebrow: 'Open source',
    price: '$0',
    period: 'forever',
    desc: 'Run local security scans without an account.',
    cta: 'Run locally',
    ctaHref: '/docs#get-started',
    featured: false,
    features: [
      'Unlimited local scans',
      'MIT licensed',
      '29 security agents',
      'No account required',
    ],
  },
  {
    name: 'Pro',
    eyebrow: 'Most popular',
    price: '$9',
    period: '/month',
    desc: 'For developers who want history, reports, and PR checks.',
    cta: 'Start Pro',
    ctaHref: '/signup?callbackUrl=/app/checkout%3Fplan%3Dpro',
    featured: true,
    features: [
      'Cloud dashboard',
      'Scan history and trends',
      'Private repos',
      'PR Guardian checks',
      'Hosted reports',
    ],
  },
  {
    name: 'Team',
    eyebrow: 'Teams',
    price: '$19',
    period: '/seat/month',
    desc: 'For shared security workflows across repos and people.',
    cta: 'Start Team',
    ctaHref: '/signup?callbackUrl=/app/checkout%3Fplan%3Dteam',
    featured: false,
    features: [
      'Everything in Pro',
      'Shared workspace',
      'Role-based access',
      'Slack and webhooks',
      'Team security score',
    ],
  },
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
            <span className={styles.sectionLabel}>// pricing</span>
            <h1>Start free. Upgrade later.</h1>
            <p>
              Local scans are free. Pro adds history, PR checks, private repos, and hosted reports.
            </p>
            <div className={styles.heroActions}>
              <MagneticButton>
                <TrackedLink href="/signup" event="Pricing CTA Clicked" payload={{ item: 'start_free_scan', section: 'hero' }} className={styles.primaryCta}>
                  Start free scan <span aria-hidden="true">→</span>
                </TrackedLink>
              </MagneticButton>
              <TrackedLink href="#plans" event="Pricing CTA Clicked" payload={{ item: 'compare_plans', section: 'hero' }} className={styles.secondaryCta}>Compare plans</TrackedLink>
            </div>
          </div>
        </section>

        {/* ── Plans ─────────────────────────────────── */}
        <section id="plans" className={styles.plansSection}>
          <CursorGlow className={styles.plansGrid}>
            {pricingCards.map((plan, i) => (
              <article
                key={plan.name}
                data-glow
                data-animate
                data-delay={String(i * 60)}
                className={`${styles.planCard} ${plan.featured ? styles.featured : ''}`}
              >
                <span className={`${styles.planEyebrow} ${plan.featured ? styles.featuredEyebrow : ''}`}>
                  {plan.eyebrow}
                </span>
                <header className={styles.planHeader}>
                  <h3 className={styles.planName}>{plan.name}</h3>
                  <div className={styles.planPrice}>
                    <strong className={styles.priceNum}>{plan.price}</strong>
                    {plan.period && <span className={styles.pricePeriod}>{plan.period}</span>}
                  </div>
                  <p className={styles.planDesc}>{plan.desc}</p>
                </header>

                <div className={styles.planCtaSlot}>
                  {plan.featured ? (
                    <MagneticButton className={styles.ctaMagnet}>
                      <TrackedLink href={plan.ctaHref} event="Pricing Plan CTA Clicked" payload={{ plan: plan.name, featured: plan.featured }} className={styles.primaryCta}>
                        {plan.cta} <span aria-hidden="true">→</span>
                      </TrackedLink>
                    </MagneticButton>
                  ) : (
                    <TrackedLink href={plan.ctaHref} event="Pricing Plan CTA Clicked" payload={{ plan: plan.name, featured: plan.featured }} className={styles.secondaryCta}>
                      {plan.cta}
                    </TrackedLink>
                  )}
                </div>

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
          <div className={styles.decisionNote}>
            <p>Most developers start free. Upgrade to Pro when you want history, GitHub PR checks, and hosted reports.</p>
          </div>
          <div className={styles.enterpriseRow}>
            <div>
              <strong>Need SSO, on-prem, or custom policies?</strong>
              <span>Enterprise includes Team plus SAML, SLA, deployment support, and volume pricing.</span>
            </div>
            <TrackedLink href="mailto:hello@shipsafecli.com" event="Pricing CTA Clicked" payload={{ item: 'contact_enterprise', section: 'enterprise' }} className={styles.secondaryCta}>Contact us</TrackedLink>
          </div>
        </section>

        {/* ── FAQ ────────────────────────────────────── */}
        <section className={styles.faqSection}>
          <div className={styles.faqInner}>
            <div className={styles.faqHead} data-animate>
              <span className={styles.sectionLabel}>// faq</span>
              <h2>Questions, answered.</h2>
              <p>Short answers for the buying decision.</p>
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
            <span className={styles.statusPill}><i /> No account needed for local scans</span>
            <h2>Start scanning free today.</h2>
            <div className={styles.finalCommand}>
              <span>$</span>
              <code>npx ship-safe scan</code>
            </div>
            <div className={styles.actions}>
              <MagneticButton>
                <TrackedLink href="/signup" event="Pricing CTA Clicked" payload={{ item: 'start_free', section: 'final' }} className={styles.primaryCta}>
                  Start free <span aria-hidden="true">→</span>
                </TrackedLink>
              </MagneticButton>
              <TrackedLink href="#plans" event="Pricing CTA Clicked" payload={{ item: 'compare_plans', section: 'final' }} className={styles.secondaryCta}>Compare plans</TrackedLink>
            </div>
          </div>
        </section>
      </main>
    </>
  );
}
