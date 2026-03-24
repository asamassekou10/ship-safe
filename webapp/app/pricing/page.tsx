import Nav from '@/components/Nav';
import Link from 'next/link';
import { plans, pricingFaq } from '@/data/plans';
import styles from './pricing.module.css';
import ScrollAnimator from '@/components/ScrollAnimator';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Pricing — Ship Safe',
  description: 'Free CLI tool for everyone. Pro and Team plans for power users and teams.',
};

export default function Pricing() {
  return (
    <>
      <ScrollAnimator />
      <Nav />
      <main>
        <section className={styles.hero}>
          <div className="container">
            <span className="section-label">Pricing</span>
            <h2>Simple, transparent pricing.</h2>
            <p className="section-sub">
              The CLI is always free and open-source. Pay only for the cloud dashboard.
            </p>
          </div>
        </section>

        <section className={styles.plansSection}>
          <div className="container">
            <div className={styles.plansGrid}>
              {plans.map((plan, i) => (
                <div
                  key={plan.name}
                  className={`${styles.planCard} card ${plan.featured ? styles.featured : ''}`}
                  data-animate
                  data-delay={String(i * 60)}
                >
                  {plan.featured && <div className={styles.popularBadge}>Most Popular</div>}
                  <div className={styles.planHeader}>
                    <h3 className={styles.planName}>{plan.name}</h3>
                    <div className={styles.planPrice}>
                      <span className={styles.priceNum}>{plan.price}</span>
                      {plan.period && <span className={styles.pricePeriod}>{plan.period}</span>}
                    </div>
                    <p className={styles.planDesc}>{plan.desc}</p>
                  </div>
                  <Link
                    href={plan.ctaHref}
                    className={`btn ${plan.featured ? 'btn-primary' : 'btn-ghost'} ${styles.planCta}`}
                  >
                    {plan.cta}
                  </Link>
                  <ul className={styles.featureList}>
                    {plan.features.map((f) => (
                      <li key={f} className={styles.featureItem}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" strokeWidth="2.5" aria-hidden="true">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.openSource}>
          <div className="container">
            <div className={styles.osCard} data-animate>
              <div className={styles.osIcon}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
                </svg>
              </div>
              <div>
                <h3>Always open source.</h3>
                <p>The CLI and all 18 agents are MIT licensed. Self-host it, fork it, contribute to it. The SaaS layer funds development while the core stays free forever.</p>
              </div>
              <a href="https://github.com/asamassekou10/ship-safe" target="_blank" rel="noopener noreferrer" className="btn btn-ghost">
                View on GitHub →
              </a>
            </div>
          </div>
        </section>

        <section className={styles.faqSection}>
          <div className="container">
            <span className="section-label">FAQ</span>
            <h2>Pricing questions</h2>
            <div className={styles.faqList} data-animate>
              {pricingFaq.map((item, i) => (
                <details key={i} className={styles.faqItem}>
                  <summary className={styles.faqQuestion}>
                    <span>{item.q}</span>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M9 18l6-6-6-6" />
                    </svg>
                  </summary>
                  <div className={styles.faqAnswer}>{item.a}</div>
                </details>
              ))}
            </div>
          </div>
        </section>
      </main>
    </>
  );
}
