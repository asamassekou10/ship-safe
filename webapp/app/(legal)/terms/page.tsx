import type { Metadata } from 'next';
import Link from 'next/link';
import styles from '../legal.module.css';

export const metadata: Metadata = {
  title: 'Terms of Service',
  description: 'Ship Safe terms of service for use of the website, dashboard, CLI, and related security tooling.',
  alternates: {
    canonical: 'https://www.shipsafecli.com/terms',
  },
};

export default function TermsPage() {
  return (
    <main className={styles.legalPage}>
      <div className={styles.legalShell}>
        <Link href="/signup" className={styles.backLink}>Back to signup</Link>
        <article className={styles.legalCard}>
          <span className={styles.eyebrow}>Legal</span>
          <h1>Terms of Service</h1>
          <p className={styles.updated}>Last updated July 17, 2026</p>
          <p className={styles.notice}>
            These terms are written for clarity, but they are not a substitute for legal advice.
            If you use Ship Safe for an organization, you confirm you have authority to accept these terms.
          </p>

          <section className={styles.section}>
            <h2>Use of Ship Safe</h2>
            <p>
              Ship Safe provides security scanning, AI-assisted analysis, reports, and related developer tooling.
              You are responsible for using the service lawfully and only on code, systems, and repositories you are authorized to test.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Accounts and Access</h2>
            <p>
              You are responsible for activity under your account and for keeping connected provider accounts secure.
              We may suspend access if we detect abuse, unauthorized testing, fraud, or activity that could harm Ship Safe or others.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Security Results</h2>
            <p>
              Findings, scores, and AI-generated explanations are provided to help prioritize risk. They may be incomplete,
              inaccurate, or require human review. You remain responsible for validating findings before taking action.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Customer Content</h2>
            <p>
              You keep ownership of code, scan data, repository metadata, and other content you provide. You grant Ship Safe
              permission to process that content only as needed to operate, secure, improve, and support the service.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Payments</h2>
            <p>
              Paid plans are billed through our payment provider. Fees, plan limits, and renewal terms are shown at checkout
              or on the pricing page. You are responsible for taxes and for keeping billing information current.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Availability and Changes</h2>
            <p>
              We work to keep Ship Safe reliable, but the service may change, pause, or experience downtime. We may update
              features, agents, plan limits, or these terms as the product evolves.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Contact</h2>
            <p>
              Questions about these terms can be sent to <span className={styles.contact}>hello@shipsafecli.com</span>.
            </p>
          </section>
        </article>
      </div>
    </main>
  );
}
